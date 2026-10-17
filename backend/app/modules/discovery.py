import json
import socket
import ipaddress
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple, Optional
from backend.app.config import SEED_DEVICES_PATH, OFFLINE_MISSED_SCANS_THRESHOLD, OFFLINE_TIMEOUT_SECONDS
from backend.app.database import get_db_connection
from backend.app.modules.classification import classifier
from backend.app.modules.risk_assessment import risk_engine
from backend.app.modules.alert_manager import alert_mgr
from backend.app.modules.audit import audit_logger

class DeviceDiscoveryService:
    """
    Device Discovery Service (Chapters 3.4, 4.2.1, 6.5, 7.3)
    Gathers network metadata (IP, MAC, hostname, services, ports) and passes
    discovered devices through the complete pipeline:
    Discovery -> Classification -> Risk Assessment -> Database -> Alert Manager.
    """

    def __init__(self):
        self.method_cache = {}
        self.consecutive_misses: Dict[int, int] = {}
        self.missed_scans_threshold: int = OFFLINE_MISSED_SCANS_THRESHOLD
        self.offline_timeout_seconds: int = OFFLINE_TIMEOUT_SECONDS

    def run_discovery_pipeline(self, scan_type: str = "simulated", target_subnet: str = "192.168.1.0/24", user: str = "SYSTEM") -> Dict[str, Any]:
        """Runs an end-to-end discovery cycle as described in Fig. 1 & 2."""
        raw_devices = []
        skipped_hosts = []

        if scan_type == "active":
            raw_devices, skipped_hosts = self._execute_nmap_scan(target_subnet)
        else:
            raw_devices = self._load_seed_devices()

        conn = get_db_connection()
        cursor = conn.cursor()

        devices_processed = 0
        new_devices_count = 0
        devices_marked_offline = 0
        devices_reconnected = 0
        detected_device_ids = set()
        detected_macs = set()

        for dev in raw_devices:
            ip = dev.get("ip_address")
            mac = dev.get("mac_address")
            hostname = dev.get("hostname", "")
            open_ports = dev.get("open_ports", [])
            services = dev.get("services", [])

            # Step 1: Device Classification (Module 2)
            device_type, manufacturer = classifier.classify_device(
                mac_address=mac,
                hostname=hostname,
                open_ports=open_ports,
                services=services
            )
            # Override if explicitly provided in high-confidence record
            if dev.get("device_type") and dev.get("device_type") != "Unknown Device":
                device_type = dev.get("device_type")
            if dev.get("manufacturer") and dev.get("manufacturer") != "Unknown":
                manufacturer = dev.get("manufacturer")

            dev["device_type"] = device_type
            dev["manufacturer"] = manufacturer

            # Step 2: Check Existing Inventory
            existing = cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac,)).fetchone()
            is_new = False
            device_id = None

            if existing:
                device_id = existing["id"]
                detected_device_ids.add(device_id)
                detected_macs.add(mac)
                prev_status = existing["status"]

                # Retain approved / known status from the persistent database
                dev["is_known_device"] = bool(existing["is_known_device"])
                # Reset consecutive miss counter on detection
                self.consecutive_misses[device_id] = 0

                # Check if device reconnected from Offline or first observed after Not Yet Observed
                if prev_status == "Offline":
                    devices_reconnected += 1
                    audit_logger.log_event(
                        event_type="DEVICE_ONLINE",
                        username=user,
                        description=f"Device #{device_id} at {ip} ({mac}) reconnected and is back Online",
                        conn=conn
                    )
                elif prev_status == "Not Yet Observed":
                    devices_reconnected += 1
                    audit_logger.log_event(
                        event_type="DEVICE_ONLINE",
                        username=user,
                        description=f"Manually registered device #{device_id} at {ip} ({mac}) observed on network and is now Online",
                        conn=conn
                    )

                # Update last seen timestamp & potential IP changes, setting status to Online
                cursor.execute(
                    """
                    UPDATE devices SET 
                        ip_address = ?, hostname = ?, manufacturer = ?, 
                        device_type = ?, open_ports = ?, services = ?,
                        firmware_version = ?, credential_status = ?,
                        network_exposure = ?, security_configuration = ?,
                        last_seen = CURRENT_TIMESTAMP, status = 'Online'
                    WHERE id = ?
                    """,
                    (
                        ip, hostname, manufacturer, device_type,
                        json.dumps(open_ports), json.dumps(services),
                        dev.get("firmware_version", "Unknown"),
                        dev.get("credential_status", "Unknown"),
                        dev.get("network_exposure", "Unknown"),
                        dev.get("security_configuration", "Unknown"),
                        device_id
                    )
                )
            else:
                is_new = True
                new_devices_count += 1
                # Genuinely new devices are marked Unknown (is_known_device = 0) until approved
                is_known_val = 1 if (scan_type == "simulated" and dev.get("is_known_device", False)) else 0
                dev["is_known_device"] = bool(is_known_val)
                cursor.execute(
                    """
                    INSERT INTO devices (
                        ip_address, mac_address, hostname, manufacturer,
                        device_type, open_ports, services, firmware_version,
                        credential_status, network_exposure, security_configuration,
                        is_known_device, status, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Online', CURRENT_TIMESTAMP)
                    """,
                    (
                        ip, mac, hostname, manufacturer,
                        device_type, json.dumps(open_ports), json.dumps(services),
                        dev.get("firmware_version", "Unknown"),
                        dev.get("credential_status", "Unknown"),
                        dev.get("network_exposure", "Unknown"),
                        dev.get("security_configuration", "Unknown"),
                        is_known_val
                    )
                )
                device_id = cursor.lastrowid
                detected_device_ids.add(device_id)
                detected_macs.add(mac)
                self.consecutive_misses[device_id] = 0

                audit_logger.log_event(
                    event_type="DEVICE_DISCOVERED",
                    username=user,
                    description=f"New device discovered at {ip} ({mac})",
                    conn=conn
                )
                audit_logger.log_event(
                    event_type="DEVICE_CLASSIFIED",
                    username=user,
                    description=f"Device {ip} classified as {device_type} (Vendor: {manufacturer})",
                    conn=conn
                )

            # Update volatile cache for UI rendering (preserve 'manual' origin for registered devices)
            if self.method_cache.get(device_id) != "manual":
                self.method_cache[device_id] = scan_type

            # Step 3: Risk Assessment (Module 3)
            risk_result = risk_engine.evaluate_device(dev)

            # Store risk assessment record
            cursor.execute(
                """
                INSERT INTO risk_assessments (
                    device_id, risk_score, risk_level,
                    factor_unknown, factor_firmware, factor_credential,
                    factor_exposure, factor_config, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    risk_result["risk_score"],
                    risk_result["risk_level"],
                    risk_result["factor_unknown"],
                    risk_result["factor_firmware"],
                    risk_result["factor_credential"],
                    risk_result["factor_exposure"],
                    risk_result["factor_config"],
                    json.dumps(risk_result["findings"])
                )
            )

            if is_new:
                audit_logger.log_event(
                    event_type="RISK_ASSESSED",
                    username=user,
                    description=f"Initial risk assessment completed for {ip} (Score: {risk_result['risk_score']})",
                    conn=conn
                )

            # Step 4: Alert Evaluation (Module 4)
            alert_mgr.evaluate_and_alert(device_id, dev, risk_result, conn=conn)

            devices_processed += 1

        # Step 4.5: Device Availability Verification (Online/Offline Tracking)
        # Verify status of existing inventory devices within the scanned network.
        # Only evaluate devices whose IP address is covered by target_subnet.
        try:
            scanned_network = ipaddress.ip_network(target_subnet.strip(), strict=False)
        except Exception:
            scanned_network = None

        if scanned_network:
            existing_inventory = cursor.execute(
                "SELECT id, ip_address, mac_address, hostname, status, last_seen FROM devices"
            ).fetchall()

            now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

            for d in existing_inventory:
                d_id = d["id"]
                d_ip_str = d["ip_address"]
                d_mac = d["mac_address"]
                d_status = d["status"]
                d_last_seen = d["last_seen"]

                # 1. Skip if detected in the current scan
                if d_id in detected_device_ids or d_mac in detected_macs:
                    continue

                # 2. Check if device IP is covered by the scanned network
                try:
                    d_ip = ipaddress.ip_address(d_ip_str)
                    if d_ip not in scanned_network:
                        continue
                except Exception:
                    continue

                # 3. Preserve 'Not Yet Observed' state for manually added devices awaiting first discovery
                if d_status == "Not Yet Observed":
                    continue

                # 4. If already Offline, maintain count and avoid duplicate logs
                if d_status == "Offline":
                    self.consecutive_misses[d_id] = self.consecutive_misses.get(d_id, self.missed_scans_threshold) + 1
                    continue

                # 5. Device was Online, but missing from this scan covering its network:
                miss_count = self.consecutive_misses.get(d_id, 0) + 1
                self.consecutive_misses[d_id] = miss_count

                # Calculate elapsed seconds since last_seen
                elapsed_seconds = 0.0
                if d_last_seen:
                    try:
                        ls_clean = str(d_last_seen).split(".")[0]
                        last_seen_dt = datetime.strptime(ls_clean, "%Y-%m-%d %H:%M:%S")
                        elapsed_seconds = max(0.0, (now_utc - last_seen_dt).total_seconds())
                    except Exception:
                        elapsed_seconds = 0.0

                # Confirmation criteria: repeated observations OR configurable timeout
                if miss_count >= self.missed_scans_threshold or elapsed_seconds >= self.offline_timeout_seconds:
                    cursor.execute("UPDATE devices SET status = 'Offline' WHERE id = ?", (d_id,))
                    devices_marked_offline += 1
                    audit_logger.log_event(
                        event_type="DEVICE_OFFLINE",
                        username=user,
                        description=(
                            f"Device #{d_id} at {d_ip_str} ({d_mac}) confirmed absent "
                            f"after {miss_count} missed scan(s) (unobserved for {int(elapsed_seconds)}s) "
                            f"and marked Offline"
                        ),
                        conn=conn
                    )

        conn.commit()
        conn.close()

        # Step 5: Security Audit Log (Module 5)
        desc_prefix = "Executed simulated network discovery test scan." if scan_type == "simulated" else "Executed authorized network discovery."
        msg_suffix = f" Processed {devices_processed} devices ({new_devices_count} newly identified)."
        if devices_marked_offline > 0:
            msg_suffix += f" {devices_marked_offline} device(s) confirmed absent and marked Offline."
        if devices_reconnected > 0:
            msg_suffix += f" {devices_reconnected} device(s) reconnected to Online."
        
        audit_logger.log_event(
            event_type="DISCOVERY_SCAN",
            username=user,
            description=desc_prefix + msg_suffix
        )

        if scan_type == "active":
            unverified_mac_count = sum(1 for h in skipped_hosts if "Local scanning" not in h.get("reason", ""))
            excluded_local_count = sum(1 for h in skipped_hosts if "Local scanning" in h.get("reason", ""))
            details = [f"{devices_processed} imported"]
            if devices_marked_offline > 0:
                details.append(f"{devices_marked_offline} marked offline")
            if devices_reconnected > 0:
                details.append(f"{devices_reconnected} reconnected")
            if excluded_local_count > 0:
                details.append(f"{excluded_local_count} scanning host excluded")
            if unverified_mac_count > 0:
                details.append(f"{unverified_mac_count} skipped (unverified MAC)")
            message = f"Authorized discovery detected {devices_processed + len(skipped_hosts)} active hosts ({', '.join(details)})."
        else:
            sim_details = [f"{devices_processed} devices active in inventory"]
            if devices_marked_offline > 0:
                sim_details.append(f"{devices_marked_offline} marked offline")
            message = f"Successfully completed simulated network discovery test scan. {', '.join(sim_details)}."

        return {
            "status": "success",
            "devices_found": devices_processed + len(skipped_hosts) if scan_type == "active" else devices_processed,
            "devices_imported": devices_processed,
            "devices_skipped": len(skipped_hosts) if scan_type == "active" else 0,
            "new_devices_added": new_devices_count,
            "devices_marked_offline": devices_marked_offline,
            "message": message,
            "skipped_hosts": skipped_hosts if scan_type == "active" else None
        }

    def _load_seed_devices(self) -> List[Dict[str, Any]]:
        """Loads representative office IoT devices from seed data file."""
        if SEED_DEVICES_PATH.exists():
            with open(SEED_DEVICES_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def _execute_nmap_scan(self, subnet: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        import shutil
        import subprocess
        import ipaddress
        import platform
        import re
        import xml.etree.ElementTree as ET

        if not shutil.which("nmap"):
            raise ValueError("Authorized network discovery unavailable. Nmap is not installed or accessible. Smart Office Testbed mode remains available.")

        # Validate private subnet
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            if not network.is_private:
                raise ValueError("Target is not a private/authorized local network range. Public Internet scanning is restricted.")
        except ValueError as e:
            if "Target is not a private" in str(e):
                raise
            raise ValueError(f"Invalid target subnet: {subnet}")

        # Detect local machine IP and all local interface addresses (Nmap never reports MAC for scanning host)
        local_ip = None
        local_ips = set()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                local_ips.add(local_ip)
        except Exception:
            pass

        try:
            hname = socket.gethostname()
            for ip_cand in socket.gethostbyname_ex(hname)[2]:
                if not ip_cand.startswith("127."):
                    local_ips.add(ip_cand)
        except Exception:
            pass

        # Detect if running with Administrator / raw socket privileges
        is_admin = False
        if platform.system() == "Windows":
            try:
                import ctypes
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                pass
        else:
            import os
            is_admin = os.geteuid() == 0

        # Stage 1: Host discovery with bounded rate and retries for Wi-Fi reliability
        # On Windows, Npcap enables standard users to perform ARP pings without Administrator elevation.
        # Adding --max-rate prevents Wi-Fi AP broadcast packet drops, and --max-retries handles sleeping devices.
        cmd_stage1 = [
            "nmap", "-sn",
            "--max-rate", "150",
            "--max-retries", "2",
            "-oX", "-",
            str(network)
        ]

        try:
            result_s1 = subprocess.run(cmd_stage1, shell=False, capture_output=True, text=True, timeout=120)
        except subprocess.TimeoutExpired:
            raise ValueError("Stage 1 discovery scan timed out. The network might be too large or unresponsive.")
        except Exception as e:
            raise ValueError(f"Failed to execute Stage 1 Nmap: {e}")

        # If ARP discovery failed completely (e.g. missing Npcap driver), fall back to unprivileged TCP SYN/ACK
        if result_s1.returncode != 0 and not result_s1.stdout.strip():
            cmd_fallback = [
                "nmap", "-sn", "--unprivileged",
                "-PS21,22,23,80,443,554,8080,9100",
                "-PA21,22,23,80,443",
                "-oX", "-",
                str(network)
            ]
            try:
                result_s1 = subprocess.run(cmd_fallback, shell=False, capture_output=True, text=True, timeout=120)
            except Exception as e:
                raise ValueError(f"Stage 1 Nmap execution failed: {e}")

        if result_s1.returncode != 0 and not result_s1.stdout.strip():
            raise ValueError("Stage 1 Nmap execution failed. Ensure Nmap/Npcap is correctly installed and accessible.")

        stage1_hosts = []
        skipped_hosts_list = []
        discovered_ips = set()

        try:
            root_s1 = ET.fromstring(result_s1.stdout)
            for host in root_s1.findall('host'):
                status = host.find('status')
                if status is None or status.get('state') != 'up':
                    continue

                ip_addr = None
                mac_addr = None
                vendor = "Unknown"

                for address in host.findall('address'):
                    addr_type = address.get('addrtype')
                    if addr_type == 'ipv4':
                        ip_addr = address.get('addr')
                    elif addr_type == 'mac':
                        raw_mac = address.get('addr')
                        if raw_mac:
                            mac_addr = raw_mac.upper().replace("-", ":")
                        if address.get('vendor'):
                            vendor = address.get('vendor')

                hostnames_elem = host.find('hostnames')
                hostname = ""
                if hostnames_elem is not None:
                    hname = hostnames_elem.find('hostname')
                    if hname is not None:
                        hostname = hname.get('name', "")

                if not ip_addr:
                    continue

                discovered_ips.add(ip_addr)

                # Skip the local scanning computer — scanning host is excluded from IoT inventory
                if ip_addr in local_ips or (local_ip and ip_addr == local_ip):
                    skipped_hosts_list.append({
                        "ip_address": ip_addr,
                        "mac_address": mac_addr,
                        "reason": "Local scanning computer (own IP excluded from inventory import)"
                    })
                    continue

                # If MAC was not provided in Nmap XML, resolve via genuine OS neighbor/ARP fallback
                if not mac_addr:
                    mac_addr = self._resolve_mac_address(ip_addr)

                if mac_addr:
                    if vendor == "Unknown" or not vendor:
                        vendor = classifier.lookup_manufacturer(mac_addr)
                    stage1_hosts.append({
                        "ip_address": ip_addr,
                        "mac_address": mac_addr,
                        "hostname": hostname,
                        "manufacturer": vendor
                    })
                else:
                    skipped_hosts_list.append({
                        "ip_address": ip_addr,
                        "mac_address": None,
                        "reason": "MAC address unavailable (hardware MAC required for database registration)"
                    })
        except ET.ParseError:
            raise ValueError("Failed to parse Stage 1 Nmap output.")

        # Check OS ARP/neighbor cache for any active hosts in the target network that Nmap missed
        try:
            active_neighbors = self._get_active_os_neighbors()
            for n_ip, n_mac in active_neighbors.items():
                if n_ip not in discovered_ips and ipaddress.ip_address(n_ip) in network:
                    discovered_ips.add(n_ip)
                    if n_ip in local_ips or (local_ip and n_ip == local_ip):
                        skipped_hosts_list.append({
                            "ip_address": n_ip,
                            "mac_address": n_mac,
                            "reason": "Local scanning computer (own IP excluded from inventory import)"
                        })
                        continue
                    if n_mac:
                        n_vendor = classifier.lookup_manufacturer(n_mac)
                        stage1_hosts.append({
                            "ip_address": n_ip,
                            "mac_address": n_mac,
                            "hostname": "",
                            "manufacturer": n_vendor
                        })
                    else:
                        skipped_hosts_list.append({
                            "ip_address": n_ip,
                            "mac_address": None,
                            "reason": "MAC address unavailable (hardware MAC required for database registration)"
                        })
        except Exception:
            pass

        if not stage1_hosts:
            return [], skipped_hosts_list

        # Build raw_devices from Stage 1 as source of truth (every host
        # with a valid MAC discovered alive MUST enter the pipeline).
        raw_devices = []
        device_by_ip = {}
        for h in stage1_hosts:
            entry = {
                "ip_address": h["ip_address"],
                "mac_address": h["mac_address"],
                "hostname": h["hostname"],
                "manufacturer": h["manufacturer"],
                "open_ports": [],
                "services": [],
                "is_known_device": False,
                "credential_status": "Unknown",
                "security_configuration": "Unknown",
                "network_exposure": "Unknown"
            }
            raw_devices.append(entry)
            device_by_ip[h["ip_address"]] = entry

        # Stage 2: Limited Port Observation — enriches Stage 1 results,
        # never filters them. Hosts with zero open IoT ports are still kept.
        # Preserve Stage 1 host discovery results even if Stage 2 port scanning
        # times out, fails, or returns no open ports.
        target_ips = [h["ip_address"] for h in stage1_hosts]
        cmd_stage2 = [
            "nmap",
            "-T4",
            "-p", "21,22,23,80,443,554,1883,8080,9100,9999,37777",
            "-oX", "-"
        ] + target_ips

        try:
            result_s2 = subprocess.run(cmd_stage2, shell=False, capture_output=True, text=True, timeout=120)
            if result_s2.returncode == 0 and result_s2.stdout.strip():
                root_s2 = ET.fromstring(result_s2.stdout)
                for host in root_s2.findall('host'):
                    ip_addr = None
                    for address in host.findall('address'):
                        if address.get('addrtype') == 'ipv4':
                            ip_addr = address.get('addr')

                    if not ip_addr or ip_addr not in device_by_ip:
                        continue

                    # Enrich the Stage 1 entry with port/service data
                    entry = device_by_ip[ip_addr]
                    ports_elem = host.find('ports')
                    if ports_elem is not None:
                        for port in ports_elem.findall('port'):
                            state = port.find('state')
                            if state is not None and state.get('state') == 'open':
                                port_id = int(port.get('portid'))
                                entry["open_ports"].append(port_id)
                                service = port.find('service')
                                if service is not None and service.get('name'):
                                    entry["services"].append(service.get('name'))
        except Exception:
            # Stage 2 port scanning failed or timed out — preserve Stage 1 host discovery results
            pass

        return raw_devices, skipped_hosts_list

    @staticmethod
    def _is_valid_mac(mac: str) -> bool:
        import re
        if not mac:
            return False
        clean = mac.strip().upper().replace("-", ":")
        if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', clean):
            return False
        parts = clean.split(":")
        if all(p == "00" for p in parts) or all(p == "FF" for p in parts):
            return False
        # Exclude Ethernet multicast / IPv6 multicast prefixes
        if parts[0] in ("01", "33"):
            return False
        return True

    @classmethod
    def _get_active_os_neighbors(cls) -> Dict[str, str]:
        """
        Retrieves active IP-to-MAC mappings from the genuine OS neighbor / ARP table.
        Does not fabricate any addresses.
        """
        import platform
        import subprocess
        import re

        neighbors = {}

        if platform.system() == "Windows":
            # Tier A: Win32 GetIpNetTable (in-kernel table)
            try:
                import ctypes
                from ctypes import wintypes
                import socket
                import struct

                class MIB_IPNETROW(ctypes.Structure):
                    _fields_ = [
                        ('dwIndex', wintypes.DWORD),
                        ('dwPhysAddrLen', wintypes.DWORD),
                        ('bPhysAddr', ctypes.c_byte * 8),
                        ('dwAddr', wintypes.DWORD),
                        ('dwType', wintypes.DWORD),
                    ]

                size = wintypes.ULONG(0)
                ctypes.windll.iphlpapi.GetIpNetTable(None, ctypes.byref(size), False)
                if size.value > 0:
                    buf = ctypes.create_string_buffer(size.value)
                    if ctypes.windll.iphlpapi.GetIpNetTable(buf, ctypes.byref(size), False) == 0:
                        num_entries = struct.unpack('<I', buf.raw[:4])[0]
                        offset = 4
                        row_size = ctypes.sizeof(MIB_IPNETROW)
                        for _ in range(num_entries):
                            row = MIB_IPNETROW.from_buffer_copy(buf.raw[offset:offset + row_size])
                            offset += row_size
                            if row.dwPhysAddrLen == 6 and row.dwType != 2:
                                ip = socket.inet_ntoa(struct.pack('<I', row.dwAddr))
                                mac = ':'.join(f'{row.bPhysAddr[j] & 0xff:02X}' for j in range(6))
                                if cls._is_valid_mac(mac):
                                    neighbors[ip] = mac
            except Exception:
                pass

            # Tier B: Windows arp -a table parser
            try:
                out = subprocess.check_output(["arp", "-a"], text=True, timeout=5, errors="ignore")
                for line in out.splitlines():
                    m = re.match(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})', line)
                    if m:
                        ip, mac = m.group(1), m.group(2).upper().replace("-", ":")
                        if cls._is_valid_mac(mac) and ip not in neighbors:
                            neighbors[ip] = mac
            except Exception:
                pass
        else:
            # Linux /proc/net/arp
            try:
                with open("/proc/net/arp", "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4:
                            ip, mac = parts[0], parts[3].upper().replace("-", ":")
                            if cls._is_valid_mac(mac):
                                neighbors[ip] = mac
            except Exception:
                pass

        return neighbors

    @classmethod
    def _resolve_mac_address(cls, ip_str: str) -> Optional[str]:
        """
        Safe, multi-tiered MAC address retrieval using genuine OS neighbor/ARP information.
        Never fabricates or substitutes random values. Returns normalized XX:XX:XX:XX:XX:XX or None.
        """
        import platform
        import subprocess
        import re

        # Tier 0: Check existing active OS neighbor cache
        try:
            cached = cls._get_active_os_neighbors()
            if ip_str in cached and cls._is_valid_mac(cached[ip_str]):
                return cached[ip_str]
        except Exception:
            pass

        # Tier 1 (Windows): Win32 SendARP (direct OS ARP request to local subnet)
        if platform.system() == "Windows":
            try:
                import ctypes
                import socket
                import struct
                p_send_arp = ctypes.windll.iphlpapi.SendARP
                p_send_arp.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
                p_send_arp.restype = ctypes.c_ulong
                mac_buf = (ctypes.c_byte * 6)()
                mac_len = ctypes.c_ulong(6)
                dest_ip = struct.unpack('=I', socket.inet_aton(ip_str))[0]
                ret = p_send_arp(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
                if ret == 0 and mac_len.value == 6:
                    mac_str = ':'.join(f'{b & 0xff:02X}' for b in mac_buf)
                    if cls._is_valid_mac(mac_str):
                        return mac_str

                # If initial SendARP missed (e.g. Wi-Fi power save), trigger OS neighbor resolution and retry
                subprocess.run(["ping", "-n", "1", "-w", "500", ip_str], capture_output=True, timeout=2)
                mac_len = ctypes.c_ulong(6)
                ret = p_send_arp(dest_ip, 0, ctypes.byref(mac_buf), ctypes.byref(mac_len))
                if ret == 0 and mac_len.value == 6:
                    mac_str = ':'.join(f'{b & 0xff:02X}' for b in mac_buf)
                    if cls._is_valid_mac(mac_str):
                        return mac_str
            except Exception:
                pass

        # Tier 2 (Windows): Re-check neighbor table after ping
        try:
            cached = cls._get_active_os_neighbors()
            if ip_str in cached and cls._is_valid_mac(cached[ip_str]):
                return cached[ip_str]
        except Exception:
            pass

        # Tier 3 (Windows): PowerShell Get-NetNeighbor query
        if platform.system() == "Windows":
            try:
                ps_cmd = [
                    "powershell", "-NoProfile", "-NonInteractive", "-Command",
                    f"(Get-NetNeighbor -IPAddress '{ip_str}' -ErrorAction SilentlyContinue | Where-Object {{ $_.State -ne 'Unreachable' -and $_.LinkLayerAddress -match '^[0-9a-fA-F]{{2}}[:-]' }}).LinkLayerAddress"
                ]
                out = subprocess.check_output(ps_cmd, text=True, timeout=5, errors="ignore").strip()
                for line in out.splitlines():
                    cand = line.strip().upper().replace("-", ":")
                    if cls._is_valid_mac(cand):
                        return cand
            except Exception:
                pass

        # Tier 4 (Windows / Unix): System arp utility
        try:
            cmd = ["arp", "-a", ip_str] if platform.system() == "Windows" else ["arp", "-n", ip_str]
            out = subprocess.check_output(cmd, text=True, timeout=5, errors="ignore")
            for line in out.splitlines():
                if ip_str in line:
                    match = re.search(r'([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})', line)
                    if match:
                        cand = match.group(1).upper().replace("-", ":")
                        if cls._is_valid_mac(cand):
                            return cand
        except Exception:
            pass

        # Tier 5 (Linux): /proc/net/arp
        if platform.system() != "Windows":
            try:
                with open("/proc/net/arp", "r", encoding="utf-8") as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 4 and parts[0] == ip_str:
                            cand = parts[3].upper().replace("-", ":")
                            if cls._is_valid_mac(cand):
                                return cand
            except Exception:
                pass

        return None

discovery_service = DeviceDiscoveryService()

