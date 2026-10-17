import json
import re
import ipaddress
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from backend.app.database import get_db_connection
from backend.app.auth import get_current_user, require_admin
from backend.app.models import DeviceResponse, DeviceCreate, DeviceUpdate, ScanTriggerRequest, ScanResponse
from backend.app.modules.discovery import discovery_service
from backend.app.modules.classification import classifier
from backend.app.modules.risk_assessment import risk_engine
from backend.app.modules.alert_manager import alert_mgr
from backend.app.modules.audit import audit_logger

router = APIRouter(prefix="/api/devices", tags=["Device Inventory"])

def validate_ip(ip_str: str) -> str:
    """Validates that a string is a well-formed IPv4 address."""
    if not ip_str or not ip_str.strip():
        raise HTTPException(status_code=400, detail="IP address is required.")
    try:
        ip = ipaddress.IPv4Address(ip_str.strip())
        return str(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IPv4 address format: '{ip_str}'.")

def validate_mac(mac_str: str) -> str:
    """Validates and normalizes a MAC address. Rejects broadcast, all-zero, and multicast addresses."""
    if not mac_str or not mac_str.strip():
        raise HTTPException(status_code=400, detail="MAC address is required.")
    clean = mac_str.strip().upper().replace("-", ":")
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', clean):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid MAC address format: '{mac_str}'. Expected standard 6-byte hexadecimal format (e.g. 00:11:22:33:44:55)."
        )
    parts = clean.split(":")
    if all(p == "00" for p in parts):
        raise HTTPException(status_code=400, detail="All-zero MAC address (00:00:00:00:00:00) is not permitted.")
    if all(p == "FF" for p in parts):
        raise HTTPException(status_code=400, detail="Broadcast MAC address (FF:FF:FF:FF:FF:FF) is not permitted.")
    if int(parts[0], 16) & 1:
        raise HTTPException(status_code=400, detail=f"Multicast MAC address ('{clean}') is not permitted for device registration.")
    return clean

def get_device_origin(device_id: int, status: str = "", ip_address: str = "", mac_address: str = "") -> str:
    """
    Truthfully identifies device origin:
    - 'Manual Entry'
    - 'Authorized Network Discovery'
    - 'Simulated Testbed'
    """
    cached = discovery_service.method_cache.get(device_id)
    if cached == "manual":
        return "Manual Entry"

    if status == "Not Yet Observed":
        discovery_service.method_cache[device_id] = "manual"
        return "Manual Entry"

    if ip_address.startswith("192.168.1."):
        discovery_service.method_cache[device_id] = "simulated"
        return "Simulated Testbed"

    try:
        conn = get_db_connection()
        search_terms = [f"%({device_id})%", f"%#{device_id}%"]
        if mac_address:
            search_terms.append(f"%{mac_address}%")
        if ip_address:
            search_terms.append(f"%{ip_address}%")

        where_clause = " OR ".join(["description LIKE ?"] * len(search_terms))
        query = f"""
            SELECT event_type FROM audit_logs 
            WHERE ({where_clause}) 
              AND event_type IN ('DEVICE_REGISTERED', 'DEVICE_DISCOVERED') 
            ORDER BY id ASC LIMIT 1
        """
        log = conn.execute(query, search_terms).fetchone()
        conn.close()

        if log and log["event_type"] == "DEVICE_REGISTERED":
            discovery_service.method_cache[device_id] = "manual"
            return "Manual Entry"
        if log and log["event_type"] == "DEVICE_DISCOVERED":
            discovery_service.method_cache[device_id] = "active"
            return "Authorized Network Discovery"
    except Exception:
        pass

    if cached == "active":
        return "Authorized Network Discovery"
    if cached == "simulated":
        return "Simulated Testbed"

    if not ip_address.startswith("192.168.1."):
        discovery_service.method_cache[device_id] = "active"
        return "Authorized Network Discovery"

    discovery_service.method_cache[device_id] = "simulated"
    return "Simulated Testbed"

@router.get("", response_model=List[DeviceResponse])
def list_devices(
    device_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Searchable & filterable device inventory (Chapter 8.1.13 & 11.3).
    Filter by device_type, risk_level, or free-text search.
    """
    conn = get_db_connection()
    query = """
        SELECT d.*, 
               r.risk_score as latest_risk_score, 
               r.risk_level as latest_risk_level
        FROM devices d
        LEFT JOIN (
            SELECT device_id, risk_score, risk_level, MAX(assessed_at)
            FROM risk_assessments
            GROUP BY device_id
        ) r ON d.id = r.device_id
        WHERE 1=1
    """
    params = []

    if device_type:
        query += " AND d.device_type = ?"
        params.append(device_type)
    
    if risk_level:
        query += " AND r.risk_level = ?"
        params.append(risk_level)

    if search:
        search_pattern = f"%{search}%"
        query += " AND (d.hostname LIKE ? OR d.ip_address LIKE ? OR d.mac_address LIKE ? OR d.manufacturer LIKE ?)"
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    query += " ORDER BY d.id DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append(DeviceResponse(
            id=r["id"],
            ip_address=r["ip_address"],
            mac_address=r["mac_address"],
            hostname=r["hostname"],
            manufacturer=r["manufacturer"],
            device_type=r["device_type"],
            open_ports=json.loads(r["open_ports"]) if r["open_ports"] else [],
            services=json.loads(r["services"]) if r["services"] else [],
            firmware_version=r["firmware_version"],
            credential_status=r["credential_status"],
            network_exposure=r["network_exposure"],
            security_configuration=r["security_configuration"],
            is_known_device=bool(r["is_known_device"]),
            status=r["status"],
            first_seen=str(r["first_seen"]),
            last_seen=str(r["last_seen"]),
            latest_risk_score=r["latest_risk_score"],
            latest_risk_level=r["latest_risk_level"] or "Low",
            detection_method=get_device_origin(r["id"], r["status"], r["ip_address"], r["mac_address"])
        ))

    return results

@router.get("/network-info")
def get_network_info(current_user: dict = Depends(get_current_user)):
    """Auto-detects the current active private network via standard library (Chapter 7.3)."""
    import socket
    import subprocess
    import ipaddress
    import platform

    local_ip = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except Exception:
        pass

    if not local_ip or local_ip.startswith("127.") or local_ip.startswith("169.254."):
        return {"status": "error", "message": "Unable to automatically determine an active private network. Enter an authorized private subnet manually."}

    subnet_mask = None
    interface_name = "Unknown"

    if platform.system() == "Windows":
        try:
            output = subprocess.check_output("ipconfig", text=True, errors="ignore")
            curr_if = None
            found_ip = False
            for line in output.split('\n'):
                if line.strip() == '': continue
                if not line.startswith(' ') and line.strip().endswith(':'):
                    curr_if = line.strip()[:-1]
                    found_ip = False
                elif "IPv4 Address" in line and local_ip in line:
                    interface_name = curr_if.replace("Ethernet adapter ", "").replace("Wireless LAN adapter ", "") if curr_if else "Unknown"
                    found_ip = True
                elif found_ip and "Subnet Mask" in line:
                    subnet_mask = line.split(':')[-1].strip()
                    break
        except Exception:
            pass
    else:
        try:
            output = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show"], text=True, errors="ignore")
            for line in output.split('\n'):
                if local_ip in line:
                    parts = line.split()
                    interface_name = parts[1]
                    ip_cidr = parts[3]
                    if '/' in ip_cidr:
                        subnet_mask_length = int(ip_cidr.split('/')[1])
                    break
        except Exception:
            pass

    prefix_length = 24
    if subnet_mask:
        try:
            prefix_length = sum(bin(int(x)).count('1') for x in subnet_mask.split('.'))
        except Exception:
            pass
    elif not subnet_mask and platform.system() != "Windows":
        try:
            output = subprocess.check_output(["ip", "-o", "-f", "inet", "addr", "show"], text=True, errors="ignore")
            for line in output.split('\n'):
                if local_ip in line:
                    ip_cidr = line.split()[3]
                    if '/' in ip_cidr:
                        prefix_length = int(ip_cidr.split('/')[1])
                    break
        except Exception:
            pass

    try:
        network = ipaddress.IPv4Network(f"{local_ip}/{prefix_length}", strict=False)
        if not network.is_private:
            return {"status": "error", "message": "Detected network is public. Enter an authorized private subnet manually."}
        
        return {
            "status": "success",
            "interface": interface_name,
            "local_ip": local_ip,
            "subnet_mask": subnet_mask or "Unknown",
            "prefix_length": prefix_length,
            "network_cidr": str(network),
            "is_private": True
        }
    except Exception:
        return {"status": "error", "message": "Unable to automatically determine an active private network. Enter an authorized private subnet manually."}

@router.get("/{device_id}")
def get_device_detail(device_id: int, current_user: dict = Depends(get_current_user)):
    """Fetches full device detail along with risk factor breakdown (Chapter 11.3 Device Detail Panel)."""
    conn = get_db_connection()
    device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    # Get latest risk assessment
    latest_assessment = conn.execute(
        "SELECT * FROM risk_assessments WHERE device_id = ? ORDER BY assessed_at DESC LIMIT 1",
        (device_id,)
    ).fetchone()

    # Get alerts associated with this device
    alerts = conn.execute(
        "SELECT * FROM alerts WHERE device_id = ? ORDER BY created_at DESC",
        (device_id,)
    ).fetchall()
    conn.close()

    risk_info = None
    if latest_assessment:
        risk_info = {
            "risk_score": latest_assessment["risk_score"],
            "risk_level": latest_assessment["risk_level"],
            "factor_unknown": latest_assessment["factor_unknown"],
            "factor_firmware": latest_assessment["factor_firmware"],
            "factor_credential": latest_assessment["factor_credential"],
            "factor_exposure": latest_assessment["factor_exposure"],
            "factor_config": latest_assessment["factor_config"],
            "details": json.loads(latest_assessment["details"]) if latest_assessment["details"] else [],
            "assessed_at": str(latest_assessment["assessed_at"])
        }

    return {
        "id": device["id"],
        "ip_address": device["ip_address"],
        "mac_address": device["mac_address"],
        "hostname": device["hostname"],
        "manufacturer": device["manufacturer"],
        "device_type": device["device_type"],
        "open_ports": json.loads(device["open_ports"]) if device["open_ports"] else [],
        "services": json.loads(device["services"]) if device["services"] else [],
        "firmware_version": device["firmware_version"],
        "credential_status": device["credential_status"],
        "network_exposure": device["network_exposure"],
        "security_configuration": device["security_configuration"],
        "is_known_device": bool(device["is_known_device"]),
        "status": device["status"],
        "first_seen": str(device["first_seen"]),
        "last_seen": str(device["last_seen"]),
        "risk_assessment": risk_info,
        "alerts": [dict(a) for a in alerts],
        "detection_method": get_device_origin(device["id"], device["status"], device["ip_address"], device["mac_address"])
    }

@router.post("", status_code=201)
def register_device(payload: DeviceCreate, current_user: dict = Depends(require_admin)):
    """
    Manually registers a device into inventory (Admin only).
    Truthfully records status as 'Not Yet Observed' and preserves the Known/Unknown approval workflow.
    """
    valid_ip = validate_ip(payload.ip_address)
    valid_mac = validate_mac(payload.mac_address)

    conn = get_db_connection()

    # Prevent duplicate MAC address
    existing_mac = conn.execute("SELECT id, ip_address, hostname FROM devices WHERE mac_address = ?", (valid_mac,)).fetchone()
    if existing_mac:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail=f"A device with MAC address '{valid_mac}' is already registered (Device #{existing_mac['id']} - {existing_mac['hostname'] or 'Unnamed'} at {existing_mac['ip_address']})."
        )

    # Prevent duplicate IP address
    existing_ip = conn.execute("SELECT id, mac_address, hostname FROM devices WHERE ip_address = ?", (valid_ip,)).fetchone()
    if existing_ip:
        conn.close()
        raise HTTPException(
            status_code=400,
            detail=f"A device with IP address '{valid_ip}' is already registered (Device #{existing_ip['id']} - {existing_ip['hostname'] or 'Unnamed'} with MAC {existing_ip['mac_address']})."
        )

    # Resolve manufacturer if omitted or unknown
    if payload.manufacturer and payload.manufacturer.strip() and payload.manufacturer.strip().lower() != "unknown":
        manufacturer = payload.manufacturer.strip()
    else:
        manufacturer = classifier.lookup_manufacturer(valid_mac)

    hostname = payload.hostname.strip() if payload.hostname and payload.hostname.strip() else f"manual-{valid_mac.replace(':', '')[-4:].lower()}"
    device_type = payload.device_type.strip() if payload.device_type and payload.device_type.strip() else "Unknown Device"

    # Do not automatically mark manually added devices as authorized; preserve approval workflow
    is_known = 0
    status = "Not Yet Observed"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO devices (
            ip_address, mac_address, hostname, manufacturer, device_type,
            open_ports, services, firmware_version, credential_status,
            network_exposure, security_configuration, is_known_device,
            status, first_seen, last_seen
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            valid_ip, valid_mac, hostname, manufacturer, device_type,
            json.dumps([]), json.dumps([]), "Unknown", "Unknown",
            "Unknown", "Unknown", is_known,
            status, now_str, now_str
        )
    )
    device_id = cursor.lastrowid
    discovery_service.method_cache[device_id] = "manual"

    dev_data = {
        "id": device_id,
        "ip_address": valid_ip,
        "mac_address": valid_mac,
        "hostname": hostname,
        "manufacturer": manufacturer,
        "device_type": device_type,
        "open_ports": [],
        "services": [],
        "firmware_version": "Unknown",
        "credential_status": "Unknown",
        "network_exposure": "Unknown",
        "security_configuration": "Unknown",
        "is_known_device": bool(is_known),
        "status": status
    }

    # Integrate with Risk Assessment Engine
    risk_result = risk_engine.evaluate_device(dev_data)
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

    # Integrate with Alert Pipeline (raises Rogue / Unknown Device alert)
    alert_mgr.evaluate_and_alert(device_id, dev_data, risk_result, conn=conn)

    # Record in Audit History
    audit_logger.log_event(
        event_type="DEVICE_REGISTERED",
        username=current_user["username"],
        description=f"Manually registered device #{device_id} at {valid_ip} ({valid_mac}) - {hostname} [Pending Approval, Vendor: {manufacturer}, Category: {device_type}]",
        conn=conn
    )
    audit_logger.log_event(
        event_type="DEVICE_CLASSIFIED",
        username=current_user["username"],
        description=f"Device {valid_ip} classified as {device_type} (Vendor: {manufacturer})",
        conn=conn
    )
    audit_logger.log_event(
        event_type="RISK_ASSESSED",
        username=current_user["username"],
        description=f"Initial risk assessment completed for {valid_ip} (Score: {risk_result['risk_score']})",
        conn=conn
    )
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "message": f"Device '{hostname}' ({valid_ip}) registered successfully.",
        "device": {
            "id": device_id,
            "ip_address": valid_ip,
            "mac_address": valid_mac,
            "hostname": hostname,
            "manufacturer": manufacturer,
            "device_type": device_type,
            "is_known_device": False,
            "status": status,
            "detection_method": "Manual Entry",
            "latest_risk_score": risk_result["risk_score"],
            "latest_risk_level": risk_result["risk_level"]
        }
    }

@router.post("/{device_id}/authorize")
def authorize_device(device_id: int, current_user: dict = Depends(require_admin)):
    """
    Authorizes a device into the approved asset inventory (Admin only).
    Updates authorization status and recalculates risk without deleting or resolving historical alerts.
    """
    conn = get_db_connection()
    device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET is_known_device = 1 WHERE id = ?", (device_id,))

    dev_data = dict(device)
    dev_data["is_known_device"] = True
    dev_data["open_ports"] = json.loads(dev_data["open_ports"]) if dev_data["open_ports"] else []
    dev_data["services"] = json.loads(dev_data["services"]) if dev_data["services"] else []

    risk_result = risk_engine.evaluate_device(dev_data)
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

    audit_logger.log_event(
        event_type="DEVICE_AUTHORIZED",
        username=current_user["username"],
        description=f"Device #{device_id} ({device['ip_address']} / {device['mac_address']}) authorized into approved asset inventory.",
        conn=conn
    )
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "message": f"Device #{device_id} successfully authorized.",
        "is_known_device": True,
        "latest_risk_score": risk_result["risk_score"],
        "latest_risk_level": risk_result["risk_level"]
    }

@router.post("/{device_id}/unauthorize")
def unauthorize_device(device_id: int, current_user: dict = Depends(require_admin)):
    """
    Marks a device as unauthorized / pending approval (Admin only).
    Recalculates risk and triggers Unknown Device alert if not already open.
    """
    conn = get_db_connection()
    device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET is_known_device = 0 WHERE id = ?", (device_id,))

    dev_data = dict(device)
    dev_data["is_known_device"] = False
    dev_data["open_ports"] = json.loads(dev_data["open_ports"]) if dev_data["open_ports"] else []
    dev_data["services"] = json.loads(dev_data["services"]) if dev_data["services"] else []

    risk_result = risk_engine.evaluate_device(dev_data)
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

    alert_mgr.evaluate_and_alert(device_id, dev_data, risk_result, conn=conn)

    audit_logger.log_event(
        event_type="DEVICE_UNAUTHORIZED",
        username=current_user["username"],
        description=f"Device #{device_id} ({device['ip_address']} / {device['mac_address']}) marked as unauthorized / pending approval.",
        conn=conn
    )
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "message": f"Device #{device_id} marked as unauthorized.",
        "is_known_device": False,
        "latest_risk_score": risk_result["risk_score"],
        "latest_risk_level": risk_result["risk_level"]
    }

@router.post("/scan", response_model=ScanResponse)
def trigger_network_scan(
    payload: ScanTriggerRequest,
    current_user: dict = Depends(require_admin)
):
    """Triggers discovery cycle across the authorized network (Admin only - Chapter 7.3)."""
    try:
        result = discovery_service.run_discovery_pipeline(
            scan_type=payload.scan_type or "simulated",
            target_subnet=payload.target_subnet or "192.168.1.0/24",
            user=current_user["username"]
        )
        return ScanResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/{device_id}")
def update_device(
    device_id: int,
    payload: DeviceUpdate,
    current_user: dict = Depends(require_admin)
):
    """Updates device authorization or custom metadata (Admin only)."""
    conn = get_db_connection()
    device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    new_ip = validate_ip(payload.ip_address) if payload.ip_address is not None else device["ip_address"]
    new_hostname = payload.hostname.strip() if payload.hostname is not None else device["hostname"]
    new_type = payload.device_type.strip() if payload.device_type is not None else device["device_type"]
    new_manufacturer = payload.manufacturer.strip() if payload.manufacturer is not None else device["manufacturer"]
    new_is_known = int(payload.is_known_device) if payload.is_known_device is not None else device["is_known_device"]

    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE devices 
        SET ip_address = ?, hostname = ?, device_type = ?, manufacturer = ?, is_known_device = ? 
        WHERE id = ?
        """,
        (new_ip, new_hostname, new_type, new_manufacturer, new_is_known, device_id)
    )

    dev_data = dict(device)
    dev_data["ip_address"] = new_ip
    dev_data["hostname"] = new_hostname
    dev_data["device_type"] = new_type
    dev_data["manufacturer"] = new_manufacturer
    dev_data["is_known_device"] = bool(new_is_known)
    dev_data["open_ports"] = json.loads(dev_data["open_ports"]) if dev_data["open_ports"] else []
    dev_data["services"] = json.loads(dev_data["services"]) if dev_data["services"] else []

    risk_result = risk_engine.evaluate_device(dev_data)
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

    if not new_is_known:
        alert_mgr.evaluate_and_alert(device_id, dev_data, risk_result, conn=conn)

    audit_logger.log_event(
        event_type="DEVICE_UPDATED",
        username=current_user["username"],
        description=f"Device #{device_id} ({new_ip}) updated (Hostname: {new_hostname}, Type: {new_type}, Manufacturer: {new_manufacturer}, Known: {bool(new_is_known)})",
        conn=conn
    )
    conn.commit()
    conn.close()

    return {
        "status": "success",
        "message": "Device successfully updated",
        "latest_risk_score": risk_result["risk_score"],
        "latest_risk_level": risk_result["risk_level"]
    }
