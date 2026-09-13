import json
from typing import Tuple, List, Optional
from backend.app.config import OUI_DB_PATH

class DeviceClassifier:
    """
    Device Classification Module (Chapters 3.5, 4.2.2, 6.6)
    Uses IEEE MAC OUI lookup and rule-based network characteristics (ports, hostnames, services)
    to categorize devices into office IoT categories or 'Unknown Device'.
    """

    def __init__(self):
        self.oui_db = self._load_oui_database()

    def _load_oui_database(self) -> dict:
        try:
            if OUI_DB_PATH.exists():
                with open(OUI_DB_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def lookup_manufacturer(self, mac_address: str) -> str:
        """Extracts the first 3 octets (OUI) and queries vendor database."""
        if not mac_address or len(mac_address) < 8:
            return "Unknown"
        
        # Normalize MAC formatting to XX:XX:XX
        clean_mac = mac_address.upper().replace("-", ":")
        oui_prefix = ":".join(clean_mac.split(":")[:3])
        return self.oui_db.get(oui_prefix, "Unknown Manufacturer")

    def classify_device(self, mac_address: str, hostname: Optional[str] = "", 
                        open_ports: Optional[List[int]] = None, 
                        services: Optional[List[str]] = None) -> Tuple[str, str]:
        """
        Rule-based classifier returning (device_type, manufacturer).
        Supported Categories:
        - CCTV Camera
        - Printer
        - Smart Lock
        - Sensor
        - Smart Plug
        - Network Device
        - Unknown Device
        """
        manufacturer = self.lookup_manufacturer(mac_address)
        open_ports = open_ports or []
        services = services or []
        hostname_lower = (hostname or "").lower()
        services_str = " ".join(services).lower()

        # Rule 1: CCTV Camera detection
        # Characteristics: Port 554 (RTSP), 37777 (Dahua), Dahua/Hikvision/Axis OUI, or 'cam' in hostname
        if 554 in open_ports or 37777 in open_ports or "rtsp" in services_str:
            return "CCTV Camera", manufacturer
        if "cam" in hostname_lower or "dvr" in hostname_lower or "nvr" in hostname_lower:
            return "CCTV Camera", manufacturer
        if any(v in manufacturer.lower() for v in ["dahua", "hikvision", "axis"]):
            return "CCTV Camera", manufacturer

        # Rule 2: Printer detection
        # Characteristics: Port 9100 (JetDirect), 631 (IPP), 515 (LPD), HP/Canon/Epson OUI, or 'printer'/'print' in hostname
        if 9100 in open_ports or 631 in open_ports or 515 in open_ports or "ipp" in services_str or "jetdirect" in services_str:
            return "Printer", manufacturer
        if "printer" in hostname_lower or "print" in hostname_lower or "mfp" in hostname_lower:
            return "Printer", manufacturer
        if any(v in manufacturer.lower() for v in ["canon", "epson", "xerox", "brother"]):
            return "Printer", manufacturer

        # Rule 3: Smart Lock detection
        # Characteristics: Assa Abloy/Yale/August OUI, or 'lock' in hostname
        if any(v in manufacturer.lower() for v in ["assa abloy", "yale", "august"]):
            return "Smart Lock", manufacturer
        if "lock" in hostname_lower or "door" in hostname_lower or "badge" in hostname_lower:
            return "Smart Lock", manufacturer

        # Rule 4: Smart Plug detection
        # Characteristics: Port 9999 (TP-Link Kasa smart plug protocol), 'plug' in hostname
        if 9999 in open_ports or "plug" in hostname_lower or "kasa" in hostname_lower:
            return "Smart Plug", manufacturer

        # Rule 5: Sensor detection
        # Characteristics: Shelly/Xiaomi environmental sensor, Port 1883 (MQTT), or sensor keywords
        if "shelly" in manufacturer.lower() or "sensor" in hostname_lower or "temp" in hostname_lower or "hvac" in hostname_lower:
            return "Sensor", manufacturer
        if 1883 in open_ports or "mqtt" in services_str:
            return "Sensor", manufacturer

        # Rule 6: Network Infrastructure Device detection
        # Characteristics: Cisco, Ubiquiti, router/AP hostnames, or gateway IPs
        if any(v in manufacturer.lower() for v in ["cisco", "ubiquiti"]):
            return "Network Device", manufacturer
        if "ap-" in hostname_lower or "switch" in hostname_lower or "router" in hostname_lower:
            return "Network Device", manufacturer

        # Fallback: When insufficient evidence is present (Chapter 4.2.2)
        return "Unknown Device", manufacturer

# Singleton instance
classifier = DeviceClassifier()
