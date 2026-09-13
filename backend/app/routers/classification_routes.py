import json
from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from backend.app.database import get_db_connection
from backend.app.auth import get_current_user
from backend.app.modules.classification import classifier

router = APIRouter(prefix="/api/classification", tags=["Device Classification"])

@router.get("/rules")
def get_classification_rules(current_user: dict = Depends(get_current_user)):
    """Returns the rule-based classification criteria defined in Chapter 6.6 & 7.4."""
    return [
        {
            "category": "CCTV Camera",
            "oui_vendors": ["Dahua Technology", "Hikvision", "Axis Communications"],
            "ports_services": [554, 37777, "RTSP", "DVR protocol"],
            "hostname_patterns": ["cam", "dvr", "nvr"],
            "description": "Video surveillance feeds and IP security cameras."
        },
        {
            "category": "Printer",
            "oui_vendors": ["HP Inc.", "Canon Inc.", "Epson", "Xerox", "Brother"],
            "ports_services": [9100, 631, 515, "IPP", "JetDirect"],
            "hostname_patterns": ["printer", "print", "mfp"],
            "description": "Networked office multifunction and document printers."
        },
        {
            "category": "Smart Lock",
            "oui_vendors": ["Assa Abloy (Yale)", "August Home Inc."],
            "ports_services": [443, "HTTPS API"],
            "hostname_patterns": ["lock", "door", "badge"],
            "description": "Smart door locks and physical access control units."
        },
        {
            "category": "Sensor",
            "oui_vendors": ["Shelly / Allterco", "Xiaomi Communications"],
            "ports_services": [1883, "MQTT", 80],
            "hostname_patterns": ["sensor", "temp", "hvac", "humidity"],
            "description": "Environmental, temperature, and IoT telemetry sensors."
        },
        {
            "category": "Smart Plug",
            "oui_vendors": ["TP-Link Corporation"],
            "ports_services": [9999, "Kasa Protocol"],
            "hostname_patterns": ["plug", "kasa"],
            "description": "Smart plugs and networked power control outlets."
        },
        {
            "category": "Network Device",
            "oui_vendors": ["Cisco Systems", "Ubiquiti Inc."],
            "ports_services": [22, 443, 161, "SSH", "SNMP"],
            "hostname_patterns": ["ap-", "switch", "router"],
            "description": "Access points, switches, and gateway network hardware."
        },
        {
            "category": "Unknown Device",
            "oui_vendors": ["Any / Unregistered"],
            "ports_services": ["Any"],
            "hostname_patterns": ["Any"],
            "description": "Devices lacking conclusive OUI or service signatures (Shadow IoT)."
        }
    ]

@router.get("/devices")
def get_classified_devices(current_user: dict = Depends(get_current_user)):
    """
    Returns devices with classification analysis:
    - Extracted MAC OUI prefix
    - Manufacturer lookup result
    - Triggered classification rule
    - Device type and confidence
    """
    conn = get_db_connection()
    devices = conn.execute("SELECT * FROM devices ORDER BY id ASC").fetchall()
    conn.close()

    results = []
    for d in devices:
        mac = d["mac_address"] or ""
        clean_mac = mac.upper().replace("-", ":")
        oui_prefix = ":".join(clean_mac.split(":")[:3]) if len(clean_mac.split(":")) >= 3 else "N/A"
        
        open_ports = json.loads(d["open_ports"]) if d["open_ports"] else []
        services = json.loads(d["services"]) if d["services"] else []
        hostname = d["hostname"] or ""
        manufacturer = d["manufacturer"] or "Unknown"
        device_type = d["device_type"] or "Unknown Device"

        # Determine explanation of why this rule was chosen
        rationale = []
        if oui_prefix in classifier.oui_db:
            rationale.append(f"OUI prefix '{oui_prefix}' matches {manufacturer}")
        else:
            rationale.append(f"OUI prefix '{oui_prefix}' not in IEEE vendor list")

        if 554 in open_ports or 37777 in open_ports:
            rationale.append("RTSP / Surveillance port active")
        if 9100 in open_ports or 631 in open_ports:
            rationale.append("JetDirect/IPP printing port active")
        if 9999 in open_ports:
            rationale.append("Port 9999 (Smart Home protocol)")
        if 1883 in open_ports or "sensor" in hostname.lower():
            rationale.append("Sensor telemetry signature")
        if any(h in hostname.lower() for h in ["ap-", "switch", "router"]):
            rationale.append("Network infrastructure hostname match")

        confidence = "High (OUI + Port Match)" if len(rationale) >= 2 else ("Moderate (Rule Match)" if device_type != "Unknown Device" else "Low (Unrecognized)")

        results.append({
            "id": d["id"],
            "hostname": hostname,
            "ip_address": d["ip_address"],
            "mac_address": mac,
            "oui_prefix": oui_prefix,
            "manufacturer": manufacturer,
            "device_type": device_type,
            "open_ports": open_ports,
            "services": services,
            "rationale": " & ".join(rationale),
            "confidence": confidence,
            "status": d["status"]
        })

    return results
