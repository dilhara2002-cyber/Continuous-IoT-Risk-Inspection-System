from typing import Optional, Dict, Any
from backend.app.database import get_db_connection
from backend.app.modules.audit import audit_logger

class AlertManager:
    """
    Alert Management Module (Chapters 4.6, 7.6, 11.4)
    Evaluates discovered devices and risk assessments to create security alerts for:
    - Newly discovered / Unknown devices (Shadow IoT)
    - Devices classified as High Risk
    - Default credentials detected
    - Disconnected / Tampered devices
    """

    @staticmethod
    def create_alert(device_id: Optional[int], alert_type: str, severity: str, 
                     title: str, description: str, notify_email: bool = False,
                     conn: Optional[Any] = None) -> int:
        """Records an alert in the persistent SQLite database."""
        should_close = False
        if conn is None:
            conn = get_db_connection()
            should_close = True

        cursor = conn.cursor()

        # Duplicate Prevention
        if device_id is not None:
            auth_alert_types = {
                "Unknown Device",
                "Unauthorized Device",
                "Unrecognized Device Type",
                "Unauthorized & Unrecognized Device"
            }
            if alert_type in auth_alert_types:
                existing = cursor.execute(
                    """
                    SELECT id FROM alerts 
                    WHERE device_id = ? 
                      AND alert_type IN ('Unknown Device', 'Unauthorized Device', 'Unrecognized Device Type', 'Unauthorized & Unrecognized Device') 
                      AND is_resolved = 0
                    """,
                    (device_id,)
                ).fetchone()
            else:
                existing = cursor.execute(
                    "SELECT id FROM alerts WHERE device_id = ? AND alert_type = ? AND is_resolved = 0",
                    (device_id, alert_type)
                ).fetchone()

            if existing:
                # Update existing active alert to keep alert details accurate without creating duplicate
                cursor.execute(
                    "UPDATE alerts SET alert_type = ?, title = ?, description = ?, severity = ? WHERE id = ?",
                    (alert_type, title, description, severity, existing["id"])
                )
                if should_close:
                    conn.commit()
                    conn.close()
                return existing["id"]

        cursor.execute(
            """
            INSERT INTO alerts (device_id, alert_type, severity, title, description, is_resolved)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (device_id, alert_type, severity, title, description)
        )
        alert_id = cursor.lastrowid

        # Simulated Email Notification (Chapter 11.4: optional administrator notification)
        if notify_email or severity == "High":
            AlertManager._simulate_email_dispatch(title, description, severity)

        audit_logger.log_event(
            event_type="ALERT_CREATED",
            username="SYSTEM",
            description=f"Generated {severity.upper()} severity alert: {title}",
            conn=conn
        )
        
        if should_close:
            conn.commit()
            conn.close()

        return alert_id

    @staticmethod
    def _simulate_email_dispatch(title: str, description: str, severity: str):
        """Simulates automated security notification sent to the administrator."""
        print(f"[SECURITY ALERT EMAIL DISPATCH] [{severity.upper()}] {title} - {description}")

    @staticmethod
    def evaluate_and_alert(device_id: int, device_data: Dict[str, Any], risk_result: Dict[str, Any], conn: Optional[Any] = None):
        """Evaluates automated alerting rules for a device."""
        hostname = device_data.get("hostname") or device_data.get("ip_address")
        risk_level = risk_result.get("risk_level", "Low")
        risk_score = risk_result.get("risk_score", 0)

        # Rule 1: Device Authorization & Device Type Identification Alerts (Shadow IoT / Unmanaged Assets)
        is_authorized = bool(device_data.get("is_known_device", False))
        device_type = device_data.get("device_type") or "Unknown Device"
        is_unrecognized = (device_type == "Unknown Device")
        mfg = device_data.get("manufacturer") or "Unknown Manufacturer"
        ip = device_data.get("ip_address", "Unknown IP")
        mac = device_data.get("mac_address", "Unknown MAC")

        if not is_authorized and not is_unrecognized:
            # Trigger: Device is not authorized, but successfully classified
            mfg_str = f" ({mfg})" if mfg and mfg.lower() not in ["unknown", "unknown manufacturer", "n/a"] else ""
            AlertManager.create_alert(
                device_id=device_id,
                alert_type="Unauthorized Device",
                severity="High",
                title=f"Unauthorized Device Detected: {hostname}",
                description=f"Device at IP {ip} ({mac}) is classified as '{device_type}'{mfg_str} but is not an authorized asset. Administrative authorization required.",
                notify_email=True,
                conn=conn
            )
        elif is_authorized and is_unrecognized:
            # Trigger: Device is authorized, but device category is Unknown Device
            AlertManager.create_alert(
                device_id=device_id,
                alert_type="Unrecognized Device Type",
                severity="High",
                title=f"Unrecognized Device Type: {hostname}",
                description=f"Device at IP {ip} ({mac}) is an authorized asset, but its category could not be determined by heuristic classification rules. Manual category assignment or protocol inspection recommended.",
                notify_email=True,
                conn=conn
            )
        elif not is_authorized and is_unrecognized:
            # Trigger: Both conditions apply (unauthorized and unrecognized device category)
            AlertManager.create_alert(
                device_id=device_id,
                alert_type="Unauthorized & Unrecognized Device",
                severity="High",
                title=f"Rogue / Unrecognized Device Detected: {hostname}",
                description=f"Device at IP {ip} ({mac}) is unauthorized and its device type is unrecognized (both conditions apply). Administrative approval and device classification required.",
                notify_email=True,
                conn=conn
            )

        # Rule 2: High Risk Score Alert
        if risk_level == "High":
            AlertManager.create_alert(
                device_id=device_id,
                alert_type="High Risk Vulnerability",
                severity="High",
                title=f"High Risk Threshold Exceeded: {hostname}",
                description=f"Device risk score reached {risk_score}/100. Action required to mitigate exposed vulnerabilities.",
                notify_email=True,
                conn=conn
            )

        # Rule 3: Default Credentials Alert (Chapter 10.4 & 11.3)
        cred_status = (device_data.get("credential_status") or "").lower()
        if "default" in cred_status or "admin:admin" in cred_status or "factory" in cred_status:
            AlertManager.create_alert(
                device_id=device_id,
                alert_type="Default Credentials",
                severity="High",
                title=f"Default Factory Credentials Detected: {hostname}",
                description=f"Device at {device_data.get('ip_address')} is actively using factory default credentials.",
                notify_email=True,
                conn=conn
            )

alert_mgr = AlertManager()
