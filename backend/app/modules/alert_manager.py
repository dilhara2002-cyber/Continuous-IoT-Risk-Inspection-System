from typing import Optional, Dict, Any
from backend.app.database import get_db_connection

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
        cursor.execute(
            """
            INSERT INTO alerts (device_id, alert_type, severity, title, description, is_resolved)
            VALUES (?, ?, ?, ?, ?, 0)
            """,
            (device_id, alert_type, severity, title, description)
        )
        alert_id = cursor.lastrowid
        if should_close:
            conn.commit()
            conn.close()

        # Simulated Email Notification (Chapter 11.4: optional administrator notification)
        if notify_email or severity in ["High", "Critical"]:
            AlertManager._simulate_email_dispatch(title, description, severity)

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

        # Rule 1: Unknown / Unmanaged Device Alert (Shadow IoT)
        if not device_data.get("is_known_device") or device_data.get("device_type") == "Unknown Device":
            AlertManager.create_alert(
                device_id=device_id,
                alert_type="Unknown Device",
                severity="High",
                title=f"Rogue / Unknown Device Detected: {hostname}",
                description=f"Device at IP {device_data.get('ip_address')} ({device_data.get('mac_address')}) is unauthorized or unknown.",
                notify_email=True,
                conn=conn
            )

        # Rule 2: High Risk Score Alert
        if risk_level == "High":
            AlertManager.create_alert(
                device_id=device_id,
                alert_type="High Risk Vulnerability",
                severity="High",
                title=f"Critical Risk Threshold Exceeded: {hostname}",
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
