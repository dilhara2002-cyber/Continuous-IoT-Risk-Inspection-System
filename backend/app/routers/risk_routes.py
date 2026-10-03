import json
from fastapi import APIRouter, Depends, HTTPException
from backend.app.database import get_db_connection
from backend.app.auth import get_current_user, require_admin
from backend.app.modules.risk_assessment import risk_engine
from backend.app.modules.alert_manager import alert_mgr
from backend.app.modules.audit import audit_logger

router = APIRouter(prefix="/api/risk", tags=["Risk Assessment"])

@router.get("/summary")
def get_risk_summary(current_user: dict = Depends(get_current_user)):
    """
    Returns aggregated metrics for the Risk Overview View (Chapter 11.3):
    - Device breakdown by severity tier (Low, Medium, High)
    - Device count by category (CCTV, Printer, Lock, Sensor, Plug, Unknown)
    - Average risk score
    """
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT d.id, d.device_type, d.hostname, d.ip_address,
               COALESCE(r.risk_score, 0) as risk_score,
               COALESCE(r.risk_level, 'Low') as risk_level
        FROM devices d
        LEFT JOIN (
            SELECT device_id, risk_score, risk_level, MAX(assessed_at)
            FROM risk_assessments
            GROUP BY device_id
        ) r ON d.id = r.device_id
    """).fetchall()
    conn.close()

    total_devices = len(rows)
    low_count = sum(1 for r in rows if r["risk_level"] == "Low")
    med_count = sum(1 for r in rows if r["risk_level"] == "Medium")
    high_count = sum(1 for r in rows if r["risk_level"] == "High")

    avg_score = round(sum(r["risk_score"] for r in rows) / total_devices, 1) if total_devices > 0 else 0

    category_counts = {}
    for r in rows:
        dtype = r["device_type"] or "Unknown Device"
        category_counts[dtype] = category_counts.get(dtype, 0) + 1

    return {
        "total_devices": total_devices,
        "risk_distribution": {
            "Low": low_count,
            "Medium": med_count,
            "High": high_count
        },
        "average_risk_score": avg_score,
        "device_categories": category_counts
    }

@router.post("/evaluate/{device_id}")
def reevaluate_device_risk(device_id: int, current_user: dict = Depends(require_admin)):
    """Forces an immediate risk recalculation on a device (Admin only)."""
    conn = get_db_connection()
    device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not device:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    dev_data = dict(device)
    dev_data["open_ports"] = json.loads(dev_data["open_ports"]) if dev_data["open_ports"] else []
    dev_data["services"] = json.loads(dev_data["services"]) if dev_data["services"] else []
    dev_data["is_known_device"] = bool(dev_data["is_known_device"])

    risk_result = risk_engine.evaluate_device(dev_data)

    cursor = conn.cursor()
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
    conn.commit()
    conn.close()

    audit_logger.log_event(
        event_type="RISK_ASSESSED",
        username=current_user["username"],
        description=f"Recalculated risk for device {device['ip_address']} ({risk_result['risk_level']} - {risk_result['risk_score']}/100)"
    )

    return {"status": "success", "risk_result": risk_result}
