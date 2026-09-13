from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from backend.app.database import get_db_connection
from backend.app.auth import get_current_user, require_admin
from backend.app.models import AlertResponse, AlertResolutionUpdate
from backend.app.modules.audit import audit_logger

router = APIRouter(prefix="/api/alerts", tags=["Alert Management"])

@router.get("", response_model=List[AlertResponse])
def list_alerts(
    unresolved_only: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """Returns alert feed for dashboard monitoring (Chapter 11.3 Alert Feed)."""
    conn = get_db_connection()
    query = """
        SELECT a.*, d.hostname as device_hostname, d.ip_address as device_ip
        FROM alerts a
        LEFT JOIN devices d ON a.device_id = d.id
        WHERE 1=1
    """
    params = []
    if unresolved_only:
        query += " AND a.is_resolved = 0"
    
    query += " ORDER BY a.id DESC LIMIT 100"
    rows = conn.execute(query, params).fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append(AlertResponse(
            id=r["id"],
            device_id=r["device_id"],
            device_hostname=r["device_hostname"],
            device_ip=r["device_ip"],
            alert_type=r["alert_type"],
            severity=r["severity"],
            title=r["title"],
            description=r["description"],
            is_resolved=bool(r["is_resolved"]),
            created_at=str(r["created_at"])
        ))
    return results

@router.put("/{alert_id}/resolve")
def resolve_alert(
    alert_id: int,
    payload: AlertResolutionUpdate,
    current_user: dict = Depends(require_admin)
):
    """Marks an alert as resolved or active (Admin only)."""
    conn = get_db_connection()
    alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not alert:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    conn.execute("UPDATE alerts SET is_resolved = ? WHERE id = ?", (1 if payload.is_resolved else 0, alert_id))
    conn.commit()
    conn.close()

    action = "resolved" if payload.is_resolved else "reopened"
    audit_logger.log_event(
        event_type="ALERT_UPDATED",
        username=current_user["username"],
        description=f"Alert #{alert_id} ('{alert['title']}') was marked as {action}"
    )

    return {"status": "success", "message": f"Alert #{alert_id} updated"}
