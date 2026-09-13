from typing import List
from fastapi import APIRouter, Depends
from backend.app.database import get_db_connection
from backend.app.auth import get_current_user
from backend.app.models import AuditLogResponse

router = APIRouter(prefix="/api/audit", tags=["Audit Log"])

@router.get("", response_model=List[AuditLogResponse])
def get_audit_logs(limit: int = 50, current_user: dict = Depends(get_current_user)):
    """Retrieves immutable append-only audit trail (Chapter 11.3 Audit Log)."""
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append(AuditLogResponse(
            id=r["id"],
            event_type=r["event_type"],
            username=r["username"],
            description=r["description"],
            ip_source=r["ip_source"],
            timestamp=str(r["timestamp"])
        ))
    return results
