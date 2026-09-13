import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from backend.app.database import get_db_connection
from backend.app.auth import get_current_user, require_admin
from backend.app.models import DeviceResponse, DeviceUpdate, ScanTriggerRequest, ScanResponse
from backend.app.modules.discovery import discovery_service
from backend.app.modules.audit import audit_logger

router = APIRouter(prefix="/api/devices", tags=["Device Inventory"])

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
            latest_risk_level=r["latest_risk_level"] or "Low"
        ))

    return results

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
        "alerts": [dict(a) for a in alerts]
    }

@router.post("/scan", response_model=ScanResponse)
def trigger_network_scan(
    payload: ScanTriggerRequest,
    current_user: dict = Depends(require_admin)
):
    """Triggers discovery cycle across the authorized network (Admin only - Chapter 7.3)."""
    result = discovery_service.run_discovery_pipeline(
        scan_type=payload.scan_type or "simulated",
        target_subnet=payload.target_subnet or "192.168.1.0/24",
        user=current_user["username"]
    )
    return ScanResponse(**result)

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

    new_hostname = payload.hostname if payload.hostname is not None else device["hostname"]
    new_type = payload.device_type if payload.device_type is not None else device["device_type"]
    new_is_known = int(payload.is_known_device) if payload.is_known_device is not None else device["is_known_device"]

    conn.execute(
        "UPDATE devices SET hostname = ?, device_type = ?, is_known_device = ? WHERE id = ?",
        (new_hostname, new_type, new_is_known, device_id)
    )
    conn.commit()
    conn.close()

    audit_logger.log_event(
        event_type="DEVICE_UPDATED",
        username=current_user["username"],
        description=f"Device {device['ip_address']} updated (Type: {new_type}, Known: {bool(new_is_known)})"
    )

    return {"status": "success", "message": "Device successfully updated"}
