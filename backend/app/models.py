from pydantic import BaseModel, Field
from typing import List, Optional, Any
from datetime import datetime

# Auth Models
class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    full_name: str
    role: str
    created_at: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# Device Models
class DeviceBase(BaseModel):
    ip_address: str
    mac_address: str
    hostname: Optional[str] = None
    manufacturer: Optional[str] = "Unknown"
    device_type: Optional[str] = "Unknown Device"
    open_ports: Optional[List[int]] = []
    services: Optional[List[str]] = []
    firmware_version: Optional[str] = "Unknown"
    credential_status: Optional[str] = "Unknown"
    network_exposure: Optional[str] = "Unknown"
    security_configuration: Optional[str] = "Unknown"
    is_known_device: Optional[bool] = False
    status: Optional[str] = "Online"

class DeviceResponse(DeviceBase):
    id: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    latest_risk_score: Optional[int] = None
    latest_risk_level: Optional[str] = None

class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    is_known_device: Optional[bool] = None

# Risk Assessment Models
class RiskAssessmentResponse(BaseModel):
    id: int
    device_id: int
    risk_score: int
    risk_level: str
    factor_unknown: int
    factor_firmware: int
    factor_credential: int
    factor_exposure: int
    factor_config: int
    details: Optional[dict] = None
    assessed_at: Optional[str] = None

# Alert Models
class AlertResponse(BaseModel):
    id: int
    device_id: Optional[int] = None
    device_hostname: Optional[str] = None
    device_ip: Optional[str] = None
    alert_type: str
    severity: str
    title: str
    description: str
    is_resolved: bool
    created_at: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None

class AlertResolutionUpdate(BaseModel):
    is_resolved: bool

# Audit Log Models
class AuditLogResponse(BaseModel):
    id: int
    event_type: str
    username: str
    description: str
    ip_source: str
    timestamp: Optional[str] = None

# Scan Trigger Models
class ScanTriggerRequest(BaseModel):
    target_subnet: Optional[str] = "192.168.1.0/24"
    scan_type: Optional[str] = "simulated"  # 'simulated' for smart-office demo or 'active' for real ARP

class ScanResponse(BaseModel):
    status: str
    devices_found: int
    new_devices_added: int
    message: str
