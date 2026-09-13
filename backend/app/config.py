import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = BASE_DIR / "iot_security.db"
OUI_DB_PATH = DATA_DIR / "oui_database.json"
SEED_DEVICES_PATH = DATA_DIR / "seed_devices.json"

# Security & JWT Configuration (Chapter 11)
SECRET_KEY = os.getenv("SECRET_KEY", "iot-security-smart-office-group14-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

# Risk Assessment Scoring Weights (Chapter 10)
RISK_WEIGHTS = {
    "unknown_device": 25,
    "firmware_risk": 25,
    "credential_risk": 25,
    "network_exposure": 15,
    "security_configuration": 10
}

# Risk Level Categorization Thresholds (Chapter 10.8)
# 0–30: Low, 31–60: Medium, 61–100: High
RISK_LEVEL_THRESHOLDS = {
    "LOW_MAX": 30,
    "MEDIUM_MAX": 60
}

# Default System Accounts (Chapter 11: Admin and Viewer roles)
DEFAULT_USERS = [
    {
        "username": "admin",
        "password": "AdminPassword123!",
        "full_name": "Office Security Admin",
        "role": "admin"
    },
    {
        "username": "viewer",
        "password": "ViewerPassword123!",
        "full_name": "Office Staff Viewer",
        "role": "viewer"
    }
]
