# Secure IoT Device Discovery and Risk Management System for Smart Office Networks

**IE3092 - Information Security Project (Group 14)**  
*B.Sc. (Hons) in Information Technology Specializing in Cyber Security*  
*Sri Lanka Institute of Information Technology (SLIIT)*

---

## 📌 Project Overview

Smart offices increasingly rely on Internet of Things (IoT) devices such as CCTV cameras, smart locks, networked printers, and environmental sensors. However, these devices often operate outside formal IT governance—frequently deployed with default credentials, unpatched firmware, and exposed network services.

This project delivers a **secure, lightweight, web-based IoT device discovery and risk management platform** designed specifically for small-to-medium smart office networks without requiring expensive enterprise platforms.

---

## 🏗️ System Architecture & Core Modules

The platform is structured as a continuous 4-stage pipeline matching the Project Proposal and Software Stack Specification:

```
+---------------------+      +------------------------+      +-------------------------+      +---------------------------+
| 1. Device Discovery | ---> | 2. Device Classification| ---> | 3. Risk Assessment       | ---> | 4. Admin Dashboard        |
| (Simulated Testbed) |      | (OUI & Heuristic Rules) |      | (5-Factor Model: 0-100) |      | (JWT, RBAC, Alerts, Audit)|
+---------------------+      +------------------------+      +-------------------------+      +---------------------------+
```

### 1. Device Discovery Component (Chapters 3.4, 4.2.1, 6.5, 7.3)
- Simulates discovery of authorized smart office network devices using predefined testbed data.
- Captures metadata: IP Address, MAC Address, Hostname, Open Ports, Observed Services, First-Seen and Last-Seen timestamps.
- Exclusively utilizes a Smart Office simulation mode to ensure a fully non-intrusive security assessment, avoiding real network sweeps or the need for root/Npcap drivers.

### 2. Device Classification Component (Chapters 3.5, 4.2.2, 6.6, 7.4)
- Performs IEEE MAC OUI prefix lookup against vendor database (`oui_database.json`).
- Applies transparent rule-based heuristic inference using ports and service banners to classify assets into:
  - **CCTV Camera** (e.g., Dahua, Hikvision, RTSP 554, Port 37777)
  - **Printer** (e.g., HP, Canon, JetDirect 9100, IPP 631)
  - **Smart Lock** (e.g., Yale, Assa Abloy, HTTPS 443)
  - **Environmental Sensor** (e.g., Shelly, MQTT 1883, Temp/HVAC)
  - **Smart Plug** (e.g., TP-Link Kasa, Port 9999)
  - **Network Device** (e.g., Ubiquiti, Cisco AP/Switch)
  - **Unknown Device** (Fallback category for unverified or rogue hardware)

### 3. Risk Assessment Engine (Chapters 3.6, 4.2.3, 10.1 - 10.9)
Calculates a transparent, explainable 100-point composite **Risk Score** using the exact weights defined in Chapter 10.8:
- **Unknown Device Status (Weight: 25 pts)**: Identifies unapproved or rogue "Shadow IoT" devices.
- **Firmware Risk (Weight: 25 pts)**: Flags outdated firmware versions and CVE associations.
- **Credential Security (Weight: 25 pts)**: Flags factory-default passwords (e.g., `admin:admin`) or weak credentials.
- **Network Exposure (Weight: 15 pts)**: Assesses risky exposed services (e.g., Telnet 23, RTSP 554, unencrypted HTTP).
- **Security Configuration (Weight: 10 pts)**: Identifies unencrypted channels and missing TLS.

**Severity Tiers:**
- `0 - 30`: **Low Risk**
- `31 - 60`: **Medium Risk**
- `61 - 100`: **High Risk**

### 4. Secure Admin Dashboard & Alert Management (Chapters 3.7, 7.6, 11.1 - 11.4)
- **Authentication & RBAC**: bcrypt-hashed passwords, JWT session tokens, and role-based access control (`admin` vs `viewer`).
- **5 Core Views**:
  1. **Risk Overview View**: High-level statistical cards and category distribution graphs.
  2. **Device Inventory View**: Searchable, filterable table by category, IP, MAC, or severity.
  3. **Alert Feed**: Real-time event log for rogue devices, high risks, and default credentials.
  4. **Device Detail Panel (Modal)**: Visual breakdown of all 5 contributing risk factors.
  5. **Audit History Log**: Immutable record of discoveries, logins, and alert changes.

---

## 💻 Technology Stack

| Layer | Technology | Role |
|---|---|---|
| **Backend Framework** | Python 3.13 + FastAPI | REST API & System Pipeline Orchestration |
| **Server** | Uvicorn ASGI | Fast, lightweight asynchronous server |
| **Database** | SQLite3 (Persistent file `iot_security.db`) | Relational storage for inventory, risks, alerts & audit |
| **Security & Auth** | PyJWT + bcrypt | Salted password hashing & bearer session tokens |
| **Classification** | IEEE OUI DB + Heuristic Rules | Multi-attribute IoT device classifier |
| **Frontend** | HTML5, Vanilla JavaScript, CSS3 | Clean, responsive, dark-mode cybersecurity dashboard |

---

## 🚀 Quickstart Guide (Local Execution)

### 1. Prerequisites
- Python 3.10+ (Python 3.13 tested)

### 2. Setup Environment
```bash
# Navigate to project folder
cd c:\Users\Methuli\OneDrive\Desktop\iot2

# Activate virtual environment
.\venv\Scripts\activate

# Install requirements (if not already installed)
pip install -r requirements.txt
```

### 3. Run Application
```bash
python run.py
```

Open your web browser and navigate to:
- **Dashboard & Login:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Documentation:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🔑 Default Evaluation Credentials

| Role | Username | Password | Access Privileges |
|---|---|---|---|
| **Administrator** | `admin` | `AdminPassword123!` | Full control: Run scans, resolve alerts, modify devices |
| **Viewer** | `viewer` | `ViewerPassword123!` | Read-only: View dashboard, inventory, alerts & audit log |

---

## 📁 Project Directory Structure

```
iot2/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py               # FastAPI application setup & lifecycle startup
│   │   ├── config.py             # Settings, paths, JWT secrets, risk model weights
│   │   ├── database.py           # SQLite database schema initialization & connections
│   │   ├── models.py             # Pydantic schemas for requests & responses
│   │   ├── auth.py               # bcrypt password hashing, JWT tokens & RBAC
│   │   ├── modules/
│   │   │   ├── __init__.py
│   │   │   ├── discovery.py      # Device discovery pipeline (Office simulation testbed)
│   │   │   ├── classification.py # IEEE OUI lookup & rule-based classifier
│   │   │   ├── risk_assessment.py# 5-factor weighted risk engine (0-100)
│   │   │   ├── alert_manager.py  # Security alert generation & notifications
│   │   │   └── audit.py          # Append-only security audit logger
│   │   └── routers/
│   │       ├── __init__.py
│   │       ├── auth_routes.py    # Login, session validation, logout
│   │       ├── device_routes.py  # Inventory retrieval, search/filter, scan triggers
│   │       ├── risk_routes.py    # Risk statistics & device risk recalculation
│   │       ├── alert_routes.py   # Alert feed & resolution endpoints
│   │       └── audit_routes.py   # Security audit trail retrieval
├── frontend/
│   ├── static/
│   │   ├── css/
│   │   │   └── style.css         # Clean, professional cyber-security dashboard styling
│   │   └── js/
│   │       ├── app.js            # Dashboard UI rendering, charts, modals & filters
│   │       └── auth.js           # JWT authentication, session handling & route guards
│   └── templates/
│       ├── index.html            # Main single-page application dashboard
│       └── login.html            # Administrator & Viewer login page
├── data/
│   ├── oui_database.json         # IEEE MAC OUI manufacturer mapping database
│   └── seed_devices.json         # Realistic smart office IoT test network devices
├── requirements.txt              # Project dependencies
├── run.py                        # Single-command runner
└── README.md                     # Documentation & setup instructions
```
