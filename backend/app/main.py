import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.app.config import BASE_DIR
from backend.app.database import init_database
from backend.app.auth import seed_default_users
from backend.app.modules.discovery import discovery_service
from backend.app.routers import auth_routes, device_routes, risk_routes, alert_routes, audit_routes, classification_routes

FRONTEND_DIR = BASE_DIR / "frontend"
STATIC_DIR = FRONTEND_DIR / "static"
TEMPLATES_DIR = FRONTEND_DIR / "templates"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database, Default Users & Baseline Devices
    print("[SYSTEM STARTUP] Initializing SQLite database...")
    init_database()
    
    print("[SYSTEM STARTUP] Ensuring default Admin and Viewer accounts exist...")
    seed_default_users()

    # Pre-populate device inventory if starting fresh
    print("[SYSTEM STARTUP] Running baseline Smart Office discovery pipeline...")
    discovery_service.run_discovery_pipeline(scan_type="simulated", user="SYSTEM")
    print("[SYSTEM STARTUP] System ready.")
    yield

app = FastAPI(
    title="Secure IoT Device Discovery and Risk Management System",
    description="Smart Office Network IoT Discovery, Classification, and Risk Assessment Platform (IE3092 - Group 14)",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware (SEC-4)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(auth_routes.router)
app.include_router(device_routes.router)
app.include_router(risk_routes.router)
app.include_router(alert_routes.router)
app.include_router(audit_routes.router)
app.include_router(classification_routes.router)

# Mount Static Assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Web UI Routes
@app.get("/", tags=["UI"])
def serve_dashboard():
    """Serves the main Admin Dashboard interface."""
    index_path = TEMPLATES_DIR / "index.html"
    return FileResponse(index_path)

@app.get("/login", tags=["UI"])
def serve_login():
    """Serves the secure authentication login page."""
    login_path = TEMPLATES_DIR / "login.html"
    return FileResponse(login_path)
