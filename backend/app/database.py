import sqlite3
import json
from datetime import datetime
from backend.app.config import DB_PATH

def get_db_connection():
    """Returns a SQLite connection with dict-like row access and WAL concurrency."""
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_database():
    """Initializes the SQLite schema as specified in Chapter 7.8 of the Proposal."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Users Table (Chapter 7.8, 11.2)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Devices Table (Chapter 7.8, 8.1.5)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        mac_address TEXT UNIQUE NOT NULL,
        hostname TEXT,
        manufacturer TEXT,
        device_type TEXT DEFAULT 'Unknown Device',
        open_ports TEXT DEFAULT '[]',
        services TEXT DEFAULT '[]',
        firmware_version TEXT DEFAULT 'Unknown',
        credential_status TEXT DEFAULT 'Unknown',
        network_exposure TEXT DEFAULT 'Unknown',
        security_configuration TEXT DEFAULT 'Unknown',
        is_known_device BOOLEAN DEFAULT 0,
        status TEXT DEFAULT 'Online',
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Risk Assessments Table (Chapter 7.8, 10.8)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        risk_score INTEGER NOT NULL,
        risk_level TEXT NOT NULL,
        factor_unknown INTEGER NOT NULL,
        factor_firmware INTEGER NOT NULL,
        factor_credential INTEGER NOT NULL,
        factor_exposure INTEGER NOT NULL,
        factor_config INTEGER NOT NULL,
        details TEXT,
        assessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
    );
    """)

    # 4. Alerts Table (Chapter 7.8, 11.4)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        is_resolved BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE SET NULL
    );
    """)

    # 5. Audit Logs Table (Chapter 7.8, 11.3)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        username TEXT NOT NULL,
        description TEXT NOT NULL,
        ip_source TEXT DEFAULT '127.0.0.1',
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()
    conn.close()
