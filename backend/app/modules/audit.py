from typing import Optional, Any
from backend.app.database import get_db_connection

class AuditLogger:
    """
    Audit Log Module (Chapters 7.8, 8.1.14, 11.3)
    Maintains an append-only log of discovery, security risk calculations,
    alert updates, and administrative authentication events.
    """

    @staticmethod
    def log_event(event_type: str, username: str, description: str, ip_source: str = "127.0.0.1", conn: Optional[Any] = None):
        """Inserts an immutable audit record."""
        should_close = False
        try:
            if conn is None:
                conn = get_db_connection()
                should_close = True
                
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_logs (event_type, username, description, ip_source)
                VALUES (?, ?, ?, ?)
                """,
                (event_type, username, description, ip_source)
            )
            if should_close:
                conn.commit()
                conn.close()
        except Exception as e:
            print(f"Error writing audit log: {e}")

audit_logger = AuditLogger()
