from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from backend.app.database import get_db_connection
from backend.app.auth import verify_password, create_access_token, get_current_user
from backend.app.models import UserLogin, TokenResponse, UserResponse
from backend.app.modules.audit import audit_logger

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

@router.post("/login", response_model=TokenResponse)
def login(credentials: UserLogin, request: Request):
    """Authenticates administrator or viewer and returns signed JWT (SEC-1, SEC-2)."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (credentials.username,)).fetchone()
    conn.close()

    client_ip = request.client.host if request.client else "127.0.0.1"

    if not user or not verify_password(credentials.password, user["password_hash"]):
        audit_logger.log_event(
            event_type="AUTH_FAILED",
            username=credentials.username,
            description=f"Failed login attempt for user '{credentials.username}'",
            ip_source=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    # Issue JWT token
    token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    
    audit_logger.log_event(
        event_type="USER_LOGIN",
        username=user["username"],
        description=f"User '{user['username']}' logged in successfully as {user['role']}",
        ip_source=client_ip
    )

    user_info = UserResponse(
        id=user["id"],
        username=user["username"],
        full_name=user["full_name"],
        role=user["role"],
        created_at=str(user["created_at"])
    )

    return TokenResponse(access_token=token, token_type="bearer", user=user_info)

@router.post("/token")
def login_for_swagger(form_data: OAuth2PasswordRequestForm = Depends()):
    """OAuth2 compatible token endpoint for Swagger API docs."""
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (form_data.username,)).fetchone()
    conn.close()

    if not user or not verify_password(form_data.password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: dict = Depends(get_current_user)):
    """Returns profile for currently active session."""
    return UserResponse(
        id=current_user["id"],
        username=current_user["username"],
        full_name=current_user["full_name"],
        role=current_user["role"],
        created_at=str(current_user["created_at"])
    )

@router.post("/logout")
def logout(current_user: dict = Depends(get_current_user)):
    """Logs the user logout action in the audit trail."""
    audit_logger.log_event(
        event_type="USER_LOGOUT",
        username=current_user["username"],
        description=f"User '{current_user['username']}' logged out"
    )
    return {"status": "success", "message": "Successfully logged out"}
