from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List
import secrets
import qrcode
import base64
import io

from database import get_db
from auth_utils import AuthManager, get_current_user, require_admin, require_manager_or_above
from models.users import User, UserManager, UserSession, LoginAttempt
from schemas import (
    Token, LoginRequest, RefreshTokenRequest, PasswordChangeRequest,
    PasswordResetRequest, PasswordResetConfirm, UserCreate, UserUpdate,
    UserResponse, UserProfile, SessionInfo, SessionResponse,
    LoginAttemptResponse, MessageResponse, MFAEnableRequest,
    MFAVerifyRequest, MFASetupResponse, MFABackupCodeRequest,
    UserPreferencesUpdate, PaginatedResponse
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

# Security scheme
security = HTTPBearer()

@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Authenticate user and return JWT tokens"""
    
    # Get client information
    client_ip = request.client.host
    user_agent = request.headers.get("user-agent", "")
    
    # Authenticate user
    user = AuthManager.authenticate_user(db, login_data.username, login_data.password)
    
    if not user:
        # Log failed attempt
        AuthManager.log_login_attempt(
            db, login_data.username, client_ip, user_agent, 
            success=False, failure_reason="invalid_credentials"
        )
        
        # Increment failed login attempts
        existing_user = db.query(User).filter(User.username == login_data.username).first()
        if existing_user:
            existing_user.failed_login_attempts += 1
            
            # Lock account after 5 failed attempts
            if existing_user.failed_login_attempts >= 5:
                existing_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            
            db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if account is locked
    if user.is_account_locked:
        AuthManager.log_login_attempt(
            db, login_data.username, client_ip, user_agent,
            success=False, failure_reason="account_locked"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is locked. Please try again later.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Reset failed login attempts on successful login
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    user.locked_until = None
    
    # Create tokens
    access_token_expires = timedelta(minutes=30)
    access_token = AuthManager.create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )
    
    refresh_token = AuthManager.create_refresh_token(
        data={"sub": user.username}
    )
    
    # Create session
    session_expires = datetime.utcnow() + timedelta(days=7)
    AuthManager.create_user_session(
        db, user.id, refresh_token, client_ip, user_agent, session_expires
    )
    
    # Log successful login
    AuthManager.log_login_attempt(
        db, login_data.username, client_ip, user_agent, success=True
    )
    
    db.commit()
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=30 * 60,  # 30 minutes in seconds
        user_info={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "department": user.department,
            "is_verified": user.is_verified,
            "mfa_enabled": user.mfa_enabled
        }
    )

@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token"""
    
    try:
        # Verify refresh token
        payload = AuthManager.verify_token(refresh_data.refresh_token)
        username = payload.get("sub")
        token_type = payload.get("type")
        
        if not username or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        # Check if session exists and is active
        session = db.query(UserSession).filter(
            UserSession.session_token == refresh_data.refresh_token,
            UserSession.is_active == True,
            UserSession.expires_at > datetime.utcnow()
        ).first()
        
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired or invalid"
            )
        
        # Get user
        user = db.query(User).filter(User.username == username).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Update session activity
        session.last_activity = datetime.utcnow()
        db.commit()
        
        # Create new access token
        access_token_expires = timedelta(minutes=30)
        access_token = AuthManager.create_access_token(
            data={"sub": user.username, "role": user.role},
            expires_delta=access_token_expires
        )
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_data.refresh_token,
            expires_in=30 * 60,
            user_info={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "role": user.role,
                "department": user.department,
                "is_verified": user.is_verified,
                "mfa_enabled": user.mfa_enabled
            }
        )
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

@router.post("/logout", response_model=MessageResponse)
async def logout(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logout user and invalidate current session"""
    
    # Invalidate all sessions for the user
    AuthManager.invalidate_user_sessions(db, current_user.id, "manual")
    
    return MessageResponse(message="Successfully logged out")

@router.post("/logout-all", response_model=MessageResponse)
async def logout_all_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logout from all active sessions"""
    
    # Invalidate all sessions for the user
    AuthManager.invalidate_user_sessions(db, current_user.id, "logout_all")
    
    return MessageResponse(message="Successfully logged out from all sessions")

@router.get("/me", response_model=UserProfile)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    """Get current user profile"""
    return current_user

@router.put("/me/password", response_model=MessageResponse)
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Change user password"""
    
    # Verify current password
    if not UserManager.verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    current_user.hashed_password = UserManager.hash_password(password_data.new_password)
    current_user.last_password_change = datetime.utcnow()
    
    # Invalidate all sessions for security
    AuthManager.invalidate_user_sessions(db, current_user.id, "password_change")
    
    db.commit()
    
    return MessageResponse(message="Password changed successfully")

@router.put("/me/preferences", response_model=MessageResponse)
async def update_preferences(
    preferences: UserPreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user preferences"""
    
    if preferences.theme is not None:
        current_user.preferences["theme"] = preferences.theme
    
    if preferences.notifications is not None:
        current_user.preferences["notifications"].update(preferences.notifications)
    
    if preferences.dashboard is not None:
        current_user.preferences["dashboard"].update(preferences.dashboard)
    
    db.commit()
    
    return MessageResponse(message="Preferences updated successfully")

@router.get("/sessions", response_model=SessionResponse)
async def get_user_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all active sessions for current user"""
    
    sessions = db.query(UserSession).filter(
        UserSession.user_id == current_user.id,
        UserSession.is_active == True
    ).all()
    
    session_info = [SessionInfo.from_orm(session) for session in sessions]
    
    return SessionResponse(
        sessions=session_info,
        total_active=len(session_info)
    )

@router.delete("/sessions/{session_id}", response_model=MessageResponse)
async def revoke_session(
    session_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a specific session"""
    
    session = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    session.is_active = False
    session.logout_reason = "manual_revoke"
    db.commit()
    
    return MessageResponse(message="Session revoked successfully")

# Password reset endpoints
@router.post("/password-reset", response_model=MessageResponse)
async def request_password_reset(
    reset_request: PasswordResetRequest,
    db: Session = Depends(get_db)
):
    """Request password reset token"""
    
    user = db.query(User).filter(User.email == reset_request.email).first()
    if not user:
        # Don't reveal if email exists or not
        return MessageResponse(message="If the email exists, a reset link has been sent")
    
    # Generate reset token
    reset_token = secrets.token_urlsafe(32)
    user.password_reset_token = reset_token
    user.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
    
    db.commit()
    
    # TODO: Send email with reset link
    # For now, just return success message
    
    return MessageResponse(message="If the email exists, a reset link has been sent")

@router.post("/password-reset/confirm", response_model=MessageResponse)
async def confirm_password_reset(
    reset_confirm: PasswordResetConfirm,
    db: Session = Depends(get_db)
):
    """Confirm password reset with token"""
    
    user = db.query(User).filter(
        User.password_reset_token == reset_confirm.token,
        User.password_reset_expires > datetime.utcnow()
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    # Update password
    user.hashed_password = UserManager.hash_password(reset_confirm.new_password)
    user.last_password_change = datetime.utcnow()
    user.password_reset_token = None
    user.password_reset_expires = None
    
    # Invalidate all sessions
    AuthManager.invalidate_user_sessions(db, user.id, "password_reset")
    
    db.commit()
    
    return MessageResponse(message="Password reset successfully")

# MFA endpoints
@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    mfa_request: MFAEnableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Setup MFA for user account"""
    
    # Verify password
    if not UserManager.verify_password(mfa_request.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is incorrect"
        )
    
    # Generate MFA secret
    mfa_secret = secrets.token_hex(16)
    
    # Generate backup codes
    backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]
    
    # Create QR code URL
    qr_data = f"otpauth://totp/IRCentral:{current_user.username}?secret={mfa_secret}&issuer=IRCentral"
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_data)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
    qr_code_url = f"data:image/png;base64,{qr_code_base64}"
    
    # Store secret and backup codes (not enabled yet)
    current_user.mfa_secret = mfa_secret
    current_user.backup_codes = backup_codes
    
    db.commit()
    
    return MFASetupResponse(
        secret=mfa_secret,
        qr_code_url=qr_code_url,
        backup_codes=backup_codes
    )

@router.post("/mfa/verify", response_model=MessageResponse)
async def verify_mfa_setup(
    mfa_verify: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verify MFA setup and enable it"""
    
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not set up"
        )
    
    # TODO: Verify TOTP token
    # For now, just enable MFA
    current_user.mfa_enabled = True
    db.commit()
    
    return MessageResponse(message="MFA enabled successfully")

@router.post("/mfa/disable", response_model=MessageResponse)
async def disable_mfa(
    mfa_request: MFAEnableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Disable MFA for user account"""
    
    # Verify password
    if not UserManager.verify_password(mfa_request.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is incorrect"
        )
    
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.backup_codes = None
    
    db.commit()
    
    return MessageResponse(message="MFA disabled successfully")

# Admin endpoints
@router.get("/users", response_model=PaginatedResponse)
async def get_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Get all users (admin only)"""
    
    users = db.query(User).offset(skip).limit(limit).all()
    total = db.query(User).count()
    
    return PaginatedResponse(
        items=[UserResponse.from_orm(user) for user in users],
        total=total,
        page=skip // limit + 1,
        size=limit,
        pages=(total + limit - 1) // limit
    )

@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create new user (admin only)"""
    
    # Check if username or email already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Create user
    user = UserManager.create_user(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        full_name=user_data.full_name,
        role=user_data.role,
        department=user_data.department
    )
    user.created_by = current_user.username
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return UserResponse.from_orm(user)

@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Update user (admin only)"""
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update fields
    for field, value in user_data.dict(exclude_unset=True).items():
        setattr(user, field, value)
    
    db.commit()
    db.refresh(user)
    
    return UserResponse.from_orm(user)

@router.delete("/users/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete user (admin only)"""
    
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Invalidate all sessions
    AuthManager.invalidate_user_sessions(db, user.id, "account_deleted")
    
    db.delete(user)
    db.commit()
    
    return MessageResponse(message="User deleted successfully")

@router.get("/login-attempts", response_model=List[LoginAttemptResponse])
async def get_login_attempts(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Get login attempts (manager/admin only)"""
    
    attempts = db.query(LoginAttempt).order_by(
        LoginAttempt.attempted_at.desc()
    ).offset(skip).limit(limit).all()
    
    return [LoginAttemptResponse.from_orm(attempt) for attempt in attempts]
