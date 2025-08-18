from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
from passlib.context import CryptContext
import enum

Base = declarative_base()

class UserRole(str, enum.Enum):
    """User roles for IR platform access control"""
    ANALYST = "analyst"              # Basic incident response analyst
    SENIOR_ANALYST = "senior_analyst"  # Can approve actions, modify playbooks
    MANAGER = "manager"              # Full incident oversight, reporting access
    ADMIN = "admin"                  # System administration, user management

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Authentication fields
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    
    # Profile information
    full_name = Column(String(100), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.ANALYST)
    department = Column(String(50), nullable=True)  # SOC, Security, IT, etc.
    phone = Column(String(20), nullable=True)
    
    # Account status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)  # Account lockout
    
    # Authentication tracking
    last_login = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, default=datetime.utcnow)
    password_reset_token = Column(String(255), nullable=True)
    password_reset_expires = Column(DateTime, nullable=True)
    
    # Session management
    current_session_token = Column(String(255), nullable=True)
    session_expires = Column(DateTime, nullable=True)
    
    # Audit trail
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(50), nullable=True)  # Username who created this user
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # User preferences for IR platform
    preferences = Column(JSON, default=dict)  # UI settings, notification preferences
    
    # MFA settings
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(32), nullable=True)  # TOTP secret
    backup_codes = Column(JSON, nullable=True)  # MFA backup codes
    
    def __repr__(self):
        return f"<User(username='{self.username}', role='{self.role}', active={self.is_active})>"

    @property
    def is_admin(self) -> bool:
        """Check if user has admin privileges"""
        return self.role == UserRole.ADMIN
    
    @property
    def is_manager_or_above(self) -> bool:
        """Check if user has manager or admin privileges"""
        return self.role in [UserRole.MANAGER, UserRole.ADMIN]
    
    @property
    def can_approve_actions(self) -> bool:
        """Check if user can approve critical IR actions"""
        return self.role in [UserRole.SENIOR_ANALYST, UserRole.MANAGER, UserRole.ADMIN]
    
    @property
    def is_account_locked(self) -> bool:
        """Check if account is currently locked"""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

# Password hashing utilities
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserManager:
    """Utility class for user operations"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password for storing in database"""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def create_user(
        username: str,
        email: str,
        password: str,
        full_name: str,
        role: UserRole = UserRole.ANALYST,
        department: str = None
    ) -> User:
        """Create a new user with hashed password"""
        return User(
            username=username,
            email=email,
            hashed_password=UserManager.hash_password(password),
            full_name=full_name,
            role=role,
            department=department,
            preferences={
                "theme": "dark",
                "notifications": {
                    "email_alerts": True,
                    "browser_notifications": True,
                    "incident_assignments": True,
                    "playbook_updates": False
                },
                "dashboard": {
                    "default_view": "incidents",
                    "auto_refresh": 30,
                    "show_resolved": False
                }
            }
        )

class UserSession(Base):
    """Track active user sessions for security"""
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)  # Foreign key reference
    session_token = Column(String(255), unique=True, index=True)
    
    # Session details
    ip_address = Column(String(45))  # IPv4 or IPv6
    user_agent = Column(Text)
    location = Column(String(100), nullable=True)  # Geo-location if available
    
    # Session lifecycle
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    
    # Security flags
    is_suspicious = Column(Boolean, default=False)
    logout_reason = Column(String(50), nullable=True)  # timeout, manual, forced
    
    def __repr__(self):
        return f"<UserSession(user_id={self.user_id}, ip='{self.ip_address}', active={self.is_active})>"

class LoginAttempt(Base):
    """Log all login attempts for security monitoring"""
    __tablename__ = "login_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Attempt details
    username = Column(String(50), index=True)  # Attempted username
    ip_address = Column(String(45))
    user_agent = Column(Text)
    
    # Result
    success = Column(Boolean)
    failure_reason = Column(String(100), nullable=True)  # invalid_password, account_locked, etc.
    
    # Timing
    attempted_at = Column(DateTime, default=datetime.utcnow)
    
    # Security context
    is_suspicious = Column(Boolean, default=False)  # Multiple failures, unusual location, etc.
    
    def __repr__(self):
        status = "SUCCESS" if self.success else "FAILED"
        return f"<LoginAttempt({status}, username='{self.username}', ip='{self.ip_address}')>"