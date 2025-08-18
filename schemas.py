from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from models.users import UserRole
from models.playbook import PlaybookStatus, StepType, InputFieldType

# Authentication schemas
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user_info: Dict[str, Any]

class TokenData(BaseModel):
    username: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    
    @validator('new_password')
    def validate_password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

# User schemas
class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: str
    role: UserRole
    department: Optional[str] = None
    phone: Optional[str] = None

class UserCreate(UserBase):
    password: str
    
    @validator('password')
    def validate_password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_verified: bool
    failed_login_attempts: int
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    preferences: Dict[str, Any]
    mfa_enabled: bool
    
    class Config:
        from_attributes = True

class UserProfile(BaseModel):
    id: int
    username: str
    email: EmailStr
    full_name: str
    role: UserRole
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool
    is_verified: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    preferences: Dict[str, Any]
    mfa_enabled: bool
    
    class Config:
        from_attributes = True

class UserPreferencesUpdate(BaseModel):
    theme: Optional[str] = None
    notifications: Optional[Dict[str, bool]] = None
    dashboard: Optional[Dict[str, Any]] = None

# Session schemas
class SessionInfo(BaseModel):
    id: int
    ip_address: str
    user_agent: str
    location: Optional[str] = None
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool
    is_suspicious: bool
    
    class Config:
        from_attributes = True

class SessionResponse(BaseModel):
    sessions: list[SessionInfo]
    total_active: int

# Login attempt schemas
class LoginAttemptResponse(BaseModel):
    id: int
    username: str
    ip_address: str
    user_agent: str
    success: bool
    failure_reason: Optional[str] = None
    attempted_at: datetime
    is_suspicious: bool
    
    class Config:
        from_attributes = True

# MFA schemas
class MFAEnableRequest(BaseModel):
    password: str

class MFAVerifyRequest(BaseModel):
    token: str

class MFASetupResponse(BaseModel):
    secret: str
    qr_code_url: str
    backup_codes: list[str]

class MFABackupCodeRequest(BaseModel):
    backup_code: str

# Response schemas
class MessageResponse(BaseModel):
    message: str
    success: bool = True

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    success: bool = False

class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    size: int
    pages: int

# Health check schema
class HealthCheck(BaseModel):
    status: str
    timestamp: datetime
    version: str = "1.0.0"
    database: str = "connected"

# Playbook schemas
class PlaybookBase(BaseModel):
    name: str
    description: Optional[str] = None
    version: str = "1.0"
    status: PlaybookStatus = PlaybookStatus.DRAFT
    tags: List[str] = Field(default_factory=list)
    severity_levels: List[str] = Field(default_factory=list)
    alert_sources: List[str] = Field(default_factory=list)
    matching_criteria: Dict[str, Any] = Field(default_factory=dict)
    playbook_definition: Dict[str, Any]
    report_template: Optional[str] = None
    estimated_duration_minutes: int = 60
    requires_approval: bool = False
    auto_assign: bool = True
    priority_score: int = Field(default=5, ge=1, le=10)

class PlaybookCreate(PlaybookBase):
    pass

class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    version: Optional[str] = None
    status: Optional[PlaybookStatus] = None
    tags: Optional[List[str]] = None
    severity_levels: Optional[List[str]] = None
    alert_sources: Optional[List[str]] = None
    matching_criteria: Optional[Dict[str, Any]] = None
    playbook_definition: Optional[Dict[str, Any]] = None
    report_template: Optional[str] = None
    estimated_duration_minutes: Optional[int] = None
    requires_approval: Optional[bool] = None
    auto_assign: Optional[bool] = None
    priority_score: Optional[int] = Field(None, ge=1, le=10)

class PlaybookResponse(PlaybookBase):
    id: int
    created_by_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    last_used: Optional[datetime] = None
    usage_count: int = 0
    created_by: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class PlaybookExecutionBase(BaseModel):
    playbook_id: int
    alert_id: Optional[int] = None
    incident_id: Optional[str] = None
    assigned_analyst_id: Optional[int] = None

class PlaybookExecutionCreate(PlaybookExecutionBase):
    pass

class PlaybookExecutionUpdate(BaseModel):
    current_phase: Optional[str] = None
    current_step_index: Optional[int] = None
    execution_status: Optional[str] = None
    execution_data: Optional[Dict[str, Any]] = None
    completed_steps: Optional[int] = None
    progress_percentage: Optional[float] = None
    completed_at: Optional[datetime] = None
    paused_at: Optional[datetime] = None
    generated_report: Optional[str] = None
    report_generated_at: Optional[datetime] = None

class PlaybookExecutionResponse(PlaybookExecutionBase):
    id: int
    execution_id: str
    current_phase: Optional[str] = None
    current_step_index: int = 0
    execution_status: str = "in_progress"
    execution_data: Dict[str, Any] = Field(default_factory=dict)
    total_steps: Optional[int] = None
    completed_steps: int = 0
    progress_percentage: float = 0.0
    assigned_at: datetime
    started_at: datetime
    completed_at: Optional[datetime] = None
    paused_at: Optional[datetime] = None
    generated_report: Optional[str] = None
    report_generated_at: Optional[datetime] = None
    playbook: Optional[Dict[str, Any]] = None
    assigned_analyst: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class StepExecutionLogBase(BaseModel):
    execution_id: int
    phase_name: str
    step_name: str
    step_type: str
    step_index: int
    status: str = "pending"
    success: Optional[bool] = None
    output_data: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    requires_manual_action: bool = False
    automation_command: Optional[str] = None
    automation_result: Optional[Dict[str, Any]] = None

class StepExecutionLogCreate(StepExecutionLogBase):
    pass

class StepExecutionLogResponse(StepExecutionLogBase):
    id: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    executed_by_id: Optional[int] = None
    executed_by: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class PlaybookUserInputBase(BaseModel):
    execution_id: int
    phase_name: str
    step_name: str
    field_name: str
    field_type: str
    user_input: Dict[str, Any]
    input_label: str
    is_required: bool = False

class PlaybookUserInputCreate(PlaybookUserInputBase):
    pass

class PlaybookUserInputResponse(PlaybookUserInputBase):
    id: int
    collected_by_id: int
    collected_by: Optional[Dict[str, Any]] = None
    collected_at: datetime
    is_valid: bool = True
    validation_error: Optional[str] = None
    
    class Config:
        from_attributes = True

class PlaybookTemplateBase(BaseModel):
    name: str
    category: str
    description: Optional[str] = None
    template_definition: Dict[str, Any]
    default_tags: List[str] = Field(default_factory=list)
    is_official: bool = False

class PlaybookTemplateCreate(PlaybookTemplateBase):
    pass

class PlaybookTemplateUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    template_definition: Optional[Dict[str, Any]] = None
    default_tags: Optional[List[str]] = None
    is_official: Optional[bool] = None

class PlaybookTemplateResponse(PlaybookTemplateBase):
    id: int
    download_count: int = 0
    rating: Optional[float] = None
    created_by_id: Optional[int] = None
    created_at: datetime
    created_by: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class PlaybookSearchRequest(BaseModel):
    search: Optional[str] = None
    status: Optional[PlaybookStatus] = None
    tags: Optional[List[str]] = None
    severity_levels: Optional[List[str]] = None
    alert_sources: Optional[List[str]] = None
    created_by_id: Optional[int] = None
    page: int = 1
    size: int = 20

class PlaybookExecutionSearchRequest(BaseModel):
    playbook_id: Optional[int] = None
    execution_status: Optional[str] = None
    assigned_analyst_id: Optional[int] = None
    incident_id: Optional[str] = None
    started_after: Optional[datetime] = None
    started_before: Optional[datetime] = None
    page: int = 1
    size: int = 20
