from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from models.users import UserRole
from models.playbook import PlaybookStatus, StepType, InputFieldType
from models.alert import AlertSeverity, AlertStatus, AlertSource, ThreatType

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
    incident_id: Optional[str] = None
    assigned_analyst_id: Optional[int] = None

class PlaybookExecutionCreate(PlaybookExecutionBase):
    pass

class PlaybookExecutionUpdate(BaseModel):
    status: Optional[str] = None
    current_phase: Optional[str] = None
    current_step: Optional[str] = None
    completed_steps: Optional[int] = None
    failed_steps: Optional[int] = None
    skipped_steps: Optional[int] = None
    completed_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    final_status: Optional[str] = None
    final_report: Optional[str] = None
    execution_context: Optional[Dict[str, Any]] = None

class PlaybookExecutionResponse(PlaybookExecutionBase):
    id: int
    execution_id: str
    status: str = "pending"
    current_phase: Optional[str] = None
    current_step: Optional[str] = None
    total_steps: int = 0
    completed_steps: int = 0
    failed_steps: int = 0
    skipped_steps: int = 0
    started_at: datetime
    completed_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    final_status: Optional[str] = None
    final_report: Optional[str] = None
    execution_context: Dict[str, Any] = Field(default_factory=dict)
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
    default_severity_levels: List[str] = Field(default_factory=list)

class PlaybookTemplateCreate(PlaybookTemplateBase):
    pass

class PlaybookTemplateUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    description: Optional[str] = None
    template_definition: Optional[Dict[str, Any]] = None
    default_tags: Optional[List[str]] = None
    default_severity_levels: Optional[List[str]] = None

class PlaybookTemplateResponse(PlaybookTemplateBase):
    id: int
    usage_count: int = 0
    created_by_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
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
    status: Optional[str] = None
    assigned_analyst_id: Optional[int] = None
    incident_id: Optional[str] = None
    started_after: Optional[datetime] = None
    started_before: Optional[datetime] = None
    page: int = 1
    size: int = 20

class AlertBase(BaseModel):
    """Base alert fields"""
    external_alert_id: str
    title: str
    description: Optional[str] = None
    severity: AlertSeverity
    source: str
    threat_type: Optional[ThreatType] = ThreatType.UNKNOWN
    detected_at: datetime
    
    # Source system info
    source_system: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    
    # Network info (optional)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=1, le=65535)
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = None
    
    # Asset info
    affected_hostname: Optional[str] = None
    affected_user: Optional[str] = None
    asset_criticality: Optional[str] = None

class AlertCreate(AlertBase):
    """Schema for creating new alerts (from SIEM systems)"""
    raw_alert_data: Optional[Dict[str, Any]] = Field(default_factory=dict)
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    risk_score: Optional[int] = Field(None, ge=1, le=100)
    
    @validator('external_alert_id')
    def validate_external_id(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('External alert ID cannot be empty')
        return v.strip()
    
    @validator('title')
    def validate_title(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Alert title cannot be empty')
        return v.strip()

class AlertUpdate(BaseModel):
    """Schema for updating alerts during investigation"""
    status: Optional[AlertStatus] = None
    assigned_analyst_id: Optional[int] = None
    incident_id: Optional[str] = None
    playbook_execution_id: Optional[int] = None
    correlation_id: Optional[str] = None
    parent_alert_id: Optional[int] = None
    
    # Investigation fields
    enrichment_data: Optional[Dict[str, Any]] = None
    investigation_notes: Optional[str] = None
    analyst_comments: Optional[str] = None
    
    # Impact assessment
    business_impact: Optional[str] = None
    data_classification: Optional[str] = None
    estimated_financial_impact: Optional[float] = None
    
    # False positive handling
    false_positive: Optional[bool] = None
    false_positive_reason: Optional[str] = None
    
    # Compliance
    requires_notification: Optional[bool] = None
    notification_deadline: Optional[datetime] = None
    compliance_notes: Optional[str] = None

class AlertResponse(AlertBase):
    """Schema for alert responses"""
    id: int
    status: AlertStatus
    confidence_score: Optional[float] = None
    risk_score: Optional[int] = None
    
    # Assignment and tracking
    assigned_analyst_id: Optional[int] = None
    incident_id: Optional[str] = None
    playbook_execution_id: Optional[int] = None
    correlation_id: Optional[str] = None
    parent_alert_id: Optional[int] = None
    
    # Enrichment and investigation
    enrichment_data: Dict[str, Any] = Field(default_factory=dict)
    investigation_notes: Optional[str] = None
    analyst_comments: Optional[str] = None
    
    # Reporting
    reported: bool = False
    reported_at: Optional[datetime] = None
    reported_to: List[str] = Field(default_factory=list)
    false_positive: bool = False
    false_positive_reason: Optional[str] = None
    
    # Impact
    business_impact: Optional[str] = None
    data_classification: Optional[str] = None
    estimated_financial_impact: Optional[float] = None
    
    # Compliance
    requires_notification: bool = False
    notification_deadline: Optional[datetime] = None
    compliance_notes: Optional[str] = None
    
    # Timing
    received_at: datetime
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    first_response_at: Optional[datetime] = None
    containment_at: Optional[datetime] = None
    resolution_at: Optional[datetime] = None
    
    # Relationships (simplified)
    assigned_analyst: Optional[Dict[str, Any]] = None
    
    # Computed properties
    is_overdue: Optional[bool] = None
    time_to_first_response: Optional[float] = None
    time_to_resolution: Optional[float] = None
    
    class Config:
        from_attributes = True

class AlertSearchRequest(BaseModel):
    """Schema for searching alerts"""
    search: Optional[str] = None                    # Search in title/description
    severity: Optional[List[AlertSeverity]] = None
    status: Optional[List[AlertStatus]] = None
    source: Optional[List[str]] = None
    threat_type: Optional[List[ThreatType]] = None
    assigned_analyst_id: Optional[int] = None
    incident_id: Optional[str] = None
    
    # Time filters
    detected_after: Optional[datetime] = None
    detected_before: Optional[datetime] = None
    received_after: Optional[datetime] = None
    received_before: Optional[datetime] = None
    
    # Filtering options
    false_positives: Optional[bool] = None          # Include/exclude false positives
    reported: Optional[bool] = None                 # Include only reported/unreported
    overdue_only: Optional[bool] = None             # Show only overdue alerts
    
    # Pagination
    page: int = Field(1, ge=1)
    size: int = Field(20, ge=1, le=100)
    
    # Sorting
    sort_by: Optional[str] = Field("received_at", pattern="^(received_at|detected_at|severity|status|updated_at)$")
    sort_order: Optional[str] = Field("desc", pattern="^(asc|desc)$")

# === ALERT ARTIFACT SCHEMAS ===

class AlertArtifactBase(BaseModel):
    """Base alert artifact fields"""
    artifact_type: str
    filename: Optional[str] = None
    description: Optional[str] = None
    file_size: Optional[int] = None
    file_hash_md5: Optional[str] = None
    file_hash_sha1: Optional[str] = None
    file_hash_sha256: Optional[str] = None

class AlertArtifactCreate(AlertArtifactBase):
    """Schema for creating alert artifacts"""
    alert_id: int
    file_path: Optional[str] = None

class AlertArtifactResponse(AlertArtifactBase):
    """Schema for alert artifact responses"""
    id: int
    alert_id: int
    file_path: Optional[str] = None
    collected_by_id: Optional[int] = None
    collected_at: datetime
    chain_of_custody: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Relationships
    collected_by: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

# === ALERT TAG SCHEMAS ===

class AlertTagCreate(BaseModel):
    """Schema for creating alert tags"""
    alert_id: int
    tag: str
    
    @validator('tag')
    def validate_tag(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Tag cannot be empty')
        return v.strip().lower()

class AlertTagResponse(BaseModel):
    """Schema for alert tag responses"""
    id: int
    alert_id: int
    tag: str
    
    class Config:
        from_attributes = True

# === BULK OPERATIONS ===

class BulkAlertUpdate(BaseModel):
    """Schema for bulk alert operations"""
    alert_ids: List[int] = Field(..., min_items=1, max_items=100)
    updates: AlertUpdate
    
class AlertStatsResponse(BaseModel):
    """Schema for alert statistics"""
    total_alerts: int
    new_alerts: int
    in_progress_alerts: int
    resolved_alerts: int
    false_positives: int
    overdue_alerts: int
    avg_response_time: Optional[float] = None
    avg_resolution_time: Optional[float] = None
    
    # By severity
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    
    # Compliance
    unreported_alerts: int = 0
    notification_required: int = 0

# === SIEM INTEGRATION SCHEMAS ===

class SiemAlertIngestion(BaseModel):
    """Schema for SIEM systems to submit alerts"""
    alerts: List[AlertCreate] = Field(..., min_items=1, max_items=50)
    source_system: str
    ingestion_timestamp: Optional[datetime] = None
    
    @validator('source_system')
    def validate_source_system(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Source system cannot be empty')
        return v.strip()

class SiemIngestionResponse(BaseModel):
    """Response for SIEM alert ingestion"""
    success: bool
    processed_count: int
    failed_count: int
    created_alert_ids: List[int] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    ingestion_id: str


# ===== ENDPOINT TOKEN SCHEMAS =====

class EndpointTokenBase(BaseModel):
    """Base endpoint token fields"""
    token_name: str = Field(..., min_length=1, max_length=100, description="Name for the token")
    description: Optional[str] = Field(None, max_length=500, description="Description of the token's purpose")
    
    # Permissions
    can_create_alerts: bool = Field(True, description="Allow creating alerts")
    can_update_alerts: bool = Field(False, description="Allow updating alerts")
    can_read_alerts: bool = Field(True, description="Allow reading alerts")
    
    # Rate limiting
    rate_limit_per_minute: int = Field(100, ge=1, le=1000, description="Requests per minute limit")
    
    # Access restrictions (optional)
    allowed_ips: Optional[List[str]] = Field(None, description="List of allowed IP addresses/ranges")
    allowed_sources: Optional[List[str]] = Field(None, description="List of allowed source systems")

class EndpointTokenCreate(EndpointTokenBase):
    """Schema for creating a new endpoint token"""
    # Expiration (optional)
    expires_in_days: Optional[int] = Field(None, ge=1, le=365, description="Token expiration in days")
    
    @validator('token_name')
    def validate_token_name(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError('Token name cannot be empty')
        # Check for valid characters (alphanumeric, spaces, hyphens, underscores)
        import re
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', v.strip()):
            raise ValueError('Token name can only contain letters, numbers, spaces, hyphens, and underscores')
        return v.strip()
    
    @validator('allowed_ips')
    def validate_ip_addresses(cls, v):
        if v is None:
            return v
        
        import ipaddress
        valid_ips = []
        for ip in v:
            try:
                # Try to parse as IP address or network
                ipaddress.ip_network(ip, strict=False)
                valid_ips.append(ip.strip())
            except ValueError:
                raise ValueError(f'Invalid IP address or network: {ip}')
        return valid_ips if valid_ips else None
    
    @validator('allowed_sources')
    def validate_source_systems(cls, v):
        if v is None:
            return v
        
        valid_sources = []
        for source in v:
            if source and source.strip():
                valid_sources.append(source.strip())
        return valid_sources if valid_sources else None

class EndpointTokenUpdate(BaseModel):
    """Schema for updating an endpoint token"""
    token_name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    
    # Permissions
    can_create_alerts: Optional[bool] = None
    can_update_alerts: Optional[bool] = None
    can_read_alerts: Optional[bool] = None
    
    # Rate limiting
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, le=1000)
    
    # Status
    is_active: Optional[bool] = None
    
    # Expiration
    expires_in_days: Optional[int] = Field(None, ge=1, le=365, description="Extend expiration by days from now")
    
    # Access restrictions
    allowed_ips: Optional[List[str]] = None
    allowed_sources: Optional[List[str]] = None
    
    @validator('token_name')
    def validate_token_name(cls, v):
        if v is None:
            return v
        if not v or len(v.strip()) == 0:
            raise ValueError('Token name cannot be empty')
        import re
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', v.strip()):
            raise ValueError('Token name can only contain letters, numbers, spaces, hyphens, and underscores')
        return v.strip()
    
    @validator('allowed_ips')
    def validate_ip_addresses(cls, v):
        if v is None:
            return v
        
        import ipaddress
        valid_ips = []
        for ip in v:
            try:
                ipaddress.ip_network(ip, strict=False)
                valid_ips.append(ip.strip())
            except ValueError:
                raise ValueError(f'Invalid IP address or network: {ip}')
        return valid_ips if valid_ips else None
    
    @validator('allowed_sources')
    def validate_source_systems(cls, v):
        if v is None:
            return v
        
        valid_sources = []
        for source in v:
            if source and source.strip():
                valid_sources.append(source.strip())
        return valid_sources if valid_sources else None

class EndpointTokenResponse(BaseModel):
    """Schema for endpoint token responses (without the actual token)"""
    id: int
    token_name: str
    token_prefix: str = Field(..., description="First 8 characters for identification")
    description: Optional[str] = None
    
    # Status
    is_active: bool
    expires_at: Optional[datetime] = None
    is_expired: bool = Field(..., description="Computed field indicating if token is expired")
    
    # Permissions
    can_create_alerts: bool
    can_update_alerts: bool
    can_read_alerts: bool
    
    # Rate limiting
    rate_limit_per_minute: int
    
    # Usage statistics
    total_requests: int = 0
    last_used_at: Optional[datetime] = None
    
    # Audit information
    created_by_id: int
    created_at: datetime
    updated_at: datetime
    
    # Access restrictions
    allowed_ips: Optional[List[str]] = None
    allowed_sources: Optional[List[str]] = None
    
    # Relationships
    created_by: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class EndpointTokenCreateResponse(BaseModel):
    """Schema for token creation response (includes the actual token once)"""
    token: str = Field(..., description="The actual token - only shown once")
    token_info: EndpointTokenResponse
    
    class Config:
        json_schema_extra = {
            "example": {
                "token": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                "token_info": {
                    "id": 1,
                    "token_name": "Firewall Integration",
                    "token_prefix": "a1b2c3d4",
                    "description": "Token for firewall to send security alerts",
                    "is_active": True,
                    "expires_at": "2025-04-15T10:30:00Z",
                    "is_expired": False,
                    "can_create_alerts": True,
                    "can_update_alerts": False,
                    "can_read_alerts": True,
                    "rate_limit_per_minute": 100,
                    "total_requests": 0,
                    "last_used_at": None,
                    "created_by_id": 1,
                    "created_at": "2025-01-15T10:30:00Z",
                    "updated_at": "2025-01-15T10:30:00Z",
                    "allowed_ips": ["192.168.1.0/24"],
                    "allowed_sources": ["Splunk", "Firewall"]
                }
            }
        }

class TokenValidationResponse(BaseModel):
    """Schema for token validation response"""
    valid: bool
    token_id: Optional[int] = None
    token_name: Optional[str] = None
    permissions: Optional[Dict[str, bool]] = None
    rate_limit_remaining: Optional[int] = None
    expires_at: Optional[datetime] = None
    message: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "valid": True,
                "token_id": 1,
                "token_name": "Firewall Integration",
                "permissions": {
                    "can_create_alerts": True,
                    "can_update_alerts": False,
                    "can_read_alerts": True
                },
                "rate_limit_remaining": 99,
                "expires_at": "2025-04-15T10:30:00Z",
                "message": None
            }
        }

class PaginatedTokenResponse(BaseModel):
    """Paginated response for tokens"""
    items: List[EndpointTokenResponse]
    total: int
    page: int
    size: int
    pages: int
    
class EndpointTokenSearchRequest(BaseModel):
    """Schema for searching endpoint tokens"""
    search: Optional[str] = Field(None, description="Search in token name and description")
    active_only: bool = Field(False, description="Show only active tokens")
    created_by_id: Optional[int] = Field(None, description="Filter by creator")
    expires_before: Optional[datetime] = Field(None, description="Filter tokens expiring before this date")
    expires_after: Optional[datetime] = Field(None, description="Filter tokens expiring after this date")
    last_used_before: Optional[datetime] = Field(None, description="Filter tokens last used before this date")
    last_used_after: Optional[datetime] = Field(None, description="Filter tokens last used after this date")
    
    # Pagination
    page: int = Field(1, ge=1, description="Page number")
    size: int = Field(20, ge=1, le=100, description="Items per page")
    
    # Sorting
    sort_by: str = Field("created_at", description="Sort field", 
                        pattern="^(created_at|updated_at|last_used_at|token_name|total_requests)$")
    sort_order: str = Field("desc", description="Sort order", pattern="^(asc|desc)$")

class TokenUsageStatsResponse(BaseModel):
    """Schema for token usage statistics"""
    token_id: int
    token_name: str
    token_prefix: str
    
    # Usage metrics
    total_requests: int
    requests_last_24h: int
    requests_last_7d: int
    requests_last_30d: int
    
    # Rate limiting stats
    rate_limit_per_minute: int
    current_minute_requests: int
    rate_limit_hits: int  # Number of times rate limit was exceeded
    
    # Time-based stats
    first_used_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    most_active_hour: Optional[int] = None  # Hour of day (0-23) with most requests
    
    # Status
    is_active: bool
    expires_at: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    
    class Config:
        from_attributes = True

class TokenPermissionsUpdate(BaseModel):
    """Schema for updating only token permissions"""
    can_create_alerts: Optional[bool] = None
    can_update_alerts: Optional[bool] = None
    can_read_alerts: Optional[bool] = None
    
    @validator('can_create_alerts', 'can_update_alerts', 'can_read_alerts')
    def at_least_one_permission(cls, v, values):
        # Ensure at least one permission is granted
        permissions = [v] + [values.get(field) for field in ['can_create_alerts', 'can_update_alerts', 'can_read_alerts']]
        if all(p is False for p in permissions if p is not None):
            raise ValueError('At least one permission must be granted')
        return v

class TokenRateLimitUpdate(BaseModel):
    """Schema for updating token rate limits"""
    rate_limit_per_minute: int = Field(..., ge=1, le=1000, description="New rate limit")
    reset_current_usage: bool = Field(False, description="Reset current minute usage counter")

class TokenSecurityUpdate(BaseModel):
    """Schema for updating token security settings"""
    allowed_ips: Optional[List[str]] = Field(None, description="Update allowed IP addresses")
    allowed_sources: Optional[List[str]] = Field(None, description="Update allowed source systems")
    
    @validator('allowed_ips')
    def validate_ip_addresses(cls, v):
        if v is None:
            return v
        
        import ipaddress
        valid_ips = []
        for ip in v:
            try:
                ipaddress.ip_network(ip, strict=False)
                valid_ips.append(ip.strip())
            except ValueError:
                raise ValueError(f'Invalid IP address or network: {ip}')
        return valid_ips if valid_ips else None
    
    @validator('allowed_sources')
    def validate_source_systems(cls, v):
        if v is None:
            return v
        
        valid_sources = []
        for source in v:
            if source and source.strip():
                valid_sources.append(source.strip())
        return valid_sources if valid_sources else None

class BulkTokenOperation(BaseModel):
    """Schema for bulk token operations"""
    token_ids: List[int] = Field(..., min_items=1, max_items=50, description="List of token IDs")
    operation: str = Field(..., description="Operation to perform", 
                          pattern="^(activate|deactivate|delete)$")
    
    class Config:
        json_schema_extra = {
            "example": {
                "token_ids": [1, 2, 3],
                "operation": "deactivate"
            }
        }

class BulkTokenOperationResponse(BaseModel):
    """Response for bulk token operations"""
    success: bool
    processed_count: int
    failed_count: int
    results: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "processed_count": 2,
                "failed_count": 1,
                "results": [
                    {"token_id": 1, "status": "deactivated"},
                    {"token_id": 2, "status": "deactivated"}
                ],
                "errors": ["Token 3 not found"]
            }
        }

# === TOKEN AUDIT SCHEMAS ===

class TokenAuditLogResponse(BaseModel):
    """Schema for token audit log entries"""
    id: int
    token_id: int
    token_name: str
    action: str  # created, updated, used, deactivated, deleted, rate_limited
    details: Dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    performed_by_id: Optional[int] = None
    performed_by: Optional[Dict[str, Any]] = None
    timestamp: datetime
    
    class Config:
        from_attributes = True

class TokenAuditSearchRequest(BaseModel):
    """Schema for searching token audit logs"""
    token_id: Optional[int] = None
    action: Optional[str] = None
    ip_address: Optional[str] = None
    performed_by_id: Optional[int] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    
    # Pagination
    page: int = Field(1, ge=1)
    size: int = Field(50, ge=1, le=100)
    
    # Sorting
    sort_order: str = Field("desc", pattern="^(asc|desc)$")