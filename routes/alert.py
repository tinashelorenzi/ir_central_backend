

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, Request, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc, asc, func, text
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Union
import uuid
import logging
import json
from functools import wraps

from database import get_db
from auth_utils import get_current_user, require_role
from models.users import User
from models.alert import Alert, AlertSeverity, AlertStatus, AlertSource, ThreatType
from models.endpoint_tokens import EndpointToken
from schemas import (
    AlertCreate, AlertUpdate, AlertResponse, AlertSearchRequest,
    SiemAlertIngestion, SiemIngestionResponse, AlertStatsResponse,
    BulkAlertUpdate, AlertTagCreate, AlertTagResponse,
    AlertArtifactCreate, AlertArtifactResponse, MessageResponse
)

# Configure logging
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

# Security scheme for Swagger docs
security = HTTPBearer()

# ===== CUSTOM AUTHENTICATION DECORATORS =====

class TokenAuthenticationError(Exception):
    """Custom exception for token authentication errors"""
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code

async def validate_endpoint_token(
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> EndpointToken:
    """
    Validate endpoint token for external system authentication.
    Used by SIEM, IDS, firewall systems.
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = authorization.replace("Bearer ", "", 1)
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token not provided",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    try:
        # Hash the provided token
        token_hash = EndpointToken.hash_token(token)
        
        # Find token in database
        db_token = db.query(EndpointToken).filter(
            EndpointToken.token_hash == token_hash
        ).first()
        
        if not db_token:
            logger.warning(f"Invalid token attempt from {request.client.host}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Check if token is valid (active and not expired)
        if not db_token.is_valid():
            reason = "expired" if db_token.is_expired() else "inactive"
            logger.warning(f"Rejected {reason} token {db_token.token_prefix}... from {request.client.host}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token is {reason}",
                headers={"WWW-Authenticate": "Bearer"}
            )
        
        # Check rate limiting
        if not db_token.can_make_request():
            logger.warning(f"Rate limit exceeded for token {db_token.token_prefix}... from {request.client.host}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={
                    "WWW-Authenticate": "Bearer",
                    "Retry-After": "60"
                }
            )
        
        # Check IP restrictions if configured
        if db_token.allowed_ips:
            allowed_ips = json.loads(db_token.allowed_ips)
            client_ip = request.client.host
            
            if client_ip not in allowed_ips:
                logger.warning(f"IP {client_ip} not allowed for token {db_token.token_prefix}...")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="IP address not allowed for this token"
                )
        
        # Record the request
        db_token.record_request(db)
        
        logger.debug(f"Valid token {db_token.token_prefix}... used by {db_token.token_name}")
        
        return db_token
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token validation failed"
        )

def require_token_permission(permission: str):
    """
    Decorator factory to require specific token permissions.
    
    Args:
        permission: One of 'can_create_alerts', 'can_update_alerts', 'can_read_alerts'
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Get the token from kwargs (injected by dependency)
            token = kwargs.get('token')
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Token validation failed - internal error"
                )
            
            # Check permission
            if not getattr(token, permission, False):
                logger.warning(f"Token {token.token_prefix}... lacks permission: {permission}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Token does not have permission: {permission.replace('can_', '').replace('_', ' ')}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# ===== DUAL AUTHENTICATION DEPENDENCY =====

async def get_user_or_token(
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> Union[User, EndpointToken]:
    """
    Dependency that supports both JWT (for frontend) and token auth (for external systems).
    Returns either a User (for JWT) or EndpointToken (for API tokens).
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token = authorization.replace("Bearer ", "", 1)
    
    # Try JWT first (for frontend users)
    try:
        from auth_utils import AuthManager
        payload = AuthManager.verify_token(token)
        if payload:
            user = db.query(User).filter(User.id == payload.get("user_id")).first()
            if user:
                return user
    except Exception:
        pass  # If JWT fails, try endpoint token
    
    # Try endpoint token (for external systems)
    try:
        return await validate_endpoint_token(request, authorization, db)
    except Exception:
        pass
    
    # If both fail
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )

# ===== SIEM INTEGRATION ENDPOINTS (TOKEN AUTH) =====

@router.post("/ingest", response_model=SiemIngestionResponse)
async def ingest_alerts_from_siem(
    ingestion_request: SiemAlertIngestion,
    background_tasks: BackgroundTasks,
    request: Request,
    token: EndpointToken = Depends(validate_endpoint_token),
    db: Session = Depends(get_db)
):
    """
    Bulk ingestion endpoint for SIEM systems to submit alerts.
    This is the primary endpoint used by external SIEM/IDS systems.
    
    **Authentication: Requires valid endpoint token with 'can_create_alerts' permission.**
    """
    # Check permission
    if not token.can_create_alerts:
        logger.warning(f"Token {token.token_prefix}... attempted alert creation without permission")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not have permission to create alerts"
        )
    
    try:
        ingestion_id = str(uuid.uuid4())
        created_alert_ids = []
        errors = []
        processed_count = 0
        failed_count = 0
        
        logger.info(f"Starting alert ingestion {ingestion_id} from {ingestion_request.source_system} via token {token.token_name}")
        logger.info(f"Processing {len(ingestion_request.alerts)} alerts")
        
        # Check source restrictions if configured
        if token.allowed_sources:
            allowed_sources = json.loads(token.allowed_sources)
            if ingestion_request.source_system not in allowed_sources:
                logger.warning(f"Source system {ingestion_request.source_system} not allowed for token {token.token_prefix}...")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Source system '{ingestion_request.source_system}' not allowed for this token"
                )
        
        for idx, alert_data in enumerate(ingestion_request.alerts):
            try:
                # Check for duplicate external alert ID
                existing_alert = db.query(Alert).filter(
                    Alert.external_alert_id == alert_data.external_alert_id,
                    Alert.source == alert_data.source
                ).first()
                
                if existing_alert:
                    logger.warning(f"Duplicate alert {alert_data.external_alert_id} from {alert_data.source}")
                    errors.append(f"Alert {idx}: Duplicate external_alert_id {alert_data.external_alert_id}")
                    failed_count += 1
                    continue
                
                # Create new alert
                alert = Alert(
                    external_alert_id=alert_data.external_alert_id,
                    title=alert_data.title,
                    description=alert_data.description,
                    severity=alert_data.severity,
                    source=alert_data.source,
                    threat_type=alert_data.threat_type or ThreatType.UNKNOWN,
                    detected_at=alert_data.detected_at,
                    
                    # Source system info
                    source_system=alert_data.source_system or ingestion_request.source_system,
                    rule_id=alert_data.rule_id,
                    rule_name=alert_data.rule_name,
                    
                    # Network info
                    source_ip=alert_data.source_ip,
                    destination_ip=alert_data.destination_ip,
                    source_port=alert_data.source_port,
                    destination_port=alert_data.destination_port,
                    protocol=alert_data.protocol,
                    
                    # Asset info
                    affected_hostname=alert_data.affected_hostname,
                    affected_user=alert_data.affected_user,
                    asset_criticality=alert_data.asset_criticality,
                    
                    # System fields
                    status=AlertStatus.NEW,
                    received_at=ingestion_request.ingestion_timestamp or datetime.utcnow(),
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                    
                    # Store token info for audit trail
                    raw_alert_data={"ingested_via_token": token.token_name, "token_id": token.id}
                )
                
                db.add(alert)
                db.flush()  # Get the ID without committing
                
                created_alert_ids.append(alert.id)
                processed_count += 1
                
                logger.debug(f"Created alert {alert.id} from external ID {alert_data.external_alert_id}")
                
            except Exception as e:
                logger.error(f"Error processing alert {idx}: {str(e)}")
                errors.append(f"Alert {idx}: {str(e)}")
                failed_count += 1
                continue
        
        # Commit all successful alerts
        if processed_count > 0:
            db.commit()
            logger.info(f"Successfully committed {processed_count} alerts via token {token.token_name}")
            
            # Schedule background task for alert processing
            background_tasks.add_task(process_new_alerts, created_alert_ids)
        else:
            db.rollback()
            
        success = processed_count > 0
        
        logger.info(f"Ingestion {ingestion_id} completed: {processed_count} processed, {failed_count} failed")
        
        return SiemIngestionResponse(
            success=success,
            processed_count=processed_count,
            failed_count=failed_count,
            created_alert_ids=created_alert_ids,
            errors=errors,
            ingestion_id=ingestion_id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Critical error during alert ingestion: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Alert ingestion failed: {str(e)}"
        )

@router.post("/single", response_model=AlertResponse)
async def create_single_alert(
    alert_data: AlertCreate,
    background_tasks: BackgroundTasks,
    request: Request,
    token: EndpointToken = Depends(validate_endpoint_token),
    db: Session = Depends(get_db)
):
    """
    Create a single alert (for manual submission or simple integrations).
    
    **Authentication: Requires valid endpoint token with 'can_create_alerts' permission.**
    """
    # Check permission
    if not token.can_create_alerts:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not have permission to create alerts"
        )
    
    try:
        # Check source restrictions
        if token.allowed_sources:
            allowed_sources = json.loads(token.allowed_sources)
            if alert_data.source_system and alert_data.source_system not in allowed_sources:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Source system '{alert_data.source_system}' not allowed for this token"
                )
        
        # Check for duplicate
        existing_alert = db.query(Alert).filter(
            Alert.external_alert_id == alert_data.external_alert_id,
            Alert.source == alert_data.source
        ).first()
        
        if existing_alert:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Alert with external_alert_id '{alert_data.external_alert_id}' already exists"
            )
        
        # Create alert
        alert = Alert(
            external_alert_id=alert_data.external_alert_id,
            title=alert_data.title,
            description=alert_data.description,
            severity=alert_data.severity,
            source=alert_data.source,
            threat_type=alert_data.threat_type or ThreatType.UNKNOWN,
            detected_at=alert_data.detected_at,
            source_system=alert_data.source_system,
            rule_id=alert_data.rule_id,
            rule_name=alert_data.rule_name,
            source_ip=alert_data.source_ip,
            destination_ip=alert_data.destination_ip,
            source_port=alert_data.source_port,
            destination_port=alert_data.destination_port,
            protocol=alert_data.protocol,
            affected_hostname=alert_data.affected_hostname,
            affected_user=alert_data.affected_user,
            asset_criticality=alert_data.asset_criticality,
            status=AlertStatus.NEW,
            received_at=datetime.utcnow(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            raw_alert_data={"created_via_token": token.token_name, "token_id": token.id}
        )
        
        db.add(alert)
        db.commit()
        db.refresh(alert)
        
        # Schedule background processing
        background_tasks.add_task(process_new_alerts, [alert.id])
        
        logger.info(f"Created single alert {alert.id} from external ID {alert_data.external_alert_id} via token {token.token_name}")
        
        return AlertResponse.from_orm(alert)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating single alert: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create alert: {str(e)}"
        )

# ===== ALERT QUERY AND MANAGEMENT ENDPOINTS (DUAL AUTH) =====

@router.get("/", response_model=Dict[str, Any])
async def list_alerts(
    search: Optional[str] = Query(None, description="Search in title/description"),
    severity: Optional[List[AlertSeverity]] = Query(None, description="Filter by severity"),
    status: Optional[List[AlertStatus]] = Query(None, description="Filter by status"),
    source: Optional[List[str]] = Query(None, description="Filter by source"),
    threat_type: Optional[List[ThreatType]] = Query(None, description="Filter by threat type"),
    assigned_analyst_id: Optional[int] = Query(None, description="Filter by assigned analyst"),
    incident_id: Optional[str] = Query(None, description="Filter by incident ID"),
    detected_after: Optional[datetime] = Query(None, description="Filter alerts detected after this time"),
    detected_before: Optional[datetime] = Query(None, description="Filter alerts detected before this time"),
    received_after: Optional[datetime] = Query(None, description="Filter alerts received after this time"),
    received_before: Optional[datetime] = Query(None, description="Filter alerts received before this time"),
    false_positives: Optional[bool] = Query(None, description="Include/exclude false positives"),
    reported: Optional[bool] = Query(None, description="Filter by reporting status"),
    overdue_only: Optional[bool] = Query(False, description="Show only overdue alerts"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    sort_by: str = Query("received_at", regex="^(received_at|detected_at|severity|status|updated_at)$"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    auth: Union[User, EndpointToken] = Depends(get_user_or_token),
    db: Session = Depends(get_db)
):
    """
    List and search alerts with comprehensive filtering options.
    
    **Authentication: Supports both JWT tokens (frontend) and endpoint tokens (external systems).**
    **For endpoint tokens: Requires 'can_read_alerts' permission.**
    """
    # Check permissions for token-based auth
    if isinstance(auth, EndpointToken):
        if not auth.can_read_alerts:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token does not have permission to read alerts"
            )
    
    try:
        # Build base query
        query = db.query(Alert).options(joinedload(Alert.assigned_analyst))
        
        # Apply filters (same as before)
        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                or_(
                    Alert.title.ilike(search_filter),
                    Alert.description.ilike(search_filter),
                    Alert.external_alert_id.ilike(search_filter)
                )
            )
        
        if severity:
            query = query.filter(Alert.severity.in_(severity))
        
        if status:
            query = query.filter(Alert.status.in_(status))
        
        if source:
            query = query.filter(Alert.source.in_(source))
        
        if threat_type:
            query = query.filter(Alert.threat_type.in_(threat_type))
        
        if assigned_analyst_id:
            query = query.filter(Alert.assigned_analyst_id == assigned_analyst_id)
        
        if incident_id:
            query = query.filter(Alert.incident_id == incident_id)
        
        if detected_after:
            query = query.filter(Alert.detected_at >= detected_after)
        
        if detected_before:
            query = query.filter(Alert.detected_at <= detected_before)
        
        if received_after:
            query = query.filter(Alert.received_at >= received_after)
        
        if received_before:
            query = query.filter(Alert.received_at <= received_before)
        
        if false_positives is not None:
            if false_positives:
                query = query.filter(Alert.status == AlertStatus.FALSE_POSITIVE)
            else:
                query = query.filter(Alert.status != AlertStatus.FALSE_POSITIVE)
        
        if reported is not None:
            query = query.filter(Alert.reported == reported)
        
        if overdue_only:
            overdue_threshold = datetime.utcnow() - timedelta(hours=24)
            query = query.filter(
                and_(
                    Alert.received_at <= overdue_threshold,
                    Alert.status.in_([AlertStatus.NEW, AlertStatus.TRIAGED, AlertStatus.INVESTIGATING])
                )
            )
        
        # Apply sorting
        sort_column = getattr(Alert, sort_by)
        if sort_order == "desc":
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(asc(sort_column))
        
        # Get total count
        total_count = query.count()
        
        # Apply pagination
        offset = (page - 1) * size
        alerts = query.offset(offset).limit(size).all()
        
        # Convert to response format
        alert_responses = []
        for alert in alerts:
            alert_response = AlertResponse.from_orm(alert)
            # Calculate computed fields
            if alert.received_at and alert.first_response_at:
                alert_response.time_to_first_response = (alert.first_response_at - alert.received_at).total_seconds() / 60
            if alert.received_at and alert.resolution_at:
                alert_response.time_to_resolution = (alert.resolution_at - alert.received_at).total_seconds() / 60
            
            alert_responses.append(alert_response)
        
        return {
            "alerts": alert_responses,
            "pagination": {
                "page": page,
                "size": size,
                "total": total_count,
                "total_pages": (total_count + size - 1) // size
            },
            "filters_applied": {
                "search": search,
                "severity": severity,
                "status": status,
                "source": source,
                "threat_type": threat_type,
                "assigned_analyst_id": assigned_analyst_id,
                "incident_id": incident_id,
                "overdue_only": overdue_only
            }
        }
        
    except Exception as e:
        logger.error(f"Error listing alerts: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve alerts: {str(e)}"
        )

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    auth: Union[User, EndpointToken] = Depends(get_user_or_token),
    db: Session = Depends(get_db)
):
    """
    Get a specific alert by ID with full details.
    
    **Authentication: Supports both JWT tokens (frontend) and endpoint tokens (external systems).**
    **For endpoint tokens: Requires 'can_read_alerts' permission.**
    """
    # Check permissions for token-based auth
    if isinstance(auth, EndpointToken):
        if not auth.can_read_alerts:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token does not have permission to read alerts"
            )
    
    alert = db.query(Alert).options(
        joinedload(Alert.assigned_analyst)
    ).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found"
        )
    
    # Convert to response and add computed fields
    alert_response = AlertResponse.from_orm(alert)
    
    # Calculate timing metrics
    if alert.received_at and alert.first_response_at:
        alert_response.time_to_first_response = (alert.first_response_at - alert.received_at).total_seconds() / 60
    if alert.received_at and alert.resolution_at:
        alert_response.time_to_resolution = (alert.resolution_at - alert.received_at).total_seconds() / 60
    
    # Check if overdue
    if alert.status in [AlertStatus.NEW, AlertStatus.TRIAGED, AlertStatus.INVESTIGATING]:
        overdue_threshold = datetime.utcnow() - timedelta(hours=24)
        alert_response.is_overdue = alert.received_at <= overdue_threshold
    
    return alert_response

@router.put("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    alert_update: AlertUpdate,
    auth: Union[User, EndpointToken] = Depends(get_user_or_token),
    db: Session = Depends(get_db)
):
    """
    Update an alert (for analysts to update status, assignment, etc.).
    
    **Authentication: Supports both JWT tokens (frontend) and endpoint tokens (external systems).**
    **For endpoint tokens: Requires 'can_update_alerts' permission.**
    """
    # Check permissions for token-based auth
    if isinstance(auth, EndpointToken):
        if not auth.can_update_alerts:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token does not have permission to update alerts"
            )
    
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id} not found"
        )
    
    try:
        # Track status changes for timing metrics
        old_status = alert.status
        update_data = alert_update.dict(exclude_unset=True)
        
        # Update fields
        for field, value in update_data.items():
            if hasattr(alert, field):
                setattr(alert, field, value)
        
        # Update timing fields based on status changes
        now = datetime.utcnow()
        
        if 'status' in update_data:
            new_status = update_data['status']
            
            # First response tracking
            if old_status == AlertStatus.NEW and new_status in [AlertStatus.TRIAGED, AlertStatus.INVESTIGATING]:
                if not alert.first_response_at:
                    alert.first_response_at = now
            
            # Containment tracking
            if new_status == AlertStatus.CONTAINED and not alert.containment_at:
                alert.containment_at = now
            
            # Resolution tracking
            if new_status in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.CLOSED]:
                if not alert.resolution_at:
                    alert.resolution_at = now
                if not alert.closed_at:
                    alert.closed_at = now
        
        alert.updated_at = now
        
        # Add audit info based on auth type
        if isinstance(auth, EndpointToken):
            if not alert.raw_alert_data:
                alert.raw_alert_data = {}
            alert.raw_alert_data["last_updated_via_token"] = auth.token_name
        
        db.commit()
        db.refresh(alert)
        
        auth_info = f"token {auth.token_name}" if isinstance(auth, EndpointToken) else f"user {auth.id}"
        logger.info(f"Updated alert {alert_id} by {auth_info}")
        
        return AlertResponse.from_orm(alert)
        
    except Exception as e:
        logger.error(f"Error updating alert {alert_id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update alert: {str(e)}"
        )

# ===== ADMIN/ANALYST ONLY ENDPOINTS (JWT AUTH ONLY) =====

@router.get("/stats/overview", response_model=AlertStatsResponse)
async def get_alert_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get alert statistics overview for dashboards.
    
    **Authentication: JWT only (frontend users)**
    """
    try:
        # Basic counts by status
        total_alerts = db.query(Alert).count()
        new_alerts = db.query(Alert).filter(Alert.status == AlertStatus.NEW).count()
        in_progress_alerts = db.query(Alert).filter(Alert.status.in_([
            AlertStatus.TRIAGED, AlertStatus.INVESTIGATING, AlertStatus.CONTAINED
        ])).count()
        resolved_alerts = db.query(Alert).filter(Alert.status == AlertStatus.RESOLVED).count()
        false_positives = db.query(Alert).filter(Alert.status == AlertStatus.FALSE_POSITIVE).count()
        
        # Overdue alerts
        overdue_threshold = datetime.utcnow() - timedelta(hours=24)
        overdue_alerts = db.query(Alert).filter(
            and_(
                Alert.received_at <= overdue_threshold,
                Alert.status.in_([AlertStatus.NEW, AlertStatus.TRIAGED, AlertStatus.INVESTIGATING])
            )
        ).count()
        
        # Severity breakdown
        critical_alerts = db.query(Alert).filter(Alert.severity == AlertSeverity.CRITICAL).count()
        high_alerts = db.query(Alert).filter(Alert.severity == AlertSeverity.HIGH).count()
        medium_alerts = db.query(Alert).filter(Alert.severity == AlertSeverity.MEDIUM).count()
        low_alerts = db.query(Alert).filter(Alert.severity == AlertSeverity.LOW).count()
        
        # Compliance metrics
        unreported_alerts = db.query(Alert).filter(Alert.reported == False).count()
        notification_required = db.query(Alert).filter(Alert.requires_notification == True).count()
        
        # Calculate average response and resolution times
        avg_response_time = None
        avg_resolution_time = None
        
        # Response time calculation
        response_times = db.query(
            func.extract('epoch', Alert.first_response_at - Alert.received_at) / 60
        ).filter(
            and_(Alert.first_response_at.isnot(None), Alert.received_at.isnot(None))
        ).all()
        
        if response_times:
            valid_response_times = [t[0] for t in response_times if t[0] is not None]
            if valid_response_times:
                avg_response_time = sum(valid_response_times) / len(valid_response_times)
        
        # Resolution time calculation
        resolution_times = db.query(
            func.extract('epoch', Alert.resolution_at - Alert.received_at) / 60
        ).filter(
            and_(Alert.resolution_at.isnot(None), Alert.received_at.isnot(None))
        ).all()
        
        if resolution_times:
            valid_resolution_times = [t[0] for t in resolution_times if t[0] is not None]
            if valid_resolution_times:
                avg_resolution_time = sum(valid_resolution_times) / len(valid_resolution_times)
        
        return AlertStatsResponse(
            total_alerts=total_alerts,
            new_alerts=new_alerts,
            in_progress_alerts=in_progress_alerts,
            resolved_alerts=resolved_alerts,
            false_positives=false_positives,
            overdue_alerts=overdue_alerts,
            avg_response_time=avg_response_time,
            avg_resolution_time=avg_resolution_time,
            critical_alerts=critical_alerts,
            high_alerts=high_alerts,
            medium_alerts=medium_alerts,
            low_alerts=low_alerts,
            unreported_alerts=unreported_alerts,
            notification_required=notification_required
        )
        
    except Exception as e:
        logger.error(f"Error getting alert stats: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get alert statistics: {str(e)}"
        )

@router.put("/bulk/update", response_model=MessageResponse)
async def bulk_update_alerts(
    bulk_update: BulkAlertUpdate,
    current_user: User = Depends(require_role(["senior_analyst", "manager", "admin"])),
    db: Session = Depends(get_db)
):
    """
    Bulk update multiple alerts (requires elevated permissions).
    
    **Authentication: JWT only (frontend users with elevated roles)**
    """
    try:
        # Get all alerts to update
        alerts = db.query(Alert).filter(Alert.id.in_(bulk_update.alert_ids)).all()
        
        if len(alerts) != len(bulk_update.alert_ids):
            found_ids = [alert.id for alert in alerts]
            missing_ids = [aid for aid in bulk_update.alert_ids if aid not in found_ids]
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alerts not found: {missing_ids}"
            )
        
        update_data = bulk_update.updates.dict(exclude_unset=True)
        now = datetime.utcnow()
        
        # Apply updates to all alerts
        for alert in alerts:
            for field, value in update_data.items():
                if hasattr(alert, field):
                    setattr(alert, field, value)
            alert.updated_at = now
        
        db.commit()
        
        logger.info(f"Bulk updated {len(alerts)} alerts by user {current_user.id}")
        
        return MessageResponse(message=f"Successfully updated {len(alerts)} alerts")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in bulk update: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Bulk update failed: {str(e)}"
        )

# ===== HEALTH CHECK ENDPOINT (NO AUTH REQUIRED) =====

@router.get("/health", response_model=Dict[str, Any])
async def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint for SIEM systems to verify API availability.
    
    **Authentication: None required**
    """
    try:
        # Test database connectivity
        db.execute(text("SELECT 1"))
        
        # Get basic stats
        total_alerts = db.query(Alert).count()
        recent_alerts = db.query(Alert).filter(
            Alert.received_at >= datetime.utcnow() - timedelta(hours=24)
        ).count()
        
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected",
            "total_alerts": total_alerts,
            "alerts_last_24h": recent_alerts,
            "authentication": {
                "jwt_auth": "available",
                "token_auth": "available"
            }
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Service unhealthy: {str(e)}"
        )

# ===== TOKEN INFORMATION ENDPOINT =====

@router.get("/token/info", response_model=Dict[str, Any])
async def get_token_info(
    token: EndpointToken = Depends(validate_endpoint_token),
    db: Session = Depends(get_db)
):
    """
    Get information about the current token (for external systems to verify their config).
    
    **Authentication: Endpoint token only**
    """
    try:
        # Calculate rate limit status
        now = datetime.utcnow()
        current_minute = now.replace(second=0, microsecond=0)
        
        remaining_requests = token.rate_limit_per_minute
        if (token.request_count_minute_start and 
            token.request_count_minute_start >= current_minute):
            remaining_requests = token.rate_limit_per_minute - token.request_count_current_minute
        
        # Parse allowed restrictions
        allowed_ips = None
        allowed_sources = None
        
        if token.allowed_ips:
            try:
                allowed_ips = json.loads(token.allowed_ips)
            except:
                pass
        
        if token.allowed_sources:
            try:
                allowed_sources = json.loads(token.allowed_sources)
            except:
                pass
        
        return {
            "token_name": token.token_name,
            "token_prefix": token.token_prefix,
            "permissions": {
                "can_create_alerts": token.can_create_alerts,
                "can_update_alerts": token.can_update_alerts,
                "can_read_alerts": token.can_read_alerts
            },
            "rate_limiting": {
                "requests_per_minute": token.rate_limit_per_minute,
                "remaining_this_minute": remaining_requests,
                "total_requests_made": token.total_requests
            },
            "restrictions": {
                "allowed_ips": allowed_ips,
                "allowed_sources": allowed_sources
            },
            "status": {
                "is_active": token.is_active,
                "expires_at": token.expires_at.isoformat() if token.expires_at else None,
                "is_expired": token.is_expired(),
                "last_used_at": token.last_used_at.isoformat() if token.last_used_at else None
            },
            "created_at": token.created_at.isoformat(),
            "updated_at": token.updated_at.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting token info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get token information: {str(e)}"
        )

# ===== BACKGROUND TASK FUNCTIONS =====

async def process_new_alerts(alert_ids: List[int]):
    """
    Background task to process newly created alerts
    (auto-assignment, playbook triggering, notifications, etc.)
    """
    try:
        logger.info(f"Processing {len(alert_ids)} new alerts in background")
        
        # This is where you would implement:
        # 1. Auto-assignment logic based on alert attributes
        # 2. Automatic playbook triggering for high-severity alerts
        # 3. Notification sending to analysts
        # 4. Integration with external systems
        # 5. Threat intelligence enrichment
        
        # For now, just log the processing
        for alert_id in alert_ids:
            logger.info(f"Processed alert {alert_id}")
            
    except Exception as e:
        logger.error(f"Error processing new alerts: {str(e)}")

# ===== ADDITIONAL UTILITY ENDPOINTS =====

@router.get("/sources", response_model=List[str])
async def get_alert_sources(
    auth: Union[User, EndpointToken] = Depends(get_user_or_token),
    db: Session = Depends(get_db)
):
    """
    Get list of all alert sources in the system.
    
    **Authentication: Supports both JWT and endpoint tokens with read permission**
    """
    # Check permissions for token-based auth
    if isinstance(auth, EndpointToken):
        if not auth.can_read_alerts:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token does not have permission to read alerts"
            )
    
    try:
        sources = db.query(Alert.source).distinct().all()
        return [source[0] for source in sources if source[0]]
    except Exception as e:
        logger.error(f"Error getting alert sources: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get alert sources"
        )

@router.get("/source-systems", response_model=List[str])
async def get_source_systems(
    auth: Union[User, EndpointToken] = Depends(get_user_or_token),
    db: Session = Depends(get_db)
):
    """
    Get list of all source systems in the system.
    
    **Authentication: Supports both JWT and endpoint tokens with read permission**
    """
    # Check permissions for token-based auth
    if isinstance(auth, EndpointToken):
        if not auth.can_read_alerts:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token does not have permission to read alerts"
            )
    
    try:
        systems = db.query(Alert.source_system).distinct().all()
        return [system[0] for system in systems if system[0]]
    except Exception as e:
        logger.error(f"Error getting source systems: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get source systems"
        )