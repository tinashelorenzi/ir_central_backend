from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import json

from database import get_db
from auth_utils import get_current_user, require_admin, require_manager_or_above
from models.users import User
from models.endpoint_tokens import EndpointToken
from schemas import (
    EndpointTokenResponse, EndpointTokenCreateResponse, 
    TokenValidationResponse, PaginatedTokenResponse,
    EndpointTokenCreate, EndpointTokenUpdate
)

router = APIRouter(prefix="/endpoint-tokens", tags=["Endpoint Tokens"])

# ============================================================================
# PYDANTIC SCHEMAS
# ============================================================================





# ============================================================================
# ENDPOINT TOKEN ROUTES
# ============================================================================

@router.post("/", response_model=EndpointTokenCreateResponse)
async def create_endpoint_token(
    token_data: EndpointTokenCreate,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Create a new endpoint token for external systems to access the alert API.
    
    **Requires Manager role or above.**
    
    Returns the token value only once - it cannot be retrieved again.
    """
    
    # Check if token name already exists
    existing_token = db.query(EndpointToken).filter(
        EndpointToken.token_name == token_data.token_name
    ).first()
    
    if existing_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A token with this name already exists"
        )
    
    # Generate token
    raw_token, token_hash, token_prefix = EndpointToken.generate_token()
    
    # Calculate expiration if specified
    expires_at = None
    if token_data.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=token_data.expires_in_days)
    
    # Create token record
    token = EndpointToken(
        token_name=token_data.token_name,
        token_hash=token_hash,
        token_prefix=token_prefix,
        description=token_data.description,
        can_create_alerts=token_data.can_create_alerts,
        can_update_alerts=token_data.can_update_alerts,
        can_read_alerts=token_data.can_read_alerts,
        rate_limit_per_minute=token_data.rate_limit_per_minute,
        expires_at=expires_at,
        allowed_ips=json.dumps(token_data.allowed_ips) if token_data.allowed_ips else None,
        allowed_sources=json.dumps(token_data.allowed_sources) if token_data.allowed_sources else None,
        created_by_id=current_user.id
    )
    
    db.add(token)
    db.commit()
    db.refresh(token)
    
    # Prepare response - exclude is_expired from validation since it's a method
    token_data = {
        'id': token.id,
        'token_name': token.token_name,
        'token_prefix': token.token_prefix,
        'description': token.description,
        'is_active': token.is_active,
        'expires_at': token.expires_at,
        'is_expired': token.is_expired(),  # Call the method to get boolean value
        'can_create_alerts': token.can_create_alerts,
        'can_update_alerts': token.can_update_alerts,
        'can_read_alerts': token.can_read_alerts,
        'rate_limit_per_minute': token.rate_limit_per_minute,
        'total_requests': token.total_requests,
        'last_used_at': token.last_used_at,
        'created_by_id': token.created_by_id,
        'created_at': token.created_at,
        'updated_at': token.updated_at,
        'allowed_ips': None,
        'allowed_sources': None,
        'created_by': None
    }
    token_response = EndpointTokenResponse(**token_data)
    
    # Parse JSON fields for response
    if token.allowed_ips:
        token_response.allowed_ips = json.loads(token.allowed_ips)
    if token.allowed_sources:
        token_response.allowed_sources = json.loads(token.allowed_sources)
    
    return EndpointTokenCreateResponse(
        token=raw_token,  # Only time the raw token is returned
        token_info=token_response
    )

@router.get("/", response_model=PaginatedTokenResponse)
async def list_endpoint_tokens(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    active_only: bool = Query(False, description="Show only active tokens"),
    search: Optional[str] = Query(None, description="Search in token name and description"),
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    List all endpoint tokens with filtering and pagination.
    
    **Requires Manager role or above.**
    """
    
    query = db.query(EndpointToken)
    
    # Apply filters
    if active_only:
        query = query.filter(EndpointToken.is_active == True)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (EndpointToken.token_name.ilike(search_term)) |
            (EndpointToken.description.ilike(search_term))
        )
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    tokens = query.order_by(EndpointToken.created_at.desc()).offset(
        (page - 1) * size
    ).limit(size).all()
    
    # Convert to response format
    token_responses = []
    for token in tokens:
        # Prepare token data - exclude is_expired from validation since it's a method
        token_data = {
            'id': token.id,
            'token_name': token.token_name,
            'token_prefix': token.token_prefix,
            'description': token.description,
            'is_active': token.is_active,
            'expires_at': token.expires_at,
            'is_expired': token.is_expired(),  # Call the method to get boolean value
            'can_create_alerts': token.can_create_alerts,
            'can_update_alerts': token.can_update_alerts,
            'can_read_alerts': token.can_read_alerts,
            'rate_limit_per_minute': token.rate_limit_per_minute,
            'total_requests': token.total_requests,
            'last_used_at': token.last_used_at,
            'created_by_id': token.created_by_id,
            'created_at': token.created_at,
            'updated_at': token.updated_at,
            'allowed_ips': None,
            'allowed_sources': None,
            'created_by': None
        }
        token_response = EndpointTokenResponse(**token_data)
        
        # Parse JSON fields
        if token.allowed_ips:
            token_response.allowed_ips = json.loads(token.allowed_ips)
        if token.allowed_sources:
            token_response.allowed_sources = json.loads(token.allowed_sources)
        
        token_responses.append(token_response)
    
    return PaginatedTokenResponse(
        items=token_responses,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )

@router.get("/{token_id}", response_model=EndpointTokenResponse)
async def get_endpoint_token(
    token_id: int,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Get details of a specific endpoint token.
    
    **Requires Manager role or above.**
    """
    
    token = db.query(EndpointToken).filter(EndpointToken.id == token_id).first()
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    # Prepare token data - exclude is_expired from validation since it's a method
    token_data = {
        'id': token.id,
        'token_name': token.token_name,
        'token_prefix': token.token_prefix,
        'description': token.description,
        'is_active': token.is_active,
        'expires_at': token.expires_at,
        'is_expired': token.is_expired(),  # Call the method to get boolean value
        'can_create_alerts': token.can_create_alerts,
        'can_update_alerts': token.can_update_alerts,
        'can_read_alerts': token.can_read_alerts,
        'rate_limit_per_minute': token.rate_limit_per_minute,
        'total_requests': token.total_requests,
        'last_used_at': token.last_used_at,
        'created_by_id': token.created_by_id,
        'created_at': token.created_at,
        'updated_at': token.updated_at,
        'allowed_ips': None,
        'allowed_sources': None,
        'created_by': None
    }
    token_response = EndpointTokenResponse(**token_data)
    
    # Parse JSON fields
    if token.allowed_ips:
        token_response.allowed_ips = json.loads(token.allowed_ips)
    if token.allowed_sources:
        token_response.allowed_sources = json.loads(token.allowed_sources)
    
    return token_response

@router.put("/{token_id}", response_model=EndpointTokenResponse)
async def update_endpoint_token(
    token_id: int,
    token_data: EndpointTokenUpdate,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Update an endpoint token's settings.
    
    **Requires Manager role or above.**
    """
    
    token = db.query(EndpointToken).filter(EndpointToken.id == token_id).first()
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    # Update fields
    update_data = token_data.model_dump(exclude_unset=True)
    
    for field, value in update_data.items():
        if field == "expires_in_days" and value is not None:
            # Special handling for expiration extension
            token.expires_at = datetime.utcnow() + timedelta(days=value)
        elif field == "allowed_ips" and value is not None:
            token.allowed_ips = json.dumps(value)
        elif field == "allowed_sources" and value is not None:
            token.allowed_sources = json.dumps(value)
        elif field not in ["expires_in_days"]:  # Skip expires_in_days as it's handled above
            setattr(token, field, value)
    
    token.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(token)
    
    # Prepare token data - exclude is_expired from validation since it's a method
    token_data = {
        'id': token.id,
        'token_name': token.token_name,
        'token_prefix': token.token_prefix,
        'description': token.description,
        'is_active': token.is_active,
        'expires_at': token.expires_at,
        'is_expired': token.is_expired(),  # Call the method to get boolean value
        'can_create_alerts': token.can_create_alerts,
        'can_update_alerts': token.can_update_alerts,
        'can_read_alerts': token.can_read_alerts,
        'rate_limit_per_minute': token.rate_limit_per_minute,
        'total_requests': token.total_requests,
        'last_used_at': token.last_used_at,
        'created_by_id': token.created_by_id,
        'created_at': token.created_at,
        'updated_at': token.updated_at,
        'allowed_ips': None,
        'allowed_sources': None,
        'created_by': None
    }
    token_response = EndpointTokenResponse(**token_data)
    
    # Parse JSON fields
    if token.allowed_ips:
        token_response.allowed_ips = json.loads(token.allowed_ips)
    if token.allowed_sources:
        token_response.allowed_sources = json.loads(token.allowed_sources)
    
    return token_response

@router.delete("/{token_id}")
async def delete_endpoint_token(
    token_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Delete an endpoint token. This action cannot be undone.
    
    **Requires Admin role.**
    """
    
    token = db.query(EndpointToken).filter(EndpointToken.id == token_id).first()
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    db.delete(token)
    db.commit()
    
    return {"message": "Token deleted successfully"}

@router.post("/{token_id}/deactivate")
async def deactivate_endpoint_token(
    token_id: int,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Deactivate an endpoint token (can be reactivated later).
    
    **Requires Manager role or above.**
    """
    
    token = db.query(EndpointToken).filter(EndpointToken.id == token_id).first()
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    token.deactivate(db)
    
    return {"message": "Token deactivated successfully"}

@router.post("/{token_id}/activate")
async def activate_endpoint_token(
    token_id: int,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Reactivate a deactivated endpoint token.
    
    **Requires Manager role or above.**
    """
    
    token = db.query(EndpointToken).filter(EndpointToken.id == token_id).first()
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found"
        )
    
    token.is_active = True
    token.updated_at = datetime.utcnow()
    
    db.commit()
    
    return {"message": "Token activated successfully"}

# ============================================================================
# TOKEN VALIDATION ENDPOINT (For internal API use)
# ============================================================================

@router.post("/validate", response_model=TokenValidationResponse)
async def validate_token(
    token: str,
    db: Session = Depends(get_db)
):
    """
    Validate an endpoint token. This endpoint is used internally by the alert API.
    
    **This endpoint does not require authentication** as it's used by external systems.
    """
    
    # Hash the provided token
    token_hash = EndpointToken.hash_token(token)
    
    # Find the token in database
    db_token = db.query(EndpointToken).filter(
        EndpointToken.token_hash == token_hash
    ).first()
    
    if not db_token:
        return TokenValidationResponse(valid=False)
    
    # Check if token is valid
    if not db_token.is_valid():
        return TokenValidationResponse(valid=False)
    
    # Check rate limiting
    if not db_token.can_make_request():
        return TokenValidationResponse(
            valid=False,
            rate_limit_remaining=0
        )
    
    # Calculate remaining rate limit
    now = datetime.utcnow()
    current_minute = now.replace(second=0, microsecond=0)
    
    remaining_requests = db_token.rate_limit_per_minute
    if (db_token.request_count_minute_start and 
        db_token.request_count_minute_start >= current_minute):
        remaining_requests = db_token.rate_limit_per_minute - db_token.request_count_current_minute
    
    # Record the request
    db_token.record_request(db)
    
    return TokenValidationResponse(
        valid=True,
        token_id=db_token.id,
        token_name=db_token.token_name,
        permissions={
            "can_create_alerts": db_token.can_create_alerts,
            "can_update_alerts": db_token.can_update_alerts,
            "can_read_alerts": db_token.can_read_alerts
        },
        rate_limit_remaining=remaining_requests - 1,  # Subtract 1 for current request
        expires_at=db_token.expires_at
    )