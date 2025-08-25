"""
Report Templates API Routes
Handles management of IR report templates
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc, asc, func
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging

from database import get_db
from models.users import User, UserRole
from models.report_templates import ReportTemplate, ReportTemplateStatus
from auth_utils import get_current_user, require_manager_or_above
from schemas import (
    ReportTemplateCreate, ReportTemplateUpdate, ReportTemplateResponse,
    ReportTemplateSearchRequest, ReportTemplateListResponse, ReportTemplateStatsResponse,
    BulkReportTemplateOperation, ReportTemplateCloneRequest, 
    MessageResponse, PaginatedResponse
)

# Configure logging
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/report-templates", tags=["report-templates"])

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def build_template_query(db: Session, search_params: ReportTemplateSearchRequest, current_user: User):
    """Build query for report template search with filters"""
    query = db.query(ReportTemplate).options(
        joinedload(ReportTemplate.created_by),
        joinedload(ReportTemplate.updated_by)
    )
    
    # Search in name, description, author
    if search_params.search:
        search_term = f"%{search_params.search}%"
        query = query.filter(
            or_(
                ReportTemplate.name.ilike(search_term),
                ReportTemplate.description.ilike(search_term),
                ReportTemplate.author.ilike(search_term)
            )
        )
    
    # Filter by status
    if search_params.status:
        query = query.filter(ReportTemplate.status == search_params.status)
    
    # Filter by author
    if search_params.author:
        query = query.filter(ReportTemplate.author.ilike(f"%{search_params.author}%"))
    
    # Filter by creator
    if search_params.created_by_id:
        query = query.filter(ReportTemplate.created_by_id == search_params.created_by_id)
    
    # Filter by default status
    if search_params.is_default is not None:
        query = query.filter(ReportTemplate.is_default == search_params.is_default)
    
    # Filter by tags (if any of the specified tags match)
    if search_params.tags:
        tag_conditions = []
        for tag in search_params.tags:
            tag_conditions.append(ReportTemplate.tags.ilike(f"%{tag}%"))
        query = query.filter(or_(*tag_conditions))
    
    # Filter by incident types
    if search_params.incident_types:
        type_conditions = []
        for incident_type in search_params.incident_types:
            type_conditions.append(ReportTemplate.incident_types.ilike(f"%{incident_type}%"))
        query = query.filter(or_(*type_conditions))
    
    return query

def format_template_response(template: ReportTemplate) -> dict:
    """Format report template for API response"""
    response_data = template.to_dict()
    
    # Add creator information
    if template.created_by:
        response_data["created_by"] = {
            "id": template.created_by.id,
            "username": template.created_by.username,
            "full_name": template.created_by.full_name
        }
    
    # Add updater information
    if template.updated_by:
        response_data["updated_by"] = {
            "id": template.updated_by.id,
            "username": template.updated_by.username,
            "full_name": template.updated_by.full_name
        }
    
    return response_data

# ============================================================================
# CRUD ENDPOINTS
# ============================================================================

@router.post("/", response_model=ReportTemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_report_template(
    template_data: ReportTemplateCreate,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Create a new report template.
    Requires Manager role or above.
    """
    try:
        # Check if template name already exists
        existing = db.query(ReportTemplate).filter(
            ReportTemplate.name == template_data.name
        ).first()
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A template with this name already exists"
            )
        
        # Create new template
        new_template = ReportTemplate(
            name=template_data.name,
            description=template_data.description,
            author=template_data.author,
            content=template_data.content,
            version=template_data.version,
            tags=', '.join(template_data.tags) if template_data.tags else None,
            incident_types=', '.join(template_data.incident_types) if template_data.incident_types else None,
            is_default=template_data.is_default,
            requires_approval=template_data.requires_approval,
            created_by_id=current_user.id,
            status=ReportTemplateStatus.DRAFT
        )
        
        # If this is set as default, unset all other defaults
        if template_data.is_default:
            db.query(ReportTemplate).filter(
                ReportTemplate.is_default == True
            ).update({"is_default": False})
        
        db.add(new_template)
        db.commit()
        db.refresh(new_template)
        
        logger.info(f"Report template '{new_template.name}' created by user {current_user.username}")
        
        return format_template_response(new_template)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating report template: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create report template"
        )

@router.get("/", response_model=ReportTemplateListResponse)
async def list_report_templates(
    search: Optional[str] = Query(None, description="Search in name, description, author"),
    status: Optional[str] = Query(None, description="Filter by status"),
    author: Optional[str] = Query(None, description="Filter by author"),
    is_default: Optional[bool] = Query(None, description="Filter by default status"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    sort_by: str = Query("updated_at", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List report templates with optional filtering and pagination.
    """
    try:
        # Build search parameters
        search_params = ReportTemplateSearchRequest(
            search=search,
            status=status,
            author=author,
            is_default=is_default,
            page=page,
            limit=limit,
            sort_by=sort_by,
            sort_order=sort_order
        )
        
        # Build query
        query = build_template_query(db, search_params, current_user)

        print(f"Query: {query}")
        
        # Apply sorting
        sort_column = getattr(ReportTemplate, search_params.sort_by)
        if search_params.sort_order == "desc":
            query = query.order_by(desc(sort_column))
        else:
            query = query.order_by(asc(sort_column))
        
        
        # Get total count
        total = query.count()
        print(f"Total templates: {total}")
        
        # Apply pagination
        offset = (search_params.page - 1) * search_params.limit
        templates = query.offset(offset).limit(search_params.limit).all()

        print(f"Templates: {templates}")
        
        # Format response
        template_responses = [format_template_response(template) for template in templates]
        
        print(f"Template responses: {template_responses}")

        return ReportTemplateListResponse(
            templates=template_responses,
            total=total,
            page=search_params.page,
            limit=search_params.limit,
            pages=(total + search_params.limit - 1) // search_params.limit
        )
        
    except Exception as e:
        logger.error(f"Error listing report templates: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve report templates"
        )

@router.get("/{template_id}", response_model=ReportTemplateResponse)
async def get_report_template(
    template_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a specific report template by ID.
    """
    print()
    try:
        template = db.query(ReportTemplate).options(
            joinedload(ReportTemplate.created_by),
            joinedload(ReportTemplate.updated_by)
        ).filter(ReportTemplate.id == template_id).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
        
        return format_template_response(template)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving report template {template_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve report template"
        )

@router.put("/{template_id}", response_model=ReportTemplateResponse)
async def update_report_template(
    template_id: int,
    template_data: ReportTemplateUpdate,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Update a report template.
    Requires Manager role or above.
    """
    try:
        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == template_id
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
        
        # Check for name conflicts if name is being changed
        if template_data.name and template_data.name != template.name:
            existing = db.query(ReportTemplate).filter(
                and_(
                    ReportTemplate.name == template_data.name,
                    ReportTemplate.id != template_id
                )
            ).first()
            
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A template with this name already exists"
                )
        
        # Update fields that are provided
        update_data = template_data.dict(exclude_unset=True)
        
        # Handle tags and incident_types
        if 'tags' in update_data:
            template.tags = ', '.join(update_data['tags']) if update_data['tags'] else None
            del update_data['tags']
        
        if 'incident_types' in update_data:
            template.incident_types = ', '.join(update_data['incident_types']) if update_data['incident_types'] else None
            del update_data['incident_types']
        
        # If setting as default, unset all other defaults
        if update_data.get('is_default'):
            db.query(ReportTemplate).filter(
                and_(
                    ReportTemplate.is_default == True,
                    ReportTemplate.id != template_id
                )
            ).update({"is_default": False})
        
        # Apply updates
        for field, value in update_data.items():
            setattr(template, field, value)
        
        template.updated_by_id = current_user.id
        template.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(template)
        
        logger.info(f"Report template '{template.name}' updated by user {current_user.username}")
        
        return format_template_response(template)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating report template {template_id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update report template"
        )

@router.delete("/{template_id}", response_model=MessageResponse)
async def delete_report_template(
    template_id: int,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Delete a report template.
    Requires Manager role or above.
    """
    try:
        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == template_id
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
        
        # Don't allow deletion of default template if it's the only one
        if template.is_default:
            other_templates_count = db.query(ReportTemplate).filter(
                ReportTemplate.id != template_id
            ).count()
            
            if other_templates_count == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot delete the last remaining template"
                )
        
        template_name = template.name
        db.delete(template)
        db.commit()
        
        logger.info(f"Report template '{template_name}' deleted by user {current_user.username}")
        
        return MessageResponse(message=f"Report template '{template_name}' deleted successfully")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting report template {template_id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete report template"
        )

# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@router.post("/{template_id}/clone", response_model=ReportTemplateResponse, status_code=status.HTTP_201_CREATED)
async def clone_report_template(
    template_id: int,
    clone_data: ReportTemplateCloneRequest,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Clone an existing report template.
    Requires Manager role or above.
    """
    try:
        # Get original template
        original = db.query(ReportTemplate).filter(
            ReportTemplate.id == template_id
        ).first()
        
        if not original:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Original template not found"
            )
        
        # Check if new name already exists
        existing = db.query(ReportTemplate).filter(
            ReportTemplate.name == clone_data.name
        ).first()
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A template with this name already exists"
            )
        
        # Create cloned template
        cloned_template = ReportTemplate(
            name=clone_data.name,
            description=clone_data.description or f"Cloned from {original.name}",
            author=clone_data.author,
            content=original.content,
            version="1.0",  # Reset version for clone
            tags=original.tags,
            incident_types=original.incident_types,
            is_default=False,  # Clones are never default
            requires_approval=original.requires_approval,
            created_by_id=current_user.id,
            status=ReportTemplateStatus.DRAFT
        )
        
        db.add(cloned_template)
        db.commit()
        db.refresh(cloned_template)
        
        logger.info(f"Report template '{original.name}' cloned as '{cloned_template.name}' by user {current_user.username}")
        
        return format_template_response(cloned_template)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cloning report template {template_id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clone report template"
        )

@router.post("/{template_id}/set-default", response_model=MessageResponse)
async def set_default_template(
    template_id: int,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Set a template as the default template.
    Requires Manager role or above.
    """
    try:
        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == template_id
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
        
        if template.status != ReportTemplateStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only active templates can be set as default"
            )
        
        # Unset all other defaults
        db.query(ReportTemplate).filter(
            ReportTemplate.is_default == True
        ).update({"is_default": False})
        
        # Set this one as default
        template.is_default = True
        template.updated_by_id = current_user.id
        template.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"Report template '{template.name}' set as default by user {current_user.username}")
        
        return MessageResponse(message=f"Template '{template.name}' set as default")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error setting default template {template_id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to set default template"
        )

@router.post("/{template_id}/activate", response_model=MessageResponse)
async def activate_template(
    template_id: int,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Activate a template (change status from draft to active).
    Requires Manager role or above.
    """
    try:
        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == template_id
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
        
        if template.status == ReportTemplateStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Template is already active"
            )
        
        template.status = ReportTemplateStatus.ACTIVE
        template.updated_by_id = current_user.id
        template.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"Report template '{template.name}' activated by user {current_user.username}")
        
        return MessageResponse(message=f"Template '{template.name}' activated successfully")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error activating template {template_id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to activate template"
        )

@router.post("/{template_id}/archive", response_model=MessageResponse)
async def archive_template(
    template_id: int,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Archive a template (change status to archived).
    Requires Manager role or above.
    """
    try:
        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == template_id
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
        
        if template.status == ReportTemplateStatus.ARCHIVED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Template is already archived"
            )
        
        # If this is the default template, ensure there's another active template
        if template.is_default:
            other_active = db.query(ReportTemplate).filter(
                and_(
                    ReportTemplate.id != template_id,
                    ReportTemplate.status == ReportTemplateStatus.ACTIVE
                )
            ).first()
            
            if not other_active:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot archive the default template when no other active templates exist"
                )
            
            # Unset default status
            template.is_default = False
        
        template.status = ReportTemplateStatus.ARCHIVED
        template.updated_by_id = current_user.id
        template.updated_at = datetime.utcnow()
        
        db.commit()
        
        logger.info(f"Report template '{template.name}' archived by user {current_user.username}")
        
        return MessageResponse(message=f"Template '{template.name}' archived successfully")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error archiving template {template_id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to archive template"
        )

@router.get("/stats", response_model=ReportTemplateStatsResponse)
async def get_template_statistics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get report template statistics and usage data.
    """
    try:
        # Get basic counts
        total_templates = db.query(ReportTemplate).count()
        active_templates = db.query(ReportTemplate).filter(
            ReportTemplate.status == ReportTemplateStatus.ACTIVE
        ).count()
        draft_templates = db.query(ReportTemplate).filter(
            ReportTemplate.status == ReportTemplateStatus.DRAFT
        ).count()
        archived_templates = db.query(ReportTemplate).filter(
            ReportTemplate.status == ReportTemplateStatus.ARCHIVED
        ).count()
        
        # Get most used template
        most_used = db.query(ReportTemplate).filter(
            ReportTemplate.usage_count > 0
        ).order_by(desc(ReportTemplate.usage_count)).first()
        
        most_used_template = None
        if most_used:
            most_used_template = {
                "id": most_used.id,
                "name": most_used.name,
                "author": most_used.author,
                "usage_count": most_used.usage_count
            }
        
        # Get recently created templates (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_templates = db.query(ReportTemplate).filter(
            ReportTemplate.created_at >= thirty_days_ago
        ).order_by(desc(ReportTemplate.created_at)).limit(5).all()
        
        recently_created = [
            {
                "id": template.id,
                "name": template.name,
                "author": template.author,
                "created_at": template.created_at.isoformat(),
                "status": template.status
            }
            for template in recent_templates
        ]
        
        # Get author statistics
        author_stats = db.query(
            ReportTemplate.author,
            func.count(ReportTemplate.id).label('template_count'),
            func.sum(ReportTemplate.usage_count).label('total_usage')
        ).group_by(ReportTemplate.author).order_by(
            desc(func.count(ReportTemplate.id))
        ).limit(10).all()
        
        authors = [
            {
                "author": stat.author,
                "template_count": stat.template_count,
                "total_usage": stat.total_usage or 0
            }
            for stat in author_stats
        ]
        
        return ReportTemplateStatsResponse(
            total_templates=total_templates,
            active_templates=active_templates,
            draft_templates=draft_templates,
            archived_templates=archived_templates,
            most_used_template=most_used_template,
            recently_created=recently_created,
            authors=authors
        )
        
    except Exception as e:
        logger.error(f"Error getting template statistics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve template statistics"
        )

@router.post("/bulk-operations", response_model=MessageResponse)
async def bulk_template_operations(
    operation_data: BulkReportTemplateOperation,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Perform bulk operations on multiple report templates.
    Requires Manager role or above.
    """
    try:
        # Get templates
        templates = db.query(ReportTemplate).filter(
            ReportTemplate.id.in_(operation_data.template_ids)
        ).all()
        
        if len(templates) != len(operation_data.template_ids):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or more templates not found"
            )
        
        operation = operation_data.operation
        updated_count = 0
        
        for template in templates:
            if operation == "activate":
                if template.status != ReportTemplateStatus.ACTIVE:
                    template.status = ReportTemplateStatus.ACTIVE
                    template.updated_by_id = current_user.id
                    template.updated_at = datetime.utcnow()
                    updated_count += 1
            
            elif operation == "archive":
                if template.status != ReportTemplateStatus.ARCHIVED:
                    # Don't archive if it's the only default template
                    if template.is_default:
                        other_active = db.query(ReportTemplate).filter(
                            and_(
                                ReportTemplate.id != template.id,
                                ReportTemplate.status == ReportTemplateStatus.ACTIVE
                            )
                        ).first()
                        if not other_active:
                            logger.warning(f"Skipping archive of default template {template.name} - no other active templates")
                            continue
                        template.is_default = False
                    
                    template.status = ReportTemplateStatus.ARCHIVED
                    template.updated_by_id = current_user.id
                    template.updated_at = datetime.utcnow()
                    updated_count += 1
            
            elif operation == "delete":
                # Don't delete if it's the only template
                total_templates = db.query(ReportTemplate).count()
                if total_templates <= len(operation_data.template_ids):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Cannot delete all templates"
                    )
                db.delete(template)
                updated_count += 1
        
        db.commit()
        
        logger.info(f"Bulk operation '{operation}' performed on {updated_count} templates by user {current_user.username}")
        
        return MessageResponse(
            message=f"Bulk {operation} operation completed successfully on {updated_count} templates"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing bulk operation: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to perform bulk operation"
        )

@router.post("/{template_id}/use", response_model=MessageResponse)
async def mark_template_used(
    template_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Mark a template as used (increment usage counter).
    This endpoint would be called when generating a report with this template.
    """
    try:
        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == template_id
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
        
        template.increment_usage()
        db.commit()
        
        logger.info(f"Template '{template.name}' marked as used by user {current_user.username}")
        
        return MessageResponse(message="Template usage recorded")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error marking template as used {template_id}: {str(e)}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record template usage"
        )