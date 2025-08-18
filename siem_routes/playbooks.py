from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session, noload
from sqlalchemy import and_, or_, desc, func
from typing import List, Optional
from datetime import datetime, timedelta
import uuid

from database import get_db
from auth_utils import get_current_user, require_admin, require_manager_or_above
from models.users import User
from models.playbook import (
    IRPlaybook, PlaybookExecution, StepExecutionLog, 
    PlaybookUserInput, PlaybookTemplate, PlaybookStatus, StepType, InputFieldType
)
from schemas import (
    PlaybookCreate, PlaybookUpdate, PlaybookResponse, PlaybookSearchRequest,
    PlaybookExecutionCreate, PlaybookExecutionUpdate, PlaybookExecutionResponse, PlaybookExecutionSearchRequest,
    StepExecutionLogCreate, StepExecutionLogResponse,
    PlaybookUserInputCreate, PlaybookUserInputResponse,
    PlaybookTemplateCreate, PlaybookTemplateUpdate, PlaybookTemplateResponse,
    PaginatedResponse, MessageResponse
)

router = APIRouter(prefix="/playbooks", tags=["Playbooks"])

# ============================================================================
# PLAYBOOK CRUD OPERATIONS
# ============================================================================

@router.post("/", response_model=PlaybookResponse)
async def create_playbook(
    playbook_data: PlaybookCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new playbook"""
    
    # Check if playbook name already exists
    existing_playbook = db.query(IRPlaybook).filter(IRPlaybook.name == playbook_data.name).first()
    if existing_playbook:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A playbook with this name already exists"
        )
    
    # Create new playbook - use model_dump() for Pydantic v2
    playbook = IRPlaybook(
        **playbook_data.model_dump(),
        created_by_id=current_user.id
    )
    
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    
    # Set created_by to None to avoid serialization issues
    playbook.created_by = None
    
    return PlaybookResponse.model_validate(playbook)

@router.get("/", response_model=PaginatedResponse)
async def list_playbooks(
    search: Optional[str] = Query(None, description="Search in name and description"),
    status: Optional[PlaybookStatus] = Query(None, description="Filter by status"),
    tags: Optional[str] = Query(None, description="Comma-separated tags to filter by"),
    severity_levels: Optional[str] = Query(None, description="Comma-separated severity levels"),
    alert_sources: Optional[str] = Query(None, description="Comma-separated alert sources"),
    created_by_id: Optional[int] = Query(None, description="Filter by creator"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List playbooks with filtering and pagination"""
    
    # Use noload to avoid loading the created_by relationship
    query = db.query(IRPlaybook).options(noload(IRPlaybook.created_by))
    
    # Apply filters
    if search:
        search_filter = or_(
            IRPlaybook.name.ilike(f"%{search}%"),
            IRPlaybook.description.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)
    
    if status:
        query = query.filter(IRPlaybook.status == status)
    
    if tags:
        tag_list = [tag.strip() for tag in tags.split(",")]
        for tag in tag_list:
            query = query.filter(IRPlaybook.tags.contains([tag]))
    
    if severity_levels:
        severity_list = [level.strip() for level in severity_levels.split(",")]
        for level in severity_list:
            query = query.filter(IRPlaybook.severity_levels.contains([level]))
    
    if alert_sources:
        source_list = [source.strip() for source in alert_sources.split(",")]
        for source in source_list:
            query = query.filter(IRPlaybook.alert_sources.contains([source]))
    
    if created_by_id:
        query = query.filter(IRPlaybook.created_by_id == created_by_id)
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    playbooks = query.order_by(desc(IRPlaybook.updated_at)).offset((page - 1) * size).limit(size).all()
    
    # Convert SQLAlchemy objects to Pydantic models - relationships are already not loaded
    playbook_responses = [PlaybookResponse.model_validate(playbook) for playbook in playbooks]
    
    return PaginatedResponse(
        items=playbook_responses,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )

@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(
    playbook_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a specific playbook by ID"""
    
    playbook = db.query(IRPlaybook).options(noload(IRPlaybook.created_by)).filter(IRPlaybook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    return PlaybookResponse.model_validate(playbook)

@router.put("/{playbook_id}", response_model=PlaybookResponse)
async def update_playbook(
    playbook_id: int,
    playbook_data: PlaybookUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update a playbook"""
    
    playbook = db.query(IRPlaybook).filter(IRPlaybook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    # Check if name is being changed and if it conflicts
    if playbook_data.name and playbook_data.name != playbook.name:
        existing_playbook = db.query(IRPlaybook).filter(
            and_(
                IRPlaybook.name == playbook_data.name,
                IRPlaybook.id != playbook_id
            )
        ).first()
        if existing_playbook:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A playbook with this name already exists"
            )
    
    # Update fields - use model_dump() for Pydantic v2
    update_data = playbook_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(playbook, field, value)
    
    playbook.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(playbook)
    
    # Set created_by to None to avoid serialization issues
    playbook.created_by = None
    
    return PlaybookResponse.model_validate(playbook)

@router.delete("/{playbook_id}", response_model=MessageResponse)
async def delete_playbook(
    playbook_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete a playbook (admin only)"""
    
    playbook = db.query(IRPlaybook).filter(IRPlaybook.id == playbook_id).first()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    # Check if playbook has any executions
    execution_count = db.query(PlaybookExecution).filter(
        PlaybookExecution.playbook_id == playbook_id
    ).count()
    
    if execution_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete playbook with {execution_count} existing executions"
        )
    
    db.delete(playbook)
    db.commit()
    
    return MessageResponse(message="Playbook deleted successfully")

# ============================================================================
# PLAYBOOK EXECUTION OPERATIONS
# ============================================================================

@router.post("/executions", response_model=PlaybookExecutionResponse)
async def create_execution(
    execution_data: PlaybookExecutionCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start a new playbook execution"""
    
    # Verify playbook exists
    playbook = db.query(IRPlaybook).filter(IRPlaybook.id == execution_data.playbook_id).first()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    # Check if playbook is active
    if playbook.status != PlaybookStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot execute inactive playbook"
        )
    
    # Generate execution ID
    execution_id = f"EXEC-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    
    # Calculate total steps from playbook definition
    total_steps = 0
    if playbook.playbook_definition and "phases" in playbook.playbook_definition:
        for phase in playbook.playbook_definition["phases"]:
            if "steps" in phase:
                total_steps += len(phase["steps"])
    
    # Create execution
    execution = PlaybookExecution(
        execution_id=execution_id,
        playbook_id=execution_data.playbook_id,
        incident_id=execution_data.incident_id,
        assigned_analyst_id=execution_data.assigned_analyst_id or current_user.id,
        total_steps=total_steps,
        execution_context={
            "phases": {},
            "user_inputs": {},
            "artifacts_collected": []
        }
    )
    
    db.add(execution)
    db.commit()
    db.refresh(execution)
    
    # Update playbook usage stats
    playbook.usage_count += 1
    playbook.last_used = datetime.utcnow()
    db.commit()
    
    return PlaybookExecutionResponse.from_orm(execution)

@router.get("/executions", response_model=PaginatedResponse)
async def list_executions(
    playbook_id: Optional[int] = Query(None, description="Filter by playbook ID"),
    execution_status: Optional[str] = Query(None, description="Filter by execution status"),
    assigned_analyst_id: Optional[int] = Query(None, description="Filter by assigned analyst"),
    incident_id: Optional[str] = Query(None, description="Filter by incident ID"),
    started_after: Optional[datetime] = Query(None, description="Filter executions started after this date"),
    started_before: Optional[datetime] = Query(None, description="Filter executions started before this date"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List playbook executions with filtering and pagination"""
    
    query = db.query(PlaybookExecution)
    
    # Apply filters
    if playbook_id:
        query = query.filter(PlaybookExecution.playbook_id == playbook_id)
    
    if execution_status:
        query = query.filter(PlaybookExecution.status == execution_status)
    
    if assigned_analyst_id:
        query = query.filter(PlaybookExecution.assigned_analyst_id == assigned_analyst_id)
    
    if incident_id:
        query = query.filter(PlaybookExecution.incident_id == incident_id)
    
    if started_after:
        query = query.filter(PlaybookExecution.started_at >= started_after)
    
    if started_before:
        query = query.filter(PlaybookExecution.started_at <= started_before)
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    executions = query.order_by(desc(PlaybookExecution.started_at)).offset((page - 1) * size).limit(size).all()
    
    # Convert SQLAlchemy objects to Pydantic models
    execution_responses = [PlaybookExecutionResponse.from_orm(execution) for execution in executions]
    
    return PaginatedResponse(
        items=execution_responses,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )

@router.get("/executions/{execution_id}", response_model=PlaybookExecutionResponse)
async def get_execution(
    execution_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a specific execution by ID"""
    
    execution = db.query(PlaybookExecution).filter(PlaybookExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found"
        )
    
    return PlaybookExecutionResponse.from_orm(execution)

@router.put("/executions/{execution_id}", response_model=PlaybookExecutionResponse)
async def update_execution(
    execution_id: int,
    execution_data: PlaybookExecutionUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update an execution"""
    
    execution = db.query(PlaybookExecution).filter(PlaybookExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found"
        )
    
    # Update fields
    update_data = execution_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(execution, field, value)
    
    # Set completion time if status is completed
    if execution_data.status == "completed" and not execution.completed_at:
        execution.completed_at = datetime.utcnow()
    
    db.commit()
    db.refresh(execution)
    
    return PlaybookExecutionResponse.from_orm(execution)

# ============================================================================
# STEP EXECUTION LOGS
# ============================================================================

@router.post("/executions/{execution_id}/steps", response_model=StepExecutionLogResponse)
async def create_step_log(
    execution_id: int,
    step_data: StepExecutionLogCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a step execution log"""
    
    # Verify execution exists
    execution = db.query(PlaybookExecution).filter(PlaybookExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found"
        )
    
    # Create step log
    step_log = StepExecutionLog(
        execution_id=execution_id,
        executed_by_id=current_user.id,
        **step_data.dict()
    )
    
    db.add(step_log)
    db.commit()
    db.refresh(step_log)
    
    return StepExecutionLogResponse.from_orm(step_log)

@router.get("/executions/{execution_id}/steps", response_model=List[StepExecutionLogResponse])
async def list_step_logs(
    execution_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List step execution logs for an execution"""
    
    # Verify execution exists
    execution = db.query(PlaybookExecution).filter(PlaybookExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found"
        )
    
    step_logs = db.query(StepExecutionLog).filter(
        StepExecutionLog.execution_id == execution_id
    ).order_by(StepExecutionLog.step_index).all()
    
    # Convert SQLAlchemy objects to Pydantic models
    return [StepExecutionLogResponse.from_orm(step_log) for step_log in step_logs]

# ============================================================================
# USER INPUTS
# ============================================================================

@router.post("/executions/{execution_id}/inputs", response_model=PlaybookUserInputResponse)
async def create_user_input(
    execution_id: int,
    input_data: PlaybookUserInputCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a user input for an execution"""
    
    # Verify execution exists
    execution = db.query(PlaybookExecution).filter(PlaybookExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found"
        )
    
    # Create user input
    user_input = PlaybookUserInput(
        execution_id=execution_id,
        collected_by_id=current_user.id,
        **input_data.dict()
    )
    
    db.add(user_input)
    db.commit()
    db.refresh(user_input)
    
    return PlaybookUserInputResponse.from_orm(user_input)

@router.get("/executions/{execution_id}/inputs", response_model=List[PlaybookUserInputResponse])
async def list_user_inputs(
    execution_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List user inputs for an execution"""
    
    # Verify execution exists
    execution = db.query(PlaybookExecution).filter(PlaybookExecution.id == execution_id).first()
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Execution not found"
        )
    
    user_inputs = db.query(PlaybookUserInput).filter(
        PlaybookUserInput.execution_id == execution_id
    ).order_by(PlaybookUserInput.collected_at).all()
    
    # Convert SQLAlchemy objects to Pydantic models
    return [PlaybookUserInputResponse.from_orm(user_input) for user_input in user_inputs]

# ============================================================================
# PLAYBOOK TEMPLATES
# ============================================================================

@router.post("/templates", response_model=PlaybookTemplateResponse)
async def create_template(
    template_data: PlaybookTemplateCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new playbook template"""
    
    # Check if template name already exists
    existing_template = db.query(PlaybookTemplate).filter(PlaybookTemplate.name == template_data.name).first()
    if existing_template:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A template with this name already exists"
        )
    
    # Create new template
    template = PlaybookTemplate(
        **template_data.dict(),
        created_by_id=current_user.id
    )
    
    db.add(template)
    db.commit()
    db.refresh(template)
    
    return PlaybookTemplateResponse.from_orm(template)

@router.get("/templates", response_model=PaginatedResponse)
async def list_templates(
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search in name and description"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List playbook templates with filtering and pagination"""
    
    query = db.query(PlaybookTemplate)
    
    # Apply filters
    if category:
        query = query.filter(PlaybookTemplate.category == category)
    
    if search:
        search_filter = or_(
            PlaybookTemplate.name.ilike(f"%{search}%"),
            PlaybookTemplate.description.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)
    
    # Get total count
    total = query.count()
    
    # Apply pagination and ordering
    templates = query.order_by(desc(PlaybookTemplate.usage_count)).offset((page - 1) * size).limit(size).all()
    
    # Convert SQLAlchemy objects to Pydantic models
    template_responses = [PlaybookTemplateResponse.from_orm(template) for template in templates]
    
    return PaginatedResponse(
        items=template_responses,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )

@router.get("/templates/{template_id}", response_model=PlaybookTemplateResponse)
async def get_template(
    template_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get a specific template by ID"""
    
    template = db.query(PlaybookTemplate).filter(PlaybookTemplate.id == template_id).first()
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    # Increment usage count
    template.usage_count += 1
    db.commit()
    
    return PlaybookTemplateResponse.from_orm(template)

@router.put("/templates/{template_id}", response_model=PlaybookTemplateResponse)
async def update_template(
    template_id: int,
    template_data: PlaybookTemplateUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update a template"""
    
    template = db.query(PlaybookTemplate).filter(PlaybookTemplate.id == template_id).first()
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    # Check if name is being changed and if it conflicts
    if template_data.name and template_data.name != template.name:
        existing_template = db.query(PlaybookTemplate).filter(
            and_(
                PlaybookTemplate.name == template_data.name,
                PlaybookTemplate.id != template_id
            )
        ).first()
        if existing_template:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A template with this name already exists"
            )
    
    # Update fields
    update_data = template_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(template, field, value)
    
    db.commit()
    db.refresh(template)
    
    return PlaybookTemplateResponse.from_orm(template)

@router.delete("/templates/{template_id}", response_model=MessageResponse)
async def delete_template(
    template_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Delete a template (admin only)"""
    
    template = db.query(PlaybookTemplate).filter(PlaybookTemplate.id == template_id).first()
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    db.delete(template)
    db.commit()
    
    return MessageResponse(message="Template deleted successfully")

# ============================================================================
# UTILITY ENDPOINTS
# ============================================================================

@router.get("/statuses", response_model=List[str])
async def get_playbook_statuses():
    """Get available playbook statuses"""
    return [status.value for status in PlaybookStatus]

@router.get("/step-types", response_model=List[str])
async def get_step_types():
    """Get available step types"""
    return [step_type.value for step_type in StepType]

@router.get("/input-field-types", response_model=List[str])
async def get_input_field_types():
    """Get available input field types"""
    return [field_type.value for field_type in InputFieldType]

@router.get("/categories", response_model=List[str])
async def get_template_categories(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get available template categories"""
    categories = db.query(PlaybookTemplate.category).distinct().all()
    return [category[0] for category in categories if category[0]]

@router.post("/templates/{template_id}/create-playbook", response_model=PlaybookResponse)
async def create_playbook_from_template(
    template_id: int,
    playbook_name: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create a new playbook from a template"""
    
    # Get template
    template = db.query(PlaybookTemplate).filter(PlaybookTemplate.id == template_id).first()
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    # Check if playbook name already exists
    existing_playbook = db.query(IRPlaybook).filter(IRPlaybook.name == playbook_name).first()
    if existing_playbook:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A playbook with this name already exists"
        )
    
    # Create playbook from template
    playbook = IRPlaybook(
        name=playbook_name,
        description=template.description,
        tags=template.default_tags,
        playbook_definition=template.template_definition,
        created_by_id=current_user.id
    )
    
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    
    return PlaybookResponse.from_orm(playbook)
