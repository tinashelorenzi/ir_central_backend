"""
Incident Flow API Routes
Handles execution of incident response procedures
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json

from database import get_db
from models.users import User
from models.incident_flow import (
    IncidentFlow, IncidentFlowStep, IncidentFlowUserInput, IncidentFlowArtifact,
    IncidentFlowStatus, StepStatus, StepType
)
from models.playbook import IRPlaybook, PlaybookExecution
from auth_utils import get_current_user, require_manager_or_above
from schemas import PaginatedResponse, MessageResponse

# Pydantic schemas for request/response
from pydantic import BaseModel, Field
from typing import Union

# ============================================================================
# PYDANTIC SCHEMAS
# ============================================================================

class IncidentFlowCreate(BaseModel):
    incident_id: str
    playbook_id: int
    alert_id: Optional[int] = None
    assigned_analyst_id: Optional[int] = None
    lead_analyst_id: Optional[int] = None
    team_members: List[int] = []
    tags: List[str] = []
    custom_fields: Dict[str, Any] = {}

class IncidentFlowUpdate(BaseModel):
    status: Optional[IncidentFlowStatus] = None
    current_phase: Optional[str] = None
    current_step_name: Optional[str] = None
    assigned_analyst_id: Optional[int] = None
    lead_analyst_id: Optional[int] = None
    team_members: Optional[List[int]] = None
    tags: Optional[List[str]] = None
    custom_fields: Optional[Dict[str, Any]] = None
    executive_summary: Optional[str] = None
    technical_summary: Optional[str] = None
    business_impact: Optional[str] = None
    lessons_learned: Optional[str] = None

class IncidentFlowStepUpdate(BaseModel):
    status: Optional[StepStatus] = None
    output_data: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    success: Optional[bool] = None
    error_message: Optional[str] = None
    evidence_collected: Optional[List[Dict[str, Any]]] = None

class UserInputCreate(BaseModel):
    field_name: str
    field_type: str
    label: str
    raw_value: Optional[str] = None
    parsed_value: Optional[Dict[str, Any]] = None
    is_required: bool = False
    is_sensitive: bool = False
    validation_rules: Optional[Dict[str, Any]] = None

class ArtifactCreate(BaseModel):
    artifact_type: str
    name: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    mime_type: Optional[str] = None
    collected_from: Optional[str] = None
    collection_method: Optional[str] = None
    is_critical: bool = False
    is_sensitive: bool = False
    tags: List[str] = []

class IncidentFlowResponse(BaseModel):
    id: int
    flow_id: str
    incident_id: str
    playbook_id: int
    alert_id: Optional[int]
    status: IncidentFlowStatus
    current_phase: Optional[str]
    current_step_name: Optional[str]
    progress_percentage: float
    total_steps: int
    completed_steps: int
    failed_steps: int
    skipped_steps: int
    started_at: datetime
    last_activity_at: datetime
    completed_at: Optional[datetime]
    estimated_completion: Optional[datetime]
    assigned_analyst_id: int
    lead_analyst_id: Optional[int]
    team_members: List[int]
    tags: List[str]
    
    # Include related data
    assigned_analyst: Optional[Dict[str, Any]] = None
    lead_analyst: Optional[Dict[str, Any]] = None
    playbook: Optional[Dict[str, Any]] = None
    current_step: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class IncidentFlowStepResponse(BaseModel):
    id: int
    phase_name: str
    step_name: str
    step_index: int
    global_step_index: int
    step_type: StepType
    title: str
    description: Optional[str]
    instructions: Optional[str]
    status: StepStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    success: Optional[bool]
    output_data: Dict[str, Any]
    notes: Optional[str]
    error_message: Optional[str]
    assigned_to_id: Optional[int]
    executed_by_id: Optional[int]
    requires_approval: bool
    approved_by_id: Optional[int]
    approved_at: Optional[datetime]
    evidence_collected: List[Dict[str, Any]]
    
    class Config:
        from_attributes = True

# ============================================================================
# ROUTER SETUP
# ============================================================================

router = APIRouter(prefix="/api/v1/incident-flows", tags=["incident-flows"])

# ============================================================================
# INCIDENT FLOW MANAGEMENT
# ============================================================================

@router.post("/", response_model=IncidentFlowResponse)
async def create_incident_flow(
    flow_data: IncidentFlowCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Create a new incident flow from a playbook.
    This initializes the IR procedure for an incident.
    """
    
    # Verify playbook exists and is active
    playbook = db.query(IRPlaybook).filter(IRPlaybook.id == flow_data.playbook_id).first()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Playbook not found"
        )
    
    if playbook.status != "active":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot create flow from inactive playbook"
        )
    
    # Check if flow already exists for this incident
    existing_flow = db.query(IncidentFlow).filter(
        IncidentFlow.incident_id == flow_data.incident_id
    ).first()
    
    if existing_flow:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Incident flow already exists for incident {flow_data.incident_id}"
        )
    
    # Calculate total phases and steps from playbook definition
    total_phases = 0
    total_steps = 0
    if playbook.playbook_definition and "phases" in playbook.playbook_definition:
        phases = playbook.playbook_definition["phases"]
        total_phases = len(phases)
        for phase in phases:
            if "steps" in phase:
                total_steps += len(phase["steps"])
    
    # Create incident flow
    flow = IncidentFlow(
        incident_id=flow_data.incident_id,
        playbook_id=flow_data.playbook_id,
        alert_id=flow_data.alert_id,
        assigned_analyst_id=flow_data.assigned_analyst_id or current_user.id,
        lead_analyst_id=flow_data.lead_analyst_id,
        team_members=flow_data.team_members,
        total_phases=total_phases,
        total_steps=total_steps,
        playbook_snapshot=playbook.playbook_definition,  # Store snapshot
        tags=flow_data.tags,
        custom_fields=flow_data.custom_fields,
        created_by_id=current_user.id
    )
    
    db.add(flow)
    db.commit()
    db.refresh(flow)
    
    # Initialize steps from playbook definition
    background_tasks.add_task(initialize_flow_steps, flow.id, db)
    
    # Update playbook usage stats
    playbook.usage_count += 1
    playbook.last_used = datetime.utcnow()
    db.commit()
    
    return await get_incident_flow_response(flow, db)

@router.get("/", response_model=PaginatedResponse)
async def list_incident_flows(
    incident_id: Optional[str] = Query(None, description="Filter by incident ID"),
    status: Optional[IncidentFlowStatus] = Query(None, description="Filter by status"),
    assigned_analyst_id: Optional[int] = Query(None, description="Filter by assigned analyst"),
    playbook_id: Optional[int] = Query(None, description="Filter by playbook"),
    search: Optional[str] = Query(None, description="Search in flow IDs and incident IDs"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List incident flows with filtering and pagination"""
    
    query = db.query(IncidentFlow).options(
        joinedload(IncidentFlow.assigned_analyst),
        joinedload(IncidentFlow.lead_analyst),
        joinedload(IncidentFlow.playbook)
    )
    
    # Apply filters
    if incident_id:
        query = query.filter(IncidentFlow.incident_id == incident_id)
    
    if status:
        query = query.filter(IncidentFlow.status == status)
    
    if assigned_analyst_id:
        query = query.filter(IncidentFlow.assigned_analyst_id == assigned_analyst_id)
    
    if playbook_id:
        query = query.filter(IncidentFlow.playbook_id == playbook_id)
    
    if search:
        search_filter = or_(
            IncidentFlow.flow_id.ilike(f"%{search}%"),
            IncidentFlow.incident_id.ilike(f"%{search}%")
        )
        query = query.filter(search_filter)
    
    # Apply pagination
    total = query.count()
    flows = query.order_by(desc(IncidentFlow.created_at)).offset((page - 1) * size).limit(size).all()
    
    # Convert to response format
    flow_responses = []
    for flow in flows:
        flow_response = await get_incident_flow_response(flow, db)
        flow_responses.append(flow_response)
    
    return PaginatedResponse(
        items=flow_responses,
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size
    )

@router.get("/{flow_id}", response_model=IncidentFlowResponse)
async def get_incident_flow(
    flow_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get incident flow by ID"""
    
    flow = db.query(IncidentFlow).options(
        joinedload(IncidentFlow.assigned_analyst),
        joinedload(IncidentFlow.lead_analyst),
        joinedload(IncidentFlow.playbook),
        joinedload(IncidentFlow.steps)
    ).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    return await get_incident_flow_response(flow, db)

@router.put("/{flow_id}", response_model=IncidentFlowResponse)
async def update_incident_flow(
    flow_id: str,
    flow_update: IncidentFlowUpdate,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Update incident flow"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    # Update fields
    update_data = flow_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(flow, field, value)
    
    flow.updated_at = datetime.utcnow()
    flow.last_activity_at = datetime.utcnow()
    
    # Update progress if status changed to completed
    if flow_update.status == IncidentFlowStatus.COMPLETED:
        flow.completed_at = datetime.utcnow()
        flow.progress_percentage = 100.0
        
        # Calculate actual duration
        if flow.started_at:
            total_duration = (datetime.utcnow() - flow.started_at).total_seconds() / 60
            flow.actual_duration = int(total_duration - flow.total_pause_duration)
    
    db.commit()
    db.refresh(flow)
    
    return await get_incident_flow_response(flow, db)

@router.delete("/{flow_id}")
async def delete_incident_flow(
    flow_id: str,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Delete incident flow (admin only)"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    # Only allow deletion if not completed or in critical status
    if flow.status in [IncidentFlowStatus.IN_PROGRESS, IncidentFlowStatus.WAITING_INPUT]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete active incident flow"
        )
    
    db.delete(flow)
    db.commit()
    
    return MessageResponse(message="Incident flow deleted successfully")

# ============================================================================
# FLOW EXECUTION CONTROL
# ============================================================================

@router.post("/{flow_id}/start")
async def start_incident_flow(
    flow_id: str,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Start executing an incident flow"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    if flow.status != IncidentFlowStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Flow is not in pending status"
        )
    
    # Start the flow
    flow.status = IncidentFlowStatus.IN_PROGRESS
    flow.started_at = datetime.utcnow()
    flow.last_activity_at = datetime.utcnow()
    
    # Set first step as current if available
    first_step = db.query(IncidentFlowStep).filter(
        IncidentFlowStep.flow_id == flow.id,
        IncidentFlowStep.global_step_index == 0
    ).first()
    
    if first_step:
        flow.current_step_name = first_step.step_name
        flow.current_phase = first_step.phase_name
        first_step.status = StepStatus.IN_PROGRESS
        first_step.started_at = datetime.utcnow()
    
    db.commit()
    
    return MessageResponse(message="Incident flow started successfully")

@router.post("/{flow_id}/pause")
async def pause_incident_flow(
    flow_id: str,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Pause an active incident flow"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    if flow.status != IncidentFlowStatus.IN_PROGRESS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Flow is not in progress"
        )
    
    flow.status = IncidentFlowStatus.PAUSED
    flow.paused_at = datetime.utcnow()
    flow.last_activity_at = datetime.utcnow()
    
    db.commit()
    
    return MessageResponse(message="Incident flow paused successfully")

@router.post("/{flow_id}/resume")
async def resume_incident_flow(
    flow_id: str,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Resume a paused incident flow"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    if flow.status != IncidentFlowStatus.PAUSED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Flow is not paused"
        )
    
    # Calculate pause duration
    if flow.paused_at:
        pause_duration = (datetime.utcnow() - flow.paused_at).total_seconds() / 60
        flow.total_pause_duration += int(pause_duration)
    
    flow.status = IncidentFlowStatus.IN_PROGRESS
    flow.resumed_at = datetime.utcnow()
    flow.last_activity_at = datetime.utcnow()
    flow.paused_at = None
    
    db.commit()
    
    return MessageResponse(message="Incident flow resumed successfully")

# ============================================================================
# STEP MANAGEMENT
# ============================================================================

@router.get("/{flow_id}/steps", response_model=List[IncidentFlowStepResponse])
async def get_flow_steps(
    flow_id: str,
    phase_name: Optional[str] = Query(None, description="Filter by phase"),
    status: Optional[StepStatus] = Query(None, description="Filter by status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all steps for an incident flow"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    query = db.query(IncidentFlowStep).filter(IncidentFlowStep.flow_id == flow.id)
    
    if phase_name:
        query = query.filter(IncidentFlowStep.phase_name == phase_name)
    
    if status:
        query = query.filter(IncidentFlowStep.status == status)
    
    steps = query.order_by(IncidentFlowStep.global_step_index).all()
    
    return [IncidentFlowStepResponse.from_orm(step) for step in steps]

@router.get("/{flow_id}/steps/{step_name}", response_model=IncidentFlowStepResponse)
async def get_flow_step(
    flow_id: str,
    step_name: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific step details"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    step = db.query(IncidentFlowStep).filter(
        IncidentFlowStep.flow_id == flow.id,
        IncidentFlowStep.step_name == step_name
    ).first()
    
    if not step:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Step not found"
        )
    
    return IncidentFlowStepResponse.from_orm(step)

@router.put("/{flow_id}/steps/{step_name}", response_model=IncidentFlowStepResponse)
async def update_flow_step(
    flow_id: str,
    step_name: str,
    step_update: IncidentFlowStepUpdate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Update step execution status and results"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    step = db.query(IncidentFlowStep).filter(
        IncidentFlowStep.flow_id == flow.id,
        IncidentFlowStep.step_name == step_name
    ).first()
    
    if not step:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Step not found"
        )
    
    # Update step fields
    update_data = step_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(step, field, value)
    
    step.last_updated_at = datetime.utcnow()
    step.executed_by_id = current_user.id
    
    # Handle status changes
    if step_update.status:
        if step_update.status == StepStatus.IN_PROGRESS and not step.started_at:
            step.started_at = datetime.utcnow()
        elif step_update.status in [StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED]:
            step.completed_at = datetime.utcnow()
            
            # Calculate actual duration
            if step.started_at:
                duration = (datetime.utcnow() - step.started_at).total_seconds() / 60
                step.actual_duration = int(duration)
    
    # Update flow progress
    background_tasks.add_task(update_flow_progress, flow.id, db)
    
    # Auto-advance to next step if current step is completed
    if step_update.status == StepStatus.COMPLETED and step_update.success:
        background_tasks.add_task(advance_to_next_step, flow.id, step.global_step_index, db)
    
    flow.last_activity_at = datetime.utcnow()
    
    db.commit()
    db.refresh(step)
    
    return IncidentFlowStepResponse.from_orm(step)

@router.post("/{flow_id}/steps/{step_name}/start")
async def start_step(
    flow_id: str,
    step_name: str,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Start executing a specific step"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    step = db.query(IncidentFlowStep).filter(
        IncidentFlowStep.flow_id == flow.id,
        IncidentFlowStep.step_name == step_name
    ).first()
    
    if not step:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Step not found"
        )
    
    if step.status != StepStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Step is not in pending status"
        )
    
    # Check dependencies
    if not step.can_execute:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Step dependencies not met"
        )
    
    step.status = StepStatus.IN_PROGRESS
    step.started_at = datetime.utcnow()
    step.assigned_to_id = current_user.id
    
    # Update flow current step
    flow.current_step_name = step.step_name
    flow.current_phase = step.phase_name
    flow.last_activity_at = datetime.utcnow()
    
    db.commit()
    
    return MessageResponse(message="Step started successfully")

@router.post("/{flow_id}/steps/{step_name}/complete")
async def complete_step(
    flow_id: str,
    step_name: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db),
    output_data: Dict[str, Any] = {},
    notes: Optional[str] = None
):
    """Mark a step as completed"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    step = db.query(IncidentFlowStep).filter(
        IncidentFlowStep.flow_id == flow.id,
        IncidentFlowStep.step_name == step_name
    ).first()
    
    if not step:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Step not found"
        )
    
    if step.status not in [StepStatus.IN_PROGRESS, StepStatus.WAITING_INPUT]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Step is not in progress or waiting for input"
        )
    
    # Complete the step
    step.status = StepStatus.COMPLETED
    step.completed_at = datetime.utcnow()
    step.success = True
    step.output_data = output_data
    step.notes = notes
    step.executed_by_id = current_user.id
    
    # Calculate duration
    if step.started_at:
        duration = (datetime.utcnow() - step.started_at).total_seconds() / 60
        step.actual_duration = int(duration)
    
    # Update flow progress
    background_tasks.add_task(update_flow_progress, flow.id, db)
    background_tasks.add_task(advance_to_next_step, flow.id, step.global_step_index, db)
    
    flow.last_activity_at = datetime.utcnow()
    
    db.commit()
    
    return MessageResponse(message="Step completed successfully")

# ============================================================================
# USER INPUT MANAGEMENT
# ============================================================================

@router.post("/{flow_id}/inputs", response_model=Dict[str, Any])
async def create_user_input(
    flow_id: str,
    input_data: UserInputCreate,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Collect user input for a step"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    # Create user input record
    user_input = IncidentFlowUserInput(
        flow_id=flow.id,
        field_name=input_data.field_name,
        field_type=input_data.field_type,
        label=input_data.label,
        raw_value=input_data.raw_value,
        parsed_value=input_data.parsed_value,
        is_required=input_data.is_required,
        is_sensitive=input_data.is_sensitive,
        validation_rules=input_data.validation_rules,
        collected_by_id=current_user.id
    )
    
    # Store in flow execution context
    if not flow.execution_variables:
        flow.execution_variables = {}
    
    flow.execution_variables[input_data.field_name] = input_data.parsed_value or input_data.raw_value
    flow.last_activity_at = datetime.utcnow()
    
    db.add(user_input)
    db.commit()
    db.refresh(user_input)
    
    return {
        "id": user_input.id,
        "field_name": user_input.field_name,
        "collected_at": user_input.collected_at,
        "message": "User input collected successfully"
    }

@router.get("/{flow_id}/inputs")
async def get_user_inputs(
    flow_id: str,
    step_name: Optional[str] = Query(None, description="Filter by step"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all user inputs for a flow"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    query = db.query(IncidentFlowUserInput).filter(IncidentFlowUserInput.flow_id == flow.id)
    
    if step_name:
        query = query.filter(IncidentFlowUserInput.step_name == step_name)
    
    inputs = query.order_by(IncidentFlowUserInput.collected_at).all()
    
    return [
        {
            "id": inp.id,
            "field_name": inp.field_name,
            "field_type": inp.field_type,
            "label": inp.label,
            "raw_value": inp.raw_value if not inp.is_sensitive else "[REDACTED]",
            "parsed_value": inp.parsed_value if not inp.is_sensitive else "[REDACTED]",
            "is_required": inp.is_required,
            "is_sensitive": inp.is_sensitive,
            "is_valid": inp.is_valid,
            "collected_at": inp.collected_at,
            "collected_by": {
                "id": inp.collected_by.id,
                "username": inp.collected_by.username
            } if inp.collected_by else None
        }
        for inp in inputs
    ]

# ============================================================================
# ARTIFACT MANAGEMENT
# ============================================================================

@router.post("/{flow_id}/artifacts", response_model=Dict[str, Any])
async def create_artifact(
    flow_id: str,
    artifact_data: ArtifactCreate,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """Add an artifact to the incident flow"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    # Create artifact record
    artifact = IncidentFlowArtifact(
        flow_id=flow.id,
        artifact_type=artifact_data.artifact_type,
        name=artifact_data.name,
        description=artifact_data.description,
        file_path=artifact_data.file_path,
        file_size=artifact_data.file_size,
        file_hash=artifact_data.file_hash,
        mime_type=artifact_data.mime_type,
        collected_from=artifact_data.collected_from,
        collection_method=artifact_data.collection_method,
        is_critical=artifact_data.is_critical,
        is_sensitive=artifact_data.is_sensitive,
        tags=artifact_data.tags,
        collected_by_id=current_user.id
    )
    
    # Add to flow's collected evidence
    if not flow.collected_evidence:
        flow.collected_evidence = []
    
    flow.collected_evidence.append({
        "name": artifact_data.name,
        "type": artifact_data.artifact_type,
        "collected_at": datetime.utcnow().isoformat(),
        "collected_by": current_user.username,
        "is_critical": artifact_data.is_critical
    })
    
    flow.last_activity_at = datetime.utcnow()
    
    db.add(artifact)
    db.commit()
    db.refresh(artifact)
    
    return {
        "id": artifact.id,
        "name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "collected_at": artifact.collected_at,
        "message": "Artifact added successfully"
    }

@router.get("/{flow_id}/artifacts")
async def get_artifacts(
    flow_id: str,
    artifact_type: Optional[str] = Query(None, description="Filter by type"),
    is_critical: Optional[bool] = Query(None, description="Filter by critical status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all artifacts for a flow"""
    
    flow = db.query(IncidentFlow).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    query = db.query(IncidentFlowArtifact).filter(IncidentFlowArtifact.flow_id == flow.id)
    
    if artifact_type:
        query = query.filter(IncidentFlowArtifact.artifact_type == artifact_type)
    
    if is_critical is not None:
        query = query.filter(IncidentFlowArtifact.is_critical == is_critical)
    
    artifacts = query.order_by(IncidentFlowArtifact.collected_at).all()
    
    return [
        {
            "id": artifact.id,
            "name": artifact.name,
            "artifact_type": artifact.artifact_type,
            "description": artifact.description,
            "file_path": artifact.file_path,
            "file_size": artifact.file_size,
            "file_hash": artifact.file_hash,
            "collected_from": artifact.collected_from,
            "collection_method": artifact.collection_method,
            "is_critical": artifact.is_critical,
            "is_sensitive": artifact.is_sensitive,
            "tags": artifact.tags,
            "collected_at": artifact.collected_at,
            "collected_by": {
                "id": artifact.collected_by.id,
                "username": artifact.collected_by.username
            } if artifact.collected_by else None
        }
        for artifact in artifacts
    ]

# ============================================================================
# REPORTING AND ANALYTICS
# ============================================================================

@router.get("/{flow_id}/report")
async def generate_flow_report(
    flow_id: str,
    format: str = Query("markdown", description="Report format: markdown, json"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate incident flow execution report"""
    
    flow = db.query(IncidentFlow).options(
        joinedload(IncidentFlow.steps),
        joinedload(IncidentFlow.user_inputs),
        joinedload(IncidentFlow.artifacts),
        joinedload(IncidentFlow.assigned_analyst),
        joinedload(IncidentFlow.playbook)
    ).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    if format == "json":
        return generate_json_report(flow)
    else:
        return generate_markdown_report(flow, current_user)

@router.get("/{flow_id}/metrics")
async def get_flow_metrics(
    flow_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get detailed metrics for an incident flow"""
    
    flow = db.query(IncidentFlow).options(
        joinedload(IncidentFlow.steps)
    ).filter(IncidentFlow.flow_id == flow_id).first()
    
    if not flow:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident flow not found"
        )
    
    # Calculate step metrics
    step_metrics = []
    total_expected_duration = 0
    total_actual_duration = 0
    
    for step in flow.steps:
        step_metric = {
            "step_name": step.step_name,
            "phase_name": step.phase_name,
            "status": step.status,
            "expected_duration": step.expected_duration,
            "actual_duration": step.actual_duration,
            "efficiency": None,
            "on_time": None
        }
        
        if step.expected_duration:
            total_expected_duration += step.expected_duration
            
            if step.actual_duration:
                efficiency = (step.expected_duration / step.actual_duration) * 100
                step_metric["efficiency"] = round(efficiency, 2)
                step_metric["on_time"] = step.actual_duration <= step.expected_duration
        
        if step.actual_duration:
            total_actual_duration += step.actual_duration
        
        step_metrics.append(step_metric)
    
    # Calculate overall metrics
    overall_efficiency = None
    if total_expected_duration > 0 and total_actual_duration > 0:
        overall_efficiency = (total_expected_duration / total_actual_duration) * 100
    
    return {
        "flow_id": flow.flow_id,
        "overall_metrics": {
            "progress_percentage": flow.progress_percentage,
            "completed_steps": flow.completed_steps,
            "failed_steps": flow.failed_steps,
            "skipped_steps": flow.skipped_steps,
            "total_steps": flow.total_steps,
            "total_expected_duration": total_expected_duration,
            "total_actual_duration": total_actual_duration,
            "overall_efficiency": round(overall_efficiency, 2) if overall_efficiency else None,
            "pause_duration": flow.total_pause_duration,
            "time_to_containment": flow.time_to_containment,
            "time_to_eradication": flow.time_to_eradication,
            "time_to_recovery": flow.time_to_recovery,
            "procedure_compliance_score": flow.procedure_compliance_score,
            "response_effectiveness_score": flow.response_effectiveness_score
        },
        "step_metrics": step_metrics,
        "phase_summary": get_phase_summary(flow.steps),
        "generated_at": datetime.utcnow().isoformat()
    }

# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================

@router.get("/dashboard/summary")
async def get_flow_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get dashboard summary of incident flows"""
    
    # Active flows
    active_flows = db.query(IncidentFlow).filter(
        IncidentFlow.status.in_([
            IncidentFlowStatus.IN_PROGRESS,
            IncidentFlowStatus.WAITING_INPUT,
            IncidentFlowStatus.PAUSED
        ])
    ).count()
    
    # Completed flows (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    completed_flows = db.query(IncidentFlow).filter(
        IncidentFlow.status == IncidentFlowStatus.COMPLETED,
        IncidentFlow.completed_at >= thirty_days_ago
    ).count()
    
    # Flows assigned to current user
    my_flows = db.query(IncidentFlow).filter(
        IncidentFlow.assigned_analyst_id == current_user.id,
        IncidentFlow.status.in_([
            IncidentFlowStatus.IN_PROGRESS,
            IncidentFlowStatus.WAITING_INPUT,
            IncidentFlowStatus.PAUSED
        ])
    ).count()
    
    # Flows waiting for input
    waiting_input = db.query(IncidentFlow).filter(
        IncidentFlow.status == IncidentFlowStatus.WAITING_INPUT
    ).count()
    
    # Recent activity
    recent_flows = db.query(IncidentFlow).options(
        joinedload(IncidentFlow.assigned_analyst),
        joinedload(IncidentFlow.playbook)
    ).filter(
        IncidentFlow.last_activity_at >= datetime.utcnow() - timedelta(hours=24)
    ).order_by(desc(IncidentFlow.last_activity_at)).limit(10).all()
    
    recent_activity = []
    for flow in recent_flows:
        recent_activity.append({
            "flow_id": flow.flow_id,
            "incident_id": flow.incident_id,
            "status": flow.status,
            "current_phase": flow.current_phase,
            "progress_percentage": flow.progress_percentage,
            "last_activity_at": flow.last_activity_at,
            "assigned_analyst": {
                "username": flow.assigned_analyst.username,
                "full_name": flow.assigned_analyst.full_name
            } if flow.assigned_analyst else None,
            "playbook_name": flow.playbook.name if flow.playbook else None
        })
    
    return {
        "summary": {
            "active_flows": active_flows,
            "completed_flows_30d": completed_flows,
            "my_active_flows": my_flows,
            "waiting_input": waiting_input
        },
        "recent_activity": recent_activity,
        "generated_at": datetime.utcnow().isoformat()
    }

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

async def get_incident_flow_response(flow: IncidentFlow, db: Session) -> IncidentFlowResponse:
    """Convert IncidentFlow to response format with related data"""
    
    # Get current step details
    current_step_data = None
    if flow.current_step_name:
        current_step = db.query(IncidentFlowStep).filter(
            IncidentFlowStep.flow_id == flow.id,
            IncidentFlowStep.step_name == flow.current_step_name
        ).first()
        
        if current_step:
            current_step_data = {
                "step_name": current_step.step_name,
                "title": current_step.title,
                "status": current_step.status,
                "step_type": current_step.step_type,
                "requires_approval": current_step.requires_approval
            }
    
    # Build response
    response_data = {
        "id": flow.id,
        "flow_id": flow.flow_id,
        "incident_id": flow.incident_id,
        "playbook_id": flow.playbook_id,
        "alert_id": flow.alert_id,
        "status": flow.status,
        "current_phase": flow.current_phase,
        "current_step_name": flow.current_step_name,
        "progress_percentage": flow.progress_percentage,
        "total_steps": flow.total_steps,
        "completed_steps": flow.completed_steps,
        "failed_steps": flow.failed_steps,
        "skipped_steps": flow.skipped_steps,
        "started_at": flow.started_at,
        "last_activity_at": flow.last_activity_at,
        "completed_at": flow.completed_at,
        "estimated_completion": flow.estimated_completion,
        "assigned_analyst_id": flow.assigned_analyst_id,
        "lead_analyst_id": flow.lead_analyst_id,
        "team_members": flow.team_members,
        "tags": flow.tags,
        "assigned_analyst": {
            "id": flow.assigned_analyst.id,
            "username": flow.assigned_analyst.username,
            "full_name": flow.assigned_analyst.full_name
        } if flow.assigned_analyst else None,
        "lead_analyst": {
            "id": flow.lead_analyst.id,
            "username": flow.lead_analyst.username,
            "full_name": flow.lead_analyst.full_name
        } if flow.lead_analyst else None,
        "playbook": {
            "id": flow.playbook.id,
            "name": flow.playbook.name,
            "version": flow.playbook.version
        } if flow.playbook else None,
        "current_step": current_step_data
    }
    
    return IncidentFlowResponse(**response_data)

def initialize_flow_steps(flow_id: int, db: Session):
    """Initialize steps from playbook definition"""
    
    with db() as session:
        flow = session.query(IncidentFlow).filter(IncidentFlow.id == flow_id).first()
        if not flow or not flow.playbook_snapshot:
            return
        
        phases = flow.playbook_snapshot.get("phases", [])
        global_step_index = 0
        
        for phase_index, phase in enumerate(phases):
            phase_name = phase.get("name", f"phase_{phase_index}")
            steps = phase.get("steps", [])
            
            for step_index, step_def in enumerate(steps):
                step = IncidentFlowStep(
                    flow_id=flow.id,
                    phase_name=phase_name,
                    step_name=step_def.get("name", f"step_{global_step_index}"),
                    step_index=step_index,
                    global_step_index=global_step_index,
                    step_type=step_def.get("type", StepType.MANUAL_ACTION),
                    title=step_def.get("title", ""),
                    description=step_def.get("description", ""),
                    instructions=step_def.get("instructions"),
                    expected_duration=step_def.get("expected_duration"),
                    input_schema=step_def.get("input_schema"),
                    validation_rules=step_def.get("validation_rules"),
                    depends_on_steps=step_def.get("depends_on", []),
                    is_automated=step_def.get("automated", False),
                    automation_script=step_def.get("automation_script"),
                    requires_approval=step_def.get("requires_approval", False)
                )
                
                session.add(step)
                global_step_index += 1
        
        session.commit()

def update_flow_progress(flow_id: int, db: Session):
    """Update flow progress based on step completion"""
    
    with db() as session:
        flow = session.query(IncidentFlow).filter(IncidentFlow.id == flow_id).first()
        if not flow:
            return
        
        # Count step statuses
        completed_steps = session.query(IncidentFlowStep).filter(
            IncidentFlowStep.flow_id == flow.id,
            IncidentFlowStep.status == StepStatus.COMPLETED
        ).count()
        
        failed_steps = session.query(IncidentFlowStep).filter(
            IncidentFlowStep.flow_id == flow.id,
            IncidentFlowStep.status == StepStatus.FAILED
        ).count()
        
        skipped_steps = session.query(IncidentFlowStep).filter(
            IncidentFlowStep.flow_id == flow.id,
            IncidentFlowStep.status == StepStatus.SKIPPED
        ).count()
        
        # Update counts
        flow.completed_steps = completed_steps
        flow.failed_steps = failed_steps
        flow.skipped_steps = skipped_steps
        
        # Update progress percentage
        flow.update_progress()
        
        # Check if flow is complete
        if completed_steps + failed_steps + skipped_steps >= flow.total_steps:
            flow.status = IncidentFlowStatus.COMPLETED
            flow.completed_at = datetime.utcnow()
            flow.progress_percentage = 100.0
        
        session.commit()

def advance_to_next_step(flow_id: int, current_step_index: int, db: Session):
    """Advance to the next available step"""
    
    with db() as session:
        flow = session.query(IncidentFlow).filter(IncidentFlow.id == flow_id).first()
        if not flow:
            return
        
        # Find next pending step that can be executed
        next_step = session.query(IncidentFlowStep).filter(
            IncidentFlowStep.flow_id == flow.id,
            IncidentFlowStep.global_step_index > current_step_index,
            IncidentFlowStep.status == StepStatus.PENDING
        ).order_by(IncidentFlowStep.global_step_index).first()
        
        if next_step and next_step.can_execute:
            # Update flow current step
            flow.current_step_name = next_step.step_name
            flow.current_phase = next_step.phase_name
            
            # Start the next step if it doesn't require manual intervention
            if next_step.step_type != StepType.USER_INPUT and not next_step.requires_approval:
                next_step.status = StepStatus.IN_PROGRESS
                next_step.started_at = datetime.utcnow()
            elif next_step.step_type == StepType.USER_INPUT:
                next_step.status = StepStatus.WAITING_INPUT
                flow.status = IncidentFlowStatus.WAITING_INPUT
            elif next_step.requires_approval:
                next_step.status = StepStatus.WAITING_APPROVAL
        
        session.commit()

def get_phase_summary(steps):
    """Generate summary metrics by phase"""
    
    phases = {}
    
    for step in steps:
        if step.phase_name not in phases:
            phases[step.phase_name] = {
                "total_steps": 0,
                "completed_steps": 0,
                "failed_steps": 0,
                "skipped_steps": 0,
                "total_duration": 0,
                "progress_percentage": 0
            }
        
        phase = phases[step.phase_name]
        phase["total_steps"] += 1
        
        if step.status == StepStatus.COMPLETED:
            phase["completed_steps"] += 1
        elif step.status == StepStatus.FAILED:
            phase["failed_steps"] += 1
        elif step.status == StepStatus.SKIPPED:
            phase["skipped_steps"] += 1
        
        if step.actual_duration:
            phase["total_duration"] += step.actual_duration
    
    # Calculate progress percentages
    for phase_name, phase in phases.items():
        completed = phase["completed_steps"] + phase["skipped_steps"]
        if phase["total_steps"] > 0:
            phase["progress_percentage"] = (completed / phase["total_steps"]) * 100
    
    return phases

def generate_json_report(flow: IncidentFlow):
    """Generate JSON format report"""
    
    return {
        "flow_id": flow.flow_id,
        "incident_id": flow.incident_id,
        "playbook": {
            "name": flow.playbook.name,
            "version": flow.playbook.version
        } if flow.playbook else None,
        "status": flow.status,
        "progress": {
            "percentage": flow.progress_percentage,
            "total_steps": flow.total_steps,
            "completed_steps": flow.completed_steps,
            "failed_steps": flow.failed_steps,
            "skipped_steps": flow.skipped_steps
        },
        "timing": {
            "started_at": flow.started_at.isoformat() if flow.started_at else None,
            "completed_at": flow.completed_at.isoformat() if flow.completed_at else None,
            "actual_duration": flow.actual_duration,
            "pause_duration": flow.total_pause_duration
        },
        "team": {
            "assigned_analyst": {
                "id": flow.assigned_analyst.id,
                "username": flow.assigned_analyst.username,
                "full_name": flow.assigned_analyst.full_name
            } if flow.assigned_analyst else None,
            "lead_analyst": {
                "id": flow.lead_analyst.id,
                "username": flow.lead_analyst.username,
                "full_name": flow.lead_analyst.full_name
            } if flow.lead_analyst else None,
            "team_members": flow.team_members
        },
        "results": {
            "incident_contained": flow.incident_contained,
            "root_cause_identified": flow.root_cause_identified,
            "threat_eradicated": flow.threat_eradicated,
            "systems_recovered": flow.systems_recovered,
            "executive_summary": flow.executive_summary,
            "technical_summary": flow.technical_summary,
            "business_impact": flow.business_impact,
            "lessons_learned": flow.lessons_learned
        },
        "metrics": {
            "time_to_containment": flow.time_to_containment,
            "time_to_eradication": flow.time_to_eradication,
            "time_to_recovery": flow.time_to_recovery,
            "procedure_compliance_score": flow.procedure_compliance_score,
            "response_effectiveness_score": flow.response_effectiveness_score
        },
        "steps": [
            {
                "phase_name": step.phase_name,
                "step_name": step.step_name,
                "title": step.title,
                "status": step.status,
                "success": step.success,
                "started_at": step.started_at.isoformat() if step.started_at else None,
                "completed_at": step.completed_at.isoformat() if step.completed_at else None,
                "actual_duration": step.actual_duration,
                "output_data": step.output_data,
                "notes": step.notes
            }
            for step in sorted(flow.steps, key=lambda x: x.global_step_index)
        ],
        "artifacts": [
            {
                "name": artifact.name,
                "type": artifact.artifact_type,
                "description": artifact.description,
                "collected_at": artifact.collected_at.isoformat(),
                "is_critical": artifact.is_critical,
                "tags": artifact.tags
            }
            for artifact in flow.artifacts
        ],
        "user_inputs": [
            {
                "field_name": inp.field_name,
                "label": inp.label,
                "field_type": inp.field_type,
                "raw_value": inp.raw_value if not inp.is_sensitive else "[REDACTED]",
                "collected_at": inp.collected_at.isoformat()
            }
            for inp in flow.user_inputs
        ]
    }

def generate_markdown_report(flow: IncidentFlow, current_user: User):
    """Generate Markdown format report"""
    
    report_lines = []
    
    # Header
    report_lines.extend([
        f"# Incident Response Flow Report",
        f"**Flow ID:** {flow.flow_id}",
        f"**Incident ID:** {flow.incident_id}",
        f"**Playbook:** {flow.playbook.name} v{flow.playbook.version}" if flow.playbook else "**Playbook:** Unknown",
        f"**Status:** {flow.status.title()}",
        f"**Progress:** {flow.progress_percentage:.1f}% ({flow.completed_steps}/{flow.total_steps} steps)",
        "",
        "---",
        ""
    ])
    
    # Executive Summary
    if flow.executive_summary:
        report_lines.extend([
            "## Executive Summary",
            flow.executive_summary,
            ""
        ])
    
    # Timeline
    report_lines.extend([
        "## Timeline",
        f"- **Started:** {flow.started_at.strftime('%Y-%m-%d %H:%M:%S UTC') if flow.started_at else 'Not started'}",
        f"- **Completed:** {flow.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if flow.completed_at else 'In progress'}",
        f"- **Duration:** {flow.actual_duration} minutes" if flow.actual_duration else "- **Duration:** In progress",
        ""
    ])
    
    # Team
    report_lines.extend([
        "## Response Team",
        f"- **Assigned Analyst:** {flow.assigned_analyst.full_name} (@{flow.assigned_analyst.username})" if flow.assigned_analyst else "- **Assigned Analyst:** Unknown",
        f"- **Lead Analyst:** {flow.lead_analyst.full_name} (@{flow.lead_analyst.username})" if flow.lead_analyst else "",
        f"- **Team Members:** {len(flow.team_members)} additional members" if flow.team_members else "- **Team Members:** None",
        ""
    ])
    
    # Results
    if any([flow.incident_contained, flow.root_cause_identified, flow.threat_eradicated, flow.systems_recovered]):
        report_lines.extend([
            "## Incident Status",
            f"- **Contained:** {'✅ Yes' if flow.incident_contained else '❌ No'}",
            f"- **Root Cause Identified:** {'✅ Yes' if flow.root_cause_identified else '❌ No'}",
            f"- **Threat Eradicated:** {'✅ Yes' if flow.threat_eradicated else '❌ No'}",
            f"- **Systems Recovered:** {'✅ Yes' if flow.systems_recovered else '❌ No'}",
            ""
        ])
    
    # Steps Summary
    report_lines.extend([
        "## Step Execution Summary",
        ""
    ])
    
    # Group steps by phase
    phases = {}
    for step in flow.steps:
        if step.phase_name not in phases:
            phases[step.phase_name] = []
        phases[step.phase_name].append(step)
    
    for phase_name, steps in phases.items():
        report_lines.extend([
            f"### {phase_name.title()} Phase",
            ""
        ])
        
        for step in sorted(steps, key=lambda x: x.step_index):
            status_icon = {
                StepStatus.COMPLETED: "✅",
                StepStatus.FAILED: "❌",
                StepStatus.SKIPPED: "⏭️",
                StepStatus.IN_PROGRESS: "🔄",
                StepStatus.PENDING: "⏸️",
                StepStatus.WAITING_INPUT: "⌨️",
                StepStatus.WAITING_APPROVAL: "👥"
            }.get(step.status, "❓")
            
            duration_text = f" ({step.actual_duration}m)" if step.actual_duration else ""
            success_text = f" - {'Success' if step.success else 'Failed'}" if step.success is not None else ""
            
            report_lines.append(f"- {status_icon} **{step.title}**{duration_text}{success_text}")
            
            if step.notes:
                report_lines.append(f"  - Notes: {step.notes}")
            
            if step.error_message:
                report_lines.append(f"  - Error: {step.error_message}")
        
        report_lines.append("")
    
    # Artifacts
    if flow.artifacts:
        report_lines.extend([
            "## Evidence Collected",
            ""
        ])
        
        for artifact in flow.artifacts:
            critical_text = " (Critical)" if artifact.is_critical else ""
            report_lines.append(f"- **{artifact.name}**{critical_text}")
            report_lines.append(f"  - Type: {artifact.artifact_type}")
            if artifact.description:
                report_lines.append(f"  - Description: {artifact.description}")
            report_lines.append(f"  - Collected: {artifact.collected_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
        
        report_lines.append("")
    
    # Technical Summary
    if flow.technical_summary:
        report_lines.extend([
            "## Technical Summary",
            flow.technical_summary,
            ""
        ])
    
    # Business Impact
    if flow.business_impact:
        report_lines.extend([
            "## Business Impact",
            flow.business_impact,
            ""
        ])
    
    # Lessons Learned
    if flow.lessons_learned:
        report_lines.extend([
            "## Lessons Learned",
            flow.lessons_learned,
            ""
        ])
    
    # Metrics
    if any([flow.time_to_containment, flow.time_to_eradication, flow.time_to_recovery]):
        report_lines.extend([
            "## Response Metrics",
            ""
        ])
        
        if flow.time_to_containment:
            report_lines.append(f"- **Time to Containment:** {flow.time_to_containment} minutes")
        if flow.time_to_eradication:
            report_lines.append(f"- **Time to Eradication:** {flow.time_to_eradication} minutes")
        if flow.time_to_recovery:
            report_lines.append(f"- **Time to Recovery:** {flow.time_to_recovery} minutes")
        if flow.procedure_compliance_score:
            report_lines.append(f"- **Procedure Compliance Score:** {flow.procedure_compliance_score}%")
        if flow.response_effectiveness_score:
            report_lines.append(f"- **Response Effectiveness Score:** {flow.response_effectiveness_score}%")
        
        report_lines.append("")
    
    # Footer
    report_lines.extend([
        "---",
        f"*Report generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')} by {current_user.full_name}*"
    ])
    
    return {
        "format": "markdown",
        "content": "\n".join(report_lines),
        "generated_at": datetime.utcnow().isoformat(),
        "generated_by": current_user.username
    }