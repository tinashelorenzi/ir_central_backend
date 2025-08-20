"""
Incident Management API Routes
Handles incident-specific operations and queries
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging

from database import get_db
from models.users import User
from models.incident import Incident, IncidentStatus
from models.incident_flow import IncidentFlow, IncidentFlowStep, IncidentFlowUserInput
from auth_utils import get_current_user
from schemas import PaginatedResponse, MessageResponse

# Configure logging
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

@router.get("/{incident_id}/closure-details", response_model=dict)
async def get_incident_closure_details(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get comprehensive closure details for a completed incident
    """
    try:
        # Get the incident
        incident = db.query(Incident).filter(Incident.incident_id == incident_id).first()
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Check if incident is closed/resolved
        if incident.status not in [IncidentStatus.RESOLVED, IncidentStatus.CLOSED]:
            raise HTTPException(
                status_code=400, 
                detail="Incident closure details only available for resolved/closed incidents"
            )
        
        # Get the associated incident flow
        flow = db.query(IncidentFlow).filter(
            IncidentFlow.incident_id == incident_id
        ).first()
        
        closure_details = {
            "incident_id": incident_id,
            "status": incident.status,
            "severity": incident.severity,
            "title": incident.title,
            "description": incident.description,
            "assigned_analyst": None,
            "completed_at": None,
            "playbook_name": None,
            "playbook_description": None,
            "final_report": None,
            "steps": [],
            "user_inputs": [],
            "time_to_containment": None,
            "time_to_resolution": None,
            "response_metrics": {}
        }
        
        if flow:
            # Add flow-specific details
            closure_details.update({
                "assigned_analyst": flow.assigned_analyst.full_name if flow.assigned_analyst else None,
                "completed_at": flow.completed_at.isoformat() if flow.completed_at else None,
                "final_report": flow.executive_summary,
                "time_to_containment": flow.time_to_containment,
                "time_to_resolution": flow.time_to_eradication,
                "response_metrics": {
                    "time_to_containment": flow.time_to_containment,
                    "time_to_eradication": flow.time_to_eradication,
                    "time_to_recovery": flow.time_to_recovery,
                    "procedure_compliance_score": flow.procedure_compliance_score,
                    "response_effectiveness_score": flow.response_effectiveness_score
                }
            })
            
            # Add playbook information
            if flow.playbook:
                closure_details.update({
                    "playbook_name": flow.playbook.name,
                    "playbook_description": flow.playbook.description
                })
            
            # Get flow steps
            steps = db.query(IncidentFlowStep).filter(
                IncidentFlowStep.flow_id == flow.id
            ).order_by(IncidentFlowStep.global_step_index).all()
            
            closure_details["steps"] = [
                {
                    "step_name": step.step_name,
                    "description": step.description,
                    "status": step.status,
                    "started_at": step.started_at.isoformat() if step.started_at else None,
                    "completed_at": step.completed_at.isoformat() if step.completed_at else None,
                    "output_data": step.output_data,
                    "error_message": step.error_message if step.status == 'failed' else None
                }
                for step in steps
            ]
            
            # Get user inputs
            user_inputs = db.query(IncidentFlowUserInput).filter(
                IncidentFlowUserInput.flow_id == flow.id
            ).order_by(IncidentFlowUserInput.collected_at).all()
            
            closure_details["user_inputs"] = [
                {
                    "field_name": ui.field_name,
                    "value": ui.raw_value,
                    "collected_at": ui.collected_at.isoformat() if ui.collected_at else None,
                    "step_name": ui.step_name
                }
                for ui in user_inputs
                if not ui.is_sensitive  # Don't expose sensitive inputs
            ]
        
        # Add incident timeline if available
        if incident.incident_timeline:
            closure_details["timeline"] = incident.incident_timeline
        
        return closure_details
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting closure details for incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/", response_model=PaginatedResponse)
async def list_incidents(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    status: Optional[List[IncidentStatus]] = Query(None, description="Filter by status"),
    severity: Optional[List[str]] = Query(None, description="Filter by severity"),
    search: Optional[str] = Query(None, description="Search in title/description"),
    assigned_to_me: bool = Query(False, description="Show only incidents assigned to current user"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List incidents with filtering and pagination
    """
    try:
        # Build base query
        query = db.query(Incident).options(
            joinedload(Incident.owner),
            joinedload(Incident.assigned_analyst)
        )
        
        # Apply filters
        if status:
            query = query.filter(Incident.status.in_(status))
        
        if severity:
            query = query.filter(Incident.severity.in_(severity))
        
        if search:
            search_filter = f"%{search}%"
            query = query.filter(
                or_(
                    Incident.title.ilike(search_filter),
                    Incident.description.ilike(search_filter),
                    Incident.incident_id.ilike(search_filter)
                )
            )
        
        if assigned_to_me:
            query = query.filter(Incident.assigned_analyst_id == current_user.id)
        
        # Get total count
        total_count = query.count()
        
        # Apply pagination and sorting
        incidents = query.order_by(desc(Incident.created_at)).offset((page - 1) * size).limit(size).all()
        
        # Convert to response format
        incident_data = []
        for incident in incidents:
            incident_data.append({
                "id": incident.id,
                "incident_id": incident.incident_id,
                "title": incident.title,
                "description": incident.description,
                "status": incident.status,
                "severity": incident.severity,
                "priority": incident.priority,
                "category": incident.category,
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
                "owner": {
                    "id": incident.owner.id,
                    "username": incident.owner.username,
                    "full_name": incident.owner.full_name
                } if incident.owner else None,
                "assigned_analyst": {
                    "id": incident.assigned_analyst.id,
                    "username": incident.assigned_analyst.username,
                    "full_name": incident.assigned_analyst.full_name
                } if incident.assigned_analyst else None,
                "alert_count": incident.alert_count,
                "time_to_first_response": incident.time_to_first_response,
                "time_to_containment": incident.time_to_containment,
                "time_to_resolution": incident.time_to_resolution
            })
        
        return PaginatedResponse(
            data=incident_data,
            page=page,
            size=size,
            total=total_count,
            total_pages=(total_count + size - 1) // size
        )
        
    except Exception as e:
        logger.error(f"Error listing incidents: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{incident_id}", response_model=dict)
async def get_incident(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get detailed information about a specific incident
    """
    try:
        incident = db.query(Incident).options(
            joinedload(Incident.owner),
            joinedload(Incident.assigned_analyst),
            joinedload(Incident.escalated_to)
        ).filter(Incident.incident_id == incident_id).first()
        
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")
        
        # Get associated flow if exists
        flow = db.query(IncidentFlow).filter(
            IncidentFlow.incident_id == incident_id
        ).first()
        
        incident_data = {
            "id": incident.id,
            "incident_id": incident.incident_id,
            "title": incident.title,
            "description": incident.description,
            "status": incident.status,
            "severity": incident.severity,
            "priority": incident.priority,
            "category": incident.category,
            "created_at": incident.created_at.isoformat(),
            "updated_at": incident.updated_at.isoformat(),
            "first_response_at": incident.first_response_at.isoformat() if incident.first_response_at else None,
            "contained_at": incident.contained_at.isoformat() if incident.contained_at else None,
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
            "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
            "owner": {
                "id": incident.owner.id,
                "username": incident.owner.username,
                "full_name": incident.owner.full_name
            } if incident.owner else None,
            "assigned_analyst": {
                "id": incident.assigned_analyst.id,
                "username": incident.assigned_analyst.username,
                "full_name": incident.assigned_analyst.full_name
            } if incident.assigned_analyst else None,
            "escalated_to": {
                "id": incident.escalated_to.id,
                "username": incident.escalated_to.username,
                "full_name": incident.escalated_to.full_name
            } if incident.escalated_to else None,
            "alert_ids": incident.alert_ids or [],
            "affected_systems": incident.affected_systems or [],
            "affected_users": incident.affected_users or [],
            "affected_services": incident.affected_services or [],
            "attack_vectors": incident.attack_vectors or [],
            "indicators_of_compromise": incident.indicators_of_compromise or [],
            "investigation_summary": incident.investigation_summary,
            "investigation_notes": incident.investigation_notes,
            "incident_timeline": incident.incident_timeline or [],
            "business_impact": incident.business_impact,
            "estimated_financial_loss": incident.estimated_financial_loss,
            "data_compromised": incident.data_compromised,
            "data_types_affected": incident.data_types_affected or [],
            "systems_compromised": incident.systems_compromised,
            "users_affected": incident.users_affected,
            "containment_strategy": incident.containment_strategy,
            "containment_actions": incident.containment_actions or [],
            "eradication_actions": incident.eradication_actions or [],
            "recovery_actions": incident.recovery_actions or [],
            "lessons_learned": incident.lessons_learned,
            "recommendations": incident.recommendations or [],
            "follow_up_actions": incident.follow_up_actions or [],
            "tags": incident.tags or [],
            "custom_fields": incident.custom_fields or {},
            "time_to_first_response": incident.time_to_first_response,
            "time_to_containment": incident.time_to_containment,
            "time_to_resolution": incident.time_to_resolution,
            "is_sla_breached": incident.is_sla_breached,
            "has_active_flow": flow is not None
        }
        
        if flow:
            incident_data["flow"] = {
                "flow_id": flow.flow_id,
                "status": flow.status,
                "progress_percentage": flow.progress_percentage,
                "current_phase": flow.current_phase,
                "current_step_name": flow.current_step_name,
                "started_at": flow.started_at.isoformat() if flow.started_at else None,
                "completed_at": flow.completed_at.isoformat() if flow.completed_at else None
            }
        
        return incident_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting incident {incident_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
