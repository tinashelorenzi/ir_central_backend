"""
Reports API Routes
Handles creation, management, and generation of IR reports
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, UploadFile, File
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc, asc, func, text
from typing import List, Optional, Dict, Any, Union
from datetime import datetime, timedelta
import logging
import json
import asyncio
from pathlib import Path
import os,traceback

from database import get_db, SessionLocal
from models.users import User, UserRole
from models.reports import Report, ReportElement, ReportShare, ReportComment, ReportType, ReportStatus, ReportFormat
from models.report_templates import ReportTemplate
from models.incident import Incident, IncidentStatus
from models.playbook import PlaybookExecution, PlaybookUserInput
from auth_utils import get_current_user, require_manager_or_above, require_role
from schemas import (
    # Report schemas
    ReportCreate, ReportUpdate, ReportResponse, ReportListItem, ReportListResponse,
    ReportSearchRequest, ReportStatsResponse, ReportGenerationRequest,
    
    # Report wizard schemas
    ReportWizardStep1, ReportWizardStep2Incident, ReportWizardStep2Collective, ReportWizardComplete,
    
    # Report element schemas
    ReportElementCreate, ReportElementUpdate, ReportElementResponse,
    
    # Report sharing schemas
    ReportShareCreate, ReportShareResponse,
    
    # Report comment schemas
    ReportCommentCreate, ReportCommentUpdate, ReportCommentResponse,
    
    # Export schemas
    ReportExportRequest, ReportExportResponse,
    
    # Utility schemas
    AvailableDataSource, ReportBuildingContext, BulkReportOperation, BulkReportOperationResponse,
    MessageResponse, PaginatedResponse
)

# Configure logging
logger = logging.getLogger(__name__)

# Create router
router = APIRouter(prefix="/api/v1/reports", tags=["reports"])

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def format_report_response(report: Report, include_elements: bool = False) -> dict:
    """Format report for API response with related data"""
    response_data = report.to_dict()
    
    # Add creator information
    if report.created_by:
        response_data["created_by"] = {
            "id": report.created_by.id,
            "username": report.created_by.username,
            "full_name": report.created_by.full_name
        }
    
    # Add template information
    if report.template:
        response_data["template"] = {
            "id": report.template.id,
            "name": report.template.name,
            "description": report.template.description
        }
    
    # Add elements if requested
    if include_elements and hasattr(report, 'elements'):
        response_data["elements"] = [
            {
                "id": element.id,
                "element_type": element.element_type,
                "element_key": element.element_key,
                "display_name": element.display_name,
                "section_name": element.section_name,
                "position_order": element.position_order,
                "element_data": element.element_data,
                "template_variable": element.template_variable
            }
            for element in sorted(report.elements, key=lambda x: (x.section_name, x.position_order))
        ]
    
    return response_data

def build_report_query(db: Session, search_params: ReportSearchRequest, current_user: User):
    """Build query for report search with filters"""
    query = db.query(Report).options(
        joinedload(Report.created_by),
        joinedload(Report.template)
    )
    
    # Search in title and description
    if search_params.search:
        search_term = f"%{search_params.search}%"
        query = query.filter(
            or_(
                Report.title.ilike(search_term),
                Report.description.ilike(search_term),
                Report.executive_summary.ilike(search_term)
            )
        )
    
    # Filter by report type
    if search_params.report_type:
        query = query.filter(Report.report_type == search_params.report_type)
    
    # Filter by status
    if search_params.status:
        query = query.filter(Report.status == search_params.status)
    
    # Filter by creator
    if search_params.created_by_id:
        query = query.filter(Report.created_by_id == search_params.created_by_id)
    
    # Filter by template
    if search_params.template_id:
        query = query.filter(Report.template_id == search_params.template_id)
    
    # Filter by tags
    if search_params.tags:
        tag_conditions = []
        for tag in search_params.tags:
            tag_conditions.append(Report.tags.ilike(f"%{tag}%"))
        query = query.filter(or_(*tag_conditions))
    
    # Filter by date range
    if search_params.date_range:
        if search_params.date_range.get("start"):
            start_date = datetime.fromisoformat(search_params.date_range["start"])
            query = query.filter(Report.created_at >= start_date)
        if search_params.date_range.get("end"):
            end_date = datetime.fromisoformat(search_params.date_range["end"])
            query = query.filter(Report.created_at <= end_date)
    
    # Apply access control - users can only see their own reports unless manager+
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        query = query.filter(Report.created_by_id == current_user.id)
    
    return query

async def get_available_incidents_for_user(db: Session, current_user: User) -> List[Dict[str, Any]]:
    """Get incidents available for report creation"""
    query = db.query(Incident).filter(
        Incident.status.in_([IncidentStatus.RESOLVED, IncidentStatus.CLOSED])
    )
    
    # Apply access control
    if current_user.role not in [UserRole.MANAGER, UserRole.ADMIN]:
        query = query.filter(Incident.assigned_analyst_id == current_user.id)
    
    incidents = query.order_by(desc(Incident.created_at)).limit(100).all()
    
    return [
        {
            "id": incident.id,
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
            "created_at": incident.created_at.isoformat(),
            "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None
        }
        for incident in incidents
    ]

async def get_available_data_sources(db: Session, incident_ids: List[int] = None) -> List[AvailableDataSource]:
    """Get available data sources for report building"""
    data_sources = []
    
    # Get user inputs from playbook executions
    query = db.query(PlaybookUserInput)
    if incident_ids:
        # Filter by incidents through playbook executions
        query = query.join(PlaybookExecution).filter(
            PlaybookExecution.incident_id.in_(incident_ids)
        )
    
    user_inputs = query.all()
    
    for input_item in user_inputs:
        data_sources.append(AvailableDataSource(
            source_type="user_input",
            source_id=f"input_{input_item.id}",
            display_name=input_item.input_label or input_item.field_name,
            description=f"User input from {input_item.phase_name} - {input_item.step_name}",
            data_type=input_item.field_type,
            sample_value=str(input_item.user_input) if input_item.user_input else None,
            available_in_sections=["timeline", "actions_taken", "user_inputs"]
        ))
    
    # Add predefined analytics options
    analytics_sources = [
        AvailableDataSource(
            source_type="analytics",
            source_id="incident_count",
            display_name="Total Incidents",
            description="Count of incidents in the report",
            data_type="number",
            available_in_sections=["executive_summary", "analytics"]
        ),
        AvailableDataSource(
            source_type="analytics", 
            source_id="mttr",
            display_name="Mean Time to Resolution",
            description="Average time to resolve incidents",
            data_type="number",
            available_in_sections=["executive_summary", "analytics"]
        ),
        AvailableDataSource(
            source_type="analytics",
            source_id="affected_systems",
            display_name="Affected Systems Count",
            description="Number of systems affected",
            data_type="number",
            available_in_sections=["impact_assessment", "analytics"]
        )
    ]
    
    data_sources.extend(analytics_sources)
    
    return data_sources

# ============================================================================
# MAIN REPORT CRUD ENDPOINTS
# ============================================================================

@router.get("/", response_model=ReportListResponse)
async def list_reports(
    search: Optional[str] = Query(None, description="Search in title, description"),
    report_type: Optional[ReportType] = None,
    status: Optional[ReportStatus] = None,
    created_by_id: Optional[int] = None,
    template_id: Optional[int] = None,
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    date_start: Optional[str] = Query(None, description="Start date (ISO format)"),
    date_end: Optional[str] = Query(None, description="End date (ISO format)"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    sort_by: str = Query("created_at", description="Field to sort by"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List reports with filtering and pagination.
    Users can only see their own reports unless they are Manager+ role.
    """
    
    # Build search parameters
    date_range = {}
    if date_start:
        date_range["start"] = date_start
    if date_end:
        date_range["end"] = date_end
    
    search_params = ReportSearchRequest(
        search=search,
        report_type=report_type,
        status=status,
        created_by_id=created_by_id,
        template_id=template_id,
        tags=tags.split(",") if tags else None,
        date_range=date_range if date_range else None,
        page=page,
        size=size,
        sort_by=sort_by,
        sort_order=sort_order
    )
    
    # Build query
    query = build_report_query(db, search_params, current_user)
    
    # Apply sorting
    sort_column = getattr(Report, sort_by, Report.created_at)
    if sort_order == "desc":
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(asc(sort_column))
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * size
    reports = query.offset(offset).limit(size).all()
    
    # Format response
    report_items = []
    for report in reports:
        item_data = format_report_response(report)
        report_items.append(ReportListItem(**item_data))
    
    return ReportListResponse(
        reports=report_items,
        total=total,
        page=page,
        size=size,
        total_pages=(total + size - 1) // size,
        has_next=offset + size < total,
        has_prev=page > 1
    )

@router.post("/", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def create_report(
    report_data: ReportCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new report.
    """
    
    # Validate template exists if specified
    if report_data.template_id:
        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == report_data.template_id
        ).first()
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
    
    # Create report
    report = Report(
        title=report_data.title,
        description=report_data.description,
        report_type=report_data.report_type,
        template_id=report_data.template_id,
        report_config=report_data.report_config,
        tags=report_data.tags,
        executive_summary=report_data.executive_summary,
        created_by_id=current_user.id,
        status=ReportStatus.DRAFT
    )
    
    db.add(report)
    db.commit()
    db.refresh(report)
    
    logger.info(f"Report created: {report.id} by user {current_user.username}")
    
    return ReportResponse(**format_report_response(report))

@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a specific report by ID.
    """
    
    report = db.query(Report).options(
        joinedload(Report.created_by),
        joinedload(Report.template),
        joinedload(Report.elements)
    ).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check access permissions
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this report"
        )
    
    # Update view count and last accessed
    report.view_count += 1
    report.last_accessed_at = datetime.utcnow()
    db.commit()
    
    return ReportResponse(**format_report_response(report, include_elements=True))

@router.put("/{report_id}", response_model=ReportResponse)
async def update_report(
    report_id: int,
    report_data: ReportUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update a report.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check permissions
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this report"
        )
    
    # Update fields
    update_data = report_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(report, field, value)
    
    report.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(report)
    
    logger.info(f"Report updated: {report.id} by user {current_user.username}")
    
    return ReportResponse(**format_report_response(report))

@router.delete("/{report_id}", response_model=MessageResponse)
async def delete_report(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a report.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check permissions
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this report"
        )
    
    # TODO: Delete associated files from filesystem
    
    db.delete(report)
    db.commit()
    
    logger.info(f"Report deleted: {report_id} by user {current_user.username}")
    
    return MessageResponse(message="Report deleted successfully")

# ============================================================================
# REPORT WIZARD ENDPOINTS
# ============================================================================

@router.get("/wizard/available-incidents", response_model=List[Dict[str, Any]])
async def get_available_incidents(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get available incidents for report creation.
    Returns resolved/closed incidents that the user has access to.
    """
    
    incidents = await get_available_incidents_for_user(db, current_user)
    return incidents

@router.post("/wizard/complete", response_model=ReportResponse)
async def complete_report_wizard(
    wizard_data: ReportWizardComplete,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Complete the report creation wizard and create the report.
    """
    
    # Validate step 1 data
    step1 = wizard_data.step1
    
    # Validate template if specified
    if step1.template_id:
        template = db.query(ReportTemplate).filter(
            ReportTemplate.id == step1.template_id
        ).first()
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report template not found"
            )
    
    # Build report configuration based on wizard steps
    report_config = {
        "type": step1.report_type.value,
        "include_sections": wizard_data.include_sections,
        "analytics": wizard_data.analytics_options
    }
    
    # Add type-specific configuration
    if step1.report_type == ReportType.INCIDENT:
        step2_incident = wizard_data.step2
        if hasattr(step2_incident, 'incident_ids'):
            report_config["incident_ids"] = step2_incident.incident_ids
            
            # Validate incidents exist and user has access
            incidents = db.query(Incident).filter(
                Incident.id.in_(step2_incident.incident_ids)
            ).all()
            
            if len(incidents) != len(step2_incident.incident_ids):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="One or more incidents not found"
                )
    
    elif step1.report_type == ReportType.COLLECTIVE:
        step2_collective = wizard_data.step2
        if hasattr(step2_collective, 'date_range'):
            report_config["filters"] = {
                "date_range": step2_collective.date_range,
                "users": step2_collective.users,
                "ip_addresses": step2_collective.ip_addresses,
                "incident_types": step2_collective.incident_types,
                "severity_levels": step2_collective.severity_levels,
                "status_filters": step2_collective.status_filters,
                "affected_departments": step2_collective.affected_departments,
                "playbook_types": step2_collective.playbook_types
            }
    
    # Create the report
    report = Report(
        title=step1.title,
        description=step1.description,
        report_type=step1.report_type,
        template_id=step1.template_id,
        report_config=report_config,
        created_by_id=current_user.id,
        status=ReportStatus.DRAFT
    )
    
    db.add(report)
    db.commit()
    db.refresh(report)
    
    logger.info(f"Report created via wizard: {report.id} by user {current_user.username}")
    
    return ReportResponse(**format_report_response(report))

# ============================================================================
# REPORT ELEMENTS ENDPOINTS
# ============================================================================

@router.get("/{report_id}/elements", response_model=List[ReportElementResponse])
async def get_report_elements(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all elements for a report.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check access
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this report"
        )
    
    elements = db.query(ReportElement).filter(
        ReportElement.report_id == report_id
    ).order_by(ReportElement.section_name, ReportElement.position_order).all()
    
    return [ReportElementResponse.from_orm(element) for element in elements]

@router.post("/{report_id}/elements", response_model=ReportElementResponse)
async def add_report_element(
    report_id: int,
    element_data: ReportElementCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Add an element to a report.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check permissions
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to modify this report"
        )
    
    # Validate element data based on type
    if element_data.element_type == "user_input":
        # Validate that the referenced user input exists
        if "execution_id" in element_data.element_data and "field_name" in element_data.element_data:
            user_input = db.query(PlaybookUserInput).filter(
                PlaybookUserInput.execution_id == element_data.element_data["execution_id"],
                PlaybookUserInput.field_name == element_data.element_data["field_name"]
            ).first()
            if not user_input:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Referenced user input not found"
                )
    
    # Create element
    element = ReportElement(
        report_id=report_id,
        element_type=element_data.element_type,
        element_key=element_data.element_key,
        display_name=element_data.display_name,
        section_name=element_data.section_name,
        position_order=element_data.position_order,
        element_data=element_data.element_data,
        template_variable=element_data.template_variable,
        added_by_id=current_user.id
    )
    
    db.add(element)
    db.commit()
    db.refresh(element)
    
    return ReportElementResponse.from_orm(element)

@router.put("/{report_id}/elements/{element_id}", response_model=ReportElementResponse)
async def update_report_element(
    report_id: int,
    element_id: int,
    element_data: ReportElementUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update a report element.
    """
    
    element = db.query(ReportElement).filter(
        ReportElement.id == element_id,
        ReportElement.report_id == report_id
    ).first()
    
    if not element:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report element not found"
        )
    
    # Check permissions
    report = element.report
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to modify this report"
        )
    
    # Update fields
    update_data = element_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(element, field, value)
    
    element.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(element)
    
    return ReportElementResponse.from_orm(element)

@router.delete("/{report_id}/elements/{element_id}", response_model=MessageResponse)
async def delete_report_element(
    report_id: int,
    element_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a report element.
    """
    
    element = db.query(ReportElement).filter(
        ReportElement.id == element_id,
        ReportElement.report_id == report_id
    ).first()
    
    if not element:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report element not found"
        )
    
    # Check permissions
    report = element.report
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to modify this report"
        )
    
    db.delete(element)
    db.commit()
    
    return MessageResponse(message="Report element deleted successfully")

# ============================================================================
# REPORT BUILDING AND DATA SOURCES
# ============================================================================

@router.get("/{report_id}/building-context", response_model=ReportBuildingContext)
async def get_report_building_context(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get context data for building/editing a report.
    Returns available data sources, template variables, etc.
    """
    
    report = db.query(Report).options(
        joinedload(Report.template)
    ).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check access
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this report"
        )
    
    # Get incident IDs from report config
    incident_ids = []
    if report.report_config.get("incident_ids"):
        incident_ids = report.report_config["incident_ids"]
    elif report.report_config.get("filters"):
        # For collective reports, we'd need to query incidents based on filters
        # This is a simplified implementation
        pass
    
    # Get available incidents
    available_incidents = await get_available_incidents_for_user(db, current_user)
    
    # Get available data sources
    data_sources = await get_available_data_sources(db, incident_ids)
    
    # Get template variables if template is set
    template_variables = []
    if report.template and report.template.content:
        # Extract Jinja2 variables from template content
        # This is a simplified regex-based extraction
        import re
        variables = re.findall(r'\{\{\s*(\w+)\s*\}\}', report.template.content)
        template_variables = list(set(variables))
    
    # Get available user inputs for the incidents
    available_user_inputs = []
    if incident_ids:
        user_inputs = db.query(PlaybookUserInput).join(PlaybookExecution).filter(
            PlaybookExecution.incident_id.in_(incident_ids)
        ).all()
        
        for input_item in user_inputs:
            available_user_inputs.append({
                "id": input_item.id,
                "execution_id": input_item.execution_id,
                "phase_name": input_item.phase_name,
                "step_name": input_item.step_name,
                "field_name": input_item.field_name,
                "field_type": input_item.field_type,
                "input_label": input_item.input_label,
                "user_input": input_item.user_input,
                "collected_at": input_item.collected_at.isoformat()
            })
    
    # Calculate some basic analytics
    available_analytics = []
    if incident_ids:
        incident_count = len(incident_ids)
        available_analytics.append({
            "metric": "incident_count",
            "value": incident_count,
            "display_name": "Total Incidents",
            "description": f"Total number of incidents in this report"
        })
        
        # Get resolution times
        incidents = db.query(Incident).filter(Incident.id.in_(incident_ids)).all()
        resolution_times = []
        for incident in incidents:
            if incident.resolved_at and incident.created_at:
                delta = incident.resolved_at - incident.created_at
                resolution_times.append(delta.total_seconds() / 3600)  # Convert to hours
        
        if resolution_times:
            avg_resolution_time = sum(resolution_times) / len(resolution_times)
            available_analytics.append({
                "metric": "avg_resolution_time",
                "value": round(avg_resolution_time, 2),
                "display_name": "Average Resolution Time",
                "description": f"Average time to resolve incidents (hours)"
            })
    
    return ReportBuildingContext(
        available_incidents=available_incidents,
        available_user_inputs=available_user_inputs,
        available_analytics=available_analytics,
        template_variables=template_variables,
        data_sources=data_sources
    )

# ============================================================================
# REPORT GENERATION ENDPOINTS
# ============================================================================

@router.post("/{report_id}/generate", response_model=MessageResponse)
async def generate_report(
    report_id: int,
    generation_request: ReportGenerationRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Start report generation process.
    This runs in the background and updates the report status.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check permissions
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to generate this report"
        )
    
    # Check if report is already being generated
    if report.status == ReportStatus.GENERATING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Report is already being generated"
        )
    
    # Update status to generating
    report.status = ReportStatus.GENERATING
    db.commit()
    
    # Start background generation task
    background_tasks.add_task(
        generate_report_background,
        report_id,
        generation_request.export_formats,
        generation_request.force_regenerate
    )
    
    logger.info(f"Report generation started: {report_id} by user {current_user.username}")
    
    return MessageResponse(message="Report generation started")

async def generate_report_background(
    report_id: int, 
    export_formats: List[ReportFormat],
    force_regenerate: bool = False
):
    """
    Background task to generate report content and files.
    """
    
    db = SessionLocal()
    start_time = datetime.utcnow()
    
    try:
        report = db.query(Report).options(
            joinedload(Report.template),
            joinedload(Report.elements)
        ).filter(Report.id == report_id).first()
        
        if not report:
            logger.error(f"Report {report_id} not found during generation")
            return
        
        # Generate report content
        generated_content = await render_report_content(db, report)
        
        # Update report with generated content
        report.generated_content = generated_content
        report.status = ReportStatus.COMPLETED
        report.generated_at = datetime.utcnow()
        report.generation_time_seconds = (datetime.utcnow() - start_time).total_seconds()
        report.available_formats = [fmt.value for fmt in export_formats]
        
        # Generate export files
        exported_files = {}
        for format_type in export_formats:
            file_path = await export_report_to_format(report, format_type, generated_content)
            if file_path:
                exported_files[format_type.value] = file_path
        
        report.exported_files = exported_files
        
        # Calculate file size (total of all exported files)
        total_size = 0
        for file_path in exported_files.values():
            if os.path.exists(file_path):
                total_size += os.path.getsize(file_path)
        report.file_size_bytes = total_size
        
        db.commit()
        
        logger.info(f"Report generation completed: {report_id}")
        
    except Exception as e:
        logger.error(f"Report generation failed for {report_id}: {str(e)}")
        
        # Update report status to failed
        if report:
            report.status = ReportStatus.FAILED
            report.content_metadata = {"error": str(e)}
            db.commit()
    
    finally:
        db.close()

async def render_report_content(db: Session, report: Report) -> str:
    """
    Render the final report content using template and elements.
    """
    
    if not report.template:
        raise ValueError("No template specified for report")
    
    # Get template content
    template_content = report.template.content
    
    # Build template variables from report elements
    template_vars = {}
    
    # Process each element
    for element in report.elements:
        if element.template_variable:
            if element.element_type == "user_input":
                # Extract user input value
                if "value" in element.element_data:
                    template_vars[element.template_variable] = element.element_data["value"]
                elif "user_input" in element.element_data:
                    template_vars[element.template_variable] = element.element_data["user_input"]
            
            elif element.element_type == "analytics":
                # Use computed analytics value
                if "value" in element.element_data:
                    template_vars[element.template_variable] = element.element_data["value"]
            
            elif element.element_type == "static_text":
                # Use static content
                if "content" in element.element_data:
                    template_vars[element.template_variable] = element.element_data["content"]
            
            elif element.element_type == "incident_data":
                # Fetch incident data
                if "incident_id" in element.element_data and "field" in element.element_data:
                    incident = db.query(Incident).filter(
                        Incident.id == element.element_data["incident_id"]
                    ).first()
                    if incident:
                        field_value = getattr(incident, element.element_data["field"], "")
                        template_vars[element.template_variable] = field_value
    
    # Add default variables
    template_vars.update({
        "report_title": report.title,
        "report_description": report.description or "",
        "generated_date": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "report_id": report.id
    })
    
    # Render template using Jinja2
    try:
        from jinja2 import Template
        template = Template(template_content)
        rendered_content = template.render(**template_vars)
        return rendered_content
    except Exception as e:
        logger.error(f"Template rendering failed: {str(e)}")
        raise ValueError(f"Template rendering failed: {str(e)}")

async def export_report_to_format(report: Report, format_type: ReportFormat, content: str) -> Optional[str]:
    """
    Export report content to specified format and return file path.
    """
    
    # Create reports directory if it doesn't exist
    reports_dir = Path("reports/files")
    reports_dir.mkdir(parents=True, exist_ok=True)
    
    base_filename = f"report_{report.id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        if format_type == ReportFormat.MARKDOWN:
            file_path = reports_dir / f"{base_filename}.md"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return str(file_path)
        
        elif format_type == ReportFormat.HTML:
            file_path = reports_dir / f"{base_filename}.html"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            return str(file_path)
        
        elif format_type == ReportFormat.PDF:
            # For PDF generation, you'd typically use a library like weasyprint
            # This is a placeholder implementation
            file_path = reports_dir / f"{base_filename}.pdf"
            
            # Convert HTML content to PDF
            # import weasyprint
            # html_doc = weasyprint.HTML(string=content)
            # html_doc.write_pdf(str(file_path))
            
            # For now, just create a placeholder file
            with open(file_path, "w") as f:
                f.write("PDF generation not implemented yet")
            
            return str(file_path)
    
    except Exception as e:
        logger.error(f"Failed to export report {report.id} to {format_type}: {str(e)}")
        return None

# ============================================================================
# REPORT EXPORT AND DOWNLOAD ENDPOINTS
# ============================================================================

@router.post("/{report_id}/export", response_model=ReportExportResponse)
async def export_report(
    report_id: int,
    export_request: ReportExportRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Export report in specified format and return download URL.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check access
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to export this report"
        )
    
    # Check if report is completed
    if report.status != ReportStatus.COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report is not ready for export"
        )
    
    # Check if requested format is available
    if export_request.format.value not in report.available_formats:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Format {export_request.format.value} not available for this report"
        )
    
    # Get file path
    file_path = report.exported_files.get(export_request.format.value)
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Export file not found"
        )
    
    # Update download count
    report.download_count += 1
    db.commit()
    
    # Generate download URL (this would typically be a signed URL or file serving endpoint)
    download_url = f"/api/v1/reports/{report_id}/download/{export_request.format.value}"
    
    file_size = os.path.getsize(file_path)
    file_name = os.path.basename(file_path)
    
    # Set expiration time
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    return ReportExportResponse(
        download_url=download_url,
        file_name=file_name,
        file_size_bytes=file_size,
        format=export_request.format,
        expires_at=expires_at
    )

@router.get("/{report_id}/download/{format_type}")
async def download_report_file(
    report_id: int,
    format_type: ReportFormat,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Download report file in specified format.
    """
    from fastapi.responses import FileResponse
    
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check access
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to download this report"
        )
    
    # Get file path
    file_path = report.exported_files.get(format_type.value)
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="File not found"
        )
    
    # Determine media type
    media_types = {
        ReportFormat.MARKDOWN: "text/markdown",
        ReportFormat.HTML: "text/html",
        ReportFormat.PDF: "application/pdf"
    }
    
    media_type = media_types.get(format_type, "application/octet-stream")
    filename = os.path.basename(file_path)
    
    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=filename
    )

# ============================================================================
# REPORT SHARING ENDPOINTS
# ============================================================================

@router.post("/{report_id}/share", response_model=ReportShareResponse)
async def share_report(
    report_id: int,
    share_data: ReportShareCreate,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Share a report with another user or create public link.
    Requires Manager role or above.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Validate shared_with_user_id if specified
    if share_data.shared_with_user_id:
        user = db.query(User).filter(User.id == share_data.shared_with_user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User to share with not found"
            )
    
    # Generate public link token if needed
    public_link_token = None
    if share_data.is_public_link:
        import secrets
        public_link_token = secrets.token_urlsafe(32)
    
    # Create share record
    share = ReportShare(
        report_id=report_id,
        shared_with_user_id=share_data.shared_with_user_id,
        shared_with_role=share_data.shared_with_role,
        is_public_link=share_data.is_public_link,
        public_link_token=public_link_token,
        can_view=share_data.can_view,
        can_download=share_data.can_download,
        can_edit=share_data.can_edit,
        expires_at=share_data.expires_at,
        created_by_id=current_user.id
    )
    
    db.add(share)
    db.commit()
    db.refresh(share)
    
    return ReportShareResponse.from_orm(share)

@router.get("/{report_id}/shares", response_model=List[ReportShareResponse])
async def get_report_shares(
    report_id: int,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Get all shares for a report.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    shares = db.query(ReportShare).filter(
        ReportShare.report_id == report_id
    ).all()
    
    return [ReportShareResponse.from_orm(share) for share in shares]

# ============================================================================
# REPORT COMMENTS ENDPOINTS
# ============================================================================

@router.post("/{report_id}/comments", response_model=ReportCommentResponse)
async def add_report_comment(
    report_id: int,
    comment_data: ReportCommentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Add a comment to a report.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check access
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to comment on this report"
        )
    
    # Validate element_id if specified
    if comment_data.element_id:
        element = db.query(ReportElement).filter(
            ReportElement.id == comment_data.element_id,
            ReportElement.report_id == report_id
        ).first()
        if not element:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report element not found"
            )
    
    # Validate parent_comment_id if specified
    if comment_data.parent_comment_id:
        parent_comment = db.query(ReportComment).filter(
            ReportComment.id == comment_data.parent_comment_id,
            ReportComment.report_id == report_id
        ).first()
        if not parent_comment:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Parent comment not found"
            )
    
    # Create comment
    comment = ReportComment(
        report_id=report_id,
        content=comment_data.content,
        element_id=comment_data.element_id,
        parent_comment_id=comment_data.parent_comment_id,
        created_by_id=current_user.id
    )
    
    db.add(comment)
    db.commit()
    db.refresh(comment)
    
    return ReportCommentResponse.from_orm(comment)

@router.get("/{report_id}/comments", response_model=List[ReportCommentResponse])
async def get_report_comments(
    report_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all comments for a report.
    """
    
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check access
    if (current_user.role not in [UserRole.MANAGER, UserRole.ADMIN] and 
        report.created_by_id != current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view comments on this report"
        )
    
    comments = db.query(ReportComment).filter(
        ReportComment.report_id == report_id
    ).order_by(ReportComment.created_at.desc()).all()
    
    return [ReportCommentResponse.from_orm(comment) for comment in comments]

# ============================================================================
# ANALYTICS AND STATISTICS ENDPOINTS
# ============================================================================

@router.get("/stats", response_model=ReportStatsResponse)
async def get_report_statistics(
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Get report statistics and analytics.
    Requires Manager role or above.
    Enhanced with detailed debugging and error handling.
    """
    logger.info(f"Starting report statistics collection for user {current_user.username}")
    
    try:
        print("Starting report statistics collection for user", current_user.username)
        # Initialize response data with defaults
        stats_data = {
            "total_reports": 0,
            "reports_by_type": {},
            "reports_by_status": {},
            "reports_this_month": 0,
            "reports_this_week": 0,
            "avg_generation_time": None,
            "most_used_templates": [],
            "recent_activity": []
        }
        
        # 1. Total reports
        logger.debug("Fetching total reports count...")
        try:
            total_reports = db.query(Report).count()
            stats_data["total_reports"] = total_reports
            logger.info(f"Total reports: {total_reports}")
        except Exception as e:
            logger.error(f"Error getting total reports count: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get total reports count: {str(e)}"
            )
        
        # 2. Reports by type
        logger.debug("Fetching reports by type...")
        try:
            type_counts = db.query(
                Report.report_type, func.count(Report.id)
            ).group_by(Report.report_type).all()
            
            reports_by_type = {str(type_name): count for type_name, count in type_counts}
            stats_data["reports_by_type"] = reports_by_type
            logger.info(f"Reports by type: {reports_by_type}")
        except Exception as e:
            logger.error(f"Error getting reports by type: {str(e)}")
            # Continue with empty dict instead of failing
            stats_data["reports_by_type"] = {}
        
        # 3. Reports by status
        logger.debug("Fetching reports by status...")
        try:
            status_counts = db.query(
                Report.status, func.count(Report.id)
            ).group_by(Report.status).all()
            
            reports_by_status = {str(status_name): count for status_name, count in status_counts}
            stats_data["reports_by_status"] = reports_by_status
            logger.info(f"Reports by status: {reports_by_status}")
        except Exception as e:
            logger.error(f"Error getting reports by status: {str(e)}")
            stats_data["reports_by_status"] = {}
        
        # 4. Reports this month
        logger.debug("Fetching reports this month...")
        try:
            month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            reports_this_month = db.query(Report).filter(
                Report.created_at >= month_start
            ).count()
            stats_data["reports_this_month"] = reports_this_month
            logger.info(f"Reports this month: {reports_this_month}")
        except Exception as e:
            logger.error(f"Error getting reports this month: {str(e)}")
            stats_data["reports_this_month"] = 0
        
        # 5. Reports this week
        logger.debug("Fetching reports this week...")
        try:
            week_start = datetime.utcnow() - timedelta(days=7)
            reports_this_week = db.query(Report).filter(
                Report.created_at >= week_start
            ).count()
            stats_data["reports_this_week"] = reports_this_week
            logger.info(f"Reports this week: {reports_this_week}")
        except Exception as e:
            logger.error(f"Error getting reports this week: {str(e)}")
            stats_data["reports_this_week"] = 0
        
        # 6. Average generation time
        logger.debug("Fetching average generation time...")
        try:
            avg_gen_time = db.query(func.avg(Report.generation_time_seconds)).filter(
                Report.generation_time_seconds.isnot(None)
            ).scalar()
            
            # Handle case where avg_gen_time might be Decimal or None
            if avg_gen_time is not None:
                stats_data["avg_generation_time"] = float(avg_gen_time)
            else:
                stats_data["avg_generation_time"] = None
            logger.info(f"Average generation time: {stats_data['avg_generation_time']}")
        except Exception as e:
            logger.error(f"Error getting average generation time: {str(e)}")
            stats_data["avg_generation_time"] = None
        
        # 7. Most used templates - This is likely where the error occurs
        logger.debug("Fetching most used templates...")
        try:
            # First, check if we have any reports with templates
            reports_with_templates = db.query(Report).filter(
                Report.template_id.isnot(None)
            ).count()
            logger.info(f"Reports with templates: {reports_with_templates}")
            
            if reports_with_templates > 0:
                # Use explicit join condition and handle potential issues
                template_usage_query = db.query(
                    ReportTemplate.name, 
                    func.count(Report.id).label('usage_count')
                ).join(
                    Report, ReportTemplate.id == Report.template_id
                ).group_by(
                    ReportTemplate.id, ReportTemplate.name
                ).order_by(
                    desc('usage_count')
                ).limit(5)
                
                logger.debug(f"Template usage query: {str(template_usage_query)}")
                template_usage = template_usage_query.all()
                
                most_used_templates = [
                    {"template_name": str(name), "usage_count": int(count)}
                    for name, count in template_usage
                ]
                logger.info(f"Most used templates: {most_used_templates}")
            else:
                logger.info("No reports with templates found, using empty list")
                most_used_templates = []
            
            stats_data["most_used_templates"] = most_used_templates
            
        except Exception as e:
            logger.error(f"Error getting most used templates: {str(e)}")
            logger.error(f"Error type: {type(e)}")
            logger.error(f"Error args: {e.args}")
            # Import traceback for full stack trace
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            stats_data["most_used_templates"] = []
        
        # 8. Recent activity - Another potential problem area
        logger.debug("Fetching recent activity...")
        try:
            # Check if we have any reports first
            if total_reports > 0:
                # Use joinedload to properly load the relationship
                from sqlalchemy.orm import joinedload
                
                recent_reports_query = db.query(Report).options(
                    joinedload(Report.created_by)
                ).order_by(desc(Report.created_at)).limit(10)
                
                logger.debug(f"Recent reports query: {str(recent_reports_query)}")
                recent_reports = recent_reports_query.all()
                logger.info(f"Found {len(recent_reports)} recent reports")
                
                recent_activity = []
                for i, report in enumerate(recent_reports):
                    try:
                        # Safely extract username
                        created_by_username = None
                        if hasattr(report, 'created_by') and report.created_by:
                            created_by_username = report.created_by.username
                        
                        activity_item = {
                            "report_id": report.id,
                            "title": str(report.title),
                            "type": str(report.report_type),
                            "status": str(report.status),
                            "created_at": report.created_at.isoformat(),
                            "created_by": created_by_username
                        }
                        recent_activity.append(activity_item)
                        logger.debug(f"Added activity item {i+1}: {activity_item}")
                        
                    except Exception as item_error:
                        logger.error(f"Error processing report {report.id}: {str(item_error)}")
                        # Skip this item and continue
                        continue
                
                logger.info(f"Recent activity: {len(recent_activity)} items")
            else:
                logger.info("No reports found, using empty recent activity")
                recent_activity = []
            
            stats_data["recent_activity"] = recent_activity
            
        except Exception as e:
            logger.error(f"Error getting recent activity: {str(e)}")
            logger.error(f"Error type: {type(e)}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            stats_data["recent_activity"] = []
        
        # 9. Create and validate the response
        logger.debug("Creating ReportStatsResponse...")
        try:
            response = ReportStatsResponse(
                total_reports=stats_data["total_reports"],
                reports_by_type=stats_data["reports_by_type"],
                reports_by_status=stats_data["reports_by_status"],
                reports_this_month=stats_data["reports_this_month"],
                reports_this_week=stats_data["reports_this_week"],
                avg_generation_time=stats_data["avg_generation_time"],
                most_used_templates=stats_data["most_used_templates"],
                recent_activity=stats_data["recent_activity"]
            )
            logger.info("Successfully created ReportStatsResponse")
            return response
            
        except Exception as e:
            logger.error(f"Error creating ReportStatsResponse: {str(e)}")
            logger.error(f"Stats data: {stats_data}")
            # Try to identify which field is causing the validation error
            for field_name, field_value in stats_data.items():
                try:
                    logger.debug(f"Field {field_name}: {type(field_value)} = {field_value}")
                except Exception as field_error:
                    logger.error(f"Error logging field {field_name}: {str(field_error)}")
            
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to create response: {str(e)}"
            )
    
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Unexpected error in get_report_statistics: {str(e)}")
        logger.error(f"Error type: {type(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve report statistics: {str(e)}"
        )

# ============================================================================
# BULK OPERATIONS ENDPOINTS
# ============================================================================

@router.post("/bulk-operation", response_model=BulkReportOperationResponse)
async def bulk_report_operation(
    operation_data: BulkReportOperation,
    current_user: User = Depends(require_manager_or_above),
    db: Session = Depends(get_db)
):
    """
    Perform bulk operations on multiple reports.
    Requires Manager role or above.
    """
    
    # Get reports
    reports = db.query(Report).filter(
        Report.id.in_(operation_data.report_ids)
    ).all()
    
    if len(reports) != len(operation_data.report_ids):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Some reports not found"
        )
    
    processed_count = 0
    failed_count = 0
    errors = []
    results = {}
    
    for report in reports:
        try:
            if operation_data.operation == "delete":
                db.delete(report)
                processed_count += 1
            
            elif operation_data.operation == "archive":
                report.status = ReportStatus.ARCHIVED
                processed_count += 1
            
            elif operation_data.operation == "export":
                # Add to export queue or process immediately
                # This would typically be a background task
                results[str(report.id)] = "queued_for_export"
                processed_count += 1
            
            elif operation_data.operation == "share":
                # Bulk sharing logic would go here
                processed_count += 1
            
        except Exception as e:
            failed_count += 1
            errors.append(f"Report {report.id}: {str(e)}")
    
    if operation_data.operation in ["delete", "archive"]:
        db.commit()
    
    return BulkReportOperationResponse(
        success=failed_count == 0,
        processed_count=processed_count,
        failed_count=failed_count,
        errors=errors,
        results=results
    )