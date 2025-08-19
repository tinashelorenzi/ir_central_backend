# models/incident.py

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON, Float, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
import uuid
from typing import Dict, List, Any, Optional

# Import Base from database.py
from database import Base

class IncidentSeverity(str, enum.Enum):
    """Incident severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class IncidentStatus(str, enum.Enum):
    """Incident status during investigation"""
    NEW = "new"                         # Just created from alert ownership
    ASSIGNED = "assigned"               # Assigned to analyst
    INVESTIGATING = "investigating"     # Active investigation
    CONTAINED = "contained"             # Threat contained
    ERADICATING = "eradicating"        # Removing threat
    RECOVERING = "recovering"           # System recovery
    LESSONS_LEARNED = "lessons_learned" # Post-incident analysis
    CLOSED = "closed"                   # Incident closed

class IncidentPriority(str, enum.Enum):
    """Business priority levels"""
    P1 = "p1"  # Critical - Immediate response required
    P2 = "p2"  # High - Response within 2 hours
    P3 = "p3"  # Medium - Response within 8 hours
    P4 = "p4"  # Low - Response within 24 hours

class IncidentCategory(str, enum.Enum):
    """Incident categories based on NIST"""
    MALWARE = "malware"
    DOS = "denial_of_service"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    INAPPROPRIATE_USAGE = "inappropriate_usage"
    MULTIPLE = "multiple"
    UNKNOWN = "unknown"

class Incident(Base):
    """Security incidents created from alert ownership"""
    __tablename__ = "incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # === BASIC INCIDENT INFORMATION ===
    incident_id = Column(String(50), unique=True, nullable=False, index=True)  # INC-2024-001
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    
    # Classification
    severity = Column(String(20), nullable=False, default=IncidentSeverity.MEDIUM)
    priority = Column(String(10), nullable=False, default=IncidentPriority.P3)
    status = Column(String(20), nullable=False, default=IncidentStatus.NEW)
    category = Column(String(50), nullable=False, default=IncidentCategory.UNKNOWN)
    
    # === OWNERSHIP AND ASSIGNMENT ===
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)  # Who took ownership
    assigned_analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Primary analyst
    assigned_team = Column(String(100), nullable=True)  # Team responsible
    escalated_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Escalation chain
    
    # === TIMING INFORMATION ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    first_response_at = Column(DateTime, nullable=True)
    contained_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    
    # SLA tracking
    response_sla_deadline = Column(DateTime, nullable=True)
    resolution_sla_deadline = Column(DateTime, nullable=True)
    sla_breached = Column(Boolean, default=False)
    
    # === INCIDENT DETAILS ===
    # Related alerts (stored as JSON list of alert IDs)
    alert_ids = Column(JSON, default=list)  # [1, 2, 3, ...]
    
    # Affected systems and assets
    affected_systems = Column(JSON, default=list)  # ["server1.corp.com", "workstation-123"]
    affected_users = Column(JSON, default=list)    # ["john.doe", "jane.smith"]
    affected_services = Column(JSON, default=list) # ["email", "file_server", "database"]
    
    # Technical details
    attack_vectors = Column(JSON, default=list)    # ["email", "usb", "network"]
    indicators_of_compromise = Column(JSON, default=list)  # IOCs found
    
    # === INVESTIGATION DATA ===
    investigation_summary = Column(Text, nullable=True)
    investigation_notes = Column(Text, nullable=True)
    
    # Evidence and artifacts
    evidence_collected = Column(JSON, default=list)  # Paths to evidence files
    forensic_data = Column(JSON, default=dict)       # Forensic analysis results
    
    # Timeline of events
    incident_timeline = Column(JSON, default=list)   # Chronological events
    # Example timeline structure:
    # [
    #   {
    #     "timestamp": "2024-01-15T10:30:00Z",
    #     "event": "Initial compromise detected",
    #     "source": "EDR Alert",
    #     "details": "Suspicious process execution on workstation-123"
    #   }
    # ]
    
    # === IMPACT ASSESSMENT ===
    business_impact = Column(String(20), nullable=True)  # low, medium, high, critical
    estimated_financial_loss = Column(Float, nullable=True)
    data_compromised = Column(Boolean, default=False)
    data_types_affected = Column(JSON, default=list)     # ["PII", "financial", "proprietary"]
    systems_compromised = Column(Integer, default=0)      # Number of systems affected
    users_affected = Column(Integer, default=0)           # Number of users affected
    
    # === CONTAINMENT AND RESPONSE ===
    containment_strategy = Column(Text, nullable=True)
    containment_actions = Column(JSON, default=list)     # Actions taken to contain
    eradication_actions = Column(JSON, default=list)     # Actions to remove threat
    recovery_actions = Column(JSON, default=list)        # Actions to restore services
    
    # Playbook execution
    playbook_execution_id = Column(Integer, ForeignKey("playbook_executions.id"), nullable=True)
    automated_actions = Column(JSON, default=list)       # Automated response actions
    
    # === COMMUNICATION AND REPORTING ===
    internal_notifications = Column(JSON, default=list)   # Who was notified internally
    external_notifications = Column(JSON, default=list)   # External notifications (customers, authorities)
    
    # Compliance and regulatory
    requires_external_reporting = Column(Boolean, default=False)
    external_reporting_deadline = Column(DateTime, nullable=True)
    reported_to_authorities = Column(Boolean, default=False)
    compliance_requirements = Column(JSON, default=list)  # ["GDPR", "SOX", "HIPAA"]
    
    # === LESSONS LEARNED ===
    lessons_learned = Column(Text, nullable=True)
    recommendations = Column(JSON, default=list)          # Improvement recommendations
    follow_up_actions = Column(JSON, default=list)        # Actions to prevent recurrence
    
    # Post-incident review
    post_incident_review_completed = Column(Boolean, default=False)
    post_incident_review_notes = Column(Text, nullable=True)
    post_incident_review_date = Column(DateTime, nullable=True)
    
    # === METADATA ===
    correlation_id = Column(String(100), nullable=True)   # Link to related incidents
    parent_incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)
    
    # Tags for categorization and search
    tags = Column(JSON, default=list)                     # ["ransomware", "targeted_attack"]
    
    # Custom fields for organization-specific needs
    custom_fields = Column(JSON, default=dict)
    
    # === RELATIONSHIPS ===
    owner = relationship("User", foreign_keys=[owner_id], back_populates="owned_incidents")
    assigned_analyst = relationship("User", foreign_keys=[assigned_analyst_id], back_populates="assigned_incidents")
    escalated_to = relationship("User", foreign_keys=[escalated_to_id])
    
    # Playbook execution relationship
    playbook_execution = relationship("PlaybookExecution", back_populates="incident")
    
    # Self-referential relationship for parent incidents
    child_incidents = relationship("Incident", backref="parent_incident", remote_side=[id])
    
    def __init__(self, **kwargs):
        """Initialize incident with auto-generated ID"""
        super().__init__(**kwargs)
        if not self.incident_id:
            # Generate incident ID like INC-2024-001
            year = datetime.now().year
            # This should ideally be atomic and use a sequence
            self.incident_id = f"INC-{year}-{str(uuid.uuid4())[:8].upper()}"
    
    @property
    def time_to_first_response(self) -> Optional[float]:
        """Calculate time to first response in minutes"""
        if self.first_response_at and self.created_at:
            delta = self.first_response_at - self.created_at
            return delta.total_seconds() / 60
        return None
    
    @property
    def time_to_containment(self) -> Optional[float]:
        """Calculate time to containment in minutes"""
        if self.contained_at and self.created_at:
            delta = self.contained_at - self.created_at
            return delta.total_seconds() / 60
        return None
    
    @property
    def time_to_resolution(self) -> Optional[float]:
        """Calculate time to resolution in minutes"""
        if self.resolved_at and self.created_at:
            delta = self.resolved_at - self.created_at
            return delta.total_seconds() / 60
        return None
    
    @property
    def is_sla_breached(self) -> bool:
        """Check if any SLA has been breached"""
        now = datetime.utcnow()
        
        # Check response SLA
        if self.response_sla_deadline and not self.first_response_at:
            if now > self.response_sla_deadline:
                return True
        
        # Check resolution SLA
        if self.resolution_sla_deadline and not self.resolved_at:
            if now > self.resolution_sla_deadline:
                return True
        
        return self.sla_breached
    
    @property
    def alert_count(self) -> int:
        """Get count of related alerts"""
        return len(self.alert_ids) if self.alert_ids else 0
    
    def add_alert(self, alert_id: int):
        """Add an alert to this incident"""
        if self.alert_ids is None:
            self.alert_ids = []
        if alert_id not in self.alert_ids:
            self.alert_ids.append(alert_id)
    
    def remove_alert(self, alert_id: int):
        """Remove an alert from this incident"""
        if self.alert_ids and alert_id in self.alert_ids:
            self.alert_ids.remove(alert_id)
    
    def add_timeline_event(self, event: str, source: str, details: str = None):
        """Add an event to the incident timeline"""
        if self.incident_timeline is None:
            self.incident_timeline = []
        
        timeline_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "source": source,
            "details": details
        }
        self.incident_timeline.append(timeline_event)
    
    def update_status(self, new_status: IncidentStatus, user_id: int, notes: str = None):
        """Update incident status with timeline tracking"""
        old_status = self.status
        self.status = new_status
        self.updated_at = datetime.utcnow()
        
        # Add to timeline
        event_details = f"Status changed from {old_status} to {new_status}"
        if notes:
            event_details += f". Notes: {notes}"
        
        self.add_timeline_event(
            event=f"Status changed to {new_status}",
            source=f"User {user_id}",
            details=event_details
        )
        
        # Update timing fields based on status
        if new_status == IncidentStatus.INVESTIGATING and not self.first_response_at:
            self.first_response_at = datetime.utcnow()
        elif new_status == IncidentStatus.CONTAINED and not self.contained_at:
            self.contained_at = datetime.utcnow()
        elif new_status == IncidentStatus.CLOSED and not self.closed_at:
            self.closed_at = datetime.utcnow()
            if not self.resolved_at:
                self.resolved_at = datetime.utcnow()


class IncidentNote(Base):
    """Notes and updates on incidents"""
    __tablename__ = "incident_notes"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    note_type = Column(String(20), default="general")  # general, investigation, containment, etc.
    content = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=True)  # Internal vs external communication
    
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    incident = relationship("Incident", backref="notes")
    user = relationship("User", backref="incident_notes")


class IncidentArtifact(Base):
    """Files and evidence associated with incidents"""
    __tablename__ = "incident_artifacts"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    
    # File information
    filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=True)
    file_type = Column(String(50), nullable=True)
    
    # Hashes for integrity
    file_hash_md5 = Column(String(32), nullable=True)
    file_hash_sha1 = Column(String(40), nullable=True)
    file_hash_sha256 = Column(String(64), nullable=True)
    
    # Artifact metadata
    artifact_type = Column(String(50), nullable=False)  # evidence, screenshot, log, report
    description = Column(Text, nullable=True)
    
    # Chain of custody
    collected_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    collected_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    chain_of_custody = Column(JSON, default=list)  # Track who handled the evidence
    
    # Relationships
    incident = relationship("Incident", backref="artifacts")
    collected_by = relationship("User", backref="collected_artifacts")
