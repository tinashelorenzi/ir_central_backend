"""
Incident Flow Model
Tracks the execution flow and state of an incident response procedure
"""

from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON, ForeignKey, Float
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import uuid
from enum import Enum

from database import Base

class IncidentFlowStatus(str, Enum):
    """Status of incident flow execution"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    WAITING_INPUT = "waiting_input"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class StepStatus(str, Enum):
    """Status of individual steps"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WAITING_INPUT = "waiting_input"
    WAITING_APPROVAL = "waiting_approval"

class StepType(str, Enum):
    """Types of steps in the incident flow"""
    MANUAL_ACTION = "manual_action"
    USER_INPUT = "user_input"
    AUTOMATION = "automation"
    DECISION_POINT = "decision_point"
    APPROVAL = "approval"
    EVIDENCE_COLLECTION = "evidence_collection"
    NOTIFICATION = "notification"
    DOCUMENTATION = "documentation"

class IncidentFlow(Base):
    """
    Main incident flow tracking the execution of an IR procedure for a specific incident.
    This represents the runtime instance of a playbook execution.
    """
    __tablename__ = "incident_flows"
    
    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(String(50), unique=True, index=True)  # FLOW-2025-001
    
    # === REFERENCES ===
    incident_id = Column(String(50), index=True)  # Reference to incident
    playbook_execution_id = Column(Integer, ForeignKey("playbook_executions.id"), nullable=True)
    playbook_id = Column(Integer, ForeignKey("ir_playbooks.id"))
    alert_id = Column(Integer, nullable=True)  # Original alert that triggered this
    
    # === ASSIGNMENT ===
    assigned_analyst_id = Column(Integer, ForeignKey("users.id"))
    lead_analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    team_members = Column(JSON, default=list)  # List of user IDs involved
    
    # === EXECUTION STATUS ===
    status = Column(String(20), default=IncidentFlowStatus.PENDING, index=True)
    current_phase = Column(String(100), nullable=True)
    current_step_index = Column(Integer, default=0)
    current_step_name = Column(String(100), nullable=True)
    
    # === PROGRESS TRACKING ===
    total_phases = Column(Integer, default=0)
    completed_phases = Column(Integer, default=0)
    total_steps = Column(Integer, default=0)
    completed_steps = Column(Integer, default=0)
    failed_steps = Column(Integer, default=0)
    skipped_steps = Column(Integer, default=0)
    progress_percentage = Column(Float, default=0.0)
    
    # === TIMING ===
    started_at = Column(DateTime, default=datetime.utcnow)
    last_activity_at = Column(DateTime, default=datetime.utcnow)
    paused_at = Column(DateTime, nullable=True)
    resumed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    estimated_completion = Column(DateTime, nullable=True)
    
    # Time tracking
    total_pause_duration = Column(Integer, default=0)  # minutes
    actual_duration = Column(Integer, nullable=True)  # minutes
    
    # === PLAYBOOK DEFINITION SNAPSHOT ===
    # Store snapshot of playbook at execution time to handle version changes
    playbook_snapshot = Column(JSON)  # Complete playbook definition at execution time
    
    # === EXECUTION STATE ===
    execution_variables = Column(JSON, default=dict)  # Variables collected during execution
    collected_evidence = Column(JSON, default=list)  # Evidence artifacts
    notifications_sent = Column(JSON, default=list)  # Track notifications
    decisions_made = Column(JSON, default=dict)  # Decision points and outcomes
    
    # === RESULTS ===
    incident_contained = Column(Boolean, default=False)
    root_cause_identified = Column(Boolean, default=False)
    threat_eradicated = Column(Boolean, default=False)
    systems_recovered = Column(Boolean, default=False)
    lessons_learned = Column(Text, nullable=True)
    
    # Summary and outcomes
    executive_summary = Column(Text, nullable=True)
    technical_summary = Column(Text, nullable=True)
    business_impact = Column(Text, nullable=True)
    remediation_actions = Column(JSON, default=list)
    
    # === METRICS ===
    time_to_containment = Column(Integer, nullable=True)  # minutes
    time_to_eradication = Column(Integer, nullable=True)  # minutes
    time_to_recovery = Column(Integer, nullable=True)  # minutes
    
    # Quality scores
    procedure_compliance_score = Column(Float, nullable=True)  # 0-100
    response_effectiveness_score = Column(Float, nullable=True)  # 0-100
    
    # === METADATA ===
    created_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Tags for categorization
    tags = Column(JSON, default=list)
    
    # Custom fields
    custom_fields = Column(JSON, default=dict)
    
    # === RELATIONSHIPS ===
    assigned_analyst = relationship("User", foreign_keys=[assigned_analyst_id], back_populates="assigned_flows")
    lead_analyst = relationship("User", foreign_keys=[lead_analyst_id], back_populates="lead_flows")
    created_by = relationship("User", foreign_keys=[created_by_id], back_populates="created_flows")
    playbook = relationship("IRPlaybook", foreign_keys=[playbook_id])
    playbook_execution = relationship("PlaybookExecution", foreign_keys=[playbook_execution_id])
    
    # Flow steps
    steps = relationship("IncidentFlowStep", back_populates="flow", cascade="all, delete-orphan")
    user_inputs = relationship("IncidentFlowUserInput", back_populates="flow", cascade="all, delete-orphan")
    artifacts = relationship("IncidentFlowArtifact", back_populates="flow", cascade="all, delete-orphan")
    
    def __init__(self, **kwargs):
        """Initialize with auto-generated flow ID"""
        super().__init__(**kwargs)
        if not self.flow_id:
            # Generate flow ID like FLOW-2025-001
            year = datetime.now().year
            self.flow_id = f"FLOW-{year}-{str(uuid.uuid4())[:8].upper()}"
    
    @property
    def is_active(self) -> bool:
        """Check if flow is currently active"""
        return self.status in [IncidentFlowStatus.IN_PROGRESS, IncidentFlowStatus.WAITING_INPUT]
    
    @property
    def is_completed(self) -> bool:
        """Check if flow is completed"""
        return self.status == IncidentFlowStatus.COMPLETED
    
    @property
    def current_step(self) -> 'IncidentFlowStep':
        """Get the current step being executed"""
        if self.current_step_name:
            return next((step for step in self.steps 
                        if step.step_name == self.current_step_name), None)
        return None
    
    def update_progress(self):
        """Calculate and update progress percentage"""
        if self.total_steps > 0:
            self.progress_percentage = (self.completed_steps / self.total_steps) * 100
        else:
            self.progress_percentage = 0.0
    
    def __repr__(self):
        return f"<IncidentFlow(flow_id='{self.flow_id}', status='{self.status}', progress={self.progress_percentage:.1f}%)>"

class IncidentFlowStep(Base):
    """
    Individual step execution within an incident flow.
    Records the execution state and results of each step.
    """
    __tablename__ = "incident_flow_steps"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # === REFERENCES ===
    flow_id = Column(Integer, ForeignKey("incident_flows.id"))
    flow = relationship("IncidentFlow", back_populates="steps")
    
    # === STEP IDENTIFICATION ===
    phase_name = Column(String(100), index=True)
    step_name = Column(String(100), index=True)
    step_index = Column(Integer)  # Position within phase
    global_step_index = Column(Integer)  # Position within entire flow
    step_type = Column(String(30), default=StepType.MANUAL_ACTION)
    
    # === STEP DEFINITION ===
    title = Column(String(200))
    description = Column(Text)
    instructions = Column(Text, nullable=True)
    expected_duration = Column(Integer, nullable=True)  # minutes
    
    # Input requirements
    input_schema = Column(JSON, nullable=True)  # Define required inputs
    validation_rules = Column(JSON, nullable=True)
    
    # Dependencies
    depends_on_steps = Column(JSON, default=list)  # List of step names this depends on
    
    # === EXECUTION STATUS ===
    status = Column(String(20), default=StepStatus.PENDING, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    last_updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # === ASSIGNMENT ===
    assigned_to_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    executed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # === RESULTS ===
    success = Column(Boolean, nullable=True)
    output_data = Column(JSON, default=dict)  # Step outputs and collected data
    error_message = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    
    # === AUTOMATION ===
    is_automated = Column(Boolean, default=False)
    automation_script = Column(Text, nullable=True)
    automation_result = Column(JSON, nullable=True)
    
    # === APPROVALS ===
    requires_approval = Column(Boolean, default=False)
    approved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_notes = Column(Text, nullable=True)
    
    # === EVIDENCE ===
    evidence_collected = Column(JSON, default=list)  # List of evidence items
    screenshots = Column(JSON, default=list)  # Screenshot URLs/paths
    
    # === TIMING ===
    actual_duration = Column(Integer, nullable=True)  # minutes
    pause_duration = Column(Integer, default=0)  # minutes
    
    # === RELATIONSHIPS ===
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    executed_by = relationship("User", foreign_keys=[executed_by_id])
    approved_by = relationship("User", foreign_keys=[approved_by_id])
    
    @property
    def is_blocking(self) -> bool:
        """Check if this step is blocking progress"""
        return self.status in [StepStatus.WAITING_INPUT, StepStatus.WAITING_APPROVAL, StepStatus.FAILED]
    
    @property
    def can_execute(self) -> bool:
        """Check if step can be executed (dependencies met)"""
        if not self.depends_on_steps:
            return True
        
        # Check if all dependencies are completed
        completed_deps = [step for step in self.flow.steps 
                         if step.step_name in self.depends_on_steps 
                         and step.status == StepStatus.COMPLETED]
        return len(completed_deps) == len(self.depends_on_steps)
    
    def __repr__(self):
        return f"<IncidentFlowStep(step_name='{self.step_name}', status='{self.status}', success={self.success})>"

class IncidentFlowUserInput(Base):
    """
    User inputs collected during incident flow execution.
    Captures all data provided by analysts during the procedure.
    """
    __tablename__ = "incident_flow_user_inputs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # === REFERENCES ===
    flow_id = Column(Integer, ForeignKey("incident_flows.id"))
    flow = relationship("IncidentFlow", back_populates="user_inputs")
    step_id = Column(Integer, ForeignKey("incident_flow_steps.id"), nullable=True)
    
    # === INPUT IDENTIFICATION ===
    phase_name = Column(String(100))
    step_name = Column(String(100))
    field_name = Column(String(100))
    field_type = Column(String(30))  # text, textarea, select, checkbox, file, etc.
    
    # === INPUT DEFINITION ===
    label = Column(String(200))
    description = Column(Text, nullable=True)
    placeholder = Column(String(200), nullable=True)
    is_required = Column(Boolean, default=False)
    is_sensitive = Column(Boolean, default=False)  # PII, passwords, etc.
    
    # Validation
    validation_rules = Column(JSON, nullable=True)
    options = Column(JSON, nullable=True)  # For select/radio inputs
    
    # === INPUT DATA ===
    raw_value = Column(Text, nullable=True)  # Raw input as string
    parsed_value = Column(JSON, nullable=True)  # Parsed/structured value
    file_paths = Column(JSON, default=list)  # For file uploads
    
    # === VALIDATION ===
    is_valid = Column(Boolean, default=True)
    validation_errors = Column(JSON, default=list)
    
    # === METADATA ===
    collected_by_id = Column(Integer, ForeignKey("users.id"))
    collected_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # === RELATIONSHIPS ===
    collected_by = relationship("User", foreign_keys=[collected_by_id])
    step = relationship("IncidentFlowStep", foreign_keys=[step_id])
    
    def __repr__(self):
        return f"<IncidentFlowUserInput(field_name='{self.field_name}', valid={self.is_valid})>"

class IncidentFlowArtifact(Base):
    """
    Artifacts and evidence collected during incident flow execution.
    Includes files, screenshots, logs, and other evidence.
    """
    __tablename__ = "incident_flow_artifacts"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # === REFERENCES ===
    flow_id = Column(Integer, ForeignKey("incident_flows.id"))
    flow = relationship("IncidentFlow", back_populates="artifacts")
    step_id = Column(Integer, ForeignKey("incident_flow_steps.id"), nullable=True)
    
    # === ARTIFACT IDENTIFICATION ===
    artifact_type = Column(String(50))  # screenshot, log_file, pcap, memory_dump, etc.
    name = Column(String(200))
    description = Column(Text, nullable=True)
    
    # === FILE INFORMATION ===
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)  # bytes
    file_hash = Column(String(64), nullable=True)  # SHA256
    mime_type = Column(String(100), nullable=True)
    
    # === EVIDENCE CHAIN ===
    collected_from = Column(String(200), nullable=True)  # Source system/location
    collection_method = Column(String(100), nullable=True)
    chain_of_custody = Column(JSON, default=list)  # Who handled it when
    
    # === METADATA ===
    collected_by_id = Column(Integer, ForeignKey("users.id"))
    collected_at = Column(DateTime, default=datetime.utcnow)
    is_critical = Column(Boolean, default=False)
    is_sensitive = Column(Boolean, default=False)
    retention_period = Column(Integer, nullable=True)  # days
    
    # Tags and categorization
    tags = Column(JSON, default=list)
    
    # === RELATIONSHIPS ===
    collected_by = relationship("User", foreign_keys=[collected_by_id])
    step = relationship("IncidentFlowStep", foreign_keys=[step_id])
    
    def __repr__(self):
        return f"<IncidentFlowArtifact(name='{self.name}', type='{self.artifact_type}')>"