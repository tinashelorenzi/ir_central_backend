from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from typing import Dict, List, Any, Optional

# Import Base from database.py instead of creating a new one
from database import Base

# Remove this import - it causes circular import issues
# from models.users import User

class PlaybookStatus(str, enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"

class StepType(str, enum.Enum):
    """Types of steps that can be defined in a playbook"""
    AUTOMATED_ACTION = "automated_action"     # Run script/API call automatically
    MANUAL_ACTION = "manual_action"          # Human performs task, marks complete
    USER_INPUT = "user_input"                # Collect data from responder
    APPROVAL = "approval"                    # Requires manager/senior approval
    NOTIFICATION = "notification"            # Send alerts to stakeholders
    ARTIFACT_COLLECTION = "artifact_collection"  # Gather evidence
    ANALYSIS = "analysis"                    # Review collected data
    DECISION_POINT = "decision_point"        # Branching logic based on conditions
    REPORT_GENERATION = "report_generation"  # Generate section of final report

class InputFieldType(str, enum.Enum):
    """Types of input fields for user data collection"""
    TEXT = "text"
    TEXTAREA = "textarea" 
    NUMBER = "number"
    DATE = "date"
    DATETIME = "datetime"
    SELECT = "select"
    MULTISELECT = "multiselect"
    CHECKBOX = "checkbox"
    FILE_UPLOAD = "file_upload"
    IP_ADDRESS = "ip_address"
    URL = "url"
    EMAIL = "email"

class IRPlaybook(Base):
    """Flexible, JSON-defined incident response playbooks"""
    __tablename__ = "ir_playbooks"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Basic metadata
    name = Column(String(200), unique=True, nullable=False)
    description = Column(Text)
    version = Column(String(20), default="1.0")
    status = Column(String(20), default=PlaybookStatus.DRAFT)
    
    # Tagging system for alert matching
    tags = Column(JSON, default=list)  # ["malware", "phishing", "lateral_movement"]
    severity_levels = Column(JSON, default=list)  # ["high", "critical"] 
    alert_sources = Column(JSON, default=list)  # ["snort", "yara", "graylog"]
    
    # Matching criteria for auto-assignment
    matching_criteria = Column(JSON, default=dict)
    # Example: {
    #   "alert_title_contains": ["malware", "trojan"],
    #   "source_ip_ranges": ["192.168.1.0/24"],
    #   "threat_types": ["malware_detected", "suspicious_file"],
    #   "confidence_threshold": 0.8
    # }
    
    # Playbook definition (the flexible JSON structure)
    playbook_definition = Column(JSON, nullable=False)
    # Complete playbook structure defined in JSON format
    
    # Report template in markdown
    report_template = Column(Text, nullable=True)
    # Markdown template with placeholders for dynamic data
    
    # Metadata
    estimated_duration_minutes = Column(Integer, default=60)
    requires_approval = Column(Boolean, default=False)
    auto_assign = Column(Boolean, default=True)
    priority_score = Column(Integer, default=5)  # 1-10, higher = more specific match
    
    # Audit fields
    created_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)
    
    # Relationships - Use string references to avoid circular imports
    created_by = relationship("User", foreign_keys=[created_by_id])
    executions = relationship("PlaybookExecution", back_populates="playbook")
    
    def __repr__(self):
        return f"<IRPlaybook(name='{self.name}', version='{self.version}', status='{self.status}')>"

class PlaybookExecution(Base):
    """Instance of a playbook being executed for a specific incident"""
    __tablename__ = "playbook_executions"
    
    id = Column(Integer, primary_key=True, index=True)
    execution_id = Column(String(50), unique=True, index=True)  # EXEC-2025-001
    
    # References
    playbook_id = Column(Integer, ForeignKey("ir_playbooks.id"))
    incident_id = Column(String(50), nullable=True)  # Link to incident system
    
    # Assignment
    assigned_analyst_id = Column(Integer, ForeignKey("users.id"))
    
    # Execution status
    status = Column(String(20), default="pending")  # pending, in_progress, completed, failed, cancelled
    current_phase = Column(String(100), nullable=True)
    current_step = Column(String(100), nullable=True)
    
    # Progress tracking
    total_steps = Column(Integer, default=0)
    completed_steps = Column(Integer, default=0)
    failed_steps = Column(Integer, default=0)
    skipped_steps = Column(Integer, default=0)
    
    # Timing
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    estimated_completion = Column(DateTime, nullable=True)
    
    # Results
    final_status = Column(String(50), nullable=True)  # success, partial_success, failure
    final_report = Column(Text, nullable=True)  # Generated markdown report
    
    # Execution context
    execution_context = Column(JSON, default=dict)  # Variables and state during execution
    
    # Relationships
    playbook = relationship("IRPlaybook", back_populates="executions")
    assigned_analyst = relationship("User", foreign_keys=[assigned_analyst_id])
    step_logs = relationship("StepExecutionLog", back_populates="execution")
    user_inputs = relationship("PlaybookUserInput", back_populates="execution")
    incident = relationship("Incident", back_populates="playbook_execution")

class StepExecutionLog(Base):
    """Log of individual step executions within a playbook"""
    __tablename__ = "step_execution_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    execution_id = Column(Integer, ForeignKey("playbook_executions.id"))
    execution = relationship("PlaybookExecution", back_populates="step_logs")
    
    # Step identification
    phase_name = Column(String(100))
    step_name = Column(String(100))
    step_type = Column(String(30))
    step_index = Column(Integer)
    
    # Execution details
    status = Column(String(20))  # pending, in_progress, completed, failed, skipped
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    # Results
    success = Column(Boolean, nullable=True)
    output_data = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    
    # User interaction
    executed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    executed_by = relationship("User", foreign_keys=[executed_by_id])
    requires_manual_action = Column(Boolean, default=False)
    
    # Automation details
    automation_command = Column(Text, nullable=True)
    automation_result = Column(JSON, nullable=True)

class PlaybookUserInput(Base):
    """Capture user inputs during playbook execution"""
    __tablename__ = "playbook_user_inputs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    execution_id = Column(Integer, ForeignKey("playbook_executions.id"))
    execution = relationship("PlaybookExecution", back_populates="user_inputs")
    
    # Input identification
    phase_name = Column(String(100))
    step_name = Column(String(100))
    field_name = Column(String(100))  # Name of the input field
    field_type = Column(String(20))   # Type of input (text, select, etc.)
    
    # Input data
    user_input = Column(JSON)  # The actual data provided by user
    input_label = Column(String(200))  # Human-readable label
    is_required = Column(Boolean, default=False)
    
    # Metadata
    collected_by_id = Column(Integer, ForeignKey("users.id"))
    collected_by = relationship("User", foreign_keys=[collected_by_id])
    collected_at = Column(DateTime, default=datetime.utcnow)
    
    # Validation
    is_valid = Column(Boolean, default=True)
    validation_error = Column(String(500), nullable=True)

class PlaybookTemplate(Base):
    """Predefined templates for common playbook patterns"""
    __tablename__ = "playbook_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    
    name = Column(String(200), unique=True)
    category = Column(String(100))  # malware_response, data_breach, phishing, etc.
    description = Column(Text)
    
    # Template structure
    template_definition = Column(JSON)  # Base playbook structure to copy
    default_tags = Column(JSON, default=list)
    default_severity_levels = Column(JSON, default=list)
    
    # Usage tracking
    usage_count = Column(Integer, default=0)
    
    # Metadata
    created_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    created_by = relationship("User", foreign_keys=[created_by_id])