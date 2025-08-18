from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from typing import Dict, List, Any, Optional

Base = declarative_base()

# Import User model for relationships
from models.users import User

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
    
    # Relationships
    created_by = relationship("User")
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
    alert_id = Column(Integer, ForeignKey("alerts.id"))
    incident_id = Column(String(50))  # Links to main incident
    
    # Execution state
    current_phase = Column(String(100))  # Which phase we're currently in
    current_step_index = Column(Integer, default=0)
    execution_status = Column(String(20), default="in_progress")  # in_progress, completed, failed, paused
    
    # Dynamic execution data - this grows as playbook runs
    execution_data = Column(JSON, default=dict)
    # Example structure:
    # {
    #   "phases": {
    #     "containment": {
    #       "status": "completed",
    #       "steps": {
    #         "isolate_host": {"status": "completed", "output": "Host isolated successfully"},
    #         "collect_memory": {"status": "completed", "file_path": "/artifacts/memory_dump.mem"}
    #       }
    #     },
    #     "analysis": {
    #       "status": "in_progress",
    #       "steps": {
    #         "analyze_malware": {"status": "pending"}
    #       }
    #     }
    #   },
    #   "user_inputs": {
    #     "affected_systems": ["SERVER-01", "WORKSTATION-05"],
    #     "business_impact": "High - production database affected"
    #   },
    #   "artifacts_collected": [
    #     {"type": "memory_dump", "path": "/artifacts/memory_001.mem", "hash": "sha256..."},
    #     {"type": "network_capture", "path": "/artifacts/traffic.pcap", "size": 1024000}
    #   ]
    # }
    
    # Progress tracking
    total_steps = Column(Integer)
    completed_steps = Column(Integer, default=0)
    progress_percentage = Column(Float, default=0.0)
    
    # Assignment
    assigned_analyst_id = Column(Integer, ForeignKey("users.id"))
    assigned_at = Column(DateTime, default=datetime.utcnow)
    
    # Timing
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    paused_at = Column(DateTime, nullable=True)
    
    # Final report
    generated_report = Column(Text, nullable=True)  # Final markdown report
    report_generated_at = Column(DateTime, nullable=True)
    
    # Relationships
    playbook = relationship("IRPlaybook", back_populates="executions")
    assigned_analyst = relationship("User")
    step_logs = relationship("StepExecutionLog", back_populates="execution")
    user_inputs = relationship("PlaybookUserInput", back_populates="execution")

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
    executed_by = relationship("User")
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
    collected_by = relationship("User")
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
    
    # Template structure - basis for creating new playbooks
    template_definition = Column(JSON, nullable=False)
    default_tags = Column(JSON, default=list)
    
    # Template metadata
    is_official = Column(Boolean, default=False)  # Official vs user-created
    download_count = Column(Integer, default=0)
    rating = Column(Float, nullable=True)  # 1.0-5.0 user rating
    
    created_by_id = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

# Example playbook JSON structure for reference:
EXAMPLE_PLAYBOOK_STRUCTURE = {
    "metadata": {
        "name": "Malware Infection Response",
        "description": "Standard response for confirmed malware infections",
        "version": "2.1",
        "estimated_duration": 120
    },
    "phases": [
        {
            "name": "initial_assessment",
            "title": "Initial Assessment",
            "description": "Gather initial information about the incident",
            "steps": [
                {
                    "name": "collect_basic_info",
                    "title": "Collect Basic Information",
                    "type": "user_input",
                    "description": "Gather essential details about the incident",
                    "required": True,
                    "inputs": [
                        {
                            "name": "affected_systems",
                            "label": "List affected systems (hostnames/IPs)",
                            "type": "textarea",
                            "required": True,
                            "placeholder": "SERVER-01, WORKSTATION-05, 192.168.1.100"
                        },
                        {
                            "name": "business_impact",
                            "label": "Business Impact Assessment",
                            "type": "select",
                            "options": ["Low", "Medium", "High", "Critical"],
                            "required": True
                        },
                        {
                            "name": "incident_time",
                            "label": "When was the incident first detected?",
                            "type": "datetime",
                            "required": True
                        }
                    ]
                }
            ]
        },
        {
            "name": "containment",
            "title": "Containment",
            "description": "Isolate and contain the threat",
            "steps": [
                {
                    "name": "isolate_systems",
                    "title": "Isolate Affected Systems",
                    "type": "manual_action",
                    "description": "Network isolate all affected systems to prevent spread",
                    "instructions": "Use network ACLs or physically disconnect systems",
                    "requires_approval": True,
                    "estimated_minutes": 15
                },
                {
                    "name": "collect_memory_dump",
                    "title": "Collect Memory Dump",
                    "type": "artifact_collection",
                    "description": "Capture memory dump from primary affected system",
                    "automation": {
                        "tool": "winpmem",
                        "command": "winpmem.exe -o {output_path}",
                        "output_path": "/artifacts/memory_{timestamp}.mem"
                    }
                }
            ]
        },
        {
            "name": "analysis",
            "title": "Analysis",
            "description": "Analyze collected evidence",
            "steps": [
                {
                    "name": "malware_analysis", 
                    "title": "Analyze Malware Sample",
                    "type": "analysis",
                    "description": "Run YARA rules and analyze collected artifacts",
                    "inputs": [
                        {
                            "name": "analysis_findings",
                            "label": "Analysis Results",
                            "type": "textarea",
                            "required": True,
                            "placeholder": "Describe malware family, IOCs, TTPs observed..."
                        }
                    ]
                }
            ]
        },
        {
            "name": "recovery",
            "title": "Recovery",
            "description": "Restore systems and implement improvements",
            "steps": [
                {
                    "name": "system_restoration",
                    "title": "System Restoration Plan",
                    "type": "user_input",
                    "inputs": [
                        {
                            "name": "restoration_steps",
                            "label": "Describe restoration steps taken",
                            "type": "textarea",
                            "required": True
                        },
                        {
                            "name": "preventive_measures",
                            "label": "Preventive measures implemented",
                            "type": "textarea",
                            "required": True
                        }
                    ]
                }
            ]
        }
    ],
    "report_template": """
# Malware Incident Response Report

## Incident Overview
- **Incident ID**: {incident_id}
- **Detection Time**: {user_inputs.incident_time}
- **Business Impact**: {user_inputs.business_impact}
- **Affected Systems**: {user_inputs.affected_systems}

## Response Timeline
{execution_timeline}

## Analysis Results
{user_inputs.analysis_findings}

## Recovery Actions
{user_inputs.restoration_steps}

## Preventive Measures
{user_inputs.preventive_measures}

## Artifacts Collected
{artifacts_list}

## Lessons Learned
{lessons_learned}
"""
}