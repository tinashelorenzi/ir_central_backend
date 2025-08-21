"""
Reports Model
Handles storage and management of generated IR reports
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

# Import Base from database.py to avoid circular imports
from database import Base

class ReportType(str, enum.Enum):
    """Types of reports that can be generated"""
    INCIDENT = "incident"        # Single incident report
    COLLECTIVE = "collective"    # Multiple incidents/collective analysis

class ReportStatus(str, enum.Enum):
    """Report generation status"""
    DRAFT = "draft"              # Report is being created/edited
    GENERATING = "generating"    # Backend is processing the report
    COMPLETED = "completed"      # Report is ready for download
    FAILED = "failed"           # Report generation failed
    ARCHIVED = "archived"       # Old report, archived

class ReportFormat(str, enum.Enum):
    """Available export formats"""
    MARKDOWN = "markdown"
    PDF = "pdf"
    HTML = "html"

class Report(Base):
    """Generated incident reports"""
    __tablename__ = "reports"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Basic report information
    title = Column(String(300), nullable=False, index=True)
    description = Column(Text, nullable=True)
    report_type = Column(String(20), nullable=False, default=ReportType.INCIDENT)
    status = Column(String(20), nullable=False, default=ReportStatus.DRAFT)
    
    # Template and content
    template_id = Column(Integer, ForeignKey("report_templates.id"), nullable=True)
    template = relationship("ReportTemplate")
    
    # Generated content - final rendered report
    generated_content = Column(Text, nullable=True)  # Final markdown/html content
    content_metadata = Column(JSON, default=dict)    # Additional metadata about content generation
    
    # Report configuration and filters
    report_config = Column(JSON, default=dict)  # Configuration used to generate the report
    # Example config structure:
    # {
    #   "type": "incident|collective",
    #   "incident_ids": [1, 2, 3],  # For incident reports
    #   "filters": {                # For collective reports
    #     "date_range": {"start": "2024-01-01", "end": "2024-01-31"},
    #     "users": ["user1", "user2"],
    #     "ip_addresses": ["192.168.1.1"],
    #     "incident_types": ["malware", "phishing"],
    #     "severity_levels": ["high", "critical"]
    #   },
    #   "include_sections": ["executive_summary", "timeline", "artifacts"],
    #   "analytics": ["incident_count", "mttr", "affected_systems"]
    # }
    
    # Data mappings - tracks what data was used in the report
    data_mappings = Column(JSON, default=dict)  # Maps template variables to actual data
    # Example structure:
    # {
    #   "incidents": [1, 2, 3],
    #   "playbook_executions": [5, 6, 7],
    #   "user_inputs": [
    #     {"execution_id": 5, "field_name": "affected_systems", "value": "Web server"},
    #     {"execution_id": 6, "field_name": "remediation_steps", "value": "Isolated infected machine"}
    #   ],
    #   "analytics": {
    #     "total_incidents": 3,
    #     "average_resolution_time": 4.5,
    #     "most_affected_department": "IT"
    #   }
    # }
    
    # Export and sharing
    available_formats = Column(JSON, default=list)  # ["markdown", "pdf", "html"]
    exported_files = Column(JSON, default=dict)     # File paths for different formats
    # Example: {"markdown": "/reports/files/report_123.md", "pdf": "/reports/files/report_123.pdf"}
    
    # Timestamps and user tracking
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    generated_at = Column(DateTime, nullable=True)   # When report generation completed
    
    # User relationships
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_by = relationship("User", foreign_keys=[created_by_id])
    
    # Generation stats
    generation_time_seconds = Column(Float, nullable=True)  # How long it took to generate
    file_size_bytes = Column(Integer, nullable=True)        # Size of generated files
    
    # Report metrics and analytics
    view_count = Column(Integer, default=0)                 # How many times viewed
    download_count = Column(Integer, default=0)             # How many times downloaded
    last_accessed_at = Column(DateTime, nullable=True)      # Last time accessed
    
    # Additional metadata
    tags = Column(String(500), nullable=True)               # Comma-separated tags
    executive_summary = Column(Text, nullable=True)         # Brief summary for dashboards
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "report_type": self.report_type,
            "status": self.status,
            "template_id": self.template_id,
            "generated_content": self.generated_content,
            "content_metadata": self.content_metadata,
            "report_config": self.report_config,
            "data_mappings": self.data_mappings,
            "available_formats": self.available_formats,
            "exported_files": self.exported_files,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
            "created_by_id": self.created_by_id,
            "generation_time_seconds": self.generation_time_seconds,
            "file_size_bytes": self.file_size_bytes,
            "view_count": self.view_count,
            "download_count": self.download_count,
            "last_accessed_at": self.last_accessed_at.isoformat() if self.last_accessed_at else None,
            "tags": self.tags,
            "executive_summary": self.executive_summary
        }

class ReportElement(Base):
    """Individual elements/sections within a report during editing phase"""
    __tablename__ = "report_elements"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Report relationship
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False)
    report = relationship("Report", backref="elements")
    
    # Element details
    element_type = Column(String(50), nullable=False)  # "user_input", "analytics", "static_text", "incident_data"
    element_key = Column(String(100), nullable=False)  # Key/identifier for the element
    display_name = Column(String(200), nullable=False) # Human-readable name
    
    # Position in report
    section_name = Column(String(100), nullable=False) # Which section of the template
    position_order = Column(Integer, default=0)        # Order within the section
    
    # Element data
    element_data = Column(JSON, default=dict)          # The actual data/value
    # Example structures:
    # User Input: {"execution_id": 5, "field_name": "affected_systems", "value": "Web server", "input_type": "text"}
    # Analytics: {"metric_type": "incident_count", "value": 15, "calculation": "COUNT(incidents)"}
    # Static Text: {"content": "This is additional context about the incident"}
    # Incident Data: {"incident_id": 123, "field": "severity", "value": "high"}
    
    # Template mapping
    template_variable = Column(String(100), nullable=True)  # Which Jinja variable this maps to
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # User who added this element
    added_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    added_by = relationship("User", foreign_keys=[added_by_id])

class ReportShare(Base):
    """Report sharing and access control"""
    __tablename__ = "report_shares"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Report relationship
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False)
    report = relationship("Report", backref="shares")
    
    # Sharing details
    shared_with_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Specific user
    shared_with_user = relationship("User", foreign_keys=[shared_with_user_id])
    
    shared_with_role = Column(String(50), nullable=True)     # Role-based sharing (e.g., "managers")
    is_public_link = Column(Boolean, default=False)          # Public shareable link
    public_link_token = Column(String(100), nullable=True, unique=True)  # Token for public access
    
    # Permissions
    can_view = Column(Boolean, default=True)
    can_download = Column(Boolean, default=True)
    can_edit = Column(Boolean, default=False)
    
    # Expiration
    expires_at = Column(DateTime, nullable=True)
    
    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_by = relationship("User", foreign_keys=[created_by_id])
    
    # Access tracking
    last_accessed_at = Column(DateTime, nullable=True)
    access_count = Column(Integer, default=0)

class ReportComment(Base):
    """Comments and collaboration on reports"""
    __tablename__ = "report_comments"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Report relationship
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False)
    report = relationship("Report", backref="comments")
    
    # Comment details
    content = Column(Text, nullable=False)
    element_id = Column(Integer, ForeignKey("report_elements.id"), nullable=True)  # Comment on specific element
    element = relationship("ReportElement")
    
    # Threading (for replies)
    parent_comment_id = Column(Integer, ForeignKey("report_comments.id"), nullable=True)
    parent_comment = relationship("ReportComment", remote_side=[id])
    
    # User tracking
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_by = relationship("User", foreign_keys=[created_by_id])
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Status
    is_resolved = Column(Boolean, default=False)
    resolved_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_by = relationship("User", foreign_keys=[resolved_by_id])
    resolved_at = Column(DateTime, nullable=True)