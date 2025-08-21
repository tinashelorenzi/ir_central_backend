"""
Report Templates Model
Handles storage and management of IR report templates in HTML/CSS format
"""

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

# Import Base from database.py to avoid circular imports
from database import Base

class ReportTemplateStatus(str, enum.Enum):
    """Report template status"""
    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"

class ReportTemplate(Base):
    """Report templates for generating IR incident reports"""
    __tablename__ = "report_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Basic template information
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    author = Column(String(100), nullable=False)
    
    # Template content (HTML with embedded CSS)
    content = Column(Text, nullable=False)
    # This will contain HTML with CSS styling and placeholder variables
    # Example: <h1>{{incident_title}}</h1> for dynamic content insertion
    
    # Template metadata
    version = Column(String(20), default="1.0")
    status = Column(String(20), default=ReportTemplateStatus.DRAFT)
    
    # Categorization and filtering
    tags = Column(String(500), nullable=True)  # comma-separated tags for filtering
    incident_types = Column(String(500), nullable=True)  # which incident types this applies to
    
    # Template configuration
    is_default = Column(Boolean, default=False)  # Is this the default template
    requires_approval = Column(Boolean, default=False)  # Requires approval before use
    
    # Usage tracking
    usage_count = Column(Integer, default=0)
    last_used = Column(DateTime, nullable=True)
    
    # Audit fields
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships - Use string references to avoid circular imports
    created_by = relationship("User", foreign_keys=[created_by_id], back_populates="created_report_templates")
    updated_by = relationship("User", foreign_keys=[updated_by_id], back_populates="updated_report_templates")
    
    def __repr__(self):
        return f"<ReportTemplate(id={self.id}, name='{self.name}', author='{self.author}', status='{self.status}')>"
    
    @property
    def tag_list(self):
        """Return tags as a list"""
        if self.tags:
            return [tag.strip() for tag in self.tags.split(',') if tag.strip()]
        return []
    
    @tag_list.setter
    def tag_list(self, tags):
        """Set tags from a list"""
        if tags:
            self.tags = ', '.join([tag.strip() for tag in tags if tag.strip()])
        else:
            self.tags = None
    
    @property
    def incident_type_list(self):
        """Return incident types as a list"""
        if self.incident_types:
            return [itype.strip() for itype in self.incident_types.split(',') if itype.strip()]
        return []
    
    @incident_type_list.setter
    def incident_type_list(self, types):
        """Set incident types from a list"""
        if types:
            self.incident_types = ', '.join([itype.strip() for itype in types if itype.strip()])
        else:
            self.incident_types = None
    
    def increment_usage(self):
        """Increment usage count and update last used timestamp"""
        self.usage_count += 1
        self.last_used = datetime.utcnow()
    
    def to_dict(self):
        """Convert model to dictionary for API responses"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "author": self.author,
            "content": self.content,
            "version": self.version,
            "status": self.status,
            "tags": self.tag_list,
            "incident_types": self.incident_type_list,
            "is_default": self.is_default,
            "requires_approval": self.requires_approval,
            "usage_count": self.usage_count,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "created_by_id": self.created_by_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "updated_by_id": self.updated_by_id
        }