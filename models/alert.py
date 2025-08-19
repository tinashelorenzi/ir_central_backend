# models/alert.py

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON, Float
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from typing import Dict, List, Any, Optional

# Import Base from database.py
from database import Base

class AlertSeverity(str, enum.Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AlertStatus(str, enum.Enum):
    """Alert processing status"""
    NEW = "new"                     # Just received from SIEM
    TRIAGED = "triaged"            # Initial assessment completed
    INVESTIGATING = "investigating" # Actively being investigated
    CONTAINED = "contained"        # Threat contained
    RESOLVED = "resolved"          # Fully resolved
    FALSE_POSITIVE = "false_positive" # Determined to be false positive
    CLOSED = "closed"              # Case closed

class AlertSource(str, enum.Enum):
    """Sources that can generate alerts"""
    SNORT = "snort"
    SURICATA = "suricata"
    SIEM = "siem"
    EDR = "edr"
    ANTIVIRUS = "antivirus"
    FIREWALL = "firewall"
    IDS = "ids"
    IPS = "ips"
    EMAIL_SECURITY = "email_security"
    WEB_PROXY = "web_proxy"
    DNS_SECURITY = "dns_security"
    USER_REPORT = "user_report"
    HONEYPOT = "honeypot"
    THREAT_INTEL = "threat_intel"
    CUSTOM = "custom"

class ThreatType(str, enum.Enum):
    """Types of threats/incidents"""
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    RECONNAISSANCE = "reconnaissance"
    DENIAL_OF_SERVICE = "denial_of_service"
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_NETWORK = "suspicious_network"
    POLICY_VIOLATION = "policy_violation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    UNKNOWN = "unknown"

class Alert(Base):
    """Security alerts from SIEM/monitoring systems"""
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # === BASIC REQUIRED FIELDS (from SIEM) ===
    # External alert identifier from the source system
    external_alert_id = Column(String(255), nullable=False, index=True)
    
    # Alert metadata
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default=AlertSeverity.MEDIUM)
    source = Column(String(50), nullable=False)  # snort, siem, edr, etc.
    threat_type = Column(String(50), nullable=True, default=ThreatType.UNKNOWN)
    
    # Timing information
    detected_at = Column(DateTime, nullable=False)  # When the threat was detected
    received_at = Column(DateTime, default=datetime.utcnow)  # When we received the alert
    
    # Source system information
    source_system = Column(String(100), nullable=True)  # e.g., "Splunk", "QRadar", "Snort-Sensor-01"
    rule_id = Column(String(100), nullable=True)        # Detection rule/signature ID
    rule_name = Column(String(255), nullable=True)      # Human-readable rule name
    
    # Basic network information (when available)
    source_ip = Column(String(45), nullable=True)       # IPv4 or IPv6
    destination_ip = Column(String(45), nullable=True)  # IPv4 or IPv6
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)        # TCP, UDP, ICMP, etc.
    
    # Asset information
    affected_hostname = Column(String(255), nullable=True)
    affected_user = Column(String(100), nullable=True)
    asset_criticality = Column(String(20), nullable=True)  # low, medium, high, critical
    
    # === PROCESSING FIELDS ===
    status = Column(String(20), default=AlertStatus.NEW)
    confidence_score = Column(Float, nullable=True)     # 0.0 to 1.0 confidence level
    risk_score = Column(Integer, nullable=True)         # 1-100 risk assessment
    
    # Assignment and tracking
    assigned_analyst_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    incident_id = Column(String(50), nullable=True)     # Link to incident system
    playbook_execution_id = Column(Integer, ForeignKey("playbook_executions.id"), nullable=True)
    
    # Correlation and grouping
    correlation_id = Column(String(100), nullable=True)  # Group related alerts
    parent_alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)  # For alert hierarchies
    
    # === ENRICHMENT DATA (populated during investigation) ===
    # Raw alert data from source system
    raw_alert_data = Column(JSON, nullable=True)
    
    # Additional context gathered during analysis
    enrichment_data = Column(JSON, default=dict)
    # Example enrichment_data structure:
    # {
    #   "file_hashes": ["sha256:abc123..."],
    #   "domain_reputation": {"malicious": ["evil.com"], "suspicious": ["sketchy.net"]},
    #   "geo_location": {"source_country": "RU", "destination_country": "US"},
    #   "threat_intelligence": {"apt_group": "APT29", "campaign": "Operation XYZ"},
    #   "similar_incidents": [{"incident_id": "INC-2024-001", "similarity": 0.85}]
    # }
    
    # Investigation notes and findings
    investigation_notes = Column(Text, nullable=True)
    analyst_comments = Column(Text, nullable=True)
    
    # === REPORTING AND COMPLIANCE ===
    reported = Column(Boolean, default=False)           # Whether included in reports
    reported_at = Column(DateTime, nullable=True)       # When it was reported
    reported_to = Column(JSON, default=list)           # Who/what it was reported to
    # Example: ["CISO", "compliance_team", "customer", "law_enforcement"]
    
    false_positive = Column(Boolean, default=False)
    false_positive_reason = Column(String(255), nullable=True)
    
    # Regulatory compliance flags
    requires_notification = Column(Boolean, default=False)  # GDPR, breach notification, etc.
    notification_deadline = Column(DateTime, nullable=True)
    compliance_notes = Column(Text, nullable=True)
    
    # === IMPACT ASSESSMENT ===
    business_impact = Column(String(20), nullable=True)     # minimal, moderate, significant, severe
    data_classification = Column(String(20), nullable=True) # public, internal, confidential, restricted
    estimated_financial_impact = Column(Float, nullable=True)
    
    # === AUDIT FIELDS ===
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)
    
    # Tracking for SLA compliance
    first_response_at = Column(DateTime, nullable=True)     # When analyst first looked at it
    containment_at = Column(DateTime, nullable=True)       # When threat was contained
    resolution_at = Column(DateTime, nullable=True)        # When fully resolved
    
    # === RELATIONSHIPS ===
    assigned_analyst = relationship("User", foreign_keys=[assigned_analyst_id], back_populates="assigned_alerts")
    playbook_execution = relationship("PlaybookExecution", foreign_keys=[playbook_execution_id])
    parent_alert = relationship("Alert", remote_side=[id], foreign_keys=[parent_alert_id], back_populates="child_alerts")
    child_alerts = relationship("Alert", foreign_keys=[parent_alert_id], back_populates="parent_alert")
    
    # Indexes for performance
    __table_args__ = (
        # Compound indexes for common queries
        {"extend_existing": True}
    )
    
    def __repr__(self):
        return f"<Alert(id={self.id}, title='{self.title}', severity='{self.severity}', status='{self.status}')>"
    
    @property
    def is_overdue(self) -> bool:
        """Check if alert response is overdue based on severity SLA"""
        if self.status in [AlertStatus.RESOLVED, AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE]:
            return False
            
        now = datetime.utcnow()
        hours_since_received = (now - self.received_at).total_seconds() / 3600
        
        # SLA thresholds by severity (in hours)
        sla_thresholds = {
            AlertSeverity.CRITICAL: 1,    # 1 hour
            AlertSeverity.HIGH: 4,        # 4 hours
            AlertSeverity.MEDIUM: 24,     # 24 hours
            AlertSeverity.LOW: 72         # 72 hours
        }
        
        threshold = sla_thresholds.get(self.severity, 24)
        return hours_since_received > threshold
    
    @property
    def time_to_first_response(self) -> Optional[float]:
        """Calculate time to first response in hours"""
        if not self.first_response_at:
            return None
        return (self.first_response_at - self.received_at).total_seconds() / 3600
    
    @property
    def time_to_resolution(self) -> Optional[float]:
        """Calculate time to resolution in hours"""
        if not self.resolution_at:
            return None
        return (self.resolution_at - self.received_at).total_seconds() / 3600

class AlertTag(Base):
    """Tags for categorizing and filtering alerts"""
    __tablename__ = "alert_tags"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    tag = Column(String(50), nullable=False)
    
    # Relationships
    alert = relationship("Alert")
    
    __table_args__ = (
        # Ensure unique tag per alert
        {"extend_existing": True}
    )

class AlertArtifact(Base):
    """Digital artifacts associated with alerts (files, network captures, etc.)"""
    __tablename__ = "alert_artifacts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    
    # Artifact metadata
    artifact_type = Column(String(50), nullable=False)  # file, pcap, memory_dump, log, screenshot
    filename = Column(String(255), nullable=True)
    file_path = Column(String(500), nullable=True)      # Storage location
    file_size = Column(Integer, nullable=True)          # Size in bytes
    file_hash_md5 = Column(String(32), nullable=True)
    file_hash_sha1 = Column(String(40), nullable=True)
    file_hash_sha256 = Column(String(64), nullable=True)
    
    # Metadata
    description = Column(Text, nullable=True)
    collected_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    collected_at = Column(DateTime, default=datetime.utcnow)
    
    # Chain of custody
    chain_of_custody = Column(JSON, default=list)
    # Example: [{"action": "collected", "by": "analyst1", "at": "2024-01-01T10:00:00", "location": "/evidence/"}]
    
    # Relationships
    alert = relationship("Alert")
    collected_by = relationship("User", foreign_keys=[collected_by_id], back_populates="collected_artifacts")
    
    def __repr__(self):
        return f"<AlertArtifact(id={self.id}, type='{self.artifact_type}', filename='{self.filename}')>"