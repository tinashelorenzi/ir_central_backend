from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from database import Base
import hashlib
import secrets


class EndpointToken(Base):
    """Model for API tokens used by external systems to access alert endpoints"""
    __tablename__ = "endpoint_tokens"

    id = Column(Integer, primary_key=True, index=True)
    
    # Token identification
    token_name = Column(String(100), nullable=False, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)  # SHA256 hash
    token_prefix = Column(String(8), nullable=False, index=True)  # First 8 chars for identification
    
    # Token metadata
    description = Column(Text, nullable=True)
    
    # Access control
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    # Permissions - specific to alert API
    can_create_alerts = Column(Boolean, default=True, nullable=False)
    can_update_alerts = Column(Boolean, default=False, nullable=False)
    can_read_alerts = Column(Boolean, default=True, nullable=False)
    
    # Rate limiting fields
    rate_limit_per_minute = Column(Integer, default=100, nullable=False)  # Requests per minute
    last_request_at = Column(DateTime, nullable=True)
    request_count_current_minute = Column(Integer, default=0, nullable=False)
    request_count_minute_start = Column(DateTime, nullable=True)
    
    # Audit fields
    created_by_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)
    total_requests = Column(Integer, default=0, nullable=False)
    
    # Expiration
    expires_at = Column(DateTime, nullable=True)  # Optional expiration
    
    # Source restrictions
    allowed_ips = Column(Text, nullable=True)  # JSON array of allowed IP addresses/ranges
    allowed_sources = Column(Text, nullable=True)  # JSON array of allowed source systems
    
    # Relationships
    created_by = relationship("User", back_populates="created_tokens")

    @staticmethod
    def generate_token():
        """Generate a new random token and return both the raw token and its hash"""
        # Generate 32 random bytes and convert to hex (64 characters)
        raw_token = secrets.token_hex(32)
        
        # Create SHA256 hash
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        
        # Get prefix for identification (first 8 characters)
        token_prefix = raw_token[:8]
        
        return raw_token, token_hash, token_prefix

    @staticmethod
    def hash_token(raw_token: str) -> str:
        """Hash a raw token using SHA256"""
        return hashlib.sha256(raw_token.encode()).hexdigest()

    def is_expired(self) -> bool:
        """Check if the token is expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        """Check if the token is valid (active and not expired)"""
        return self.is_active and not self.is_expired()

    def can_make_request(self) -> bool:
        """Check if the token can make a request based on rate limiting"""
        if not self.is_valid():
            return False
        
        now = datetime.utcnow()
        current_minute = now.replace(second=0, microsecond=0)
        
        # Reset counter if we're in a new minute
        if (self.request_count_minute_start is None or 
            self.request_count_minute_start < current_minute):
            return True  # New minute, can make request
        
        # Check if we're under the rate limit
        return self.request_count_current_minute < self.rate_limit_per_minute

    def record_request(self, db_session):
        """Record a request being made with this token"""
        now = datetime.utcnow()
        current_minute = now.replace(second=0, microsecond=0)
        
        # Reset counter if we're in a new minute
        if (self.request_count_minute_start is None or 
            self.request_count_minute_start < current_minute):
            self.request_count_current_minute = 1
            self.request_count_minute_start = current_minute
        else:
            self.request_count_current_minute += 1
        
        # Update usage statistics
        self.last_used_at = now
        self.last_request_at = now
        self.total_requests += 1
        
        db_session.commit()

    def update_last_used(self, db_session):
        """Update the last used timestamp"""
        self.last_used_at = datetime.utcnow()
        db_session.commit()

    def deactivate(self, db_session):
        """Deactivate the token"""
        self.is_active = False
        self.updated_at = datetime.utcnow()
        db_session.commit()

    def __repr__(self):
        return f"<EndpointToken(id={self.id}, name='{self.token_name}', prefix='{self.token_prefix}', active={self.is_active})>"