from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import os

load_dotenv()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/ir_central")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Import all models to ensure they are registered with SQLAlchemy
# These imports must come after Base is defined to avoid circular imports
from models.users import User, UserManager, UserSession, LoginAttempt
from models.playbook import (
    IRPlaybook, PlaybookExecution, StepExecutionLog, 
    PlaybookUserInput, PlaybookTemplate, PlaybookStatus, StepType, InputFieldType
)
from models.endpoint_tokens import EndpointToken
from models.alert import Alert, AlertTag, AlertArtifact, AlertSeverity, AlertStatus, AlertSource, ThreatType
