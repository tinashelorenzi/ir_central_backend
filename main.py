from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from sqlalchemy import text
from datetime import datetime

from database import engine, get_db, Base
from siem_routes.auth import router as auth_router
from siem_routes.playbooks import router as playbook_router
from siem_routes.endpoint_tokens import router as endpoint_tokens_router
from routes.alert import router as alert_router
from schemas import HealthCheck, ErrorResponse

# Create database tables
def create_tables():
    Base.metadata.create_all(bind=engine)

# Startup and shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_tables()
    print("Database tables created successfully")
    yield
    # Shutdown
    print("Application shutting down")

# Create FastAPI app
app = FastAPI(
    title="IR Central Backend",
    description="Incident Response Central Management System",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc)
        ).dict()
    )

# Health check endpoint
@app.get("/health", response_model=HealthCheck)
async def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db = next(get_db())
        db.execute(text("SELECT 1"))
        db.close()
        database_status = "connected"
    except Exception as e:
        database_status = f"error: {str(e)}"
    
    return HealthCheck(
        status="healthy",
        timestamp=datetime.utcnow(),
        database=database_status
    )

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "IR Central Backend API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }

# Include routers
app.include_router(auth_router, prefix="/api/v1")
app.include_router(playbook_router, prefix="/api/v1")
app.include_router(endpoint_tokens_router, prefix="/api/v1")
app.include_router(alert_router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
