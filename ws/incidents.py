# websockets/incidents.py

from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc, asc, func
from typing import Dict, List, Set, Optional, Any
import json
import logging
import asyncio
from datetime import datetime
import jwt

from database import get_db
from auth_utils import SECRET_KEY, ALGORITHM
from models.users import User
from models.incident import Incident, IncidentStatus, IncidentSeverity, IncidentPriority
from models.alert import Alert, AlertStatus
from schemas import IncidentResponse, AlertResponse

logger = logging.getLogger(__name__)


def serialize_user_for_response(user) -> Dict[str, Any]:
    """Convert User model to dictionary for API responses"""
    if not user:
        return None
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None
    }

def create_alert_response_dict(alert) -> Dict[str, Any]:
    """Create a properly serialized alert response dictionary"""
    return {
        "id": alert.id,
        "external_alert_id": alert.external_alert_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "source": alert.source,
        "threat_type": alert.threat_type,
        "detected_at": alert.detected_at,
        "source_system": alert.source_system,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "source_port": alert.source_port,
        "destination_port": alert.destination_port,
        "protocol": alert.protocol,
        "affected_hostname": alert.affected_hostname,
        "affected_user": alert.affected_user,
        "asset_criticality": alert.asset_criticality,
        "status": alert.status,
        "confidence_score": alert.confidence_score,
        "risk_score": alert.risk_score,
        "assigned_analyst_id": alert.assigned_analyst_id,
        "incident_id": alert.incident_id,
        "playbook_execution_id": alert.playbook_execution_id,
        "correlation_id": alert.correlation_id,
        "parent_alert_id": alert.parent_alert_id,
        "enrichment_data": alert.enrichment_data or {},
        "investigation_notes": alert.investigation_notes,
        "analyst_comments": alert.analyst_comments,
        "reported": alert.reported,
        "reported_at": alert.reported_at,
        "reported_to": alert.reported_to or [],
        "false_positive": alert.false_positive,
        "false_positive_reason": alert.false_positive_reason,
        "business_impact": alert.business_impact,
        "data_classification": alert.data_classification,
        "estimated_financial_impact": alert.estimated_financial_impact,
        "requires_notification": alert.requires_notification,
        "notification_deadline": alert.notification_deadline,
        "compliance_notes": alert.compliance_notes,
        "received_at": alert.received_at,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "closed_at": alert.closed_at,
        "first_response_at": alert.first_response_at,
        "containment_at": alert.containment_at,
        "resolution_at": alert.resolution_at,
        "assigned_analyst": serialize_user_for_response(alert.assigned_analyst),
        "is_overdue": alert.is_overdue,
        "time_to_first_response": alert.time_to_first_response,
        "time_to_resolution": alert.time_to_resolution
    }

def create_incident_response_dict(incident) -> Dict[str, Any]:
    """Create a properly serialized incident response dictionary"""
    
    # Convert the incident to dict first
    incident_dict = {
        "id": incident.id,
        "incident_id": incident.incident_id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "priority": incident.priority,
        "status": incident.status,
        "category": incident.category,
        
        # IDs
        "owner_id": incident.owner_id,
        "assigned_analyst_id": incident.assigned_analyst_id,
        "escalated_to_id": incident.escalated_to_id,
        
        # Timing
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "first_response_at": incident.first_response_at.isoformat() if incident.first_response_at else None,
        "contained_at": incident.contained_at.isoformat() if incident.contained_at else None,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
        
        # SLA tracking
        "response_sla_deadline": incident.response_sla_deadline.isoformat() if incident.response_sla_deadline else None,
        "resolution_sla_deadline": incident.resolution_sla_deadline.isoformat() if incident.resolution_sla_deadline else None,
        "sla_breached": incident.sla_breached or False,
        
        # Related data
        "alert_ids": incident.alert_ids or [],
        "affected_systems": incident.affected_systems or [],
        "affected_users": incident.affected_users or [],
        "affected_services": incident.affected_services or [],
        
        # Investigation
        "investigation_summary": incident.investigation_summary,
        "investigation_notes": incident.investigation_notes,
        "incident_timeline": incident.incident_timeline or [],
        
        # Impact
        "business_impact": incident.business_impact,
        "estimated_financial_loss": incident.estimated_financial_loss,
        "data_compromised": incident.data_compromised or False,
        "data_types_affected": incident.data_types_affected or [],
        "systems_compromised": incident.systems_compromised or 0,
        "users_affected": incident.users_affected or 0,
        
        # Response
        "containment_strategy": incident.containment_strategy,
        "containment_actions": incident.containment_actions or [],
        "eradication_actions": incident.eradication_actions or [],
        "recovery_actions": incident.recovery_actions or [],
        
        # Playbook
        "playbook_execution_id": incident.playbook_execution_id,
        "automated_actions": incident.automated_actions or [],
        
        # Communication
        "internal_notifications": incident.internal_notifications or [],
        "external_notifications": incident.external_notifications or [],
        
        # Compliance
        "requires_external_reporting": incident.requires_external_reporting or False,
        "external_reporting_deadline": incident.external_reporting_deadline.isoformat() if incident.external_reporting_deadline else None,
        "reported_to_authorities": incident.reported_to_authorities or False,
        "compliance_requirements": incident.compliance_requirements or [],
        
        # Post-incident
        "lessons_learned": incident.lessons_learned,
        "recommendations": incident.recommendations or [],
        "follow_up_actions": incident.follow_up_actions or [],
        "post_incident_review_completed": incident.post_incident_review_completed or False,
        "post_incident_review_notes": incident.post_incident_review_notes,
        "post_incident_review_date": incident.post_incident_review_date.isoformat() if incident.post_incident_review_date else None,
        
        # Metadata
        "correlation_id": incident.correlation_id,
        "parent_incident_id": incident.parent_incident_id,
        "tags": incident.tags or [],
        "custom_fields": incident.custom_fields or {},
        
        # Relationships (properly serialized)
        "owner": serialize_user_for_response(incident.owner),
        "assigned_analyst": serialize_user_for_response(incident.assigned_analyst),
        "escalated_to": serialize_user_for_response(incident.escalated_to),
        
        # Computed properties
        "time_to_first_response": incident.time_to_first_response,
        "time_to_containment": incident.time_to_containment,
        "time_to_resolution": incident.time_to_resolution,
        "alert_count": len(incident.alert_ids) if incident.alert_ids else 0,
        "is_sla_breached": incident.sla_breached or False,
    }
    
    return incident_dict


class IncidentWebSocketManager:
    """Manages WebSocket connections for real-time incident updates"""
    
    def __init__(self):
        # Store active connections: {user_id: {websocket, user_info}}
        self.active_connections: Dict[int, Dict[str, Any]] = {}
        
        # Store incident watchers: {incident_id: {user_id, user_id, ...}}
        self.incident_watchers: Dict[int, Set[int]] = {}
        
        # Store user's owned incidents: {user_id: {incident_id, incident_id, ...}}
        self.user_owned_incidents: Dict[int, Set[int]] = {}
    
    async def connect(self, websocket: WebSocket, user: User, db: Session):
        """Accept a new WebSocket connection"""
        await websocket.accept()
        
        user_info = {
            "websocket": websocket,
            "user": user,
            "connected_at": datetime.utcnow(),
            "last_ping": datetime.utcnow()
        }
        
        self.active_connections[user.id] = user_info
        
        # Load user's owned incidents
        await self._load_user_owned_incidents(user.id, db)
        
        # Send initial data
        await self._send_initial_data(user.id, db)
        
        logger.info(f"User {user.username} connected to incident WebSocket")
    
    async def disconnect(self, user_id: int):
        """Remove a WebSocket connection"""
        if user_id in self.active_connections:
            del self.active_connections[user_id]
        
        # Remove from all incident watchers
        for incident_id in list(self.incident_watchers.keys()):
            if user_id in self.incident_watchers[incident_id]:
                self.incident_watchers[incident_id].discard(user_id)
                if not self.incident_watchers[incident_id]:
                    del self.incident_watchers[incident_id]
        
        # Remove from owned incidents
        if user_id in self.user_owned_incidents:
            del self.user_owned_incidents[user_id]
        
        logger.info(f"User {user_id} disconnected from incident WebSocket")
    
    async def _load_user_owned_incidents(self, user_id: int, db: Session):
        """Load incidents owned by the user"""
        owned_incidents = db.query(Incident).filter(
            Incident.owner_id == user_id,
            Incident.status != IncidentStatus.CLOSED
        ).all()
        
        incident_ids = {incident.id for incident in owned_incidents}
        self.user_owned_incidents[user_id] = incident_ids
        
        # Add user as watcher for their owned incidents
        for incident_id in incident_ids:
            if incident_id not in self.incident_watchers:
                self.incident_watchers[incident_id] = set()
            self.incident_watchers[incident_id].add(user_id)
    
    async def _send_initial_data(self, user_id: int, db: Session):
        """Send initial data to newly connected user"""
        try:
            # Send current owned incidents
            owned_incidents = await self._get_user_owned_incidents(user_id, db)
            await self._send_to_user(user_id, {
                "type": "initial_data",
                "data": {
                    "owned_incidents": owned_incidents,
                    "connection_time": datetime.utcnow().isoformat()
                }
            })
            
            # Send recent unassigned alerts
            recent_alerts = await self._get_recent_alerts(db, limit=50)
            await self._send_to_user(user_id, {
                "type": "recent_alerts",
                "data": {
                    "alerts": recent_alerts  # Already serialized dictionaries
                }
            })
            
        except Exception as e:
            logger.error(f"Error sending initial data to user {user_id}: {e}")
    
    async def _get_user_owned_incidents(self, user_id: int, db: Session) -> List[Dict[str, Any]]:
        """Get incidents owned by user"""
        incidents = db.query(Incident).filter(
            Incident.owner_id == user_id,
            Incident.status != IncidentStatus.CLOSED
        ).options(
            joinedload(Incident.owner),
            joinedload(Incident.assigned_analyst),
            joinedload(Incident.escalated_to)
        ).order_by(desc(Incident.created_at)).all()
        
        # Convert to properly serialized dictionaries
        return [create_incident_response_dict(incident) for incident in incidents]
    
    async def _get_recent_alerts(self, db: Session, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts that could become incidents"""
        alerts = db.query(Alert).filter(
            Alert.status.in_([AlertStatus.NEW, AlertStatus.TRIAGED]),
            Alert.assigned_analyst_id.is_(None)
        ).options(
            joinedload(Alert.assigned_analyst)
        ).order_by(desc(Alert.received_at)).limit(limit).all()
        
        # Convert to properly serialized dictionaries
        return [create_alert_response_dict(alert) for alert in alerts]
    
    async def _send_to_user(self, user_id: int, message: dict):
        """Send message to a specific user"""
        if user_id in self.active_connections:
            try:
                websocket = self.active_connections[user_id]["websocket"]
                await websocket.send_text(json.dumps(message, default=str))
            except Exception as e:
                logger.error(f"Error sending message to user {user_id}: {e}")
                # Connection might be dead, clean up
                await self.disconnect(user_id)
    
    async def _broadcast_to_watchers(self, incident_id: int, message: dict):
        """Send message to all users watching an incident"""
        if incident_id in self.incident_watchers:
            watchers = list(self.incident_watchers[incident_id])
            for user_id in watchers:
                await self._send_to_user(user_id, message)
    
    async def broadcast_new_alert(self, alert: Alert, db: Session):
        """Broadcast a new alert to all connected users"""
        alert_dict = create_alert_response_dict(alert)
        
        message = {
            "type": "new_alert",
            "data": alert_dict
        }
        
        # Send to all connected users
        for user_id in list(self.active_connections.keys()):
            await self._send_to_user(user_id, message)
    
    async def broadcast_alert_update(self, alert: Alert, db: Session):
        """Broadcast alert update (status change, assignment, etc.)"""
        alert_dict = create_alert_response_dict(alert)
        
        message = {
            "type": "alert_updated",
            "data": alert_dict
        }
        
        # Send to all connected users
        for user_id in list(self.active_connections.keys()):
            await self._send_to_user(user_id, message)
    
    async def handle_take_ownership(self, alert_id: int, user_id: int, db: Session) -> Optional[Incident]:
        """Handle taking ownership of an alert and creating an incident"""
        try:
            # Get the alert
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")
            
            if alert.assigned_analyst_id is not None:
                raise HTTPException(status_code=400, detail="Alert already assigned")
            
            # Update alert
            alert.assigned_analyst_id = user_id
            alert.status = AlertStatus.INVESTIGATING
            alert.first_response_at = datetime.utcnow()
            
            # Create incident
            incident = Incident(
                title=alert.title,
                description=f"Incident created from alert: {alert.title}",
                severity=alert.severity,  # Map alert severity to incident severity
                owner_id=user_id,
                assigned_analyst_id=user_id,
                alert_ids=[alert_id]
            )
            
            # Set priority based on severity
            if alert.severity == "critical":
                incident.priority = IncidentPriority.P1
            elif alert.severity == "high":
                incident.priority = IncidentPriority.P2
            elif alert.severity == "medium":
                incident.priority = IncidentPriority.P3
            else:
                incident.priority = IncidentPriority.P4
            
            # Add initial timeline event
            incident.add_timeline_event(
                event="Incident created from alert ownership",
                source=f"User {user_id}",
                details=f"Alert {alert_id} ({alert.title}) assigned and incident created"
            )
            
            db.add(incident)
            db.commit()
            db.refresh(incident)
            
            # Update user's owned incidents
            if user_id not in self.user_owned_incidents:
                self.user_owned_incidents[user_id] = set()
            self.user_owned_incidents[user_id].add(incident.id)
            
            # Add user as watcher
            if incident.id not in self.incident_watchers:
                self.incident_watchers[incident.id] = set()
            self.incident_watchers[incident.id].add(user_id)
            
            # Broadcast updates
            await self.broadcast_alert_update(alert, db)
            await self.broadcast_incident_created(incident, db)
            
            return incident
            
        except Exception as e:
            db.rollback()
            logger.error(f"Error taking ownership of alert {alert_id}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    async def broadcast_incident_created(self, incident: Incident, db: Session):
        """Broadcast new incident creation"""
        incident_data = IncidentResponse.from_orm(incident)
        message = {
            "type": "incident_created",
            "data": incident_data.model_dump()
        }
        
        # Send to the owner
        await self._send_to_user(incident.owner_id, message)
        
        # Send notification to managers/admins
        managers = db.query(User).filter(
            User.role.in_(["manager", "admin"])
        ).all()
        
        for manager in managers:
            if manager.id != incident.owner_id:  # Don't double-send to owner
                await self._send_to_user(manager.id, {
                    "type": "incident_notification",
                    "data": {
                        "message": f"New incident {incident.incident_id} created by {incident.owner.username}",
                        "incident": incident_data.model_dump()
                    }
                })
    
    async def broadcast_incident_update(self, incident: Incident, db: Session):
        """Broadcast incident updates to watchers"""
        incident_data = IncidentResponse.from_orm(incident)
        message = {
            "type": "incident_updated",
            "data": incident_data.model_dump()
        }
        
        await self._broadcast_to_watchers(incident.id, message)
    
    async def handle_message(self, user_id: int, message: dict, db: Session):
        """Handle incoming WebSocket messages"""
        try:
            message_type = message.get("type")
            
            if message_type == "ping":
                # Update last ping time
                if user_id in self.active_connections:
                    self.active_connections[user_id]["last_ping"] = datetime.utcnow()
                await self._send_to_user(user_id, {"type": "pong"})
            
            elif message_type == "get_owned_incidents":
                owned_incidents = await self._get_user_owned_incidents(user_id, db)
                await self._send_to_user(user_id, {
                    "type": "owned_incidents",
                    "data": {
                        "incidents": owned_incidents
                    }
                })
            
            elif message_type == "get_recent_alerts":
                recent_alerts = await self._get_recent_alerts(db)
                await self._send_to_user(user_id, {
                    "type": "recent_alerts",
                    "data": {
                        "alerts": recent_alerts  # Already serialized dictionaries
                    }
                })
            
            elif message_type == "take_alert_ownership":
                # Handle taking ownership of an alert
                alert_id = message.get("data", {}).get("alert_id")
                if alert_id:
                    try:
                        incident = await self.handle_take_ownership(alert_id, user_id, db)
                        await self._send_to_user(user_id, {
                            "type": "alert_ownership_taken",
                            "data": {
                                "alert_id": alert_id,
                                "incident": create_incident_response_dict(incident) if incident else None
                            }
                        })
                    except Exception as e:
                        await self._send_to_user(user_id, {
                            "type": "error",
                            "data": {"message": str(e)}
                        })
                else:
                    await self._send_to_user(user_id, {
                        "type": "error",
                        "data": {"message": "alert_id required for take_alert_ownership"}
                    })
            
            elif message_type == "take_ownership":
                # Handle taking ownership of an alert (alternative message type)
                alert_id = message.get("data", {}).get("alert_id")
                if alert_id:
                    try:
                        incident = await self.handle_take_ownership(alert_id, user_id, db)
                        await self._send_to_user(user_id, {
                            "type": "alert_ownership_taken",
                            "data": {
                                "alert_id": alert_id,
                                "incident": create_incident_response_dict(incident) if incident else None
                            }
                        })
                    except Exception as e:
                        await self._send_to_user(user_id, {
                            "type": "error",
                            "data": {"message": str(e)}
                        })
                else:
                    await self._send_to_user(user_id, {
                        "type": "error",
                        "data": {"message": "alert_id required for take_ownership"}
                    })
            
            elif message_type == "update_alert_status":
                # Handle alert status updates
                alert_id = message.get("data", {}).get("alert_id")
                new_status = message.get("data", {}).get("status")
                if alert_id and new_status:
                    try:
                        # Update alert status in database
                        alert = db.query(Alert).filter(Alert.id == alert_id).first()
                        if alert:
                            alert.status = new_status
                            alert.updated_at = datetime.utcnow()
                            db.commit()
                            
                            # Broadcast the update to all connected users
                            await self.broadcast_alert_update(alert, db)
                            
                            await self._send_to_user(user_id, {
                                "type": "alert_status_updated",
                                "data": {
                                    "alert_id": alert_id,
                                    "status": new_status
                                }
                            })
                        else:
                            await self._send_to_user(user_id, {
                                "type": "error",
                                "data": {"message": f"Alert {alert_id} not found"}
                            })
                    except Exception as e:
                        await self._send_to_user(user_id, {
                            "type": "error",
                            "data": {"message": str(e)}
                        })
                else:
                    await self._send_to_user(user_id, {
                        "type": "error",
                        "data": {"message": "alert_id and status required for update_alert_status"}
                    })
            
            elif message_type == "get_alert_details":
                # Handle getting detailed alert information
                alert_id = message.get("data", {}).get("alert_id")
                if alert_id:
                    try:
                        alert = db.query(Alert).options(
                            joinedload(Alert.assigned_analyst)
                        ).filter(Alert.id == alert_id).first()
                        
                        if alert:
                            alert_dict = create_alert_response_dict(alert)
                            
                            await self._send_to_user(user_id, {
                                "type": "alert_details",
                                "data": alert_dict
                            })
                        else:
                            await self._send_to_user(user_id, {
                                "type": "error",
                                "data": {"message": f"Alert {alert_id} not found"}
                            })
                    except Exception as e:
                        await self._send_to_user(user_id, {
                            "type": "error",
                            "data": {"message": str(e)}
                        })
                else:
                    await self._send_to_user(user_id, {
                        "type": "error",
                        "data": {"message": "alert_id required for get_alert_details"}
                    })
            
            else:
                logger.warning(f"Unknown message type: {message_type}")
                
        except Exception as e:
            logger.error(f"Error handling message: {e}")
            await self._send_to_user(user_id, {
                "type": "error",
                "data": {"message": str(e)}
            })

# Global WebSocket manager instance
websocket_manager = IncidentWebSocketManager()

async def websocket_endpoint(websocket: WebSocket):
    """Main WebSocket endpoint for incident updates"""
    user = None
    db = None
    
    try:
        # Get database session
        db = next(get_db())
        
        # Get token from query parameters
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=4001, reason="Authentication required")
            return
        
        try:
            # Decode and validate JWT token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            # Validate required claims
            username = payload.get("sub")
            token_type = payload.get("type")
            exp = payload.get("exp")
            
            if not username:
                await websocket.close(code=4001, reason="Invalid token: missing subject")
                return
                
            if token_type != "access":
                await websocket.close(code=4001, reason="Invalid token: wrong token type")
                return
            
            # Check if token is expired (redundant but explicit)
            if exp and datetime.utcnow().timestamp() > exp:
                await websocket.close(code=4001, reason="Token expired")
                return
            
            # Get user from database
            user = db.query(User).filter(User.username == username).first()
            if not user:
                await websocket.close(code=4001, reason="User not found")
                return
            
            # Check if user account is active and not locked
            if not user.is_active:
                await websocket.close(code=4001, reason="User account is inactive")
                return
                
            if user.is_account_locked:
                await websocket.close(code=4001, reason="User account is locked")
                return
                
        except jwt.ExpiredSignatureError:
            await websocket.close(code=4001, reason="Token expired")
            return
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token for WebSocket: {str(e)}")
            await websocket.close(code=4001, reason="Invalid token")
            return
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            await websocket.close(code=4003, reason="Authentication error")
            return
        
        # Connect to WebSocket manager
        await websocket_manager.connect(websocket, user, db)
        
        # Handle incoming messages
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)
                await websocket_manager.handle_message(user.id, message, db)
                
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "data": {"message": "Invalid JSON"}
                }))
            except Exception as e:
                logger.error(f"WebSocket message handling error: {e}")
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "data": {"message": "Internal error"}
                }))
                
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
        try:
            await websocket.close(code=4003, reason="Internal server error")
        except:
            pass
    finally:
        if user:
            await websocket_manager.disconnect(user.id)
        if db:
            db.close()

async def cleanup_connections_task():
    """Background task to clean up stale connections"""
    while True:
        try:
            await asyncio.sleep(60)  # Run every minute
            
            current_time = datetime.utcnow()
            stale_connections = []
            
            for user_id, connection_info in websocket_manager.active_connections.items():
                last_ping = connection_info.get("last_ping")
                if last_ping and (current_time - last_ping).total_seconds() > 300:  # 5 minutes
                    stale_connections.append(user_id)
            
            # Disconnect stale connections
            for user_id in stale_connections:
                logger.info(f"Disconnecting stale connection for user {user_id}")
                await websocket_manager.disconnect(user_id)
                
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")
            await asyncio.sleep(60)  # Wait before retrying