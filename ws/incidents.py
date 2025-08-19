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
                    "owned_incidents": [incident.dict() for incident in owned_incidents],
                    "connection_time": datetime.utcnow().isoformat()
                }
            })
            
            # Send recent unassigned alerts
            recent_alerts = await self._get_recent_alerts(db, limit=50)
            await self._send_to_user(user_id, {
                "type": "recent_alerts",
                "data": {
                    "alerts": [alert.dict() for alert in recent_alerts]
                }
            })
            
        except Exception as e:
            logger.error(f"Error sending initial data to user {user_id}: {e}")
    
    async def _get_user_owned_incidents(self, user_id: int, db: Session) -> List[IncidentResponse]:
        """Get incidents owned by user"""
        incidents = db.query(Incident).filter(
            Incident.owner_id == user_id,
            Incident.status != IncidentStatus.CLOSED
        ).options(
            joinedload(Incident.owner),
            joinedload(Incident.assigned_analyst)
        ).order_by(desc(Incident.created_at)).all()
        
        return [IncidentResponse.from_orm(incident) for incident in incidents]
    
    async def _get_recent_alerts(self, db: Session, limit: int = 50) -> List[AlertResponse]:
        """Get recent alerts that could become incidents"""
        alerts = db.query(Alert).filter(
            Alert.status.in_([AlertStatus.NEW, AlertStatus.TRIAGED]),
            Alert.assigned_analyst_id.is_(None)
        ).options(
            joinedload(Alert.assigned_analyst)
        ).order_by(desc(Alert.received_at)).limit(limit).all()
        
        return [AlertResponse.from_orm(alert) for alert in alerts]
    
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
        alert_data = AlertResponse.from_orm(alert)
        message = {
            "type": "new_alert",
            "data": alert_data.dict()
        }
        
        # Send to all connected users
        for user_id in list(self.active_connections.keys()):
            await self._send_to_user(user_id, message)
    
    async def broadcast_alert_update(self, alert: Alert, db: Session):
        """Broadcast alert update (status change, assignment, etc.)"""
        alert_data = AlertResponse.from_orm(alert)
        message = {
            "type": "alert_updated",
            "data": alert_data.dict()
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
            "data": incident_data.dict()
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
                        "incident": incident_data.dict()
                    }
                })
    
    async def broadcast_incident_update(self, incident: Incident, db: Session):
        """Broadcast incident updates to watchers"""
        incident_data = IncidentResponse.from_orm(incident)
        message = {
            "type": "incident_updated",
            "data": incident_data.dict()
        }
        
        await self._broadcast_to_watchers(incident.id, message)
    
    async def handle_message(self, user_id: int, message: dict, db: Session):
        """Handle incoming WebSocket messages"""
        try:
            message_type = message.get("type")
            data = message.get("data", {})
            
            if message_type == "ping":
                # Update last ping time
                if user_id in self.active_connections:
                    self.active_connections[user_id]["last_ping"] = datetime.utcnow()
                await self._send_to_user(user_id, {"type": "pong"})
            
            elif message_type == "take_ownership":
                alert_id = data.get("alert_id")
                if not alert_id:
                    raise ValueError("alert_id is required")
                
                incident = await self.handle_take_ownership(alert_id, user_id, db)
                await self._send_to_user(user_id, {
                    "type": "ownership_taken",
                    "data": {
                        "success": True,
                        "incident_id": incident.id,
                        "incident": IncidentResponse.from_orm(incident).dict()
                    }
                })
            
            elif message_type == "watch_incident":
                incident_id = data.get("incident_id")
                if incident_id:
                    if incident_id not in self.incident_watchers:
                        self.incident_watchers[incident_id] = set()
                    self.incident_watchers[incident_id].add(user_id)
            
            elif message_type == "unwatch_incident":
                incident_id = data.get("incident_id")
                if incident_id and incident_id in self.incident_watchers:
                    self.incident_watchers[incident_id].discard(user_id)
                    if not self.incident_watchers[incident_id]:
                        del self.incident_watchers[incident_id]
            
            elif message_type == "get_owned_incidents":
                owned_incidents = await self._get_user_owned_incidents(user_id, db)
                await self._send_to_user(user_id, {
                    "type": "owned_incidents",
                    "data": {
                        "incidents": [incident.dict() for incident in owned_incidents]
                    }
                })
            
            elif message_type == "get_recent_alerts":
                recent_alerts = await self._get_recent_alerts(db)
                await self._send_to_user(user_id, {
                    "type": "recent_alerts",
                    "data": {
                        "alerts": [alert.dict() for alert in recent_alerts]
                    }
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
        
        # Authenticate user (you may need to implement token-based auth)
        # For now, we'll use a simple approach - you can enhance this
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=4001, reason="Authentication required")
            return
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username:
                await websocket.close(code=4001, reason="Invalid token")
                return
            
            user = db.query(User).filter(User.username == username).first()
            if not user:
                await websocket.close(code=4001, reason="User not found")
                return
                
        except jwt.PyJWTError:
            await websocket.close(code=4001, reason="Invalid token")
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
                logger.error(f"WebSocket error: {e}")
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "data": {"message": "Internal error"}
                }))
                
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
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