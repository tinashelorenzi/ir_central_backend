# WebSocket Alert Integration

This document explains how the WebSocket integration works for real-time alert updates in the IR Central Backend.

## Overview

The system now provides real-time updates to connected frontend users when alerts are created or updated. This is achieved through WebSocket connections that broadcast alert events to all connected clients.

## How It Works

### 1. Alert Creation Flow

When an alert is created via either:
- `/api/v1/alerts/ingest` (bulk SIEM ingestion)
- `/api/v1/alerts/single` (single alert creation)

The following happens:

1. Alert is saved to the database
2. Background task `process_new_alerts()` is scheduled for processing
3. **NEW**: Background task `broadcast_new_alerts_websocket()` is scheduled
4. WebSocket manager broadcasts the new alert to all connected users

### 2. Alert Update Flow

When an alert is updated via:
- `/api/v1/alerts/{alert_id}` (PUT endpoint)

The following happens:

1. Alert is updated in the database
2. **NEW**: Background task `broadcast_alert_update_websocket()` is scheduled
3. WebSocket manager broadcasts the alert update to all connected users

### 3. WebSocket Message Types

The frontend will receive the following message types:

#### New Alert
```json
{
  "type": "new_alert",
  "data": {
    "id": 123,
    "title": "Suspicious Login Attempt",
    "severity": "high",
    "status": "new",
    "source": "SIEM",
    // ... other alert fields
  }
}
```

#### Alert Updated
```json
{
  "type": "alert_updated",
  "data": {
    "id": 123,
    "title": "Suspicious Login Attempt",
    "severity": "high",
    "status": "investigating",
    "assigned_analyst_id": 456,
    // ... other alert fields
  }
}
```

## Frontend Integration

### Connecting to WebSocket

```javascript
// Connect to WebSocket with JWT token
const token = "your-jwt-token";
const ws = new WebSocket(`ws://localhost:8000/ws/incidents?token=${token}`);

ws.onopen = function() {
  console.log('Connected to incident WebSocket');
};

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);
  
  switch(message.type) {
    case 'new_alert':
      // Handle new alert
      console.log('New alert received:', message.data);
      // Update UI to show new alert
      break;
      
    case 'alert_updated':
      // Handle alert update
      console.log('Alert updated:', message.data);
      // Update UI to reflect changes
      break;
      
    case 'initial_data':
      // Handle initial data sent on connection
      console.log('Initial data:', message.data);
      break;
      
    case 'pong':
      // Handle ping/pong for connection health
      break;
      
    default:
      console.log('Unknown message type:', message.type);
  }
};

ws.onclose = function(event) {
  console.log('WebSocket closed:', event.code, event.reason);
  // Implement reconnection logic
};

ws.onerror = function(error) {
  console.error('WebSocket error:', error);
};
```

### Handling Alert Updates

When receiving alert updates, the frontend should:

1. **Update alert lists**: Refresh or update any alert lists/dashboards
2. **Show notifications**: Display toast notifications for new alerts
3. **Update counters**: Update alert count badges/indicators
4. **Refresh details**: If viewing a specific alert that was updated, refresh the details

## Error Handling

### WebSocket Connection Issues

- The WebSocket will close with specific error codes:
  - `4001`: Authentication required or invalid token
  - `4003`: Internal server error

### Background Task Failures

- WebSocket broadcasting failures are logged but don't affect the main alert creation/update flow
- Database session management is handled properly in background tasks

## Configuration

### Rate Limiting

The WebSocket system includes rate limiting for alert broadcasts to prevent overwhelming connected clients.

### Connection Management

- Stale connections are automatically cleaned up every 5 minutes
- Users are automatically subscribed to their owned incidents
- Connection health is monitored via ping/pong messages

## Testing

### Manual Testing

1. Start the backend server
2. Connect a WebSocket client to `/ws/incidents` with a valid JWT token
3. Create an alert via the API endpoints
4. Verify the WebSocket receives the `new_alert` message
5. Update an alert via the API
6. Verify the WebSocket receives the `alert_updated` message

### Automated Testing

The WebSocket integration can be tested by:
- Unit testing the background task functions
- Integration testing with a WebSocket client
- End-to-end testing with the full alert creation flow

## Performance Considerations

- WebSocket broadcasting is done asynchronously in background tasks
- Database sessions are properly managed and closed
- Connection cleanup prevents memory leaks
- Rate limiting prevents broadcast storms

## Security

- WebSocket connections require valid JWT authentication
- Token validation includes expiration and user status checks
- Users only receive updates for alerts they have access to
- IP restrictions and rate limiting apply to alert creation endpoints
