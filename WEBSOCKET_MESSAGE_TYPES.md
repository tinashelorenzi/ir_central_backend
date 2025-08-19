# WebSocket Message Types

This document describes all the WebSocket message types supported by the IR Central Backend WebSocket system.

## Connection

### Authentication
- **URL**: `ws://localhost:8000/ws/incidents?token=your-jwt-token`
- **Token**: JWT access token required for authentication

## Client to Server Messages

### 1. Ping/Pong
```json
{
  "type": "ping"
}
```
**Response:**
```json
{
  "type": "pong"
}
```

### 2. Get Owned Incidents
```json
{
  "type": "get_owned_incidents"
}
```
**Response:**
```json
{
  "type": "owned_incidents",
  "data": {
    "incidents": [...]
  }
}
```

### 3. Get Recent Alerts
```json
{
  "type": "get_recent_alerts"
}
```
**Response:**
```json
{
  "type": "recent_alerts",
  "data": {
    "alerts": [...]
  }
}
```

### 4. Take Alert Ownership
```json
{
  "type": "take_alert_ownership",
  "data": {
    "alert_id": 123
  }
}
```
**Alternative format:**
```json
{
  "type": "take_ownership",
  "data": {
    "alert_id": 123
  }
}
```
**Response:**
```json
{
  "type": "alert_ownership_taken",
  "data": {
    "alert_id": 123,
    "incident": {...}  // New incident if created, null if assigned to existing
  }
}
```

### 5. Update Alert Status
```json
{
  "type": "update_alert_status",
  "data": {
    "alert_id": 123,
    "status": "in_progress"
  }
}
```
**Response:**
```json
{
  "type": "alert_status_updated",
  "data": {
    "alert_id": 123,
    "status": "in_progress"
  }
}
```

### 6. Get Alert Details
```json
{
  "type": "get_alert_details",
  "data": {
    "alert_id": 123
  }
}
```
**Response:**
```json
{
  "type": "alert_details",
  "data": {
    // Full alert object
  }
}
```

## Server to Client Messages

### 1. New Alert
```json
{
  "type": "new_alert",
  "data": {
    // Alert object
  }
}
```

### 2. Alert Updated
```json
{
  "type": "alert_updated",
  "data": {
    // Updated alert object
  }
}
```

### 3. Incident Created
```json
{
  "type": "incident_created",
  "data": {
    // Incident object
  }
}
```

### 4. Incident Updated
```json
{
  "type": "incident_updated",
  "data": {
    // Updated incident object
  }
}
```

### 5. Initial Data (sent on connection)
```json
{
  "type": "initial_data",
  "data": {
    "user": {...},
    "recent_incidents": [...],
    "recent_alerts": [...]
  }
}
```

### 6. Error Messages
```json
{
  "type": "error",
  "data": {
    "message": "Error description"
  }
}
```

## Alert Status Values

- `new` - Newly created alert
- `in_progress` - Alert is being investigated
- `resolved` - Alert has been resolved
- `false_positive` - Alert was a false positive
- `escalated` - Alert has been escalated to incident

## Example Usage

### JavaScript Client Example
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/incidents?token=' + jwtToken);

ws.onopen = function() {
  console.log('WebSocket connected');
  
  // Get recent alerts
  ws.send(JSON.stringify({
    type: 'get_recent_alerts'
  }));
};

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);
  
  switch(message.type) {
    case 'new_alert':
      console.log('New alert received:', message.data);
      break;
      
    case 'alert_updated':
      console.log('Alert updated:', message.data);
      break;
      
    case 'recent_alerts':
      console.log('Recent alerts:', message.data.alerts);
      break;
      
    case 'error':
      console.error('WebSocket error:', message.data.message);
      break;
  }
};

// Take ownership of an alert
function takeAlertOwnership(alertId) {
  ws.send(JSON.stringify({
    type: 'take_ownership',
    data: {
      alert_id: alertId
    }
  }));
}

// Update alert status
function updateAlertStatus(alertId, status) {
  ws.send(JSON.stringify({
    type: 'update_alert_status',
    data: {
      alert_id: alertId,
      status: status
    }
  }));
}
```

## Error Handling

All WebSocket messages that fail will return an error response:
```json
{
  "type": "error",
  "data": {
    "message": "Specific error message"
  }
}
```

Common error scenarios:
- Missing required fields in message data
- Invalid alert_id or incident_id
- Database errors
- Authentication/permission errors

## Best Practices

1. **Always handle errors**: Check for error responses in your client code
2. **Use ping/pong**: Implement heartbeat to detect connection issues
3. **Reconnect on disconnect**: Implement automatic reconnection logic
4. **Validate data**: Always validate message data before processing
5. **Rate limiting**: Don't send messages too frequently to avoid overwhelming the server

## Troubleshooting

### Common Issues

1. **"Unknown message type"**: Check that you're using one of the supported message types
2. **Authentication errors**: Ensure your JWT token is valid and not expired
3. **Missing data**: Verify all required fields are present in your message
4. **Connection drops**: Implement reconnection logic in your client

### Debug Mode

Enable debug logging in the backend to see detailed WebSocket activity:
```python
logging.getLogger('ws.incidents').setLevel(logging.DEBUG)
```
