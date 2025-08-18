# IR Central Playbook API Documentation

## Overview

The IR Central Playbook API provides a comprehensive system for managing incident response playbooks, executions, and templates. This system enables organizations to create flexible, JSON-defined playbooks that can be executed for specific incidents.

## Features

- **Flexible Playbook Definition**: JSON-based playbook structure supporting multiple phases and step types
- **Execution Tracking**: Complete tracking of playbook executions with progress monitoring
- **Template System**: Reusable templates for common incident types
- **User Input Collection**: Dynamic data collection during playbook execution
- **Step Logging**: Detailed logging of each step execution
- **Report Generation**: Automated report generation from playbook data

## Database Schema

### Core Tables

1. **ir_playbooks**: Main playbook definitions
2. **playbook_executions**: Instances of playbook executions
3. **step_execution_logs**: Individual step execution records
4. **playbook_user_inputs**: User-provided data during execution
5. **playbook_templates**: Reusable playbook templates

## API Endpoints

### Playbook Management

#### Create Playbook
```http
POST /api/v1/playbooks/
```

**Request Body:**
```json
{
  "name": "Malware Response Playbook",
  "description": "Standard response for malware incidents",
  "version": "1.0",
  "status": "active",
  "tags": ["malware", "infection"],
  "severity_levels": ["high", "critical"],
  "alert_sources": ["snort", "yara"],
  "matching_criteria": {
    "alert_title_contains": ["malware", "trojan"],
    "confidence_threshold": 0.8
  },
  "playbook_definition": {
    "metadata": {
      "name": "Malware Response",
      "estimated_duration": 120
    },
    "phases": [...]
  },
  "report_template": "# Incident Report\n...",
  "estimated_duration_minutes": 120,
  "requires_approval": true,
  "auto_assign": true,
  "priority_score": 8
}
```

#### List Playbooks
```http
GET /api/v1/playbooks/?search=malware&status=active&page=1&size=20
```

**Query Parameters:**
- `search`: Search in name and description
- `status`: Filter by status (draft, active, deprecated, archived)
- `tags`: Comma-separated tags to filter by
- `severity_levels`: Comma-separated severity levels
- `alert_sources`: Comma-separated alert sources
- `created_by_id`: Filter by creator
- `page`: Page number (default: 1)
- `size`: Items per page (default: 20, max: 100)

#### Get Playbook
```http
GET /api/v1/playbooks/{playbook_id}
```

#### Update Playbook
```http
PUT /api/v1/playbooks/{playbook_id}
```

#### Delete Playbook
```http
DELETE /api/v1/playbooks/{playbook_id}
```

### Playbook Execution

#### Start Execution
```http
POST /api/v1/playbooks/executions
```

**Request Body:**
```json
{
  "playbook_id": 1,
  "alert_id": 123,
  "incident_id": "INC-2025-001",
  "assigned_analyst_id": 5
}
```

#### List Executions
```http
GET /api/v1/playbooks/executions/?playbook_id=1&execution_status=in_progress&page=1&size=20
```

**Query Parameters:**
- `playbook_id`: Filter by playbook ID
- `execution_status`: Filter by status (in_progress, completed, failed, paused)
- `assigned_analyst_id`: Filter by assigned analyst
- `incident_id`: Filter by incident ID
- `started_after`: Filter executions started after this date
- `started_before`: Filter executions started before this date
- `page`: Page number (default: 1)
- `size`: Items per page (default: 20, max: 100)

#### Get Execution
```http
GET /api/v1/playbooks/executions/{execution_id}
```

#### Update Execution
```http
PUT /api/v1/playbooks/executions/{execution_id}
```

**Request Body:**
```json
{
  "current_phase": "containment",
  "current_step_index": 2,
  "execution_status": "in_progress",
  "completed_steps": 5,
  "progress_percentage": 50.0
}
```

### Step Execution Logs

#### Create Step Log
```http
POST /api/v1/playbooks/executions/{execution_id}/steps
```

**Request Body:**
```json
{
  "phase_name": "containment",
  "step_name": "isolate_systems",
  "step_type": "manual_action",
  "step_index": 1,
  "status": "completed",
  "success": true,
  "output_data": {
    "systems_isolated": ["SERVER-01", "WORKSTATION-05"],
    "isolation_method": "network_acl"
  },
  "requires_manual_action": false
}
```

#### List Step Logs
```http
GET /api/v1/playbooks/executions/{execution_id}/steps
```

### User Inputs

#### Create User Input
```http
POST /api/v1/playbooks/executions/{execution_id}/inputs
```

**Request Body:**
```json
{
  "phase_name": "initial_assessment",
  "step_name": "collect_basic_info",
  "field_name": "affected_systems",
  "field_type": "textarea",
  "user_input": {
    "value": "SERVER-01, WORKSTATION-05, 192.168.1.100"
  },
  "input_label": "List affected systems (hostnames/IPs)",
  "is_required": true
}
```

#### List User Inputs
```http
GET /api/v1/playbooks/executions/{execution_id}/inputs
```

### Templates

#### Create Template
```http
POST /api/v1/playbooks/templates
```

**Request Body:**
```json
{
  "name": "Malware Response Template",
  "category": "malware_response",
  "description": "Template for malware incident response",
  "template_definition": {
    "metadata": {...},
    "phases": [...]
  },
  "default_tags": ["malware", "infection"],
  "is_official": true
}
```

#### List Templates
```http
GET /api/v1/playbooks/templates/?category=malware_response&is_official=true&page=1&size=20
```

**Query Parameters:**
- `category`: Filter by category
- `is_official`: Filter by official status
- `search`: Search in name and description
- `page`: Page number (default: 1)
- `size`: Items per page (default: 20, max: 100)

#### Get Template
```http
GET /api/v1/playbooks/templates/{template_id}
```

#### Update Template
```http
PUT /api/v1/playbooks/templates/{template_id}
```

#### Delete Template
```http
DELETE /api/v1/playbooks/templates/{template_id}
```

#### Create Playbook from Template
```http
POST /api/v1/playbooks/templates/{template_id}/create-playbook?playbook_name=My Malware Response
```

### Utility Endpoints

#### Get Available Statuses
```http
GET /api/v1/playbooks/statuses
```

#### Get Step Types
```http
GET /api/v1/playbooks/step-types
```

#### Get Input Field Types
```http
GET /api/v1/playbooks/input-field-types
```

#### Get Template Categories
```http
GET /api/v1/playbooks/categories
```

## Playbook Definition Structure

### JSON Schema

```json
{
  "metadata": {
    "name": "Playbook Name",
    "description": "Playbook description",
    "version": "1.0",
    "estimated_duration": 120
  },
  "phases": [
    {
      "name": "phase_name",
      "title": "Phase Title",
      "description": "Phase description",
      "steps": [
        {
          "name": "step_name",
          "title": "Step Title",
          "type": "step_type",
          "description": "Step description",
          "required": true,
          "inputs": [...],
          "automation": {...},
          "instructions": "Manual instructions",
          "requires_approval": true,
          "estimated_minutes": 15
        }
      ]
    }
  ],
  "report_template": "Markdown template with placeholders"
}
```

### Step Types

- `automated_action`: Run script/API call automatically
- `manual_action`: Human performs task, marks complete
- `user_input`: Collect data from responder
- `approval`: Requires manager/senior approval
- `notification`: Send alerts to stakeholders
- `artifact_collection`: Gather evidence
- `analysis`: Review collected data
- `decision_point`: Branching logic based on conditions
- `report_generation`: Generate section of final report

### Input Field Types

- `text`: Single line text input
- `textarea`: Multi-line text input
- `number`: Numeric input
- `date`: Date picker
- `datetime`: Date and time picker
- `select`: Dropdown selection
- `multiselect`: Multiple selection
- `checkbox`: Boolean checkbox
- `file_upload`: File upload
- `ip_address`: IP address input
- `url`: URL input
- `email`: Email address input

## Authentication

All endpoints require authentication using JWT tokens. Include the token in the Authorization header:

```http
Authorization: Bearer <your_jwt_token>
```

## Error Handling

The API returns standard HTTP status codes:

- `200`: Success
- `201`: Created
- `400`: Bad Request
- `401`: Unauthorized
- `403`: Forbidden
- `404`: Not Found
- `422`: Validation Error
- `500`: Internal Server Error

Error responses include a detail message:

```json
{
  "error": "Error message",
  "detail": "Additional error details",
  "success": false
}
```

## Pagination

List endpoints return paginated responses:

```json
{
  "items": [...],
  "total": 100,
  "page": 1,
  "size": 20,
  "pages": 5
}
```

## Setup Instructions

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Database**
   Set the `DATABASE_URL` environment variable or update the default in `database.py`

3. **Create Database Tables**
   ```bash
   python create_playbook_tables.py
   ```

4. **Start the Server**
   ```bash
   python main.py
   ```

5. **Access API Documentation**
   Visit `http://localhost:8000/docs` for interactive API documentation

## Example Usage

### Creating a Playbook

```python
import requests

# Create a new playbook
playbook_data = {
    "name": "Ransomware Response",
    "description": "Response procedure for ransomware incidents",
    "status": "active",
    "tags": ["ransomware", "encryption"],
    "playbook_definition": {
        "metadata": {
            "name": "Ransomware Response",
            "estimated_duration": 180
        },
        "phases": [
            {
                "name": "containment",
                "title": "Containment",
                "steps": [
                    {
                        "name": "isolate_network",
                        "title": "Isolate Network",
                        "type": "manual_action",
                        "description": "Isolate affected network segments"
                    }
                ]
            }
        ]
    }
}

response = requests.post(
    "http://localhost:8000/api/v1/playbooks/",
    json=playbook_data,
    headers={"Authorization": f"Bearer {token}"}
)

playbook = response.json()
```

### Starting an Execution

```python
# Start a playbook execution
execution_data = {
    "playbook_id": playbook["id"],
    "incident_id": "INC-2025-001",
    "assigned_analyst_id": 1
}

response = requests.post(
    "http://localhost:8000/api/v1/playbooks/executions",
    json=execution_data,
    headers={"Authorization": f"Bearer {token}"}
)

execution = response.json()
```

### Recording Step Progress

```python
# Record step completion
step_data = {
    "phase_name": "containment",
    "step_name": "isolate_network",
    "step_type": "manual_action",
    "step_index": 0,
    "status": "completed",
    "success": True,
    "output_data": {
        "networks_isolated": ["192.168.1.0/24"],
        "isolation_time": "2025-01-15T10:30:00Z"
    }
}

response = requests.post(
    f"http://localhost:8000/api/v1/playbooks/executions/{execution['id']}/steps",
    json=step_data,
    headers={"Authorization": f"Bearer {token}"}
)
```

## Frontend Integration

The API is designed to be easily consumed by frontend applications. Key integration points:

1. **Playbook Builder**: Use the playbook definition structure to create a visual playbook builder
2. **Execution Dashboard**: Display execution progress using the execution endpoints
3. **Step Interface**: Create dynamic forms based on step input definitions
4. **Report Generation**: Use the report template and execution data to generate final reports

## Security Considerations

- All endpoints require authentication
- Admin-only operations are protected with role-based access control
- Input validation is performed on all endpoints
- SQL injection protection through SQLAlchemy ORM
- JWT token expiration and refresh mechanisms

## Performance Considerations

- Pagination implemented for all list endpoints
- Database indexes on frequently queried fields
- Efficient JSON storage for flexible playbook definitions
- Caching can be implemented for frequently accessed templates

## Troubleshooting

### Common Issues

1. **Database Connection**: Ensure `DATABASE_URL` is correctly configured
2. **Authentication**: Verify JWT token is valid and not expired
3. **Validation Errors**: Check request body against schema requirements
4. **Permission Errors**: Ensure user has required role for admin operations

### Debug Mode

Enable debug logging by setting the `DEBUG` environment variable:

```bash
export DEBUG=1
python main.py
```

## Contributing

When adding new features:

1. Update the database models in `models/playbook.py`
2. Add corresponding schemas in `schemas.py`
3. Implement API endpoints in `siem_routes/playbooks.py`
4. Update this documentation
5. Add tests for new functionality
