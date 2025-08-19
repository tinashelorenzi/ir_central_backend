# IR Central Backend

A comprehensive Incident Response Central Management System built with FastAPI, providing robust authentication, user management, and security features.

## Features

### Authentication & Security
- **JWT-based authentication** with access and refresh tokens
- **Role-based access control** (Analyst, Senior Analyst, Manager, Admin)
- **Multi-factor authentication (MFA)** with TOTP support
- **Password reset** functionality
- **Session management** with device tracking
- **Account lockout** protection against brute force attacks
- **Login attempt logging** for security monitoring

### User Management
- **User registration and management** (Admin only)
- **User profile management**
- **Preference settings** (theme, notifications, dashboard)
- **Active session monitoring**
- **Password change functionality**

### Security Features
- **Password strength validation**
- **Secure password hashing** with bcrypt
- **CORS middleware** for cross-origin requests
- **Comprehensive error handling**
- **Audit trail** for user actions

### Real-time Features
- **WebSocket integration** for real-time alert updates
- **Live incident notifications** to connected frontend users
- **Real-time alert broadcasting** when new alerts are created
- **Instant status updates** when alerts are modified
- **WebSocket authentication** with JWT tokens

## Quick Start

### Prerequisites
- Python 3.8+
- PostgreSQL database
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ir_central_backend
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file in the root directory:
   ```env
   DATABASE_URL=postgresql://username:password@localhost/ir_central
   SECRET_KEY=your-super-secret-key-change-this-in-production
   ACCESS_TOKEN_EXPIRE_MINUTES=30
   REFRESH_TOKEN_EXPIRE_DAYS=7
   DEBUG=True
   ```

5. **Set up database**
   - Create a PostgreSQL database named `ir_central`
   - Update the `DATABASE_URL` in your `.env` file
   - The application will automatically create tables on startup

6. **Run the application**
   ```bash
   python main.py
   ```
   
   Or using uvicorn directly:
   ```bash
   uvicorn main:app --host 0.0.0.0 --port 8000 --reload
   ```

7. **Access the API**
   - API Documentation: http://localhost:8000/docs
   - Health Check: http://localhost:8000/health
   - Root Endpoint: http://localhost:8000/
   - WebSocket Endpoint: ws://localhost:8000/ws/incidents

## API Endpoints

### Authentication Endpoints

#### POST `/api/v1/auth/login`
Authenticate user and get JWT tokens.

**Request:**
```json
{
  "username": "admin",
  "password": "SecurePass123!"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user_info": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "full_name": "Administrator",
    "role": "admin",
    "department": "IT",
    "is_verified": true,
    "mfa_enabled": false
  }
}
```

#### POST `/api/v1/auth/refresh`
Refresh access token using refresh token.

#### POST `/api/v1/auth/logout`
Logout current user session.

#### POST `/api/v1/auth/logout-all`
Logout from all active sessions.

### User Management Endpoints

#### GET `/api/v1/auth/me`
Get current user profile.

#### PUT `/api/v1/auth/me/password`
Change user password.

#### PUT `/api/v1/auth/me/preferences`
Update user preferences.

#### GET `/api/v1/auth/sessions`
Get all active sessions for current user.

### Admin Endpoints

#### GET `/api/v1/auth/users`
Get all users (Admin only).

#### POST `/api/v1/auth/users`
Create new user (Admin only).

#### PUT `/api/v1/auth/users/{user_id}`
Update user (Admin only).

#### DELETE `/api/v1/auth/users/{user_id}`
Delete user (Admin only).

#### GET `/api/v1/auth/login-attempts`
Get login attempts (Manager/Admin only).

### MFA Endpoints

#### POST `/api/v1/auth/mfa/setup`
Setup MFA for user account.

#### POST `/api/v1/auth/mfa/verify`
Verify MFA setup and enable it.

#### POST `/api/v1/auth/mfa/disable`
Disable MFA for user account.

### Password Reset Endpoints

#### POST `/api/v1/auth/password-reset`
Request password reset token.

#### POST `/api/v1/auth/password-reset/confirm`
Confirm password reset with token.

### WebSocket Endpoints

#### WebSocket `/ws/incidents`
Real-time incident and alert updates.

**Connection:**
```
ws://localhost:8000/ws/incidents?token=your-jwt-token
```

**Message Types:**
- `new_alert`: New alert created
- `alert_updated`: Alert status/assignment updated
- `incident_created`: New incident created
- `incident_updated`: Incident status updated
- `initial_data`: Initial data sent on connection

**Example Usage:**
```javascript
const ws = new WebSocket(`ws://localhost:8000/ws/incidents?token=${token}`);

ws.onmessage = function(event) {
  const message = JSON.parse(event.data);
  if (message.type === 'new_alert') {
    console.log('New alert:', message.data);
  }
};
```

## User Roles

### Analyst
- Basic incident response capabilities
- View assigned incidents
- Update incident status

### Senior Analyst
- All Analyst permissions
- Can approve actions
- Modify playbooks
- Access to advanced features

### Manager
- All Senior Analyst permissions
- Full incident oversight
- Reporting access
- User management (limited)

### Admin
- Full system access
- User management
- System configuration
- Security monitoring

## Security Features

### Password Requirements
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit

### Account Protection
- Account lockout after 5 failed login attempts
- 30-minute lockout duration
- Automatic unlock after lockout period

### Session Management
- JWT access tokens (30-minute expiry)
- Refresh tokens (7-day expiry)
- Session tracking with IP and user agent
- Ability to revoke individual sessions

### MFA Support
- TOTP-based authentication
- QR code generation for easy setup
- Backup codes for account recovery
- Compatible with Google Authenticator, Authy, etc.

## Database Schema

The application uses the following main tables:

- **users**: User accounts and profiles
- **user_sessions**: Active user sessions
- **login_attempts**: Login attempt logging

## Development

### Project Structure
```
ir_central_backend/
├── main.py                 # FastAPI application entry point
├── database.py             # Database configuration
├── auth_utils.py           # Authentication utilities
├── schemas.py              # Pydantic schemas
├── config.py               # Configuration settings
├── models/
│   ├── users.py            # User models and utilities
│   ├── alert.py            # Alert models
│   └── incident.py         # Incident models
├── routes/
│   └── alert.py            # Alert API routes
├── siem_routes/
│   └── auth.py             # Authentication API routes
├── ws/
│   └── incidents.py        # WebSocket incident management
├── requirements.txt        # Python dependencies
├── WEBSOCKET_ALERT_INTEGRATION.md  # WebSocket integration docs
├── test_websocket_alerts.py        # WebSocket testing script
└── README.md              # This file
```

### Adding New Features

1. **Create new models** in the `models/` directory
2. **Add schemas** in `schemas.py`
3. **Create API routes** in `siem_routes/` directory
4. **Update main.py** to include new routers

### Testing

The API includes comprehensive error handling and validation. Test endpoints using:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Postman** or similar API testing tools

## Production Deployment

### Security Considerations
1. **Change default SECRET_KEY** in production
2. **Configure proper CORS origins**
3. **Use HTTPS** in production
4. **Set up proper database credentials**
5. **Configure email settings** for password reset
6. **Set DEBUG=False** in production

### Environment Variables
```env
DATABASE_URL=postgresql://user:password@host:port/database
SECRET_KEY=your-production-secret-key
DEBUG=False
CORS_ORIGINS=https://yourdomain.com,https://api.yourdomain.com
```

### Docker Deployment
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue in the repository or contact the development team.
