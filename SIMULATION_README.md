# Alert Simulation Script

This script simulates realistic alert generation for testing the IR Central Backend system, including WebSocket integration.

## Features

- **Realistic Alert Generation**: Creates alerts based on common security event templates
- **Configurable Timing**: Adjustable intervals between alerts with realistic variations
- **Multiple Alert Types**: 10 different alert types with weighted distribution
- **Burst Mode**: Rapid alert generation for intensive testing
- **Comprehensive Logging**: Detailed logs with statistics
- **API Token Integration**: Uses the provided API token for authentication

## Alert Types

The script generates alerts based on these security event templates:

1. **Suspicious Login Attempt** (25% weight) - Failed login attempts
2. **Malware Detection** (15% weight) - Malware signature matches
3. **Data Exfiltration Attempt** (10% weight) - Large data transfers
4. **Privilege Escalation** (12% weight) - Administrative access attempts
5. **Network Scan Detected** (20% weight) - Port scanning activity
6. **Ransomware Activity** (8% weight) - File encryption patterns
7. **Phishing Email Detected** (18% weight) - Suspicious emails
8. **Database Access Violation** (12% weight) - Unauthorized DB access
9. **Web Application Attack** (14% weight) - SQL injection attempts
10. **Insider Threat Activity** (16% weight) - Unusual user behavior

## Usage

### Basic Usage

```bash
# Run for 1 hour with 60-second intervals
python simulate_alerts.py

# Run for 5 minutes with 30-second intervals
python simulate_alerts.py --duration 300 --interval 30

# Test API connection first
python simulate_alerts.py --test-connection
```

### Advanced Usage

```bash
# Burst mode for rapid testing (5-15 second intervals)
python simulate_alerts.py --burst-mode --duration 120

# Long-term simulation (2 hours with 2-minute intervals)
python simulate_alerts.py --duration 7200 --interval 120

# Quick test (1 minute with 10-second intervals)
python simulate_alerts.py --duration 60 --interval 10
```

### Command Line Options

- `--duration`: Duration in seconds (default: 3600)
- `--interval`: Base interval between alerts in seconds (default: 60)
- `--burst-mode`: Enable rapid alert generation for testing
- `--test-connection`: Test API connection and exit

## Configuration

The script uses the following configuration:

- **API Base URL**: `http://localhost:8000`
- **API Token**: `2d9ae96c914e0203945941db1935919c2dcd9bf3f54c37d91833983bf8714ea9`
- **Endpoint**: `/api/v1/alerts/single`

## Realistic Features

### Timing Variations
- Random intervals with ±30% variation
- Occasional longer delays (10% chance) to simulate quiet periods
- Burst mode for intensive testing scenarios

### Network Data
- Realistic internal/external IP addresses
- Common ports and protocols
- Varied hostnames and usernames
- Asset criticality levels

### Alert Distribution
- Weighted selection based on real-world frequency
- Unique external alert IDs
- Realistic threat types and sources

## Testing Scenarios

### 1. Basic WebSocket Testing
```bash
# Start the backend server
python main.py

# In another terminal, run simulation
python simulate_alerts.py --duration 300 --interval 30

# Connect WebSocket client to see real-time updates
```

### 2. High-Volume Testing
```bash
# Burst mode for high-volume testing
python simulate_alerts.py --burst-mode --duration 60
```

### 3. Long-Term Stability Testing
```bash
# Run for extended period
python simulate_alerts.py --duration 7200 --interval 120
```

### 4. Connection Testing
```bash
# Test API connectivity
python simulate_alerts.py --test-connection
```

## Output

The script provides:

1. **Console Output**: Real-time progress and status
2. **Log File**: `alert_simulation.log` with detailed logs
3. **Final Statistics**: Summary of simulation results

### Sample Output
```
🚀 Starting alert simulation for 300 seconds
📊 Base interval: 30s, Burst mode: False
🔑 Using API token: 2d9ae96c914e0203945941db1935919c2dcd9bf3f54c37d91833983bf8714ea9
✅ Alert sent successfully: Suspicious Login Attempt (ID: 123)
⏱️  Next alert in 28s (Elapsed: 32s, Remaining: 268s)
```

### Final Statistics
```
📊 SIMULATION COMPLETE - FINAL STATISTICS
⏱️  Total Duration: 300.1 seconds
📨 Total Alerts Generated: 10
✅ Successful Alerts: 10
❌ Failed Alerts: 0
📈 Alerts per minute: 2.00
🎯 Success Rate: 100.0%
```

## Integration with WebSocket Testing

To test the complete system:

1. **Start the backend server**:
   ```bash
   python main.py
   ```

2. **Connect a WebSocket client**:
   ```javascript
   const ws = new WebSocket('ws://localhost:8000/ws/incidents?token=your-jwt-token');
   ws.onmessage = function(event) {
     const message = JSON.parse(event.data);
     if (message.type === 'new_alert') {
       console.log('New alert received:', message.data);
     }
   };
   ```

3. **Run the simulation**:
   ```bash
   python simulate_alerts.py --duration 300 --interval 30
   ```

4. **Observe real-time updates** in your WebSocket client

## Troubleshooting

### Common Issues

1. **Connection Refused**: Ensure the backend server is running
2. **Authentication Error**: Verify the API token is valid
3. **Rate Limiting**: Reduce frequency if hitting rate limits
4. **Database Errors**: Check database connectivity

### Debug Mode

Enable debug logging by modifying the script:
```python
logging.basicConfig(level=logging.DEBUG, ...)
```

## Performance Considerations

- **Memory Usage**: Minimal memory footprint
- **Network Load**: Configurable to avoid overwhelming the API
- **Database Load**: Realistic alert volumes
- **WebSocket Load**: Tests real-time broadcasting capabilities

## Security Notes

- The script uses the provided API token for authentication
- All alerts are marked as simulated/test data
- No real security events are generated
- Safe for testing environments

## Customization

You can customize the script by:

1. **Adding new alert templates** in the `alert_templates` list
2. **Modifying IP ranges** for different network environments
3. **Adjusting timing patterns** for different scenarios
4. **Adding new threat types** and sources

## Support

For issues or questions:
1. Check the log file for detailed error messages
2. Verify API connectivity with `--test-connection`
3. Ensure the backend server is running and accessible
4. Check database connectivity and permissions
