#!/usr/bin/env python3
"""
Alert Simulation Script

This script simulates real-world alert generation by making API calls to the
single alerts endpoint at realistic intervals. It's designed to test the entire
system including WebSocket integration.

Usage:
    python simulate_alerts.py [--duration 3600] [--interval 30-120] [--burst-mode]
"""

import asyncio
import json
import random
import time
import argparse
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import requests
from dataclasses import dataclass
import signal
import sys

# Configuration
API_BASE_URL = "http://localhost:8000"
API_TOKEN = "2d9ae96c914e0203945941db1935919c2dcd9bf3f54c37d91833983bf8714ea9"
SINGLE_ALERT_ENDPOINT = f"{API_BASE_URL}/api/v1/alerts/single"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('alert_simulation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AlertTemplate:
    """Template for generating realistic alerts"""
    title: str
    description: str
    severity: str
    source: str
    threat_type: str
    rule_id: str
    rule_name: str
    weight: int  # Higher weight = more likely to be selected

class AlertSimulator:
    """Simulates realistic alert generation"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {API_TOKEN}",
            "Content-Type": "application/json"
        })
        
        # Alert templates based on common security events
        self.alert_templates = [
            AlertTemplate(
                title="Suspicious Login Attempt",
                description="Multiple failed login attempts detected from unusual location",
                severity="medium",
                source="SIEM",
                threat_type="credential_access",
                rule_id="LOGIN_001",
                rule_name="Failed Login Detection",
                weight=25
            ),
            AlertTemplate(
                title="Malware Detection",
                description="Suspicious file detected with known malware signatures",
                severity="high",
                source="EDR",
                threat_type="malware",
                rule_id="MALWARE_001",
                rule_name="Malware Signature Match",
                weight=15
            ),
            AlertTemplate(
                title="Data Exfiltration Attempt",
                description="Large data transfer detected to external destination",
                severity="critical",
                source="DLP",
                threat_type="data_exfiltration",
                rule_id="DLP_001",
                rule_name="Data Exfiltration Detection",
                weight=10
            ),
            AlertTemplate(
                title="Privilege Escalation",
                description="User attempting to access administrative functions",
                severity="high",
                source="SIEM",
                threat_type="privilege_escalation",
                rule_id="PRIV_001",
                rule_name="Privilege Escalation Detection",
                weight=12
            ),
            AlertTemplate(
                title="Network Scan Detected",
                description="Port scanning activity detected from external source",
                severity="medium",
                source="IDS",
                threat_type="reconnaissance",
                rule_id="SCAN_001",
                rule_name="Network Scan Detection",
                weight=20
            ),
            AlertTemplate(
                title="Ransomware Activity",
                description="File encryption patterns consistent with ransomware",
                severity="critical",
                source="EDR",
                threat_type="ransomware",
                rule_id="RANSOM_001",
                rule_name="Ransomware Behavior Detection",
                weight=8
            ),
            AlertTemplate(
                title="Phishing Email Detected",
                description="Suspicious email with malicious links or attachments",
                severity="medium",
                source="Email_Security",
                threat_type="phishing",
                rule_id="PHISH_001",
                rule_name="Phishing Email Detection",
                weight=18
            ),
            AlertTemplate(
                title="Database Access Violation",
                description="Unauthorized access attempt to sensitive database",
                severity="high",
                source="DB_Monitor",
                threat_type="data_access",
                rule_id="DB_001",
                rule_name="Database Access Control",
                weight=12
            ),
            AlertTemplate(
                title="Web Application Attack",
                description="SQL injection attempt detected on web application",
                severity="high",
                source="WAF",
                threat_type="web_attack",
                rule_id="WAF_001",
                rule_name="Web Application Firewall",
                weight=14
            ),
            AlertTemplate(
                title="Insider Threat Activity",
                description="Unusual data access patterns by internal user",
                severity="medium",
                source="UEBA",
                threat_type="insider_threat",
                rule_id="UEBA_001",
                rule_name="User Behavior Analytics",
                weight=16
            )
        ]
        
        # IP ranges for realistic source/destination
        self.internal_ips = [
            "192.168.1.10", "192.168.1.15", "192.168.1.20", "192.168.1.25",
            "192.168.1.30", "192.168.1.35", "192.168.1.40", "192.168.1.45",
            "10.0.0.10", "10.0.0.15", "10.0.0.20", "10.0.0.25"
        ]
        
        self.external_ips = [
            "203.0.113.10", "203.0.113.20", "203.0.113.30", "203.0.113.40",
            "198.51.100.10", "198.51.100.20", "198.51.100.30", "198.51.100.40",
            "45.67.89.10", "45.67.89.20", "45.67.89.30", "45.67.89.40"
        ]
        
        self.hostnames = [
            "workstation-01", "workstation-02", "workstation-03", "workstation-04",
            "server-web-01", "server-web-02", "server-db-01", "server-db-02",
            "laptop-user-01", "laptop-user-02", "laptop-user-03", "laptop-user-04"
        ]
        
        self.usernames = [
            "john.doe", "jane.smith", "bob.wilson", "alice.johnson",
            "admin", "service_account", "guest", "test_user"
        ]
        
        self.stats = {
            "total_alerts": 0,
            "successful_alerts": 0,
            "failed_alerts": 0,
            "start_time": None,
            "last_alert_time": None
        }
        
        self.running = False
    
    def generate_alert_data(self) -> Dict[str, Any]:
        """Generate realistic alert data based on templates"""
        # Select template based on weights
        total_weight = sum(template.weight for template in self.alert_templates)
        rand_val = random.randint(1, total_weight)
        
        current_weight = 0
        selected_template = None
        
        for template in self.alert_templates:
            current_weight += template.weight
            if rand_val <= current_weight:
                selected_template = template
                break
        
        if not selected_template:
            selected_template = self.alert_templates[0]
        
        # Generate unique external alert ID
        timestamp = int(time.time())
        random_suffix = random.randint(1000, 9999)
        external_alert_id = f"{selected_template.rule_id}_{timestamp}_{random_suffix}"
        
        # Determine if this should be internal or external source
        is_external = random.random() < 0.3  # 30% chance of external source
        
        if is_external:
            source_ip = random.choice(self.external_ips)
            dest_ip = random.choice(self.internal_ips)
        else:
            source_ip = random.choice(self.internal_ips)
            dest_ip = random.choice(self.external_ips) if random.random() < 0.5 else random.choice(self.internal_ips)
        
        # Generate alert data
        alert_data = {
            "external_alert_id": external_alert_id,
            "title": selected_template.title,
            "description": selected_template.description,
            "severity": selected_template.severity,
            "source": selected_template.source,
            "threat_type": selected_template.threat_type,
            "detected_at": datetime.utcnow().isoformat(),
            "source_system": selected_template.source,
            "rule_id": selected_template.rule_id,
            "rule_name": selected_template.rule_name,
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "source_port": random.randint(1024, 65535),
            "destination_port": random.choice([80, 443, 22, 3389, 1433, 3306]),
            "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS"]),
            "affected_hostname": random.choice(self.hostnames),
            "affected_user": random.choice(self.usernames),
            "asset_criticality": random.choice(["low", "medium", "high", "critical"])
        }
        
        return alert_data
    
    async def send_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Send a single alert to the API"""
        try:
            response = self.session.post(
                SINGLE_ALERT_ENDPOINT,
                json=alert_data,
                timeout=10
            )
            
            if response.status_code == 201:
                alert_response = response.json()
                logger.info(f"✅ Alert sent successfully: {alert_data['title']} (ID: {alert_response.get('id', 'N/A')})")
                self.stats["successful_alerts"] += 1
                return True
            else:
                logger.error(f"❌ Failed to send alert: {response.status_code} - {response.text}")
                self.stats["failed_alerts"] += 1
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Request error sending alert: {e}")
            self.stats["failed_alerts"] += 1
            return False
        except Exception as e:
            logger.error(f"❌ Unexpected error sending alert: {e}")
            self.stats["failed_alerts"] += 1
            return False
    
    def calculate_interval(self, base_interval: int, burst_mode: bool = False) -> int:
        """Calculate realistic interval between alerts"""
        if burst_mode:
            # Burst mode: rapid alerts for testing
            return random.randint(5, 15)
        
        # Normal mode: realistic intervals
        # Add some randomness to make it more realistic
        variation = random.uniform(0.7, 1.3)
        interval = int(base_interval * variation)
        
        # Occasionally add longer delays (simulating quiet periods)
        if random.random() < 0.1:  # 10% chance
            interval += random.randint(60, 300)
        
        return max(5, interval)  # Minimum 5 seconds
    
    async def simulate_alerts(self, duration: int, base_interval: int, burst_mode: bool = False):
        """Main simulation loop"""
        self.running = True
        self.stats["start_time"] = datetime.utcnow()
        
        logger.info(f"🚀 Starting alert simulation for {duration} seconds")
        logger.info(f"📊 Base interval: {base_interval}s, Burst mode: {burst_mode}")
        logger.info(f"🔑 Using API token: {API_TOKEN[:20]}...")
        
        start_time = time.time()
        
        while self.running and (time.time() - start_time) < duration:
            try:
                # Generate and send alert
                alert_data = self.generate_alert_data()
                self.stats["total_alerts"] += 1
                
                success = await self.send_alert(alert_data)
                self.stats["last_alert_time"] = datetime.utcnow()
                
                # Calculate next interval
                interval = self.calculate_interval(base_interval, burst_mode)
                
                # Log progress
                elapsed = time.time() - start_time
                remaining = duration - elapsed
                
                logger.info(f"⏱️  Next alert in {interval}s (Elapsed: {elapsed:.0f}s, Remaining: {remaining:.0f}s)")
                
                # Wait for next alert
                await asyncio.sleep(interval)
                
            except KeyboardInterrupt:
                logger.info("🛑 Simulation interrupted by user")
                break
            except Exception as e:
                logger.error(f"❌ Error in simulation loop: {e}")
                await asyncio.sleep(5)  # Wait before retrying
        
        self.running = False
        self.print_final_stats()
    
    def print_final_stats(self):
        """Print final simulation statistics"""
        if not self.stats["start_time"]:
            return
        
        end_time = datetime.utcnow()
        duration = (end_time - self.stats["start_time"]).total_seconds()
        
        logger.info("=" * 60)
        logger.info("📊 SIMULATION COMPLETE - FINAL STATISTICS")
        logger.info("=" * 60)
        logger.info(f"⏱️  Total Duration: {duration:.1f} seconds")
        logger.info(f"📨 Total Alerts Generated: {self.stats['total_alerts']}")
        logger.info(f"✅ Successful Alerts: {self.stats['successful_alerts']}")
        logger.info(f"❌ Failed Alerts: {self.stats['failed_alerts']}")
        
        if duration > 0:
            alerts_per_minute = (self.stats['successful_alerts'] / duration) * 60
            logger.info(f"📈 Alerts per minute: {alerts_per_minute:.2f}")
        
        success_rate = (self.stats['successful_alerts'] / self.stats['total_alerts'] * 100) if self.stats['total_alerts'] > 0 else 0
        logger.info(f"🎯 Success Rate: {success_rate:.1f}%")
        
        if self.stats['last_alert_time']:
            logger.info(f"🕐 Last Alert Time: {self.stats['last_alert_time']}")
        
        logger.info("=" * 60)

def signal_handler(signum, frame):
    """Handle interrupt signals"""
    logger.info("🛑 Received interrupt signal, stopping simulation...")
    sys.exit(0)

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Simulate realistic alert generation")
    parser.add_argument("--duration", type=int, default=3600, 
                       help="Duration in seconds (default: 3600)")
    parser.add_argument("--interval", type=int, default=60,
                       help="Base interval between alerts in seconds (default: 60)")
    parser.add_argument("--burst-mode", action="store_true",
                       help="Enable burst mode for rapid testing")
    parser.add_argument("--test-connection", action="store_true",
                       help="Test API connection and exit")
    
    args = parser.parse_args()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create simulator
    simulator = AlertSimulator()
    
    # Test connection if requested
    if args.test_connection:
        logger.info("🔍 Testing API connection...")
        try:
            response = simulator.session.get(f"{API_BASE_URL}/health")
            if response.status_code == 200:
                logger.info("✅ API connection successful")
                health_data = response.json()
                logger.info(f"📊 API Status: {health_data}")
            else:
                logger.error(f"❌ API connection failed: {response.status_code}")
                return
        except Exception as e:
            logger.error(f"❌ API connection error: {e}")
            return
        return
    
    # Validate parameters
    if args.duration < 10:
        logger.error("❌ Duration must be at least 10 seconds")
        return
    
    if args.interval < 1:
        logger.error("❌ Interval must be at least 1 second")
        return
    
    # Start simulation
    await simulator.simulate_alerts(args.duration, args.interval, args.burst_mode)

if __name__ == "__main__":
    print("🚀 Alert Simulation Script")
    print("=" * 50)
    print("This script simulates realistic alert generation for testing")
    print("the IR Central Backend system including WebSocket integration.")
    print()
    print("Usage examples:")
    print("  python simulate_alerts.py --duration 300 --interval 30")
    print("  python simulate_alerts.py --burst-mode --duration 60")
    print("  python simulate_alerts.py --test-connection")
    print()
    
    asyncio.run(main())
