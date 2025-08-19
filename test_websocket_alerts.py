#!/usr/bin/env python3
"""
Test script for WebSocket alert integration
This script tests the real-time alert broadcasting functionality
"""

import asyncio
import json
import websockets
import requests
import time
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws/incidents"

# Test credentials (you'll need to create a test user first)
TEST_USERNAME = "testuser"
TEST_PASSWORD = "testpass123"

class WebSocketAlertTester:
    def __init__(self):
        self.token = None
        self.websocket = None
        self.received_messages = []
        
    async def authenticate(self):
        """Authenticate and get JWT token"""
        try:
            # Login to get token
            login_data = {
                "username": TEST_USERNAME,
                "password": TEST_PASSWORD
            }
            
            response = requests.post(f"{BASE_URL}/api/v1/auth/login", json=login_data)
            response.raise_for_status()
            
            data = response.json()
            self.token = data.get("access_token")
            
            if not self.token:
                raise Exception("No access token received")
                
            print(f"✅ Authenticated successfully")
            return True
            
        except Exception as e:
            print(f"❌ Authentication failed: {e}")
            return False
    
    async def connect_websocket(self):
        """Connect to WebSocket"""
        try:
            uri = f"{WS_URL}?token={self.token}"
            self.websocket = await websockets.connect(uri)
            print(f"✅ Connected to WebSocket")
            return True
            
        except Exception as e:
            print(f"❌ WebSocket connection failed: {e}")
            return False
    
    async def listen_for_messages(self, duration=30):
        """Listen for WebSocket messages"""
        print(f"🔍 Listening for messages for {duration} seconds...")
        
        try:
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    message = await asyncio.wait_for(self.websocket.recv(), timeout=1.0)
                    data = json.loads(message)
                    self.received_messages.append(data)
                    print(f"📨 Received: {data.get('type', 'unknown')}")
                    
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    print(f"❌ Error receiving message: {e}")
                    break
                    
        except Exception as e:
            print(f"❌ Error in message listening: {e}")
    
    async def create_test_alert(self):
        """Create a test alert via API"""
        try:
            # Create endpoint token first (if needed)
            # For this test, we'll use the single alert endpoint
            
            alert_data = {
                "external_alert_id": f"test_alert_{int(time.time())}",
                "title": "Test WebSocket Alert",
                "description": "This is a test alert to verify WebSocket integration",
                "severity": "medium",
                "source": "test_system",
                "threat_type": "malware",
                "detected_at": datetime.utcnow().isoformat(),
                "source_system": "test_integration",
                "rule_id": "TEST_001",
                "rule_name": "Test Rule",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "affected_hostname": "test-host-01"
            }
            
            headers = {"Authorization": f"Bearer {self.token}"}
            
            # Note: This would require a valid endpoint token
            # For testing, you might need to create one first
            print("⚠️  Note: Creating test alert requires valid endpoint token")
            print(f"📤 Alert data prepared: {alert_data['title']}")
            
            return alert_data
            
        except Exception as e:
            print(f"❌ Error creating test alert: {e}")
            return None
    
    async def update_test_alert(self, alert_id):
        """Update a test alert via API"""
        try:
            update_data = {
                "status": "investigating",
                "assigned_analyst_id": 1,  # Assuming user ID 1 exists
                "investigation_notes": "Test investigation via WebSocket"
            }
            
            headers = {"Authorization": f"Bearer {self.token}"}
            
            response = requests.put(
                f"{BASE_URL}/api/v1/alerts/{alert_id}",
                json=update_data,
                headers=headers
            )
            response.raise_for_status()
            
            print(f"✅ Updated alert {alert_id}")
            return True
            
        except Exception as e:
            print(f"❌ Error updating alert: {e}")
            return False
    
    def analyze_results(self):
        """Analyze the received messages"""
        print("\n📊 Analysis of received messages:")
        print(f"Total messages received: {len(self.received_messages)}")
        
        message_types = {}
        for msg in self.received_messages:
            msg_type = msg.get('type', 'unknown')
            message_types[msg_type] = message_types.get(msg_type, 0) + 1
        
        for msg_type, count in message_types.items():
            print(f"  - {msg_type}: {count}")
        
        # Check for specific message types
        has_new_alert = any(msg.get('type') == 'new_alert' for msg in self.received_messages)
        has_alert_updated = any(msg.get('type') == 'alert_updated' for msg in self.received_messages)
        has_initial_data = any(msg.get('type') == 'initial_data' for msg in self.received_messages)
        
        print(f"\n✅ WebSocket Integration Status:")
        print(f"  - Initial data received: {'Yes' if has_initial_data else 'No'}")
        print(f"  - New alert messages: {'Yes' if has_new_alert else 'No'}")
        print(f"  - Alert update messages: {'Yes' if has_alert_updated else 'No'}")
        
        if has_initial_data and (has_new_alert or has_alert_updated):
            print("🎉 WebSocket alert integration is working correctly!")
        else:
            print("⚠️  Some expected messages were not received")
    
    async def run_test(self):
        """Run the complete test"""
        print("🚀 Starting WebSocket Alert Integration Test")
        print("=" * 50)
        
        # Step 1: Authenticate
        if not await self.authenticate():
            return
        
        # Step 2: Connect to WebSocket
        if not await self.connect_websocket():
            return
        
        # Step 3: Listen for initial messages
        print("\n📡 Listening for initial messages...")
        await asyncio.sleep(5)
        
        # Step 4: Create test alert (if possible)
        print("\n📝 Creating test alert...")
        alert_data = await self.create_test_alert()
        
        # Step 5: Listen for alert messages
        print("\n📡 Listening for alert messages...")
        await self.listen_for_messages(10)
        
        # Step 6: Cleanup
        if self.websocket:
            await self.websocket.close()
        
        # Step 7: Analyze results
        self.analyze_results()

async def main():
    """Main test function"""
    tester = WebSocketAlertTester()
    await tester.run_test()

if __name__ == "__main__":
    print("WebSocket Alert Integration Test")
    print("Make sure the backend server is running on localhost:8000")
    print("You may need to create a test user first")
    print()
    
    asyncio.run(main())
