#!/usr/bin/env python3
"""
Script to create playbook database tables and add sample data
"""

import sys
import os
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import engine, SessionLocal
from models.playbook import (
    IRPlaybook, PlaybookTemplate, PlaybookStatus, StepType, InputFieldType
)
from models.users import User

def create_tables():
    """Create all database tables"""
    print("Creating database tables...")
    
    # Import Base from database to ensure all models are registered
    from database import Base
    Base.metadata.create_all(bind=engine)
    print("✓ Database tables created successfully")

def create_sample_data():
    """Create sample playbook data for testing"""
    print("Creating sample data...")
    
    db = SessionLocal()
    
    try:
        # Check if we have any users
        user = db.query(User).first()
        if not user:
            print("⚠ No users found. Please create a user first using create_admin.py")
            return
        
        # Create sample playbook template
        malware_template = {
            "metadata": {
                "name": "Malware Infection Response",
                "description": "Standard response for confirmed malware infections",
                "version": "2.1",
                "estimated_duration": 120
            },
            "phases": [
                {
                    "name": "initial_assessment",
                    "title": "Initial Assessment",
                    "description": "Gather initial information about the incident",
                    "steps": [
                        {
                            "name": "collect_basic_info",
                            "title": "Collect Basic Information",
                            "type": "user_input",
                            "description": "Gather essential details about the incident",
                            "required": True,
                            "inputs": [
                                {
                                    "name": "affected_systems",
                                    "label": "List affected systems (hostnames/IPs)",
                                    "type": "textarea",
                                    "required": True,
                                    "placeholder": "SERVER-01, WORKSTATION-05, 192.168.1.100"
                                },
                                {
                                    "name": "business_impact",
                                    "label": "Business Impact Assessment",
                                    "type": "select",
                                    "options": ["Low", "Medium", "High", "Critical"],
                                    "required": True
                                },
                                {
                                    "name": "incident_time",
                                    "label": "When was the incident first detected?",
                                    "type": "datetime",
                                    "required": True
                                }
                            ]
                        }
                    ]
                },
                {
                    "name": "containment",
                    "title": "Containment",
                    "description": "Isolate and contain the threat",
                    "steps": [
                        {
                            "name": "isolate_systems",
                            "title": "Isolate Affected Systems",
                            "type": "manual_action",
                            "description": "Network isolate all affected systems to prevent spread",
                            "instructions": "Use network ACLs or physically disconnect systems",
                            "requires_approval": True,
                            "estimated_minutes": 15
                        },
                        {
                            "name": "collect_memory_dump",
                            "title": "Collect Memory Dump",
                            "type": "artifact_collection",
                            "description": "Capture memory dump from primary affected system",
                            "automation": {
                                "tool": "winpmem",
                                "command": "winpmem.exe -o {output_path}",
                                "output_path": "/artifacts/memory_{timestamp}.mem"
                            }
                        }
                    ]
                },
                {
                    "name": "analysis",
                    "title": "Analysis",
                    "description": "Analyze collected evidence",
                    "steps": [
                        {
                            "name": "malware_analysis", 
                            "title": "Analyze Malware Sample",
                            "type": "analysis",
                            "description": "Run YARA rules and analyze collected artifacts",
                            "inputs": [
                                {
                                    "name": "analysis_findings",
                                    "label": "Analysis Results",
                                    "type": "textarea",
                                    "required": True,
                                    "placeholder": "Describe malware family, IOCs, TTPs observed..."
                                }
                            ]
                        }
                    ]
                },
                {
                    "name": "recovery",
                    "title": "Recovery",
                    "description": "Restore systems and implement improvements",
                    "steps": [
                        {
                            "name": "system_restoration",
                            "title": "System Restoration Plan",
                            "type": "user_input",
                            "inputs": [
                                {
                                    "name": "restoration_steps",
                                    "label": "Describe restoration steps taken",
                                    "type": "textarea",
                                    "required": True
                                },
                                {
                                    "name": "preventive_measures",
                                    "label": "Preventive measures implemented",
                                    "type": "textarea",
                                    "required": True
                                }
                            ]
                        }
                    ]
                }
            ],
            "report_template": """
# Malware Incident Response Report

## Incident Overview
- **Incident ID**: {incident_id}
- **Detection Time**: {user_inputs.incident_time}
- **Business Impact**: {user_inputs.business_impact}
- **Affected Systems**: {user_inputs.affected_systems}

## Response Timeline
{execution_timeline}

## Analysis Results
{user_inputs.analysis_findings}

## Recovery Actions
{user_inputs.restoration_steps}

## Preventive Measures
{user_inputs.preventive_measures}

## Artifacts Collected
{artifacts_list}

## Lessons Learned
{lessons_learned}
"""
        }
        
        # Check if template already exists
        existing_template = db.query(PlaybookTemplate).filter(
            PlaybookTemplate.name == "Malware Infection Response Template"
        ).first()
        
        if not existing_template:
            template = PlaybookTemplate(
                name="Malware Infection Response Template",
                category="malware_response",
                description="Standard template for responding to malware infections",
                template_definition=malware_template,
                default_tags=["malware", "infection", "response"],
                is_official=True,
                created_by_id=user.id
            )
            db.add(template)
            print("✓ Created malware response template")
        else:
            print("✓ Malware response template already exists")
        
        # Create sample playbook
        existing_playbook = db.query(IRPlaybook).filter(
            IRPlaybook.name == "Sample Malware Response"
        ).first()
        
        if not existing_playbook:
            playbook = IRPlaybook(
                name="Sample Malware Response",
                description="Sample playbook for malware incident response",
                version="1.0",
                status=PlaybookStatus.ACTIVE,
                tags=["malware", "infection", "sample"],
                severity_levels=["high", "critical"],
                alert_sources=["snort", "yara", "graylog"],
                matching_criteria={
                    "alert_title_contains": ["malware", "trojan", "virus"],
                    "threat_types": ["malware_detected", "suspicious_file"],
                    "confidence_threshold": 0.8
                },
                playbook_definition=malware_template,
                report_template=malware_template["report_template"],
                estimated_duration_minutes=120,
                requires_approval=True,
                auto_assign=True,
                priority_score=8,
                created_by_id=user.id
            )
            db.add(playbook)
            print("✓ Created sample malware response playbook")
        else:
            print("✓ Sample malware response playbook already exists")
        
        # Create phishing template
        phishing_template = {
            "metadata": {
                "name": "Phishing Incident Response",
                "description": "Response procedure for phishing incidents",
                "version": "1.0",
                "estimated_duration": 60
            },
            "phases": [
                {
                    "name": "assessment",
                    "title": "Phishing Assessment",
                    "description": "Assess the phishing incident",
                    "steps": [
                        {
                            "name": "identify_scope",
                            "title": "Identify Affected Users",
                            "type": "user_input",
                            "description": "Identify all users who received the phishing email",
                            "inputs": [
                                {
                                    "name": "affected_users",
                                    "label": "List of affected users",
                                    "type": "textarea",
                                    "required": True
                                },
                                {
                                    "name": "email_subject",
                                    "label": "Phishing email subject",
                                    "type": "text",
                                    "required": True
                                }
                            ]
                        }
                    ]
                },
                {
                    "name": "containment",
                    "title": "Containment",
                    "description": "Contain the phishing threat",
                    "steps": [
                        {
                            "name": "block_sender",
                            "title": "Block Sender Domain",
                            "type": "automated_action",
                            "description": "Block the sender domain in email filters",
                            "automation": {
                                "tool": "email_filter",
                                "command": "block_domain {sender_domain}"
                            }
                        }
                    ]
                }
            ]
        }
        
        existing_phishing_template = db.query(PlaybookTemplate).filter(
            PlaybookTemplate.name == "Phishing Incident Response Template"
        ).first()
        
        if not existing_phishing_template:
            phishing_template_obj = PlaybookTemplate(
                name="Phishing Incident Response Template",
                category="phishing_response",
                description="Template for responding to phishing incidents",
                template_definition=phishing_template,
                default_tags=["phishing", "email", "social_engineering"],
                is_official=True,
                created_by_id=user.id
            )
            db.add(phishing_template_obj)
            print("✓ Created phishing response template")
        else:
            print("✓ Phishing response template already exists")
        
        db.commit()
        print("✓ Sample data created successfully")
        
    except Exception as e:
        print(f"✗ Error creating sample data: {e}")
        db.rollback()
    finally:
        db.close()

def main():
    """Main function"""
    print("=== Playbook Database Setup ===")
    
    try:
        create_tables()
        create_sample_data()
        print("\n=== Setup Complete ===")
        print("You can now start the API server with: python main.py")
        print("API documentation will be available at: http://localhost:8000/docs")
        
    except Exception as e:
        print(f"✗ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
