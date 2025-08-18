#!/usr/bin/env python3
"""
Script to create an initial admin user for the IR Central system.
Run this script after setting up the database to create your first admin user.
"""

import sys
import os
from sqlalchemy.orm import Session

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import SessionLocal, engine, Base
from models.users import User, UserManager, UserRole
from config import settings

def create_admin_user():
    """Create an initial admin user"""
    
    # Create tables if they don't exist
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        # Check if admin user already exists
        existing_admin = db.query(User).filter(User.role == UserRole.ADMIN).first()
        if existing_admin:
            print(f"Admin user already exists: {existing_admin.username}")
            return
        
        # Get admin details from user input
        print("Creating initial admin user for IR Central...")
        print("-" * 50)
        
        username = input("Enter admin username: ").strip()
        if not username:
            print("Username cannot be empty!")
            return
        
        email = input("Enter admin email: ").strip()
        if not email:
            print("Email cannot be empty!")
            return
        
        full_name = input("Enter admin full name: ").strip()
        if not full_name:
            print("Full name cannot be empty!")
            return
        
        password = input("Enter admin password: ").strip()
        if len(password) < 8:
            print("Password must be at least 8 characters long!")
            return
        
        department = input("Enter department (optional): ").strip() or None
        
        # Check if username or email already exists
        existing_user = db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            print("User with this username or email already exists!")
            return
        
        # Create admin user
        admin_user = UserManager.create_user(
            username=username,
            email=email,
            password=password,
            full_name=full_name,
            role=UserRole.ADMIN,
            department=department
        )
        
        # Set as verified
        admin_user.is_verified = True
        admin_user.created_by = "system"
        
        db.add(admin_user)
        db.commit()
        
        print("\n" + "=" * 50)
        print("✅ Admin user created successfully!")
        print("=" * 50)
        print(f"Username: {username}")
        print(f"Email: {email}")
        print(f"Full Name: {full_name}")
        print(f"Role: {UserRole.ADMIN}")
        print(f"Department: {department or 'Not specified'}")
        print("\nYou can now log in to the system using these credentials.")
        print("Access the API at: http://localhost:8000/docs")
        
    except Exception as e:
        print(f"Error creating admin user: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_admin_user()
