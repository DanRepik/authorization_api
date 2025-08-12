#!/usr/bin/env python3
"""
Simple test script to verify the path authorization logic.
"""

import os
import sys
import json
import logging

# Add the authorization_api module to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'authorization_api'))

# Set up environment variables for testing
os.environ['PATH_ROLES'] = json.dumps({
    "GET /users/{username}": ["admin"],
    "PUT /users/{username}/groups": ["admin"], 
    "GET /users": ["admin", "member"],
    "POST /users": ["admin"]
})

os.environ['ISSUER'] = 'https://cognito-idp.us-east-1.amazonaws.com/test-pool'
os.environ['LOGGING_LEVEL'] = 'DEBUG'

import validator_lambda

# Set up logging
logging.basicConfig(level=logging.DEBUG)

def test_path_authorization():
    """Test the path authorization logic."""
    
    # Test case 1: Admin user accessing admin-only endpoint
    print("\n=== Test 1: Admin user accessing GET /users/john ===")
    method_arn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/GET/users/john"
    decoded_token = {
        "sub": "admin-user-123",
        "cognito:groups": ["admin"],
        "username": "admin"
    }
    
    try:
        validator_lambda.check_path_authorization(method_arn, decoded_token)
        print("✅ Authorization successful for admin user")
    except Exception as e:
        print(f"❌ Authorization failed: {e}")
    
    # Test case 2: Regular user accessing admin-only endpoint (should fail)
    print("\n=== Test 2: Regular user accessing PUT /users/john/groups ===")
    method_arn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/PUT/users/john/groups"
    decoded_token = {
        "sub": "regular-user-123", 
        "cognito:groups": ["member"],
        "username": "regular"
    }
    
    try:
        validator_lambda.check_path_authorization(method_arn, decoded_token)
        print("❌ Authorization should have failed for regular user")
    except Exception as e:
        print(f"✅ Authorization correctly failed: {e}")
    
    # Test case 3: Member user accessing member-allowed endpoint
    print("\n=== Test 3: Member user accessing GET /users ===")
    method_arn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/GET/users"
    decoded_token = {
        "sub": "member-user-123",
        "cognito:groups": ["member"],
        "username": "member"
    }
    
    try:
        validator_lambda.check_path_authorization(method_arn, decoded_token)
        print("✅ Authorization successful for member user")
    except Exception as e:
        print(f"❌ Authorization failed: {e}")
    
    # Test case 4: Path without role requirements
    print("\n=== Test 4: Accessing endpoint without role requirements ===")
    method_arn = "arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/GET/public"
    decoded_token = {
        "sub": "any-user-123",
        "cognito:groups": [],
        "username": "anyone"
    }
    
    try:
        validator_lambda.check_path_authorization(method_arn, decoded_token)
        print("✅ Authorization successful for unrestricted endpoint")
    except Exception as e:
        print(f"❌ Authorization failed: {e}")

def test_path_matching():
    """Test the path matching logic."""
    print("\n=== Testing Path Matching Logic ===")
    
    test_cases = [
        ("/users/{username}", "/users/john", True),
        ("/users/{username}", "/users/jane", True),
        ("/users/{username}/groups", "/users/john/groups", True),
        ("/users", "/users", True),
        ("/users/{username}", "/posts/123", False),
        ("/api/v1/users/{id}", "/api/v1/users/123", True),
    ]
    
    for pattern, actual, expected in test_cases:
        result = validator_lambda.path_matches(pattern, actual)
        status = "✅" if result == expected else "❌"
        print(f"{status} Pattern: {pattern} | Actual: {actual} | Expected: {expected} | Got: {result}")

if __name__ == "__main__":
    print("Testing Path Authorization Logic")
    print("=" * 50)
    
    test_path_matching()
    test_path_authorization()
    
    print("\n" + "=" * 50)
    print("Test completed")
