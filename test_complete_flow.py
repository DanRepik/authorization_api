#!/usr/bin/env python3
"""
Test showing the complete flow: OpenAPI spec -> extraction -> API Gateway deployment
"""

import json

def test_complete_flow():
    """Test the complete flow from OpenAPI spec to final deployment."""
    
    print("COMPLETE FLOW TEST")
    print("=" * 60)
    
    # 1. Original OpenAPI spec as it would be written by developers
    original_spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "security": [{"auth": ["admin", "member"]}]
                },
                "post": {
                    "summary": "Create user", 
                    "security": [{"auth": ["admin"]}]
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user",
                    "security": [{"auth": ["admin", "member"]}]
                },
                "delete": {
                    "summary": "Delete user",
                    "security": [{"auth": ["admin"]}]
                }
            },
            "/public": {
                "get": {
                    "summary": "Public endpoint"
                    # No security - anyone can access
                }
            }
        }
    }
    
    print("1. ORIGINAL OPENAPI SPEC (as written by developers):")
    print(json.dumps(original_spec, indent=2))
    
    # 2. Simulate extraction process
    print(f"\n{'='*60}")
    print("2. EXTRACTION PROCESS:")
    print("="*60)
    
    extracted_roles = {}
    paths = original_spec["paths"]
    
    for path, path_item in paths.items():
        for method, operation in path_item.items():
            if "security" in operation:
                for security_req in operation["security"]:
                    if "auth" in security_req:
                        roles = security_req["auth"]
                        if roles:
                            operation_key = f"{method.upper()} {path}"
                            extracted_roles[operation_key] = roles
                            print(f"Extracted: {operation_key} -> {roles}")
                        
                        # Clear roles but keep validator
                        security_req["auth"] = []
    
    print(f"\nTotal operations with role requirements: {len(extracted_roles)}")
    
    # 3. Show the modified OpenAPI spec that goes to API Gateway
    print(f"\n{'='*60}")
    print("3. MODIFIED OPENAPI SPEC (deployed to API Gateway):")
    print("="*60)
    print(json.dumps(original_spec, indent=2))
    
    # 4. Show the PATH_ROLES that go to the Lambda
    print(f"\n{'='*60}")
    print("4. PATH_ROLES ENVIRONMENT VARIABLE (sent to Lambda):")
    print("="*60)
    print(json.dumps(extracted_roles, indent=2))
    
    # 5. Simulate what happens at runtime
    print(f"\n{'='*60}")
    print("5. RUNTIME BEHAVIOR:")
    print("="*60)
    
    test_requests = [
        ("GET", "/users", ["admin"], "✅ ALLOWED"),
        ("GET", "/users", ["member"], "✅ ALLOWED"), 
        ("GET", "/users", ["guest"], "❌ DENIED"),
        ("POST", "/users", ["admin"], "✅ ALLOWED"),
        ("POST", "/users", ["member"], "❌ DENIED"),
        ("DELETE", "/users/{id}", ["admin"], "✅ ALLOWED"),
        ("DELETE", "/users/{id}", ["member"], "❌ DENIED"),
        ("GET", "/public", ["guest"], "✅ ALLOWED (no auth required)"),
    ]
    
    for method, path, user_groups, expected in test_requests:
        operation_key = f"{method} {path}"
        required_roles = extracted_roles.get(operation_key, [])
        
        if not required_roles:
            # No auth required
            result = "✅ ALLOWED (no auth required)"
        else:
            # Check if user has required roles
            has_access = bool(set(user_groups).intersection(set(required_roles)))
            result = "✅ ALLOWED" if has_access else "❌ DENIED"
        
        print(f"{method:<6} {path:<15} | User groups: {str(user_groups):<15} | Required: {str(required_roles):<15} | {result}")
    
    print(f"\n{'='*60}")
    print("KEY BENEFITS:")
    print("="*60)
    print("✅ API Gateway still calls the 'auth' validator for all protected endpoints")
    print("✅ Lambda gets only the role requirements (no OpenAPI parsing needed)")
    print("✅ Role-based authorization happens in the Lambda validator")
    print("✅ Clean separation between API Gateway integration and business logic")
    print("✅ Multiple validators can be used in the same API")

if __name__ == "__main__":
    test_complete_flow()
