#!/usr/bin/env python3
"""
Test the new v                            for security_req in security_requirements:
                                if isinstance(security_req, dict):
                                    # Check if this security requirement uses our validator
                                    if self.validator_name in security_req:
                                        roles = security_req[self.validator_name]
                                        if roles:  # Only if there are actual roles specified
                                            operation_key = f"{method.upper()} {path}"
                                            path_roles[operation_key] = roles
                                            print(f"Extracted roles for {operation_key}: {roles}")
                                        
                                        # Clear the roles but keep the validator with empty array
                                        security_req[self.validator_name] = []cific path role extraction approach.
"""

import json
import logging
from typing import Dict, Any

# Mock OpenAPI spec editor for testing
class MockOpenAPISpecEditor:
    def __init__(self, spec_data):
        self.spec_data = spec_data
    
    def get_spec_part(self, keys):
        result = self.spec_data
        for key in keys:
            if isinstance(result, dict) and key in result:
                result = result[key]
            else:
                return None
        return result

# Mock ValidationFunction for testing
class MockValidationFunction:
    def __init__(self, api_specification, validator_name="auth"):
        self.api_specification = api_specification
        self.validator_name = validator_name
        self._path_roles = {}
    
    def _extract_path_roles(self) -> Dict[str, Any]:
        """Extract role-based security requirements from path operations for this specific validator."""
        path_items = self.api_specification.get_spec_part(['paths'])
        
        if isinstance(path_items, dict):
            path_roles: Dict[str, Any] = {}
            for path, path_item in path_items.items():
                if isinstance(path_item, dict):
                    for method, operation in path_item.items():
                        if isinstance(operation, dict) and 'security' in operation:
                            security_requirements = operation.get('security', [])
                            for security_req in security_requirements:
                                if isinstance(security_req, dict):
                                    # Check if this security requirement uses our validator
                                    if self.validator_name in security_req:
                                        roles = security_req[self.validator_name]
                                        if roles:  # Only if there are actual roles specified
                                            operation_key = f"{method.upper()} {path}"
                                            path_roles[operation_key] = roles
                                            print(f"Extracted roles for {operation_key}: {roles}")
                                        
                                        # Clear the roles but keep the validator in the security requirement
                                        security_req[self.validator_name] = []
                        
            self._path_roles = path_roles
            print(f"Total path roles extracted for validator '{self.validator_name}': {len(path_roles)}")
            return path_roles
        else:
            print("OpenAPI spec 'paths' is not a dictionary. Skipping path roles extraction.")
            self._path_roles = {}
            return {}
    
    @property
    def path_roles(self) -> Dict[str, Any]:
        return self._path_roles

def test_validator_specific_extraction():
    """Test that we only extract roles for the specific validator."""
    
    # Sample OpenAPI spec with multiple validators
    spec_data = {
        "paths": {
            "/users": {
                "get": {
                    "summary": "List users",
                    "security": [
                        {"auth": ["admin", "member"]},  # Our validator
                        {"api_key": []}  # Different validator
                    ]
                },
                "post": {
                    "summary": "Create user", 
                    "security": [
                        {"auth": ["admin"]}  # Our validator only
                    ]
                }
            },
            "/users/{username}": {
                "get": {
                    "summary": "Get user",
                    "security": [
                        {"auth": ["admin"]}  # Our validator
                    ]
                },
                "delete": {
                    "summary": "Delete user",
                    "security": [
                        {"other_auth": ["super_admin"]}  # Different validator
                    ]
                }
            },
            "/public": {
                "get": {
                    "summary": "Public endpoint"
                    # No security requirements
                }
            }
        }
    }
    
    print("Original OpenAPI spec:")
    print(json.dumps(spec_data, indent=2))
    print("\n" + "="*60 + "\n")
    
    # Create mock API spec editor
    api_spec = MockOpenAPISpecEditor(spec_data)
    
    # Test extraction for 'auth' validator
    print("Testing extraction for 'auth' validator:")
    validator = MockValidationFunction(api_spec, validator_name="auth")
    path_roles = validator._extract_path_roles()
    
    print(f"\nExtracted PATH_ROLES for 'auth' validator:")
    print(json.dumps(path_roles, indent=2))
    
    print(f"\nModified OpenAPI spec after extraction:")
    print(json.dumps(spec_data, indent=2))
    
    # Verify expectations
    expected_roles = {
        "GET /users": ["admin", "member"],
        "POST /users": ["admin"], 
        "GET /users/{username}": ["admin"]
    }
    
    print(f"\n" + "="*60)
    print("VERIFICATION:")
    print("="*60)
    
    success = True
    for expected_key, expected_vals in expected_roles.items():
        if expected_key in path_roles:
            if path_roles[expected_key] == expected_vals:
                print(f"✅ {expected_key}: {expected_vals}")
            else:
                print(f"❌ {expected_key}: Expected {expected_vals}, got {path_roles[expected_key]}")
                success = False
        else:
            print(f"❌ {expected_key}: Missing from extracted roles")
            success = False
    
    # Check that other validators' security requirements are preserved
    users_get_security = spec_data["paths"]["/users"]["get"].get("security", [])
    api_key_preserved = any("api_key" in req for req in users_get_security)
    
    if api_key_preserved:
        print("✅ Other validators' security requirements preserved")
    else:
        print("❌ Other validators' security requirements were removed")
        success = False
    
    # Check that 'auth' validator is still present but with empty roles
    auth_present = any("auth" in req for req in users_get_security)
    auth_empty = any(req.get("auth") == [] for req in users_get_security if "auth" in req)
    
    if auth_present and auth_empty:
        print("✅ 'auth' validator present with empty roles array")
    else:
        print("❌ 'auth' validator not correctly preserved with empty roles")
        print(f"   Present: {auth_present}, Empty: {auth_empty}")
        print(f"   Security: {users_get_security}")
        success = False
    
    # Check that endpoints with other validators only are not included
    if "DELETE /users/{username}" not in path_roles:
        print("✅ Endpoints with only other validators correctly excluded")
    else:
        print("❌ Endpoints with only other validators were incorrectly included")
        success = False
    
    print(f"\n{'='*60}")
    if success:
        print("🎉 All tests PASSED!")
    else:
        print("💥 Some tests FAILED!")
    print("="*60)

if __name__ == "__main__":
    test_validator_specific_extraction()
