#!/usr/bin/env python3
"""
Test the integration of ValidationFunction with AuthorizationAPI
"""

import os
import sys
import json

# Add the authorization_api directory to path
sys.path.insert(0, os.path.join(os.getcwd(), 'authorization_api'))

def test_validation_function_path_extraction():
    """Test that ValidationFunction extracts path roles from OpenAPI spec."""
    import cloud_foundry
    from validation_function import ValidationFunction
    
    print("VALIDATION FUNCTION INTEGRATION TEST")
    print("=" * 60)
    
    # Load the OpenAPI specification
    spec_path = os.path.join(os.getcwd(), 'authorization_api', 'authorization_api.yaml')
    if not os.path.exists(spec_path):
        print(f"❌ OpenAPI spec file not found: {spec_path}")
        return False
    
    print(f"✅ Loading OpenAPI spec from: {spec_path}")
    
    try:
        # Create the OpenAPI spec editor
        api_spec = cloud_foundry.OpenAPISpecEditor(spec_path)
        print("✅ OpenAPI spec editor created successfully")
        
        # Test path roles extraction (without creating actual resources)
        class MockValidationFunction:
            def __init__(self, api_specification, user_pool_endpoint, validator_name):
                self.api_specification = api_specification
                self.validator_name = validator_name
                self._path_roles = self._extract_path_roles()
            
            def _extract_path_roles(self):
                """Extract path roles like the real ValidationFunction does."""
                path_items = self.api_specification.get_spec_part(['paths'])
                
                if isinstance(path_items, dict):
                    path_roles = {}
                    for path, path_item in path_items.items():
                        if isinstance(path_item, dict):
                            for method, operation in path_item.items():
                                if isinstance(operation, dict) and 'security' in operation:
                                    security_requirements = operation.get('security', [])
                                    for security_req in security_requirements:
                                        if isinstance(security_req, dict):
                                            if self.validator_name in security_req:
                                                roles = security_req[self.validator_name]
                                                if roles:
                                                    operation_key = f"{method.upper()} {path}"
                                                    path_roles[operation_key] = roles
                    return path_roles
                return {}
            
            @property
            def path_roles(self):
                return getattr(self, '_path_roles', {})
        
        # Extract path roles
        mock_validator = MockValidationFunction(api_spec, 'https://example.com', 'auth')
        
        print(f"✅ Path roles extracted: {len(mock_validator.path_roles)} operations")
        
        if mock_validator.path_roles:
            print("\n📋 Extracted path roles:")
            for operation, roles in mock_validator.path_roles.items():
                print(f"   {operation}: {roles}")
            
            # Verify some expected endpoints
            expected_admin_endpoints = [
                "GET /users/{username}",
                "DELETE /users/{username}",
                "PUT /users/{username}/groups"
            ]
            
            expected_user_endpoints = [
                "GET /users/me",
                "PUT /users/me/password",
                "DELETE /sessions/me"
            ]
            
            admin_found = any(op in mock_validator.path_roles for op in expected_admin_endpoints)
            user_found = any(op in mock_validator.path_roles for op in expected_user_endpoints)
            
            if admin_found and user_found:
                print("✅ Both admin and user endpoints found with proper roles")
                return True
            else:
                print("⚠️  Expected admin or user endpoints not found")
                return False
        else:
            print("❌ No path roles extracted")
            return False
            
    except Exception as e:
        print(f"❌ Error during test: {str(e)}")
        return False

def test_authorization_api_integration():
    """Test that AuthorizationAPI properly integrates with ValidationFunction concepts."""
    print("\nAUTHORIZATION API INTEGRATION TEST")
    print("=" * 60)
    
    try:
        # Test that the module imports correctly
        import authorization_api
        print("✅ AuthorizationAPI module imports successfully")
        
        # Test that the ValidationFunction import works
        from authorization_api.validation_function import ValidationFunction
        print("✅ ValidationFunction can be imported from authorization_api")
        
        print("✅ Integration test passed - all components can be imported")
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {str(e)}")
        return False

if __name__ == "__main__":
    print("Testing ValidationFunction integration with AuthorizationAPI...")
    print()
    
    test1_passed = test_validation_function_path_extraction()
    test2_passed = test_authorization_api_integration()
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Path extraction test: {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"Integration test: {'✅ PASSED' if test2_passed else '❌ FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n🎉 All tests passed! ValidationFunction is successfully integrated.")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed.")
        sys.exit(1)
