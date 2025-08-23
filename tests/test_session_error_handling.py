import pytest
import logging
import dotenv
import requests
import uuid
from tests.automation_helpers import deploy_stack
from tests.test_authorization_api import (
    security_services_pulumi, 
    domain, 
    user_pool_id, 
    create_user,
    admin_user,
    user_session
)
import boto3

log = logging.getLogger(__name__)
dotenv.load_dotenv()

def test_login_not_confirmed(domain, user_pool_id):
    """Test that login returns proper error when user is not confirmed"""
    # Create a unique user payload
    unique_email = f"testunconfirmed_{uuid.uuid4()}@example.com"
    user_payload = {
        "username": unique_email,
        "password": "TestPass123!",
        "email": unique_email
    }
    
    try:
        # Create the user without confirming
        response = create_user(domain, user_payload, auto_confirm=False)
        assert response.ok, f"Failed to create user: {response.text}"
        
        # The response should indicate the user needs confirmation
        assert "needs confirmation" in response.json().get("message", "").lower()
        
        # Try to login - this should fail with a specific error message
        login_resp = requests.post(f"{domain}/sessions", json={
            "username": user_payload["username"],
            "password": user_payload["password"]
        })
        
        # Validate the response
        assert login_resp.status_code == 401, f"Expected status code 401, got {login_resp.status_code}"
        response_data = login_resp.json()
        assert "error_code" in response_data, f"Response is missing error_code: {response_data}"
        assert response_data["error_code"] == "USER_NOT_CONFIRMED", f"Unexpected error code: {response_data['error_code']}"
        assert "not confirmed" in response_data["message"].lower(), f"Message doesn't indicate user is not confirmed: {response_data['message']}"
        assert "username" in response_data, "Response should include the username"
        assert response_data["username"] == user_payload["username"]
        
        # Now confirm the user with the admin endpoint
        with admin_user(domain, user_pool_id) as admin:
            with user_session(domain, admin["username"], admin["password"]) as (admin_token, _):
                headers = {"Authorization": f"Bearer {admin_token}"}
                confirm_response = requests.post(
                    f"{domain}/users/{user_payload['username']}/confirm",
                    headers=headers
                )
                assert confirm_response.ok, f"Admin confirmation failed: {confirm_response.text}"
        
        # Try logging in again - should succeed now
        login_resp = requests.post(f"{domain}/sessions", json={
            "username": user_payload["username"],
            "password": user_payload["password"]
        })
        assert login_resp.ok, f"Login failed after confirmation: {login_resp.text}"
        assert "access_token" in login_resp.json(), "Login response missing access token"
        
    finally:
        # Clean up
        client = boto3.client('cognito-idp')
        try:
            client.admin_delete_user(
                UserPoolId=user_pool_id,
                Username=user_payload["username"]
            )
        except Exception as e:
            log.error(f"Error during cleanup: {e}")

def test_login_invalid_credentials(domain):
    """Test that login returns generic error for invalid credentials"""
    # Generate a random email that shouldn't exist
    unique_email = f"nonexistent_{uuid.uuid4()}@example.com"
    
    # Try to login with non-existent user
    login_resp = requests.post(f"{domain}/sessions", json={
        "username": unique_email,
        "password": "WrongPassword123!"
    })
    
    # Validate the response
    assert login_resp.status_code == 401, f"Expected status code 401, got {login_resp.status_code}"
    response_data = login_resp.json()
    assert "error_code" in response_data, f"Response is missing error_code: {response_data}"
    assert response_data["error_code"] == "INVALID_CREDENTIALS", f"Unexpected error code: {response_data['error_code']}"
    
    # The message should be generic and not reveal if the user exists
    assert "incorrect username or password" in response_data["message"].lower(), f"Message should be generic: {response_data['message']}"
    
    # Username should not be included for security reasons
    assert "username" not in response_data, "Response should not include username for security reasons"
