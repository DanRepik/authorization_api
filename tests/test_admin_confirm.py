import pytest
import logging
import dotenv
import requests
import uuid
import boto3
from tests.test_authorization_api import (
    security_services_stack,
    domain,
    user_pool_id,
    create_user,
    delete_user,
    admin_user,
    user_session
)

log = logging.getLogger(__name__)
dotenv.load_dotenv()

def test_admin_confirm_endpoint(domain, user_pool_id):
    """Test the new admin confirm user endpoint"""
    # Create a unique user payload
    unique_email = f"testadminconfirm_{uuid.uuid4()}@example.com"
    user_payload = {
        "username": unique_email,
        "password": "TestPass123!",
        "email": unique_email
    }
    
    # Create the user without auto-confirming
    response = create_user(domain, user_payload, auto_confirm=False)
    assert response.ok
    response_data = response.json()
    assert "needs confirmation" in response_data["message"].lower()
    
    # Initialize user_token to None
    user_token = None
    
    try:
        # Try to login - this should fail because the user is not confirmed
        login_resp = requests.post(f"{domain}/sessions", json={
            "username": user_payload["username"],
            "password": user_payload["password"]
        })
        assert not login_resp.ok
        assert "not confirmed" in login_resp.text.lower()
        
        # Login as admin and confirm the user
        with admin_user(domain, user_pool_id) as admin:
            with user_session(domain, admin["username"], admin["password"]) as (admin_token, _):
                # Use admin token to confirm the user
                headers = {"Authorization": f"Bearer {admin_token}"}
                confirm_response = requests.post(
                    f"{domain}/users/{user_payload['username']}/confirm",
                    headers=headers
                )
                assert confirm_response.ok, f"Admin confirmation failed: {confirm_response.text}"
                
                # Now the user should be able to login
                login_resp = requests.post(f"{domain}/sessions", json={
                    "username": user_payload["username"],
                    "password": user_payload["password"]
                })
                assert login_resp.ok, f"User should be able to login after admin confirmation: {login_resp.text}"
                
                # Get the user's token for later cleanup
                user_token = login_resp.json().get("access_token")
    finally:
        # Clean up - try using the user's token if available, otherwise use admin
        if user_token:
            headers = {"Authorization": f"Bearer {user_token}"}
            requests.delete(f"{domain}/users/me", headers=headers)
        else:
            # If we couldn't get the user token, use admin
            with admin_user(domain, user_pool_id) as admin:
                with user_session(domain, admin["username"], admin["password"]) as (admin_token, _):
                    headers = {"Authorization": f"Bearer {admin_token}"}
                    requests.delete(f"{domain}/users/{user_payload['username']}", headers=headers)

def test_admin_permissions_required(domain, user_pool_id):
    """Test that only admins can use the admin confirm endpoint"""
    # Create two users - one to be confirmed and one non-admin that will try to confirm
    admin_email = f"testadmin_{uuid.uuid4()}@example.com"
    regular_email = f"testregular_{uuid.uuid4()}@example.com"
    unconfirmed_email = f"testunconfirmed_{uuid.uuid4()}@example.com"
    
    admin_payload = {
        "username": admin_email,
        "password": "AdminPass123!",
        "email": admin_email
    }
    
    regular_payload = {
        "username": regular_email,
        "password": "RegularPass123!",
        "email": regular_email
    }
    
    unconfirmed_payload = {
        "username": unconfirmed_email,
        "password": "UserPass123!",
        "email": unconfirmed_email
    }
    
    # Create admin user (auto-confirmed)
    create_user(domain, admin_payload, auto_confirm=True)
    
    # Create regular user (auto-confirmed)
    create_user(domain, regular_payload, auto_confirm=True)
    
    # Create unconfirmed user
    response = create_user(domain, unconfirmed_payload, auto_confirm=False)
    assert response.ok
    
    try:
        # Add the admin to the admin group using boto3
        client = boto3.client("cognito-idp")
        client.admin_add_user_to_group(
            UserPoolId=user_pool_id,
            Username=admin_payload["username"],
            GroupName="admin"
        )
        
        # Login as the regular user
        regular_login = requests.post(f"{domain}/sessions", json={
            "username": regular_payload["username"],
            "password": regular_payload["password"]
        })
        assert regular_login.ok
        regular_token = regular_login.json().get("access_token")
        
        # Try to confirm the unconfirmed user as a regular user - should fail
        headers = {"Authorization": f"Bearer {regular_token}"}
        confirm_response = requests.post(
            f"{domain}/users/{unconfirmed_payload['username']}/confirm",
            headers=headers
        )
        assert not confirm_response.ok
        assert confirm_response.status_code == 403, "Regular user should get 403 Forbidden"
        
        # Login as admin
        admin_login = requests.post(f"{domain}/sessions", json={
            "username": admin_payload["username"],
            "password": admin_payload["password"]
        })
        assert admin_login.ok
        admin_token = admin_login.json().get("access_token")
        
        # Try to confirm as admin - should succeed
        headers = {"Authorization": f"Bearer {admin_token}"}
        confirm_response = requests.post(
            f"{domain}/users/{unconfirmed_payload['username']}/confirm",
            headers=headers
        )
        assert confirm_response.ok, "Admin should be able to confirm users"
        
    finally:
        # Clean up all users
        with admin_user(domain, user_pool_id) as admin:
            with user_session(domain, admin["username"], admin["password"]) as (admin_token, _):
                for username in [admin_payload["username"], regular_payload["username"], unconfirmed_payload["username"]]:
                    try:
                        delete_user(domain, username, admin_token)
                    except Exception as e:
                        log.error(f"Error deleting user {username}: {e}")
