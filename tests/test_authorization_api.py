import pulumi
import pytest
import logging
import dotenv
import requests
import uuid
import urllib.parse
from tests.automation_helpers import deploy_stack, deploy_stack_no_teardown
from typing import Dict
import boto3
import os
import contextlib
import time
from cloud_foundry import AuthorizationAPI, UserPool  # noqa: F401

log = logging.getLogger(__name__)
dotenv.load_dotenv()


def security_services_pulumi():
    def pulumi_program():
        user_pool = UserPool(
            "security-user-pool",
            self_serve=True,
            attributes=["username", "nickName"],
            groups=[
                {"description": "Admins group", "role": "admin"},
                {"description": "Manager group", "role": "manager"},
                {"description": "Member group", "role": "member"},
            ],
        )
        security_api = AuthorizationAPI(
            "security-api",
            client_id=user_pool.client_id,
            user_pool_id=user_pool.id,
            client_secret=user_pool.client_secret,
            user_admin_group="admin",
            user_default_group="member",
        )

        log.info("Security API and User Pool created successfully.")
        pulumi.export("security-user-pool-id", user_pool.id)
        pulumi.export("security-api-host", security_api.domain)
        pulumi.export("token-validator", security_api.token_validator.function_name)

    return pulumi_program


@pytest.fixture(scope="module")
def security_services_stack():
    log.info("Starting deployment of security services stack")
    yield from deploy_stack("cf", "security", security_services_pulumi())


@pytest.fixture(scope="module")
def domain(security_services_stack):
    log.info("Setting up domain fixture")
    stack, outputs = security_services_stack
    yield f"https://{outputs.get('security-api-host').value}"


@pytest.fixture(scope="module")
def user_pool_id(security_services_stack):
    log.info("Setting up domain fixture")
    stack, outputs = security_services_stack
    yield outputs.get("security-user-pool-id").value


def unique_user_payload():
    unique_email = f"apitestmember_{uuid.uuid4()}@example.com"
    return {"username": unique_email, "password": "InitialPass123!"}


def create_user(domain, member_payload):
    log.info(f"Creating user with payload: {member_payload}, domain:{domain}")
    response = requests.post(f"{domain}/users", json=member_payload)
    if response.status_code == 400 and "already exists" in response.text.lower():
        # User already exists, try to delete and recreate
        login_payload = {
            "username": member_payload["username"],
            "password": member_payload["password"],
        }
        login_resp = requests.post(f"//{domain}/sessions", json=login_payload)
        if login_resp.ok:
            tokens = login_resp.json()
            headers = {"Authorization": f"Bearer {tokens['access_token']}"}
            requests.delete(f"{domain}/users/me", headers=headers)
        # Try again
        response = requests.post(f"{domain}/users", json=member_payload)
    if not response.ok:
        log.error(f"Failed to create user: {response.status_code} - {response.text}")
        response.raise_for_status()
    return response


def delete_user(domain, username, access_token):
    log.info(
        f"Deleting user: {username} with access token: {access_token}, domain:{domain}"
    )

    headers = {"Authorization": f"Bearer {access_token}"}
    # Use /users/me if deleting the current user, otherwise use the username
    if username == "me":
        url = f"{domain}/users/me "
    else:
        url = f"{domain}/users/{urllib.parse.quote(username)}"

    log.info(f"Delete user URL: {url}")
    response = requests.delete(url, headers=headers)
    log.info(f"Delete user response: {response.status_code} - {response.text}")
    if not response.ok:
        log.error(f"Failed to delete user: {response.status_code} - {response.text}")
        response.raise_for_status()
    return response


@contextlib.contextmanager
def member_user(domain, user_pool_id):
    log.info(f"Setting up member user, domain:{domain}")
    member_payload = unique_user_payload()
    create_user(domain, member_payload)
    try:
        log.info(f"Member user created: {member_payload['username']}, domain:{domain}")
        yield member_payload
    finally:
        log.info(f"Cleaning up user: {member_payload['username']}, domain:{domain}")
        with admin_user(domain, user_pool_id) as admin:
            with user_session(domain, admin["username"], admin["password"]) as (
                access_token,
                _,
            ):
                delete_user(domain, member_payload["username"], access_token)


@contextlib.contextmanager
def admin_user(domain, user_pool_id):
    admin_payload = {
        "username": f"apitestadmin_{uuid.uuid4()}@example.com",
        "password": "AdminPass1234!",
    }

    create_user(domain, admin_payload)
    log.info(
        f"Creating admin user: {admin_payload['username']} in user pool: {user_pool_id}"
    )

    # Add user to admin group
    client = boto3.client("cognito-idp")
    client.admin_add_user_to_group(
        UserPoolId=user_pool_id, Username=admin_payload["username"], GroupName="admin"
    )

    yield admin_payload

    # Cleanup: delete the user
    try:
        client.admin_delete_user(
            UserPoolId=user_pool_id, Username=admin_payload["username"]
        )
    except Exception:
        pass


@contextlib.contextmanager
def user_session(domain, username, password):
    log.info(f"Logging in user {username}")
    login_payload = {"username": username, "password": password}
    response = requests.post(f"{domain}/sessions", json=login_payload)
    response.raise_for_status()

    tokens = response.json()
    log.info(f"tokens: {tokens}")
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    try:
        log.info(
            f"User {username} logged in successfully, access_token: {access_token}"
        )
        yield access_token, refresh_token
    finally:
        log.info(f"Logging out {username}")
        if access_token:
            headers = {"Authorization": f"Bearer {access_token}"}
            log.info(f"Headers for logout: {headers}")
            try:
                response = requests.delete(f"{domain}/sessions/me", headers=headers)
                log.info(
                    f"response from logout: {response.status_code} - {response.text}"
                )
            except Exception as e:
                log.error(f"Exception during logout: {e}")
        log.info(f"User {username} session ended, domain:{domain}")


def test_admin_session(domain, user_pool_id):
    with admin_user(domain, user_pool_id) as admin:
        with user_session(domain, admin["username"], admin["password"]) as (
            access_token,
            _,
        ):
            assert access_token is not None

    with admin_user(domain, user_pool_id) as admin:
        with user_session(domain, admin["username"], admin["password"]) as (
            access_token,
            _,
        ):
            assert access_token is not None


def test_member_session(domain, user_pool_id):
    log.info(f"Testing member session, domain:{domain}")
    with member_user(domain, user_pool_id) as member:
        with user_session(domain, member["username"], member["password"]) as (
            access_token,
            refresh_token,
        ):
            log.info(f"Member user session: {member}")
            assert access_token is not None


def test_delete_user(domain, user_pool_id):
    member_payload = unique_user_payload()
    create_user(domain, member_payload)

    with admin_user(domain, user_pool_id) as admin:
        with user_session(domain, admin["username"], admin["password"]) as (
            access_token,
            _,
        ):
            delete_user(domain, member_payload["username"], access_token)

    try:
        with user_session(
            domain, member_payload["username"], member_payload["password"]
        ) as (access_token, _):
            assert False, "User should not be able to log in after deletion"
    except requests.HTTPError as e:
        log.info(f"Expected error when logging in deleted user: {e}")


def test_change_password(domain, user_pool_id):
    # loggin the user an change the password
    with member_user(domain, user_pool_id) as member:
        with user_session(domain, member["username"], member["password"]) as (
            access_token,
            _,
        ):
            headers = {"Authorization": f"Bearer {access_token}"}

            # Change password
            change_payload = {"new_password": "NewPass456!"}
            response = requests.put(
                f"{domain}/users/me/password", json=change_payload, headers=headers
            )
            assert (
                response.status_code == 200
            ), f"Password change failed: {response.text}"
            data = response.json()
            assert "message" in data
            assert data["message"].lower().startswith("password changed")
            log.info(f"Password changed successfully for user {member['username']}")

        with user_session(domain, member["username"], "NewPass456!") as (
            access_token,
            refresh_token,
        ):
            assert access_token is not None


def test_refresh_token(domain, user_pool_id):
    with member_user(domain, user_pool_id) as member:
        with user_session(domain, member["username"], member["password"]) as (
            access_token,
            refresh_token,
        ):
            headers = {"Authorization": f"Bearer {access_token}"}

            # Refresh token
            refresh_payload = {
                "username": member["username"],
                "refresh_token": refresh_token,
            }
            response = requests.post(f"{domain}/sessions/refresh", json=refresh_payload)
            assert response.status_code == 200, f"Refresh token failed: {response.text}"
            data = response.json()
            assert (
                "access_token" in data and data["access_token"] != access_token
            ), "Access token should be refreshed"
            assert "refresh_token" in data
            assert "groups" in data
            assert isinstance(data["groups"], list)

    member_payload = unique_user_payload()
    tokens = None
    data = None
    try:
        # Create user
        requests.post(f"{domain}/users", json=member_payload)

        # Login to get tokens
        login_payload = {
            "username": member_payload["username"],
            "password": member_payload["password"],
        }
        response = requests.post(f"{domain}/sessions", json=login_payload)
        tokens = response.json()

        # Refresh token
        refresh_payload = {
            "username": member_payload["username"],
            "refresh_token": tokens["refresh_token"],
        }
        response = requests.post(f"{domain}/sessions/refresh", json=refresh_payload)
        assert response.status_code == 200, f"Refresh token failed: {response.text}"
        data = response.json()
        assert "access_token" in data
        assert data["access_token"] != access_token, "Access token should be refreshed"
        assert "refresh_token" in data
        assert "groups" in data
        assert isinstance(data["groups"], list)

    finally:
        # Cleanup: delete user if possible
        access_token = None
        if data and "access_token" in data:
            access_token = data["access_token"]
        elif tokens and "access_token" in tokens:
            access_token = tokens["access_token"]
        if access_token:
            headers = {"Authorization": f"Bearer {access_token}"}
            try:
                requests.delete(f"{domain}/users/me", headers=headers)
            except Exception:
                pass
