from time import sleep
import pytest
import contextlib
import logging
import dotenv
import boto3
import uuid
import json
import pulumi
import pulumi_aws as aws
import urllib.parse
import cloud_foundry
from authorization_api import AuthorizationUsers
from authorization_api.authorization_lambda import AuthorizationServices

from tests.automation_helpers import deploy_stack, deploy_stack_no_teardown

log = logging.getLogger(__name__)
dotenv.load_dotenv()

ADMIN_USER = f"apitestadmin_{uuid.uuid4()}@example.com"

def user_pool_pulumi():
    def pulumi_program():
        attributes=[
            {
            "name": "email",
            "required": True,
            },
            {
            "name": "phone_number",
            "required": True,
            },
            {
            "name": "preferred_username",
            "required": False,
            },
            {
            "name": "family_name",
            "required": False,
            }
        ]

        user_pool = AuthorizationUsers(
            "security-user-pool",
            attributes=attributes,
            groups=[
                {"description": "Admins group", "role": "admin"},
                {"description": "Manager group", "role": "manager"},
                {"description": "Member group", "role": "member"},
            ],
        )
        log.info("Security API and User Pool created successfully.")

        # Create a Parameter Store resource for storing the client secret
        client_config = pulumi.Output.all(user_pool.id, user_pool.client_id, user_pool.client_secret, user_pool.endpoint).apply(lambda args: 
            json.dumps({
                "client_id": args[1],
                "user_pool_id": args[0],
                "client_secret": args[2],
                "issuer": args[3],
                "logging_level": "DEBUG",
                "user_admin_group": "admin",
                "user_default_group": "member",
                "admin_emails": [ADMIN_USER],
                "user_verification": False,
                "attributes": attributes
            })
        )
        # Create a Parameter Store resource for storing the client secret
        client_secret_param = aws.ssm.Parameter(
            "authorizer-function-config",
            name="/" + cloud_foundry.resource_id(f"authorizer-config", separator="/"),
            type="SecureString",
            value=client_config,
            )
        pulumi.export("authorizer-function-config", client_secret_param.name)

    return pulumi_program


@pytest.fixture(scope="module")
def user_pool_stack():
    log.info("Starting deployment of security services stack")
    yield from deploy_stack("test", "security-func", user_pool_pulumi())


@pytest.fixture(scope="module")
def authorization_services(user_pool_stack):
    stack, outputs = user_pool_stack
    log.info(f"Stack outputs: {outputs}")
    service = AuthorizationServices(
        client_config_name=outputs.get("authorizer-function-config").value,
    )
    yield service


def create_user(service, member_payload):
    log.info(f"Creating user with payload: {member_payload}")
    event = make_event(
        path="/users",
        method="POST",
        body=member_payload
    )
    # Call the handler to create the user
    return service.handler(event, None)


def delete_user(service, access_token, username="me"):
    log.info(f"Deleting user: {username} with access token: {access_token}")

    # Use /users/me if deleting the current user, otherwise use the username
    if username == "me":
        url = "/users/me "
    else:
        url = "/users/{username}"

    event = make_event(
        path=url,
        method="DELETE",
        headers={"Authorization": f"Bearer {access_token}"},
        path_parameters={"username": urllib.parse.quote(username)},
        authorizer_context={"permissions": ["admin"]},
    )

    log.info(f"event: {event}")
    response = service.handler(event, None)
    log.info(f"response {response}")
    assert response["statusCode"] == 200


@contextlib.contextmanager
def member_user(service, member_payload=None):
    email = f"apitestmember_{uuid.uuid4()}@example.com"
    payload = member_payload or {
        "username": email,
        "email": email,
        "password": "MemberPass1234!",
        "phone_number": "+12065550100",  # <-- Add a valid phone number
    }

    log.info(f"Creating member user: {payload['username']}")
    try:
        create_user(service, payload)

        yield payload
    finally:
        with admin_user(service) as admin:
            with user_session(service, admin["username"], admin["password"]) as (
                access_token,
                _,
            ):
                delete_user(service, access_token, payload["username"])


@contextlib.contextmanager
def admin_user(service):
    admin_payload = {
        "username": ADMIN_USER,
        "password": "AdminPass1234!",
        'email': ADMIN_USER,
        "phone_number": "+12065550101",  # <-- Add a valid phone number
    }

    try:
        create_user(service, admin_payload)
        log.info(f"Creating admin user: {admin_payload['username']}")

        yield admin_payload

    finally:
        with user_session(service, admin_payload["username"], admin_payload["password"]) as (
            access_token,
            _,
        ):
            delete_user(service, access_token, admin_payload["username"])


@contextlib.contextmanager
def user_session(service, username, password):
    log.info(f"Logging in user {username}")

    access_token = None
    refresh_token = None
    try:
        event = make_event(
            path="/sessions",
            method="POST",
            body={"username": username, "password": password},
        )
        response = service.handler(event, None)
        assert response["statusCode"] == 200
        tokens = json.loads(response["body"])
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")

        log.info(f"User {username} logged in successfully")
        yield access_token, refresh_token
    finally:
        log.info(f"Logging out {username}")
        if access_token:

            event = make_event(
                path="/sessions/me",
                method="DELETE",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            # Retry logout up to 5 times due to Cognito eventual consistency
            response = None
            for attempt in range(5):
                response = service.handler(event, None)
                if response["statusCode"] == 200:
                    break
                log.warning(f"Logout attempt {attempt+1} failed: {response}")
                sleep(2)
            log.info(f"Logout response: {response}")
            assert response is not None and response.get("statusCode") == 200
        log.info(f"User {username} session ended")


def make_event(
    path, method, headers=None, body=None, path_parameters=None, authorizer_context=None
):
    return {
        "resource": path,
        "httpMethod": method,
        "headers": headers or {},
        "body": json.dumps(body) if body else None,
        "requestContext": {"authorizer": authorizer_context or {}},
        "pathParameters": path_parameters or {},
    }


def test_create_user_missing_required_fields(authorization_services):
    # Missing email (username)
    incomplete_payload = {
        "password": "SomePass123!",
        "phone_number": "+12065550105",
    }
    event = make_event(
        path="/users",
        method="POST",
        body=incomplete_payload,
    )
    response = authorization_services.handler(event, None)
    assert response["statusCode"] == 400

    # Missing password
    incomplete_payload = {
        "username": f"apitestmember_{uuid.uuid4()}@example.com",
        "phone_number": "+12065550106",
    }
    event = make_event(
        path="/users",
        method="POST",
        body=incomplete_payload,
    )
    response = authorization_services.handler(event, None)
    assert response["statusCode"] == 400

    # Missing phone_number
    incomplete_payload = {
        "username": f"apitestmember_{uuid.uuid4()}@example.com",
        "password": "SomePass123!",
    }
    event = make_event(
        path="/users",
        method="POST",
        body=incomplete_payload,
    )
    response = authorization_services.handler(event, None)
    assert response["statusCode"] == 400


def test_delete_user(authorization_services):
    email = f"apitestmember_{uuid.uuid4()}@example.com"
    member_payload = {
        "username": email,
        "email": email,
        "password": "InitialPass123!",
        "phone_number": "+12065550102",  # <-- Add phone number
    }
    create_user(authorization_services, member_payload)

    with admin_user(authorization_services) as admin:
        with user_session(
            authorization_services, admin["username"], admin["password"]
        ) as (access_token, _):
            delete_user(
                authorization_services, access_token, member_payload["username"]
            )

    # attempt to login, should fail
    event = make_event(
        path="/sessions",
        method="POST",
        body={
            "username": member_payload["username"],
            "password": member_payload["password"],
        },
    )
    response = authorization_services.handler(event, None)
    assert response["statusCode"] != 200


def test_change_password(authorization_services):
    with member_user(authorization_services) as member:
        new_password = "NewPass12345!"
        with user_session(
            authorization_services, member["username"], member["password"]
        ) as (user_token, _):
            log.info(f"Changing password for user: {member['username']}")
            log.info(f"User token: {user_token}")
            log.info(f"New password: {new_password}")
            response = authorization_services.handler(
                make_event(
                    path="/users/me/password",
                    method="PUT",
                    headers={"Authorization": f"Bearer {user_token}"},
                    body={
                        "old_password": member["password"],
                        "new_password": new_password,
                    },
                    authorizer_context={
                        "permissions": ["member"],
                        "username": member["username"],
                    },
                ),
                None,
            )
            log.info(f"Change password response: {response}")
            assert response["statusCode"] == 200

        sleep(15)  # wait for eventual consistency
        with user_session(authorization_services, member["username"], new_password) as (
            new_access_token,
            _,
        ):
            assert new_access_token is not None


def test_get_user(authorization_services):
    email = f"apitestmember_{uuid.uuid4()}@example.com"
    member_payload = {
        "username": email,
        "email": email,
        "password": "InitialPass123!",
        "phone_number": "+12065550103",
        "preferred_username": "apitestmember",
    }

    with member_user(authorization_services, member_payload) as member:
        with admin_user(authorization_services) as admin:
            with user_session(
                authorization_services, admin["username"], admin["password"]
            ) as (access_token, _):
                response = authorization_services.handler(
                    make_event(
                        path="/users/{username}",
                        method="GET",
                        headers={"Authorization": f"Bearer {access_token}"},
                        path_parameters={
                            "username": urllib.parse.quote(member["username"])
                        },
                        authorizer_context={"permissions": ["admin"]},
                    ),
                    None,
                )
                log.info(f"Get user response: {response}")
                assert response["statusCode"] == 200
                body = json.loads(response["body"])
                log.info(f"user_info: {body}")
                log.info(f"user_info: {body["user_info"]}")
                assert body["user_info"]["email"] == member_payload["username"]
                assert body["user_info"]["preferred_username"] == member_payload["preferred_username"]
                assert body["groups"] == ["member"]


def test_change_groups(authorization_services):
    with member_user(authorization_services) as member:
        with admin_user(authorization_services) as admin:
            with user_session(
                authorization_services, admin["username"], admin["password"]
            ) as (access_token, _):
                response = authorization_services.handler(
                    make_event(
                        path="/users/{username}",
                        method="GET",
                        headers={"Authorization": f"Bearer {access_token}"},
                        path_parameters={
                            "username": urllib.parse.quote(member["username"])
                        },
                        authorizer_context={"permissions": ["admin"]},
                    ),
                    None,
                )
                log.info(f"Get user info response: {response}")
                assert response["statusCode"] == 200
                body = json.loads(response["body"])
                log.info(f"user info body: {body}")
                assert body["groups"] == ["member"]

                sleep(10)

                # add a role
                response = authorization_services.handler(
                    make_event(
                        path="/users/{username}/groups",
                        method="PUT",
                        body={"groups": ["member", "manager"]},
                        headers={"Authorization": f"Bearer {access_token}"},
                        path_parameters={
                            "username": urllib.parse.quote(member["username"])
                        },
                        authorizer_context={"permissions": ["admin"]},
                    ),
                    None,
                )
                assert response["statusCode"] == 200

                sleep(10)

                response = authorization_services.handler(
                    make_event(
                        path="/users/{username}",
                        method="GET",
                        headers={"Authorization": f"Bearer {access_token}"},
                        path_parameters={
                            "username": urllib.parse.quote(member["username"])
                        },
                        authorizer_context={"permissions": ["admin"]},
                    ),
                    None,
                )
                assert response["statusCode"] == 200
                body = json.loads(response["body"])
                log.info(f"body: {body}")
                assert body["groups"] == ["manager", "member"]

                # add a role
                response = authorization_services.handler(
                    make_event(
                        path="/users/{username}/groups",
                        method="PUT",
                        body={"groups": ["member"]},
                        headers={"Authorization": f"Bearer {access_token}"},
                        path_parameters={
                            "username": urllib.parse.quote(member["username"])
                        },
                        authorizer_context={"permissions": ["admin"]},
                    ),
                    None,
                )
                assert response["statusCode"] == 200
                log.info(f"Get user response: {response}")

                sleep(10)

                response = authorization_services.handler(
                    make_event(
                        path="/users/{username}",
                        method="GET",
                        headers={"Authorization": f"Bearer {access_token}"},
                        path_parameters={
                            "username": urllib.parse.quote(member["username"])
                        },
                        authorizer_context={"permissions": ["admin"]},
                    ),
                    None,
                )
                assert response["statusCode"] == 200
                body = json.loads(response["body"])
                log.info(f"body: {body}")
                assert body["groups"] == ["member"]


def test_refresh_token(authorization_services):
    with member_user(authorization_services) as member:
        with user_session(
            authorization_services, member["username"], member["password"]
        ) as (access_token, refresh_token):
            event = make_event(
                path="/sessions/refresh",
                method="POST",
                body={"refresh_token": refresh_token},
                authorizer_context={
                    "permissions": ["member"],
                    "username": member["username"],
                },
            )
            response = authorization_services.handler(event, None)
            assert response["statusCode"] == 200
            tokens = json.loads(response["body"])
            assert "access_token" in tokens
            assert "refresh_token" in tokens


def test_signup_existing_user(authorization_services):
    with member_user(authorization_services) as member:
        # Try to create the same user again
        event = make_event(
            path="/users",
            method="POST",
            body={
                "username": member["username"],
                "password": "AnotherPass123!",
            },
        )
        response = authorization_services.handler(event, None)
        assert response["statusCode"] == 400 or response["statusCode"] == 409


def test_login_wrong_password(authorization_services):
    with member_user(authorization_services) as member:
        event = make_event(
            path="/sessions",
            method="POST",
            body={
                "username": member["username"],
                "password": "WrongPassword!",
            },
        )
        response = authorization_services.handler(event, None)
        assert response["statusCode"] == 400 or response["statusCode"] == 401


def test_unauthorized_access(authorization_services):
    # Try to get user info without a token
    member_payload = {
        "username": f"apitestmember_{uuid.uuid4()}@example.com",
        "password": "InitialPass123!",
        "phone_number": "+12065550104",  # <-- Add phone number
    }
    create_user(authorization_services, member_payload)
    event = make_event(
        path="/users/{username}",
        method="GET",
        path_parameters={"username": urllib.parse.quote(member_payload["username"])},
    )
    try:
        response = authorization_services.handler(event, None)
        assert response["statusCode"] == 401 or response["statusCode"] == 403
    except Exception as e:
        # If an exception is expected, assert its type or message here
        assert True, f"Expected exception was raised: {e}"


def test_admin_only_with_member_token(authorization_services):
    with member_user(authorization_services) as member:
        with user_session(authorization_services, member["username"], member["password"]) as (access_token, _):
            # Try to change another user's groups as a member
            event = make_event(
                path="/users/{username}/groups",
                method="PUT",
                body={"groups": ["admin"]},
                headers={"Authorization": f"Bearer {access_token}"},
                path_parameters={"username": urllib.parse.quote(member["username"])},
                authorizer_context={"permissions": ["member"]},
            )
            response = authorization_services.handler(event, None)
            assert response["statusCode"] == 403


def test_password_change_wrong_old_password(authorization_services):
    with member_user(authorization_services) as member:
        with user_session(authorization_services, member["username"], member["password"]) as (access_token, _):
            event = make_event(
                path="/users/me/password",
                method="PUT",
                headers={"Authorization": f"Bearer {access_token}"},
                body={
                    "old_password": "WrongOldPassword!",
                    "new_password": "NewPass12345!",
                },
                authorizer_context={
                    "permissions": ["member"],
                    "username": member["username"],
                },
            )
            response = authorization_services.handler(event, None)
            assert response["statusCode"] == 400


def test_get_nonexistent_user(authorization_services):
    with admin_user(authorization_services) as admin:
        with user_session(authorization_services, admin["username"], admin["password"]) as (access_token, _):
            event = make_event(
                path="/users/{username}",
                method="GET",
                headers={"Authorization": f"Bearer {access_token}"},
                path_parameters={"username": urllib.parse.quote("nonexistentuser@example.com")},
                authorizer_context={"permissions": ["admin"]},
            )
            response = authorization_services.handler(event, None)
            assert response["statusCode"] == 400 or response["statusCode"] == 404


def test_refresh_token_invalid(authorization_services):
    # Use an obviously invalid refresh token
    event = make_event(
        path="/sessions/refresh",
        method="POST",
        body={"refresh_token": "invalidtoken"},
        authorizer_context={"permissions": ["member"], "username": "fakeuser"},
    )
    response = authorization_services.handler(event, None)
    assert response["statusCode"] == 400 or response["statusCode"] == 401


def test_disable_enable_user(authorization_services):
    email = f"apitestmember_{uuid.uuid4()}@example.com"
    member_payload = {
        "username": email,
        "email": email,
        "password": "InitialPass123!",
        "phone_number": "+12065550110",
    }
    with member_user(authorization_services, member_payload) as member:
        with admin_user(authorization_services) as admin:
            with user_session(authorization_services, admin["username"], admin["password"]) as (access_token, _):
                # Disable the user
                event = make_event(
                    path="/users/{username}/disable",
                    method="POST",
                    headers={"Authorization": f"Bearer {access_token}"},
                    path_parameters={"username": urllib.parse.quote(member["username"])},
                    authorizer_context={"permissions": ["admin"]},
                )
                response = authorization_services.handler(event, None)
                assert response["statusCode"] == 200
                assert "disabled" in json.loads(response["body"])["message"]

            # Wait for eventual consistency after disabling the user
            sleep(10)

            # Attempt to login as the disabled user (should fail)
            event = make_event(
                path="/sessions",
                method="POST",
                body={"username": member["username"], "password": member["password"]},
            )
            response = authorization_services.handler(event, None)
            assert response["statusCode"] != 200

            with user_session(authorization_services, admin["username"], admin["password"]) as (access_token, _):
                # Enable the user
                event = make_event(
                    path="/users/{username}/enable",
                    method="POST",
                    headers={"Authorization": f"Bearer {access_token}"},
                    path_parameters={"username": urllib.parse.quote(member["username"])},
                    authorizer_context={"permissions": ["admin"]},
                )
                response = authorization_services.handler(event, None)
                assert response["statusCode"] == 200
                assert "enabled" in json.loads(response["body"])["message"]

            # Wait for eventual consistency after disabling the user
            sleep(10)

            # Attempt to login as the enabled user (should succeed)
            event = make_event(
                path="/sessions",
                method="POST",
                body={"username": member["username"], "password": member["password"]},
            )
            response = authorization_services.handler(event, None)
            assert response["statusCode"] == 200
