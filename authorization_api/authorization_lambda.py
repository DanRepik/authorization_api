import hmac
import hashlib
import base64
import json
import os
import jwt
import requests
import boto3
from urllib.parse import unquote
from botocore.exceptions import ClientError
import logging

log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOGGING_LEVEL", "INFO"))

# Initialize the Cognito client
cognito_client = boto3.client("cognito-idp")


def handler(event, context):
    log.info(f"Received event: {event}")
    auth_service = AuthorizationServices()
    return auth_service.handler(event, context)


class AuthorizationServices:
    def __init__(
        self,
        user_pool_id=None,
        client_id=None,
        client_secret=None,
        user_admin_group=None,
        user_default_group=None,
        region=None,
    ):
        self.user_pool_id = user_pool_id or os.getenv("USER_POOL_ID")
        self.client_id = client_id or os.getenv("CLIENT_ID")
        self.client_secret = client_secret or os.getenv("CLiENT_SECRET")
        self.user_admin_group = user_admin_group or os.getenv("USER_ADMIN_GROUP")
        self.user_default_group = user_default_group or os.getenv("USER_DEFAULT_GROUP")
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self.issuer = (
            region
            or f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"
        )
        self.cognito_client = boto3.client("cognito-idp", region_name=region)

    def handler(self, event, context):
        log.info(f"event: {event}")
        path = event.get("resource", "")
        http_method = event.get("httpMethod", "").upper()
        log.info(f"Path: {path}, HTTP Method: {http_method}")

        if path.endswith("/users") and http_method == "POST":
            return self.create_user(event)
        elif path.endswith("/users/{username}") and http_method == "GET":
            return self.get_user(event)
        elif path.endswith("/users/{username}") and http_method == "DELETE":
            return self.delete_user(event)
        elif path.endswith("/users/me/password") and http_method == "PUT":
            return self.change_user_password(event)
        elif path.endswith("/users/{username}/groups") and http_method == "PUT":
            return self.change_user_groups(event)
        elif path.endswith("/sessions") and http_method == "POST":
            return self.create_session(event)
        elif path.endswith("/sessions/me") and http_method == "DELETE":
            return self.delete_session(event)
        elif path.endswith("/sessions/refresh") and http_method == "POST":
            return self.refresh_session(event)
        else:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Invalid action or method"}),
            }

    def create_user(self, event):
        body = json.loads(event["body"])
        log.info(f"body: {body}")
        username = body.get("username") or body.get("email")
        password = body.get("password")

        try:

            cognito_client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=[
                    {
                        "name": attr.get("name", "customAttribute"),
                        "attribute_data_type": attr.get("attribute_data_type", "String"),
                        "mutable": attr.get("mutable", True),
                        "required": attr.get("required", False),
                        **(attr.get("string_constraints", {}) if attr.get("attribute_data_type") == "String" else {}),
                        **(attr.get("number_constraints", {}) if attr.get("attribute_data_type") == "Number" else {})
                    }
                    for attr in (attributes if attributes is not None else default_attributes)
                ],
                TemporaryPassword=password,
                MessageAction="SUPPRESS",
            )

            # Set the user's password to a permanent one
            cognito_client.admin_set_user_password(
                UserPoolId=self.user_pool_id,
                Username=username,
                Password=password,
                Permanent=True,
            )
            # Add user to default group if self.user_default_group is set
            if self.user_default_group:
                log.info(f"Adding user {username} to group {self.user_default_group}")
                cognito_client.admin_add_user_to_group(
                    UserPoolId=self.user_pool_id,
                    Username=username,
                    GroupName=self.user_default_group,
                )

            return {
                "statusCode": 201,
                "body": json.dumps({"message": "Signup successful"}),
            }
        except ClientError as e:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def get_user(self, event):
        log.info("Getting user")
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        log.info(f"permissions: {permissions}")
        # Check if admin group is defined and user is an admin
        if self.user_admin_group:
            if self.user_admin_group not in permissions:
                return {
                    "statusCode": 403,
                    "body": json.dumps(
                        {"message": "You are not authorized to delete users"}
                    ),
                }

        username = unquote(event["pathParameters"]["username"])
        log.info(f"username: {username}")
        try:
            user_info, groups = self.fetch_user_info(username)
            log.info(f"user_info: {user_info}")
            return {
                "statusCode": 200,
                "body": json.dumps({"user_info": user_info, "groups": groups}),
            }
        except ClientError as e:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def delete_user(self, event):
        log.info("Deleting user")
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        log.info(f"permissions: {permissions}")
        username = event["pathParameters"]["username"]
        try:
            # If username is 'me', get the actual username from the authorizer
            if username == "me":
                username = event["requestContext"]["authorizer"]["username"]
            else:
                username = unquote(username)
        except Exception:
            # If decoding fails, just use the original username
            pass
        log.info(f"username: {username}")

        # Check if admin group is defined and user is an admin
        if self.user_admin_group:
            if self.user_admin_group not in permissions:
                return {
                    "statusCode": 403,
                    "body": json.dumps(
                        {"message": "You are not authorized to delete users"}
                    ),
                }
        log.info(f"Deleting user: {username}")
        try:
            cognito_client.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=username,
            )
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "User deleted successfully"}),
            }
        except ClientError as e:
            log.error(f"Error deleting user: {e.response}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def change_user_password(self, event):
        body = json.loads(event["body"])
        request_context = event.get("requestContext")
        log.info(f"request_context: {request_context}")
        log.info(f"body: {body}")
        username = request_context.get("authorizer", {}).get("username")
        new_password = body.get("new_password")

        log.info(
            f"Changing password for user: {username}, new_password: {new_password}"
        )
        try:
            cognito_client.admin_set_user_password(
                UserPoolId=self.user_pool_id,
                Username=username,
                Password=new_password,
                Permanent=True,
            )

            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Password changed successfully"}),
            }
        except ClientError as e:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def change_user_groups(self, event):
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        log.info(f"permissions: {permissions}")
        # Check if admin group is defined and user is an admin
        if self.user_admin_group:
            if self.user_admin_group not in permissions:
                return {
                    "statusCode": 403,
                    "body": json.dumps(
                        {"message": "You are not authorized to delete users"}
                    ),
                }

        username = unquote(event["pathParameters"]["username"])
        body = json.loads(event["body"])
        log.info(f"body: {body}")
        groups = body.get("groups", [])

        try:
            current_groups = set(self.fetch_user_info(username)[1])
            new_groups = set(groups)

            # Remove user from groups they are no longer in
            for group in current_groups - new_groups:
                cognito_client.admin_remove_user_from_group(
                    UserPoolId=self.user_pool_id,
                    Username=username,
                    GroupName=group,
                )

            # Add user to new groups they are not already in
            for group in new_groups - current_groups:
                cognito_client.admin_add_user_to_group(
                    UserPoolId=self.user_pool_id,
                    Username=username,
                    GroupName=group,
                )

            return {
                "statusCode": 200,
                "body": json.dumps({"message": "User groups updated successfully"}),
            }
        except ClientError as e:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def create_session(self, event):
        # Log all the request headers
        headers = event.get("headers", {})
        log.info(f"Request headers: {headers}")
        body = json.loads(event["body"])
        log.info(f"body: {body}")
        username = body.get("username") or body.get("email")
        password = body.get("password")
        secret_hash = self.calculate_secret_hash(username)

        try:
            log.info(f"username: {username}")
            response = cognito_client.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": username,
                    "PASSWORD": password,
                    "SECRET_HASH": secret_hash,
                },
                ClientId=self.client_id,
            )

            user_info, groups = self.fetch_user_info(username)
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "user_info": user_info,
                        "groups": groups,
                        "id_token": response["AuthenticationResult"]["IdToken"],
                        "access_token": response["AuthenticationResult"]["AccessToken"],
                        "refresh_token": response["AuthenticationResult"][
                            "RefreshToken"
                        ],
                    }
                ),
            }
        except ClientError as e:
            log.error(f"Error: {e.response}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def delete_session(self, event):
        try:
            headers = event.get("headers", {})
            authorization_header = headers.get("Authorization")

            if not authorization_header:
                log.error("Authorization header is missing")
                return {
                    "statusCode": 400,
                    "body": json.dumps({"message": "Authorization header is required"}),
                }

            access_token = (
                authorization_header.split(" ")[1]
                if " " in authorization_header
                else authorization_header
            )

            if not access_token:
                return {
                    "statusCode": 200,
                    "body": json.dumps({"message": "Logout successful"}),
                }

            response = cognito_client.global_sign_out(AccessToken=access_token)
            log.info(f"Logout response: {response}")
            if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
                log.error("Logout failed")
                return {
                    "statusCode": 400,
                    "body": json.dumps({"message": "Logout failed"}),
                }
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Logout successful"}),
            }
        except ClientError as e:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def calculate_secret_hash(self, username):
        message = username + self.client_id
        secret_hash = hmac.new(
            self.client_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
        ).digest()
        return base64.b64encode(secret_hash).decode("utf-8")

    def refresh_session(self, event):
        log.info("Starting refresh_token function")
        body = json.loads(event["body"])

        refresh_token = body.get("refresh_token")
        if not refresh_token:
            log.info("Refresh token is missing in the request")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Refresh token is required"}),
            }

        username = event["requestContext"]["authorizer"].get("username")

        try:
            log.info("Attempting to use the refresh token to get new tokens")
            # Use the refresh token to get new tokens
            secret_hash = self.calculate_secret_hash(
                username
            )  # Calculate the secret hash
            response = cognito_client.initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={
                    "REFRESH_TOKEN": refresh_token,
                    "SECRET_HASH": secret_hash,  # Include the secret hash
                },
                ClientId=self.client_id,
            )
            log.info(f"InitiateAuth response: {response}")

            # Extract tokens from the response
            access_token = response["AuthenticationResult"]["AccessToken"]
            id_token = response["AuthenticationResult"]["IdToken"]
            new_refresh_token = response["AuthenticationResult"].get(
                "RefreshToken", refresh_token
            )  # Use the new refresh token if provided
            log.info(f"Access token: {access_token}")
            log.info(f"ID token: {id_token}")
            log.info(f"Refresh token: {new_refresh_token}")

            user_info, groups = self.fetch_user_info(username)

            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "access_token": access_token,
                        "id_token": id_token,
                        "refresh_token": new_refresh_token,
                        "user_info": user_info,
                        "groups": groups,
                    }
                ),
            }
        except ClientError as e:
            log.error(f"ClientError occurred: {e.response}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }
        except Exception as e:
            log.error(f"Unexpected error occurred: {str(e)}")
            return {
                "statusCode": 500,
                "body": json.dumps({"message": "An unexpected error occurred"}),
            }

    def fetch_user_info(self, username):
        # Fetch user attributes
        user_details = cognito_client.admin_get_user(
            UserPoolId=self.user_pool_id, Username=username
        )
        attributes = {
            attr["Name"]: attr["Value"]
            for attr in user_details.get("UserAttributes", [])
        }
        log.info(f"User attributes: {attributes}")
        # Get the user's groups
        user_groups = cognito_client.admin_list_groups_for_user(
            UserPoolId=self.user_pool_id, Username=username
        )
        groups = [group["GroupName"] for group in user_groups.get("Groups", [])]
        log.info(f"User groups: {groups}")

        return attributes, groups

    def get_permissions_from_token(self, decoded_token):
        """
        Extracts permissions from a decoded JWT token.
        Looks for 'permissions', 'scope', or 'cognito:groups' claims.
        Returns a list of permissions.
        """
        import re

        to_list = lambda x: (
            re.split(r"[,\s]+", x.strip())
            if isinstance(x, str)
            else x if isinstance(x, list) else []
        )
        # Check for a 'permissions' claim (custom claim)
        if "permissions" in decoded_token:
            return to_list(decoded_token["permissions"])
        # Check for OAuth2 'scope' claim
        if "scope" in decoded_token:
            return to_list(decoded_token["scope"])
        # Check for Cognito groups
        if "cognito:groups" in decoded_token:
            return to_list(decoded_token["cognito:groups"])
        # No permissions found
        return []
