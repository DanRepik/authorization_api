from typing import Optional, Dict, List, Any
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

# Configuration for Pre Token Generation
ENABLE_TOKEN_CUSTOMIZATION = os.environ.get("ENABLE_TOKEN_CUSTOMIZATION", "true").lower() == "true"

def load_configuration(param_name):
    """
    Loads a JSON object from an AWS SSM Parameter Store item.
    """
    ssm = boto3.client("ssm", region_name=os.environ.get("AWS_REGION"))
    try:
        response = ssm.get_parameter(Name=param_name, WithDecryption=True)
        value = response["Parameter"]["Value"]
        return json.loads(value)
    except ClientError as e:
        log.error(f"Error loading parameter {param_name}: {e.response['Error']['Message']}")
        raise

config = None

def handler(event, context):
    # Handle regular API Gateway requests
    auth_service = AuthorizationServices()
    result = auth_service.handler(event, context)
    log.debug(f"Handler result: {json.dumps(result)}")
    return result


class AuthorizationServices:
    def __init__(
        self,
        client_config_name: Optional[str] = None,
        region: Optional[str] = None,
    ):
        global config
        if not config:
            log.info("Loading configuration from Parameter Store")
            # Load the configuration from AWS SSM Parameter Store
            config = load_configuration(client_config_name or os.environ.get("CONFIG_PARAMETER"))
            log.debug(f"Configuration loaded: {json.dumps(config)}")

        self.user_pool_id = os.getenv("USER_POOL_ID") or config.get("user_pool_id")
        self.client_id = os.getenv("CLIENT_ID") or config.get("client_id")
        self.client_secret = os.getenv("CLIENT_SECRET") or config.get("client_secret")
        self.user_admin_group = os.getenv("USER_ADMIN_GROUP") or config.get("user_admin_group")
        self.user_default_group = os.getenv("USER_DEFAULT_GROUP") or config.get("user_default_group")
        self.admin_emails = os.getenv("ADMIN_EMAILS")
        if self.admin_emails:
            self.admin_emails = json.loads(self.admin_emails)
        else:
            self.admin_emails = config.get("admin_emails", [])
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self.issuer = (
            region
            or f"https://cognito-idp.{self.region}.amazonaws.com/{self.user_pool_id}"
        )
        self.attributes = config.get("attributes", None)

    def handler(self, event, context):
        log.debug(f"Received event: {json.dumps(event)}")

        path = event.get("resource", "")
        http_method = event.get("httpMethod", "").upper()
        username = self._extract_username(event)
        
        log.info(f"API: {http_method} {path} | User: {username or 'anonymous'}")

        if path.endswith("/users") and http_method == "POST":
            return self.create_user(event)
        elif path.endswith("/users/{username}") and http_method == "GET":
            return self.get_user(event)
        elif path.endswith("/users/confirm") and http_method == "POST":
            return self.confirm_user(event)
        elif path.endswith("/users/{username}/confirm") and http_method == "POST":
            return self.admin_confirm_user(event)
        elif path.endswith("/users/{username}") and http_method == "DELETE":
            return self.delete_user(event)
        elif path.endswith("/users/me/password") and http_method == "PUT":
            return self.change_user_password(event)
        elif path.endswith("/users/{username}/groups") and http_method == "PUT":
            return self.change_user_groups(event)
        elif path.endswith("/users/{username}/disable") and http_method == "POST":
            return self.disable_user(event)
        elif path.endswith("/users/{username}/enable") and http_method == "POST":
            return self.enable_user(event)
        elif path.endswith("/sessions") and http_method == "POST":
            return self.create_session(event)
        elif path.endswith("/sessions/me") and http_method == "DELETE":
            return self.delete_session(event)
        elif path.endswith("/sessions/refresh") and http_method == "POST":
            return self.refresh_session(event)
        else:
            log.warning(f"Invalid action: {http_method} {path}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Invalid action or method"}),
            }

    def _extract_username(self, event):
        """Extract username from event for logging purposes"""
        # Try to get from authorizer context
        try:
            if event.get("requestContext") and event["requestContext"].get("authorizer") and event["requestContext"]["authorizer"].get("username"):
                return event["requestContext"]["authorizer"]["username"]
        except (KeyError, TypeError, AttributeError):
            pass
    
        # Try to get from path parameters - handle None case properly
        try:
            path_params = event.get("pathParameters")
            if path_params and path_params.get("username"):
                username = path_params["username"]
                if username != "me":
                    return unquote(username)
        except (KeyError, TypeError, AttributeError):
            pass
    
        # Try to get from body
        try:
            if event.get("body"):
                body = json.loads(event["body"])
                if body:
                    return body.get("username") or body.get("email")
        except (KeyError, TypeError, AttributeError, json.JSONDecodeError):
            pass
        
        return None

    def create_user(self, event):
        body = json.loads(event["body"])
        log.debug(f"Request body: {json.dumps(body)}")
        username = body.get("username") or body.get("email")
        password = body.get("password")

        try:
            # Compile UserAttributes from the body using self.attributes
            user_attributes = []
            missing_required = []
            for attr in self.attributes or []:
                attr_name = attr.get("name")
                required = attr.get("required", False)
                value = body.get(attr_name)
                if required and (value is None or value == ""):
                    missing_required.append(attr_name)
                if value is not None:
                    user_attributes.append({"Name": attr_name, "Value": str(value)})
            if missing_required:
                log.warning(f"User creation failed: Missing required attributes: {', '.join(missing_required)}")
                return {
                    "statusCode": 400,
                    "body": json.dumps({"message": f"Missing required attributes: {', '.join(missing_required)}"}),
                }

            # Create the user with a temporary password
            cognito_client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=username,
                UserAttributes=user_attributes,
                TemporaryPassword=password,
            )
            # Set the user's password but keep them in an unconfirmed state
            cognito_client.admin_set_user_password(
                UserPoolId=self.user_pool_id,
                Username=username,
                Password=password,
                Permanent=False,  # Set to False to keep user unconfirmed
            )

            # Add user to default group if self.user_default_group is set
            if self.user_default_group:
                log.debug(f"Adding user {username} to group {self.user_default_group}")
                cognito_client.admin_add_user_to_group(
                    UserPoolId=self.user_pool_id,
                    Username=username,
                    GroupName=self.user_default_group,
                )

            # Add user to admin group if their email is in admin_emails
            user_email = body.get("email") or username
            if self.user_admin_group and user_email and self.admin_emails and user_email in self.admin_emails:
                log.debug(f"Adding user {username} to admin group {self.user_admin_group}")
                cognito_client.admin_add_user_to_group(
                    UserPoolId=self.user_pool_id,
                    Username=username,
                    GroupName=self.user_admin_group,
                    )

            log.info(f"USER: Created user {username} (needs confirmation) | Groups: {self.user_default_group or 'none'} | Admin: {'yes' if user_email in self.admin_emails else 'no'}")
            # Return a success response                
            return {
                "statusCode": 201,
                "body": json.dumps({"message": "Signup successful, but user needs confirmation"}),
            }
        except ClientError as e:
            log.error(f"User creation failed: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def get_user(self, event):
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        log.debug(f"User permissions: {permissions}")
        # Check if admin group is defined and user is an admin
        if self.user_admin_group:
            if self.user_admin_group not in permissions:
                log.info(f"USER: Access denied | Reason: Missing admin permission")
                return {
                    "statusCode": 403,
                    "body": json.dumps(
                        {"message": "You are not authorized to view user details"}
                    ),
                }

        username = unquote(event["pathParameters"]["username"])
        try:
            user_info, groups = self.fetch_user_info(username)
            log.info(f"USER: Retrieved details for {username} | Groups: {', '.join(groups)}")
            return {
                "statusCode": 200,
                "body": json.dumps({"user_info": user_info, "groups": groups}),
            }
        except ClientError as e:
            log.error(f"Error retrieving user details: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def delete_user(self, event):
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        log.debug(f"User permissions: {permissions}")
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
        
        # Check if admin group is defined and user is an admin
        if self.user_admin_group:
            if self.user_admin_group not in permissions:
                log.info(f"USER: Delete denied for {username} | Reason: Missing admin permission")
                return {
                    "statusCode": 403,
                    "body": json.dumps(
                        {"message": "You are not authorized to delete users"}
                    ),
                }
        
        try:
            cognito_client.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=username,
            )
            log.info(f"USER: Deleted {username}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "User deleted successfully"}),
            }
        except ClientError as e:
            log.error(f"Error deleting user: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def change_user_password(self, event):
        body = json.loads(event["body"])
        request_context = event.get("requestContext")
        log.debug(f"Request context: {json.dumps(request_context)}")
        username = request_context.get("authorizer", {}).get("username")
        old_password = body.get("old_password")
        new_password = body.get("new_password")

        log.debug(f"Changing password for user: {username}")
        
        # Check if both old_password and new_password are provided
        if not old_password:
            log.info(f"USER: Password change failed for {username} | Reason: Missing old password")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Old password is required"})
            }
        
        if not new_password:
            log.info(f"USER: Password change failed for {username} | Reason: Missing new password")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "New password is required"})
            }

        try:
            # Authenticate the user with the old password to verify it is correct
            secret_hash = self.calculate_secret_hash(username)
            cognito_client.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": username,
                    "PASSWORD": old_password,
                    "SECRET_HASH": secret_hash,
                },
                ClientId=self.client_id,
            )
        except ClientError as e:
            log.info(f"USER: Password change failed for {username} | Reason: Old password incorrect")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Old password is incorrect"})
            }

        try:
            cognito_client.admin_set_user_password(
                UserPoolId=self.user_pool_id,
                Username=username,
                Password=new_password,
                Permanent=True,
            )
            
            log.info(f"USER: Password changed for {username}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Password changed successfully"}),
            }
        except ClientError as e:
            log.error(f"Error changing password: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def change_user_groups(self, event):
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        log.debug(f"User permissions: {permissions}")
        # Check if admin group is defined and user is an admin
        if self.user_admin_group:
            if self.user_admin_group not in permissions:
                log.info(f"USER: Group change denied | Reason: Missing admin permission")
                return {
                    "statusCode": 403,
                    "body": json.dumps(
                        {"message": "You are not authorized to modify user groups"}
                    ),
                }

        username = unquote(event["pathParameters"]["username"])
        body = json.loads(event["body"])
        groups = body.get("groups", [])

        try:
            current_groups = set(self.fetch_user_info(username)[1])
            new_groups = set(groups)
            
            removed_groups = current_groups - new_groups
            added_groups = new_groups - current_groups

            # Remove user from groups they are no longer in
            for group in removed_groups:
                cognito_client.admin_remove_user_from_group(
                    UserPoolId=self.user_pool_id,
                    Username=username,
                    GroupName=group,
                )

            # Add user to new groups they are not already in
            for group in added_groups:
                cognito_client.admin_add_user_to_group(
                    UserPoolId=self.user_pool_id,
                    Username=username,
                    GroupName=group,
                )

            log.info(f"USER: Updated groups for {username} | Added: {', '.join(added_groups) or 'none'} | Removed: {', '.join(removed_groups) or 'none'}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "User groups updated successfully"}),
            }
        except ClientError as e:
            log.error(f"Error changing user groups: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def create_session(self, event):
        # Log all the request headers
        headers = event.get("headers", {})
        log.debug(f"Request headers: {json.dumps(headers)}")
        body = json.loads(event["body"])
        username = body.get("username") or body.get("email")
        secret_hash = self.calculate_secret_hash(username)

        try:
            log.debug(f"Authenticating user: {username}")
            response = cognito_client.initiate_auth(
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={
                    "USERNAME": username,
                    "PASSWORD": body.get("password"),
                    "SECRET_HASH": secret_hash,
                },
                ClientId=self.client_id,
            )
            log.debug(f"Authentication response: {response}")
            user_info, groups = self.fetch_user_info(username)
            log.info(f"SESSION: Created for {username} | Groups: {', '.join(groups)}")
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
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', '')
            
            # Handle specific error cases
            if error_code == "NotAuthorizedException" and "not confirmed" in error_message.lower():
                # User exists but is not confirmed
                log.info(f"SESSION: Login failed for {username} | Reason: User not confirmed")
                return {
                    "statusCode": 401,
                    "body": json.dumps({
                        "message": "User is not confirmed. Please check your email for a confirmation link or contact an administrator.",
                        "error_code": "USER_NOT_CONFIRMED",
                        "username": username
                    }),
                }
            elif error_code == "UserNotConfirmedException":
                # Explicit error code for unconfirmed users
                log.info(f"SESSION: Login failed for {username} | Reason: User not confirmed")
                return {
                    "statusCode": 401,
                    "body": json.dumps({
                        "message": "User is not confirmed. Please check your email for a confirmation link or contact an administrator.",
                        "error_code": "USER_NOT_CONFIRMED",
                        "username": username
                    }),
                }
            elif error_code == "UserNotFoundException":
                # User doesn't exist
                log.info(f"SESSION: Login failed for {username} | Reason: User not found")
                return {
                    "statusCode": 401,
                    "body": json.dumps({
                        "message": "Incorrect username or password",
                        "error_code": "INVALID_CREDENTIALS"
                    }),
                }
            elif error_code == "NotAuthorizedException" and "incorrect username or password" in error_message.lower():
                # Invalid credentials
                log.info(f"SESSION: Login failed for {username} | Reason: Invalid credentials")
                return {
                    "statusCode": 401,
                    "body": json.dumps({
                        "message": "Incorrect username or password",
                        "error_code": "INVALID_CREDENTIALS"
                    }),
                }
            elif error_code == "UserNotFoundError":
                # User doesn't exist (different error code)
                log.info(f"SESSION: Login failed for {username} | Reason: User not found")
                return {
                    "statusCode": 401,
                    "body": json.dumps({
                        "message": "Incorrect username or password",
                        "error_code": "INVALID_CREDENTIALS"
                    }),
                }
            else:
                # Generic error handling
                log.info(f"SESSION: Login failed for {username} | Reason: {error_message}")
                return {
                    "statusCode": 400,
                    "body": json.dumps({"message": error_message}),
                }

    def delete_session(self, event):
        try:
            headers = event.get("headers", {})
            authorization_header = headers.get("Authorization")
            username = event["requestContext"]["authorizer"].get("username", "unknown")

            if not authorization_header:
                log.warning("Logout attempt without Authorization header")
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
                log.info(f"SESSION: Logout successful for {username} (no token)")
                return {
                    "statusCode": 200,
                    "body": json.dumps({"message": "Logout successful"}),
                }

            response = cognito_client.global_sign_out(AccessToken=access_token)
            log.debug(f"Logout response: {response}")
            if response["ResponseMetadata"]["HTTPStatusCode"] != 200:
                log.warning(f"SESSION: Logout failed for {username}")
                return {
                    "statusCode": 400,
                    "body": json.dumps({"message": "Logout failed"}),
                }
                
            log.info(f"SESSION: Logout successful for {username}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Logout successful"}),
            }
        except ClientError as e:
            log.error(f"Error during logout: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def calculate_secret_hash(self, username):
        message = username + self.client_id
        digest = hmac.new(
            key=self.client_secret.encode("utf-8"), 
            msg=message.encode("utf-8"), 
            digestmod=hashlib.sha256
        ).digest()
        return base64.b64encode(digest).decode("utf-8")

    def refresh_session(self, event):
        log.debug("Starting refresh_token function")
        body = json.loads(event["body"])

        refresh_token = body.get("refresh_token")
        if not refresh_token:
            log.warning("Refresh token is missing in the request")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Refresh token is required"}),
            }

        username = event["requestContext"]["authorizer"].get("username")

        try:
            log.debug("Attempting to use the refresh token to get new tokens")
            # Use the refresh token to get new tokens
            secret_hash = self.calculate_secret_hash(username)
            response = cognito_client.initiate_auth(
                AuthFlow="REFRESH_TOKEN_AUTH",
                AuthParameters={
                    "REFRESH_TOKEN": refresh_token,
                    "SECRET_HASH": secret_hash,
                },
                ClientId=self.client_id,
            )
            log.debug(f"InitiateAuth response status: {response['ResponseMetadata']['HTTPStatusCode']}")

            # Extract tokens from the response
            access_token = response["AuthenticationResult"]["AccessToken"]
            id_token = response["AuthenticationResult"]["IdToken"]
            new_refresh_token = response["AuthenticationResult"].get(
                "RefreshToken", refresh_token
            )

            user_info, groups = self.fetch_user_info(username)
            log.info(f"SESSION: Refreshed for {username} | Groups: {', '.join(groups)}")

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
            log.info(f"SESSION: Refresh failed for {username} | Reason: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }
        except Exception as e:
            log.error(f"Unexpected error occurred during token refresh: {str(e)}")
            return {
                "statusCode": 500,
                "body": json.dumps({"message": "An unexpected error occurred"}),
            }

    def fetch_user_info(self, username):
        # Fetch user attributes and status
        user_details = cognito_client.admin_get_user(
            UserPoolId=self.user_pool_id, Username=username
        )
        attributes = {
            attr["Name"]: attr["Value"]
            for attr in user_details.get("UserAttributes", [])
        }
        enabled = user_details.get("Enabled", False)
        log.debug(f"User attributes: {json.dumps(attributes)}, Enabled: {enabled}")
        
        # Get the user's groups
        user_groups = cognito_client.admin_list_groups_for_user(
            UserPoolId=self.user_pool_id, Username=username
        )
        groups = [group["GroupName"] for group in user_groups.get("Groups", [])]
        log.debug(f"User groups: {groups}")

        # Include enabled status in the returned attributes
        attributes["enabled"] = enabled

        return attributes, sorted(groups)

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

    def confirm_user(self, event):
        """
        Confirms a user's signup using a confirmation code.
        Expects 'username' and 'confirmation_code' in the request body.
        """
        body = json.loads(event["body"])
        username = body.get("username")
        confirmation_code = body.get("confirmation_code")

        if not username or not confirmation_code:
            log.warning(f"User confirmation failed: Missing username or confirmation code")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Username and confirmation code are required"}),
            }

        try:
            # For client-side confirmation, we need to include the secret hash
            secret_hash = self.calculate_secret_hash(username)
            
            cognito_client.confirm_sign_up(
                ClientId=self.client_id,
                Username=username,
                ConfirmationCode=confirmation_code,
                SecretHash=secret_hash,
            )
            
            # After confirmation, we can set the password as permanent if needed
            # This step is optional - depends on your requirements
            cognito_client.admin_set_user_password(
                UserPoolId=self.user_pool_id,
                Username=username,
                Password=body.get("password", ""),  # If a new password is provided
                Permanent=True,
            ) if body.get("password") else None
            
            log.info(f"USER: Confirmed {username}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "User confirmed successfully"}),
            }
        except ClientError as e:
            log.info(f"USER: Confirmation failed for {username} | Reason: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def disable_user(self, event):
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        username = unquote(event["pathParameters"]["username"])
        
        if self.user_admin_group and self.user_admin_group not in permissions:
            log.info(f"USER: Disable denied for {username} | Reason: Missing admin permission")
            return {
                "statusCode": 403,
                "body": json.dumps({"message": "You are not authorized to disable users"}),
            }
        
        try:
            cognito_client.admin_disable_user(
                UserPoolId=self.user_pool_id,
                Username=username,
            )
            log.info(f"USER: Disabled {username}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "User disabled successfully"}),
            }
        except ClientError as e:
            log.error(f"Error disabling user: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }

    def enable_user(self, event):
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        username = unquote(event["pathParameters"]["username"])
        
        if self.user_admin_group and self.user_admin_group not in permissions:
            log.info(f"USER: Enable denied for {username} | Reason: Missing admin permission")
            return {
                "statusCode": 403,
                "body": json.dumps({"message": "You are not authorized to enable users"}),
            }
        
        try:
            cognito_client.admin_enable_user(
                UserPoolId=self.user_pool_id,
                Username=username,
            )
            log.info(f"USER: Enabled {username}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "User enabled successfully"}),
            }
        except ClientError as e:
            log.error(f"Error enabling user: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }
            
    def admin_confirm_user(self, event):
        permissions = self.get_permissions_from_token(
            event["requestContext"]["authorizer"]
        )
        username = unquote(event["pathParameters"]["username"])
        
        if self.user_admin_group and self.user_admin_group not in permissions:
            log.info(f"USER: Confirm denied for {username} | Reason: Missing admin permission")
            return {
                "statusCode": 403,
                "body": json.dumps({"message": "You are not authorized to confirm users"}),
            }
        
        try:
            cognito_client.admin_confirm_sign_up(
                UserPoolId=self.user_pool_id,
                Username=username,
            )
            log.info(f"USER: Admin confirmed {username}")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "User confirmed successfully"}),
            }
        except ClientError as e:
            log.error(f"Error confirming user: {e.response['Error']['Message']}")
            return {
                "statusCode": 400,
                "body": json.dumps({"message": e.response["Error"]["Message"]}),
            }
