import json
from typing import Optional
import pulumi
import pulumi_aws as aws
from dotenv import load_dotenv
import cloud_foundry
import logging
import os
import boto3
from .authorization_users import AuthorizationUsers
from .validation_function import ValidationFunction

load_dotenv()

log = logging.getLogger(__name__)

predefined_attributes = ["email", "phone_number", "preferred_username", "name", "given_name", "family_name", "middle_name", "nickname", "address", "birthdate", "gender", "locale", "picture", "profile", "updated_at", "website", "zoneinfo", "username"]

# Default attributes if none provided
default_attributes = [
    {"name": "email", "required": True, "mutable": True},
    {"name": "phone_number", "required": False, "mutable": True},
]

default_groups=[
    {"description": "Admins group", "role": "admin"},
    {"description": "Member group", "role": "user"},
]

default_password_policy = {
    "minimum_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_numbers": True,
    "require_symbols": False,
}


package_dir = "pkg://authorization_api"

class AuthorizationAPI(pulumi.ComponentResource):
    """
    A Pulumi component resource for deploying a secure authorization API using AWS Cognito and Lambda functions.
    This class provisions and configures:
      - An AWS Cognito User Pool with custom attributes, password policies, and user groups.
      - A Cognito User Pool Client with secret management.
      - AWS Lambda functions for security operations and token validation.
      - A REST API with endpoints for user and session management, integrated with the security Lambda.
      - Secure storage of client secrets and configuration in AWS SSM Parameter Store.
      - Extraction and removal of role-based security requirements from OpenAPI specifications.
    Args:
        name (str): The base name for resources.
        user_pool_id (Optional[str]): Existing Cognito User Pool ID. If not provided, a new pool is created.
        client_id (Optional[str]): Existing Cognito User Pool Client ID. If not provided, a new client is created.
        client_secret (Optional[str]): Existing Cognito User Pool Client Secret. If not provided, a new client is created.
        attributes (Optional[list]): List of custom attributes for the user pool.
        groups (Optional[list]): List of user groups with roles and descriptions.
        user_admin_group (Optional[str]): Name of the admin group. Defaults to "admin".
        user_default_group (Optional[str]): Name of the default user group. Defaults to "user".
        admin_emails (Optional[list]): List of admin email addresses.
        password_policy (Optional[dict]): Password policy configuration for the user pool.
        sms_message (Optional[str]): SMS message template for user invitations.
        email_message (Optional[str]): Email message template for user invitations and verification.
        email_subject (Optional[str]): Email subject for user invitations and verification.
        invitation_only (bool): If True, only admins can create users. Defaults to True.
        allow_alias_sign_in (bool): If True, allows alias sign-in (email, phone, username). Defaults to False.
        enable_mfa (bool): If True, enables multi-factor authentication. Defaults to False.
        use_token_verification (bool): If True, enables token verification Lambda integration. Defaults to False.
        opts (Optional[pulumi.ResourceOptions]): Pulumi resource options.
    Attributes:
        domain (str): The domain name of the deployed REST API.
        token_validator (str): The name of the token validator Lambda function.
        user_pool_id (str): The ID of the Cognito User Pool.
        validation_function (ValidationFunction): The validation function component that handles path roles and token validation.
    Methods:
        create_client_secret_param(name, client_id, user_pool_id, client_secret, user_pool_endpoint, user_admin_group, user_default_group, admin_emails, attributes):
            Stores client secret and configuration in AWS SSM Parameter Store as a SecureString.
    Example:
        api = AuthorizationAPI(
            "my-auth-api",
            attributes=[{"name": "department", "attribute_data_type": "String"}],
            groups=[{"role": "admin", "description": "Administrators"}],
            admin_emails=["admin@example.com"]
        )
        
        # Access the role mappings through the validation function component
        # (Note: This requires using Pulumi's apply method since validation_function is an Output)
        # validation_function_roles = api.validation_function.apply(lambda vf: vf.path_roles)
    """
    def __init__(
        self,
        name,
        user_pool_id=None,
        client_id=None,
        client_secret=None,
        attributes=None,
        groups: Optional[list[dict]] = None,
        user_admin_group: Optional[str] = None,
        user_default_group: Optional[str] = None,
        admin_emails: Optional[list] = None,
        password_policy: Optional[dict] = None,
        sms_message: Optional[str] = None,
        email_message: Optional[str] = None,
        email_subject: Optional[str] = None,
        invitation_only: bool = True,
        allow_alias_sign_in: bool = False,
        enable_mfa: bool = False,
        use_token_verification: bool = False,
        opts=None,
    ):
        super().__init__("cloud_foundry:api:SecurityAPI", name, {}, opts)

        user_pool = AuthorizationUsers(
            f"{name}-users",
            attributes=attributes or default_attributes,
            groups=groups or default_groups,
            password_policy=password_policy or default_password_policy,
            email_message=email_message,
            email_subject=email_subject,
            user_pool_id=user_pool_id,
            client_id=client_id or "",
        )

        client_secret_param = self.create_client_secret_param(
            name,
            client_id=user_pool.client_id,
            user_pool_id=user_pool.id,
            client_secret=user_pool.client_secret,
            user_pool_endpoint=user_pool.endpoint,
            user_admin_group=user_admin_group or "admin",
            user_default_group=user_default_group or "user",
            admin_emails=admin_emails or [],
            attributes=attributes or default_attributes,
        )

        # Security Lambda
        # Create policy statements using Pulumi apply to handle Outputs
        def create_security_function(args):
            user_pool_arn, client_secret_param_arn = args
            policy_statements = [
                json.dumps({
                    "Effect": "Allow",
                    "Actions": [
                        "cognito-idp:SignUp",
                        "cognito-idp:InitiateAuth",
                        "cognito-idp:GlobalSignOut",
                        "cognito-idp:AdminCreateUser",
                        "cognito-idp:AdminGetUser",
                        "cognito-idp:AdminSetUserPassword",
                        "cognito-idp:AdminListGroupsForUser",
                        "cognito-idp:AdminAddUserToGroup",
                        "cognito-idp:AdminRemoveUserFromGroup",
                        "cognito-idp:AdminDeleteUser",
                        "cognito-idp:AdminUpdateUserAttributes",
                        "cognito-idp:GetJWKS",
                    ],
                    "Resources": [user_pool_arn],
                }),
                json.dumps({
                    "Effect": "Allow",
                    "Actions": [
                        "ssm:GetParameter"
                    ],
                    "Resources": [client_secret_param_arn],
                })
            ]
            return cloud_foundry.python_function(
                "security-function",
                sources={"app.py": f"{package_dir}/authorization_lambda.py"},
                environment={
                    "CONFIG_PARAMETER": client_secret_param.name,
                    "ADMIN_EMAILS": json.dumps(admin_emails or []),
                },
                requirements=["pyjwt", "requests", "cryptography"],
                policy_statements=policy_statements,
                opts=pulumi.ResourceOptions(parent=self),
            )

        self.security_function = pulumi.Output.all(user_pool.arn, client_secret_param.arn).apply(create_security_function)

        # Load and create OpenAPI specification editor
        spec_path = os.path.join(os.path.dirname(__file__), "authorization_api.yaml")
        api_specification = cloud_foundry.OpenAPISpecEditor(spec_path)

        # Create ValidationFunction which handles both path roles extraction and token validator creation
        # We need to use pulumi.Output.apply to handle the dynamic user_pool.endpoint
        def create_validator(endpoint):
            return ValidationFunction(
                name="token-validator",
                api_specification=api_specification,
                user_pool_endpoint=endpoint,
                validator_name="auth",
                opts=pulumi.ResourceOptions(parent=self)
            )

        # Apply the ValidationFunction creation with the user pool endpoint
        self.validation_function = user_pool.endpoint.apply(create_validator)
        
        # Extract the token_validator from the ValidationFunction
        self.token_validator = self.validation_function.apply(lambda vf: vf.token_validator)
        
        # REST API
        self.api = cloud_foundry.rest_api(
            "security-api",
            logging=True,
            specification=self.build_api(api_specification, enable_mfa),
            token_validators=[
                {
                    "type": "token_validator",
                    "name": "auth",
                    "function": self.token_validator,
                }
            ],
            integrations=self.build_integrations(
                self.security_function, enable_mfa=enable_mfa
            ),
            export_api="./temp/security-services-api.yaml",
            opts=pulumi.ResourceOptions(parent=self),
        )

        self.domain = self.api.domain
        self.user_pool_id = user_pool.id

        self.register_outputs(
            {
                "domain": self.api.domain,
                "user_pool_id": user_pool.id,
            }
        )

    def create_client_secret_param(self, name, client_id, user_pool_id, client_secret, user_pool_endpoint, user_admin_group, user_default_group, admin_emails, attributes):
        def serialize_config(client_id_value, user_pool_id_value, client_secret_value, user_pool_endpoint, attributes):
            # Create the JSON configuration
            config = {
                "client_id": client_id_value,
                "user_pool_id": user_pool_id_value,
                "client_secret": client_secret_value,
                "issuer": user_pool_endpoint,
                "logging_level": "DEBUG",
                "user_admin_group": user_admin_group,
                "user_default_group": user_default_group,
                "admin_emails": admin_emails or [],
                "attributes": attributes
            }
            return json.dumps(config)

        # Apply method to combine outputs
        config_output = pulumi.Output.all(
            client_id, 
            user_pool_id,
            client_secret,
            user_pool_endpoint,
            attributes
        ).apply(lambda values: serialize_config(*values))

        log.info(f"Client secret configuration: {config_output}")
        # Create a Parameter Store resource for storing the client secret
        return aws.ssm.Parameter(
            f"{name}-client-secret-param",
            name=f"/{cloud_foundry.resource_id(name)}/config",
            type="SecureString",
            value=config_output,
            opts=pulumi.ResourceOptions(parent=self),
        )

    def build_api(self, api_specification: cloud_foundry.OpenAPISpecEditor, enable_mfa, allow_alias_sign_in=False):
        # Clone the OpenAPI specification to avoid mutating the original
        # This prevents race conditions and allows the original to be used elsewhere
        import copy
        api_spec_copy = cloud_foundry.OpenAPISpecEditor(copy.deepcopy(api_specification.openapi_spec))
        
        # Remove any roles from the security instances in the OpenAPI specification
        # The gateway doesn't accept custom validators with role arrays
        self._remove_roles_from_security_schemes(api_spec_copy)
        
        if enable_mfa:
            api_spec_copy.set(['paths', "/sessions", "post", "responses", "200", "content", "application/json", "schema", "$ref" ], "#/components/schemas/MfaResponse")
        else:
            api_spec_copy.prune(['components', 'schemas', 'MFARequest'])
            api_spec_copy.prune(['components', 'schemas', 'MfaResponse'])
            api_spec_copy.prune(['paths', "/sessions/mfa"])

        if allow_alias_sign_in:
            # Add 'email' and 'phone_number' properties to the sign-in request schema
            api_spec_copy.set(
                ['components', 'schemas', 'SignInRequest', 'properties', 'email'],
                {"type": "string", "format": "email"}
            )
            api_spec_copy.set(
                ['components', 'schemas', 'SignInRequest', 'properties', 'phone_number'],
                {"type": "string", "pattern": "^\\+?[1-9]\\d{1,14}$"}
            )
        return api_spec_copy.to_yaml()

    def build_integrations(self, security_function, enable_mfa: bool = False) -> list:  
        # Define the integrations for the API
        integrations = [
            {
            "path": "/users",
            "method": "POST",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/users/confirm",
            "method": "POST",
            "function": security_function,
            "auth": False,
            },
            {
            "path": "/users/{username}",
            "method": "GET",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/users/{username}",
            "method": "DELETE",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/users/me",
            "method": "GET",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/users/me/password",
            "method": "PUT",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/users/{username}/groups",
            "method": "PUT",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/users/{username}/disable",
            "method": "POST",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/users/{username}/enable",
            "method": "POST",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/sessions",
            "method": "POST",
            "function": security_function,
            "auth": False,
            },
            {
            "path": "/sessions/me",
            "method": "DELETE",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/sessions/refresh",
            "method": "POST",
            "function": security_function,
            "auth": True,
            },
        ]
        if enable_mfa:
            integrations.append({
                "path": "/sessions/mfa",
                "method": "POST",
                "function": security_function,
                "auth": True,
                })
        return integrations


    def _remove_roles_from_security_schemes(self, api_specification: cloud_foundry.OpenAPISpecEditor):
        """
        Remove any roles from security schemes in the OpenAPI specification.
        AWS API Gateway doesn't accept custom validators with role arrays in security requirements.
        """
        # Get all paths from the specification
        path_items = api_specification.get_spec_part(['paths'])
        
        if not isinstance(path_items, dict):
            log.warning("OpenAPI spec 'paths' is not a dictionary. Skipping roles removal.")
            return
            
        # Iterate through all paths and operations
        for path, path_item in path_items.items():
            if isinstance(path_item, dict):
                for method, operation in path_item.items():
                    if isinstance(operation, dict) and 'security' in operation:
                        security_requirements = operation.get('security', [])
                        
                        # Modify each security requirement to remove role arrays
                        for security_req in security_requirements:
                            if isinstance(security_req, dict):
                                for validator_name in security_req:
                                    # Clear the roles array but keep the validator
                                    security_req[validator_name] = []
                        
                        log.debug(f"Cleared roles from security requirements for {method.upper()} {path}")
        
        log.info("Removed all roles from security schemes for API Gateway compatibility")