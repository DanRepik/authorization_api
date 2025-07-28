import json
import pulumi
import pulumi_aws as aws
from dotenv import load_dotenv
import cloud_foundry
import logging
import os
import boto3

load_dotenv()

log = logging.getLogger(__name__)

predefined_attributes = ["email", "phone_number", "preferred_username", "name", "given_name", "family_name", "middle_name", "nickname", "address", "birthdate", "gender", "locale", "picture", "profile", "updated_at", "website", "zoneinfo", "username"]

# Default attributes if none provided
default_attributes = [
    {"name": "email", "required": True, "mutable": True},
    {"name": "phone_number", "required": False, "mutable": True},
    {"name": "given_name", "required": False, "mutable": True},
    {"name": "family_name", "required": False, "mutable": True},
]


default_groups = [
                    {"description": "Admins group", "role": "admin"},
                    {"description": "Superuser group", "role": "superuser"},
                    {"description": "User group", "role": "user"},
                ]

package_dir = "pkg://authorization_api"

default_password_policy = {
    "minimum_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_numbers": True,
    "require_symbols": False,
}

class AuthorizationAPI(pulumi.ComponentResource):
    """
    A Pulumi component resource for deploying a secure authorization API using AWS Cognito and Lambda functions.
    This class provisions and configures:
      - An AWS Cognito User Pool with custom attributes, password policies, and user groups.
      - A Cognito User Pool Client with secret management.
      - AWS Lambda functions for security operations and token validation.
      - A REST API with endpoints for user and session management, integrated with the security Lambda.
      - Secure storage of client secrets and configuration in AWS SSM Parameter Store.
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
    Methods:
        create_user_pool(name, attributes, groups, password_policy, email_message, email_subject, invitation_only):
            Creates a Cognito User Pool with custom attributes and groups.
        create_client_secret_param(name, client_id, user_pool_id, client_secret, user_pool_endpoint, user_admin_group, user_default_group, admin_emails, attributes):
            Stores client secret and configuration in AWS SSM Parameter Store as a SecureString.
    Example:
        api = AuthorizationAPI(
            "my-auth-api",
            attributes=[{"name": "department", "attribute_data_type": "String"}],
            groups=[{"role": "admin", "description": "Administrators"}],
            admin_emails=["admin@example.com"]
    """
    def __init__(
        self,
        name,
        user_pool_id=None,
        client_id=None,
        client_secret=None,
        attributes=None,
        groups=None,
        user_admin_group: str = None,
        user_default_group: str = None,
        admin_emails=None,
        password_policy=None,
        sms_message=None,
        email_message=None,
        email_subject=None,
        invitation_only: bool = True,
        allow_alias_sign_in: bool = False,
        enable_mfa: bool = False,
        use_token_verification: bool = False,
        opts=None,
    ):
        super().__init__("cloud_foundry:api:SecurityAPI", name, {}, opts)

        if user_pool_id:
            user_pool = aws.cognito.UserPool.get(user_pool_id)
        else:
            user_pool = self.create_user_pool(
                name,
                attributes=attributes,
                groups=groups,
                password_policy=password_policy,
                email_message=email_message,
                email_subject=email_subject,
                invitation_only=invitation_only,
                allow_alias_sign_in=allow_alias_sign_in,
            )

        self.create_user_groups(user_pool, groups)
            
        if not client_id or not client_secret:
            user_pool_client = aws.cognito.UserPoolClient(
                f"{name}-auto-client",
                name=cloud_foundry.resource_id(f"{name}-auto-client"),
                user_pool_id=user_pool.id,
                generate_secret=True,
                explicit_auth_flows=[
                    "ALLOW_USER_PASSWORD_AUTH",
                    "ALLOW_REFRESH_TOKEN_AUTH",
                    "ALLOW_USER_SRP_AUTH",
                ],
                opts=pulumi.ResourceOptions(parent=self),
            )
            client_id = user_pool_client.id
            client_secret = user_pool_client.client_secret

        # Fetch user pool attributes using boto3, using apply to handle Pulumi Output
        def fetch_attributes(user_pool_id):
            cognito_client = boto3.client("cognito-idp")
            user_pool_desc = cognito_client.describe_user_pool(UserPoolId=user_pool_id)
            pool_attributes = user_pool_desc["UserPool"]["SchemaAttributes"]
            def convert_schema(attr):
                return {
                    "name": attr["Name"],
                    "attribute_data_type": attr.get("AttributeDataType", "String"),
                    "required": attr.get("Required", False),
                    "mutable": attr.get("Mutable", True),
                    "string_constraints": attr.get("StringAttributeConstraints", {}),
                }
            return [convert_schema(a) for a in pool_attributes]

        attributes_from_pool = user_pool.id.apply(fetch_attributes)

        client_secret_param = self.create_client_secret_param(
            name,
            client_id,
            user_pool.id,
            client_secret,
            user_pool.endpoint,
            user_admin_group or "admin",
            user_default_group or "user",
            admin_emails or [],
            attributes_from_pool,
        )

        # Security Lambda
        self.security_function = cloud_foundry.python_function(
            "security-function",
            sources={"app.py": f"{package_dir}/authorization_lambda.py"},
            environment={
                "CONFIG_PARAMETER": client_secret_param.name
            },
            requirements=["pyjwt", "requests", "cryptography"],
            policy_statements=[
                {
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
                    "Resources": [ user_pool.arn ],
                }
            ],
            opts=pulumi.ResourceOptions(parent=self),
        )

        # Token Validator Lambda
        self.token_validator = cloud_foundry.python_function(
            "token-validator",
            sources={"app.py": f"{package_dir}/validator_lambda.py"},
            requirements=["pyjwt", "requests", "cryptography"],
            environment={"ISSUER": user_pool.endpoint},
            opts=pulumi.ResourceOptions(parent=self),
        )

        
        # REST API
        self.api = cloud_foundry.rest_api(
            "security-api",
            logging=True,
            specification=self.build_api(enable_mfa),
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
        self.token_validator = self.token_validator
        self.user_pool_id = user_pool.id

        self.register_outputs(
            {
                "domain": self.api.domain,
                "token_validator": self.token_validator.function_name,
                "user_pool_id": user_pool.id,
            }
        )

    def create_user_groups(self, user_pool, name, groups=None):
        """
        Create user groups in the specified user pool.
        """
        for group in groups or default_groups:
            # Validate group structure
            if not isinstance(group, dict) or "role" not in group or "description" not in group:
                raise ValueError("Each group must be a dictionary with 'role' and 'description' keys.")
            
            # Create User Pool Groups with specified names and descriptions
            existing_groups = aws.cognito.get_user_groups(user_pool_id=user_pool.id)
            if any(g.name == group["role"] for g in existing_groups.groups):
                log.info(f"User group '{group['role']}' already exists in user pool '{user_pool.id}'. Skipping creation.")
                continue
            aws.cognito.UserGroup(
                f"{name}-{group['role']}-group",
                user_pool_id=user_pool.id,
                name=group["role"],
                description=group["description"],
                opts=pulumi.ResourceOptions(parent=self),
            )


        return user_pool
    
    def create_client_secret_param(self, name, client_id, user_pool_id, client_secret, user_pool_endpoint, user_admin_group, user_default_group, admin_emails, attributes):
        def serialize_config(client_id_value, user_pool_id_value, client_secret_value, user_pool_endpoint):
            # Create the JSON configuration
            config = {
                "CLIENT_ID": client_id_value,
                "USER_POOL_ID": user_pool_id_value,
                "CLIENT_SECRET": client_secret_value,
                "ISSUER": user_pool_endpoint,
                "LOGGING_LEVEL": "DEBUG",
                "USER_ADMIN_GROUP": user_admin_group,
                "USER_DEFAULT_GROUP": user_default_group,
                "ADMIN_EMAILS": admin_emails or [],
                "ATTRIBUTES": json.dumps(attributes)
            }
            return json.dumps(config)

        # Apply method to combine outputs
        config_output = pulumi.Output.all(
            client_id, 
            user_pool_id,
            client_secret,
            user_pool_endpoint
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

    def create_user_pool(self, name, attributes=None, groups=None, password_policy=None, email_message=None, email_subject=None, invitation_only=True, allow_alias_sign_in=False):
        # Create Cognito User Pool with custom attributes

        schemas = self.build_schemas(attributes)
        log.debug(f"schemas: {schemas}")

        admin_create_user_config= {
            "allow_admin_create_user_only": invitation_only,
            "invite_message_template": {
                "email_subject": email_subject or "Welcome to our service",
                "email_message": email_message or "You have been invited to join our service. Please click the link below to set your password and complete your registration:\n{##Invite Link##}",  # noqa e501
            }
        }
        # Set sign-in alias attributes based on allow_alias_sign_in
        alias_attributes = []
        if allow_alias_sign_in:
            alias_attributes = ["email", "phone_number"]

        # Add alias_attributes to user pool config if needed
        user_pool_config = {
            "auto_verified_attributes": ["email"],
            "alias_attributes": alias_attributes if alias_attributes else None,
            "schemas": schemas,
            "password_policy": password_policy or default_password_policy,
            "admin_create_user_config": admin_create_user_config,
            "verification_message_template": {
            "default_email_option": "CONFIRM_WITH_LINK",
            "email_message_by_link": email_message or "Click the link below to verify your email address:\n{##Verify Email##}",
            "email_subject_by_link": email_subject or "Verify your email",
            },
            "email_configuration": {"email_sending_account": "COGNITO_DEFAULT"},
            "opts": pulumi.ResourceOptions(parent=self),
        }
        # Remove None values to avoid Pulumi errors
        user_pool_config = {k: v for k, v in user_pool_config.items() if v is not None}
        user_pool = aws.cognito.UserPool(
            f"{name}-user-pool",
            name=cloud_foundry.resource_id(name),
            auto_verified_attributes=["email"],  # Auto-verify emails
            schemas=schemas,
            password_policy=password_policy or default_password_policy,
            admin_create_user_config={
                "allow_admin_create_user_only": invitation_only,
                "invite_message_template": {
                    "email_subject": email_subject or "Welcome to our service",
                    "email_message": email_message or "You have been invited to join our service. Please click the link below to set your password and complete your registration:\n{##Invite Link##}",  # noqa e501
                },
            },
            verification_message_template={
                "default_email_option": "CONFIRM_WITH_LINK",
                "email_message_by_link": email_message or "Click the link below to verify your email address:\n{##Verify Email##}",  # noqa e501
                "email_subject_by_link": email_subject or "Verify your email",
            },
            email_configuration={"email_sending_account": "COGNITO_DEFAULT"},
            opts=pulumi.ResourceOptions(parent=self),
        )
        log.info(f"Created user pool {user_pool.id} with attributes: {schemas}")

    def build_api(self, enable_mfa, allow_alias_sign_in=False):
        # Load the OpenAPI specification as a string
        with open(f"{package_dir}/authorization_api.yaml", "r") as spec_file:
            api_specification = spec_file.read()
        
        # Optionally edit the OpenAPI spec before deploying the API
        api_specification = cloud_foundry.OpenAPISpecEditor(api_specification)
        if enable_mfa:
            api_specification.set(['paths', "/sessions", "post", "200", "content", "application/json", "schema", "$ref" ], "#/components/schemas/MfaResponse")
        else:
            api_specification.prune(['components', 'schemas', 'MFARequest'])
            api_specification.prune(['components', 'schemas', 'MfaResponse'])
            api_specification.prune(['paths', "/sessions/mfa"])

        if allow_alias_sign_in:
            # Add 'email' and 'phone_number' properties to the sign-in request schema
            api_specification.set(
                ['components', 'schemas', 'SignInRequest', 'properties', 'email'],
                {"type": "string", "format": "email"}
            )
            api_specification.set(
                ['components', 'schemas', 'SignInRequest', 'properties', 'phone_number'],
                {"type": "string", "pattern": "^\\+?[1-9]\\d{1,14}$"}
            )
        return api_specification

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
            "path": "/users/{username}",
            "method": "GET",
            "function": security_function,
            "auth": True,
            },
            {
            "path": "/sessions",
            "method": "POST",
            "function": security_function,
            "auth": False,
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

    def build_schemas(self, attributes):
        """
        Build the schemas for the user pool attributes.
        """
        schemas = []
        for attr in attributes or default_attributes:
            if attr["name"] not in predefined_attributes:
                schemas.append({
                    "name": attr["name"],
                    "attribute_data_type": "String",
                    "required": attr.get("required", False),
                    "mutable": attr.get("mutable", True),
                    "string_constraints": attr.get("string_constraints", {}),
                })
            else:
                log.warning(f"Attribute '{attr['name']}' is a predefined attribute and will be ignored.")
        return schemas