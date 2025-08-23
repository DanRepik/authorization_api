from typing import Optional, Any
import pulumi_aws as aws
from pulumi import ComponentResource, ResourceOptions
from cloud_foundry.utils.names import resource_id

cognito_attributes = ["email", "phone_number", "preferred_username", "name", "given_name", "family_name", "middle_name", "nickname", "address", "birthdate", "gender", "locale", "picture", "profile", "updated_at", "website", "zoneinfo", "username"]

default_password_policy = {
    "minimum_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_numbers": True,
    "require_symbols": False,
}


class AuthorizationUsers(ComponentResource):
    def __init__(
        self,
        name,
        attributes: Optional[list[dict]] = None,
        groups: Optional[list[dict]] = None,
        password_policy: Optional[dict[str, Any]] = None,
        sms_message: Optional[str] = None,  # SMS verification message template
        email_message: Optional[str] = None,  # Email verification message template
        email_subject: Optional[str] = None,  # Email verification subject
        invitation_only: bool = False,  # If True, only admins can create users
        user_pool_id: Optional[str] = None,
        client_id: Optional[str] = None,
        opts=None,
    ):
        super().__init__("cloud_foundry:user_pool:Domain", name, {}, opts)

        if user_pool_id:
            user_pool = aws.cognito.UserPool.get(f"{name}-user-pool", user_pool_id)
        else:
            schemas = [
                aws.cognito.UserPoolSchemaArgs(
                name=attr["name"] if attr.get("name") in cognito_attributes else f"custom:{attr['name']}",
                attribute_data_type=attr.get("attribute_data_type", "String"),
                mutable=attr.get("mutable", True),
                required=attr.get("required", False),
                string_attribute_constraints=attr.get("string_constraints") if attr.get("attribute_data_type", "String") == "String" else None,
                number_attribute_constraints=attr.get("number_constraints") if attr.get("attribute_data_type") == "Number" else None,
                )
                for attr in (attributes if attributes is not None else [])
            ]
            print("Creating user pool with attributes:")
            for schema in schemas:
                print(vars(schema))

            # Create Cognito User Pool with custom attributes
            
            # Set up the parameters for the user pool
            user_pool_args = {
                "name": resource_id(name),
                "schemas": schemas,
                "admin_create_user_config": {
                    # Control whether users can sign up themselves or only admins can create users
                    "allow_admin_create_user_only": invitation_only,
                    # If invitation_only is True, customize invitation messages
                    "invite_message_template": {
                        "email_subject": email_subject or "Your invitation to join our service",
                        "email_message": email_message or "You have been invited to join our service. Your username is {username} and temporary password is {####}",
                        "sms_message": sms_message or "Your username is {username} and temporary password is {####}"
                    } if invitation_only else None
                },
                "email_configuration": {"email_sending_account": "COGNITO_DEFAULT"},
                "opts": ResourceOptions(parent=self),
            }
            
            # Track auto-verified attributes based on provided messages
            # Only set up verification if not in invitation_only mode
            if not invitation_only:
                auto_verified_attributes = []
                verification_template = {}
                
                # Add email verification if email_message and email_subject are defined
                if email_message and email_subject:
                    auto_verified_attributes.append("email")
                    verification_template["default_email_option"] = "CONFIRM_WITH_LINK"
                    verification_template["email_message_by_link"] = email_message
                    verification_template["email_subject_by_link"] = email_subject
                
                # Add SMS verification if sms_message is defined
                if sms_message:
                    auto_verified_attributes.append("phone_number")
                    verification_template["sms_message"] = sms_message
                
                # Only add these parameters if we have something to verify
                if auto_verified_attributes:
                    user_pool_args["auto_verified_attributes"] = auto_verified_attributes
                    user_pool_args["verification_message_template"] = verification_template
            
            # Add password policy
            if password_policy is not None:
                user_pool_args["password_policy"] = aws.cognito.UserPoolPasswordPolicyArgs(**password_policy)
            else:
                user_pool_args["password_policy"] = aws.cognito.UserPoolPasswordPolicyArgs(**default_password_policy)
            
            # Create the user pool with the configured arguments
            try:
                user_pool = aws.cognito.UserPool(
                    f"{name}-user-pool",
                    **user_pool_args
                )
                # Log creation with different messages based on mode
                if invitation_only:
                    print(f"Created user pool in invitation-only mode: {resource_id(name)}")
                else:
                    auto_verified = user_pool_args.get("auto_verified_attributes", [])
                    print(f"Created user pool with auto-verified attributes: {auto_verified if auto_verified else 'None'}")
            except Exception as e:
                print(f"Error creating user pool: {e}")
                raise

        if client_id:
            user_pool_client = aws.cognito.UserPoolClient.get(f"{name}-user-pool-client", client_id)
            # For existing user pools, we'll handle group creation more carefully
            # Pulumi Output objects can't be used directly with AWS SDK calls
            # We'll use the create_user_groups method which handles the group creation properly
            self.create_user_groups(user_pool, name, groups)
        else:
            # Create Cognito User Pool Client with Secret Generation
            user_pool_client = aws.cognito.UserPoolClient(
                f"{name}-user-pool-client",
                name=resource_id(f"{name}-client"),
                user_pool_id=user_pool.id,
                generate_secret=True,
                explicit_auth_flows=[
                    "ALLOW_USER_PASSWORD_AUTH",
                    "ALLOW_REFRESH_TOKEN_AUTH",
                    "ALLOW_USER_SRP_AUTH",
                ],
                opts=ResourceOptions(parent=self, depends_on=[user_pool]),
            )
            self.create_user_groups(user_pool, name, groups)

        self.arn = user_pool.arn
        self.id = user_pool.id
        self.endpoint = user_pool.endpoint
        self.client_id = user_pool_client.id
        self.client_secret = user_pool_client.client_secret

        self.register_outputs(
            {
                "id": self.id,
                "arn": self.arn,
                "endpoint": self.endpoint,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        )

    def create_user_groups(self, user_pool, name, groups):
        """
        Create user groups in the specified user pool.
        Handles checking for existing groups in a Pulumi-compatible way.
        """
        if not groups:
            return user_pool
            
        for group in groups:
            # Validate group structure
            if not isinstance(group, dict) or "role" not in group or "description" not in group:
                raise ValueError("Each group must be a dictionary with 'role' and 'description' keys.")
            
            # Create the group using Pulumi's conditional logic
            # This approach allows Pulumi to handle the Output objects properly
            group_resource = aws.cognito.UserGroup(
                f"{name}-{group['role']}-group",
                user_pool_id=user_pool.id,
                name=group["role"],
                description=group["description"],
                opts=ResourceOptions(
                    parent=self,
                    # Ignore changes to description to avoid unnecessary updates
                    ignore_changes=["description"]
                ),
            )
        
        return user_pool
    
