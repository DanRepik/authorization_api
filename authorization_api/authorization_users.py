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
        email_message: Optional[str] = None,
        email_subject: Optional[str] = None,
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
            user_pool = aws.cognito.UserPool(
                f"{name}-user-pool",
                name=resource_id(name),
                auto_verified_attributes=["email"],  # Auto-verify emails
                schemas=schemas,
                password_policy=aws.cognito.UserPoolPasswordPolicyArgs(**password_policy) if password_policy is not None else aws.cognito.UserPoolPasswordPolicyArgs(**default_password_policy),
                admin_create_user_config={
                    # Allow users to sign up themselves
                    "allow_admin_create_user_only": False
                },
                verification_message_template={
                    "default_email_option": "CONFIRM_WITH_LINK",
                    "email_message_by_link": email_message or "Click the link below to verify your email address:\n{##Verify Email##}",  # noqa e501
                    "email_subject_by_link": email_subject or "Verify your email",
                },
                email_configuration={"email_sending_account": "COGNITO_DEFAULT"},
                opts=ResourceOptions(parent=self),
            )

        if client_id:
            user_pool_client = aws.cognito.UserPoolClient.get(f"{name}-user-pool-client",client_id)
            existing_groups = aws.cognito.get_user_groups(user_pool_id=user_pool.id)
            # Remove any groups that already exist in the user pool
            group_names = {g["role"] for g in (groups or []) if isinstance(g, dict) and "role" in g}
            existing_group_names = {g.name for g in existing_groups.groups}
            filtered_groups = [g for g in (groups or []) if g.get("role") not in existing_group_names]
            self.create_user_groups(user_pool, name, filtered_groups)
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
        """
        for group in groups or []:
            # Validate group structure
            if not isinstance(group, dict) or "role" not in group or "description" not in group:
                raise ValueError("Each group must be a dictionary with 'role' and 'description' keys.")
            
            aws.cognito.UserGroup(
                f"{name}-{group['role']}-group",
                user_pool_id=user_pool.id,
                name=group["role"],
                description=group["description"],
                opts=ResourceOptions(parent=self),
            )


        return user_pool
    
