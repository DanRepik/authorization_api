import pulumi_aws as aws
from pulumi import ComponentResource, ResourceOptions
from cloud_foundry.utils.names import resource_id


class UserPool(ComponentResource):
    def __init__(
        self,
        name,
        attributes: list[str] = None,
        password_policy: dict = None,
        groups: list = None,
        email_message: str = None,
        email_subject: str = None,
        opts=None,
    ):
        super().__init__("cloud_foundry:user_pool:Domain", name, {}, opts)

        # Create Cognito User Pool with custom attributes
        user_pool = aws.cognito.UserPool(
            f"{name}-user-pool",
            name=resource_id(name),
            auto_verified_attributes=["email"],  # Auto-verify emails
            schemas=[
                {
                    "name": attr,
                    "attribute_data_type": "String",
                    "mutable": True,
                    "required": False,
                }
                for attr in attributes or []
            ],
            password_policy=password_policy or {
                "minimum_length": 8,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_numbers": True,
                "require_symbols": False,
            },
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
            opts=ResourceOptions(parent=self),
        )

        for group in groups or []:
            # Create User Pool Groups with specified names and descriptions
            aws.cognito.UserGroup(
                f"{name}-{group["role"]}-group",
                user_pool_id=user_pool.id,
                name=group["role"],
                description=group["description"],
                opts=ResourceOptions(parent=self),
            )

        self.arn = user_pool.arn
        self.id = user_pool.id
        self.client_id = user_pool_client.id
        self.client_secret = user_pool_client.client_secret

        self.register_outputs(
            {
                "id": self.id,
                "arn": self.arn,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
        )
