import os
import pulumi
import pulumi_aws as aws
from dotenv import load_dotenv
import cloud_foundry

load_dotenv()


class AuthorizationAPI(pulumi.ComponentResource):
    def __init__(
        self,
        name,
        user_pool_id,
        client_id,
        client_secret,
        user_admin_group: str = None,
        user_default_group: str = None,
        opts=None,
    ):
        super().__init__("cloud_foundry:api:SecurityAPI", name, {}, opts)
        source_dir = "./tests/resources/security_services"

        # Helper to get region/account/user pool
        region = os.getenv("AWS_REGION") or aws.get_region().name
        account_id = os.getenv("AWS_ACCOUNT_ID") or aws.get_caller_identity().account_id

        def get_issuer():
            if not user_pool_id:
                raise ValueError("user_pool_id environment variable is not set.")
            return pulumi.Output.concat(
                "https://cognito-idp.", region, ".amazonaws.com/", user_pool_id
            )

        # Security Lambda
        self.security_function = cloud_foundry.python_function(
            "security-function",
            sources={"app.py": f"{source_dir}/security_lambda.py"},
            environment={
                "CLIENT_ID": client_id,
                "USER_POOL_ID": user_pool_id,
                "CLIENT_SECRET": client_secret,
                "ISSUER": get_issuer(),
                "LOGGING_LEVEL": "DEBUG",
                "USER_ADMIN_GROUP": user_admin_group,
                "USER_DEFAULT_GROUP": user_default_group,
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
                    "Resources": [
                        pulumi.Output.concat(
                            "arn:aws:cognito-idp:",
                            region,
                            ":",
                            account_id,
                            ":userpool/",
                            user_pool_id,
                        )
                    ],
                }
            ],
            opts=pulumi.ResourceOptions(parent=self),
        )

        # Token Validator Lambda
        self.token_validator = cloud_foundry.python_function(
            "token-validator",
            sources={"app.py": f"{source_dir}/token_validator.py"},
            requirements=["pyjwt", "requests", "cryptography"],
            environment={"ISSUER": get_issuer()},
            opts=pulumi.ResourceOptions(parent=self),
        )

        # REST API
        self.api = cloud_foundry.rest_api(
            "security-api",
            logging=True,
            specification="./tests/resources/security_services/api_spec.yaml",
            token_validators=[
                {
                    "type": "token_validator",
                    "name": "auth",
                    "function": self.token_validator,
                }
            ],
            integrations=[
                {
                    "path": "/users",
                    "method": "post",
                    "function": self.security_function,
                },
                {
                    "path": "/users/{username}",
                    "method": "get",
                    "function": self.security_function,
                },
                {
                    "path": "/users/me",
                    "method": "delete",
                    "function": self.security_function,
                },
                {
                    "path": "/users/{username}",
                    "method": "delete",
                    "function": self.security_function,
                },
                {
                    "path": "/users/me/password",
                    "method": "put",
                    "function": self.security_function,
                },
                {
                    "path": "/users/{username}/groups",
                    "method": "put",
                    "function": self.security_function,
                },
                {
                    "path": "/sessions",
                    "method": "post",
                    "function": self.security_function,
                },
                {
                    "path": "/sessions/me",
                    "method": "delete",
                    "function": self.security_function,
                },
                {
                    "path": "/sessions/refresh",
                    "method": "post",
                    "function": self.security_function,
                },
            ],
            export_api="./temp/security-services-api.yaml",
            opts=pulumi.ResourceOptions(parent=self),
        )

        self.domain = self.api.domain
        self.token_validator = self.token_validator

        self.register_outputs(
            {
                "domain": self.api.domain,
                "token_validator": self.token_validator.function_name,
            }
        )
