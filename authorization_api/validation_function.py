import json
import pulumi
import cloud_foundry
import logging
from typing import Dict, Any, Optional

log = logging.getLogger(__name__)

package_dir = "pkg://authorization_api"

class ValidationFunction(pulumi.ComponentResource):
    """
    A Pulumi ComponentResource for creating and managing token validation infrastructure.
    
    This component handles:
    - Extraction of role-based security requirements from OpenAPI specifications
    - Creation of AWS Lambda function for token validation
    - Configuration of the validator with extracted path roles
    - Proper resource hierarchy and management within Pulumi
    
    The component creates a token validator Lambda function that receives the ISSUER
    and PATH_ROLES environment variables, enabling it to validate JWT tokens and
    enforce role-based access control based on the OpenAPI specification.
    """
    
    def __init__(self, name: str, api_specification: cloud_foundry.OpenAPISpecEditor, user_pool_endpoint: str, validator_name: str = "auth", opts: Optional[pulumi.ResourceOptions] = None) -> None:
        """
        Initialize the ValidationFunction as a Pulumi ComponentResource.
        
        Args:
            name: The name of this component resource
            api_specification: The OpenAPI specification editor instance
            user_pool_endpoint: The Cognito user pool endpoint
            validator_name: The name of the validator/authenticator (default: "auth")
            opts: Optional Pulumi resource options
        
        Outputs:
            token_validator: The AWS Lambda function for token validation
            path_roles: Dictionary of extracted path roles from OpenAPI spec
            validator_name: The name of the validator
        """
        super().__init__("authorization_api:ValidationFunction", name, {}, opts)
        self.api_specification = api_specification
        self.validator_name = validator_name
        
        # Extract path roles from the OpenAPI specification
        self._path_roles = self._extract_path_roles()
        
        # Token Validator Lambda
        self.token_validator = cloud_foundry.python_function(
            "token-validator",
            sources={"app.py": f"{package_dir}/validator_lambda.py"},
            requirements=["pyjwt", "requests", "cryptography"],
            environment={
                "ISSUER": user_pool_endpoint, 
                "PATH_ROLES": json.dumps(self._path_roles)
            },
            opts=pulumi.ResourceOptions(parent=self),
        )

        # Register outputs for this component resource
        self.register_outputs({
            "token_validator": self.token_validator,
            "path_roles": self._path_roles,
            "validator_name": self.validator_name
        })

    def _extract_path_roles(self) -> Dict[str, list]:
        """
        Extract roles per operation for ONLY this validator.
        Leaves the validator present in the spec with an empty array so API Gateway still invokes it.
        """
        path_roles: Dict[str, list] = {}
        spec = self.api_specification.openapi_spec
        paths = spec.get("paths", {})

        for raw_path, operations in paths.items():
            if not isinstance(operations, dict):
                continue
            for method, op_obj in operations.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                    continue
                if not isinstance(op_obj, dict):
                    continue
                sec_reqs = op_obj.get("security")
                if not isinstance(sec_reqs, list):
                    continue
                modified = False
                for sec_req in sec_reqs:
                    if not isinstance(sec_req, dict):
                        continue
                    if self.validator_name in sec_req:
                        roles = sec_req.get(self.validator_name) or []
                        if roles:
                            key = f"{method.upper()} {raw_path}"
                            path_roles[key] = roles
                        # Always clear roles but keep validator present
                        sec_req[self.validator_name] = []
                        modified = True
                if modified:
                    op_obj["security"] = sec_reqs  # ensure retained

        # Handle top-level security (inherited cases)
        top_sec = spec.get("security")
        if isinstance(top_sec, list):
            for sec_req in top_sec:
                if isinstance(sec_req, dict) and self.validator_name in sec_req:
                    roles = sec_req.get(self.validator_name) or []
                    if roles:
                        # We cannot map to specific operations here—leave extraction of
                        # inherited roles out or optionally log a warning.
                        pass
                    sec_req[self.validator_name] = []  # retain authorizer

        return path_roles
    
    @property
    def path_roles(self) -> Dict[str, Any]:
        """Get the extracted path roles mapping."""
        return getattr(self, '_path_roles', {})
    
    def get_path_roles_summary(self) -> str:
        """Get a formatted summary of extracted path roles for debugging."""
        if not self._path_roles:
            return f"No path roles extracted for validator '{self.validator_name}'"
        
        summary = f"Path roles for validator '{self.validator_name}':\n"
        for operation, roles in self._path_roles.items():
            summary += f"  {operation}: {roles}\n"
        return summary.strip()
