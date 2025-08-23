## Authorization API for AWS Cognito (Pulumi Component)

This package is a reusable Pulumi Component that deploys a secure, Cognito‑backed Authorization API on AWS. It provisions a Cognito User Pool and Client, a Lambda security function, a token validation function, and an API Gateway REST API with endpoints for signup, confirmation, session management, and user administration.

Highlights
- Turn‑key REST API for authentication and user management
- AWS Cognito integration (user pool, client, groups, password policy)
- Lambda handler for security operations
- Token validator wiring for API Gateway
- OpenAPI spec driven, exportable to YAML

Documentation status: Active. Interfaces are stabilizing; small changes are still possible.

---

## Architecture

- Cognito User Pool and User Pool Client
- Security Lambda (handles signup, login, groups, etc.)
- Token Validation function for API Gateway custom authorizer
- API Gateway REST API generated from `authorization_api/authorization_api.yaml`

The OpenAPI used to deploy is edited at runtime to remove validator role arrays for API Gateway compatibility and exported to `./temp/security-services-api.yaml`.

---

## Attributes

Attributes are the Cognito user profile fields your app cares about. The component:
- Provisions these attributes in the Cognito User Pool (standard or custom)
- Stores the attribute configuration in SSM for the runtime Lambda
- Enforces required attributes during signup and writes provided values to the user profile

Defining attributes
- Standard attributes: use their Cognito names (e.g., `email`, `phone_number`, `name`)
- Custom attributes: provide the raw name (e.g., `department`); the component will create them in the pool as `custom:department`

Supported attribute options per item
- name: string (required)
- required: bool (default False)
- mutable: bool (default True)
- attribute_data_type: "String" | "Number" (default "String")
- string_constraints: { min_length?: int, max_length?: int }
- number_constraints: { min_value?: string, max_value?: string }

Example (Pulumi code)
```python
api = AuthorizationAPI(
		name="auth",
		attributes=[
				{"name": "email", "required": True, "mutable": True},
				{"name": "department", "required": False, "attribute_data_type": "String"},
				{"name": "age", "attribute_data_type": "Number", "number_constraints": {"min_value": "18"}},
		],
)
```

How attributes are used at runtime
- During signup (POST /users), the service builds Cognito UserAttributes from the request body using the configured attribute list
- Any attribute marked required must appear in the request or signup will fail
- Provided values are written to the Cognito user profile
- User attributes are returned by the API in `user_info` on login/refresh and when fetching a user; they are not added to JWTs by default

Signup payload example
```json
{
	"username": "jdoe",
	"password": "Password123!",
	"email": "jdoe@example.com",
	"department": "Engineering",
	"age": 34
}
```

Notes
- Use the raw field names in API requests (e.g., `department`), not the `custom:` prefix
- Changes to attributes require a redeploy to update the user pool schema and configuration consumed by the Lambda

---

## Prerequisites

- Python 3.9+
- Pulumi CLI and an AWS backend configured
- AWS credentials with permissions for Cognito, Lambda, API Gateway, and SSM Parameter Store

---

## Quick start

1) Install dependencies (editable install for local development)

```bash
pip install -r requirements.txt
pip install -e .
```

2) Use in a Pulumi Python program

```python
import pulumi
from authorization_api.authorization_api import AuthorizationAPI

# Minimal usage; most defaults provided by the component
api = AuthorizationAPI(
	name="auth",
	attributes=[{"name": "email", "required": True}],
	groups=[{"role": "admin", "description": "Admins"}, {"role": "user", "description": "Users"}],
	email_subject="Verify your email",
	email_message="Click the link to verify: {##Verify Email##}",
	enable_mfa=False,
)

pulumi.export("domain", api.domain)
pulumi.export("user_pool_id", api.user_pool_id)
```

3) Deploy

```bash
pulumi up
```

Outputs
- domain: API Gateway domain
- user_pool_id: Cognito User Pool ID

---

## Configuration options (constructor)

Key parameters on `AuthorizationAPI`:
- name: Base name for resources
- user_pool_id, client_id, client_secret: Reuse existing Cognito resources if provided
- attributes: List of Cognito attributes to provision (defaults include email/phone)
- groups: List of groups `{ role, description }` to create (defaults: admin, user)
- password_policy: Dict of password policy (default is sane minimums)
- email_message, email_subject: Templates for Cognito email verification/invite
- enable_mfa: If True, exposes an MFA path and response schema

Notes
- Some documented flags (e.g., alias sign‑in) may be reserved for future expansion unless visible in code. See `authorization_api/authorization_api.py` for the source of truth.

---

## Endpoints

A detailed endpoint reference lives in `authorization_api/readme.md`. Core routes include:
- POST /users (signup)
- POST /users/confirm (confirm signup)
- GET/DELETE /users/{username} (admin)
- GET /users/me
- PUT /users/me/password
- PUT /users/{username}/groups (admin)
- POST /sessions (login)
- DELETE /sessions/me (logout)
- POST /sessions/refresh
- POST /sessions/mfa (when enabled)

The OpenAPI source is `authorization_api/authorization_api.yaml`; the deployed YAML is exported to `temp/security-services-api.yaml`.

Security tip: Do not add endpoints that return user confirmation codes. Instead, implement resend flows via Cognito.

---

## Development

Run tests

```bash
pytest -q
```

Project config
- Test discovery is configured in `pyproject.toml` (pytest)

Build/publish (flit)

```bash
python -m pip install flit
flit build
flit publish  # optional
```

---

## Troubleshooting

- Pulumi/AWS credentials: ensure your AWS profile has permissions for Cognito, Lambda, API Gateway, and SSM.
- Stuck stacks: export the generated OpenAPI at `temp/security-services-api.yaml` to inspect the effective spec.
- Missing endpoints: verify `authorization_api/authorization_api.yaml` and the integrations in `AuthorizationAPI.build_integrations`.

---

## License

Apache-2.0