import os
import json
import re
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
import requests
import logging
from typing import Dict, Any, List

log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOGGING_LEVEL", "DEBUG"))

# Load environment variables
AUTH_MAPPINGS = json.loads(os.getenv("AUTH0_AUTH_MAPPINGS", "{}"))
DEFAULT_ARN = "arn:aws:execute-api:*:*:*/*/*/*"

# Cognito user pool issuer URL
ISSUER = os.getenv(
    "ISSUER"
)  # expected format: https://cognito-idp.<region>.amazonaws.com/<user_pool_id>
PATH_ROLES = json.loads(os.getenv("PATH_ROLES", "{}"))

def handler(event, context):
    log.debug(f"PATH_ROLES keys: {list(PATH_ROLES.keys())}")
    """Main Lambda handler."""
    log.info(event)
    try:
        token = parse_token_from_event(check_event_for_error(event))
        decoded_token = decode_token(event, token)
        log.info(f"Decoded token: {decoded_token}")
        
        # Check role-based authorization if PATH_ROLES are configured
        if PATH_ROLES:
            check_path_authorization(event["methodArn"], decoded_token)
        
        policy = get_policy(
            event["methodArn"],
            decoded_token,
            "sec-websocket-protocol" in event["headers"],
        )
        log.info(f"Generated policy: {json.dumps(policy)}")
        return policy
    except (ExpiredSignatureError, InvalidTokenError) as e:
        log.error(f"Token validation failed: {e}")
        return {
            "statusCode": 401,
            "body": json.dumps({"message": "Unauthorized", "error": str(e)}),
        }
    except Exception as e:
        log.error(f"Authorization error: {e}")
        return {
            "statusCode": 500,
            "body": json.dumps({"message": "Internal Server Error", "error": str(e)}),
        }


def check_path_authorization(method_arn: str, decoded_token: Dict[str, Any]) -> None:
    """
    Enforce PATH_ROLES: keys are 'METHOD /path'
    """
    try:
        # methodArn: arn:aws:execute-api:region:acct:apiId/stage/METHOD/path/parts
        arn_parts = method_arn.split("/", 3)
        if len(arn_parts) < 4:
            log.debug(f"Unexpected methodArn format: {method_arn}")
            return
        method = arn_parts[2].upper()
        resource_path = "/" + arn_parts[3] if len(arn_parts) > 3 else "/"
        # Normalize double slashes
        resource_path = re.sub(r"//+", "/", resource_path)

        # Build keys
        request_key = f"{method} {resource_path}"
        user_roles = set(
            decoded_token.get("permissions", [])
            or decoded_token.get("cognito:groups", [])
            or []
        )

        # Exact or templated match
        required = None
        if request_key in PATH_ROLES:
            required = PATH_ROLES[request_key]
        else:
            # template fallback
            for pattern_key, roles in PATH_ROLES.items():
                pmeth, ppath = pattern_key.split(" ", 1)
                if pmeth == method and path_matches(ppath, resource_path):
                    required = roles
                    break

        if required:
            if not user_roles.intersection(required):
                log.warning(f"Authorization failed. Need one of {required}, user has {user_roles}")
                raise Exception("Forbidden")
        # If no required roles found, pass (unprotected operation as per extracted map)
    except Exception:
        raise


def path_matches(pattern_path: str, actual_path: str) -> bool:
    """
    Check if an actual path matches a pattern path.
    Supports basic path parameter matching with {param} syntax.
    
    Args:
        pattern_path: Path pattern like "/users/{username}"
        actual_path: Actual request path like "/users/john"
        
    Returns:
        bool: True if the paths match
    """
    # Simple exact match first
    if pattern_path == actual_path:
        return True
    
    # Convert pattern to regex for parameter matching
    # Replace {param} with [^/]+ to match any non-slash characters
    pattern_regex = re.sub(r'\{[^}]+\}', r'[^/]+', pattern_path)
    pattern_regex = f"^{pattern_regex}$"
    
    return bool(re.match(pattern_regex, actual_path))


def check_event_for_error(event: dict) -> dict:
    """Check event for errors and prepare headers."""
    if "headers" not in event:
        event["headers"] = {}

    # Normalize headers to lowercase
    event["headers"] = {k.lower(): v for k, v in event["headers"].items()}

    # Check if it's a REST request (type TOKEN)
    if event.get("type") == "TOKEN":
        if "methodArn" not in event or "authorizationToken" not in event:
            raise Exception(
                'Missing required fields: "methodArn" or "authorizationToken".'
            )
    # Check if it's a WebSocket request
    elif "sec-websocket-protocol" in event["headers"]:
        protocols = event["headers"]["sec-websocket-protocol"].split(", ")
        if len(protocols) != 2 or not protocols[0] or not protocols[1]:
            raise Exception("Invalid token, required protocols not found.")
        event["authorizationToken"] = f"bearer {protocols[1]}"
    else:
        raise Exception("Unable to find token in the event.")

    return event


def parse_token_from_event(event: dict) -> str:
    """Extract the Bearer token from the authorization header."""
    log.info("Parsing token from event")
    auth_token_parts = event["authorizationToken"].split(" ")
    log.info(f"auth_token_parts: {auth_token_parts}")
    if (
        len(auth_token_parts) != 2
        or auth_token_parts[0].lower() != "bearer"
        or not auth_token_parts[1]
    ):
        raise Exception("Invalid AuthorizationToken.")
    log.info(f"token: {auth_token_parts[1]}")
    return auth_token_parts[1]


def build_policy_resource_base(event: dict) -> str:
    """Build the policy resource base from the event's methodArn."""
    if not AUTH_MAPPINGS:
        return DEFAULT_ARN

    method_arn = str(event["methodArn"]).rstrip("/")
    slice_where = -2 if event.get("type") == "TOKEN" else -1
    arn_pieces = re.split(":|/", method_arn)[:slice_where]

    if len(arn_pieces) != 7:
        raise Exception("Invalid methodArn.")

    last_element = f"{arn_pieces[-2]}/{arn_pieces[-1]}/"
    arn_pieces = arn_pieces[:5] + [last_element]
    return ":".join(arn_pieces)


def decode_token(event, token: str) -> Dict[str, Any]:
    """
    Validate and decode the JWT token using the public key from the Cognito User Pool.
    """
    log.info("Decoding token")

    # Normalize the issuer URL
    if not ISSUER:
        raise Exception("ISSUER environment variable is not set.")
    if not ISSUER.startswith("https://"):
        issuer_url = f"https://{ISSUER}"
    else:
        issuer_url = ISSUER

    # Get the public keys from Cognito
    jwks_url = f"{issuer_url}/.well-known/jwks.json"
    log.info(f"Fetching JWKS from {jwks_url}")
    response = requests.get(jwks_url)
    if response.status_code != 200:
        raise Exception(f"Error fetching JWKS: {response.text}")

    jwks = response.json()

    # Get the token header to find the key ID
    header = jwt.get_unverified_header(token)
    
    # Find the matching key
    key = None
    for k in jwks["keys"]:
        if k["kid"] == header["kid"]:
            key = k
            break
    
    if not key:
        raise Exception(f"Unable to find matching key for kid: {header.get('kid')}")
    
    # Create the RSA public key from the JWK
    from jwt.algorithms import RSAAlgorithm
    
    public_key = RSAAlgorithm.from_jwk(json.dumps(key))

    log.info("Public key loaded successfully")

    try:
        # Decode and verify the JWT token
        decoded_token = jwt.decode(
            token,
            public_key,  # type: ignore
            algorithms=["RS256"],
            issuer=issuer_url,  # Use the normalized URL
        )
        return decoded_token
    except ExpiredSignatureError:
        log.error("Token has expired.")
        raise
    except InvalidTokenError as e:
        log.error(f"Token validation failed: {e}")
        raise


def get_policy(method_arn: str, decoded: dict, is_ws: bool) -> dict:
    """Create and return the policy for API Gateway."""

    context = {
        "scope": decoded.get("scope"),
        "permissions": ",".join(
            decoded.get("permissions", decoded.get("cognito:groups", []))
        ),
        "username": decoded.get("username"),
    }

    return {
        "principalId": decoded["sub"],
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [create_statement("Allow", method_arn, "execute-api:Invoke")],
        },
        "context": context,
    }


def create_statement(effect: str, resource: str, action: str) -> Dict[str, Any]:
    """Create a policy statement."""
    return {
        "Effect": effect,
        "Resource": resource,
        "Action": action,
    }
