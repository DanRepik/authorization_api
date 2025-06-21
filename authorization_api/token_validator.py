import os
import json
import re
import jwt
import requests
import logging

log = logging.getLogger(__name__)
log.setLevel(os.environ.get("LOGGING_LEVEL", "DEBUG"))

# Load environment variables
AUTH_MAPPINGS = json.loads(os.getenv("AUTH0_AUTH_MAPPINGS", "{}"))
DEFAULT_ARN = "arn:aws:execute-api:*:*:*/*/*/*"

# Cognito user pool issuer URL
ISSUER = os.getenv(
    "ISSUER"
)  # expected format: https://cognito-idp.<region>.amazonaws.com/<user_pool_id>


def handler(event, context):
    """Main Lambda handler."""
    log.info(event)
    try:
        token = parse_token_from_event(check_event_for_error(event))
        decoded_token = decode_token(event, token)
        log.info(f"Decoded token: {decoded_token}")
        policy = get_policy(
            event["methodArn"],
            decoded_token,
            "sec-websocket-protocol" in event["headers"],
        )
        log.info(f"Generated policy: {json.dumps(policy)}")
        return policy
    except jwt.InvalidTokenError as e:
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


def decode_token(event, token: str) -> dict:
    """
    Validate and decode the JWT token using the public key from the Cognito User Pool.
    """
    log.info("Decoding token")

    # Get the public keys from Cognito (could be improved with dynamic key fetching)
    jwks_url = f"{ISSUER}/.well-known/jwks.json"
    response = requests.get(jwks_url)
    if response.status_code != 200:
        raise Exception(f"Error fetching JWKS: {response.text}")

    jwks = response.json()

    # Load the public key corresponding to the token's kid
    header = jwt.get_unverified_header(token)
    key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

    log.info(f"Public key: {public_key}")

    audience = event["methodArn"].rstrip("/").split(":")[-1].split("/")[1]
    log.info(f"Audience: {audience}")
    try:
        # Decode and verify the JWT token
        decoded_token = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=ISSUER,
        )
        return decoded_token
    except jwt.ExpiredSignatureError:
        log.error("Token has expired.")
        raise jwt.InvalidTokenError("Token has expired.")
    except jwt.InvalidTokenError as e:
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


def create_statement(effect: str, resource: list, action: list) -> dict:
    """Create a policy statement."""
    return {
        "Effect": effect,
        "Resource": resource,
        "Action": action,
    }
