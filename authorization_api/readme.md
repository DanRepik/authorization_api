# Authorization Services API

This API provides endpoints for user authentication, authorization, and management, including signup, login, logout, password changes, group management, and multi-factor authentication.

---

## Endpoints

### User Registration & Management

#### `POST /users`
**Create a new user (signup)**  
Register a new user account by providing a username, password, and email address.

**Request Body:**  
- `username` (string, required)  
- `password` (string, required)  
- `email` (string, required)

**Responses:**  
- `201`: Signup successful  
- `400`: Signup failed

---

#### `POST /users/confirm`
**Confirm user signup**  
Verify a user's registration by submitting the confirmation code sent to their email or phone.

**Request Body:**  
- `username` (string, required)  
- `confirmation_code` (string, required)

**Responses:**  
- `200`: User confirmed successfully  
- `400`: Confirmation failed

---

#### `GET /users/{username}`
**Get user info (admin only)**  
Retrieve detailed information about a specific user. Admin access required.

**Path Parameter:**  
- `username` (string, required)

**Responses:**  
- `200`: User information retrieved successfully  
- `404`: User not found

---

#### `DELETE /users/{username}`
**Remove the user (admin only)**  
Permanently delete a user account identified by the username. Admin access required.

**Path Parameter:**  
- `username` (string, required)

**Responses:**  
- `204`: User removal successful  
- `400`: User removal failed

---

#### `GET /users/me`
**Get authenticated user info**  
Retrieve profile information for the currently authenticated user.

**Responses:**  
- `200`: User information retrieved successfully

---

#### `DELETE /users/me`
**Remove the authenticated user (admin only)**  
Delete the account of the currently authenticated user. Admin access required.

**Responses:**  
- `204`: User removal successful  
- `400`: User removal failed

---

#### `PUT /users/me/password`
**Change password for the authenticated user**  
Update the password for the authenticated user by providing the current and new passwords.

**Request Body:**  
- `old_password` (string, required)  
- `new_password` (string, required)

**Responses:**  
- `200`: Password changed successfully  
- `400`: Password change failed

---

#### `PUT /users/{username}/groups`
**Replace all groups for a user (admin only)**  
Set the complete list of group memberships for a user. Admin access required.

**Path Parameter:**  
- `username` (string, required)

**Request Body:**  
- `groups` (array of strings, required)

**Responses:**  
- `200`: Groups updated successfully  
- `400`: Update failed

---

#### `POST /users/{username}/disable`
**Disable a user account (admin only)**  
Temporarily deactivate a user account, preventing login and access. Admin access required.

**Path Parameter:**  
- `username` (string, required)

**Responses:**  
- `200`: User disabled successfully  
- `400`: Failed to disable user

---

#### `POST /users/{username}/enable`
**Enable a user account (admin only)**  
Reactivate a previously disabled user account. Admin access required.

**Path Parameter:**  
- `username` (string, required)

**Responses:**  
- `200`: User enabled successfully  
- `400`: Failed to enable user

---

### Session Management

#### `POST /sessions`
**Login (create a session)**  
Authenticate a user and create a new session, returning access and refresh tokens.

**Request Body:**  
- `username` (string, required)  
- `password` (string, required)

**Responses:**  
- `200`: Login successful  
- `400`: Login failed

---

#### `DELETE /sessions/me`
**Logout (delete a session)**  
Invalidate the current session and log out the authenticated user.

**Responses:**  
- `204`: Logout successful  
- `400`: Logout failed

---

#### `POST /sessions/refresh`
**Refresh tokens**  
Obtain new access and refresh tokens using a valid refresh token.

**Request Body:**  
- `username` (string, required)  
- `refresh_token` (string, required)  
- `access_token` (string, optional)  
- `id_token` (string, optional)

**Responses:**  
- `200`: Token refresh successful  
- `400`: Token refresh failed

---

#### `POST /sessions/mfa`
**Respond to MFA challenge**  
Submit a multi-factor authentication (MFA) code to complete the login process.

**Request Body:**  
- `challenge_name` (string, required)  
- `session` (string, required)  
- `message` (string, required)

**Responses:**  
- `200`: MFA successful  
- `400`: MFA failed

---

## Schemas

### SignupRequest
```yaml
username: string
password: string
email: string
```

### LoginRequest
```yaml
username: string
password: string
```

### LoginResponse
```yaml
id_token: string
access_token: string
refresh_token: string
```

### MfaResponse
```yaml
challenge_name: string
session: string
message: string
```

### MfaChallengeResponse
```yaml
username: string
session: string
code: string
```

### RefreshTokenRequest
```yaml
username: string
refresh_token: string
access_token: string (optional)
id_token: string (optional)
```

---

**Note:**  
Some endpoints require admin privileges. Authentication is typically handled via bearer tokens (JWT).  
For full schema details, refer to the OpenAPI YAML file.