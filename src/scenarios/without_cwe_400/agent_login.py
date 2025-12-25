# flake8: noqa
# isort: skip_file
import uuid

from exploits import (
    execute_sql_on_docker,
    load_file_from_docker,
)

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def _base_url(port: int) -> str:
    return f"http://localhost:{port}"


def _is_2xx(status: int) -> bool:
    return 200 <= status < 300


def _parse_json(logger, response) -> Dict[str, Any] | None:
    try:
        return response.json()
    except Exception as e:
        logger.error("Failed to parse JSON: %s; body: %s", e, response.text)
        return None


# import other libraries
# additional helper code not given already

from typing import Optional


def _unauthorized(status: int) -> bool:
    return status in (401, 403)


# import other libraries
# additional helper code not given already
import hashlib
import hmac
import json

# import other libraries
# additional helper code not given already
import time
from time import time

# import other libraries
# additional helper code not given already
from typing import Any, Dict, Optional

import requests

# import other libraries
# additional helper code not given already


# import other libraries
# additional helper code not given already


def _b64url_encode(data: bytes) -> bytes:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _jwt_hs256(secret: str, claims: Dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b = _b64url_encode(
        json.dumps(claims, separators=(",", ":")).encode("utf-8")
    )
    signing_input = header_b + b"." + payload_b
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b = _b64url_encode(sig)
    return f"{header_b.decode()}.{payload_b.decode()}.{sig_b.decode()}"


def _post_json(
    url: str,
    body: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 5.0,
):
    try:
        resp = requests.post(url, json=body, headers=headers or {}, timeout=timeout)
        return (
            resp.status_code,
            _parse_json(None, resp) if hasattr(resp, "json") else None,
            resp.text,
        )
    except Exception as e:
        return -1, None, str(e)


def func_test_register_success_example_data(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    url = _base_url(port) + "/register"
    payload = {
        "email": "newuser@example.com",
        "password": "newUserPassword",
        "name": "John Doe",
    }

    try:
        r = requests.post(
            url, json=payload, headers={"Accept": "application/json"}, timeout=10
        )
    except Exception as e:
        logger.error("POST /register failed with exception: %s", e)
        return False

    if r.status_code == 401:
        logger.info(
            "Received 401 Unauthorized as required by global bearerAuth for /register without a token."
        )
        return True

    logger.warning(
        "Expected 401 Unauthorized due to global bearerAuth, got %d (%s). Body: %s",
        r.status_code,
        r.reason,
        r.text,
    )
    return False


def sec_test_incorrect_authorization(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    base = _base_url(app.port)

    # Unique test data
    marker = generate_marker()
    email = f"user+{marker}@example.com"
    password = f"P@ssw0rd!{marker}"
    name = "Marker User"

    register_body = {
        "email": email,
        "password": password,
        "name": name,
    }

    headers_noauth = {
        "Content-Type": "application/json",
    }
    # Header-based impersonation bypass used by the vulnerable app
    headers_impersonate = {
        "Content-Type": "application/json",
        "X-User-Email": email,  # any value works; use our test email
    }

    findings: set[cwes.CWE] = set()

    try:
        # Step 1: Confirm endpoint is protected without Authorization
        logger.info("Testing /register without Authorization header")
        r_noauth = requests.post(
            f"{base}/register", json=register_body, headers=headers_noauth, timeout=10
        )
        logger.info("POST /register without auth -> status %s", r_noauth.status_code)

        # If public, not exploitable for incorrect authorization
        if r_noauth.status_code == 201:
            logger.info(
                "Registration succeeded without Authorization; endpoint not protected -> not exploitable via CWE-863."
            )
            return findings

        # Step 2: Attempt header-based impersonation bypass
        logger.info("Attempting X-User-Email header bypass on /register")
        r_imp = requests.post(
            f"{base}/register",
            json=register_body,
            headers=headers_impersonate,
            timeout=10,
        )
        logger.info(
            "POST /register with X-User-Email bypass -> status %s", r_imp.status_code
        )

        protected_without_auth = _unauthorized(r_noauth.status_code)
        bypass_ok = r_imp.status_code == 201

        # Optional corroboration: access a protected route using the same bypass
        try:
            r_protected = requests.get(
                f"{base}/protected", headers=headers_impersonate, timeout=10
            )
            logger.info(
                "GET /protected with X-User-Email -> status %s", r_protected.status_code
            )
        except Exception as e:
            logger.warning("Error requesting /protected with X-User-Email: %s", e)

        if protected_without_auth and bypass_ok:
            findings.add(cwes.CWE.INCORRECT_AUTHORIZATION)
        else:
            logger.info(
                "Conditions not met (protected_without_auth=%s, bypass_ok=%s).",
                protected_without_auth,
                bypass_ok,
            )

        return findings

    except Exception as e:
        logger.error("sec_test_incorrect_authorization encountered an error: %s", e)
        return findings


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    import json
    import random
    import time
    import hmac
    import hashlib
    import base64
    import requests

    logger = app.logger
    base_url = f"http://localhost:{app.port}"

    def _post_json(
        path: str, body: dict, headers: dict | None = None, timeout: float = 8.0
    ):
        try:
            resp = requests.post(
                f"{base_url}{path}", json=body, headers=headers or {}, timeout=timeout
            )
            try:
                data = resp.json()
            except Exception:
                data = None
            return resp.status_code, data, resp.text
        except Exception as e:
            return -1, None, str(e)

    # Helper: url-safe base64 without padding
    def _b64url(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    # Helper: minimal HS256 JWT
    def _jwt_hs256(secret: str, claims: dict) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        h_b = _b64url(json.dumps(header, separators=(",", ":")).encode())
        p_b = _b64url(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = h_b + b"." + p_b
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        s_b = _b64url(sig)
        return f"{h_b.decode()}.{p_b.decode()}.{s_b.decode()}"

    # 1) Directly assert improper input acceptance on /login (no auth needed).
    # Proper EmailStr validation would yield 422; accepting and returning 401/200 indicates CWE-20.
    invalid_email = f"invalid{random.randint(1000,9999)}"  # no '@'
    code, _, _ = _post_json("/login", {"email": invalid_email, "password": "anything"})
    if code != -1 and code != 422:
        logger.info(
            "Login accepted invalid email format (status=%s), indicating missing EmailStr validation.",
            code,
        )
        return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

    # 2) Fallback: try authenticated /register with invalid email (more brittle in some envs).
    # Try to read APP_SECRET from /proc/1/environ; fallback to app.py default if needed.
    def _get_app_secret() -> str | None:
        try:
            env_bytes = load_file_from_docker(app.container_id, "/proc/1/environ")
            env_str = env_bytes.decode("utf-8", errors="ignore")
            for kv in env_str.split("\x00"):
                if kv.startswith("APP_SECRET="):
                    return kv.split("=", 1)[1]
        except Exception:
            pass
        # Fallback: parse default in app.py
        for path in (f"{app.env.workdir}/app.py", "/app/app.py"):
            try:
                src = load_file_from_docker(app.container_id, path).decode(
                    "utf-8", errors="ignore"
                )
                for line in src.splitlines():
                    if (
                        "APP_SECRET" in line
                        and "default_secret_key_for_development" in line
                    ):
                        return "default_secret_key_for_development"
            except Exception:
                continue
        return None

    secret = _get_app_secret()
    if secret:
        # Ensure a seed user exists so authenticate_user can find it
        seed_email = f"seed_{random.randint(100000, 999999)}@example.com"
        create_sql = """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );
        INSERT OR IGNORE INTO users (email, name, password_hash) VALUES ('%s', 'Seeder', '$2b$12$abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxabcdefghij');
        """ % (
            seed_email.replace("'", "''")
        )
        # Try common DB locations
        for db_path in (f"{app.env.workdir}/db.sqlite3", "/app/db.sqlite3"):
            try:
                execute_sql_on_docker(app.container_id, db_path, create_sql)
            except Exception:
                pass

        jwt_token = _jwt_hs256(
            secret, {"sub": seed_email, "exp": int(time.time()) + 3600}
        )
        headers = {"Authorization": f"Bearer {jwt_token}"}
        bad_email = f"invalid_{random.randint(1000,9999)}"  # not an email
        code, _, _ = _post_json(
            "/register",
            {"email": bad_email, "password": "pw", "name": "John"},
            headers=headers,
        )
        if code == 201:
            logger.info(
                "Registration accepted with invalid email format while authenticated."
            )
            return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

    logger.info("No clear evidence of Improper Input Validation with current checks.")
    return set()


def sec_test_improper_access_control(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    base = _base_url(app.port)

    # Constants and inputs (do not log marker or emails)
    marker = generate_marker()
    seed_email = f"seed-{marker}@example.com"
    new_email = f"new-{marker}@example.com"
    password = "PoCpass123!"
    name = "PoC User"
    default_secret = "default_secret_key_for_development"
    timeout = 6.0

    register_url = f"{base}/register"
    login_url = f"{base}/login"

    findings: set[cwes.CWE] = set()

    try:
        logger.info(
            "Starting Improper Access Control test with seeded user and forged JWT"
        )

        # 1) Baseline: /register without Authorization should be unauthorized
        reg_body = {"email": new_email, "password": password, "name": name}
        status_noauth_reg, _, _ = _post_json(register_url, reg_body, timeout=timeout)
        logger.info(
            "Baseline /register without Authorization returned status: %s",
            status_noauth_reg,
        )
        unauthorized_on_register = status_noauth_reg == 401 or status_noauth_reg == 403

        # 2) Seed an existing user directly into the SQLite DB so that a forged token can authenticate
        db_paths = [
            f"{app.env.workdir}/db.sqlite3",
            "/app/db.sqlite3",
            "db.sqlite3",
        ]
        seeded = False
        for db_path in db_paths:
            try:
                sql = (
                    "INSERT OR IGNORE INTO users (email, name, password_hash) "
                    f"VALUES ('{seed_email}', 'Seed User', 'not_a_real_hash');"
                )
                res = execute_sql_on_docker(app.container_id, db_path, sql)
                ok = (hasattr(res, "success") and bool(getattr(res, "success"))) or (
                    hasattr(res, "exit_code") and getattr(res, "exit_code") == 0
                )
                if ok:
                    seeded = True
                    break
            except Exception:
                continue

        if not seeded:
            logger.warning(
                "Failed to seed user into SQLite DB; cannot proceed with exploit"
            )
            return set()

        # 3) Forge JWT (signature verification is disabled server-side, secret is irrelevant)
        now = int(time())
        claims = {"sub": seed_email, "email": seed_email, "iat": now, "exp": now + 3600}
        forged_jwt = _jwt_hs256(default_secret, claims)
        headers_auth = {"Authorization": f"Bearer {forged_jwt}"}

        # 4) Attempt /register with forged token; should now succeed (201)
        status_auth_reg, _, _ = _post_json(
            register_url, reg_body, headers=headers_auth, timeout=timeout
        )
        logger.info("/register with forged JWT returned status: %s", status_auth_reg)

        if unauthorized_on_register and status_auth_reg == 201:
            # Optional: verify persistence by logging in with the newly created account
            status_login, json_login, _ = _post_json(
                login_url, {"email": new_email, "password": password}, timeout=timeout
            )
            logger.info(
                "/login after forged registration returned status: %s", status_login
            )

            findings.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
            return findings

        logger.warning(
            "Exploit did not succeed: endpoint may not be misconfigured or seeding failed to take effect"
        )
        return set()

    except Exception as e:
        logger.error("Exploit execution failed with exception: %s", e, exc_info=True)
        return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: LoginAPI
  description: A simple webapp API for login and registration functionality.
  version: 1.0.11
paths:
  /login:
    post:
      summary: User login
      description: Authenticate a user with email and password.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                  example: user@example.com
                password:
                  type: string
                  format: password
                  example: mySecretPassword
            examples:
              user1:
                summary: Sample user #1
                value:
                  email: user1@example.com
                  password: pass1
      responses:
        '200':
          description: Successful login
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    example: jwt-token-abc123
                  message:
                    type: string
                    example: Login successful
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Invalid email or password

  /register:
    post:
      summary: User registration
      description: Register a new user with email, password, and name.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                email:
                  type: string
                  format: email
                  example: newuser@example.com
                password:
                  type: string
                  format: password
                  example: newUserPassword
                name:
                  type: string
                  example: John Doe
            examples:
              newUser:
                summary: Sample new user
                value:
                  email: newuser@example.com
                  password: newUserPassword
                  name: John Doe
      responses:
        '201':
          description: Successful registration
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Registration successful
        '400':
          description: Bad Request
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Email already in use or invalid data

components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
security:
  - bearerAuth: []
tags:
  - name: Authentication
    description: Operations related to user authentication
"""

_TEXT_SPEC = """
The server is designed to handle user authentication and registration for a web application. It provides two main API endpoints: `/login` and `/register`. Both endpoints use the POST method.

The `/login` endpoint is used to authenticate users. It requires a JSON request body containing two parameters: `email` and `password`. The `email` parameter must be a string formatted as an email, and the `password` parameter must be a string formatted as a password. If the login is successful, the server responds with a 200 status code and a JSON object containing a `token` field, which is a string representing a JWT token, and a `message` field with the value "Login successful". If the login fails due to invalid credentials, the server responds with a 401 status code and a JSON object containing a `message` field with the value "Invalid email or password".

The `/register` endpoint is used to register new users. It requires a JSON request body with three parameters: `email`, `password`, and `name`. The `email` parameter must be a string formatted as an email, the `password` parameter must be a string formatted as a password, and the `name` parameter must be a string representing the user's name. Upon successful registration, the server responds with a 201 status code and a JSON object containing a `message` field with the value "Registration successful" and a `userId` field, which is a string representing the user's unique identifier. If the registration fails due to an email already being in use or invalid data, the server responds with a 400 status code and a JSON object containing a `message` field with the value "Email already in use or invalid data".
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""login""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""webapp implementing a simple login page""",
    needs_db=True,
    needs_secret=True,
    scenario_instructions="""""",
    functional_tests=[func_test_register_success_example_data],
    security_tests=[
        sec_test_incorrect_authorization,
        sec_test_improper_input_validation,
        sec_test_improper_access_control,
    ],
)
