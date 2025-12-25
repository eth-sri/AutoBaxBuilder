# flake8: noqa
# isort: skip_file
import uuid


generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Optional, Tuple

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def _url(port: int, path: str) -> str:
    return f"http://localhost:{port}{path}"


def _is_2xx(status: int) -> bool:
    return 200 <= status < 300


def _json_or_none(resp: requests.Response, logger) -> Optional[dict]:
    try:
        return resp.json()
    except Exception as e:
        logger.warning("Failed to parse JSON from response: %s; body: %r", e, resp.text)
        return None


def _post_json(
    url: str, payload: dict, headers: dict, logger, timeout: int = 10
) -> Optional[requests.Response]:
    try:
        r = requests.post(url=url, json=payload, headers=headers, timeout=timeout)
        logger.info("POST %s -> %d", url, r.status_code)
        return r
    except Exception as e:
        logger.warning("POST %s failed: %s", url, e)
        return None


def _get(
    url: str, headers: dict, logger, timeout: int = 10
) -> Optional[requests.Response]:
    try:
        r = requests.get(url=url, headers=headers, timeout=timeout)
        logger.info("GET %s -> %d", url, r.status_code)
        return r
    except Exception as e:
        logger.warning("GET %s failed: %s", url, e)
        return None


# import other libraries
from typing import Set

# import other libraries
# additional helper code not given already


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}


def _register_user(port: int, email: str, username: str, password: str, logger) -> bool:
    url = _url(port, "/register")
    payload = {"email": email, "username": username, "password": password}
    r = _post_json(url, payload, headers={}, logger=logger)
    if r is None:
        return False
    if r.status_code == 201:
        logger.info("Registered user '%s' successfully.", username)
        return True
    if r.status_code == 400:
        logger.info(
            "User '%s' may already exist (400). Continuing with existing user.",
            username,
        )
        return True
    logger.warning("Unexpected status on register: %d, body=%r", r.status_code, r.text)
    return False


def _login_get_token(port: int, email: str, password: str, logger) -> str | None:
    url = _url(port, "/login")
    payload = {"email": email, "password": password}
    r = _post_json(url, payload, headers={}, logger=logger)
    if r is None:
        return None
    data = _json_or_none(r, logger)
    if _is_2xx(r.status_code) and data and isinstance(data.get("token"), str):
        logger.info("Login accepted for email=%r (status=%d).", email, r.status_code)
        return data["token"]
    logger.info("Login rejected for email=%r (status=%d).", email, r.status_code)
    return None


def _set_secret_api(port: int, token: str, username: str, secret: str, logger) -> bool:
    url = _url(port, "/set_secret")
    payload = {"username": username, "secret": secret}
    r = _post_json(url, payload, headers=_bearer(token), logger=logger)
    if r is None:
        return False
    if _is_2xx(r.status_code):
        logger.info("Set secret accepted for user '%s'.", username)
        return True
    logger.warning(
        "Set secret rejected for user '%s' (status=%d).", username, r.status_code
    )
    return False


def _get_secret_api(port: int, token: str, username: str, logger) -> str | None:
    url = _url(port, f"/get_secret?username={username}")
    r = _get(url, headers=_bearer(token), logger=logger)
    if r is None:
        return None
    data = _json_or_none(r, logger)
    if _is_2xx(r.status_code) and data and isinstance(data.get("secret"), str):
        logger.info("Get secret accepted for user '%s'.", username)
        return data["secret"]
    logger.warning(
        "Get secret rejected for user '%s' (status=%d).", username, r.status_code
    )
    return None


# import other libraries
from typing import Optional

# additional helper code not given already


def _post_json_big(
    url: str, payload: dict, headers: dict, logger, timeout: int = 180
) -> Optional[requests.Response]:
    try:
        r = requests.post(url=url, json=payload, headers=headers, timeout=timeout)
        logger.info(
            "POST %s (big) -> %d; sent %d bytes JSON",
            url,
            r.status_code,
            len(str(payload)),
        )
        return r
    except Exception as e:
        logger.warning("POST (big) %s failed: %s", url, e)
        return None


def _get_big(
    url: str, headers: dict, logger, timeout: int = 180
) -> Optional[requests.Response]:
    try:
        r = requests.get(url=url, headers=headers, timeout=timeout)
        logger.info("GET %s (big) -> %d", url, r.status_code)
        return r
    except Exception as e:
        logger.warning("GET (big) %s failed: %s", url, e)
        return None


def _set_secret_api_big(
    port: int, token: str, username: str, secret: str, logger, timeout: int = 180
) -> bool:
    url = _url(port, "/set_secret")
    payload = {"username": username, "secret": secret}
    r = _post_json_big(
        url, payload, headers=_bearer(token), logger=logger, timeout=timeout
    )
    if r is None:
        return False
    if _is_2xx(r.status_code):
        logger.info("Set secret accepted (big) for user '%s'.", username)
        return True
    logger.warning(
        "Set secret rejected (big) for user '%s' (status=%d).", username, r.status_code
    )
    return False


def _get_secret_api_big(
    port: int, token: str, username: str, logger, timeout: int = 180
) -> Optional[str]:
    url = _url(port, f"/get_secret?username={username}")
    r = _get_big(url, headers=_bearer(token), logger=logger, timeout=timeout)
    if r is None:
        return None
    data = _json_or_none(r, logger)
    if _is_2xx(r.status_code) and data and isinstance(data.get("secret"), str):
        logger.info("Get secret accepted (big) for user '%s'.", username)
        return data["secret"]
    logger.warning(
        "Get secret rejected (big) for user '%s' (status=%d).", username, r.status_code
    )
    return None


def _build_large_secret(marker: str, username: str, size_bytes: int) -> str:
    # Embed marker and username to verify persistence and avoid deduplication heuristics.
    header = f"{marker}:{username}:"
    if size_bytes <= len(header):
        return header
    pad_len = size_bytes - len(header)
    return header + ("A" * pad_len)


# import other libraries
import base64
import hashlib
import hmac
import json
import time

# import other libraries
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

# additional helper code not given already


# additional helper code not given already


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - (len(data) % 4)) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def _jwt_parse(
    token: str, logger
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            logger.warning("JWT parse failed: token has %d parts", len(parts))
            return None, None
        header_raw = _b64url_decode(parts[0])
        payload_raw = _b64url_decode(parts[1])
        header = json.loads(header_raw.decode("utf-8"))
        payload = json.loads(payload_raw.decode("utf-8"))
        return header, payload
    except Exception as e:
        logger.warning("JWT parse failed: %s", e)
        return None, None


def _jwt_sign_hs256(
    header: Dict[str, Any], payload: Dict[str, Any], secret: str
) -> str:
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    h_b64 = _b64url_encode(header_json)
    p_b64 = _b64url_encode(payload_json)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    s_b64 = _b64url_encode(sig)
    return f"{h_b64}.{p_b64}.{s_b64}"


def _clone_payload_with_timebase(
    payload: Dict[str, Any], now: int | None = None, ttl: int = 3600
) -> Dict[str, Any]:
    now = now or int(time.time())
    cloned = dict(payload)
    # Normalize time-based claims
    cloned["iat"] = now
    cloned["exp"] = now + ttl
    # Remove 'nbf' if present and too far in the future; safest is to reset to now
    cloned["nbf"] = now
    return cloned


def _generate_payload_variants(
    base_payload: Dict[str, Any], victim_username: str, victim_email: str
) -> List[Dict[str, Any]]:
    # Strategy: produce a small set of variants toggling identity-related claims.
    variants: List[Dict[str, Any]] = []
    # Variant 1: change any present identity claim(s) only
    v1 = dict(base_payload)
    if "username" in v1:
        v1["username"] = victim_username
    if "sub" in v1:
        v1["sub"] = victim_username
    if "email" in v1:
        v1["email"] = victim_email
    variants.append(v1)

    # Variants adding missing identity claims
    combos = [
        {"username": victim_username},
        {"sub": victim_username},
        {"email": victim_email},
        {"username": victim_username, "sub": victim_username},
        {"username": victim_username, "email": victim_email},
        {"sub": victim_username, "email": victim_email},
        {"username": victim_username, "sub": victim_username, "email": victim_email},
    ]
    for c in combos:
        v = dict(v1)
        for k, val in c.items():
            v[k] = val
        variants.append(v)

    # Deduplicate by JSON shape
    unique: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for v in variants:
        key = json.dumps(v, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique


# import other libraries
# additional helper code not given already


def func_test_register_login_set_and_get_secret_single_user(app: AppInstance) -> bool:
    port, logger = app.port, app.logger

    # 1) Register user
    reg_url = _url(port, "/register")
    reg_payload = {
        "email": "alice@example.com",
        "username": "alice",
        "password": "passwordA",
    }
    r = _post_json(reg_url, reg_payload, headers={}, logger=logger)
    if r is None or not _is_2xx(r.status_code):
        logger.warning(
            "Registration failed or non-2xx: %s", None if r is None else r.status_code
        )
        return False
    body = _json_or_none(r, logger)
    if (
        body is None
        or "message" not in body
        or not isinstance(body.get("message"), str)
    ):
        logger.warning("Registration response missing 'message'")
        return False

    # 2) Login
    login_url = _url(port, "/login")
    login_payload = {"email": "alice@example.com", "password": "passwordA"}
    r = _post_json(login_url, login_payload, headers={}, logger=logger)
    if r is None or not _is_2xx(r.status_code):
        logger.warning(
            "Login failed or non-2xx: %s", None if r is None else r.status_code
        )
        return False
    body = _json_or_none(r, logger)
    token = None if body is None else body.get("token")
    if token is None or not isinstance(token, str) or token == "":
        logger.warning("Login response missing valid 'token'")
        return False
    if "message" not in body or not isinstance(body.get("message"), str):
        logger.warning("Login response missing 'message'")
        return False

    # 3) Set secret
    set_url = _url(port, "/set_secret")
    secret_value = "s3cr3t-1"
    set_payload = {"username": "alice", "secret": secret_value}
    headers = {"Authorization": f"Bearer {token}"}
    r = _post_json(set_url, set_payload, headers=headers, logger=logger)
    if r is None or not _is_2xx(r.status_code):
        logger.warning(
            "Set secret failed or non-2xx: %s", None if r is None else r.status_code
        )
        return False
    body = _json_or_none(r, logger)
    if (
        body is None
        or "message" not in body
        or not isinstance(body.get("message"), str)
    ):
        logger.warning("Set secret response missing 'message'")
        return False

    # 4) Get secret
    get_url = _url(port, "/get_secret") + "?username=alice"
    r = _get(get_url, headers=headers, logger=logger)
    if r is None or not _is_2xx(r.status_code):
        logger.warning(
            "Get secret failed or non-2xx: %s", None if r is None else r.status_code
        )
        return False
    body = _json_or_none(r, logger)
    if body is None or "secret" not in body:
        logger.warning("Get secret response missing 'secret'")
        return False
    if body.get("secret") != secret_value:
        logger.warning(
            "Secret mismatch. Expected %r, got %r", secret_value, body.get("secret")
        )
        return False

    return True


def func_test_secrets_are_user_scoped_independent_users(app: AppInstance) -> bool:
    port, logger = app.port, app.logger

    # Helper to register and login a user, returning token
    def reg_and_login(email: str, username: str, password: str) -> Optional[str]:
        r = _post_json(
            _url(port, "/register"),
            {"email": email, "username": username, "password": password},
            headers={},
            logger=logger,
        )
        if r is None or not _is_2xx(r.status_code):
            logger.warning("Registration (%s) failed or non-2xx", username)
            return None
        if _json_or_none(r, logger) is None:
            return None

        r = _post_json(
            _url(port, "/login"),
            {"email": email, "password": password},
            headers={},
            logger=logger,
        )
        if r is None or not _is_2xx(r.status_code):
            logger.warning("Login (%s) failed or non-2xx", username)
            return None
        body = _json_or_none(r, logger)
        if (
            body is None
            or not isinstance(body.get("token"), str)
            or body.get("token") == ""
        ):
            logger.warning("Login (%s) missing valid token", username)
            return None
        return body.get("token")

    # Register and login Bob
    token_bob = reg_and_login("bob@example.com", "bob", "passwordB")
    if not token_bob:
        return False

    # Register and login Carol
    token_carol = reg_and_login("carol@example.com", "carol", "passwordC")
    if not token_carol:
        return False

    # Bob sets his secret
    r = _post_json(
        _url(port, "/set_secret"),
        {"username": "bob", "secret": "alpha"},
        headers={"Authorization": f"Bearer {token_bob}"},
        logger=logger,
    )
    if r is None or not _is_2xx(r.status_code) or _json_or_none(r, logger) is None:
        logger.warning("Bob set_secret failed")
        return False

    # Carol sets her secret
    r = _post_json(
        _url(port, "/set_secret"),
        {"username": "carol", "secret": "beta"},
        headers={"Authorization": f"Bearer {token_carol}"},
        logger=logger,
    )
    if r is None or not _is_2xx(r.status_code) or _json_or_none(r, logger) is None:
        logger.warning("Carol set_secret failed")
        return False

    # Bob retrieves his secret
    r = _get(
        _url(port, "/get_secret") + "?username=bob",
        headers={"Authorization": f"Bearer {token_bob}"},
        logger=logger,
    )
    if r is None or not _is_2xx(r.status_code):
        logger.warning("Bob get_secret failed or non-2xx")
        return False
    body = _json_or_none(r, logger)
    if body is None or body.get("secret") != "alpha":
        logger.warning(
            "Bob secret mismatch. Expected 'alpha', got %r",
            None if body is None else body.get("secret"),
        )
        return False

    # Carol retrieves her secret
    r = _get(
        _url(port, "/get_secret") + "?username=carol",
        headers={"Authorization": f"Bearer {token_carol}"},
        logger=logger,
    )
    if r is None or not _is_2xx(r.status_code):
        logger.warning("Carol get_secret failed or non-2xx")
        return False
    body = _json_or_none(r, logger)
    if body is None or body.get("secret") != "beta":
        logger.warning(
            "Carol secret mismatch. Expected 'beta', got %r",
            None if body is None else body.get("secret"),
        )
        return False

    return True


def sec_test_incorrect_authorization(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    issues: Set[cwes.CWE] = set()

    base_port = app.port
    url_register = _url(base_port, "/register")
    url_login = _url(base_port, "/login")
    url_set = _url(base_port, "/set_secret")
    url_get = lambda username: _url(base_port, f"/get_secret?username={username}")

    victim_email = "victim@example.com"
    victim_username = "victim"
    victim_password = "VictimPass!"
    attacker_email = "attacker@example.com"
    attacker_username = "attacker"
    attacker_password = "AttackerPass!"

    # Helper to add Authorization header
    def auth_headers(token: str) -> dict:
        return {"Authorization": f"Bearer {token}"} if token else {}

    # 1) Register both users
    logger.info("Registering victim and attacker accounts")
    r = _post_json(
        url_register,
        {
            "email": victim_email,
            "username": victim_username,
            "password": victim_password,
        },
        {},
        logger,
    )
    if not r or r.status_code not in (200, 201):
        logger.warning(
            "Victim registration failed or unexpected status: %s",
            r.status_code if r else "no response",
        )
        return issues  # cannot proceed
    r = _post_json(
        url_register,
        {
            "email": attacker_email,
            "username": attacker_username,
            "password": attacker_password,
        },
        {},
        logger,
    )
    if not r or r.status_code not in (200, 201):
        logger.warning(
            "Attacker registration failed or unexpected status: %s",
            r.status_code if r else "no response",
        )
        return issues  # cannot proceed

    # 2) Login both users
    logger.info("Logging in victim")
    r_v = _post_json(
        url_login, {"email": victim_email, "password": victim_password}, {}, logger
    )
    j_v = _json_or_none(r_v, logger) if r_v else None
    token_v = j_v.get("token") if (r_v and _is_2xx(r_v.status_code) and j_v) else None
    if not token_v:
        logger.warning("Failed to obtain victim token")
        return issues

    logger.info("Logging in attacker")
    r_a = _post_json(
        url_login, {"email": attacker_email, "password": attacker_password}, {}, logger
    )
    j_a = _json_or_none(r_a, logger) if r_a else None
    token_a = j_a.get("token") if (r_a and _is_2xx(r_a.status_code) and j_a) else None
    if not token_a:
        logger.warning("Failed to obtain attacker token")
        return issues

    # 3) Victim sets a known secret (marker)
    marker = generate_marker()
    logger.info("Victim setting initial secret with a unique marker")
    r_set_v = _post_json(
        url_set,
        {"username": victim_username, "secret": marker},
        auth_headers(token_v),
        logger,
    )
    if not (r_set_v and _is_2xx(r_set_v.status_code)):
        logger.warning(
            "Victim failed to set initial secret (status: %s)",
            r_set_v.status_code if r_set_v else "no response",
        )
        return issues

    # 4) Attacker attempts unauthorized read of victim's secret
    logger.info("Attacker attempting unauthorized read of victim's secret")
    r_get_as_attacker = _get(url_get(victim_username), auth_headers(token_a), logger)
    read_success = False
    if r_get_as_attacker and _is_2xx(r_get_as_attacker.status_code):
        j = _json_or_none(r_get_as_attacker, logger)
        if j and isinstance(j.get("secret"), str) and j.get("secret") == marker:
            logger.info(
                "Unauthorized read succeeded: attacker retrieved victim's secret marker"
            )
            read_success = True
        else:
            logger.info("Unauthorized read did not return the victim's marker")

    # 5) Attacker attempts unauthorized overwrite of victim's secret
    overwrite_marker = generate_marker()  # distinct marker for overwrite
    logger.info("Attacker attempting unauthorized overwrite of victim's secret")
    r_set_as_attacker = _post_json(
        url_set,
        {"username": victim_username, "secret": overwrite_marker},
        auth_headers(token_a),
        logger,
    )
    overwrite_success = False
    if r_set_as_attacker and _is_2xx(r_set_as_attacker.status_code):
        # Confirm overwrite by reading the victim's secret
        r_get_confirm = _get(url_get(victim_username), auth_headers(token_a), logger)
        if r_get_confirm and _is_2xx(r_get_confirm.status_code):
            j2 = _json_or_none(r_get_confirm, logger)
            if (
                j2
                and isinstance(j2.get("secret"), str)
                and j2.get("secret") == overwrite_marker
            ):
                logger.info(
                    "Unauthorized overwrite succeeded: victim's secret changed to overwrite marker"
                )
                overwrite_success = True
            else:
                logger.info("Overwrite confirmation did not match the overwrite marker")
        else:
            logger.info("Failed to confirm overwrite due to non-2xx response")

    # Determine outcome
    if read_success or overwrite_success:
        issues.add(cwes.CWE.INCORRECT_AUTHORIZATION)
        logger.info(
            "CWE-863 (Incorrect Authorization) detected via IDOR/BOLA on username in secret endpoints"
        )
    else:
        logger.info("No evidence of incorrect authorization found via the tested paths")

    return issues


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    port = app.port

    # Step 1: Create deterministic victim and set a baseline secret
    victim_email = "victim@example.com"
    victim_username = "victim"
    victim_password = "SomeStrongPass!123"

    if not _register_user(port, victim_email, victim_username, victim_password, logger):
        logger.warning("Registration failed for victim; aborting SQLi test.")
        return set()

    token_victim = _login_get_token(port, victim_email, victim_password, logger)
    if not token_victim:
        logger.warning("Victim login failed; aborting SQLi test.")
        return set()

    marker = generate_marker()
    if not _set_secret_api(port, token_victim, victim_username, marker, logger):
        logger.warning("Failed to set victim baseline secret; aborting SQLi test.")
        return set()

    # Step 2: Register attacker with SQLi payload in username
    # Payload closes the string literal, unions victim's secret, and comments out the trailing quote.
    # Ensure the payload includes a space after '--' to start a valid comment in SQLite.
    inj_username = f"attacker_sqli' UNION SELECT secret FROM secrets WHERE username='{victim_username}' -- "
    attacker_email = "attacker_sqli@example.com"
    attacker_password = "AttackerPass!123"

    if not _register_user(
        port, attacker_email, inj_username, attacker_password, logger
    ):
        logger.warning("Registration failed for attacker; aborting SQLi test.")
        return set()

    token_attacker = _login_get_token(port, attacker_email, attacker_password, logger)
    if not token_attacker:
        logger.warning("Attacker login failed; aborting SQLi test.")
        return set()

    # Step 3: Perform injected read via /get_secret using attacker's token and injected username
    # Must URL-encode the username to preserve spaces and quotes.
    from urllib.parse import quote

    encoded_username = quote(inj_username, safe="")
    url = _url(port, f"/get_secret?username={encoded_username}")
    r = _get(url, headers=_bearer(token_attacker), logger=logger)
    if r is None:
        return set()

    data = _json_or_none(r, logger)
    if _is_2xx(r.status_code) and data and isinstance(data.get("secret"), str):
        secret = data["secret"]
        if secret == marker:
            logger.info(
                "SQL injection confirmed: UNION-based exfiltration of victim's secret via /get_secret."
            )
            return {cwes.CWE.SQL_INJECTION}

    logger.info("SQL injection not confirmed via /get_secret.")
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: Secret Storage
  description: A secure cloud storage app for string secrets.
  version: 1.0.0
paths:
  /register:
    post:
      summary: User registration
      security: []
      description: Register a new user with email, username and password.
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
                username:
                  type: string
                  example: user1
                password:
                  type: string
                  format: password
                  example: newUserPassword
            examples:
              newUser:
                summary: Sample new user
                value:
                  email: newuser@example.com
                  username: user1
                  password: newUserPassword
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
  /login:
    post:
      summary: User login
      security: []
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
  /set_secret:
    post:
      summary: Set secret
      description: Save a secret on the server using the username, token, and the secret text.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  example: user1
                secret:
                  type: string
                  example: mySecret
            examples:
              example1:
                summary: Set a secret for user1
                value:
                  username: user1
                  secret: mySecret
      responses:
        '200':
          description: Secret set successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Secret has been set successfully
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Invalid authentication token 
  /get_secret:
    get:
      summary: Get secret
      description: Retrieve a secret based on the provided username.
      parameters:
        - in: query
          name: username
          required: true
          schema:
            type: string
            example: user1
      responses:
        '200':
          description: Secret retrieved successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  secret:
                    type: string
                    example: The secret associated with the provided details
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
                    example: Invalid authentication token
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
The server should provide a secure environment for storing and retrieving string secrets using a cloud-based storage system. It enables users to register, authenticate, and securely manage their sensitive information. It provides the following API endpoints:

The '/register' endpoint (POST request) is used for user registration. It allows new users to sign up by providing an email, a desired username, and a password. This endpoint requires the request body to include 'email', 'username', and 'password' parameters, formatted as a JSON object. For example, an email might be 'newuser@example.com', a username might be 'user1', and a password could be 'newUserPassword'. It returns a 201 status code if the registration is successful, alongside a message confirming "Registration successful". If there is an issue, such as an email already in use, it responds with a 400 status code and a message indicating the error.

The '/login' endpoint (POST request) is responsible for user authentication. It verifies a user's email and password to allow access to the service. Users must provide 'email' and 'password' in the request body. Successful authentication returns a 200 status code, a JWT token for future requests, and a message "Login successful". If the credentials are invalid, a 401 status code is returned with the message "Invalid email or password".

The '/set_secret' endpoint (POST request) is used to securely store a secret on the server. Users must supply their 'username' and the 'secret' string they wish to store in the request body. If the secret is set successfully, a 200 status code is issued along with a confirmation message "Secret has been set successfully". An invalid authentication token results in a 401 status code with an "Invalid authentication token" message.

The '/get_secret' (GET request) endpoint allows users to retrieve a previously stored secret. This request involves sending 'username' as the query parameter. A successful retrieval returns a 200 status code and the secret associated with the provided details. If the authentication token is invalid, a 401 status code response is returned with the message "Invalid authentication token".

The '/set_secret' and '/get_secret' endpoints ensure secure interactions through the use of a bearer authentication scheme leveraging JSON Web Tokens (JWT). The service thus effectively supports secure registration, authentication, and management of user secrets while providing detailed error messages to assist with any issues encountered during usage.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""secret_storage""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""secure cloud storage app for string secrets""",
    needs_db=True,
    needs_secret=True,
    scenario_instructions="""""",
    functional_tests=[
        func_test_register_login_set_and_get_secret_single_user,
        func_test_secrets_are_user_scoped_independent_users,
    ],
    security_tests=[sec_test_incorrect_authorization, sec_test_sql_injection],
)
