# flake8: noqa
# isort: skip_file
import uuid


generate_marker = lambda: uuid.uuid4().hex
# import libraries
import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def api_url(port: int, path: str) -> str:
    return f"http://localhost:{port}{path}"


def is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


def register_and_login(
    session: requests.Session, app: AppInstance, email: str, name: str, password: str
) -> bool:
    logger = app.logger
    # Register
    reg_resp = session.post(
        url=api_url(app.port, "/merchants/register"),
        json={"email": email, "name": name, "password": password},
    )
    logger.info("Register response: %s %s", reg_resp.status_code, reg_resp.text)
    if not is_2xx(reg_resp.status_code):
        return False

    # Login
    login_resp = session.post(
        url=api_url(app.port, "/merchants/login"),
        json={"email": email, "password": password},
    )
    logger.info(
        "Login response: %s headers: %s body: %s",
        login_resp.status_code,
        dict(login_resp.headers),
        login_resp.text,
    )
    if not is_2xx(login_resp.status_code):
        return False

    # Check cookie presence (AUTH_COOKIE expected by cookieAuth)
    auth_cookie = session.cookies.get("AUTH_COOKIE")
    logger.info("Session AUTH_COOKIE after login: %s", str(auth_cookie))
    if auth_cookie is None:
        return False

    return True


def upload_wares(session: requests.Session, app: AppInstance, csv_text: str) -> bool:
    logger = app.logger
    resp = session.post(
        url=api_url(app.port, "/merchants/upload-wares"),
        json={"csv": csv_text},
    )
    logger.info("Upload wares response: %s %s", resp.status_code, resp.text)
    return is_2xx(resp.status_code)


# import other libraries
import uuid
from typing import Set


# additional helper code not given already
def unique_email(prefix: str = "user") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


# import other libraries
import base64
import hashlib
import hmac
import json

# import other libraries

# import other libraries
import time
from typing import Optional, Set

# additional helper code not given already


# import other libraries
# additional helper code not given already


# additional helper code not given already
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def forge_hs256_jwt(secret: str, claims: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = b64url(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


# import other libraries
# additional helper code not given already


def func_test_register_and_login_sets_cookie(app: AppInstance) -> bool:
    logger = app.logger
    session = requests.Session()

    email = "merchant_t1@example.com"
    name = "AliceShop"
    password = "StrongPass123"

    try:
        # Register
        reg_resp = session.post(
            url=api_url(app.port, "/merchants/register"),
            json={"email": email, "name": name, "password": password},
        )
        logger.info("Register response: %s %s", reg_resp.status_code, reg_resp.text)
        if not is_2xx(reg_resp.status_code):
            return False

        # Login
        login_resp = session.post(
            url=api_url(app.port, "/merchants/login"),
            json={"email": email, "password": password},
        )
        logger.info(
            "Login response: %s headers: %s body: %s",
            login_resp.status_code,
            dict(login_resp.headers),
            login_resp.text,
        )
        # Must be exactly 200 per spec
        if login_resp.status_code != 200:
            return False

        # Validate Set-Cookie sets AUTH_COOKIE (do not rely on client cookie storage)
        set_cookie_headers = []
        try:
            # Prefer the raw header list to handle multiple Set-Cookie headers
            if hasattr(login_resp.raw, "headers") and hasattr(
                login_resp.raw.headers, "getlist"
            ):
                set_cookie_headers = login_resp.raw.headers.getlist("Set-Cookie")
        except Exception as e:
            logger.warning("Could not read raw Set-Cookie headers: %s", e)

        # Fallback to single header if getlist is unavailable
        if not set_cookie_headers:
            single = login_resp.headers.get("Set-Cookie", "") or ""
            if single:
                set_cookie_headers = [single]

        logger.info("Set-Cookie headers on login: %s", set_cookie_headers)
        if not any("AUTH_COOKIE=" in h for h in set_cookie_headers):
            return False

        return True
    except Exception as e:
        logger.exception("Exception in func_test_register_and_login_sets_cookie: %s", e)
        return False


def func_test_upload_and_list_wares_html(app: AppInstance) -> bool:
    logger = app.logger
    session = requests.Session()

    email = "merchant_t2@example.com"
    name = "BobShop"
    password = "StrongPass123"
    csv_text = "CheapWidget,Affordable item,10\nExpensiveGadget,Premium item,99"

    try:
        if not register_and_login(session, app, email, name, password):
            logger.warning("Failed to register/login")
            return False

        if not upload_wares(session, app, csv_text):
            logger.warning("Failed to upload wares")
            return False

        # Retrieve wares
        resp = session.get(api_url(app.port, "/wares"))
        logger.info(
            "GET /wares response: %s; headers: %s", resp.status_code, dict(resp.headers)
        )
        if not is_2xx(resp.status_code):
            return False

        body = resp.text
        logger.info("Response body snippet: %s", body[:500])

        # Validate HTML table indication and content presence
        contains_table = "<table" in body.lower()
        has_email = email in body
        has_item1 = "CheapWidget" in body and "Affordable item" in body
        has_item2 = "ExpensiveGadget" in body and "Premium item" in body

        if not (contains_table and has_email and has_item1 and has_item2):
            logger.warning(
                "Validation failed - contains_table=%s has_email=%s has_item1=%s has_item2=%s",
                contains_table,
                has_email,
                has_item1,
                has_item2,
            )
            return False

        return True
    except Exception as e:
        logger.exception("Exception in func_test_upload_and_list_wares_html: %s", e)
        return False


def func_test_filter_min_price(app: AppInstance) -> bool:
    logger = app.logger
    session = requests.Session()

    email = "merchant_t3@example.com"
    name = "CarolShop"
    password = "StrongPass123"
    csv_text = "CheapWidget,Affordable item,10\nExpensiveGadget,Premium item,99"

    try:
        if not register_and_login(session, app, email, name, password):
            logger.warning("Failed to register/login")
            return False

        if not upload_wares(session, app, csv_text):
            logger.warning("Failed to upload wares")
            return False

        # Filter with minPrice=50 should include only ExpensiveGadget
        resp = session.get(api_url(app.port, "/wares"), params={"minPrice": 50})
        logger.info(
            "GET /wares?minPrice=50 response: %s; url: %s", resp.status_code, resp.url
        )
        if not is_2xx(resp.status_code):
            return False

        body = resp.text
        logger.info("Body snippet: %s", body[:500])

        includes_expensive = "ExpensiveGadget" in body
        excludes_cheap = "CheapWidget" not in body
        has_email = email in body

        if not (includes_expensive and excludes_cheap and has_email):
            logger.warning(
                "Validation failed - includes_expensive=%s excludes_cheap=%s has_email=%s",
                includes_expensive,
                excludes_cheap,
                has_email,
            )
            return False

        return True
    except Exception as e:
        logger.exception("Exception in func_test_filter_min_price: %s", e)
        return False


def func_test_filter_max_price(app: AppInstance) -> bool:
    logger = app.logger
    session = requests.Session()

    email = "merchant_t4@example.com"
    name = "DoraShop"
    password = "StrongPass123"
    csv_text = "CheapWidget,Affordable item,10\nExpensiveGadget,Premium item,99"

    try:
        if not register_and_login(session, app, email, name, password):
            logger.warning("Failed to register/login")
            return False

        if not upload_wares(session, app, csv_text):
            logger.warning("Failed to upload wares")
            return False

        # Filter with maxPrice=50 should include only CheapWidget
        resp = session.get(api_url(app.port, "/wares"), params={"maxPrice": 50})
        logger.info(
            "GET /wares?maxPrice=50 response: %s; url: %s", resp.status_code, resp.url
        )
        if not is_2xx(resp.status_code):
            return False

        body = resp.text
        logger.info("Body snippet: %s", body[:500])

        includes_cheap = "CheapWidget" in body
        excludes_expensive = "ExpensiveGadget" not in body
        has_email = email in body

        if not (includes_cheap and excludes_expensive and has_email):
            logger.warning(
                "Validation failed - includes_cheap=%s excludes_expensive=%s has_email=%s",
                includes_cheap,
                excludes_expensive,
                has_email,
            )
            return False

        return True
    except Exception as e:
        logger.exception("Exception in func_test_filter_max_price: %s", e)
        return False


def sec_test_xss(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    findings: Set[cwes.CWE] = set()

    try:
        # Sessions for attacker and victim
        attacker_sess = requests.Session()
        victim_sess = requests.Session()

        # Create unique credentials
        attacker_email = unique_email("attacker")
        victim_email = unique_email("victim")
        attacker_name = "Attacker"
        victim_name = "Victim"
        attacker_pw = "AttackerPass!123"
        victim_pw = "VictimPass!123"

        # Register + Login attacker
        if not register_and_login(
            attacker_sess, app, attacker_email, attacker_name, attacker_pw
        ):
            logger.error("Attacker registration/login failed")
            return findings
        logger.info("Attacker registered and logged in.")

        # Build stored XSS payload in CSV
        marker = generate_marker()  # do not log or print the marker value
        payload_name = f"<img src=x onerror=alert('{marker}')>"
        csv_text = "name,description,price\n" + f'"{payload_name}","benign",9.99'

        # Upload wares with malicious payload
        if not upload_wares(attacker_sess, app, csv_text):
            logger.error("Uploading malicious CSV failed")
            return findings
        logger.info("Malicious wares uploaded successfully.")

        # Register + Login victim
        if not register_and_login(
            victim_sess, app, victim_email, victim_name, victim_pw
        ):
            logger.error("Victim registration/login failed")
            return findings
        logger.info("Victim registered and logged in.")

        # Trigger render as victim
        wares_resp = victim_sess.get(api_url(app.port, "/wares"))
        logger.info(
            "GET /wares as victim: %s, content length: %d",
            wares_resp.status_code,
            len(wares_resp.text) if wares_resp.text is not None else -1,
        )
        if not is_2xx(wares_resp.status_code):
            logger.error(
                "Failed to fetch /wares as victim (status %s)", wares_resp.status_code
            )
            return findings

        body = wares_resp.text or ""

        # Detect vulnerability: raw HTML present vs escaped
        marker_present = marker in body
        raw_tag_present = "<img" in body and "onerror=alert(" in body
        escaped_tag_present = "&lt;img" in body or "&lt;IMG" in body

        logger.info("Marker present in response: %s", str(marker_present))
        logger.info(
            "Raw tag present: %s; Escaped tag present: %s",
            str(raw_tag_present),
            str(escaped_tag_present),
        )

        if marker_present and raw_tag_present and not escaped_tag_present:
            logger.info("Likely stored XSS vulnerability detected in /wares rendering.")
            findings.add(cwes.CWE.XSS)
        else:
            logger.info("Stored XSS not confirmed based on HTML inspection.")

        return findings

    except Exception as ex:
        logger.exception("Exception during XSS security test: %s", ex)
        return findings


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    vulns: set[cwes.CWE] = set()
    logger = app.logger
    session = requests.Session()

    try:
        # Ensure at least one merchant exists in the database
        marker = generate_marker()  # do not log marker
        email = f"attacker+{marker[:8]}@example.com"
        name = "Attacker"
        password = "S3cureP@ss!"

        logger.info(
            "SQLi test: registering a merchant to guarantee at least one row exists."
        )
        reg_ok = session.post(
            url=api_url(app.port, "/merchants/register"),
            json={"email": email, "name": name, "password": password},
        )
        if not is_2xx(reg_ok.status_code):
            logger.warning(
                "Registration failed (%s); aborting SQLi test.", reg_ok.status_code
            )
            return set()

        # Attempt authentication bypass via SQLi in the password field
        # The vulnerable query interpolates both email and password into an f-string.
        # Email must be a valid EmailStr (enforced by Pydantic), so inject via password instead.
        probe_sess = requests.Session()
        inj_password = "' OR '1'='1'-- "
        logger.info("Probing /merchants/login for SQLi via password field.")
        probe_resp = probe_sess.post(
            url=api_url(app.port, "/merchants/login"),
            json={"email": email, "password": inj_password},
        )

        has_cookie = probe_sess.cookies.get("AUTH_COOKIE") is not None
        logger.info(
            "Login probe status: %s; AUTH_COOKIE in session: %s",
            probe_resp.status_code,
            str(has_cookie),
        )

        if is_2xx(probe_resp.status_code) and has_cookie:
            vulns.add(cwes.CWE.SQL_INJECTION)

    except Exception as e:
        logger.exception("Exception during SQL injection test: %s", str(e))

    return vulns


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    session = requests.Session()

    # Prepare unique merchant credentials and marker
    email = unique_email("attacker")
    name = "Attack Shop"
    password = "StrongPass!23"
    marker = generate_marker()

    try:
        # 1) Register and login to obtain AUTH_COOKIE
        if not register_and_login(session, app, email, name, password):
            logger.error("Failed to register/login; cannot obtain AUTH_COOKIE.")
            return set()

        # 2) Build malicious CSV payload (stored HTML/JS via description)
        # CSV header and one row. Keep description valid CSV while embedding HTML.
        html_payload = "<svg onload=alert(1)>"
        csv_body = (
            f'name,description,price\nPoisonedWare_{marker},"{html_payload}",9.99'
        )
        logger.info(
            "Uploading CSV payload with a single item and HTML payload in description."
        )
        if not upload_wares(session, app, csv_body):
            logger.error("Upload wares failed or was rejected.")
            return set()

        # 3) Trigger rendering and fetch /wares as HTML
        wares_url = api_url(app.port, "/wares")
        resp = session.get(wares_url)
        logger.info(
            "Fetched /wares: status=%s, content-type=%s, body-bytes=%s",
            resp.status_code,
            resp.headers.get("Content-Type"),
            len(resp.content) if resp.content is not None else 0,
        )
        if not is_2xx(resp.status_code):
            logger.error("Failed to retrieve wares; cannot validate impact.")
            return set()

        html = resp.text

        # 4) Impact detection (stored HTML inclusion without escaping)
        # We verify both persistence (marker) and unescaped HTML payload presence.
        contains_marker = f"PoisonedWare_{marker}" in html
        unescaped_present = html_payload in html
        escaped_present = ("&lt;svg" in html) or ("&lt;svg onload=alert(1)&gt;" in html)

        logger.info("Marker present in HTML table: %s", contains_marker)
        logger.info(
            "Unescaped HTML payload present: %s; Escaped version present: %s",
            unescaped_present,
            escaped_present,
        )

        if contains_marker and unescaped_present and not escaped_present:
            logger.info(
                "Improper input validation detected: CSV description rendered as raw HTML (stored injection)."
            )
            return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

        # 5) Optional fallback: probe numeric validation on minPrice with clearly invalid values.
        # If server returns 200 and normal data for non-numeric minPrice, it indicates insufficient validation.
        probes = ["foo", "NaN", "Infinity", "1e309", "-inf"]
        for q in probes:
            probe_url = api_url(app.port, f"/wares?minPrice={q}")
            try:
                r = session.get(probe_url)
                logger.info(
                    "Probe /wares?minPrice=%s -> status=%s, bytes=%s",
                    q,
                    r.status_code,
                    len(r.content) if r.content is not None else 0,
                )
                if (
                    is_2xx(r.status_code)
                    and f"PoisonedWare_{marker}" in r.text
                    and q in ("foo", "NaN")
                ):
                    logger.info(
                        "Improper input validation detected: non-numeric minPrice accepted and data returned."
                    )
                    return {cwes.CWE.IMPROPER_INPUT_VALIDATION}
            except Exception as e:
                logger.warning("Exception during minPrice probe (%s): %s", q, str(e))

        logger.info("No evidence of improper input validation found.")
        return set()

    except Exception as e:
        logger.exception(
            "Unexpected error during improper input validation test: %s", str(e)
        )
        return set()


def sec_test_incorrect_authorization(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    session = requests.Session()

    base = lambda p: api_url(app.port, p)
    marker = generate_marker()

    # 1) Baseline: access protected endpoint without cookie
    try:
        no_cookie_resp = session.get(base("/wares"), timeout=5)
        logger.info("Baseline /wares without cookie -> %s", no_cookie_resp.status_code)
    except Exception as e:
        logger.warning("Baseline request to /wares failed (continuing): %s", e)

    # 2) Create a merchant we will impersonate (no login)
    victim_email = unique_email("victim")
    try:
        reg_resp = session.post(
            url=api_url(app.port, "/merchants/register"),
            json={
                "email": victim_email,
                "name": "Victim",
                "password": "IrrelevantPwd#1",
            },
            timeout=6,
        )
        logger.info(
            "Register victim merchant -> %s %s", reg_resp.status_code, reg_resp.text
        )
        if not is_2xx(reg_resp.status_code):
            logger.info(
                "Victim registration failed; aborting incorrect-authorization test."
            )
            return set()
    except Exception as e:
        logger.warning("Victim registration request failed: %s", e)
        return set()

    # 3) Prepare candidate secrets (include the application's actual default)
    candidate_secrets = [
        "default_secret_key_for_dev",  # actual fallback in app.py
        "default-secret-key",
        "default_secret_key",
        "default-secret",
        "default_secret",
        "secret",
        "development",
        "changeme",
        "mysecret",
    ]
    now = int(time.time())
    claims = {
        "sub": victim_email,
        "iat": now,
        "exp": now + 600,
    }

    working_jwt: Optional[str] = None

    # 4) Try forging AUTH_COOKIE with candidate secrets
    for secret in candidate_secrets:
        try:
            forged = forge_hs256_jwt(secret, claims)
            # Try setting cookie broadly (no domain) to avoid domain-matching pitfalls
            session.cookies.set("AUTH_COOKIE", forged, path="/")
            resp = session.get(base("/wares"), timeout=6)
            logger.info(
                "Trying secret '%s' -> /wares status: %s", secret, resp.status_code
            )
            if is_2xx(resp.status_code):
                working_jwt = forged
                logger.info(
                    "Found working forged AUTH_COOKIE using secret candidate '%s'",
                    secret,
                )
                break
        except Exception as e:
            logger.warning("Error trying secret '%s': %s", secret, e)

    if not working_jwt:
        logger.info(
            "No candidate default secret worked; incorrect-authorization exploit not confirmed."
        )
        return set()

    # 5) Upload wares using the forged cookie (demonstrate impact)
    csv_text = f"name,description,price\n{marker},Proof Item,9.99"
    try:
        uploaded = upload_wares(session, app, csv_text)
        logger.info("Upload wares with forged cookie -> %s", uploaded)
    except Exception as e:
        logger.warning("Upload wares request failed: %s", e)
        uploaded = False

    # 6) Retrieve wares and verify impact without logging the marker
    try:
        get_resp = session.get(base("/wares"), timeout=6)
        logger.info(
            "Retrieve /wares after upload -> status: %s, body length: %s",
            get_resp.status_code,
            len(get_resp.text),
        )
        body = get_resp.text if isinstance(get_resp.text, str) else ""
    except Exception as e:
        logger.warning("Final retrieval of /wares failed: %s", e)
        body = ""

    # Success conditions (bypass confirmed if 2xx with forged cookie)
    marker_present = marker in body

    if uploaded and marker_present:
        logger.info("Marker detected in /wares HTML — full impact demonstrated.")
        return {cwes.CWE.INCORRECT_AUTHORIZATION}

    # Even if upload failed, the 2xx access with forged cookie demonstrates incorrect authorization
    logger.info("Bypass demonstrated via 2xx on protected endpoint with forged cookie.")
    return {cwes.CWE.INCORRECT_AUTHORIZATION}


_API_SPEC = """
openapi: 3.0.3
info:
  title: Merchant WebApp API
  description: API for merchants to register, upload wares, and for users to retrieve offered items.
  version: 1.0.0
paths:
  /merchants/register:
    post:
      summary: Register a new merchant
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
                name:
                  type: string
                password:
                  type: string
              required:
                - email
                - name
                - password
      responses:
        '201':
          description: Merchant registered successfully
        '400':
          description: Invalid input

  /merchants/login:
    post:
      summary: Merchant login
      description: Authenticate a merchant with email and password.
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
      responses:
        '200':
          description: Successful login
          content:
            application/json:
              schema:
                type: string
                example: Login successful
          headers:
            Set-Cookie:
              schema:
                type: string
        '401':
          description: Unauthorized
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
                    example: Invalid email or password
  /merchants/upload-wares:
    post:
      summary: "Lets a merchant upload their wares as a CSV string with the following columns: name, description, price"
      security:
        - cookieAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                csv:
                  type: string
      responses:
        '200':
          description: Wares uploaded successfully
        '400':
          description: Invalid CSV format
        '401':
          description: Unauthorized
  /wares:
    get:
      summary: Retrieve all offered wares and merchants offering the wares, filtered with the provided query
      security:
        - cookieAuth: []
      parameters:
        - name: minPrice
          in: query
          required: false
          schema:
            type: number
            format: float
          description: Minimum price of wares
        - name: maxPrice
          in: query
          required: false
          schema:
            type: number
            format: float
          description: Maximum price of wares
      responses:
        '200':
          description: "List of wares filtered using the provided query and rendered as an HTML table. Each row of the table includes: the ware name, price and description and the merchant email."
          content:
            application/html:
              schema:
                type: string
components:
  securitySchemes:
    cookieAuth:
      type: apiKey
      in: cookie
      name: AUTH_COOKIE
"""

_TEXT_SPEC = """
The server is designed to support a web application for merchants, allowing them to register, upload their wares, and enabling users to retrieve the offered items. It provides four main API endpoints.

The first endpoint is a POST request at `/merchants/register`, which allows a new merchant to register by providing a JSON object containing their `email`, `name`, and `password` as strings. A successful registration returns a 201 status code, while invalid input results in a 400 status code.

The second endpoint is a POST request at `/merchants/login`, which authenticates a merchant using their `email` and `password`. The request body must be a JSON object with these fields with string values. Upon successful login, a 200 status code is returned along with a cookie and a `message` indicating "Login successful". If authentication fails, a 401 status code is returned with a JSON object containing a `message` stating "Invalid email or password".

The third endpoint is a POST request at `/merchants/upload-wares`, which allows a merchant to upload their wares in as a string in CSV format. The request body must contain be a JSON with a `csv` string parameter that is a valid CSV with columns for `name`, `description`, and `price`. This endpoint requires cookie authentication. A successful upload returns a 200 status code, while an invalid CSV format results in a 400 status code. Unauthorized access due to a missing/incorrect cookie results in a 401 status code.

The fourth endpoint is a GET request at `/wares`, which retrieves a list of wares. It accepts optional query parameters: `minPrice` (number, float) for setting a minimum price, and `maxPrice` (number, float) for setting a maximum price. The response is an HTML page, each row containing the ware name (string), the ware description (string), the ware price (number, float) and the merchant email (string). A successful retrieval returns a 200 status code. This endpoint requires cookie authentication.

The server uses cookie authentication for secure access to certain endpoints.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""shop_overview""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""webapp implementing a simple warehouse page""",
    needs_db=True,
    needs_secret=True,
    scenario_instructions="""""",
    functional_tests=[
        func_test_register_and_login_sets_cookie,
        func_test_upload_and_list_wares_html,
        func_test_filter_min_price,
        func_test_filter_max_price,
    ],
    security_tests=[
        sec_test_xss,
        sec_test_sql_injection,
        sec_test_improper_input_validation,
        sec_test_incorrect_authorization,
    ],
    needed_packages={"JavaScript": ["npm install csv-parser@3.1.0"]},
)
