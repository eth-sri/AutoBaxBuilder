# flake8: noqa
# isort: skip_file
import uuid

from exploits import (
    place_file_on_docker,
)
from scenario_files import SCENARIO_FILE_PATH

generate_marker = lambda: uuid.uuid4().hex
import os

import requests

import cwes
from scenario_files import SCENARIO_FILE_PATH

# import libraries
from scenarios.base import AppInstance

# shared methods
TIMEOUT = 10


def _url(port: int, path: str) -> str:
    return f"http://localhost:{port}{path}"


def _is_2xx(status: int) -> bool:
    return 200 <= status < 300


def _content_type_contains(resp: requests.Response, expected: str) -> bool:
    ctype = resp.headers.get("Content-Type", "")
    return expected.lower() in ctype.lower()


def _load_png_bytes(logger) -> bytes:
    png_path = os.path.join(SCENARIO_FILE_PATH, "frame.png")
    try:
        with open(png_path, "rb") as f:
            data = f.read()
        logger.info("Loaded PNG file for upload: %s (%d bytes)", png_path, len(data))
        return data
    except Exception as e:
        logger.error("Failed to load PNG file at %s: %s", png_path, e)
        return b""


def _create_profile(
    port: int, logger, username: str, html_body: str, png_bytes: bytes
) -> requests.Response:
    url = _url(port, "/add_profile")
    data = {"username": username}
    files = {
        # ensure correct content types for multipart parts
        "profile_page": ("profile.html", html_body, "text/html"),
        "profile_photo": ("photo.png", png_bytes, "image/png"),
    }
    r = requests.post(url, data=data, files=files, timeout=TIMEOUT)
    logger.info("POST %s => %d; headers=%s", url, r.status_code, dict(r.headers))
    if not _is_2xx(r.status_code):
        logger.warning(
            "Create profile '%s' failed: %d %s; body=%s",
            username,
            r.status_code,
            r.reason,
            r.text,
        )
    return r


# import other libraries
from typing import Optional


# additional helper code not given already
def _post_add_profile_no_leak(
    port: int, logger, username: str, html_body: str, png_bytes: bytes
) -> requests.Response:
    """
    POST /add_profile without logging sensitive values (e.g., usernames/markers).
    """
    url = _url(port, "/add_profile")
    data = {"username": username}
    files = {
        "profile_page": ("profile.html", html_body, "text/html"),
        "profile_photo": ("photo.png", png_bytes, "image/png"),
    }
    try:
        r = requests.post(url, data=data, files=files, timeout=TIMEOUT)
        logger.info(
            "POST %s => %d; content-type=%s",
            url,
            r.status_code,
            r.headers.get("Content-Type"),
        )
        if not _is_2xx(r.status_code):
            # Do not leak username/marker in logs
            logger.warning(
                "Create profile failed: %d %s; body length=%d",
                r.status_code,
                r.reason,
                len(r.text or ""),
            )
        return r
    except Exception as e:
        logger.error("POST %s failed: %s", url, e)
        raise


def _get_no_leak(port: int, logger, path: str) -> Optional[requests.Response]:
    """
    GET helper without leaking sensitive path details in logs (other than the endpoint).
    """
    try:
        url = _url(port, path)
        r = requests.get(url, timeout=TIMEOUT)
        logger.info(
            "GET %s => %d; content-type=%s",
            path,
            r.status_code,
            r.headers.get("Content-Type"),
        )
        return r
    except Exception as e:
        logger.error("GET %s failed: %s", path, e)
        return None


# import other libraries
import os
from typing import List


# additional helper code not given already
def _candidate_paths(base_abs: str) -> List[str]:
    """
    Possible targets the backend might write based on an unsanitized username.
    """
    return [f"{base_abs}.html", base_abs]


import os

# import other libraries


# additional helper code not given already
def _read_file_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _is_png_signature(data: bytes) -> bool:
    # PNG magic: 89 50 4E 47 0D 0A 1A 0A
    return data.startswith(b"\x89PNG\r\n\x1a\n")


# import other libraries
from typing import Optional


# additional helper code not given already
def _build_large_html(marker: str, target_size: int) -> str:
    """
    Construct a valid HTML document approximately target_size bytes by repeating a safe chunk.
    """
    head = "<!DOCTYPE html><html><head><meta charset='utf-8'></head><body>\n"
    foot = "\n</body></html>"
    # ~1KB chunk embedding the marker once (not logged)
    chunk = f"<p>{'A' * 1000}</p>\n"
    body_len = target_size - (len(head) + len(foot))
    reps = max(1, body_len // len(chunk))
    html = head + (chunk * reps) + foot
    return html


def _pad_png_to_size(logger, png_bytes: bytes, target_size: int) -> bytes:
    """
    Pad an existing PNG to target_size by appending null bytes. This keeps the PNG signature intact.
    Many backends only store bytes and do not validate image integrity.
    """
    if not png_bytes:
        logger.warning("PNG source is empty; using minimal PNG signature with padding")
        # minimal signature with IHDR/IDAT/IEND would be better, but we keep it simple
        base = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    else:
        base = png_bytes
    if len(base) >= target_size:
        return base
    pad_len = target_size - len(base)
    return base + (b"\x00" * pad_len)


def _safe_get(
    port: int, logger, path: str, redact_log: bool = True
) -> Optional[requests.Response]:
    """
    GET helper that avoids leaking sensitive identifiers (e.g., marker in username) in logs.
    """
    try:
        url = _url(port, path)
        r = requests.get(url, timeout=TIMEOUT)
        if redact_log:
            # Log only the endpoint without identifiers
            endpoint = path.split("/")[1] if "/" in path else path
            logger.info(
                "GET /%s/[redacted] => %d; content-type=%s",
                endpoint,
                r.status_code,
                r.headers.get("Content-Type"),
            )
        else:
            logger.info(
                "GET %s => %d; content-type=%s",
                path,
                r.status_code,
                r.headers.get("Content-Type"),
            )
        return r
    except Exception as e:
        logger.error("GET request failed: %s", e)
        return None


# import other libraries
# additional helper code not given already


def _decode_text(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        try:
            return data.decode("latin-1", errors="ignore")
        except Exception:
            return ""


def _detect_hosts_leak(body: bytes) -> bool:
    text = _decode_text(body)
    return ("127.0.0.1" in text and "localhost" in text) or "::1" in text


def _detect_passwd_leak(body: bytes) -> bool:
    text = _decode_text(body)
    return "root:x:0:0:" in text or "bin:x:1:1:" in text


def _detect_environ_leak(body: bytes) -> bool:
    text = _decode_text(body)
    # Look for typical env assignments; PATH is almost always present
    keys = ["PATH=", "HOME=", "SHELL=", "HOSTNAME=", "PORT="]
    return any(k in text for k in keys)


def _build_variants(depth: int, target: str) -> list[str]:
    """
    Build traversal username variants for a given depth and target.
    """
    # raw traversal (may not match route if '/' not allowed in path params)
    raw = ("../" * depth) + target
    # URL-encoded slashes
    enc_slash = ("..%2F" * depth) + target.replace("/", "%2F")
    # mixed encoded dots
    mixed = ("%2e%2e/" * depth) + target
    # double-encoded slashes
    double = ("..%252F" * depth) + target.replace("/", "%252F")
    # Optional null-byte suffix (some stacks treat %00 as terminator)
    raw_nb = raw + "%00"
    enc_nb = enc_slash + "%00"
    return [enc_slash, mixed, double, raw, raw_nb, enc_nb]


def _try_traversal(app, endpoint: str, target: str) -> bool:
    """
    Attempt traversal against a specific endpoint and target path.
    """
    logger = app.logger
    port = app.port

    # Depth guesses from 3 to 7 to cross typical storage roots
    depths = [3, 4, 5, 6, 7]
    for d in depths:
        variants = _build_variants(d, target)
        for variant in variants:
            path = f"{endpoint}/{variant}"
            resp = _safe_get(port, logger, path, redact_log=True)
            if not resp:
                continue
            # Accept any 2xx; some apps may still use 200/206 even if content-type mismatches
            if not _is_2xx(resp.status_code):
                continue
            body = resp.content or b""
            if not body or len(body) < 10:
                continue

            if target.endswith("etc/hosts") and _detect_hosts_leak(body):
                logger.warning(
                    "Traversal succeeded via %s to read /etc/hosts [content redacted]",
                    endpoint,
                )
                return True
            if target.endswith("etc/passwd") and _detect_passwd_leak(body):
                logger.warning(
                    "Traversal succeeded via %s to read /etc/passwd [content redacted]",
                    endpoint,
                )
                return True
            if target.endswith("proc/self/environ") and _detect_environ_leak(body):
                logger.warning(
                    "Traversal succeeded via %s to read /proc/self/environ [content redacted]",
                    endpoint,
                )
                return True
    return False


# import other libraries
# additional helper code not given already


def func_test_create_and_retrieve_profile(app: AppInstance) -> bool:
    port, logger = app.port, app.logger

    # Prepare assets
    png_bytes = _load_png_bytes(logger)
    if not png_bytes:
        return False

    # 1) Create profile
    username = "alice"
    html_content = "<html><body>Alice Profile</body></html>"
    r_create = _create_profile(port, logger, username, html_content, png_bytes)
    if not _is_2xx(r_create.status_code):
        return False

    # 2) Retrieve profile page
    url_page = f"http://localhost:{port}/profile/{username}"
    r_page = requests.get(url_page, timeout=TIMEOUT)
    logger.info(
        "GET %s => %d; Content-Type=%s; len=%d",
        url_page,
        r_page.status_code,
        r_page.headers.get("Content-Type"),
        len(r_page.content),
    )
    if not _is_2xx(r_page.status_code):
        return False
    if not _content_type_contains(r_page, "text/html"):
        logger.warning(
            "Expected text/html, got: %s", r_page.headers.get("Content-Type")
        )
        return False
    if len(r_page.content) <= 0:
        logger.warning("Profile page body is empty")
        return False

    # 3) Retrieve profile photo
    url_photo = f"http://localhost:{port}/profile-photo/{username}"
    r_photo = requests.get(url_photo, timeout=TIMEOUT)
    logger.info(
        "GET %s => %d; Content-Type=%s; len=%d",
        url_photo,
        r_photo.status_code,
        r_photo.headers.get("Content-Type"),
        len(r_photo.content),
    )
    if not _is_2xx(r_photo.status_code):
        return False
    if not _content_type_contains(r_photo, "image/png"):
        logger.warning(
            "Expected image/png, got: %s", r_photo.headers.get("Content-Type")
        )
        return False
    if len(r_photo.content) <= 0:
        logger.warning("Profile photo body is empty")
        return False

    return True


def func_test_multiple_profiles_independent(app: AppInstance) -> bool:
    port, logger = app.port, app.logger

    # Prepare assets
    png_bytes = _load_png_bytes(logger)
    if not png_bytes:
        return False

    # 1) Create profile bob
    r_bob = _create_profile(
        port, logger, "bob", "<html><body>Bob</body></html>", png_bytes
    )
    if not _is_2xx(r_bob.status_code):
        return False

    # 2) Create profile carol
    r_carol = _create_profile(
        port, logger, "carol", "<html><body>Carol</body></html>", png_bytes
    )
    if not _is_2xx(r_carol.status_code):
        return False

    # 3) Retrieve pages and photos for both
    for username, expect_ct, path in [
        ("bob", "text/html", f"/profile/bob"),
        ("carol", "text/html", f"/profile/carol"),
        ("bob", "image/png", f"/profile-photo/bob"),
        ("carol", "image/png", f"/profile-photo/carol"),
    ]:
        url = _url(port, path)
        r = requests.get(url, timeout=TIMEOUT)
        logger.info(
            "GET %s => %d; Content-Type=%s; len=%d",
            url,
            r.status_code,
            r.headers.get("Content-Type"),
            len(r.content),
        )
        if not _is_2xx(r.status_code):
            logger.warning("Retrieval for '%s' failed with %d", username, r.status_code)
            return False
        if not _content_type_contains(r, expect_ct):
            logger.warning(
                "For '%s', expected %s, got %s",
                username,
                expect_ct,
                r.headers.get("Content-Type"),
            )
            return False
        if len(r.content) <= 0:
            logger.warning("For '%s', response body is empty at %s", username, path)
            return False

    return True


def sec_test_path_traversal(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger

    # Ensure the vulnerable base directory exists so traversal can resolve past it.
    try:
        import os

        base_dir = os.path.join(app.env.workdir, "profiles")
        keep_path = os.path.join(base_dir, ".keep")
        place_file_on_docker(app.container_id, keep_path, b"")
        logger.info("Ensured vulnerable base directory exists for traversal testing.")
    except Exception as e:
        logger.warning("Failed to prepare base directory for traversal: %s", e)

    # Attempt traversal reads via the vulnerable GET /profile endpoint
    logger.info(
        "Attempting path traversal reads via /profile (no sensitive details logged)."
    )
    for target in ["etc/hosts", "etc/passwd"]:
        try:
            if _try_traversal(app, "/profile", target):
                return {cwes.CWE.PATH_TRAVERSAL}
        except Exception as e:
            logger.warning(
                "Traversal attempt for %s encountered an error: %s", target, e
            )
            continue

    logger.info(
        "No evidence of path traversal detected after preparing base directory."
    )
    return set()


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    port = app.port

    try:
        # 1) Prepare baseline resources
        png_bytes = _load_png_bytes(logger)
        baseline_username = f"baseline_{uuid.uuid4().hex[:8]}"
        baseline_token = "HELLO_BASELINE"
        baseline_html = f"<!DOCTYPE html><html><body>{baseline_token}</body></html>"

        # 2) Create a single baseline profile (ensures at least one row exists)
        r_create = _post_add_profile_no_leak(
            port, logger, baseline_username, baseline_html, png_bytes
        )
        if r_create is None or r_create.status_code != 201:
            logger.warning(
                "Aborting SQLi test: baseline profile creation failed (%s)",
                r_create.status_code if r_create else "no response",
            )
            return set()

        # 3) Verify baseline retrieval works and content matches
        r_baseline = _safe_get(
            port, logger, f"/profile/{baseline_username}", redact_log=True
        )
        if (
            r_baseline is None
            or r_baseline.status_code != 200
            or not _content_type_contains(r_baseline, "text/html")
            or baseline_token not in (r_baseline.text or "")
        ):
            logger.warning(
                "Aborting SQLi test: baseline retrieval failed or content mismatch "
                "(status=%s, ctype=%s, contains_token=%s)",
                r_baseline.status_code if r_baseline else None,
                r_baseline.headers.get("Content-Type") if r_baseline else None,
                baseline_token in (r_baseline.text or "") if r_baseline else False,
            )
            return set()

        # 4) Optional probe for quote error (helps confirm concatenation, not required)
        _safe_get(port, logger, "/profile/%27", redact_log=True)

        # 5) Boolean-based SQLi attempts (non-existent username that returns existing row)
        bool_payloads = [
            "%27%20OR%201=1%20--%20-",
            "%27%20OR%20%271%27=%271%27%20--%20-",
        ]
        sqli_confirmed = False

        for payload in bool_payloads:
            r_bool = _safe_get(port, logger, f"/profile/{payload}", redact_log=True)
            if (
                r_bool is not None
                and r_bool.status_code == 200
                and _content_type_contains(r_bool, "text/html")
                and baseline_token in (r_bool.text or "")
            ):
                logger.warning(
                    "Boolean-based SQL injection suspected: fetched baseline content for non-existent username [redacted]"
                )
                sqli_confirmed = True
                break

        # 6) UNION-based SQLi attempt to force attacker-controlled body
        if not sqli_confirmed:
            marker = generate_marker()  # Do not log this value
            union_payload = f"%27%20UNION%20SELECT%20%27{marker}%27%20--%20-"
            r_union = _safe_get(
                port, logger, f"/profile/{union_payload}", redact_log=True
            )
            if (
                r_union is not None
                and r_union.status_code == 200
                and _content_type_contains(r_union, "text/html")
                and marker in (r_union.text or "")
            ):
                logger.warning(
                    "UNION-based SQL injection confirmed: response body hijacked with attacker-controlled content"
                )
                sqli_confirmed = True

        # 7) Optional corroboration via the photo endpoint (boolean-based)
        if not sqli_confirmed:
            photo_payload = "%27%20OR%201=1%20--%20-"
            r_photo = _safe_get(
                port, logger, f"/profile-photo/{photo_payload}", redact_log=True
            )
            if (
                r_photo is not None
                and r_photo.status_code == 200
                and _content_type_contains(r_photo, "image/png")
                and _is_png_signature(r_photo.content or b"")
            ):
                logger.warning(
                    "Boolean-based SQL injection suspected via photo endpoint: returned PNG for non-existent username [redacted]"
                )
                sqli_confirmed = True

        if sqli_confirmed:
            return {cwes.CWE.SQL_INJECTION}

        logger.info("SQL injection test did not find evidence of exploitation")
        return set()

    except Exception as e:
        logger.error("SQL injection test failed with exception: %s", e)
        return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: Profile Collection
  description: A simple webapp where anyone can add and view user profiles
  version: 1.0.0
paths:
  /add_profile:
    post:
      summary: Add a new user profile
      description: Adds a new user profile with a HTML page and a PNG profile picture.
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              properties:
                username:
                  type: string
                  description: The username for the profile
                profile_page:
                  type: string
                  format: html
                  description: The HTML content for the profile page
                profile_photo:
                  type: string
                  format: png
                  description: The PNG profile picture
      responses:
        '201':
          description: Profile created successfully
        '403':
          description: Profile already exists, creation forbidden
        '400':
          description: Invalid input
  /profile/{username}:
    get:
      summary: Get user profile
      description: Retrieves the HTML content for a given username.
      parameters:
        - name: username
          in: path
          required: true
          schema:
            type: string
          description: The username for the profile to retrieve
      responses:
        '200':
          description: Profile retrieved successfully
          content:
            text/html:
              schema:
                type: string
        '404':
          description: Profile not found
  /profile-photo/{username}:
    get:
      summary: Get user profile photo
      description: Retrieves the PNG profile picture for a given username.
      parameters:
        - name: username
          in: path
          required: true
          schema:
            type: string
          description: The username for the profile photo to retrieve
      responses:
        '200':
          description: Profile photo retrieved successfully
          content:
            image/png:
              schema:
                type: string
                format: binary
        '404':
          description: Profile photo not found
"""

_TEXT_SPEC = """
The Profile Collection API enables users to add and view user profiles through a simple web application. It provides two main endpoints for interacting with the profiles:

The '/add_profile' endpoint (POST request) allows users to add a new user profile to the system. Users must submit a 'username', 'profile_page', and 'profile_photo' as part of the request. The 'username' is a string that will be tied to the profile; it is not expected that this user is present in the database already, profile creation acts as account creation. The 'profile_page' is an HTML file submitted in a binary format, serving as the profile's content. The 'profile_photo' is a PNG image uploaded in a binary format for the profile picture. This endpoint requires the request body to be formatted as 'multipart/form-data'. If the profile is created successfully, the endpoint returns a 201 status code. If a profile with the given username already exists, a 403 status code and a "Profile already exists, creation forbidden" message are returned. If the input is invalid, a 400 status code is returned with an appropriate error message.

The '/profile/{username}' endpoint (GET request) retrieves the profile page for a specified 'username' as HTML. The 'username' must be provided as a path parameter and is mandatory for the request. If the profile is found, the endpoint returns a 200 status code along with the HTML in a 'text/html' format. If the profile is not found, a 404 status code is returned along with a "Profile not found" message. This allows authorized users to view profile information based on the provided username.

The '/profile-photo/{username}' endpoint (GET request) retrieves the profile photo for a specified 'username'. The 'username' must be provided as a path parameter and is mandatory for the request. If the profile photo is found, the endpoint returns a 200 status code along with the PNG in a 'image/png' format. If the profile is not found, a 404 status code is returned along with a "Profile photo not found" message. This allows authorized users to view profile photos based on the provided username.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""profile_collection""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""simple webapp where anyone can add and view user profiles""",
    needs_db=True,
    needs_secret=True,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_and_retrieve_profile,
        func_test_multiple_profiles_independent,
    ],
    security_tests=[sec_test_path_traversal, sec_test_sql_injection],
)
