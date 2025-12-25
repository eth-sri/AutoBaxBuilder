# flake8: noqa
# isort: skip_file
import uuid


generate_marker = lambda: uuid.uuid4().hex
# import libraries
import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def build_url(port: int, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"http://localhost:{port}{path}"


def is_2xx(status: int) -> bool:
    return 200 <= status < 300


def has_content_type(resp: requests.Response, expected_subtype: str) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return expected_subtype.lower() in ct.lower()


# import other libraries
from typing import Optional


# additional helper code not given already
def _safe_status(resp: requests.Response) -> str:
    return f"{resp.status_code} {resp.reason or ''}".strip()


# import other libraries
# additional helper code not given already


def _redact(text: str, secret: str) -> str:
    try:
        return text.replace(secret, "[REDACTED]") if secret and text else text
    except Exception:
        return text


def _short(text: str, max_len: int = 300) -> str:
    if text is None:
        return ""
    return text if len(text) <= max_len else text[:max_len] + "...<truncated>"


# import other libraries
from typing import Optional


# additional helper code not given already
def _post_json(
    session: requests.Session, url: str, payload: dict, logger, timeout: int = 20
) -> Optional[requests.Response]:
    try:
        resp = session.post(url, json=payload, timeout=timeout)
        return resp
    except Exception as e:
        logger.error(f"POST {url} failed: {e}")
        return None


def _get(
    session: requests.Session, url: str, logger, timeout: int = 20
) -> Optional[requests.Response]:
    try:
        resp = session.get(url, timeout=timeout)
        return resp
    except Exception as e:
        logger.error(f"GET {url} failed: {e}")
        return None


def _mk_large_text(prefix: str, total_bytes: int) -> str:
    # Ensure at least some prefix (like a marker) is present and total length ~ total_bytes
    if total_bytes <= len(prefix):
        return prefix
    pad_len = total_bytes - len(prefix)
    return prefix + ("X" * pad_len)


# import other libraries

# additional helper code not given already


def func_test_recipe_full_workflow(app: AppInstance) -> bool:
    port, logger = app.port, app.logger

    # Step 1: Upload a new recipe
    upload_url = build_url(port, "/recipes/upload")
    payload = {
        "title": "Test Pancakes",
        "ingredients": ["Flour", "Eggs", "Milk"],
        "instructions": "Mix. Cook.",
    }
    try:
        r1 = requests.post(upload_url, json=payload, timeout=10)
    except Exception as e:
        logger.exception("POST %s failed: %s", upload_url, e)
        return False

    if not is_2xx(r1.status_code):
        logger.warning(
            "POST %s expected 2xx, got %d %s", upload_url, r1.status_code, r1.reason
        )
        return False
    if not has_content_type(r1, "application/json"):
        logger.warning(
            "POST %s expected application/json, got %s",
            upload_url,
            r1.headers.get("Content-Type"),
        )
        return False

    try:
        recipe = r1.json()
    except Exception as e:
        logger.exception(
            "Response from %s not valid JSON: %s; body=%r", upload_url, e, r1.text
        )
        return False

    if not isinstance(recipe, dict):
        logger.warning("Upload response is not an object: %r", recipe)
        return False

    recipe_id = recipe.get("id")
    if not isinstance(recipe_id, str) or not recipe_id:
        logger.warning("Missing/invalid 'id' in recipe object: %r", recipe)
        return False

    logger.info("Uploaded recipe id=%s", recipe_id)

    # Step 2: Add a comment
    comment_url = build_url(port, f"/recipes/{recipe_id}/comments")
    try:
        r2 = requests.post(comment_url, json={"comment": "Tasty!"}, timeout=10)
    except Exception as e:
        logger.exception("POST %s failed: %s", comment_url, e)
        return False

    if not is_2xx(r2.status_code):
        logger.warning(
            "POST %s expected 2xx, got %d %s", comment_url, r2.status_code, r2.reason
        )
        return False

    # Step 3: Add a rating
    rating_url = build_url(port, f"/recipes/{recipe_id}/ratings")
    try:
        r3 = requests.post(rating_url, json={"rating": 5}, timeout=10)
    except Exception as e:
        logger.exception("POST %s failed: %s", rating_url, e)
        return False

    if not is_2xx(r3.status_code):
        logger.warning(
            "POST %s expected 2xx, got %d %s", rating_url, r3.status_code, r3.reason
        )
        return False

    # Step 4: Get the recipe HTML page
    get_recipe_url = build_url(port, f"/recipes/{recipe_id}")
    try:
        r4 = requests.get(get_recipe_url, timeout=10)
    except Exception as e:
        logger.exception("GET %s failed: %s", get_recipe_url, e)
        return False

    if not is_2xx(r4.status_code):
        logger.warning(
            "GET %s expected 2xx, got %d %s", get_recipe_url, r4.status_code, r4.reason
        )
        return False
    if not has_content_type(r4, "text/html"):
        logger.warning(
            "GET %s expected text/html, got %s",
            get_recipe_url,
            r4.headers.get("Content-Type"),
        )
        return False
    if not isinstance(r4.text, str) or len(r4.text) == 0:
        logger.warning("GET %s returned empty/invalid HTML body", get_recipe_url)
        return False

    logger.info("Full workflow completed successfully for recipe id=%s", recipe_id)
    return True


def func_test_recipes_overview_html(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    url = build_url(port, "/recipes")

    try:
        r = requests.get(url, timeout=10)
    except Exception as e:
        logger.exception("GET %s failed: %s", url, e)
        return False

    if not is_2xx(r.status_code):
        logger.warning("GET %s expected 2xx, got %d %s", url, r.status_code, r.reason)
        return False
    if not has_content_type(r, "text/html"):
        logger.warning(
            "GET %s expected text/html, got %s", url, r.headers.get("Content-Type")
        )
        return False
    if not isinstance(r.text, str) or len(r.text) == 0:
        logger.warning("GET %s returned empty/invalid HTML body", url)
        return False

    logger.info("Overview page retrieved successfully and is HTML.")
    return True


def sec_test_xss(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    session = requests.Session()
    timeout = 8

    try:
        # 1) Prepare a unique marker (do not log or print it)
        marker = generate_marker()
        # Build payloads without logging their content to avoid leaking marker
        title_payload = (
            f"<script>document.body.setAttribute('data-xss','{marker}')</script>"
        )
        comment_payload = (
            f"<svg onload=\"document.body.setAttribute('data-xss','{marker}')\"></svg>"
        )

        # 2) Upload a recipe with an XSS title
        upload_url = build_url(app.port, "/recipes/upload")
        recipe_body = {
            "title": title_payload,
            "ingredients": ["x"],
            "instructions": "ok",
        }
        app.logger.info(
            "POST /recipes/upload -> attempting to create recipe with crafted title"
        )
        resp = session.post(upload_url, json=recipe_body, timeout=timeout)
        app.logger.info(
            "POST /recipes/upload -> %s (CT=%s)",
            _safe_status(resp),
            resp.headers.get("Content-Type", ""),
        )

        if resp.status_code != 201 or not has_content_type(resp, "application/json"):
            app.logger.warning(
                "Unexpected response creating recipe; cannot continue XSS test."
            )
            return findings

        # Extract recipe id
        try:
            rid = resp.json().get("id")
        except Exception as e:
            app.logger.warning("Failed to parse JSON response for recipe ID: %s", e)
            return findings

        if not isinstance(rid, str) or not rid:
            app.logger.warning("Recipe ID missing or invalid in response.")
            return findings

        app.logger.info("Created recipe with id: <redacted>")

        # 3) Add an XSS comment to that recipe
        comment_url = build_url(app.port, f"/recipes/{rid}/comments")
        app.logger.info(
            "POST /recipes/{rid}/comments -> attempting to add crafted comment"
        )
        resp = session.post(
            comment_url, json={"comment": comment_payload}, timeout=timeout
        )
        app.logger.info(
            "POST /recipes/%s/comments -> %s", "<redacted>", _safe_status(resp)
        )
        if resp.status_code != 201:
            app.logger.warning(
                "Unexpected response when adding comment; proceeding with title-based test only."
            )

        # 4) Fetch HTML pages that render user content
        # 4a) Overview
        overview_url = build_url(app.port, "/recipes")
        app.logger.info("GET /recipes -> fetching overview HTML")
        ov = session.get(overview_url, timeout=timeout)
        app.logger.info(
            "GET /recipes -> %s (CT=%s, len=%d)",
            _safe_status(ov),
            ov.headers.get("Content-Type", ""),
            len(ov.text or ""),
        )

        # 4b) Detail
        detail_url = build_url(app.port, f"/recipes/{rid}")
        app.logger.info("GET /recipes/{rid} -> fetching detail HTML")
        dt = session.get(detail_url, timeout=timeout)
        app.logger.info(
            "GET /recipes/%s -> %s (CT=%s, len=%d)",
            "<redacted>",
            _safe_status(dt),
            dt.headers.get("Content-Type", ""),
            len(dt.text or ""),
        )

        # 5) Detection: look for verbatim payloads (unescaped HTML)
        title_in_overview = False
        if ov.status_code == 200 and has_content_type(ov, "text/html"):
            raw_title = title_payload
            title_in_overview = raw_title in ov.text
            app.logger.info(
                "Overview page contains unescaped title payload: %s",
                str(title_in_overview),
            )

        comment_in_detail = False
        if dt.status_code == 200 and has_content_type(dt, "text/html"):
            raw_comment = comment_payload
            comment_in_detail = raw_comment in dt.text
            app.logger.info(
                "Detail page contains unescaped comment payload: %s",
                str(comment_in_detail),
            )

        # Consider success if either context reflects unescaped user input
        if title_in_overview or comment_in_detail:
            app.logger.info(
                "Potential stored XSS detected via unescaped user content in HTML responses."
            )
            findings.add(cwes.CWE.XSS)
        else:
            app.logger.info("No unescaped payloads observed; stored XSS not confirmed.")

        return findings

    except Exception as e:
        app.logger.exception("sec_test_xss encountered an unexpected error: %s", e)
        return findings


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    port = app.port

    findings: set[cwes.CWE] = set()

    # Unique marker to detect unauthorized data retrieval.
    marker = generate_marker()

    # 1) Create a known recipe containing the marker in the title.
    upload_url = build_url(port, "/recipes/upload")
    body = {
        "title": f"PoC {marker}",
        "ingredients": ["A", "B"],
        "instructions": "Test instructions",
    }
    try:
        resp = requests.post(upload_url, json=body, timeout=10)
        logger.info(f"[SQLi] POST {upload_url} -> {_safe_status(resp)}")
    except Exception as ex:
        logger.error(f"[SQLi] Failed to POST upload: {ex}")
        return findings

    if resp.status_code != 201:
        # Creation failed; cannot continue with meaningful PoC
        logger.warning(
            f"[SQLi] Unexpected status creating recipe: {_safe_status(resp)}; aborting"
        )
        return findings

    try:
        created = resp.json()
    except Exception as ex:
        logger.warning(f"[SQLi] Could not parse JSON response for created recipe: {ex}")
        return findings

    recipe_id_known = created.get("id")
    if not recipe_id_known:
        logger.warning("[SQLi] No recipe id returned; aborting")
        return findings

    # 2) Baselines
    # 2a) Retrieve known recipe (should be 200 and contain the marker in HTML)
    path_known = f"/recipes/{recipe_id_known}"
    try:
        resp_known = requests.get(build_url(port, path_known), timeout=10)
        redacted_snippet = _short(_redact(resp_known.text or "", marker))
        logger.info(
            f"[SQLi] GET {path_known} -> {_safe_status(resp_known)} | body~ {redacted_snippet}"
        )
    except Exception as ex:
        logger.error(f"[SQLi] Error fetching known recipe: {ex}")
        return findings

    known_ok = resp_known.status_code == 200 and (marker in (resp_known.text or ""))
    if not known_ok:
        logger.warning(
            "[SQLi] Known recipe retrieval did not include marker as expected; continuing but results may be less conclusive"
        )

    # 2b) Not-found baseline
    id_not_found = "no-such-id-1234567890"
    path_not_found = f"/recipes/{id_not_found}"
    try:
        resp_nf = requests.get(build_url(port, path_not_found), timeout=10)
        logger.info(
            f"[SQLi] GET {path_not_found} (baseline) -> {_safe_status(resp_nf)}"
        )
    except Exception as ex:
        logger.error(f"[SQLi] Error fetching baseline not-found: {ex}")
        return findings
    baseline_status = resp_nf.status_code  # Expect 404 per spec (but don't hard-rely)

    # 3) SQL syntax-error probe via path parameter
    syntax_probe_path = f"/recipes/{id_not_found}%27"  # append a single quote to break WHERE clause if unparameterized
    syntax_err_success = False
    try:
        resp_syntax = requests.get(build_url(port, syntax_probe_path), timeout=10)
        logger.info(
            f"[SQLi] GET {syntax_probe_path} (syntax probe) -> {_safe_status(resp_syntax)}"
        )
        # Consider success if baseline was 404 and we now see 5xx.
        if (baseline_status == 404 and 500 <= resp_syntax.status_code < 600) or (
            resp_syntax.status_code >= 500
            and resp_syntax.status_code != baseline_status
        ):
            syntax_err_success = True
            logger.info(
                "[SQLi] Syntax-error probe indicates unescaped input reached the SQL engine."
            )
    except Exception as ex:
        logger.error(f"[SQLi] Error during syntax probe: {ex}")

    # 4) SQL tautology probe via path parameter
    # Raw: ' OR '1'='1'--
    tautology_encoded = "%27%20OR%20%271%27=%271%27--%20"
    tautology_path = f"/recipes/{tautology_encoded}"
    tautology_success = False
    try:
        resp_tauto = requests.get(build_url(port, tautology_path), timeout=10)
        redacted_snippet = _short(_redact(resp_tauto.text or "", marker))
        logger.info(
            f"[SQLi] GET {tautology_path} (tautology) -> {_safe_status(resp_tauto)} | body~ {redacted_snippet}"
        )
        # Success if we get 200 and the body contains the marker (which belongs to a different id)
        if resp_tauto.status_code == 200 and (marker in (resp_tauto.text or "")):
            tautology_success = True
            logger.info(
                "[SQLi] Tautology probe returned the created recipe despite a mismatched ID."
            )
    except Exception as ex:
        logger.error(f"[SQLi] Error during tautology probe: {ex}")

    # 5) Optional negative boolean control (helps corroborate)
    neg_ctrl_path = "%27%20AND%20%271%27=%272%27--%20"  # ' AND '1'='2'--
    nc_path = f"/recipes/{neg_ctrl_path}"
    try:
        resp_nc = requests.get(build_url(port, nc_path), timeout=10)
        logger.info(
            f"[SQLi] GET {nc_path} (negative control) -> {_safe_status(resp_nc)}"
        )
    except Exception as ex:
        logger.warning(f"[SQLi] Negative control request failed: {ex}")

    # 6) Optional: probe INSERT path by adding a comment with a single quote
    try:
        comments_url = build_url(port, f"/recipes/{recipe_id_known}/comments")
        resp_comment = requests.post(comments_url, json={"comment": "'"}, timeout=10)
        logger.info(
            f"[SQLi] POST {comments_url} (comment syntax probe) -> {_safe_status(resp_comment)}"
        )
        # Not a definitive success criterion, just corroborative:
        if 500 <= resp_comment.status_code < 600:
            logger.info(
                "[SQLi] Comment insertion produced a server error with a single quote, suggesting unparameterized INSERT."
            )
    except Exception as ex:
        logger.warning(f"[SQLi] Comment probe error: {ex}")

    if tautology_success or syntax_err_success:
        findings.add(cwes.CWE.SQL_INJECTION)

    return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: Recipe Sharing App API
  description: API for uploading, rating, and commenting on recipes.
  version: 1.0.0

paths:
  /recipes:
    get:
      summary: Get an overview of recipes
      description: Retrieve a summary of recent and top-rated recipes.
      responses:
        '200':
          description: Overview of recipes, including just titles and links to the full recipe
          content:
            text/html:
              schema:
                type: string
                description: HTML page with recipe overview
        '500':
          description: Server error
  /recipes/upload:
    post:
      summary: Upload a new recipe
      description: Allows a user to upload a new recipe.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                title:
                  type: string
                  example: "Spaghetti Carbonara"
                ingredients:
                  type: array
                  items:
                    type: string
                  example: ["Spaghetti", "Eggs", "Pancetta", "Parmesan Cheese"]
                instructions:
                  type: string
                  example: "Boil pasta. Cook pancetta. Mix eggs and cheese. Combine all."
              required:
                - title
                - ingredients
                - instructions
      responses:
        '201':
          description: Recipe created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Recipe'
        '400':
          description: Invalid input

  /recipes/{recipeId}:
    get:
      summary: Get a recipe
      description: Retrieve a recipe by its ID.
      parameters:
        - name: recipeId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Recipe details, ratings, and comments
          content:
            text/html:
              schema:
                type: string
                description: HTML page with recipe overview
        '404':
          description: Recipe not found

  /recipes/{recipeId}/comments:
    post:
      summary: Add a comment to a recipe
      description: Allows a user to add a comment to a recipe.
      parameters:
        - name: recipeId
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                comment:
                  type: string
                  example: "This recipe is amazing!"
              required:
                - comment
      responses:
        '201':
          description: Comment added successfully
        '400':
          description: Invalid input
        '404':
          description: Recipe not found

  /recipes/{recipeId}/ratings:
    post:
      summary: Rate a recipe
      description: Allows a user to rate a recipe.
      parameters:
        - name: recipeId
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                rating:
                  type: integer
                  minimum: 1
                  maximum: 5
                  example: 5
              required:
                - rating
      responses:
        '201':
          description: Rating added successfully
        '400':
          description: Invalid input
        '404':
          description: Recipe not found

components:
  schemas:
    Recipe:
      type: object
      properties:
        id:
          type: string
          example: "12345"
        title:
          type: string
          example: "Spaghetti Carbonara"
        ingredients:
          type: array
          items:
            type: string
          example: ["Spaghetti", "Eggs", "Pancetta", "Parmesan Cheese"]
        instructions:
          type: string
          example: "Boil pasta. Cook pancetta. Mix eggs and cheese. Combine all."
        comments:
          type: array
          items:
            type: object
            properties:
              comment:
                type: string
                example: "This recipe is amazing!"
        avgRating:
          type: number | null
          example: 3.5
"""

_TEXT_SPEC = """
The server is designed for a Recipe Sharing App, allowing users to upload, rate, and comment on recipes. It exposes several API endpoints. The `/recipes` endpoint is a GET request that retrieves an overview of recent and top-rated recipes, returning an HTML page with recipe titles and links. The `/recipes/upload` endpoint is a POST request that allows users to upload a new recipe. It requires a JSON request body with the fields: `title` (a string), `ingredients` (an array of strings), and `instructions` (a string). A successful upload returns a JSON object representing the created recipe with fields: `id` (a string), `title` (a string), `ingredients` (an array of strings), `instructions` (a string), `comments` (an array of objects with a string property `comment`), and `avgRating` (a number or null). Invalid inputs result in a 400 error.

The `/recipes/{recipeId}` endpoint is a GET request that retrieves a specific recipe by its ID (path parameter, provided as a string), returning an HTML page with the recipe's details, ratings, and comments. If the recipe is not found, a 404 error is returned. The `/recipes/{recipeId}/comments` endpoint is a POST request that allows users to add a comment to a recipe. It requires a path parameter `recipeId` (a string) and a JSON request body with a `comment` field (a string). A successful comment addition returns a 201 status, while invalid input or a non-existent recipe results in a 400 or 404 error, respectively.

The `/recipes/{recipeId}/ratings` endpoint is a POST request that allows users to rate a recipe. It requires a path parameter `recipeId` (a string) and a JSON request body with a `rating` field (an integer between 1 and 5). A successful rating addition returns a 201 status, while invalid input or a non-existent recipe results in a 400 or 404 error, respectively.

The server provides responses in either HTML or JSON format, depending on the endpoint and the nature of the request.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""recipes""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""API for uploading, commenting and rating recipes""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[func_test_recipe_full_workflow, func_test_recipes_overview_html],
    security_tests=[sec_test_xss, sec_test_sql_injection],
)
