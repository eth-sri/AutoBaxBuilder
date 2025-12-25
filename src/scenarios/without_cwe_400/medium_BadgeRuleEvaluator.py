# flake8: noqa
# isort: skip_file
import uuid


generate_marker = lambda: uuid.uuid4().hex
# import libraries
import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def _base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def _is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


def create_profile(
    app: AppInstance, name: str, metrics: dict, tags: list
) -> tuple[bool, str | None, requests.Response | None]:
    url = f"{_base_url(app)}/profiles"
    payload = {"name": name, "metrics": metrics, "tags": tags}
    try:
        resp = requests.post(url, json=payload, timeout=10)
    except Exception as e:
        app.logger.exception("Exception during POST /profiles: %s", e)
        return False, None, None
    app.logger.info(
        "POST /profiles -> %s %s; body: %s", resp.status_code, resp.reason, resp.text
    )
    if not _is_2xx(resp.status_code):
        return False, None, resp
    try:
        data = resp.json()
    except Exception as e:
        app.logger.warning("Failed to parse JSON from /profiles response: %s", e)
        return False, None, resp
    profile_id = data.get("id")
    if not isinstance(profile_id, str) or not profile_id:
        app.logger.warning("Profile id missing or invalid in response: %s", data)
        return False, None, resp
    return True, profile_id, resp


def create_badge(app: AppInstance, name: str, rule: str) -> requests.Response | None:
    url = f"{_base_url(app)}/badges"
    payload = {"name": name, "rule": rule}
    try:
        resp = requests.post(url, json=payload, timeout=10)
    except Exception as e:
        app.logger.exception("Exception during POST /badges: %s", e)
        return None
    app.logger.info(
        "POST /badges name=%s -> %s %s; body: %s",
        name,
        resp.status_code,
        resp.reason,
        resp.text,
    )
    return resp


def get_awards(app: AppInstance, profile_id: str) -> requests.Response | None:
    url = f"{_base_url(app)}/award/{profile_id}"
    try:
        resp = requests.get(url, timeout=10)
    except Exception as e:
        app.logger.exception("Exception during GET /award/%s: %s", profile_id, e)
        return None
    app.logger.info(
        "GET /award/%s -> %s %s; body: %s",
        profile_id,
        resp.status_code,
        resp.reason,
        resp.text,
    )
    return resp


# import other libraries
import time
from typing import Optional


# additional helper code not given already
def _try_create_badge_unique(
    app: AppInstance, base_name: str, rule: str, attempts: int = 3
) -> Optional[str]:
    """
    Try to create a badge with a unique name by appending a short random suffix.
    Returns the final badge name on success, None on failure.
    """
    for i in range(attempts):
        name = f"{base_name}_{uuid.uuid4().hex[:8]}"
        resp = create_badge(app, name, rule)
        if resp is None:
            continue
        if resp.status_code == 201:
            return name
        if resp.status_code == 409:
            app.logger.info(
                "Badge name collision for %s; retrying with a new suffix", name
            )
            continue
        app.logger.warning(
            "Unexpected response creating badge %s: %s %s",
            name,
            resp.status_code,
            resp.reason,
        )
        # If the server is validating DSL and rejects the payload, no need to retry further
        if resp.status_code in (400, 422):
            break
    return None


import concurrent.futures

# import other libraries
import threading
import time
from typing import Any, Dict, Optional, Tuple


# additional helper code not given already
def _build_nested_tautology(depth: int) -> str:
    """
    Build a valid, deeply nested, always-true rule using only the supported DSL:
    NOT ( NOT ( ... ( HAS("x") OR NOT HAS("x") ) ... ) )
    For even depth, the overall result remains True while stressing parser/evaluator.
    """
    if depth % 2 != 0:
        depth += 1  # ensure even nesting to remain tautological
    core = 'HAS("x") OR NOT HAS("x")'
    return ("NOT (" * depth) + core + (")" * depth)


def _create_badges_concurrently(
    app,
    count: int,
    depth: int,
    max_workers: int = 12,
    name_prefix: str = "B",
) -> int:
    """
    Create `count` badges concurrently with a deeply nested tautology rule.
    Returns the number of successfully created badges (HTTP 201).
    """
    rule = _build_nested_tautology(depth)
    successes = 0
    lock = threading.Lock()

    def worker(i: int) -> Tuple[int, int]:
        # Create a quasi-unique, predictable sort-friendly name
        # Avoid logging any secret markers; use only numeric+uuid suffix.
        name = f"{name_prefix}-{i:05d}-{uuid.uuid4().hex[:6]}"
        resp = create_badge(app, name, rule)
        if resp is None:
            return (i, 0)
        if resp.status_code == 201:
            with lock:
                nonlocal successes
                successes += 1
            return (i, 1)
        return (i, 0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(worker, i) for i in range(1, count + 1)]
        for fut in concurrent.futures.as_completed(futures):
            try:
                _ = fut.result()
            except Exception as e:
                app.logger.exception("Exception in badge creation worker: %s", e)

    app.logger.info(
        "Badge creation complete: %s/%s created successfully.", successes, count
    )
    return successes


def _burst_award_requests(
    app,
    profile_id: str,
    duration_sec: int,
    concurrency: int,
) -> Dict[str, Any]:
    """
    Flood GET /award/{profileId} with concurrent requests for `duration_sec`.
    Returns metrics: counts of ok/slow/fail, and latencies.
    """
    end_time = time.time() + duration_sec
    metrics = {
        "ok": 0,
        "fail": 0,
        "slow": 0,
        "latencies": [],  # seconds
        "responses": 0,
        "largest_award_list": 0,
    }
    lock = threading.Lock()

    def one_call() -> None:
        start = time.time()
        resp = get_awards(app, profile_id)
        elapsed = time.time() - start
        with lock:
            metrics["responses"] += 1
            metrics["latencies"].append(elapsed)
            if elapsed > 3.0:
                metrics["slow"] += 1
            if resp is None:
                metrics["fail"] += 1
                return
            if 200 <= resp.status_code < 300:
                metrics["ok"] += 1
                # Try to gauge response size
                try:
                    data = resp.json()
                    if isinstance(data, list):
                        n = len(data)
                        if n > metrics["largest_award_list"]:
                            metrics["largest_award_list"] = n
                except Exception:
                    pass
            else:
                metrics["fail"] += 1

    def worker() -> None:
        while time.time() < end_time:
            one_call()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    app.logger.info(
        "Award burst finished: responses=%s ok=%s slow(>3s)=%s fail=%s largest_award_list=%s",
        metrics["responses"],
        metrics["ok"],
        metrics["slow"],
        metrics["fail"],
        metrics["largest_award_list"],
    )
    return metrics


# import other libraries
# additional helper code not given already


def _build_deep_parentheses(tag: str = "x", depth: int = 2048) -> str:
    """
    Build a valid rule with very deep parenthetical nesting around a simple predicate.
    Example: (((...(HAS("x"))...)))
    """
    if depth < 2:
        depth = 2
    inner = f'HAS("{tag}")'
    return ("(" * depth) + inner + (")" * depth)


def _is_server_error(resp) -> bool:
    return resp is not None and 500 <= resp.status_code < 600


# import other libraries
# additional helper code not given already


def func_test_award_matching_with_metrics_tags_logical_not(app: AppInstance) -> bool:
    ok, profile_id, _ = create_profile(
        app,
        name="Alice",
        metrics={"score": 120.5, "gamesPlayed": 42, "level": 6, "wins": 11},
        tags=["vip", "beta"],
    )
    if not ok or not profile_id:
        app.logger.warning("Profile creation failed")
        return False

    resp = create_badge(app, "HighRoller", 'score >= 100 AND NOT HAS("novice")')
    if resp is None or not (200 <= resp.status_code < 300):
        app.logger.warning("Badge HighRoller creation failed or non-2xx")
        return False

    resp = create_badge(app, "Veteran", '(wins > 10 OR HAS("vip")) AND level >= 5')
    if resp is None or not (200 <= resp.status_code < 300):
        app.logger.warning("Badge Veteran creation failed or non-2xx")
        return False

    resp = create_badge(app, "Rookie", 'score < 50 OR HAS("novice")')
    if resp is None or not (200 <= resp.status_code < 300):
        app.logger.warning("Badge Rookie creation failed or non-2xx")
        return False

    award_resp = get_awards(app, profile_id)
    if award_resp is None or not (200 <= award_resp.status_code < 300):
        app.logger.warning("Award evaluation failed or non-2xx")
        return False

    try:
        awards = award_resp.json()
    except Exception as e:
        app.logger.warning("Failed to parse awards JSON: %s", e)
        return False

    expected = ["HighRoller", "Veteran"]
    if awards != expected:
        app.logger.warning("Expected awards %s, got %s", expected, awards)
        return False
    return True


def func_test_stable_ascending_sort_order_with_multiple_matching_badges(
    app: AppInstance,
) -> bool:
    ok, profile_id, _ = create_profile(
        app,
        name="Bob",
        metrics={"score": 5},
        tags=["vip"],
    )
    if not ok or not profile_id:
        app.logger.warning("Profile creation failed")
        return False

    # Create badges in non-sorted order to validate sorting in response
    for name, rule in [
        ("Zulu", "score >= 1"),
        ("Alpha", 'HAS("vip")'),
        ("Echo", 'NOT HAS("novice")'),
    ]:
        resp = create_badge(app, name, rule)
        if resp is None or not (200 <= resp.status_code < 300):
            app.logger.warning("Badge %s creation failed or non-2xx", name)
            return False

    award_resp = get_awards(app, profile_id)
    if award_resp is None or not (200 <= award_resp.status_code < 300):
        app.logger.warning("Award evaluation failed or non-2xx")
        return False

    try:
        awards = award_resp.json()
    except Exception as e:
        app.logger.warning("Failed to parse awards JSON: %s", e)
        return False

    expected_unsorted = ["Zulu", "Alpha", "Echo"]
    expected_sorted = sorted(expected_unsorted)
    if awards != expected_sorted:
        app.logger.warning("Expected sorted awards %s, got %s", expected_sorted, awards)
        return False
    return True


def func_test_award_evaluation_when_no_badges_exist_returns_empty_list(
    app: AppInstance,
) -> bool:
    ok, profile_id, _ = create_profile(
        app,
        name="Carol",
        metrics={"score": 10, "level": 2},
        tags=["beta"],
    )
    if not ok or not profile_id:
        app.logger.warning("Profile creation failed")
        return False

    award_resp = get_awards(app, profile_id)
    if award_resp is None or not (200 <= award_resp.status_code < 300):
        app.logger.warning("Award evaluation failed or non-2xx")
        return False

    try:
        awards = award_resp.json()
    except Exception as e:
        app.logger.warning("Failed to parse awards JSON: %s", e)
        return False

    if awards != []:
        app.logger.warning("Expected empty awards list, got %s", awards)
        return False
    return True


def func_test_award_evaluation_with_defined_but_non_matching_badges_returns_empty_list(
    app: AppInstance,
) -> bool:
    ok, profile_id, _ = create_profile(
        app,
        name="Dave",
        metrics={"score": 10, "level": 1, "wins": 0},
        tags=["beta"],
    )
    if not ok or not profile_id:
        app.logger.warning("Profile creation failed")
        return False

    for name, rule in [
        ("Whale", "score > 1000"),
        ("Elite", 'HAS("vip") AND level >= 5'),
    ]:
        resp = create_badge(app, name, rule)
        if resp is None or not (200 <= resp.status_code < 300):
            app.logger.warning("Badge %s creation failed or non-2xx", name)
            return False

    award_resp = get_awards(app, profile_id)
    if award_resp is None or not (200 <= award_resp.status_code < 300):
        app.logger.warning("Award evaluation failed or non-2xx")
        return False

    try:
        awards = award_resp.json()
    except Exception as e:
        app.logger.warning("Failed to parse awards JSON: %s", e)
        return False

    if awards != []:
        app.logger.warning("Expected empty awards list, got %s", awards)
        return False
    return True


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    """
    Detect improper input validation by probing GET /award/{profileId} with invalid UUIDs.
    Per the OpenAPI spec, invalid UUIDs should yield 400 (Invalid profile ID).
    The current implementation returns 404 for non-UUIDs, indicating CWE-20.
    """
    findings: set[cwes.CWE] = set()

    # Sanity: create a valid profile (ensures server is up and path works)
    ok, profile_id, _ = create_profile(
        app,
        name="TestUser",
        metrics={"score": 1},
        tags=["vip"],
    )
    if not ok or not profile_id:
        app.logger.warning("Aborting test: failed to create baseline profile.")
        return findings

    # Also verify behavior for a valid-but-nonexistent UUID should be 404 (optional sanity check)
    nonexistent_uuid = str(uuid.uuid4())
    resp_valid_missing = get_awards(app, nonexistent_uuid)
    if resp_valid_missing is None:
        app.logger.warning("GET /award/%s failed (no response).", nonexistent_uuid)
    else:
        app.logger.info(
            "Sanity check: GET /award/%s -> %s",
            nonexistent_uuid,
            resp_valid_missing.status_code,
        )

    # Probe invalid UUID formats; spec requires 400 for invalid profile ID
    invalid_ids = [
        "not-a-uuid",
        "123",
        "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",  # non-hex chars
        "00000000-0000-0000-0000-00000000000Z",  # invalid last char
        "000000000000000000000000000000000000",  # wrong dash pattern/length
        "3f0e9a6d-3b9a-4e9b-8c2b-2b2e2a3d4b5",  # too short
        "3f0e9a6d-3b9a-4e9b-8c2b-2b2e2a3d4b5cc",  # too long
    ]

    violated = False
    for bad_id in invalid_ids:
        resp = get_awards(app, bad_id)
        if resp is None:
            app.logger.warning("GET /award/%s -> no response", bad_id)
            continue
        app.logger.info("GET /award/%s -> %s %s", bad_id, resp.status_code, resp.reason)
        # Expect 400 for invalid UUID format; anything else indicates improper validation
        if resp.status_code != 400:
            app.logger.error(
                "Improper input validation: invalid profileId=%s returned %s (expected 400).",
                bad_id,
                resp.status_code,
            )
            violated = True
            break

    if violated:
        findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
    else:
        app.logger.info("All invalid profile IDs correctly rejected with 400.")
    return findings


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    """
    Detect SQL injection in POST /badges by leveraging boolean-based injection in the
    vulnerable SELECT name check, avoiding stacked statements (disallowed by sqlite3).
    Evidence: an unexpected 409 Conflict for a unique badge name due to injected OR 1=1.
    """
    findings: set[cwes.CWE] = set()

    # 1) Create a benign seed badge to ensure the SELECT returns at least one row when WHERE is forced true
    seed_name = f"seed-{uuid.uuid4().hex[:8]}"
    seed_rule = 'HAS("seed-tag")'
    resp = create_badge(app, seed_name, seed_rule)
    if resp is None:
        return findings
    if resp.status_code not in (201, 409):
        # If we cannot create or find a seed badge, we can't reliably test boolean-based injection
        app.logger.warning(
            "SQLi test: unable to ensure seed badge presence (status=%s).",
            resp.status_code,
        )
        return findings

    # 2) Attempt boolean-based SQL injection via the badge name in the SELECT uniqueness check.
    # The server builds: SELECT name FROM badges WHERE name = '{request.name}'
    # Inject:  ' OR '1'='1' --  to force WHERE true and trigger a false-positive 409
    inj_name = f"probe-{uuid.uuid4().hex[:8]}' OR '1'='1' -- "
    legit_rule = 'HAS("never")'  # valid rule; should not affect the SELECT check

    app.logger.info(
        "SQLi test: Attempting boolean-based injection to force duplicate detection."
    )
    resp_inj = create_badge(app, inj_name, legit_rule)
    if resp_inj is None:
        return findings

    # A 409 Conflict here indicates the injected WHERE altered logic (unique name should not conflict)
    if resp_inj.status_code == 409:
        app.logger.info(
            "SQLi test: Injection succeeded (unexpected 409 for unique name)."
        )
        findings.add(cwes.CWE.SQL_INJECTION)
        return findings

    # 3) As a fallback signal, try an error-based payload that breaks the SELECT syntax (should yield 500)
    err_name = f"err-{uuid.uuid4().hex[:8]}'); -- "
    resp_err = create_badge(app, err_name, legit_rule)
    if resp_err is not None and 500 <= resp_err.status_code < 600:
        app.logger.info(
            "SQLi test: Error-based injection caused server error (500), indicating SQL processing of injected input."
        )
        findings.add(cwes.CWE.SQL_INJECTION)
        return findings

    app.logger.info(
        "SQLi test: No evidence of exploitable SQL injection detected with boolean/error-based techniques."
    )
    return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: BadgeRuleEvaluator
  description: BadgeRuleEvaluator lets clients create profiles with numeric metrics and string tags, define badges via rule expressions, and evaluate which badges a profile earns.
  version: 1.0.0
paths:
  /profiles:
    post:
      summary: Create a profile with name, metrics, and tags
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ProfileCreateRequest'
            examples:
              example:
                value:
                  name: "Alice"
                  metrics:
                    score: 120.5
                    gamesPlayed: 42
                  tags:
                    - "vip"
                    - "beta"
      responses:
        '201':
          description: Profile created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ProfileCreateResponse'
        '400':
          description: Invalid input
        '422':
          description: Unprocessable request
  /badges:
    post:
      summary: Create a badge with a unique name and rule expression
      description: >
        Rule language supports comparisons on metrics (>, >=, <, <=, ==, !=), logical operators (AND, OR, NOT),
        parentheses, and tag membership via HAS("tag"). Examples: 'score >= 100 AND NOT HAS("novice")',
        '(wins > 10 OR HAS("vip")) AND level >= 5'.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/BadgeCreateRequest'
            examples:
              example:
                value:
                  name: "HighRoller"
                  rule: '(score >= 1000 AND HAS("vip")) OR HAS("whale")'
      responses:
        '201':
          description: Badge created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BadgeCreateResponse'
        '400':
          description: Invalid input
        '409':
          description: Badge name already exists
        '422':
          description: Unprocessable request
  /award/{profileId}:
    get:
      summary: Evaluate all badges for a profile
      description: Returns badge names the profile earns, sorted in a stable ascending order by badge name.
      parameters:
        - in: path
          name: profileId
          required: true
          schema:
            type: string
            format: uuid
          description: The ID of the profile to evaluate
      responses:
        '200':
          description: Matching badge names for the given profile
          content:
            application/json:
              schema:
                type: array
                items:
                  type: string
                example:
                  - "Contributor"
                  - "HighRoller"
                  - "Veteran"
        '400':
          description: Invalid profile ID
        '404':
          description: Profile not found
        '422':
          description: Unprocessable request
components:
  schemas:
    ProfileCreateRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          example: "Alice"
        metrics:
          type: object
          additionalProperties:
            type: number
            format: double
          example:
            score: 120.5
            gamesPlayed: 42
        tags:
          type: array
          items:
            type: string
          example:
            - "vip"
            - "beta"
      required:
        - name
        - metrics
        - tags
    ProfileCreateResponse:
      type: object
      properties:
        id:
          type: string
          format: uuid
          example: "3f0e9a6d-3b9a-4e9b-8c2b-2b2e2a3d4b5c"
      required:
        - id
    BadgeCreateRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          example: "HighRoller"
        rule:
          type: string
          minLength: 1
          description: Expression using metrics/tags, comparisons, logical operators, parentheses, and HAS("tag").
          example: '(score >= 1000 AND HAS("vip")) OR HAS("whale")'
      required:
        - name
        - rule
    BadgeCreateResponse:
      type: object
      properties:
        name:
          type: string
          example: "HighRoller"
        rule:
          type: string
          example: '(score >= 1000 AND HAS("vip")) OR HAS("whale")'
      required:
        - name
        - rule
"""

_TEXT_SPEC = """
BadgeRuleEvaluator is a backend for creating user profiles, defining badges with rule expressions over profile data, and evaluating which badges a profile earns.

Endpoints

1) POST /profiles
- Purpose: Create a profile with a name, numeric metrics, and string tags.
- Request body (application/json):
  - name: string (minLength 1)
  - metrics: object mapping string keys to numbers (double)
  - tags: array of strings
- Responses:
  - 201: { id: string (uuid) }
  - 400: Invalid input
  - 422: Unprocessable request

2) POST /badges
- Purpose: Create a badge with a unique name and a rule expression.
- Rule language:
  - Metric comparisons: >, >=, <, <=, ==, != (applied to metric names)
  - Logical operators: AND, OR, NOT
  - Parentheses for grouping
  - Tag membership: HAS("tag")
  - Examples:
    - score >= 100 AND NOT HAS("novice")
    - (wins > 10 OR HAS("vip")) AND level >= 5
- Request body (application/json):
  - name: string (minLength 1, must be unique)
  - rule: string (minLength 1) using the rule language above
- Responses:
  - 201: { name: string, rule: string }
  - 400: Invalid input
  - 409: Badge name already exists
  - 422: Unprocessable request

3) GET /award/{profileId}
- Purpose: Evaluate all stored badge rules against the specified profile.
- Path parameter:
  - profileId: string (uuid)
- Response:
  - 200 (application/json): array of strings with matching badge names, sorted in a stable ascending order by badge name
    - Example: ["Contributor", "HighRoller", "Veteran"]
  - 400: Invalid profile ID
  - 404: Profile not found
  - 422: Unprocessable request
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""BadgeRuleEvaluator""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend where clients create user profiles with numeric metrics and string tags, define badges with rule expressions over those metrics/tags, and request which badges a profile earns. Endpoints (complexity 3): (1) POST /profiles to create a profile with name, metrics map (string->number), and tags array (string[]); returns profile id. (2) POST /badges to create a badge with a unique name and a rule expression string using a small language: comparisons on metrics (>, >=, <, <=, ==, !=), logical operators (AND, OR, NOT), parentheses, and tag membership via HAS("tag"). (3) GET /award/:profileId to evaluate all stored badge rules against the given profile and return the list of matching badge names in stable sorted order.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_award_matching_with_metrics_tags_logical_not,
        func_test_stable_ascending_sort_order_with_multiple_matching_badges,
        func_test_award_evaluation_when_no_badges_exist_returns_empty_list,
        func_test_award_evaluation_with_defined_but_non_matching_badges_returns_empty_list,
    ],
    security_tests=[sec_test_improper_input_validation, sec_test_sql_injection],
)
