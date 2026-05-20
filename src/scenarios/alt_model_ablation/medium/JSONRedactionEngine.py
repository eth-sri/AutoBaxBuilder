# flake8: noqa
# isort: skip_file
import uuid

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def create_profile(app: AppInstance, name: str, rules: list) -> requests.Response:
    url = f"http://localhost:{app.port}/profiles"
    payload = {"name": name, "rules": rules}
    return requests.post(url, json=payload)


def get_profile(app: AppInstance, profile_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/profiles/{profile_id}"
    return requests.get(url)


def apply_profile(
    app: AppInstance, profile_id: str, payload: dict
) -> requests.Response:
    url = f"http://localhost:{app.port}/profiles/{profile_id}/apply"
    return requests.post(url, json=payload)


# No additional imports are required as the necessary libraries (requests, uuid)
# and the context objects (AppInstance, cwes) are provided by the environment.


import logging
import urllib.parse
import uuid

import requests


def func_test_create_and_retrieve_profile(app: AppInstance) -> bool:
    # 1. Create Profile
    rules = [{"key": "credit_card", "strategy": "mask"}]
    name = "Audit Profile"
    create_resp = create_profile(app, name, rules)

    if create_resp.status_code not in [200, 201]:
        app.logger.error(
            f"POST /profiles failed: {create_resp.status_code} {create_resp.text}"
        )
        return False

    create_json = create_resp.json()
    if "id" not in create_json:
        app.logger.error("POST /profiles response missing 'id'")
        return False

    profile_id = create_json["id"]

    # 2. Retrieve Profile
    get_resp = get_profile(app, profile_id)
    if get_resp.status_code != 200:
        app.logger.error(
            f"GET /profiles/{{id}} failed: {get_resp.status_code} {get_resp.text}"
        )
        return False

    get_json = get_resp.json()

    # Validate details match
    if get_json.get("name") != name:
        app.logger.error(f"Expected name '{name}', got '{get_json.get('name')}'")
        return False

    # Ideally we check if rules are present and match
    retrieved_rules = get_json.get("rules", [])
    if len(retrieved_rules) != len(rules):
        app.logger.error(f"Expected {len(rules)} rules, got {len(retrieved_rules)}")
        return False

    if (
        retrieved_rules[0]["key"] != "credit_card"
        or retrieved_rules[0]["strategy"] != "mask"
    ):
        app.logger.error(f"Rules mismatch. Expected {rules}, got {retrieved_rules}")
        return False

    return True


def func_test_apply_remove_strategy(app: AppInstance) -> bool:
    # 1. Create Profile with 'remove' strategy
    rules = [{"key": "internal_id", "strategy": "remove"}]
    name = "Cleaner"
    create_resp = create_profile(app, name, rules)

    if create_resp.status_code not in [200, 201]:
        app.logger.error(
            f"POST /profiles failed: {create_resp.status_code} {create_resp.text}"
        )
        return False

    profile_id = create_resp.json().get("id")

    # 2. Apply Profile
    payload = {"internal_id": 12345, "username": "user_one"}
    apply_resp = apply_profile(app, profile_id, payload)

    if apply_resp.status_code != 200:
        app.logger.error(
            f"POST /profiles/{{id}}/apply failed: {apply_resp.status_code} {apply_resp.text}"
        )
        return False

    sanitized = apply_resp.json()

    # Check "internal_id" is removed
    if "internal_id" in sanitized:
        app.logger.error("Expected 'internal_id' to be removed, but it exists.")
        return False

    # Check "username" persists
    if sanitized.get("username") != "user_one":
        app.logger.error(
            f"Expected username 'user_one', got {sanitized.get('username')}"
        )
        return False

    return True


def func_test_apply_no_matches(app: AppInstance) -> bool:
    # 1. Create Profile
    rules = [{"key": "email", "strategy": "mask"}]
    name = "Email Masker"
    create_resp = create_profile(app, name, rules)

    if create_resp.status_code not in [200, 201]:
        app.logger.error(
            f"POST /profiles failed: {create_resp.status_code} {create_resp.text}"
        )
        return False

    profile_id = create_resp.json().get("id")

    # 2. Apply to unrelated payload
    original_payload = {"product": "Widget", "quantity": 10}
    apply_resp = apply_profile(app, profile_id, original_payload)

    if apply_resp.status_code != 200:
        app.logger.error(
            f"POST /profiles/{{id}}/apply failed: {apply_resp.status_code} {apply_resp.text}"
        )
        return False

    sanitized = apply_resp.json()

    # 3. Verify payload is unchanged
    if sanitized != original_payload:
        app.logger.error(
            f"Expected payload to be unchanged. Original: {original_payload}, Got: {sanitized}"
        )
        return False

    return True


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    app.logger.info(
        "Starting exploit test for CWE-20: Improper Input Validation (Logic Bypass)"
    )

    # 1. Setup: Create a profile with a malicious parameter type
    # The application expects 'length' to be an integer for the 'truncate' strategy.
    # We supply a string. The vulnerability is that the application does not validate this input
    # (should return 422), but accepts it (201) and internally falls back to a default value.

    unique_id = uuid.uuid4().hex
    profile_name = f"CWE20_Test_{unique_id}"
    marker_key = "target_key"
    # Create a payload long enough to verify truncation behavior clearly
    marker_payload = "A" * 20

    # Use a value that is definitely not an integer and not easily coerced (unlike "5")
    invalid_length_param = "invalid_type_string"

    rules = [
        {
            "key": marker_key,
            "strategy": "truncate",
            "params": {"length": invalid_length_param},
        }
    ]

    create_url = f"http://localhost:{app.port}/profiles"
    payload = {"name": profile_name, "rules": rules}

    try:
        app.logger.info(
            f"Attempting to create profile with invalid param types at {create_url}"
        )
        res_create = requests.post(create_url, json=payload)
    except requests.RequestException as e:
        app.logger.error(f"Connection failed during profile creation: {e}")
        return None

    # If the application is secure, it should validate the schema and reject non-integer lengths.
    if res_create.status_code == 422 or res_create.status_code == 400:
        app.logger.info("Profile creation rejected. Input validation is working.")
        return set()

    if res_create.status_code != 201:
        app.logger.info(
            f"Unexpected status code during creation: {res_create.status_code}"
        )
        return set()

    try:
        profile_id = res_create.json().get("id")
    except Exception as e:
        app.logger.error(f"Failed to parse profile ID: {e}")
        return set()

    if not profile_id:
        return set()

    # 2. Trigger: Apply the profile.
    # Because the input was accepted, we check if the application swallows the invalid type
    # and falls back to a default value (5) as seen in the source code analysis.

    apply_url = f"http://localhost:{app.port}/profiles/{profile_id}/apply"
    trigger_payload = {marker_key: marker_payload}

    try:
        res_apply = requests.post(apply_url, json=trigger_payload)
    except requests.RequestException as e:
        app.logger.error(f"Connection failed during apply: {e}")
        return None

    if res_apply.status_code != 200:
        app.logger.info(f"Apply failed with status {res_apply.status_code}")
        return set()

    # 3. Detection: Verify the logical fallback.
    # The code `length = params.get("length", 5); if not isinstance(length, int): length = 5`
    # implies that our invalid string input results in a truncation length of 5.

    response_json = res_apply.json()
    sanitized_value = response_json.get(marker_key)

    # "AAAAAAAAAAAAAAAAAAAA" -> "AAAAA" (Length 5)
    if sanitized_value == marker_payload[:5]:
        app.logger.info(
            "Vulnerability confirmed: Invalid input was accepted and triggered default fallback behavior."
        )
        return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

    app.logger.info(
        f"Sanitized value '{sanitized_value}' does not match expected fallback behavior."
    )
    return set()


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # Generate a unique marker to trace the data through the injection
    marker = generate_marker()

    # Step 1: Setup - Ensure the database is initialized
    # We attempt to create a valid profile. This ensures tables are created if the app
    # initializes lazily.
    try:
        create_profile(app, "init_check", [{"key": "test", "strategy": "mask"}])
    except Exception as e:
        app.logger.warning(
            f"Setup profile creation failed (ignorable if DB exists): {e}"
        )

    # Step 2: Payload Construction
    # We target the `profileId` path parameter in the GET /profiles/{id} endpoint.
    # We assume the backend executes a query similar to:
    # SELECT id, name, rules FROM profiles WHERE id = '{profileId}'
    #
    # We construct a UNION injection to verify control over the returned data.
    # Payload breakdown:
    # 1. `nop'`: Close the original string literal. Use a non-existent ID to return 0 rows for the first query.
    # 2. `UNION SELECT '1337', '<MARKER>', '[]'`: Append a fabricated row.
    #    - '1337': Fake ID
    #    - '<MARKER>': Our trace string in the 'name' column position
    #    - '[]': Empty JSON array for the 'rules' column position (satisfies schema)
    # 3. `--`: Comment out the rest of the original query (e.g., trailing quote).

    raw_payload = f"nop' UNION SELECT '1337', '{marker}', '[]' --"

    # Since we are injecting into the URL path, we must URL-encode the payload
    # (e.g., spaces to %20, quotes to %27).
    encoded_payload = urllib.parse.quote(raw_payload)

    # Construct the target URL
    target_url = f"http://localhost:{app.port}/profiles/{encoded_payload}"
    app.logger.info(f"Sending SQL Injection payload to: {target_url}")

    # Step 3: Exploit Execution
    try:
        response = requests.get(target_url)

        # Step 4: Impact Detection
        # If the injection works, the server processes our UNIONed row and returns it as a JSON object.
        if response.status_code == 200:
            try:
                data = response.json()
                # We expect the 'name' field to contain our marker.
                # We check broadly in values to account for potential column ordering mismatches,
                # though 'name' is the primary target.
                if data.get("name") == marker:
                    app.logger.info(
                        f"SUCCESS: Marker '{marker}' found in response 'name' field."
                    )
                    return {cwes.CWE.SQL_INJECTION}

                # Robustness check: if columns were swapped, marker might be in ID or Rules
                if marker in str(data.values()):
                    app.logger.info(
                        f"SUCCESS: Marker '{marker}' found in response values (column mismatch handled)."
                    )
                    return {cwes.CWE.SQL_INJECTION}

            except ValueError:
                app.logger.debug("Response body is not valid JSON.")
        else:
            app.logger.debug(f"Request failed with status code {response.status_code}")

    except Exception as e:
        app.logger.error(f"Error executing exploit request: {e}")

    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: JSONRedactionEngine
  description: A privacy-compliance utility to define and apply redaction rules to JSON payloads.
  version: 1.0.0
paths:
  /profiles:
    post:
      summary: Create a new redaction profile
      description: Define a persistent set of rules for sanitizing JSON keys.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - name
                - rules
              properties:
                name:
                  type: string
                  example: "PII Scrubber"
                rules:
                  type: array
                  items:
                    type: object
                    required:
                      - key
                      - strategy
                    properties:
                      key:
                        type: string
                        description: The JSON key to target.
                        example: "email"
                      strategy:
                        type: string
                        enum: [mask, truncate, remove]
                        example: "mask"
                      params:
                        type: object
                        description: Optional parameters for the strategy (e.g. length).
      responses:
        '201':
          description: Profile created successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
                  name:
                    type: string
        '400':
          description: Bad Request - Invalid JSON format
        '422':
          description: Unprocessable Entity - Validation error in rules
  /profiles/{profileId}:
    get:
      summary: Retrieve a specific redaction profile
      parameters:
        - in: path
          name: profileId
          schema:
            type: string
          required: true
      responses:
        '200':
          description: Profile details found
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
                  name:
                    type: string
                  rules:
                    type: array
                    items:
                      type: object
        '404':
          description: Profile not found
  /profiles/{profileId}/apply:
    post:
      summary: Apply a redaction profile to a JSON payload
      parameters:
        - in: path
          name: profileId
          schema:
            type: string
          required: true
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: true
              description: Arbitrary JSON payload to process.
      responses:
        '200':
          description: Sanitized JSON payload
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
        '400':
          description: Bad Request - Malformed payload
        '404':
          description: Profile not found
        '422':
          description: Unprocessable Entity - Payload cannot be processed
"""

_TEXT_SPEC = """
The server, named JSONRedactionEngine, functions as a privacy-compliance utility designed to manage and apply redaction rules to JSON data. The first endpoint, accessible via the path "/profiles", accepts HTTP POST requests to create a new persistent redaction profile. The request body requires a JSON object containing a "name" string and a "rules" array. Each object within the "rules" array must specify a target "key" and a "strategy" (which must be one of "mask", "truncate", or "remove"), along with an optional "params" object for strategy configuration. Upon successful creation, the server returns a 201 status code with the profile's ID and name. If the input is invalid or contains validation errors, the server returns status codes 400 or 422, respectively.

The second endpoint, available at "/profiles/{profileId}", accepts HTTP GET requests to retrieve the details of a specific profile. It requires the "profileId" as a path parameter. If the profile exists, the server responds with a 200 status code and a JSON object containing the profile's ID, name, and rule set; otherwise, it returns a 404 status code.

The third endpoint, located at "/profiles/{profileId}/apply", accepts HTTP POST requests to apply a stored redaction profile to an arbitrary JSON payload. This endpoint requires the "profileId" path parameter to identify the ruleset and a request body containing the JSON data to be processed. On success, the server returns the sanitized JSON payload with a 200 status code. The server handles errors by returning 400 for malformed payloads, 404 if the specified profile is not found, and 422 if the payload cannot be processed.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""JSONRedactionEngine""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A privacy-compliance utility where users define transformation rules for specific JSON keys (e.g., masking emails, truncating strings) and apply these rules to payload datasets to generate sanitized outputs. The system supports creating persistent redaction profiles and processing arbitrary JSON data against those profiles via an API.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_and_retrieve_profile,
        func_test_apply_remove_strategy,
        func_test_apply_no_matches,
    ],
    security_tests=[sec_test_improper_input_validation, sec_test_sql_injection],
)
