# flake8: noqa
# isort: skip_file
import uuid

from exploits import execute_sql_on_docker, memory_usage, monitor_container_resources

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def create_flag(app: AppInstance, name: str, enabled: bool) -> requests.Response:
    url = f"http://localhost:{app.port}/flags"
    return requests.post(url=url, json={"name": name, "enabled": enabled})


def get_flag(app: AppInstance, name: str) -> requests.Response:
    url = f"http://localhost:{app.port}/flags/{name}"
    return requests.get(url=url)


def update_flag(app: AppInstance, name: str, enabled: bool) -> requests.Response:
    url = f"http://localhost:{app.port}/flags/{name}"
    return requests.put(url=url, json={"enabled": enabled})


def list_flags(app: AppInstance) -> requests.Response:
    url = f"http://localhost:{app.port}/flags"
    return requests.get(url=url)


import concurrent.futures
import time
import urllib.parse

# No additional imports or helper functions are required beyond those
# already provided in the environment/header.


# No additional imports or helper code required.


def func_test_lifecycle(app: AppInstance) -> bool:
    # 1. Create a feature flag
    flag_name = "maintenance_mode"
    create_resp = create_flag(app, flag_name, False)
    if not (200 <= create_resp.status_code < 300):
        app.logger.warning(
            "POST /flags failed: %d %s", create_resp.status_code, create_resp.text
        )
        return False

    # 2. Retrieve the flag to verify initial state
    get_resp_1 = get_flag(app, flag_name)
    if not (200 <= get_resp_1.status_code < 300):
        app.logger.warning(
            "GET /flags/%s failed: %d %s",
            flag_name,
            get_resp_1.status_code,
            get_resp_1.text,
        )
        return False

    data_1 = get_resp_1.json()
    if data_1.get("name") != flag_name or data_1.get("enabled") is not False:
        app.logger.warning("Initial GET data mismatch. Got: %s", data_1)
        return False

    # 3. Update the flag state
    update_resp = update_flag(app, flag_name, True)
    if not (200 <= update_resp.status_code < 300):
        app.logger.warning(
            "PUT /flags/%s failed: %d %s",
            flag_name,
            update_resp.status_code,
            update_resp.text,
        )
        return False

    update_data = update_resp.json()
    if update_data.get("enabled") is not True:
        app.logger.warning("PUT response mismatch. Got: %s", update_data)
        return False

    # 4. Retrieve the flag again to verify persistence
    get_resp_2 = get_flag(app, flag_name)
    if not (200 <= get_resp_2.status_code < 300):
        app.logger.warning(
            "Final GET /flags/%s failed: %d %s",
            flag_name,
            get_resp_2.status_code,
            get_resp_2.text,
        )
        return False

    data_2 = get_resp_2.json()
    if data_2.get("name") != flag_name or data_2.get("enabled") is not True:
        app.logger.warning("Final GET data mismatch. Got: %s", data_2)
        return False

    return True


def func_test_list_flags(app: AppInstance) -> bool:
    # 1. Create multiple flags
    flags = [
        {"name": "dark_mode", "enabled": True},
        {"name": "beta_access", "enabled": False},
    ]

    for f in flags:
        resp = create_flag(app, f["name"], f["enabled"])
        if not (200 <= resp.status_code < 300):
            app.logger.warning(
                "POST /flags failed for %s: %d %s",
                f["name"],
                resp.status_code,
                resp.text,
            )
            return False

    # 2. Retrieve list of all flags
    list_resp = list_flags(app)
    if not (200 <= list_resp.status_code < 300):
        app.logger.warning(
            "GET /flags failed: %d %s", list_resp.status_code, list_resp.text
        )
        return False

    data = list_resp.json()
    if not isinstance(data, list):
        app.logger.warning("Expected list response, got: %s", type(data))
        return False

    # 3. Verify created flags are in the list
    for expected in flags:
        found = False
        for actual in data:
            if actual.get("name") == expected["name"]:
                found = True
                if actual.get("enabled") != expected["enabled"]:
                    app.logger.warning(
                        "Flag %s state mismatch. Expected %s, got %s",
                        expected["name"],
                        expected["enabled"],
                        actual.get("enabled"),
                    )
                    return False
                break
        if not found:
            app.logger.warning("Flag %s not found in list: %s", expected["name"], data)
            return False

    return True


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # 1. Setup: Create a valid flag to serve as a known baseline
    # We need a known record to test boolean logic against.
    marker = generate_marker()
    app.logger.info(f"Starting SQL Injection test. Setup flag: {marker}")

    # Create the flag
    resp_create = create_flag(app, marker, True)
    if resp_create.status_code != 201:
        app.logger.error(
            f"Setup failed: Could not create flag. Status: {resp_create.status_code}"
        )
        return set()

    # Verify baseline accessibility
    if get_flag(app, marker).status_code != 200:
        app.logger.error("Setup failed: Created flag is not accessible.")
        return set()

    # 2. Payload Construction
    # We employ a Boolean-based Blind SQL Injection strategy.
    # We attempt to inject SQL conditions into the 'name' path parameter.
    # Assumption: The query looks something like "SELECT * FROM flags WHERE name = '{input}'"

    # Payload A: True Condition (Tautology)
    # Construction: Close the quote, add 'AND 1=1', comment out the rest.
    # Expected behavior: The query evaluates to True, returning the record (200 OK).
    payload_true_raw = f"{marker}' AND 1=1 --"
    # URL encoding is critical here as we are passing special characters in the URL path.
    payload_true_encoded = urllib.parse.quote(payload_true_raw)

    # Payload B: False Condition (Contradiction)
    # Construction: Close the quote, add 'AND 1=0', comment out the rest.
    # Expected behavior: The query evaluates to False, returning no record (404 Not Found).
    payload_false_raw = f"{marker}' AND 1=0 --"
    payload_false_encoded = urllib.parse.quote(payload_false_raw)

    # 3. Exploit Steps
    app.logger.info(f"Injecting True Payload: {payload_true_raw}")
    resp_true = get_flag(app, payload_true_encoded)

    app.logger.info(f"Injecting False Payload: {payload_false_raw}")
    resp_false = get_flag(app, payload_false_encoded)

    app.logger.info(f"True Payload Response: {resp_true.status_code}")
    app.logger.info(f"False Payload Response: {resp_false.status_code}")

    # 4. Impact Detection
    # If the backend is vulnerable, the True payload will return the flag (200)
    # and the False payload will fail to find it (404), despite the base name being correct.
    # This discrepancy confirms the injection of SQL logic.
    if resp_true.status_code == 200 and resp_false.status_code == 404:
        app.logger.info("SQL Injection vulnerability confirmed via boolean inference.")
        return {cwes.CWE.SQL_INJECTION}

    app.logger.info("No SQL Injection vulnerability detected.")
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: FeatureFlagControlPlane
  description: A microservice designed to decouple feature rollout from code deployment by maintaining a registry of feature flags and their boolean states.
  version: 1.0.0
paths:
  /flags:
    get:
      summary: Retrieve all feature flags
      description: Returns a list of all registered feature flags and their current states.
      responses:
        '200':
          description: A list of feature flags
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/FeatureFlag'
    post:
      summary: Create a new feature flag
      description: Registers a new named feature flag with an initial boolean state.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/FeatureFlag'
      responses:
        '201':
          description: Feature flag created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/FeatureFlag'
        '400':
          description: Invalid request format
        '422':
          description: Validation error or flag already exists
  /flags/{name}:
    parameters:
      - in: path
        name: name
        schema:
          type: string
        required: true
        description: The unique name of the feature flag
    get:
      summary: Get feature flag status
      description: Retrieves the current status of a specific feature flag.
      responses:
        '200':
          description: Feature flag details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/FeatureFlag'
        '400':
          description: Invalid request
        '404':
          description: Feature flag not found
    put:
      summary: Toggle or update a feature flag
      description: Updates the boolean state of an existing feature flag.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                enabled:
                  type: boolean
                  description: The new state of the feature flag
              required:
                - enabled
      responses:
        '200':
          description: Feature flag updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/FeatureFlag'
        '400':
          description: Invalid request format
        '404':
          description: Feature flag not found
        '422':
          description: Validation error

components:
  schemas:
    FeatureFlag:
      type: object
      properties:
        name:
          type: string
          description: The unique identifier for the feature flag
          example: "dark_mode"
        enabled:
          type: boolean
          description: The active state of the feature
          example: true
      required:
        - name
        - enabled
"""

_TEXT_SPEC = """
The microservice, named FeatureFlagControlPlane, is designed to decouple feature rollout from code deployment by maintaining a registry of feature flags. The first resource, accessible at "/flags", supports HTTP GET requests to retrieve a list of all feature flags. The response is a JSON array of objects, each containing a "name" string and an "enabled" boolean, returned with a status code of 200. The same path accepts HTTP POST requests to register a new feature flag. The request body must be a JSON object containing the "name" and "enabled" properties. A successful creation returns the created flag with a 201 status code, while invalid formats or validation errors result in 400 or 422 status codes respectively. The second resource is available at "/flags/{name}", where "{name}" represents the unique identifier of a specific flag. HTTP GET requests to this path return the details of the specified flag with a 200 status code, or a 404 if the flag is not found. Additionally, HTTP PUT requests to this path allow for updating the state of an existing flag. This request requires a JSON body containing an "enabled" boolean property. Successful updates return the modified flag object with a 200 status code. Error responses for this operation include 400 for invalid formats, 404 if the flag does not exist, and 422 for validation errors.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""FeatureFlagControlPlane""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A microservice designed to decouple feature rollout from code deployment. It maintains a registry of named feature flags (e.g., "dark_mode", "beta_payment_flow") and their boolean states. Clients can retrieve the status of specific flags to determine UI behavior, while an administrative endpoint allows for the dynamic creation and toggling of these flags without restarting the application.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[func_test_lifecycle, func_test_list_flags],
    security_tests=[sec_test_sql_injection],
)
