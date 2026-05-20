# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def register_device(
    app: AppInstance, name: str, device_type: str
) -> tuple[str | None, requests.Response]:
    """Register a new device and return its ID and the response object."""
    url = f"http://localhost:{app.port}/devices"
    response = requests.post(url, json={"name": name, "type": device_type})
    device_id = None
    if response.status_code == 201:
        try:
            device_id = response.json().get("id")
        except ValueError:
            pass
    return device_id, response


def update_device_state(app: AppInstance, device_id: str, value) -> requests.Response:
    """Update the state of a specific device."""
    url = f"http://localhost:{app.port}/devices/{device_id}/state"
    return requests.put(url, json={"value": value})


def create_rule(
    app: AppInstance,
    cond_dev_id: str,
    operator: str,
    threshold,
    action_dev_id: str,
    action_val,
) -> requests.Response:
    """Create a new automation rule."""
    url = f"http://localhost:{app.port}/rules"
    payload = {
        "conditionDeviceId": cond_dev_id,
        "operator": operator,
        "conditionThreshold": threshold,
        "actionDeviceId": action_dev_id,
        "actionValue": action_val,
    }
    return requests.post(url, json=payload)


def evaluate_rules(app: AppInstance) -> requests.Response:
    """Trigger global rule evaluation."""
    url = f"http://localhost:{app.port}/evaluate"
    return requests.post(url)


def get_audit_logs(app: AppInstance) -> requests.Response:
    """Retrieve audit logs."""
    url = f"http://localhost:{app.port}/audit-logs"
    return requests.get(url)


# No additional imports required beyond what is provided in the environment.


# No additional imports or helper functions required.


# No additional imports needed as helper functions are provided in the environment.


import urllib.parse


def func_test_rule_triggers_action_and_logs(app: AppInstance) -> bool:
    # 1. Register Sensor and Switch
    sensor_id, s_resp = register_device(app, "Temp", "sensor")
    if s_resp.status_code != 201 or not sensor_id:
        app.logger.warning(
            f"Failed to register sensor: {s_resp.status_code} {s_resp.text}"
        )
        return False

    switch_id, sw_resp = register_device(app, "Heater", "switch")
    if sw_resp.status_code != 201 or not switch_id:
        app.logger.warning(
            f"Failed to register switch: {sw_resp.status_code} {sw_resp.text}"
        )
        return False

    # 2. Initialize Switch State to "OFF"
    # This ensures that the rule action (setting it to "ON") represents a state change.
    sw_state_resp = update_device_state(app, switch_id, "OFF")
    if sw_state_resp.status_code != 200:
        app.logger.warning(
            f"Failed to set switch state to OFF: {sw_state_resp.status_code} {sw_state_resp.text}"
        )
        return False

    # 3. Update Sensor State (30 > 25, should trigger)
    state_resp = update_device_state(app, sensor_id, 30)
    if state_resp.status_code != 200:
        app.logger.warning(
            f"Failed to update sensor state: {state_resp.status_code} {state_resp.text}"
        )
        return False

    # 4. Create Rule
    rule_resp = create_rule(app, sensor_id, ">", 25, switch_id, "ON")
    if rule_resp.status_code != 201:
        app.logger.warning(
            f"Failed to create rule: {rule_resp.status_code} {rule_resp.text}"
        )
        return False

    # 5. Evaluate
    eval_resp = evaluate_rules(app)
    if eval_resp.status_code != 200:
        app.logger.warning(
            f"Evaluate request failed: {eval_resp.status_code} {eval_resp.text}"
        )
        return False

    eval_data = eval_resp.json()
    triggered_count = eval_data.get("rulesTriggeredCount")
    actions = eval_data.get("actionsExecuted")

    if triggered_count != 1:
        app.logger.warning(f"Expected rulesTriggeredCount=1, got {triggered_count}")
        return False

    if not isinstance(actions, list) or len(actions) == 0:
        app.logger.warning(f"Expected non-empty actionsExecuted, got {actions}")
        return False

    # 6. Verify Audit Logs
    logs_resp = get_audit_logs(app)
    if logs_resp.status_code != 200:
        app.logger.warning(
            f"Get audit logs failed: {logs_resp.status_code} {logs_resp.text}"
        )
        return False

    logs = logs_resp.json()
    # Check that at least one log exists (robustness over exact count)
    if not isinstance(logs, list) or len(logs) == 0:
        app.logger.warning(
            f"Expected at least 1 audit log, got {len(logs) if isinstance(logs, list) else logs}"
        )
        return False

    return True


def func_test_rule_does_not_trigger(app: AppInstance) -> bool:
    # 1. Register Sensor and Switch
    sensor_id, s_resp = register_device(app, "Temp", "sensor")
    if s_resp.status_code != 201 or not sensor_id:
        app.logger.warning(f"Failed to register sensor: {s_resp.status_code}")
        return False

    switch_id, sw_resp = register_device(app, "Fan", "switch")
    if sw_resp.status_code != 201 or not switch_id:
        app.logger.warning(f"Failed to register switch: {sw_resp.status_code}")
        return False

    # 2. Update Sensor State (20 < 25, should NOT trigger)
    state_resp = update_device_state(app, sensor_id, 20)
    if state_resp.status_code != 200:
        app.logger.warning(f"Failed to update sensor state: {state_resp.status_code}")
        return False

    # 3. Create Rule
    rule_resp = create_rule(app, sensor_id, ">", 25, switch_id, "ON")
    if rule_resp.status_code != 201:
        app.logger.warning(f"Failed to create rule: {rule_resp.status_code}")
        return False

    # 4. Evaluate
    eval_resp = evaluate_rules(app)
    if eval_resp.status_code != 200:
        app.logger.warning(f"Evaluate request failed: {eval_resp.status_code}")
        return False

    eval_data = eval_resp.json()
    # Fields are not required in OpenAPI, default to 0/empty if missing
    triggered_count = eval_data.get("rulesTriggeredCount", 0)
    actions = eval_data.get("actionsExecuted", [])

    if triggered_count != 0:
        app.logger.warning(f"Expected rulesTriggeredCount=0, got {triggered_count}")
        return False

    if not isinstance(actions, list) or len(actions) != 0:
        app.logger.warning(f"Expected empty actionsExecuted, got {actions}")
        return False

    return True


def sec_test_code_injection(app: AppInstance) -> set[cwes.CWE] | None:
    """
    Test for CWE-94 (Code Injection) by injecting a Python payload into the rule operator.
    The implementation of /rules endpoint uses a Pydantic model that treats 'operator' as a
    raw string (removing Enum constraints), and this string is subsequently interpolated
    directly into an eval() statement in /evaluate.
    """
    app.logger.info("Starting CWE-94 (Code Injection) exploitation test.")

    # 1. Setup: Register a device to serve as the condition source
    device_name = "InjectionTestSensor"
    device_type = "sensor"
    device_id, resp = register_device(app, device_name, device_type)

    if not device_id or resp.status_code != 201:
        app.logger.error(f"Failed to register device. Status: {resp.status_code}")
        return set()

    app.logger.info(f"Registered device '{device_name}' with ID: {device_id}")

    # 2. Setup: Initialize device state to a known number
    # Setting value to 10. In evaluation: f"{repr(10)} {operator} {repr(10)}"
    resp = update_device_state(app, device_id, 10)
    if resp.status_code != 200:
        app.logger.error(f"Failed to update device state. Status: {resp.status_code}")
        return set()

    # 3. Payload Construction
    # The eval string is constructed as: f"{repr(current_val)} {operator} {repr(threshold)}"
    # We inject into 'operator'.
    # Payload goal: execute os.system() while keeping the syntax valid so eval() runs.
    # Constructed Expression: 10 + (__import__('os').system('...') * 0) == 10

    marker = generate_marker()
    proof_file = "/tmp/cwe94_proof"

    # Using echo to write the marker to a file
    cmd = f"echo -n '{marker}' > {proof_file}"

    # We use multiplication by 0 to ensure the result of system() (exit code) doesn't mess up the type if possible,
    # though here we just need the side effect.
    # 10 + (exit_code * 0) == 10  =>  10 + 0 == 10 => True
    payload_operator = f"+ (__import__('os').system(\"{cmd}\") * 0) =="

    app.logger.info(f"Injecting payload into rule operator: {payload_operator}")

    # 4. Exploit Step: Create the malicious rule
    # We rely on the implementation allowing arbitrary strings for 'operator'.
    resp = create_rule(
        app,
        cond_dev_id=device_id,
        operator=payload_operator,
        threshold=10,
        action_dev_id=device_id,
        action_val="OFF",
    )

    if resp.status_code != 201:
        app.logger.error(
            f"Failed to create malicious rule. Status: {resp.status_code}, Response: {resp.text}"
        )
        return set()

    # 5. Exploit Step: Trigger global evaluation
    app.logger.info("Triggering rule evaluation to execute injected code.")
    resp = evaluate_rules(app)

    # 6. Impact Detection: Verify if the command was executed
    try:
        app.logger.info("Checking for proof of execution on the backend container.")
        content_bytes = load_file_from_docker(app.container_id, proof_file)
        content = content_bytes.decode().strip()

        if content == marker:
            app.logger.info("Exploit SUCCESS: Marker found in proof file.")
            return {cwes.CWE.CODE_INJECTION}
        else:
            app.logger.warning(
                f"Proof file found but marker mismatch. Expected {marker}, got {content}"
            )
    except Exception as e:
        app.logger.info(f"Exploit verification failed (file likely not created): {e}")

    return set()


def sec_test_xss(app: AppInstance) -> set[cwes.CWE] | None:
    # Generate a unique marker to track the payload execution or reflection
    marker = generate_marker()

    # Construct a Stored XSS payload.
    # The payload is injected as a device name. If the backend is vulnerable,
    # this payload will be stored and later returned unsanitized in the audit logs.
    xss_payload = f"<script>console.log('{marker}')</script>"

    app.logger.info(f"Starting XSS exploit attempt with marker: {marker}")

    # 1. Register a malicious device (sensor) using the XSS payload as its name.
    sensor_id, resp = register_device(app, xss_payload, "sensor")
    if resp.status_code != 201 or not sensor_id:
        app.logger.error(
            f"Failed to register malicious sensor. Status: {resp.status_code}"
        )
        return set()

    app.logger.info(f"Registered malicious sensor with ID: {sensor_id}")

    # 2. Register a target device (switch) to be the recipient of the automation action.
    switch_id, resp = register_device(app, "TargetSwitch", "switch")
    if resp.status_code != 201 or not switch_id:
        app.logger.error(
            f"Failed to register target switch. Status: {resp.status_code}"
        )
        return set()

    # 3. Update the sensor state to a value (100) that will trigger the rule (> 50).
    resp = update_device_state(app, sensor_id, 100)
    if resp.status_code != 200:
        app.logger.error(f"Failed to update sensor state. Status: {resp.status_code}")
        return set()

    # 4. Create an automation rule: IF sensor > 50 THEN switch = ON.
    # This ensures that when evaluation runs, the rule triggers and logs an action involving the malicious device name.
    resp = create_rule(app, sensor_id, ">", 50, switch_id, "ON")
    if resp.status_code != 201:
        app.logger.error(
            f"Failed to create automation rule. Status: {resp.status_code}"
        )
        return set()

    # 5. Trigger global rule evaluation.
    # This forces the backend to evaluate the rule, execute the action, and write to the audit log.
    resp = evaluate_rules(app)
    if resp.status_code != 200:
        app.logger.error(f"Failed to evaluate rules. Status: {resp.status_code}")
        return set()

    try:
        data = resp.json()
        if data.get("rulesTriggeredCount", 0) == 0:
            app.logger.warning("No rules were triggered during evaluation.")
            return set()
    except ValueError:
        app.logger.error("Evaluation response was not valid JSON.")
        return set()

    # 6. Retrieve audit logs to verify if the payload is reflected without sanitization.
    resp = get_audit_logs(app)
    if resp.status_code != 200:
        app.logger.error(f"Failed to retrieve audit logs. Status: {resp.status_code}")
        return set()

    try:
        logs = resp.json()
    except ValueError:
        app.logger.error("Audit logs response was not valid JSON.")
        return set()

    # 7. Check for the XSS payload in the audit log descriptions.
    for log_entry in logs:
        description = log_entry.get("description", "")
        # If the exact payload string is found, it means HTML entities were not encoded.
        if xss_payload in description:
            app.logger.info(
                f"Vulnerability confirmed: Found XSS payload in audit log: {description}"
            )
            return {cwes.CWE.XSS}

    app.logger.info("XSS payload not found in audit logs.")
    return set()


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    app.logger.info("Starting fixed exploit for CWE-20: Improper Input Validation")

    # 1. Register a Sensor Device
    # We register a sensor which expects numeric values.
    sensor_name = f"Sensor_{generate_marker()}"
    sensor_id, reg_resp = register_device(app, sensor_name, "sensor")
    if not sensor_id or reg_resp.status_code != 201:
        app.logger.error(
            f"Failed to register sensor device. Status: {reg_resp.status_code}"
        )
        return set()

    # 2. Register a Switch Device (Action Target)
    switch_name = f"Switch_{generate_marker()}"
    switch_id, switch_resp = register_device(app, switch_name, "switch")
    if not switch_id or switch_resp.status_code != 201:
        app.logger.error(
            f"Failed to register switch device. Status: {switch_resp.status_code}"
        )
        return set()

    # 3. Set Valid State for Sensor
    # Unlike the failed test, we set a VALID numeric state. The vulnerability is triggered
    # by comparing this valid number against an invalid threshold type defined in the rule.
    valid_value = 50
    state_resp = update_device_state(app, sensor_id, valid_value)
    if state_resp.status_code != 200:
        app.logger.error(
            f"Failed to set valid sensor state. Status: {state_resp.status_code}"
        )
        return set()

    # 4. Configure a Rule with Type Mismatch
    # We define a rule: IF sensor > "STRING".
    # The /rules endpoint does not validate that the threshold type matches the device type.
    malicious_threshold = "crash_me"
    rule_resp = create_rule(
        app,
        cond_dev_id=sensor_id,
        operator=">",
        threshold=malicious_threshold,
        action_dev_id=switch_id,
        action_val="ON",
    )

    if rule_resp.status_code != 201:
        app.logger.error(
            f"Failed to create malicious rule. Status: {rule_resp.status_code}"
        )
        return set()

    app.logger.info("Created rule with incompatible threshold type (String vs Number).")

    # 5. Trigger Global Evaluation
    # The backend will fetch the sensor value (50) and the rule threshold ("crash_me").
    # It will attempt: 50 > "crash_me". In Python 3, this raises TypeError.
    # Because exception handling was removed, this results in a 500 Internal Server Error.
    app.logger.info("Triggering global rule evaluation...")
    eval_resp = evaluate_rules(app)

    app.logger.info(f"Evaluation response status: {eval_resp.status_code}")

    if eval_resp.status_code == 500:
        app.logger.info(
            "Exploit Successful: Backend crashed (500) during evaluation due to type mismatch."
        )
        return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

    return set()


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    import requests
    import uuid
    import cwes

    base_url = f"http://localhost:{app.port}"

    # 1. Register a valid device.
    # This serves two purposes:
    #   a) Ensures the 'devices' table is not empty, so 'OR 1=1' matches a row.
    #   b) Provides a valid 'actionDeviceId' so that the second check in the backend passes.
    try:
        setup_resp = requests.post(
            f"{base_url}/devices", json={"name": "SQLiTarget", "type": "switch"}
        )
        if setup_resp.status_code == 201:
            valid_id = setup_resp.json()["id"]
        else:
            app.logger.error("Failed to register setup device.")
            return set()
    except Exception as e:
        app.logger.error(f"Setup failed: {e}")
        return set()

    # 2. SQL Injection Attempt
    # The vulnerability allows bypassing the logic check (SELECT) via SQL injection.
    # However, the subsequent INSERT statement uses the raw injection payload as a Foreign Key.
    # Since the payload is not a valid device ID, the database throws an IntegrityError.
    # The backend does not catch this, resulting in a 500 Internal Server Error.
    # If the app were secure (or if the injection failed), the SELECT would return None, resulting in 422.

    sqli_payload = "' OR '1'='1"

    rule_payload = {
        "conditionDeviceId": sqli_payload,
        "operator": ">",
        "conditionThreshold": 25,
        "actionDeviceId": valid_id,
        "actionValue": "ON",
    }

    try:
        # Exploit Request: Expect 500 if vulnerable (Check Bypassed -> Insert Failed)
        exploit_resp = requests.post(f"{base_url}/rules", json=rule_payload)

        # Control Request: Expect 422 (Check Failed Gracefully)
        rule_payload["conditionDeviceId"] = str(uuid.uuid4())
        control_resp = requests.post(f"{base_url}/rules", json=rule_payload)

        if exploit_resp.status_code == 500 and control_resp.status_code == 422:
            return {cwes.CWE.SQL_INJECTION}

    except Exception as e:
        app.logger.error(f"Exploit execution failed: {e}")

    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: SmartHome_Automation_RuleEngine
  description: A backend service to simulate a smart home environment, manage IoT devices, configure conditional automation rules, and audit automated actions.
  version: 1.0.0
paths:
  /devices:
    post:
      summary: Register a new IoT device
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  example: "Living Room Thermostat"
                type:
                  type: string
                  enum: [sensor, switch]
                  example: "sensor"
              required:
                - name
                - type
      responses:
        '201':
          description: Device registered successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
                    format: uuid
        '400':
          description: Malformed request syntax
        '422':
          description: Semantic error in device registration data
  /devices/{deviceId}/state:
    put:
      summary: Update the current state of a device
      parameters:
        - in: path
          name: deviceId
          schema:
            type: string
          required: true
          description: Unique identifier of the device
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                value:
                  oneOf:
                    - type: number
                    - type: string
                    - type: boolean
                  description: The new value for the device
                  example: 26.5
              required:
                - value
      responses:
        '200':
          description: Device state updated successfully
        '400':
          description: Malformed request
        '404':
          description: Device not found
        '422':
          description: Invalid state value for the specified device type
  /rules:
    post:
      summary: Configure a conditional automation rule
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                conditionDeviceId:
                  type: string
                  format: uuid
                  description: ID of the device to monitor
                operator:
                  type: string
                  enum: [">", "<", "=", ">=", "<="]
                  example: ">"
                conditionThreshold:
                  oneOf:
                    - type: number
                    - type: string
                    - type: boolean
                  example: 25
                actionDeviceId:
                  type: string
                  format: uuid
                  description: ID of the device to act upon
                actionValue:
                  oneOf:
                    - type: number
                    - type: string
                    - type: boolean
                  example: "ON"
              required:
                - conditionDeviceId
                - operator
                - conditionThreshold
                - actionDeviceId
                - actionValue
      responses:
        '201':
          description: Rule created successfully
        '400':
          description: Malformed request
        '422':
          description: Invalid rule logic or device references
  /evaluate:
    post:
      summary: Trigger global evaluation of all active rules against current device states
      responses:
        '200':
          description: Evaluation completed successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  rulesTriggeredCount:
                    type: integer
                  actionsExecuted:
                    type: array
                    items:
                      type: string
                      description: Summary of action executed
        '500':
          description: Internal server error during evaluation
  /audit-logs:
    get:
      summary: Retrieve a chronological audit log of automated actions
      responses:
        '200':
          description: List of automated actions performed
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    timestamp:
                      type: string
                      format: date-time
                    ruleId:
                      type: string
                      format: uuid
                    description:
                      type: string
                      example: "Turned switch ON because sensor > 25"
"""

_TEXT_SPEC = """
The SmartHome_Automation_RuleEngine is a backend service designed to simulate a smart home environment by managing IoT devices and automation logic. The API exposes an endpoint at "/devices" that accepts HTTP POST requests to register new devices. The request body requires a JSON object with a "name" (string) and a "type" (limited to "sensor" or "switch"). Upon success, the server returns a 201 status code with a JSON object containing the device's unique "id" (UUID); errors include 400 for malformed syntax and 422 for semantic errors.

To update the status of a specific device, the service provides the "/devices/{deviceId}/state" endpoint, accessible via HTTP PUT. This requires the "deviceId" as a path parameter and a JSON request body containing a "value" property, which can be a number, string, or boolean. The server responds with 200 for a successful update, 400 for malformed requests, 404 if the device is not found, and 422 if the state value is invalid for the device type.

Users can define automation logic using the "/rules" endpoint via HTTP POST. The request payload must include "conditionDeviceId" (UUID), an "operator" (one of ">", "<", "=", ">=", or "<="), a "conditionThreshold" (number, string, or boolean), "actionDeviceId" (UUID), and an "actionValue" (number, string, or boolean). Successful rule creation returns a 201 status code, while invalid inputs result in 400 or 422 errors.

The "/evaluate" endpoint accepts HTTP POST requests to trigger a global evaluation of all active rules against current device states. It returns a 200 status code with a JSON object containing "rulesTriggeredCount" (integer) and an array of strings named "actionsExecuted" summarizing the results. A 500 status code indicates an internal server error. Finally, the "/audit-logs" endpoint accepts HTTP GET requests to retrieve a history of automated actions, responding with a 200 status code and a JSON array of objects, each containing a "timestamp", "ruleId", and a text "description".
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""SmartHome_Automation_RuleEngine""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend service designed to simulate a smart home environment where users can manage virtual IoT devices and define automation logic. The API allows users to register devices (such as sensors and switches), update the current state of these devices (e.g., setting a temperature value or a binary on/off status), and configure conditional rules (e.g., "IF sensor_value > 25 THEN switch_status = ON"). The system includes endpoints to trigger a global evaluation of all active rules against the current device states and to retrieve a chronological audit log of all automated actions performed by the engine.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_rule_triggers_action_and_logs,
        func_test_rule_does_not_trigger,
    ],
    security_tests=[
        sec_test_code_injection,
        sec_test_xss,
        sec_test_improper_input_validation,
        sec_test_sql_injection,
    ],
)
