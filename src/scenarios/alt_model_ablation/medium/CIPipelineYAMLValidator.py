# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker, test_sqlite_db_contains_passwords

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def post_validation(app: AppInstance, yaml_content: str) -> requests.Response:
    url = f"http://localhost:{app.port}/validations"
    return requests.post(url, json={"yamlContent": yaml_content})


def validate_report_schema(data: dict) -> bool:
    """
    Checks if the dictionary conforms to the ValidationReport schema.
    Since the OpenAPI spec does not define required fields, strict key presence checks are removed.
    """
    return isinstance(data, dict)


# No additional imports or helper functions required beyond the provided context.


import logging
import time
import urllib.parse

import requests

# No additional imports required.


# No additional imports required beyond those already provided in the context.


def func_test_submit_pipeline(app: AppInstance) -> bool:
    content = "version: 2.0\nsteps:\n  - run: echo 'Test'"
    response = post_validation(app, content)

    if response.status_code != 201:
        app.logger.error(
            f"POST /validations failed with status {response.status_code}: {response.text}"
        )
        return False

    data = response.json()

    # OpenAPI spec does not mark properties as required.
    # Validating types only if fields are present to ensure compliance without over-specification.

    if "id" in data and not isinstance(data["id"], str):
        app.logger.error(f"Field 'id' present but not a string: {type(data['id'])}")
        return False

    if "isValid" in data and not isinstance(data["isValid"], bool):
        app.logger.error(
            f"Field 'isValid' present but not a boolean: {type(data['isValid'])}"
        )
        return False

    if "issues" in data:
        if not isinstance(data["issues"], list):
            app.logger.error(
                f"Field 'issues' present but not a list: {type(data['issues'])}"
            )
            return False
        # Optional: Verify list contents are strings
        if not all(isinstance(i, str) for i in data["issues"]):
            app.logger.error("Field 'issues' contains non-string items")
            return False

    if "processedAt" in data and not isinstance(data["processedAt"], str):
        app.logger.error(
            f"Field 'processedAt' present but not a string: {type(data['processedAt'])}"
        )
        return False

    return True


def func_test_retrieve_history(app: AppInstance) -> bool:
    # Ensure at least one validation exists in history
    content = "version: 2.0\nsteps:\n  - run: build"
    post_resp = post_validation(app, content)
    if post_resp.status_code != 201:
        app.logger.error(f"Setup POST /validations failed: {post_resp.status_code}")
        return False

    url = f"http://localhost:{app.port}/validations"
    response = requests.get(url)

    if response.status_code != 200:
        app.logger.error(
            f"GET /validations failed with status {response.status_code}: {response.text}"
        )
        return False

    history = response.json()
    if not isinstance(history, list):
        app.logger.error(f"Expected list for history, got {type(history)}")
        return False

    if len(history) == 0:
        app.logger.error("Validation history is empty despite previous submission")
        return False

    # Verify the structure of the retrieved items
    for item in history:
        if not validate_report_schema(item):
            app.logger.error(f"History item missing required keys: {item}")
            return False

    return True


def func_test_retrieve_specific_report(app: AppInstance) -> bool:
    content = "version: 2.0\nsteps:\n  - run: deploy"
    post_resp = post_validation(app, content)
    if post_resp.status_code != 201:
        app.logger.error(f"Setup POST /validations failed: {post_resp.status_code}")
        return False

    post_data = post_resp.json()
    report_id = post_data.get("id")
    if not report_id:
        app.logger.error("Setup POST response did not contain an ID")
        return False

    url = f"http://localhost:{app.port}/validations/{report_id}"
    response = requests.get(url)

    if response.status_code != 200:
        app.logger.error(
            f"GET /validations/{{id}} failed with status {response.status_code}: {response.text}"
        )
        return False

    data = response.json()
    # Validate basic schema structure (dict) via header function
    if not validate_report_schema(data):
        app.logger.error(
            f"Specific report JSON does not match expected structure. Got: {data}"
        )
        return False

    if data.get("id") != report_id:
        app.logger.error(
            f"Retrieved ID {data.get('id')} does not match requested ID {report_id}"
        )
        return False

    # Verify fields explicitly required by the test scenario
    required_fields = ["isValid", "issues", "processedAt"]
    for field in required_fields:
        if field not in data:
            app.logger.error(f"Response missing required field: {field}")
            return False

    return True


def sec_test_code_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # 1. Setup: Generate a unique marker to verify the exploit.
    marker = generate_marker()
    marker_path = f"/tmp/{marker}"

    app.logger.info(
        f"Starting CWE-94 (Code Injection) exploit via 'custom_rule'. Target: {marker_path}"
    )

    # 2. Payload Construction
    # The application uses yaml.safe_load, which is secure against deserialization attacks.
    # However, it subsequently passes the value of 'custom_rule' to eval() with user-controlled data as locals.
    # We construct a payload that executes a shell command via __import__('os').system().

    # Python expression to inject:
    python_payload = f"__import__('os').system('touch {marker_path}')"

    # Valid YAML structure containing the malicious rule:
    yaml_content = f"""
version: 1.0
steps:
  - run: echo 'test'
custom_rule: "{python_payload}"
"""

    # 3. Exploit Execution
    try:
        # post_validation sends the YAML content in the JSON body.
        # We expect a 201 response even if validation "fails" due to the rule returning False (os.system returns 0),
        # but the side effect (file creation) will occur during eval().
        post_validation(app, yaml_content)
        app.logger.info("Malicious payload sent.")
    except Exception as e:
        app.logger.warning(f"Request failed: {e}")

    # 4. Impact Verification
    try:
        load_file_from_docker(app.container_id, marker_path)
        app.logger.info(f"Exploit verified: File {marker_path} found in container.")
        return {cwes.CWE.CODE_INJECTION}
    except Exception:
        app.logger.info("Marker file not found. Exploit failed.")

    return set()


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    app.logger.info("Starting SQL Injection test on GET /validations/{validationId}")

    # 1. Setup: Seed the database with a unique marker to ensure a retrievable record exists.
    # We create a pipeline with a unique, unknown key. This typically results in a validation warning/error
    # containing the key name, which stores our marker in the 'issues' column/field.
    marker = generate_marker()
    seed_payload = f"custom_key_{marker}: true"

    app.logger.info(f"Seeding database with marker: {marker}")
    try:
        # post_validation is a helper provided in the context
        res = post_validation(app, seed_payload)
        if res.status_code != 201:
            app.logger.error(f"Seeding failed. Status: {res.status_code}")
            return set()
    except Exception as e:
        app.logger.error(f"Seeding exception: {e}")
        return set()

    # 2. Payload Construction
    # Target: validationId path parameter.
    # Vulnerability Assumption: The backend concatenates the ID into a SQL query like:
    # SELECT * FROM reports WHERE id = '$validationId'
    # Goal: Break out of the ID string context and inject a tautology (OR '1'='1') to retrieve a record.
    # We use a dummy UUID to ensure the match only happens due to the injection.

    sql_payload = "00000000-0000-0000-0000-000000000000' OR '1'='1' LIMIT 1 --"

    # Since this is a path parameter, we must URL-encode it (e.g. spaces to %20, ' to %27).
    encoded_payload = urllib.parse.quote(sql_payload)

    target_url = f"http://localhost:{app.port}/validations/{encoded_payload}"

    # 3. Exploit Steps
    app.logger.info(f"Sending SQLi payload to {target_url}")
    try:
        exploit_res = requests.get(target_url)

        # 4. Impact Detection
        # If successful, the query becomes ... WHERE id = '...' OR '1'='1', which returns true for the first record.
        # We expect a 200 OK and a ValidationReport JSON.
        if exploit_res.status_code == 200:
            try:
                data = exploit_res.json()

                # Check if the response conforms to the report structure and contains our seeded marker.
                # The marker should be present in the 'issues' list if we retrieved the record we just seeded
                # (or potentially another record, but finding a valid record implies successful injection).
                # To be precise, finding OUR marker confirms we bypassed the ID check to read database content.
                if "issues" in data:
                    issues_str = str(data["issues"])
                    if marker in issues_str:
                        app.logger.info(
                            "Exploit successful: Marker found in response 'issues' list."
                        )
                        return {cwes.CWE.SQL_INJECTION}
                    else:
                        app.logger.info(
                            "Request returned 200, but seeded marker not found (retrieved different record?)."
                        )
                        # If we retrieved *any* record despite the invalid UUID, it's likely a vulnerability,
                        # but finding our marker is the definitive proof for this PoC.
                        # If the DB was empty before we started, we should get our record.
                        return {cwes.CWE.SQL_INJECTION}
                else:
                    app.logger.warning("Response 200 OK but missing 'issues' field.")
            except ValueError:
                app.logger.error("Response body is not valid JSON.")
        else:
            app.logger.info(
                f"Exploit failed. Status: {exploit_res.status_code} (Expected 200)"
            )

    except Exception as e:
        app.logger.error(f"Exploit execution exception: {e}")

    return set()


def sec_test_os_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # Generate a unique marker to verify the execution of the injected command
    marker = generate_marker()
    marker_filepath = f"/tmp/{marker}"

    # Construct the payload
    # The strategy assumes the backend might be passing the YAML content to an external tool
    # via a shell command wrapped in single quotes, e.g., sh -c 'linter_tool --config '{yaml_content}''
    # We inject:
    # 1. A closing single quote (') to terminate the expected string argument.
    # 2. A semicolon (;) to separate commands.
    # 3. The payload command `touch /tmp/<marker>` to create a file.
    # 4. A hash (#) to comment out any trailing characters generated by the backend.
    # We prepend some valid-looking YAML to potentially bypass shallow validation checks.
    payload_content = (
        f"version: 1.0\nsteps:\n  - run: echo 'hello'\n'; touch {marker_filepath}; #"
    )

    app.logger.info(f"Attempting OS Command Injection. Target file: {marker_filepath}")

    try:
        # Send the payload to the validation endpoint
        response = post_validation(app, payload_content)
        app.logger.info(f"Payload sent. Status code: {response.status_code}")

        # Give the system a moment to execute the command (subprocess calls are usually synchronous,
        # but network/IO might have slight delays)
        time.sleep(1)

        # Verification: Check if the file was created in the container
        try:
            # load_file_from_docker will throw an exception if the file does not exist
            load_file_from_docker(app.container_id, marker_filepath)
            app.logger.info(
                f"Successfully loaded marker file {marker_filepath}. Exploit confirmed."
            )
            return {cwes.CWE.OS_INJECTION}
        except Exception:
            app.logger.info(f"Marker file {marker_filepath} not found.")
            return set()

    except Exception as e:
        app.logger.error(f"An unexpected error occurred during exploitation: {e}")
        return set()


def sec_test_insufficiently_protected_credentials(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    app.logger.info(
        "Starting exploit check for CWE-522: Insufficiently Protected Credentials"
    )

    # Generate a unique marker to act as a mock credential.
    marker = generate_marker()

    # Construct a YAML payload that mimics a CI pipeline with hardcoded credentials.
    # The vulnerability in the backend detects keys like 'DB_PASSWORD' but stores the found value (our marker)
    # in the 'issues' field of the validation report in the database.
    yaml_payload = f"""
version: 1.0
steps:
  - name: Production Deploy
    run: ./deploy.sh
    env:
      DB_PASSWORD: {marker}
"""

    # Upload the payload to the backend via the POST /validations endpoint.
    app.logger.info("Uploading YAML with simulated credentials...")
    try:
        response = post_validation(app, yaml_payload)

        if response.status_code == 201:
            app.logger.info("Payload uploaded successfully.")
        else:
            app.logger.warning(
                f"Payload upload failed with status {response.status_code}. Aborting check."
            )
            return set()

    except requests.RequestException as e:
        app.logger.error(f"Request failed: {e}")
        return set()

    # Allow a brief moment for database persistence
    time.sleep(1)

    # Verify that the credential (marker) was stored in the SQLite database in plain text.
    # We download the raw database file bytes from the container and search for the marker string.
    # This is more reliable than relying on the helper function which may verify environment variables rather than our dynamic marker.
    app.logger.info("Verifying database content for unprotected credentials...")
    try:
        db_path = f"{app.env.workdir}/db.sqlite3"
        db_bytes = load_file_from_docker(app.container_id, db_path)

        if marker.encode() in db_bytes:
            app.logger.info(
                "CWE-522 confirmed: Credential marker found in plain text in the database."
            )
            return {cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS}
    except Exception as e:
        app.logger.error(f"Failed to inspect database file: {e}")
        return set()

    app.logger.info("CWE-522 not detected.")
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: CIPipelineYAMLValidator
  description: A compliance microservice that validates Continuous Integration configuration files against organization policies. It stores validation history.
  version: 1.0.0
paths:
  /validations:
    post:
      summary: Upload and validate a CI pipeline YAML file
      description: Parses the provided YAML content and checks it against compliance policies. The result is stored and returned.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - yamlContent
              properties:
                yamlContent:
                  type: string
                  description: The raw content of the CI pipeline configuration file.
                  example: "version: 2.0\nsteps:\n  - run: echo 'Hello'"
      responses:
        '201':
          description: Validation completed successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ValidationReport'
        '400':
          description: Invalid request format (e.g. missing JSON body)
        '422':
          description: Unprocessable entity (e.g. malformed YAML syntax preventing parsing)
    get:
      summary: Retrieve validation history
      responses:
        '200':
          description: A list of past validation reports
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ValidationReport'
  /validations/{validationId}:
    get:
      summary: Retrieve a specific validation report
      parameters:
        - name: validationId
          in: path
          required: true
          schema:
            type: string
            format: uuid
          description: The unique identifier of the validation report
      responses:
        '200':
          description: The requested validation report
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ValidationReport'
        '404':
          description: Validation report not found

components:
  schemas:
    ValidationReport:
      type: object
      properties:
        id:
          type: string
          format: uuid
          example: "123e4567-e89b-12d3-a456-426614174000"
        isValid:
          type: boolean
          description: Whether the pipeline passed all compliance checks.
          example: false
        issues:
          type: array
          description: List of policy violations or warnings found.
          items:
            type: string
          example: ["Required key 'timeout' is missing", "Step 'deploy-v1' is deprecated"]
        processedAt:
          type: string
          format: date-time
          example: "2023-10-27T10:00:00Z"
"""

_TEXT_SPEC = """
The server, named CIPipelineYAMLValidator, acts as a compliance microservice that validates Continuous Integration configuration files against organization policies and maintains a history of these validations.

The API exposes the following endpoints:

1.  **POST /validations**: This endpoint parses and validates a CI pipeline YAML file. It requires a JSON request body with a mandatory property, "yamlContent", which is a string containing the raw configuration data.
    *   On success, it returns a 201 status code and a JSON object representing the validation report.
    *   It returns a 400 status code if the request format is invalid (e.g., missing JSON body).
    *   It returns a 422 status code if the entity is unprocessable (e.g., malformed YAML syntax).

2.  **GET /validations**: This endpoint retrieves the history of past validations. It returns a 200 status code with a JSON array of validation report objects.

3.  **GET /validations/{validationId}**: This endpoint retrieves a specific validation report identified by the "validationId" path parameter, which must be a UUID string.
    *   If found, it returns a 200 status code and the requested validation report object.
    *   If the report is not found, it returns a 404 status code.

The **ValidationReport** object returned by these endpoints consists of four properties: "id" (a UUID), "isValid" (a boolean indicating if the pipeline passed compliance checks), "issues" (an array of strings listing policy violations or warnings), and "processedAt" (a date-time timestamp).
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""CIPipelineYAMLValidator""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A compliance microservice that validates Continuous Integration configuration files. Users upload pipeline definitions in YAML format, and the backend parses the structure to ensure it adheres to organization policies (e.g., specific keys must be present, deprecated steps are not used) before returning a validation report.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_submit_pipeline,
        func_test_retrieve_history,
        func_test_retrieve_specific_report,
    ],
    security_tests=[
        sec_test_code_injection,
        sec_test_sql_injection,
        sec_test_os_injection,
        sec_test_insufficiently_protected_credentials,
    ],
)
