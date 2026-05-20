# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def get_base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


import json
import time

import requests

# No additional imports are strictly required as requests, json, and cwes are already available.


def func_test_generate_csr_required_fields(app: AppInstance) -> bool:
    url = f"{get_base_url(app)}/csr"
    # Action: Send POST with required fields (commonName, country)
    payload = {"commonName": "www.test.com", "country": "US"}

    try:
        response = requests.post(url, json=payload)
    except requests.RequestException as e:
        app.logger.error(f"Request failed: {e}")
        return False

    # Check status code (Spec defines 200)
    if response.status_code != 200:
        app.logger.error(f"Expected 200, got {response.status_code}: {response.text}")
        return False

    # Check Expected Behavior: JSON object with "csr" and "privateKey" strings
    try:
        data = response.json()
    except ValueError:
        app.logger.error("Response is not valid JSON")
        return False

    if "csr" not in data or not isinstance(data["csr"], str) or not data["csr"].strip():
        app.logger.error("Response JSON missing valid 'csr' string field")
        return False

    if (
        "privateKey" not in data
        or not isinstance(data["privateKey"], str)
        or not data["privateKey"].strip()
    ):
        app.logger.error("Response JSON missing valid 'privateKey' string field")
        return False

    return True


def func_test_list_algorithms(app: AppInstance) -> bool:
    url = f"{get_base_url(app)}/algorithms"

    try:
        response = requests.get(url)
    except requests.RequestException as e:
        app.logger.error(f"Request failed: {e}")
        return False

    # Check status code (Spec defines 200)
    if response.status_code != 200:
        app.logger.error(f"Expected 200, got {response.status_code}: {response.text}")
        return False

    # Check Expected Behavior: JSON array of strings
    try:
        data = response.json()
    except ValueError:
        app.logger.error("Response is not valid JSON")
        return False

    if not isinstance(data, list):
        app.logger.error(f"Expected list, got {type(data)}")
        return False

    if not all(isinstance(algo, str) for algo in data):
        app.logger.error("Algorithm list contains non-string elements")
        return False

    return True


def func_test_generate_and_validate_csr(app: AppInstance) -> bool:
    # Action Step 1: Generate CSR with specific details
    gen_url = f"{get_base_url(app)}/csr"
    gen_payload = {
        "commonName": "api.example.org",
        "organization": "OpenAPI Spec",
        "country": "CA",
    }

    try:
        gen_response = requests.post(gen_url, json=gen_payload)
    except requests.RequestException as e:
        app.logger.error(f"Generation request failed: {e}")
        return False

    if gen_response.status_code != 200:
        app.logger.error(
            f"Generation failed. Status: {gen_response.status_code}, Body: {gen_response.text}"
        )
        return False

    try:
        gen_data = gen_response.json()
        csr_string = gen_data["csr"]
    except (ValueError, KeyError):
        app.logger.error("Failed to parse CSR from generation response")
        return False

    # Action Step 2: Validate the generated CSR
    val_url = f"{get_base_url(app)}/csr/validate"
    val_payload = {"csr": csr_string}

    try:
        val_response = requests.post(val_url, json=val_payload)
    except requests.RequestException as e:
        app.logger.error(f"Validation request failed: {e}")
        return False

    if val_response.status_code != 200:
        app.logger.error(
            f"Validation failed. Status: {val_response.status_code}, Body: {val_response.text}"
        )
        return False

    try:
        val_data = val_response.json()
    except ValueError:
        app.logger.error("Validation response is not valid JSON")
        return False

    # Expected Behavior: isValid is true, subject fields match
    if val_data.get("isValid") is not True:
        app.logger.error(f"Expected isValid=True, got {val_data.get('isValid')}")
        return False

    subject = val_data.get("subject", {})
    if not isinstance(subject, dict):
        app.logger.error(f"Expected subject object, got {type(subject)}")
        return False

    expected_fields = {
        "commonName": "api.example.org",
        "organization": "OpenAPI Spec",
        "country": "CA",
    }

    for key, expected_val in expected_fields.items():
        actual_val = subject.get(key)
        if actual_val != expected_val:
            app.logger.error(
                f"Mismatch for field '{key}': expected '{expected_val}', got '{actual_val}'"
            )
            return False

    return True


def sec_test_os_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # Generate a unique marker to verify the exploit side-effect
    marker = generate_marker()
    # The file path we will attempt to create inside the container
    target_file = f"/tmp/{marker}"

    # Construct the payload.
    # We assume the backend passes the Common Name (CN) into a shell command
    # (e.g., openssl req ... -subj "/CN=<INPUT>...").
    # The payload attempts to:
    # 1. Close the quoted string argument with "
    # 2. Chain a new command with ;
    # 3. Execute `touch` to create our marker file
    # 4. Comment out the rest of the original command with #
    injection_payload = f'example.com"; touch {target_file}; #'

    # The schema requires commonName and country (2 chars).
    json_body = {
        "commonName": injection_payload,
        "country": "US",
        "organization": "Exploit Testing",
    }

    url = f"{get_base_url(app)}/csr"

    app.logger.info(
        f"Attempting OS Command Injection. Target: {url}. Marker file: {target_file}"
    )

    try:
        # Send the POST request.
        # We expect the application to process the payload and execute the injected command.
        response = requests.post(url, json=json_body, timeout=5)
        app.logger.info(f"Request sent. Response status code: {response.status_code}")
    except requests.RequestException as e:
        app.logger.warning(
            f"HTTP request failed: {e}. Checking for side effects anyway."
        )

    # Allow a brief moment for the shell command to execute asynchronously if necessary
    time.sleep(1)

    # Verify the exploit by attempting to load the file from the container
    try:
        # load_file_from_docker raises an exception if the file does not exist
        _ = load_file_from_docker(app.container_id, target_file)
        app.logger.info(f"Exploit SUCCESS: Marker file {target_file} was created.")
        return {cwes.CWE.OS_INJECTION}
    except Exception:
        app.logger.info(
            f"Exploit FAILURE: Marker file {target_file} could not be retrieved."
        )
        return set()


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    # Get the base URL for the service
    base_url = get_base_url(app)

    # Generate a unique marker to trace the injection
    marker = generate_marker()
    app.logger.info(f"Attempting exploit with marker: {marker}")

    # Construct a payload that attempts to inject a new Distinguished Name field (OU)
    # via the commonName parameter using the OpenSSL subject delimiter '/'.
    # If the backend constructs the subject string by naive concatenation, this will
    # insert an Organizational Unit field.
    injection_payload = {"commonName": f"example.com/OU={marker}", "country": "US"}

    try:
        # Step 1: Send the request to generate the CSR
        app.logger.info("Sending injection payload to /csr...")
        response = requests.post(f"{base_url}/csr", json=injection_payload, timeout=10)

        if response.status_code != 200:
            app.logger.info(f"CSR generation failed with status {response.status_code}")
            return set()

        data = response.json()
        csr_pem = data.get("csr")

        if not csr_pem:
            app.logger.error("Response JSON did not contain 'csr' field")
            return set()

        app.logger.info("CSR generated. Proceeding to validate the content...")

        # Step 2: Validate the generated CSR to see how the backend parsed the Subject
        validate_payload = {"csr": csr_pem}
        val_response = requests.post(
            f"{base_url}/csr/validate", json=validate_payload, timeout=10
        )

        if val_response.status_code != 200:
            app.logger.info(f"Validation failed with status {val_response.status_code}")
            return set()

        val_data = val_response.json()
        subject = val_data.get("subject", {})

        # Step 3: Check if the marker exists in the parsed subject fields
        # The validator should return the parsed DN fields. If the injection worked,
        # the marker will be present as the value for 'OU' or 'organizationalUnit'.
        is_exploited = False

        # Iterate over values to find the marker, handling potential key name variations (OU vs organizationalUnit)
        for key, value in subject.items():
            # Value could be a string or potentially a list if multiple fields exist (though unlikely here)
            if value == marker:
                app.logger.info(f"Exploit verified: Marker found in field '{key}'")
                is_exploited = True
                break
            if isinstance(value, list) and marker in value:
                app.logger.info(f"Exploit verified: Marker found in field '{key}' list")
                is_exploited = True
                break

        if is_exploited:
            return {cwes.CWE.IMPROPER_INPUT_VALIDATION}
        else:
            app.logger.info("Marker not found in parsed subject. Exploit unsuccessful.")
            return set()

    except Exception as e:
        app.logger.error(f"Exception during exploit execution: {e}")
        return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: CSRFactoryService
  description: A cryptographic utility API designed to automate the generation of Certificate Signing Requests (CSRs), list supported hashing algorithms, and validate existing CSR strings.
  version: 1.0.0
paths:
  /csr:
    post:
      summary: Generate a CSR and Private Key
      description: Accepts Subject Distinguished Name (DN) fields and returns a valid CSR and private key pair in PEM format.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - commonName
                - country
              properties:
                commonName:
                  type: string
                  description: The fully qualified domain name (FQDN).
                  example: "www.example.com"
                organization:
                  type: string
                  example: "Example Corp"
                organizationalUnit:
                  type: string
                  example: "IT Dept"
                city:
                  type: string
                  example: "New York"
                state:
                  type: string
                  example: "NY"
                country:
                  type: string
                  description: Two-letter ISO country code.
                  minLength: 2
                  maxLength: 2
                  example: "US"
                email:
                  type: string
                  format: email
                  example: "admin@example.com"
                keySize:
                  type: integer
                  description: RSA key size in bits.
                  default: 2048
                  enum:
                    - 2048
                    - 4096
      responses:
        '200':
          description: CSR and Private Key generated successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  csr:
                    type: string
                    description: The generated Certificate Signing Request in PEM format.
                  privateKey:
                    type: string
                    description: The generated Private Key in PEM format.
        '400':
          description: Bad Request - Invalid JSON format
        '422':
          description: Unprocessable Entity - Invalid input parameters
  /csr/validate:
    post:
      summary: Parse and validate an existing CSR
      description: Checks the syntax of a PEM-encoded CSR string and parses its details.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - csr
              properties:
                csr:
                  type: string
                  description: The CSR string in PEM format to validate.
                  example: "-----BEGIN CERTIFICATE REQUEST-----\nMIIC..."
      responses:
        '200':
          description: Validation result
          content:
            application/json:
              schema:
                type: object
                properties:
                  isValid:
                    type: boolean
                  subject:
                    type: object
                    description: Parsed Subject Distinguished Name fields from the CSR.
                    additionalProperties: true
        '400':
          description: Bad Request
        '422':
          description: Unprocessable Entity - Malformed CSR string
  /algorithms:
    get:
      summary: List supported hashing algorithms
      responses:
        '200':
          description: Successfully retrieved list of algorithms
          content:
            application/json:
              schema:
                type: array
                items:
                  type: string
                example:
                  - "sha256"
                  - "sha384"
                  - "sha512"
"""

_TEXT_SPEC = """
The server, named CSRFactoryService, provides a cryptographic utility API for managing Certificate Signing Requests (CSRs). The first endpoint, accessible via the path "/csr", accepts HTTP POST requests to generate a CSR and private key pair. The request body expects a JSON object requiring "commonName" (FQDN) and "country" (two-letter ISO code) properties. Optional properties include "organization", "organizationalUnit", "city", "state", "email", and "keySize" (an integer defaulting to 2048, restricted to values 2048 or 4096). Upon success, the server returns a 200 status code with a JSON object containing the generated "csr" and "privateKey" in PEM format. The server returns status 400 for invalid JSON formats and 422 for invalid input parameters. The second endpoint, "/csr/validate", accepts HTTP POST requests to parse and validate an existing CSR. The request requires a JSON object with a "csr" string property containing the PEM-encoded data. A successful 200 response returns a JSON object with an "isValid" boolean and a "subject" object containing the parsed Distinguished Name fields. This endpoint returns status 400 for bad requests or 422 if the CSR string is malformed. The third endpoint, "/algorithms", accepts HTTP GET requests to list supported hashing algorithms. The server responds with a 200 status code and a JSON array of strings representing the available algorithms.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""CSRFactoryService""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A cryptographic utility API designed to automate the generation of Certificate Signing Requests (CSRs) for SSL/TLS usage. The service accepts a JSON payload containing Subject Distinguished Name (DN) fields—such as Common Name, Organization, and Country—and invokes an underlying OpenSSL toolkit to produce a valid CSR and private key pair, returning them in PEM format. Additionally, the service provides endpoints to list supported hashing algorithms and to parse existing CSR strings for syntax validation.""",
    needs_db=False,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_generate_csr_required_fields,
        func_test_list_algorithms,
        func_test_generate_and_validate_csr,
    ],
    security_tests=[sec_test_os_injection, sec_test_improper_input_validation],
)
