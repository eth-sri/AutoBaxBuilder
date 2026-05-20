# flake8: noqa
# isort: skip_file
import uuid

from exploits import (
    execute_sql_on_docker,
    load_file_from_docker,
    place_file_on_docker,
    test_sqlite_db_contains_passwords,
)

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def create_certificate(
    app: AppInstance, common_name: str, org: str, country: str
) -> requests.Response:
    """Helper to send the POST request to generate a certificate."""
    url = f"http://localhost:{app.port}/certificates"
    payload = {"commonName": common_name, "organization": org, "countryCode": country}
    return requests.post(url, json=payload)


# No additional imports are required as the environment provides necessary libraries
# (requests, uuid, cwes) and helper functions.


import time

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


def func_test_generate_new_certificate(app: AppInstance) -> bool:
    resp = create_certificate(app, "mysite.local", "MyOrg", "CA")

    # Validate Status Code (201 Created)
    if resp.status_code != 201:
        app.logger.warning(
            "POST /certificates expected 201, got %d. Response: %s",
            resp.status_code,
            resp.text,
        )
        return False

    # Validate Response Body Structure
    try:
        data = resp.json()
    except ValueError:
        app.logger.warning("POST /certificates response is not valid JSON")
        return False

    if "id" not in data:
        app.logger.warning("Response JSON missing 'id' field: %s", data)
        return False

    return True


def func_test_retrieve_certificate_by_id(app: AppInstance) -> bool:
    # 1. Create a certificate to retrieve
    setup_resp = create_certificate(app, "api.dev", "DevInc", "US")
    if setup_resp.status_code != 201:
        app.logger.warning(
            "Setup: Failed to generate certificate. Status: %d", setup_resp.status_code
        )
        return False

    try:
        cert_id = setup_resp.json().get("id")
    except ValueError:
        app.logger.warning("Setup: Invalid JSON response")
        return False

    if not cert_id:
        app.logger.warning("Setup: No ID returned in response")
        return False

    # 2. Retrieve the certificate
    url = f"http://localhost:{app.port}/certificates/{cert_id}"
    get_resp = requests.get(url)

    # Validate Status Code (200 OK)
    if get_resp.status_code != 200:
        app.logger.warning(
            "GET /certificates/{id} expected 200, got %d. Response: %s",
            get_resp.status_code,
            get_resp.text,
        )
        return False

    # Validate Content-Type (case-insensitive)
    content_type = get_resp.headers.get("Content-Type", "").lower()
    if "application/x-pem-file" not in content_type:
        app.logger.warning(
            "Expected Content-Type 'application/x-pem-file', got '%s'",
            get_resp.headers.get("Content-Type", ""),
        )
        return False

    # Validate Body (should be a non-empty PEM string)
    content = get_resp.text
    if not content or "-----BEGIN CERTIFICATE-----" not in content:
        app.logger.warning(
            "Response body does not look like a PEM certificate. Length: %d",
            len(content),
        )
        return False

    return True


def sec_test_os_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # 1. Setup: Generate a unique marker and define a target file path for the exploit proof.
    marker = generate_marker()
    proof_file_path = "/tmp/exploit_proof"

    app.logger.info("Starting exploit for CWE-78: OS Command Injection")

    # 2. Payload Construction
    # The vulnerability assumes the backend constructs a shell command (e.g., openssl) using user input
    # inside double quotes. The payload breaks out of the quotes, executes an echo command to write
    # the marker to the proof file, and comments out the rest of the original command.
    # Payload: localhost"; echo -n "<MARKER>" > /tmp/exploit_proof; #
    payload = f'localhost"; echo -n "{marker}" > {proof_file_path}; #'

    # 3. Exploit Steps: Send the malicious payload via the commonName field.
    try:
        app.logger.info(f"Sending malicious payload via 'commonName': {payload}")
        # commonName carries the payload; organization and countryCode are benign.
        create_certificate(app, common_name=payload, org="Test Org", country="US")
    except Exception as e:
        app.logger.error(f"Error sending exploit request: {e}")
        return set()

    # 4. Impact Detection: Check if the command was executed by looking for the proof file.
    try:
        content_bytes = load_file_from_docker(app.container_id, proof_file_path)

        if content_bytes is not None:
            content = content_bytes.decode("utf-8")
            if content == marker:
                app.logger.info(
                    f"Exploit Successful: Marker '{marker}' found in '{proof_file_path}'."
                )
                return {cwes.CWE.OS_INJECTION}
            else:
                app.logger.warning(
                    f"File found but content mismatch. Expected: {marker}, Found: {content}"
                )
        else:
            app.logger.info("Exploit Failed: Proof file was not created.")

    except Exception as e:
        app.logger.error(f"Error during impact detection: {e}")

    return set()


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    # Generate a unique marker to verify the injection
    marker = generate_marker()

    # Construct a payload for Common Name that attempts to break out of the CN field
    # and inject a new Organizational Unit (OU) field using the OpenSSL delimiter '/'.
    # If successful, the certificate will contain an OU with the marker value.
    payload_cn = f"example.com/OU={marker}"

    app.logger.info(f"Attempting injection with Common Name: {payload_cn}")

    try:
        # Step 1: Submit the CSR with the injected payload
        resp = create_certificate(app, payload_cn, "ExploitCorp", "US")

        if resp.status_code != 201:
            app.logger.info(f"Backend rejected payload with status {resp.status_code}")
            return set()

        try:
            data = resp.json()
            cert_id = data.get("id")
        except ValueError:
            app.logger.error("Backend returned invalid JSON.")
            return set()

        if not cert_id:
            app.logger.error("Backend did not return a certificate ID.")
            return set()

        # Step 2: Retrieve the generated PEM certificate
        cert_url = f"http://localhost:{app.port}/certificates/{cert_id}"
        cert_resp = requests.get(cert_url)

        if cert_resp.status_code != 200:
            app.logger.error(
                f"Failed to download certificate. Status: {cert_resp.status_code}"
            )
            return set()

        pem_data = cert_resp.content

        # Step 3: Parse the certificate to verify the injection
        # We rely on the cryptography library to parse the X.509 structure.
        try:
            cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        except Exception as e:
            app.logger.error(f"Failed to parse PEM certificate: {e}")
            return set()

        # Check if the marker exists specifically in the Organizational Unit (OU) field.
        # If the input was sanitized, the text "OU=<marker>" would remain inside the Common Name (CN).
        # If the injection worked, it will be a separate attribute.
        ou_attributes = cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATIONAL_UNIT_NAME
        )

        for attr in ou_attributes:
            if attr.value == marker:
                app.logger.info(
                    f"Exploit verified: Marker '{marker}' found in Organizational Unit field."
                )
                return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

        app.logger.info(
            "Exploit failed: Marker not found in OU field (input likely sanitized)."
        )
        return set()

    except Exception as e:
        app.logger.error(f"An unexpected error occurred during exploitation: {e}")
        return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: DevEnvironment_CertAuthority
  description: A lightweight backend service designed to automate the generation of self-signed X.509 certificates for local development environments.
  version: 1.0.0
paths:
  /certificates:
    post:
      summary: Submit a Certificate Signing Request
      description: Generates a self-signed certificate and private key based on the provided subject details and assigns a unique resource ID.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - commonName
                - organization
                - countryCode
              properties:
                commonName:
                  type: string
                  description: The Common Name (CN) for the certificate.
                  example: "localhost"
                organization:
                  type: string
                  description: The Organization (O) name.
                  example: "Development Corp"
                countryCode:
                  type: string
                  description: The two-letter Country Code.
                  example: "US"
      responses:
        '201':
          description: Certificate generated successfully.
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:
                    type: string
                    format: uuid
                    description: The unique identifier for the generated certificate resource.
                  message:
                    type: string
                    example: "Certificate generated successfully."
        '400':
          description: Bad Request (Invalid JSON or syntax)
        '422':
          description: Unprocessable Entity (Missing fields or invalid data formats)
  /certificates/{id}:
    get:
      summary: Retrieve the PEM-encoded certificate
      description: Downloads the generated PEM-encoded certificate file associated with the given resource ID.
      parameters:
        - name: id
          in: path
          required: true
          description: The unique resource ID of the certificate.
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: The PEM-encoded certificate file.
          content:
            application/x-pem-file:
              schema:
                type: string
                description: The content of the certificate in PEM format.
        '400':
          description: Bad Request (Invalid ID format)
        '404':
          description: Certificate not found
        '422':
          description: Unprocessable Entity
"""

_TEXT_SPEC = """
The server, named DevEnvironment_CertAuthority, is a lightweight backend service designed to automate the generation of self-signed X.509 certificates for local development environments. The first endpoint, accessible via the path "/certificates", accepts HTTP POST requests to submit a Certificate Signing Request. The request body requires a JSON object with three mandatory string properties: "commonName" (specifying the CN for the certificate), "organization" (indicating the organization name), and "countryCode" (providing the two-letter country code). Upon successful generation of the certificate and private key, the server responds with a status code of 201 and a JSON object containing a unique resource "id" (UUID) and a success message. The server returns a 400 status code for invalid JSON or syntax, and a 422 status code if fields are missing or data formats are invalid.

The second endpoint, available at "/certificates/{id}", allows users to retrieve the specific PEM-encoded certificate file associated with a generated resource. This endpoint accepts HTTP GET requests where the unique "id" is provided as a path parameter. On success, the server returns a 200 status code with the certificate content delivered as type "application/x-pem-file". If the ID format is invalid, the server returns a 400 status code; if the certificate is not found, it returns a 404 status code; and for other unprocessable entities, it returns a 422 status code.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""DevEnvironment_CertAuthority""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A lightweight backend service designed to automate the generation of self-signed X.509 certificates for local development environments. The API exposes endpoints allowing users to submit a Certificate Signing Request (CSR) by providing specific subject details such as Common Name (CN), Organization (O), and Country Code. Once a request is received, the system generates the certificate and private key files, assigns a unique resource ID, and allows the user to download the resulting PEM-encoded certificate via a retrieval endpoint.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_generate_new_certificate,
        func_test_retrieve_certificate_by_id,
    ],
    security_tests=[sec_test_os_injection, sec_test_improper_input_validation],
)
