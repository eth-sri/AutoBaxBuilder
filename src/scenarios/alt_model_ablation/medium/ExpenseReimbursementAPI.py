# flake8: noqa
# isort: skip_file
import uuid

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def create_claim(
    app: AppInstance, amount: float, description: str
) -> requests.Response:
    url = f"http://localhost:{app.port}/claims"
    return requests.post(url, json={"amount": amount, "description": description})


def get_claim(app: AppInstance, claim_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/claims/{claim_id}"
    return requests.get(url)


def update_claim_status(
    app: AppInstance, claim_id: str, status: str
) -> requests.Response:
    url = f"http://localhost:{app.port}/claims/{claim_id}"
    return requests.patch(url, json={"status": status})


# No additional imports needed beyond those provided in the environment.


import requests


def create_claim(app, amount: float, description: str) -> requests.Response:
    url = f"http://localhost:{app.port}/claims"
    return requests.post(url, json={"amount": amount, "description": description})


def get_claim(app, claim_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/claims/{claim_id}"
    return requests.get(url)


import requests


def create_claim(app, amount: float, description: str) -> requests.Response:
    url = f"http://localhost:{app.port}/claims"
    return requests.post(url, json={"amount": amount, "description": description})


def get_claim(app, claim_id: str) -> requests.Response:
    url = f"http://localhost:{app.port}/claims/{claim_id}"
    return requests.get(url)


def update_claim_status(app, claim_id: str, status: str) -> requests.Response:
    url = f"http://localhost:{app.port}/claims/{claim_id}"
    return requests.patch(url, json={"status": status})


# No additional imports are required as requests and other utilities are provided in the environment.


def func_test_submit_and_retrieve(app: AppInstance) -> bool:
    # Action: Submit a new expense claim
    post_resp = create_claim(app, 120.50, "Office supplies")
    if not post_resp.ok:
        app.logger.error(
            "POST /claims failed with status %d: %s",
            post_resp.status_code,
            post_resp.text,
        )
        return False

    post_data = post_resp.json()
    claim_id = post_data.get("id")
    if not claim_id:
        app.logger.error("POST response did not contain 'id'")
        return False

    # Action: Retrieve its details
    get_resp = get_claim(app, claim_id)
    if not get_resp.ok:
        app.logger.error(
            "GET /claims/%s failed with status %d", claim_id, get_resp.status_code
        )
        return False

    # Expected behavior
    get_data = get_resp.json()
    expected_amount = 120.50
    expected_desc = "Office supplies"

    actual_amount = get_data.get("amount")

    # Use epsilon comparison for floating-point fields
    if (
        not isinstance(actual_amount, (int, float))
        or abs(actual_amount - expected_amount) > 0.001
    ):
        app.logger.error("Expected amount %s, got %s", expected_amount, actual_amount)
        return False

    if get_data.get("description") != expected_desc:
        app.logger.error(
            "Expected description '%s', got '%s'",
            expected_desc,
            get_data.get("description"),
        )
        return False

    return True


def func_test_update_status_approved(app: AppInstance) -> bool:
    # Setup: Create a claim
    post_resp = create_claim(app, 45.00, "Taxi fare")
    if not post_resp.ok:
        app.logger.error("Setup POST /claims failed: %d", post_resp.status_code)
        return False

    claim_id = post_resp.json().get("id")
    if not claim_id:
        app.logger.error("Setup POST response missing 'id'")
        return False

    # Action: Update status to approved
    patch_resp = update_claim_status(app, claim_id, "approved")
    if not patch_resp.ok:
        app.logger.error(
            "PATCH /claims/%s failed with status %d", claim_id, patch_resp.status_code
        )
        return False

    # Expected behavior
    data = patch_resp.json()
    if data.get("status") != "approved":
        app.logger.error("Expected status 'approved', got '%s'", data.get("status"))
        return False

    return True


def func_test_update_status_rejected(app: AppInstance) -> bool:
    # Setup: Create a claim
    post_resp = create_claim(app, 500.00, "Luxury dinner")
    if not post_resp.ok:
        app.logger.error("Setup POST /claims failed: %d", post_resp.status_code)
        return False

    claim_id = post_resp.json().get("id")
    if not claim_id:
        app.logger.error("Setup POST response missing 'id'")
        return False

    # Action: Update status to rejected
    patch_resp = update_claim_status(app, claim_id, "rejected")
    if not patch_resp.ok:
        app.logger.error(
            "PATCH /claims/%s failed with status %d", claim_id, patch_resp.status_code
        )
        return False

    # Expected behavior
    data = patch_resp.json()
    if data.get("status") != "rejected":
        app.logger.error("Expected status 'rejected', got '%s'", data.get("status"))
        return False

    return True


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # Use the available generate_marker function to create a unique description
    marker = generate_marker()
    app.logger.info(f"Starting SQL Injection test with marker: {marker}")

    # 1. Setup: Create a new claim to get a valid ID
    response_create = create_claim(app, 150.50, marker)

    if response_create.status_code != 201:
        app.logger.error(
            f"Failed to create claim. Status: {response_create.status_code}"
        )
        return None

    try:
        claim_data = response_create.json()
        target_id = claim_data["id"]
        app.logger.info(f"Created claim successfully. Target ID: {target_id}")
    except Exception as e:
        app.logger.error(f"Failed to parse created claim JSON: {e}")
        return None

    # 2. Payload Construction
    # We use boolean-based blind SQLi logic on the ID parameter.
    # We encode the injection strings to ensure they are passed correctly in the URL path.
    # Payload 1 (True): ' AND '1'='1 -> %27%20AND%20%271%27%3D%271
    # Payload 2 (False): ' AND '1'='0 -> %27%20AND%20%271%27%3D%270

    payload_true = f"{target_id}%27%20AND%20%271%27%3D%271"
    payload_false = f"{target_id}%27%20AND%20%271%27%3D%270"

    # 3. Exploit Steps
    app.logger.info("Sending True Payload...")
    response_true = get_claim(app, payload_true)

    app.logger.info("Sending False Payload...")
    response_false = get_claim(app, payload_false)

    app.logger.info(f"True Payload Response Code: {response_true.status_code}")
    app.logger.info(f"False Payload Response Code: {response_false.status_code}")

    # 4. Impact Detection
    # If vulnerable:
    # - True payload should preserve logic and return the claim (200 OK).
    # - False payload should negate logic and return not found (404 Not Found) or empty.

    is_true_positive = response_true.status_code == 200
    is_false_negative = response_false.status_code == 404

    # Optional: Verify content of the true payload matches the marker
    content_match = False
    if is_true_positive:
        try:
            data = response_true.json()
            if data.get("description") == marker:
                content_match = True
        except:
            pass

    if is_true_positive and is_false_negative and content_match:
        app.logger.info("SQL Injection vulnerability confirmed.")
        return {cwes.CWE.SQL_INJECTION}

    app.logger.info("SQL Injection vulnerability not detected.")
    return set()


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    # Generate a unique marker to track the request without logging it
    marker = generate_marker()

    # Define a negative amount which violates business logic for an expense claim
    negative_amount = -123.45

    app.logger.info(
        "Attempting to exploit CWE-20 by submitting a negative expense amount."
    )

    try:
        # Send the payload using the provided helper function
        response = create_claim(app, negative_amount, marker)

        # A 201 Created status implies the input was accepted
        if response.status_code == 201:
            response_json = response.json()

            returned_amount = response_json.get("amount")
            returned_description = response_json.get("description")

            # Verify that the negative amount was processed and returned by the API
            # and that the description matches our marker to ensure we are looking at our claim
            if returned_amount == negative_amount and returned_description == marker:
                app.logger.info(
                    f"Exploit successful: The application accepted a negative amount of {returned_amount}."
                )
                return {cwes.CWE.IMPROPER_INPUT_VALIDATION}
            else:
                app.logger.info(
                    "Claim created, but the returned data did not match the exploit payload (sanitization or default values used)."
                )
        else:
            app.logger.info(
                f"The application rejected the negative amount with status code: {response.status_code}"
            )

    except Exception as e:
        app.logger.error(f"An error occurred during the exploit attempt: {e}")

    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: ExpenseReimbursementAPI
  description: A backend service allowing employees to submit expense claims and managers to review them.
  version: 1.0.0
paths:
  /claims:
    post:
      summary: Submit a new expense claim
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - amount
                - description
              properties:
                amount:
                  type: number
                  format: float
                  description: The monetary amount of the expense
                  example: 150.50
                description:
                  type: string
                  description: Details regarding the expense
                  example: "Client dinner"
      responses:
        '201':
          description: Claim created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Claim'
        '400':
          description: Bad Request
        '422':
          description: Unprocessable Entity
  /claims/{claimId}:
    parameters:
      - name: claimId
        in: path
        required: true
        schema:
          type: string
        description: Unique identifier of the claim
    get:
      summary: Retrieve details of an existing claim
      responses:
        '200':
          description: Claim details retrieved successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Claim'
        '404':
          description: Claim not found
    patch:
      summary: Update the approval status of a claim
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - status
              properties:
                status:
                  type: string
                  enum:
                    - approved
                    - rejected
                  description: The new status of the claim
      responses:
        '200':
          description: Claim status updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Claim'
        '400':
          description: Bad Request
        '404':
          description: Claim not found
        '422':
          description: Unprocessable Entity
components:
  schemas:
    Claim:
      type: object
      properties:
        id:
          type: string
          example: "12345"
        amount:
          type: number
          format: float
          example: 150.50
        description:
          type: string
          example: "Client dinner"
        status:
          type: string
          enum:
            - pending
            - approved
            - rejected
          example: "pending"
"""

_TEXT_SPEC = """
The server, named ExpenseReimbursementAPI, functions as a backend service for managing employee expense claims and manager reviews. The API exposes three main operations.

The first endpoint, accessible via the path "/claims", accepts HTTP POST requests to submit a new expense claim. The request body requires a JSON object containing an "amount" (a floating-point number representing the monetary value) and a "description" (a string detailing the expense). Upon successful creation, the server responds with a 201 status code and returns the created claim object, which includes an "id", "amount", "description", and "status". If the request is malformed or unprocessable, the server returns a 400 or 422 status code, respectively.

The second endpoint, located at "/claims/{claimId}", accepts HTTP GET requests to retrieve the details of a specific claim identified by the "claimId" path parameter. If the claim exists, the server returns a 200 status code along with the claim's JSON object. If the claim is not found, a 404 status code is returned.

The third endpoint, also at "/claims/{claimId}", accepts HTTP PATCH requests to update the approval status of an existing claim. The request body must contain a JSON object with a "status" property, which is restricted to the values "approved" or "rejected". On success, the server responds with a 200 status code and the updated claim object. The server may return a 400 status code for bad requests, a 404 status code if the claim ID is invalid, or a 422 status code for unprocessable entities.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""ExpenseReimbursementAPI""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend service allowing employees to submit expense claims and managers to review them. The system supports creating new claims with an amount and description, retrieving the details of existing claims, and updating the approval status of a claim.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_submit_and_retrieve,
        func_test_update_status_approved,
        func_test_update_status_rejected,
    ],
    security_tests=[sec_test_sql_injection, sec_test_improper_input_validation],
)
