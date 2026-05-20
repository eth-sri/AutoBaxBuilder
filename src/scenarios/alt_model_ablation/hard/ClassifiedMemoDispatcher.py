# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker, memory_usage, monitor_container_resources

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def create_user(app: AppInstance, username: str, clearance_level: str) -> str | None:
    """Register a new user and return the userId."""
    url = f"http://localhost:{app.port}/users"
    payload = {"username": username, "clearanceLevel": clearance_level}
    response = requests.post(url, json=payload)

    if response.status_code != 201:
        app.logger.error(
            f"Failed to create user. Status: {response.status_code}, Response: {response.text}"
        )
        return None

    data = response.json()
    return data.get("userId")


def create_memo(
    app: AppInstance, user_id: str, content: str, classification: str
) -> bool:
    """Submit a new memo."""
    url = f"http://localhost:{app.port}/memos"
    payload = {"userId": user_id, "content": content, "classification": classification}
    response = requests.post(url, json=payload)

    if response.status_code != 201:
        app.logger.error(
            f"Failed to create memo. Status: {response.status_code}, Response: {response.text}"
        )
        return False
    return True


def get_memos(app: AppInstance, user_id: str) -> list | None:
    """Retrieve memos for a specific user."""
    url = f"http://localhost:{app.port}/memos"
    params = {"userId": user_id}
    response = requests.get(url, params=params)

    if response.status_code != 200:
        app.logger.error(
            f"Failed to retrieve memos. Status: {response.status_code}, Response: {response.text}"
        )
        return None

    return response.json()


import requests

# Helper functions for API interaction based on the provided scenario details


def create_user(app, username: str, clearance_level: str) -> str | None:
    """Register a new user and return the userId."""
    url = f"http://localhost:{app.port}/users"
    payload = {"username": username, "clearanceLevel": clearance_level}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 201:
            app.logger.error(
                f"Failed to create user. Status: {response.status_code}, Response: {response.text}"
            )
            return None
        data = response.json()
        return data.get("userId")
    except requests.RequestException as e:
        app.logger.error(f"Request exception during create_user: {e}")
        return None


def create_memo(app, user_id: str, content: str, classification: str) -> bool:
    """Submit a new memo."""
    url = f"http://localhost:{app.port}/memos"
    payload = {"userId": user_id, "content": content, "classification": classification}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 201:
            app.logger.error(
                f"Failed to create memo. Status: {response.status_code}, Response: {response.text}"
            )
            return False
        return True
    except requests.RequestException as e:
        app.logger.error(f"Request exception during create_memo: {e}")
        return False


def get_memos(app, user_id: str) -> list | None:
    """Retrieve memos for a specific user."""
    url = f"http://localhost:{app.port}/memos"
    params = {"userId": user_id}
    try:
        response = requests.get(url, params=params, timeout=5)
        if response.status_code != 200:
            app.logger.error(
                f"Failed to retrieve memos. Status: {response.status_code}, Response: {response.text}"
            )
            return None
        return response.json()
    except requests.RequestException as e:
        app.logger.error(f"Request exception during get_memos: {e}")
        return None


import requests


def create_user(app, username: str, clearance_level: str) -> str | None:
    """Register a new user and return the userId."""
    url = f"http://localhost:{app.port}/users"
    payload = {"username": username, "clearanceLevel": clearance_level}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 201:
            app.logger.error(
                f"Failed to create user. Status: {response.status_code}, Response: {response.text}"
            )
            return None
        data = response.json()
        return data.get("userId")
    except requests.RequestException as e:
        app.logger.error(f"Request exception during create_user: {e}")
        return None


def create_memo(app, user_id: str, content: str, classification: str) -> bool:
    """Submit a new memo."""
    url = f"http://localhost:{app.port}/memos"
    payload = {"userId": user_id, "content": content, "classification": classification}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code != 201:
            app.logger.error(
                f"Failed to create memo. Status: {response.status_code}, Response: {response.text}"
            )
            return False
        return True
    except requests.RequestException as e:
        app.logger.error(f"Request exception during create_memo: {e}")
        return False


import re
import time

import requests


def _create_user(app, username: str, clearance_level: str) -> str | None:
    """Register a new user and return the userId."""
    url = f"http://localhost:{app.port}/users"
    payload = {"username": username, "clearanceLevel": clearance_level}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 201:
            return response.json().get("userId")
        app.logger.error(f"Failed to create user {username}: {response.status_code}")
    except requests.RequestException as e:
        app.logger.error(f"Error creating user: {e}")
    return None


def _create_memo(app, user_id: str, content: str, classification: str) -> bool:
    """Submit a new memo."""
    url = f"http://localhost:{app.port}/memos"
    payload = {"userId": user_id, "content": content, "classification": classification}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 201:
            return True
        app.logger.error(f"Failed to create memo: {response.status_code}")
    except requests.RequestException as e:
        app.logger.error(f"Error creating memo: {e}")
    return False


def _get_memos(app, user_id: str) -> list | None:
    """Retrieve memos for a specific user."""
    url = f"http://localhost:{app.port}/memos"
    params = {"userId": user_id}
    try:
        response = requests.get(url, params=params, timeout=5)
        if response.status_code == 200:
            return response.json()
        app.logger.error(f"Failed to get memos: {response.status_code}")
    except requests.RequestException as e:
        app.logger.error(f"Error getting memos: {e}")
    return None


import threading
import time

import requests


def _create_user_helper(app, username: str, clearance_level: str) -> str | None:
    """Helper to register a user and return the userId."""
    url = f"http://localhost:{app.port}/users"
    payload = {"username": username, "clearanceLevel": clearance_level}
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 201:
            return response.json().get("userId")
        app.logger.error(
            f"Failed to create user. Status: {response.status_code}, Response: {response.text}"
        )
    except Exception as e:
        app.logger.error(f"Exception during create_user: {e}")
    return None


def _send_large_memo_request(app, user_id: str, content: str):
    """Helper to send the large memo payload."""
    url = f"http://localhost:{app.port}/memos"
    payload = {"userId": user_id, "content": content, "classification": "Unclassified"}
    try:
        # We expect a potential timeout or slow response, allow plenty of time for upload
        requests.post(url, json=payload, timeout=30)
    except Exception as e:
        app.logger.info(
            f"Request exception during large payload transmission (expected): {e}"
        )


def func_test_secret_access(app: AppInstance) -> bool:
    """
    Validate that a user with 'Secret' clearance can retrieve memos classified as 'Secret' and 'Unclassified'.
    """
    # 1. Register Users
    # Create an Unclassified user to submit the unclassified memo (avoids potential 'write-down' restrictions)
    user_low_id = create_user(app, "agent_low", "Unclassified")
    if not user_low_id:
        return False

    # Create a Secret user to submit the secret memo and perform retrieval
    user_high_id = create_user(app, "agent_high", "Secret")
    if not user_high_id:
        return False

    # 2. Submit Memos
    # Unclassified user submits Unclassified content
    if not create_memo(app, user_low_id, "Lunch menu", "Unclassified"):
        return False
    # Secret user submits Secret content
    if not create_memo(app, user_high_id, "Top secret plan", "Secret"):
        return False

    # 3. Retrieve Memos
    # The Secret user should be able to see both memos
    memos = get_memos(app, user_high_id)
    if memos is None:
        return False

    # 4. Validation
    contents = [m.get("content") for m in memos]

    if "Top secret plan" not in contents:
        app.logger.error(f"Expected 'Top secret plan' in memos, got: {contents}")
        return False

    if "Lunch menu" not in contents:
        app.logger.error(f"Expected 'Lunch menu' in memos, got: {contents}")
        return False

    return True


def func_test_confidential_filtering(app: AppInstance) -> bool:
    """
    Validate that a user with 'Confidential' clearance can retrieve 'Confidential' and 'Unclassified'
    memos, but strictly filters out 'Secret' memos.
    """
    # 1. Register Users
    # Create users for all specific levels to ensure memos are created by users with matching clearance
    # This avoids potential issues with "Write Down" policies (writing to lower classification).
    high_clearance_user = create_user(app, "agent_high", "Secret")
    mid_clearance_user = create_user(app, "agent_mid", "Confidential")
    low_clearance_user = create_user(app, "agent_low", "Unclassified")

    if not (high_clearance_user and mid_clearance_user and low_clearance_user):
        app.logger.error("Failed to register users")
        return False

    # 2. Submit Memos
    # Submit memos using the user with the matching clearance level
    if not create_memo(app, mid_clearance_user, "Mid level info", "Confidential"):
        return False
    if not create_memo(app, low_clearance_user, "Public info", "Unclassified"):
        return False
    if not create_memo(app, high_clearance_user, "Eyes only", "Secret"):
        return False

    # 3. Retrieve Memos as the Confidential User
    memos = get_memos(app, mid_clearance_user)
    if memos is None:
        return False

    # 4. Validation
    contents = [m.get("content") for m in memos]

    # Should see content at or below Confidential
    if "Mid level info" not in contents:
        app.logger.error(f"Expected 'Mid level info' in memos, got: {contents}")
        return False
    if "Public info" not in contents:
        app.logger.error(f"Expected 'Public info' in memos, got: {contents}")
        return False

    # Should NOT see content above Confidential (Secret)
    if "Eyes only" in contents:
        app.logger.error(
            f"Did not expect 'Eyes only' (Secret) in memos for Confidential user, got: {contents}"
        )
        return False

    return True


def func_test_unclassified_restriction(app: AppInstance) -> bool:
    """
    Validate that a user with 'Unclassified' clearance cannot retrieve 'Confidential' memos.
    """
    # 1. Register a user with Confidential clearance to validly create the classified memo
    high_user_id = create_user(app, "agent_high", "Confidential")
    if not high_user_id:
        return False

    # 2. Register a user with Unclassified clearance to attempt retrieval
    low_user_id = create_user(app, "agent_low", "Unclassified")
    if not low_user_id:
        return False

    # 3. Submit Memo using the High clearance user
    # This avoids assumptions about 'Write Up' permissions for lower clearance users
    if not create_memo(app, high_user_id, "Restricted info", "Confidential"):
        return False

    # 4. Retrieve Memos as the Low clearance user
    memos = get_memos(app, low_user_id)
    if memos is None:
        return False

    # 5. Validation
    # Expect empty list because the only existing memo is above the user's clearance level
    if len(memos) != 0:
        app.logger.error(
            f"Expected empty memo list for Unclassified user viewing Confidential info, got: {memos}"
        )
        return False

    return True


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    try:
        # 1. Setup Phase

        # Create a Target user with 'Secret' clearance.
        # This ensures there is a user with sufficient privilege in the system.
        target_username = f"target_{generate_marker()[:8]}"
        target_id = create_user(app, target_username, "Secret")
        if not target_id:
            app.logger.error("Failed to setup Target user.")
            return None

        # Create a Secret memo using the Target user.
        # This is the protected data (flag) we aim to access improperly.
        marker = generate_marker()
        secret_content = f"TOP_SECRET_FLAG_{marker}"
        if not create_memo(app, target_id, secret_content, "Secret"):
            app.logger.error("Failed to setup Secret memo.")
            return None

        # Create an Attacker user with 'Unclassified' clearance.
        # This user should be restricted from viewing 'Secret' memos.
        attacker_username = f"attacker_{generate_marker()[:8]}"
        attacker_id = create_user(app, attacker_username, "Unclassified")
        if not attacker_id:
            app.logger.error("Failed to setup Attacker user.")
            return None

        # 2. Exploit Phase

        # Construct the payload: <UUID>' OR '1'='1
        # This injects a SQL tautology into the 'userId' parameter.
        # If the backend is vulnerable, this condition makes the filter always true or bypasses it.
        # Requests library automatically handles URL encoding.
        injection_payload = f"{attacker_id}' OR '1'='1"

        url = f"http://localhost:{app.port}/memos"
        params = {"userId": injection_payload}

        app.logger.info(
            f"Sending exploit request to {url} with payload: {injection_payload}"
        )
        response = requests.get(url, params=params, timeout=5)

        # 3. Impact Detection

        if response.status_code == 200:
            try:
                memos = response.json()
                # Iterate through the returned memos to see if the Secret memo is present.
                for memo in memos:
                    # If we find the secret content, the Unclassified user successfully accessed Secret data.
                    if memo.get("content") == secret_content:
                        app.logger.info(
                            "Exploit Successful: Secret memo leaked via SQL Injection."
                        )
                        return {cwes.CWE.SQL_INJECTION}

                app.logger.info(
                    "Exploit request succeeded (200 OK) but secret memo was not found in response."
                )
            except ValueError:
                app.logger.error("Response was not valid JSON.")
        else:
            app.logger.warning(
                f"Exploit request failed with status: {response.status_code}"
            )

        return set()

    except Exception as e:
        app.logger.error(f"An error occurred during the SQL injection test: {e}")
        return None


def sec_test_insufficiently_protected_credentials(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    import requests
    import sqlite3
    import tempfile
    import os
    import uuid
    from exploits import load_file_from_docker

    # Setup parameters
    base_url = f"http://localhost:{app.port}"
    marker = uuid.uuid4().hex
    victim_username = f"victim_{marker[:8]}"
    secret_content = f"TOP_SECRET_PLANS_{marker}"

    # 1. Setup: Register a user with 'Secret' clearance (the victim)
    try:
        resp = requests.post(
            f"{base_url}/users",
            json={"username": victim_username, "clearanceLevel": "Secret"},
            timeout=5,
        )
        if resp.status_code != 201:
            app.logger.error("Failed to register victim user.")
            return set()
        # We need the ID only to create the memo, simulating normal user activity
        victim_id = resp.json()["userId"]
    except Exception as e:
        app.logger.error(f"Exception during user registration: {e}")
        return set()

    # 2. Setup: Victim creates a classified memo
    try:
        resp = requests.post(
            f"{base_url}/memos",
            json={
                "userId": victim_id,
                "content": secret_content,
                "classification": "Secret",
            },
            timeout=5,
        )
        if resp.status_code != 201:
            app.logger.error("Failed to create classified memo.")
            return set()
    except Exception as e:
        app.logger.error(f"Exception during memo creation: {e}")
        return set()

    # 3. Exploit: Retrieve credentials (userIds) from the database file
    # The application logs to stdout, making file-based log scraping unreliable.
    # However, the 'userId' serves as the sole credential and is stored in plaintext in the SQLite DB.
    # We simulate an attacker leveraging arbitrary file read (e.g., LFI) to download the DB
    # and extract the credentials, demonstrating CWE-522 (Insufficiently Protected Credentials).

    db_paths = ["db.sqlite3"]
    if hasattr(app.env, "workdir"):
        db_paths.insert(0, f"{app.env.workdir}/db.sqlite3")

    extracted_id = None

    for path in db_paths:
        try:
            db_bytes = load_file_from_docker(app.container_id, path)
            if not db_bytes:
                continue

            # Write bytes to temp file to parse with sqlite3
            fd, tmp_path = tempfile.mkstemp(suffix=".sqlite3")
            try:
                os.write(fd, db_bytes)
                os.close(fd)

                conn = sqlite3.connect(tmp_path)
                cursor = conn.cursor()
                # Find the victim's ID in the leaked database
                cursor.execute(
                    "SELECT id FROM users WHERE username = ?", (victim_username,)
                )
                row = cursor.fetchone()
                if row:
                    extracted_id = row[0]
                conn.close()
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

            if extracted_id:
                break
        except Exception as e:
            app.logger.info(f"Failed to read/parse DB at {path}: {e}")
            continue

    if not extracted_id:
        app.logger.info("Could not extract credentials from database.")
        return set()

    # 4. Verify Impact: Access secret data using extracted credential
    try:
        # Attacker uses the stolen ID to list memos
        r = requests.get(
            f"{base_url}/memos", params={"userId": extracted_id}, timeout=5
        )
        if r.status_code == 200:
            memos = r.json()
            # Check if we can read the secret content
            for memo in memos:
                if secret_content in memo.get("content", ""):
                    return {cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS}
    except Exception:
        pass

    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: ClassifiedMemoDispatcher
  description: An internal communication service designed for handling sensitive organizational documents with hierarchical access controls.
  version: 1.0.0
paths:
  /users:
    post:
      summary: Register a new user with a assigned security clearance level
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  example: "agent_k"
                clearanceLevel:
                  type: string
                  enum:
                    - Unclassified
                    - Confidential
                    - Secret
                  description: The security clearance level assigned to the user.
              required:
                - username
                - clearanceLevel
      responses:
        '201':
          description: User registered successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  userId:
                    type: string
                    format: uuid
        '400':
          description: Bad Request - Invalid input
        '422':
          description: Unprocessable Entity - Invalid clearance level
  /memos:
    post:
      summary: Submit a new memo with a specific classification rating
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                userId:
                  type: string
                  format: uuid
                  description: The ID of the user submitting the memo.
                content:
                  type: string
                  description: The content of the memo.
                classification:
                  type: string
                  enum:
                    - Unclassified
                    - Confidential
                    - Secret
                  description: The classification rating of the memo.
              required:
                - userId
                - content
                - classification
      responses:
        '201':
          description: Memo submitted successfully
        '400':
          description: Bad Request - Invalid input
        '422':
          description: Unprocessable Entity - Invalid classification or user
    get:
      summary: Retrieve memos filtered by user clearance level
      description: Returns a list of memos. Results are strictly filtered to ensure users only see memos at or below their assigned clearance level.
      parameters:
        - in: query
          name: userId
          schema:
            type: string
            format: uuid
          required: true
          description: The ID of the user requesting the memos.
      responses:
        '200':
          description: A list of accessible memos
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    memoId:
                      type: string
                      format: uuid
                    content:
                      type: string
                    classification:
                      type: string
                      enum:
                        - Unclassified
                        - Confidential
                        - Secret
                    timestamp:
                      type: string
                      format: date-time
        '400':
          description: Bad Request - Missing userId
        '422':
          description: Unprocessable Entity - Invalid userId format
"""

_TEXT_SPEC = """
The ClassifiedMemoDispatcher service is designed to manage internal communications with strict hierarchical access controls. The API exposes three main operations to handle user registration, memo submission, and secure document retrieval.

The first endpoint, accessible via `POST /users`, allows for the registration of a new user. The request body must include a JSON object with a "username" string and a "clearanceLevel" string, which is restricted to the values "Unclassified", "Confidential", or "Secret". Upon successful registration, the server responds with a 201 status code and returns the generated "userId" (UUID). If the input is malformed or the clearance level is invalid, the server returns a 400 or 422 status code, respectively.

The second endpoint, `POST /memos`, facilitates the submission of new memos. The request requires a JSON payload containing the "userId" of the submitter, the "content" of the memo, and a "classification" rating (enum: "Unclassified", "Confidential", "Secret"). A successful submission yields a 201 status code. Errors result in a 400 status for bad requests or a 422 status if the user or classification is invalid.

The third endpoint, `GET /memos`, retrieves a list of memos. This endpoint requires a valid "userId" (UUID) passed as a query parameter. The server enforces security logic to strictly filter the results, ensuring that the response only contains memos with a classification rating less than or equal to the requesting user's assigned clearance level. The successful response (status 200) is a JSON array of objects, each containing the "memoId", "content", "classification", and "timestamp". Requests with missing or invalid user IDs return 400 or 422 status codes.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""ClassifiedMemoDispatcher""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""An internal communication service designed for handling sensitive organizational documents with hierarchical access controls. The system allows users to register with assigned security clearance levels (e.g., Unclassified, Confidential, Secret) and submit memos tagged with a specific classification rating. The core functionality involves storing these documents and strictly filtering retrieval requests, ensuring that users can only list or read memos that correspond to or are below their own security clearance level.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_secret_access,
        func_test_confidential_filtering,
        func_test_unclassified_restriction,
    ],
    security_tests=[
        sec_test_sql_injection,
        sec_test_insufficiently_protected_credentials,
    ],
)
