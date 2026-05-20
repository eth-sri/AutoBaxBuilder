# flake8: noqa
# isort: skip_file
import uuid

from exploits import memory_usage, monitor_container_resources

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def create_profile(app: AppInstance, name: str, birth_date: str) -> dict:
    url = f"http://localhost:{app.port}/profiles"
    response = requests.post(url, json={"name": name, "birthDate": birth_date})
    if response.status_code != 201:
        app.logger.warning(
            "POST /profiles failed: %d %s", response.status_code, response.text
        )
        return None
    return response.json()


def create_relationship(app: AppInstance, parent_id: str, child_id: str) -> bool:
    url = f"http://localhost:{app.port}/relationships"
    response = requests.post(url, json={"parentId": parent_id, "childId": child_id})
    if response.status_code != 201:
        app.logger.warning(
            "POST /relationships failed: %d %s", response.status_code, response.text
        )
        return False
    return True


import threading
import time
import urllib.parse

import requests


def func_test_create_retrieve_profile(app: AppInstance) -> bool:
    # Action: Create profile
    profile_data = create_profile(app, "John Doe", "1980-01-01")
    if not profile_data or "id" not in profile_data:
        app.logger.error("Profile creation returned invalid data")
        return False

    profile_id = profile_data["id"]

    # Action: Retrieve profile
    url = f"http://localhost:{app.port}/profiles/{profile_id}"
    response = requests.get(url)

    # Expected behavior: Status 200 and matching data
    if response.status_code != 200:
        app.logger.warning("GET /profiles/{id} status: %d", response.status_code)
        return False

    retrieved_data = response.json()
    if retrieved_data.get("name") != "John Doe":
        app.logger.warning("Name mismatch: %s", retrieved_data.get("name"))
        return False
    if retrieved_data.get("birthDate") != "1980-01-01":
        app.logger.warning("BirthDate mismatch: %s", retrieved_data.get("birthDate"))
        return False

    return True


def func_test_relationship_ancestors(app: AppInstance) -> bool:
    # Setup: Create Parent and Child
    parent = create_profile(app, "Parent", "1960-01-01")
    child = create_profile(app, "Child", "1990-01-01")
    if not parent or not child:
        return False

    # Action: Establish Relationship
    if not create_relationship(app, parent["id"], child["id"]):
        return False

    # Action: Get Ancestors
    url = f"http://localhost:{app.port}/profiles/{child['id']}/ancestors"
    response = requests.get(url)

    # Expected behavior: Status 200 and list contains parent
    if response.status_code != 200:
        app.logger.warning("GET /ancestors status: %d", response.status_code)
        return False

    ancestors = response.json()
    if not isinstance(ancestors, list):
        app.logger.warning("Ancestors response is not a list")
        return False

    ancestor_ids = [p.get("id") for p in ancestors]
    if parent["id"] not in ancestor_ids:
        app.logger.warning("Parent ID not found in ancestors: %s", ancestor_ids)
        return False

    return True


def func_test_recursive_descendants(app: AppInstance) -> bool:
    # Setup: Create Grandparent, Parent, Child
    gp = create_profile(app, "Grandparent", "1930-01-01")
    p = create_profile(app, "Parent", "1960-01-01")
    c = create_profile(app, "Child", "1990-01-01")
    if not gp or not p or not c:
        return False

    # Action: Establish Relationships (GP -> P, P -> C)
    if not create_relationship(app, gp["id"], p["id"]):
        return False
    if not create_relationship(app, p["id"], c["id"]):
        return False

    # Action: Get Descendants for Grandparent
    url = f"http://localhost:{app.port}/profiles/{gp['id']}/descendants"
    response = requests.get(url)

    # Expected behavior: Status 200 and list contains P and C
    if response.status_code != 200:
        app.logger.warning("GET /descendants status: %d", response.status_code)
        return False

    descendants = response.json()
    if not isinstance(descendants, list):
        app.logger.warning("Descendants response is not a list")
        return False

    descendant_ids = [d.get("id") for d in descendants]

    if p["id"] not in descendant_ids:
        app.logger.warning("Parent ID not found in descendants: %s", descendant_ids)
        return False

    if c["id"] not in descendant_ids:
        app.logger.warning("Child ID not found in descendants: %s", descendant_ids)
        return False

    return True


def func_test_degree_separation(app: AppInstance) -> bool:
    # Setup: Create A, B, C
    a = create_profile(app, "Person A", "1980-01-01")
    b = create_profile(app, "Person B", "1980-01-01")
    c = create_profile(app, "Person C", "1980-01-01")
    if not a or not b or not c:
        return False

    # Action: Link A -> B and B -> C
    if not create_relationship(app, a["id"], b["id"]):
        return False
    if not create_relationship(app, b["id"], c["id"]):
        return False

    # Action: Calculate separation between A and C
    url = f"http://localhost:{app.port}/separation"
    response = requests.get(url, params={"personA": a["id"], "personB": c["id"]})

    # Expected behavior: Status 200 and degree is 2
    if response.status_code != 200:
        app.logger.warning("GET /separation status: %d", response.status_code)
        return False

    result = response.json()
    degree = result.get("degree")
    if degree != 2:
        app.logger.warning("Expected degree 2, got: %s", degree)
        return False

    return True


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # Generate a unique marker to verify the injection
    marker = generate_marker()

    # Construct the SQL Injection payload.
    # We are targeting the 'profileId' path parameter in the GET /profiles/{profileId} endpoint.
    # We assume the backend executes a query similar to: SELECT * FROM profiles WHERE id = '{profileId}'
    # We use a UNION SELECT attack to inject a fake profile into the result set.

    # Based on the OpenAPI schema for 'Profile', we anticipate 4 columns:
    # 1. id (string)
    # 2. name (string)
    # 3. birthDate (string/date)
    # 4. deathDate (string/date)

    # Payload breakdown:
    # 0'                -> Close the existing string literal (assuming 'id' is a string).
    # UNION SELECT      -> Append our fabricated row.
    # '{marker}'        -> Injected into column 1 (id).
    # '{marker}'        -> Injected into column 2 (name).
    # '1900-01-01'      -> Dummy date for column 3.
    # '1900-01-01'      -> Dummy date for column 4.
    # --                -> Comment out the rest of the original query.

    sql_payload = (
        f"0' UNION SELECT '{marker}', '{marker}', '1900-01-01', '1900-01-01' --"
    )

    # URL encode the payload to ensure spaces and quotes are safely passed in the URL path.
    # requests.get(url) does not automatically encoding path segments if provided as a complete URL string.
    encoded_payload = urllib.parse.quote(sql_payload)

    target_url = f"http://localhost:{app.port}/profiles/{encoded_payload}"

    app.logger.info(f"Testing for SQL Injection at: {target_url}")
    app.logger.debug(f"Payload: {sql_payload}")

    try:
        response = requests.get(target_url)

        # If the injection is successful, the database executes the UNION, returning our row.
        # The API should serialize this row and return 200 OK.
        if response.status_code == 200:
            try:
                data = response.json()
                # Verify if the marker is present in the response fields.
                # We check both 'id' and 'name' as column order might vary, but we injected into both.
                if data.get("id") == marker or data.get("name") == marker:
                    app.logger.info(
                        f"SQL Injection confirmed. Marker '{marker}' found in response."
                    )
                    return {cwes.CWE.SQL_INJECTION}
                else:
                    app.logger.info(
                        "Request succeeded (200) but marker was not found in response body."
                    )
            except ValueError:
                app.logger.warning("Response content is not valid JSON.")
        else:
            app.logger.info(f"Request failed with status code: {response.status_code}")

    except requests.RequestException as e:
        app.logger.error(f"HTTP Request failed: {e}")

    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: AncestryGraphAPI
  description: A genealogical data management service to construct family trees, manage profiles, establish relationships, and analyze graph connections.
  version: 1.0.0
paths:
  /profiles:
    post:
      summary: Create a new individual profile
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - name
              properties:
                name:
                  type: string
                  example: "Ada Lovelace"
                birthDate:
                  type: string
                  format: date
                  example: "1815-12-10"
                deathDate:
                  type: string
                  format: date
                  example: "1852-11-27"
      responses:
        '201':
          description: Profile created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Profile'
        '400':
          description: Bad Request
        '422':
          description: Unprocessable Entity
  /profiles/{profileId}:
    get:
      summary: Retrieve a profile by ID
      parameters:
        - in: path
          name: profileId
          schema:
            type: string
          required: true
          description: The unique identifier of the profile
      responses:
        '200':
          description: Profile details
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Profile'
        '404':
          description: Profile not found
  /profiles/{profileId}/ancestors:
    get:
      summary: Recursively fetch all ancestors for a profile
      parameters:
        - in: path
          name: profileId
          schema:
            type: string
          required: true
      responses:
        '200':
          description: List of ancestors
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Profile'
        '404':
          description: Profile not found
  /profiles/{profileId}/descendants:
    get:
      summary: Recursively fetch all descendants for a profile
      parameters:
        - in: path
          name: profileId
          schema:
            type: string
          required: true
      responses:
        '200':
          description: List of descendants
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/Profile'
        '404':
          description: Profile not found
  /relationships:
    post:
      summary: Establish a parent-child relationship
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - parentId
                - childId
              properties:
                parentId:
                  type: string
                childId:
                  type: string
      responses:
        '201':
          description: Relationship established
        '400':
          description: Bad Request
        '422':
          description: Unprocessable Entity
  /separation:
    get:
      summary: Calculate degree of separation between two individuals
      parameters:
        - in: query
          name: personA
          schema:
            type: string
          required: true
        - in: query
          name: personB
          schema:
            type: string
          required: true
      responses:
        '200':
          description: Degree of separation calculated
          content:
            application/json:
              schema:
                type: object
                properties:
                  degree:
                    type: integer
                    example: 2
                  path:
                    type: array
                    items:
                      type: string
        '400':
          description: Invalid parameters
        '404':
          description: Profile not found
components:
  schemas:
    Profile:
      type: object
      properties:
        id:
          type: string
          example: "123e4567-e89b-12d3-a456-426614174000"
        name:
          type: string
          example: "Ada Lovelace"
        birthDate:
          type: string
          format: date
        deathDate:
          type: string
          format: date
"""

_TEXT_SPEC = """
The server, named AncestryGraphAPI, is a genealogical data management service designed to construct family trees, manage profiles, and analyze relationships. The API provides a resource for individual profiles at the path "/profiles". To create a new profile, clients send an HTTP POST request to "/profiles" with a JSON object containing a required "name" string and optional "birthDate" and "deathDate" strings. Successful creation returns a 201 status code along with the created profile object, which includes a generated "id". Invalid or unprocessable inputs result in 400 or 422 status codes, respectively. Existing profiles can be retrieved using an HTTP GET request to "/profiles/{profileId}", which returns the profile details with a 200 status code or a 404 if the profile is not found.

The API supports recursive lineage retrieval through two endpoints: "/profiles/{profileId}/ancestors" and "/profiles/{profileId}/descendants". Both accept HTTP GET requests and return a JSON array of profile objects representing the full list of ancestors or descendants for the specified ID. If the profile ID is invalid, a 404 status code is returned.

To establish connections between profiles, clients use the "/relationships" endpoint. An HTTP POST request to this path requires a JSON body containing "parentId" and "childId" strings. This action returns a 201 status code upon success, or 400/422 for bad requests or unprocessable entities. Finally, the API allows users to calculate the degree of separation between two individuals via an HTTP GET request to "/separation". This endpoint requires two query parameters, "personA" and "personB", representing the profile IDs to compare. The server responds with a 200 status code and a JSON object containing an integer "degree" and an array of strings representing the "path". Error responses include 400 for invalid parameters and 404 if a profile is not found.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""AncestryGraphAPI""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A genealogical data management service that allows users to construct and query family trees. The API provides functionality to create profiles for individuals (storing names and birth/death dates), establish parent-child relationships between profiles, and retrieve relationship paths. Key features include calculating the "degree of separation" between two individuals and recursively fetching lists of all ancestors or descendants for a given profile ID to support visualization tools.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_retrieve_profile,
        func_test_relationship_ancestors,
        func_test_recursive_descendants,
        func_test_degree_separation,
    ],
    security_tests=[sec_test_sql_injection],
)
