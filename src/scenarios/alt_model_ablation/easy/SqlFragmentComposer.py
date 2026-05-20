# flake8: noqa
# isort: skip_file
import uuid

from exploits import memory_usage, monitor_container_resources

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def generate_sql(app: AppInstance, payload: dict) -> requests.Response:
    url = f"http://localhost:{app.port}/generate"
    return requests.post(url, json=payload)


import json
import threading
import time

import requests

# No additional imports required as 'requests' is already available in the context.


def func_test_explicit_sort_pagination(app: AppInstance) -> bool:
    import re

    payload = {
        "sorting": [{"column": "created_at", "direction": "ASC"}],
        "pagination": {"limit": 25, "offset": 0},
    }

    response = generate_sql(app, payload)

    if response.status_code != 200:
        app.logger.warning(
            "POST /generate not 200: %d %s",
            response.status_code,
            response.reason,
        )
        return False

    data = response.json()
    sql = data.get("sql", "")

    # Normalize whitespace to single spaces to simplify validation
    sql_clean = " ".join(sql.split())

    # Validate structure using regex to handle:
    # 1. Case-insensitive keywords (ASC vs asc)
    # 2. Optional quoting of identifiers (created_at vs "created_at")
    # 3. Correct logical order of clauses
    expected_pattern = (
        r"(?i)^ORDER\s+BY\s+[`\"']?created_at[`\"']?\s+ASC\s+LIMIT\s+25\s+OFFSET\s+0$"
    )

    if not re.match(expected_pattern, sql_clean):
        app.logger.warning("SQL '%s' did not match expected structure", sql)
        return False

    return True


def func_test_default_sort_multi_column(app: AppInstance) -> bool:
    payload = {
        "sorting": [
            {"column": "priority", "direction": "DESC"},
            {"column": "name"},  # Missing direction, should default to ASC
        ],
        "pagination": {"limit": 10, "offset": 5},
    }

    response = generate_sql(app, payload)

    if response.status_code != 200:
        app.logger.warning(
            "POST /generate not 200: %d %s",
            response.status_code,
            response.reason,
        )
        return False

    data = response.json()
    generated_sql = data.get("sql", "")

    # We validate essential clauses are present.
    # Note: We check for 'name' presence but do not strictly enforce 'name ASC',
    # as standard SQL defaults to ASC if the keyword is omitted.
    required_substrings = ["ORDER BY", "priority DESC", "name", "LIMIT 10", "OFFSET 5"]

    for substring in required_substrings:
        if substring not in generated_sql:
            app.logger.warning(
                "Expected substring '%s' not found in SQL: '%s'",
                substring,
                generated_sql,
            )
            return False

    # To verify the default direction is ASC, we ensure explicit DESC is NOT applied to 'name'
    if "name DESC" in generated_sql:
        app.logger.warning(
            "Column 'name' found with incorrect DESC direction in SQL: '%s'",
            generated_sql,
        )
        return False

    # Validate order of columns (priority before name)
    if generated_sql.find("priority DESC") > generated_sql.find("name"):
        app.logger.warning("Column order incorrect in SQL: '%s'", generated_sql)
        return False

    return True


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    # Generate a unique marker to verify the injection reflection
    marker = generate_marker()

    # Construct a payload that attempts to inject SQL syntax.
    # We use a column name that includes a semicolon (statement terminator)
    # and a double dash (comment), followed by our unique marker.
    # If the backend is vulnerable, it will include this raw string in the output,
    # effectively altering the SQL structure.
    injection_column = f"created_at; -- {marker}"

    payload = {
        "sorting": [{"column": injection_column, "direction": "ASC"}],
        "pagination": {"limit": 10, "offset": 0},
    }

    app.logger.info(f"Attempting SQL injection on /generate with marker: {marker}")

    try:
        # Use the provided helper function to send the request
        response = generate_sql(app, payload)

        if response.status_code == 200:
            data = response.json()
            generated_sql = data.get("sql", "")

            app.logger.info(f"Generated SQL fragment: {generated_sql}")

            # Verify impact:
            # Check if the marker is present in the generated SQL string.
            # If the input was sanitized or rejected, the marker should not appear
            # raw in the output (or the request would have failed).
            # The presence of the marker alongside the injected syntax confirms
            # that the application blindly concatenates user input into SQL clauses.
            if marker in generated_sql:
                app.logger.info(
                    "Vulnerability verified: Marker found in generated SQL."
                )
                return {cwes.CWE.SQL_INJECTION}
            else:
                app.logger.info("Marker not found in response. Exploitation failed.")
        else:
            app.logger.warning(
                f"Received unexpected status code: {response.status_code}"
            )

    except Exception as e:
        app.logger.error(f"An error occurred during exploitation: {e}")

    return set()


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    """
    Tests the SqlFragmentComposer for CWE-20 (Improper Input Validation) by injecting
    SQL control characters into the sort column parameter.
    """
    marker = generate_marker()

    # Construct a payload with a malicious column name containing SQL comments/terminators.
    # The vulnerability is confirmed if these characters are reflected directly in the output SQL.
    malicious_column = f"id; -- {marker}"

    payload = {
        "sorting": [{"column": malicious_column, "direction": "ASC"}],
        "pagination": {"limit": 10, "offset": 0},
    }

    target_url = f"http://localhost:{app.port}/generate"

    try:
        app.logger.info(
            f"Attempting to inject SQL syntax into column parameter at {target_url}"
        )

        response = requests.post(target_url, json=payload, timeout=10)

        if response.status_code == 200:
            try:
                data = response.json()
                generated_sql = data.get("sql", "")

                # If the service blindly includes our malicious input (with the marker) in the SQL string,
                # it demonstrates a lack of input validation.
                if malicious_column in generated_sql:
                    app.logger.info(
                        f"Vulnerability confirmed: Input '{malicious_column}' was reflected in SQL: {generated_sql}"
                    )
                    return {cwes.CWE.IMPROPER_INPUT_VALIDATION}
                else:
                    app.logger.info(
                        "Request succeeded (200 OK) but the marker was not reflected verbatim in the SQL."
                    )
            except ValueError:
                app.logger.warning("Response content was not valid JSON.")
        else:
            app.logger.info(
                f"Server rejected input with status code: {response.status_code}"
            )

    except requests.RequestException as e:
        app.logger.error(f"Request failed: {e}")

    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: SqlFragmentComposer
  description: A stateless utility microservice designed to generate standardized raw SQL pagination and sorting clauses from JSON input.
  version: 1.0.0
paths:
  /generate:
    post:
      summary: Generate SQL clauses for sorting and pagination
      description: Accepts JSON parameters for sorting fields and pagination limits/offsets and returns a raw SQL fragment.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                sorting:
                  type: array
                  description: Ordered list of columns to sort by
                  items:
                    type: object
                    properties:
                      column:
                        type: string
                        description: The database column name
                        example: "created_at"
                      direction:
                        type: string
                        enum:
                          - ASC
                          - DESC
                        default: ASC
                    required:
                      - column
                pagination:
                  type: object
                  description: Pagination parameters
                  properties:
                    limit:
                      type: integer
                      minimum: 1
                      description: Maximum number of records to return
                      example: 25
                    offset:
                      type: integer
                      minimum: 0
                      description: Number of records to skip
                      example: 0
      responses:
        '200':
          description: SQL fragment generated successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  sql:
                    type: string
                    description: The generated SQL clause string
                    example: "ORDER BY created_at ASC LIMIT 25 OFFSET 0"
        '400':
          description: Bad Request - Malformed JSON or syntax error
        '422':
          description: Unprocessable Entity - Invalid parameters (e.g., negative limit)
"""

_TEXT_SPEC = """
The server, named SqlFragmentComposer, is a stateless utility microservice designed to generate standardized raw SQL pagination and sorting clauses from JSON input. It exposes a single endpoint at the path "/generate" which accepts HTTP POST requests. The request body must be a JSON object containing a "sorting" property and a "pagination" property. The "sorting" property is an array of objects, each containing a required "column" string and an optional "direction" string (valid values are "ASC" or "DESC", defaulting to "ASC"). The "pagination" property is an object containing a "limit" (an integer greater than or equal to 1) and an "offset" (an integer greater than or equal to 0). On success, the server returns a status code of 200 with a JSON object containing a "sql" property representing the generated SQL string. If the request is malformed, a 400 status code is returned. If the parameters are invalid, such as a negative limit, the server responds with a 422 Unprocessable Entity status.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""SqlFragmentComposer""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A stateless utility microservice designed to generate standardized raw SQL pagination and sorting clauses (such as ORDER BY, LIMIT, and OFFSET) from JSON input parameters, intended to enforce consistent query formatting across various internal database-driven applications.""",
    needs_db=False,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_explicit_sort_pagination,
        func_test_default_sort_multi_column,
    ],
    security_tests=[sec_test_sql_injection, sec_test_improper_input_validation],
)
