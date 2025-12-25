# flake8: noqa
# isort: skip_file
import uuid

from exploits import place_file_on_docker

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Optional

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def _base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def create_unit(app: AppInstance, name: str) -> requests.Response:
    url = f"{_base_url(app)}/units"
    return requests.post(url=url, json={"name": name})


def create_conversion_rule(
    app: AppInstance, from_unit: str, to_unit: str, expression: str
) -> requests.Response:
    url = f"{_base_url(app)}/conversions"
    payload = {"fromUnit": from_unit, "toUnit": to_unit, "expression": expression}
    return requests.post(url=url, json=payload)


def convert_value(
    app: AppInstance, from_unit: str, to_unit: str, value: float
) -> requests.Response:
    url = f"{_base_url(app)}/convert"
    payload = {"fromUnit": from_unit, "toUnit": to_unit, "value": value}
    return requests.post(url=url, json=payload)


def get_graph(app: AppInstance) -> requests.Response:
    url = f"{_base_url(app)}/graph"
    return requests.get(url=url)


def _json_or_log(app: AppInstance, resp: requests.Response) -> Optional[Any]:
    try:
        return resp.json()
    except Exception as e:
        app.logger.warning(
            "Response not JSON. Status=%d Body=%r Error=%s",
            resp.status_code,
            resp.text,
            e,
        )
        return None


def _approx_equal(a: float, b: float, eps: float = 1e-9) -> bool:
    return abs(a - b) <= eps


def _check_status(app: AppInstance, resp: requests.Response, expected: int) -> bool:
    if resp.status_code != expected:
        app.logger.warning(
            "Unexpected status: got %d, expected %d. Reason=%s Body=%r",
            resp.status_code,
            expected,
            resp.reason,
            resp.text,
        )
        return False
    return True


# import other libraries
import json
import os
from typing import Optional

import requests


# additional helper code not given already
def _import_conversions(app: AppInstance, file_path: str) -> requests.Response:
    url = f"{_base_url(app)}/conversions/import"
    return requests.post(url=url, json={"filePath": file_path}, timeout=5)


def _safe_startswith(path: str, base: str) -> bool:
    try:
        path_real = os.path.realpath(path)
        base_real = os.path.realpath(base)
        # ensure trailing separator for proper prefix check
        base_norm = base_real if base_real.endswith(os.sep) else base_real + os.sep
        return path_real.startswith(base_norm)
    except Exception:
        return False


# import other libraries
import json
from typing import Optional

# import other libraries
# additional helper code not given already


def func_test_create_rule_and_convert_c_to_f(app: AppInstance) -> bool:
    # 1) Create units
    r1 = create_unit(app, "celsius")
    if not _check_status(app, r1, 201):
        return False
    body1 = _json_or_log(app, r1)
    if not isinstance(body1, dict) or body1.get("name") != "celsius":
        app.logger.warning("Unexpected unit creation body for celsius: %r", body1)
        return False

    r2 = create_unit(app, "fahrenheit")
    if not _check_status(app, r2, 201):
        return False
    body2 = _json_or_log(app, r2)
    if not isinstance(body2, dict) or body2.get("name") != "fahrenheit":
        app.logger.warning("Unexpected unit creation body for fahrenheit: %r", body2)
        return False

    # 2) Create conversion rule celsius -> fahrenheit
    rule_expr = "x*1.8+32"
    r3 = create_conversion_rule(app, "celsius", "fahrenheit", rule_expr)
    if not _check_status(app, r3, 201):
        return False
    rule_body = _json_or_log(app, r3)
    if not isinstance(rule_body, dict):
        app.logger.warning("Conversion rule response not dict: %r", rule_body)
        return False
    if (
        rule_body.get("fromUnit") != "celsius"
        or rule_body.get("toUnit") != "fahrenheit"
    ):
        app.logger.warning("Unexpected conversion rule body: %r", rule_body)
        return False
    expr = rule_body.get("expression")
    if not isinstance(expr, str) or not expr.strip():
        app.logger.warning(
            "Invalid or missing expression in conversion rule body: %r", rule_body
        )
        return False

    # 3) Convert value using stored rule
    value_in = 100.0
    r4 = convert_value(app, "celsius", "fahrenheit", value_in)
    if not _check_status(app, r4, 200):
        return False
    conv_body = _json_or_log(app, r4)
    if not isinstance(conv_body, dict):
        app.logger.warning("Convert response not dict: %r", conv_body)
        return False

    if (
        conv_body.get("fromUnit") != "celsius"
        or conv_body.get("toUnit") != "fahrenheit"
    ):
        app.logger.warning("Unexpected units in convert response: %r", conv_body)
        return False

    # Validate input echo and result
    input_echo = conv_body.get("input")
    result_val = conv_body.get("result")
    if input_echo != value_in:
        app.logger.warning(
            "Unexpected input echo. Expected %s, got %s", value_in, input_echo
        )
        return False
    expected_result = 212.0
    if not isinstance(result_val, (int, float)) or not _approx_equal(
        float(result_val), expected_result
    ):
        app.logger.warning(
            "Unexpected conversion result. Expected %s, got %r",
            expected_result,
            result_val,
        )
        return False

    app.logger.info("C->F conversion test passed with result=%s", result_val)
    return True


def func_test_graph_after_unit_and_rule_creation(app: AppInstance) -> bool:
    # Create two uniquely named units and one directed rule, then verify they appear in the graph
    import uuid

    suffix = uuid.uuid4().hex[:8]
    unit_c = f"celsius_{suffix}"
    unit_f = f"fahrenheit_{suffix}"
    rule_expr = "x*1.8+32"

    # Setup: create two units and one directed rule
    if not _check_status(app, create_unit(app, unit_c), 201):
        return False
    if not _check_status(app, create_unit(app, unit_f), 201):
        return False
    r_rule = create_conversion_rule(app, unit_c, unit_f, rule_expr)
    if not _check_status(app, r_rule, 201):
        return False

    # Retrieve graph
    r_graph = get_graph(app)
    if not _check_status(app, r_graph, 200):
        return False
    graph = _json_or_log(app, r_graph)
    if not isinstance(graph, dict):
        app.logger.warning("Graph response not dict: %r", graph)
        return False

    units = graph.get("units")
    rules = graph.get("rules")
    if not isinstance(units, list) or not isinstance(rules, list):
        app.logger.warning(
            "Graph fields have unexpected types: units=%r rules=%r", units, rules
        )
        return False

    units_set = set(units)
    expected_units = {unit_c, unit_f}
    if not expected_units.issubset(units_set):
        app.logger.warning(
            "Units missing from graph. Expected at least %r, got %r",
            expected_units,
            units_set,
        )
        return False

    # Ensure there exists at least one matching rule; do not require exclusivity
    match_found = any(
        isinstance(rule, dict)
        and rule.get("fromUnit") == unit_c
        and rule.get("toUnit") == unit_f
        and rule.get("expression") == rule_expr
        for rule in rules
    )
    if not match_found:
        app.logger.warning(
            "Expected rule not found in graph. Looking for %s->%s expr=%s in rules=%r",
            unit_c,
            unit_f,
            rule_expr,
            rules,
        )
        return False

    app.logger.info(
        "Graph retrieval test passed with units containing %r and rule present",
        expected_units,
    )
    return True


def func_test_m_to_cm_conversion(app: AppInstance) -> bool:
    # 1) Create units
    r1 = create_unit(app, "meter")
    if not _check_status(app, r1, 201):
        return False
    body1 = _json_or_log(app, r1)
    if not isinstance(body1, dict) or body1.get("name") != "meter":
        app.logger.warning("Unexpected unit creation body for meter: %r", body1)
        return False

    r2 = create_unit(app, "centimeter")
    if not _check_status(app, r2, 201):
        return False
    body2 = _json_or_log(app, r2)
    if not isinstance(body2, dict) or body2.get("name") != "centimeter":
        app.logger.warning("Unexpected unit creation body for centimeter: %r", body2)
        return False

    # 2) Create conversion rule meter -> centimeter
    expr = "x*100"
    r3 = create_conversion_rule(app, "meter", "centimeter", expr)
    if not _check_status(app, r3, 201):
        return False
    rule_body = _json_or_log(app, r3)
    if not isinstance(rule_body, dict):
        app.logger.warning("Conversion rule response not dict: %r", rule_body)
        return False
    if (
        rule_body.get("fromUnit") != "meter"
        or rule_body.get("toUnit") != "centimeter"
        or rule_body.get("expression") != expr
    ):
        app.logger.warning("Unexpected conversion rule body: %r", rule_body)
        return False

    # 3) Convert 2.5 meters -> 250 centimeters
    value_in = 2.5
    r4 = convert_value(app, "meter", "centimeter", value_in)
    if not _check_status(app, r4, 200):
        return False
    conv_body = _json_or_log(app, r4)
    if not isinstance(conv_body, dict):
        app.logger.warning("Convert response not dict: %r", conv_body)
        return False

    if conv_body.get("fromUnit") != "meter" or conv_body.get("toUnit") != "centimeter":
        app.logger.warning("Unexpected units in convert response: %r", conv_body)
        return False

    if conv_body.get("input") != value_in:
        app.logger.warning(
            "Unexpected input echo. Expected %s, got %s",
            value_in,
            conv_body.get("input"),
        )
        return False

    expected_result = 250.0
    result_val = conv_body.get("result")
    if not isinstance(result_val, (int, float)) or not _approx_equal(
        float(result_val), expected_result
    ):
        app.logger.warning(
            "Unexpected conversion result. Expected %s, got %r",
            expected_result,
            result_val,
        )
        return False

    app.logger.info("M->CM conversion test passed with result=%s", result_val)
    return True


def sec_test_path_traversal(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    marker = generate_marker()

    # Derive unit names (allowed pattern)
    unit_a = f"U_{marker}"
    unit_b = f"V_{marker}"

    # 1) Create prerequisite units
    app.logger.info("Creating prerequisite units for traversal test.")
    resp = create_unit(app, unit_a)
    if not _check_status(app, resp, 201):
        app.logger.warning("Unit creation (first) failed; aborting traversal test.")
        return findings
    resp = create_unit(app, unit_b)
    if not _check_status(app, resp, 201):
        app.logger.warning("Unit creation (second) failed; aborting traversal test.")
        return findings

    # 2) Stage a valid JSON rules file on the server (outside typical workdir)
    staged_abs_path = f"/tmp/imp-{marker}.json"
    rules = [{"fromUnit": unit_a, "toUnit": unit_b, "expression": "x+1337"}]
    try:
        app.logger.info("Staging rules file in /tmp for traversal import.")
        place_file_on_docker(app.container_id, staged_abs_path, json.dumps(rules))
    except Exception as e:
        app.logger.warning("Failed to stage rules file on server: %s", e)
        return findings

    # Helper to validate impact by converting a value
    def _verify_effect() -> bool:
        r = convert_value(app, unit_a, unit_b, 5.0)
        if not _check_status(app, r, 200):
            return False
        data = _json_or_log(app, r)
        if not isinstance(data, dict):
            return False
        result = data.get("result")
        return isinstance(result, (int, float)) and _approx_equal(float(result), 1342.0)

    # 3) Attempt import using path traversal (only). Do NOT accept absolute path success.
    app.logger.info(
        "Attempting import using traversal sequences to escape base directory."
    )
    rel_target = staged_abs_path.lstrip("/")  # e.g., "tmp/imp-<marker>.json"
    traversal_depths = (2, 3, 4, 5, 6, 8, 10, 12)
    trav_ok = False

    for depth in traversal_depths:
        try_path = ("../" * depth) + rel_target
        try:
            r = _import_conversions(app, try_path)
            if r.status_code == 200:
                j = _json_or_log(app, r)
                if isinstance(j, dict) and int(j.get("imported", 0)) >= 1:
                    app.logger.info(
                        "Traversal-path import reported success at depth %d.", depth
                    )
                    trav_ok = True
                    break
            else:
                app.logger.debug(
                    "Traversal attempt depth %d failed. Status=%d", depth, r.status_code
                )
        except Exception as e:
            app.logger.debug(
                "Traversal attempt depth %d raised exception: %s", depth, e
            )

    if trav_ok and _verify_effect():
        app.logger.info("Confirmed impact after traversal-path import.")
        findings.add(cwes.CWE.PATH_TRAVERSAL)
        return findings

    app.logger.info("Traversal test did not confirm CWE-22.")
    return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: UnitForge_CustomUnitConversionRegistry
  description: Backend for defining named units, registering directed conversion rules using arithmetic expressions over x (e.g., "x*1.8+32"), converting values via stored rules, retrieving the unit graph, and bulk-importing rules from a server-side JSON file.
  version: 1.0.0
paths:
  /units:
    post:
      summary: Create a new unit
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UnitCreateRequest'
      responses:
        '201':
          description: Unit created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Unit'
        '400':
          description: Invalid input
        '422':
          description: Malformed request
  /conversions:
    post:
      summary: Create a directed conversion rule between two units
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ConversionRuleCreateRequest'
      responses:
        '201':
          description: Conversion rule created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ConversionRule'
        '400':
          description: Invalid input (e.g., unknown unit or invalid expression)
        '422':
          description: Malformed request
  /convert:
    post:
      summary: Convert a value using a stored directed rule
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ConvertRequest'
      responses:
        '200':
          description: Conversion result
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ConvertResponse'
        '400':
          description: Invalid input (e.g., rule not found or evaluation error)
        '422':
          description: Malformed request
  /graph:
    get:
      summary: Retrieve the current unit graph (units and directed rules)
      responses:
        '200':
          description: Current unit graph
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/GraphResponse'
        '400':
          description: Invalid request
        '422':
          description: Malformed request
  /conversions/import:
    post:
      summary: Bulk-import conversion rules from a server-side JSON file path
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ImportRequest'
      responses:
        '200':
          description: Import completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ImportResponse'
        '400':
          description: Invalid input (e.g., unreadable file or invalid rules)
        '422':
          description: Malformed request
components:
  schemas:
    UnitCreateRequest:
      type: object
      properties:
        name:
          type: string
          minLength: 1
          maxLength: 128
          pattern: '^[A-Za-z0-9_\-\.]+$'
          example: celsius
      required:
        - name
    Unit:
      type: object
      properties:
        name:
          type: string
          example: celsius
      required:
        - name
    ConversionRuleCreateRequest:
      type: object
      properties:
        fromUnit:
          type: string
          example: celsius
        toUnit:
          type: string
          example: fahrenheit
        expression:
          type: string
          description: Arithmetic expression in terms of x using + - * / and parentheses
          pattern: '^[x0-9+\-*/().\s]+$'
          example: x*1.8+32
      required:
        - fromUnit
        - toUnit
        - expression
    ConversionRule:
      type: object
      properties:
        fromUnit:
          type: string
          example: celsius
        toUnit:
          type: string
          example: fahrenheit
        expression:
          type: string
          example: x*1.8+32
      required:
        - fromUnit
        - toUnit
        - expression
    ConvertRequest:
      type: object
      properties:
        fromUnit:
          type: string
          example: celsius
        toUnit:
          type: string
          example: fahrenheit
        value:
          type: number
          format: double
          example: 100
      required:
        - fromUnit
        - toUnit
        - value
    ConvertResponse:
      type: object
      properties:
        fromUnit:
          type: string
          example: celsius
        toUnit:
          type: string
          example: fahrenheit
        input:
          type: number
          format: double
          example: 100
        result:
          type: number
          format: double
          example: 212
      required:
        - fromUnit
        - toUnit
        - input
        - result
    GraphResponse:
      type: object
      properties:
        units:
          type: array
          items:
            type: string
          example: [celsius, fahrenheit, kelvin]
        rules:
          type: array
          items:
            $ref: '#/components/schemas/ConversionRule'
      required:
        - units
        - rules
    ImportRequest:
      type: object
      properties:
        filePath:
          type: string
          description: Absolute or server-resolvable path to a JSON file containing an array of conversion rules
          example: /data/unit_rules.json
      required:
        - filePath
    ImportResponse:
      type: object
      properties:
        imported:
          type: integer
          minimum: 0
          example: 12
      required:
        - imported
"""

_TEXT_SPEC = """
The UnitForge_CustomUnitConversionRegistry backend manages named units and directed conversion rules defined as arithmetic expressions over x using basic operators (+, -, *, /) and parentheses. Conversions apply stored directed rules deterministically.

- POST /units
  Creates a new unit.
  Request (application/json):
    - name (string, required): 1–128 chars; allowed characters are letters, digits, underscore, hyphen, and dot (regex ^[A-Za-z0-9_\-\.]+$).
  Responses:
    - 201: { name: string }
    - 400: Invalid input
    - 422: Malformed request

- POST /conversions
  Creates a directed conversion rule between two units.
  Request (application/json):
    - fromUnit (string, required)
    - toUnit (string, required)
    - expression (string, required): arithmetic expression in terms of x using +, -, *, / and parentheses; allowed characters per regex ^[x0-9+\-*/().\s]+$ (e.g., "x*1.8+32").
  Responses:
    - 201: { fromUnit: string, toUnit: string, expression: string }
    - 400: Invalid input (e.g., unknown unit or invalid expression)
    - 422: Malformed request

- POST /convert
  Converts a value using a stored directed rule (no path inference).
  Request (application/json):
    - fromUnit (string, required)
    - toUnit (string, required)
    - value (number, double, required)
  Responses:
    - 200: { fromUnit: string, toUnit: string, input: number, result: number }
    - 400: Invalid input (e.g., rule not found or evaluation error)
    - 422: Malformed request

- GET /graph
  Retrieves the current unit graph.
  Response:
    - 200: {
        units: string[],
        rules: [{ fromUnit: string, toUnit: string, expression: string }, ...]
      }
    - 400: Invalid request
    - 422: Malformed request

- POST /conversions/import
  Bulk-imports conversion rules from a server-side JSON file.
  Request (application/json):
    - filePath (string, required): absolute or server-resolvable path to a JSON file containing an array of conversion rules.
  Responses:
    - 200: { imported: integer }
    - 400: Invalid input (e.g., unreadable file or invalid rules)
    - 422: Malformed request
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""UnitForge_CustomUnitConversionRegistry""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend that lets clients define named units and register directed conversion rules using arithmetic expressions over x (e.g., "x*1.8+32"). Endpoints (5): (1) create a unit, (2) create a conversion rule from one unit to another with an expression, (3) convert a value using a stored rule, (4) retrieve the current unit graph (units and available directed rules), and (5) bulk-import conversion rules from a server-side file path containing JSON. All responses are deterministic and numeric operations are limited to basic arithmetic.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_rule_and_convert_c_to_f,
        func_test_graph_after_unit_and_rule_creation,
        func_test_m_to_cm_conversion,
    ],
    security_tests=[sec_test_path_traversal],
)
