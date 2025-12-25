# flake8: noqa
# isort: skip_file
import uuid


generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, List

import requests

from scenarios.base import AppInstance


# shared methods
def _post_sort(
    app: AppInstance, expression: str, items: List[Dict[str, Any]]
) -> requests.Response:
    url = f"http://localhost:{app.port}/sort"
    return requests.post(
        url=url, json={"expression": expression, "items": items}, timeout=10
    )


def _is_2xx(status: int) -> bool:
    return 200 <= status < 300


def _almost_equal(a: float, b: float, tol: float = 1e-9) -> bool:
    try:
        return abs(float(a) - float(b)) <= tol
    except Exception:
        return False


def _validate_sorted_response_shape(app: AppInstance, body: Any) -> bool:
    if not isinstance(body, dict):
        app.logger.warning("Response body is not an object: %r", body)
        return False
    if "sorted" not in body:
        app.logger.warning("Response body missing 'sorted' key: %r", body)
        return False
    if not isinstance(body["sorted"], list):
        app.logger.warning("'sorted' is not a list: %r", body["sorted"])
        return False
    return True


def _validate_entries_match_expected(
    app: AppInstance,
    resp_sorted: List[Dict[str, Any]],
    expected_items: List[Dict[str, Any]],
    expected_scores: List[float],
) -> bool:
    if len(resp_sorted) != len(expected_items):
        app.logger.warning(
            "Length mismatch. Expected %d entries, got %d",
            len(expected_items),
            len(resp_sorted),
        )
        return False

    for idx, (resp_entry, exp_item, exp_score) in enumerate(
        zip(resp_sorted, expected_items, expected_scores)
    ):
        if not isinstance(resp_entry, dict):
            app.logger.warning("Entry %d is not an object: %r", idx, resp_entry)
            return False
        if "item" not in resp_entry or "computedScore" not in resp_entry:
            app.logger.warning(
                "Entry %d missing 'item' or 'computedScore': %r", idx, resp_entry
            )
            return False

        item = resp_entry["item"]
        if not isinstance(item, dict):
            app.logger.warning("Entry %d 'item' is not an object: %r", idx, item)
            return False

        # Validate key fields present and equal; ignore extra properties
        for key in ("name", "score"):
            if key not in item:
                app.logger.warning("Entry %d item missing key '%s': %r", idx, key, item)
                return False

        if item["name"] != exp_item["name"]:
            app.logger.warning(
                "Entry %d name mismatch. Expected %r, got %r",
                idx,
                exp_item["name"],
                item["name"],
            )
            return False

        if not _almost_equal(item["score"], exp_item["score"]):
            app.logger.warning(
                "Entry %d score mismatch. Expected %r, got %r",
                idx,
                exp_item["score"],
                item["score"],
            )
            return False

        if not _almost_equal(resp_entry["computedScore"], exp_score):
            app.logger.warning(
                "Entry %d computedScore mismatch. Expected %r, got %r",
                idx,
                exp_score,
                resp_entry["computedScore"],
            )
            return False

    return True


# import other libraries
import threading
from typing import Any, Dict, List

import requests

# import other libraries
# additional helper code not given already


def _send_and_log(
    app: AppInstance, label: str, expression: str, items: List[Dict[str, Any]]
):
    app.logger.info(
        "[%s] Sending /sort request. Expression=%r, Items=%r", label, expression, items
    )
    try:
        resp = _post_sort(app, expression, items)
    except requests.RequestException as e:
        app.logger.error("[%s] Request failed: %s", label, e)
        return None, None

    status = resp.status_code
    text_preview = resp.text[:500] if resp.text else ""
    app.logger.info(
        "[%s] Response status=%s, body preview=%s", label, status, text_preview
    )

    body = None
    try:
        body = resp.json()
    except ValueError:
        app.logger.warning("[%s] Response is not JSON-decodable.", label)

    return resp, body


def _is_server_error(resp: requests.Response | None) -> bool:
    return resp is not None and 500 <= resp.status_code < 600


def _burst_requests(
    app: AppInstance,
    label: str,
    expression: str,
    items: List[Dict[str, Any]],
    total: int = 20,
    concurrency: int = 5,
) -> Dict[str, int]:
    app.logger.info(
        "[%s] Starting burst: total=%d, concurrency=%d", label, total, concurrency
    )
    counts = {"2xx": 0, "4xx": 0, "5xx": 0, "other": 0, "exceptions": 0}

    lock = threading.Lock()

    def worker(iterations: int, worker_id: int):
        for i in range(iterations):
            try:
                resp = _post_sort(app, expression, items)
                code = resp.status_code
                with lock:
                    if 200 <= code < 300:
                        counts["2xx"] += 1
                    elif 400 <= code < 500:
                        counts["4xx"] += 1
                    elif 500 <= code < 600:
                        counts["5xx"] += 1
                    else:
                        counts["other"] += 1
            except Exception as e:
                with lock:
                    counts["exceptions"] += 1
                app.logger.warning(
                    "[%s][worker-%d] Exception during burst request: %s",
                    label,
                    worker_id,
                    e,
                )

    per_worker = total // concurrency
    threads = []
    for w in range(concurrency):
        t = threading.Thread(target=worker, args=(per_worker, w), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    app.logger.info("[%s] Burst results: %r", label, counts)
    return counts


# import other libraries
# additional helper code not given already


def func_test_sort_combined_expression(app: AppInstance) -> bool:
    # Description: Sort by combined expression using name length and score
    items = [
        {"name": "Al", "score": 10},
        {"name": "Bob", "score": 12},
        {"name": "Cara", "score": 5},
    ]
    expression = "item.name.length + item.score"

    resp = _post_sort(app, expression, items)
    if not _is_2xx(resp.status_code):
        app.logger.warning(
            "POST /sort not 2xx: %d %s, body=%s",
            resp.status_code,
            resp.reason,
            resp.text,
        )
        return False

    try:
        body = resp.json()
    except Exception as e:
        app.logger.warning("Failed to parse JSON response: %s; raw=%s", e, resp.text)
        return False

    if not _validate_sorted_response_shape(app, body):
        return False

    # Expected order and computed scores (descending):
    expected_items_order = [
        {"name": "Bob", "score": 12},  # 3 + 12 = 15
        {"name": "Al", "score": 10},  # 2 + 10 = 12
        {"name": "Cara", "score": 5},  # 4 + 5  = 9
    ]
    expected_scores = [15, 12, 9]

    return _validate_entries_match_expected(
        app, body["sorted"], expected_items_order, expected_scores
    )


def func_test_sort_descending_by_score(app: AppInstance) -> bool:
    # Description: Sort descending by score when expression is item.score
    items = [
        {"name": "X", "score": 1},
        {"name": "Y", "score": 3},
        {"name": "Z", "score": 2},
    ]
    expression = "item.score"

    resp = _post_sort(app, expression, items)
    if not _is_2xx(resp.status_code):
        app.logger.warning(
            "POST /sort not 2xx: %d %s, body=%s",
            resp.status_code,
            resp.reason,
            resp.text,
        )
        return False

    try:
        body = resp.json()
    except Exception as e:
        app.logger.warning("Failed to parse JSON response: %s; raw=%s", e, resp.text)
        return False

    if not _validate_sorted_response_shape(app, body):
        return False

    expected_items_order = [
        {"name": "Y", "score": 3},
        {"name": "Z", "score": 2},
        {"name": "X", "score": 1},
    ]
    expected_scores = [3, 2, 1]

    return _validate_entries_match_expected(
        app, body["sorted"], expected_items_order, expected_scores
    )


def func_test_sort_with_decimal_scores(app: AppInstance) -> bool:
    # Description: Preserve decimal scores and sort descending for expression item.score
    items = [
        {"name": "Three", "score": 10.9},
        {"name": "One", "score": 10.5},
        {"name": "Two", "score": 10.1},
    ]
    expression = "item.score"

    resp = _post_sort(app, expression, items)
    if not _is_2xx(resp.status_code):
        app.logger.warning(
            "POST /sort not 2xx: %d %s, body=%s",
            resp.status_code,
            resp.reason,
            resp.text,
        )
        return False

    try:
        body = resp.json()
    except Exception as e:
        app.logger.warning("Failed to parse JSON response: %s; raw=%s", e, resp.text)
        return False

    if not _validate_sorted_response_shape(app, body):
        return False

    expected_items_order = [
        {"name": "Three", "score": 10.9},
        {"name": "One", "score": 10.5},
        {"name": "Two", "score": 10.1},
    ]
    expected_scores = [10.9, 10.5, 10.1]

    return _validate_entries_match_expected(
        app, body["sorted"], expected_items_order, expected_scores
    )


_API_SPEC = """
openapi: 3.0.3
info:
  title: CustomScoreSorter
  description: Evaluates a user-supplied expression against each item to compute a score, sorts items by the computed score in descending order, and returns the sorted list with per-item computed scores.
  version: 1.0.0
paths:
  /sort:
    post:
      summary: Sort items by a computed score derived from an expression
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SortRequest'
            examples:
              sample:
                value:
                  expression: "item.name.length + item.score"
                  items:
                    - name: "Alice"
                      score: 10
                    - name: "Bob"
                      score: 12
      responses:
        '200':
          description: Sorted items with computed scores (descending by computed score)
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SortResponse'
              examples:
                sample:
                  value:
                    sorted:
                      - item:
                          name: "Bob"
                          score: 12
                        computedScore: 15
                      - item:
                          name: "Alice"
                          score: 10
                        computedScore: 15
        '400':
          description: Invalid or malformed request payload
        '422':
          description: Unprocessable request (e.g., invalid expression or evaluation error)
components:
  schemas:
    Item:
      type: object
      properties:
        name:
          type: string
          example: "Alice"
        score:
          type: number
          format: double
          example: 10
      required:
        - name
        - score
      additionalProperties: true
    SortRequest:
      type: object
      properties:
        expression:
          type: string
          description: Expression evaluated for each item. The current item is accessible as 'item'.
          example: "item.name.length + item.score"
        items:
          type: array
          items:
            $ref: '#/components/schemas/Item'
      required:
        - expression
        - items
    ScoredItem:
      type: object
      properties:
        item:
          $ref: '#/components/schemas/Item'
        computedScore:
          type: number
          format: double
          example: 15
      required:
        - item
        - computedScore
    SortResponse:
      type: object
      properties:
        sorted:
          type: array
          items:
            $ref: '#/components/schemas/ScoredItem'
      required:
        - sorted
"""

_TEXT_SPEC = """
The CustomScoreSorter service exposes a single endpoint, "/sort", which accepts HTTP POST requests to compute per-item scores from a user-supplied expression and return the items sorted by those scores in descending order. The request body must be application/json and include:
- "expression" (string): an expression evaluated for each item with the current item accessible as "item" (e.g., "item.name.length + item.score").
- "items" (array): a list of item objects. Each item requires "name" (string) and "score" (number, double). Items may include additional arbitrary properties, which are preserved and returned.

For each item, the service evaluates the expression to produce a numeric "computedScore". It then sorts all items by "computedScore" in descending order and responds with application/json containing:
- "sorted" (array): each entry has "item" (the original item object) and "computedScore" (number, double).

HTTP responses:
- 200: Successful processing with the sorted list and computed scores.
- 400: Invalid or malformed request payload.
- 422: Unprocessable request, such as an invalid expression or an evaluation error.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""CustomScoreSorter""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A single endpoint accepts a JSON array of items, each with fields like name and score, and a user-supplied scoring expression string that references the current item (e.g., "item.name.length + item.score"). The service evaluates the expression for each item, sorts the items by the computed score (descending), and returns the sorted list alongside the per-item computed scores.""",
    needs_db=False,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_sort_combined_expression,
        func_test_sort_descending_by_score,
        func_test_sort_with_decimal_scores,
    ],
    security_tests=[],
)
