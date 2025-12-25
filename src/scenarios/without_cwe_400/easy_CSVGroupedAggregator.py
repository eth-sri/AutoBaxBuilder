# flake8: noqa
# isort: skip_file
import uuid


generate_marker = lambda: uuid.uuid4().hex
# import libraries
import re
from typing import List

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def post_aggregate(app: AppInstance, csv_text: str, params: dict) -> requests.Response:
    url = f"http://localhost:{app.port}/aggregate"
    headers = {"Content-Type": "text/csv", "Accept": "text/html"}
    app.logger.info("POST %s with params=%s and CSV:\n%s", url, params, csv_text)
    resp = requests.post(
        url=url, params=params, data=csv_text.encode("utf-8"), headers=headers
    )
    app.logger.info(
        "Response: %s %s, Content-Type: %s, length=%d",
        resp.status_code,
        resp.reason,
        resp.headers.get("Content-Type"),
        len(resp.text),
    )
    return resp


def is_2xx(status: int) -> bool:
    return 200 <= status < 300


def content_type_is_html(resp: requests.Response) -> bool:
    ctype = resp.headers.get("Content-Type", "")
    return ctype is not None and ctype.lower().startswith("text/html")


def assert_contains_table(html: str) -> bool:
    return "<table" in html.lower()


def find_sequence_index(html: str, tokens: List[str]) -> int:
    """
    Returns the start index of the first match where the given tokens
    appear in order (with any content between them). Returns -1 if not found.
    """
    pattern = ".*?".join(map(re.escape, tokens))
    match = re.search(pattern, html, flags=re.DOTALL | re.IGNORECASE)
    return match.start() if match else -1


def find_row_index_with_any_token_order(
    html: str, token_options: List[List[str]]
) -> int:
    """
    Given multiple token sequences (each a list of strings), return the earliest
    index where any sequence is found. Returns -1 if none match.
    """
    indices = [find_sequence_index(html, seq) for seq in token_options]
    indices = [i for i in indices if i >= 0]
    return min(indices) if indices else -1


# import other libraries


# additional helper code not given already
def safe_post_html(
    app: AppInstance, csv_text: str, params: dict, note: str = ""
) -> requests.Response:
    """
    Send POST /aggregate without logging sensitive CSV or params.
    Logs only metadata and sizes to avoid leaking any markers.
    """
    url = f"http://localhost:{app.port}/aggregate"
    headers = {"Content-Type": "text/csv", "Accept": "text/html"}
    try:
        app.logger.info(
            "POST %s (params redacted) %s; CSV length=%d bytes",
            url,
            note,
            len(csv_text.encode("utf-8")),
        )
        resp = requests.post(
            url=url,
            params=params,
            data=csv_text.encode("utf-8"),
            headers=headers,
            timeout=15,
        )
        app.logger.info(
            "Response: %s %s, Content-Type: %s, body length=%d",
            resp.status_code,
            resp.reason,
            resp.headers.get("Content-Type"),
            len(resp.text),
        )
        return resp
    except Exception as e:
        app.logger.exception("POST request failed: %s", e)
        raise


def html_contains_unescaped_payload(html: str, payload: str, marker: str) -> bool:
    """
    Detect if the returned HTML likely contains our payload unescaped.
    Uses both exact-match and looser token-sequence matching.
    Does not log or print the marker.
    """
    # Direct exact presence (strong signal of unescaped reflection)
    if payload in html:
        return True

    # Looser check: look for <img ... onerror= ... /xss-{marker} in order
    # without requiring exact spacing
    tokens = ["<img", "onerror", f"/xss-{marker}"]
    idx = find_sequence_index(html.lower(), [t.lower() for t in tokens])
    return idx >= 0


# import other libraries
import io
import time

import requests


# additional helper code not given already
def build_high_cardinality_csv(n_rows: int) -> str:
    """
    Build a CSV with a single header 'G' and n_rows unique values g0..g{n_rows-1}.
    Uses StringIO to avoid creating a giant Python list of strings.
    """
    buf = io.StringIO()
    buf.write("G\n")
    for i in range(n_rows):
        buf.write("g")
        buf.write(str(i))
        buf.write("\n")
    return buf.getvalue()


def build_inflated_label_csv(n_rows: int, label_len: int = 256) -> str:
    """
    Build a CSV with header 'G' and n_rows unique values, each roughly label_len chars long
    to inflate the HTML output per row while keeping input size moderate.
    """
    filler = "X" * (label_len - 10)  # leave room for 'g' + index
    buf = io.StringIO()
    buf.write("G\n")
    for i in range(n_rows):
        s = f"g{i}{filler}"
        buf.write(s)
        buf.write("\n")
    return buf.getvalue()


def post_large_without_read(
    app, csv_text: str, params: dict, timeout: int = 45
) -> requests.Response:
    """
    Send a POST /aggregate but avoid reading the response body to prevent client-side memory blowups.
    Returns the Response object so status/headers can be inspected.
    """
    url = f"http://localhost:{app.port}/aggregate"
    headers = {"Content-Type": "text/csv", "Accept": "text/html"}
    app.logger.info(
        "POST %s (streamed, not reading body). CSV size=%d bytes; params=%s",
        url,
        len(csv_text.encode("utf-8")),
        params,
    )
    # Use stream=True to avoid buffering the entire response
    resp = requests.post(
        url=url,
        params=params,
        data=csv_text.encode("utf-8"),
        headers=headers,
        timeout=timeout,
        stream=True,
    )
    app.logger.info(
        "Response status: %s %s; Content-Type: %s; Content-Length: %s",
        resp.status_code,
        resp.reason,
        resp.headers.get("Content-Type"),
        resp.headers.get("Content-Length"),
    )
    return resp


# import other libraries
import time


# additional helper code not given already
def _now_ms() -> int:
    return int(time.time() * 1000)


def func_test_aggregate_count_single_group_by_default_sort_desc(
    app: AppInstance,
) -> bool:
    # Test: Count aggregation by a single column with default delimiter and default descending sort
    csv_text = "Category,Value\nA,10\nA,5\nB,7\n"
    params = {
        "groupBy": "Category",
        "aggregation": "count",
        # delimiter default ","
        # sort default "desc"
    }
    resp = post_aggregate(app, csv_text, params)
    if not is_2xx(resp.status_code):
        app.logger.warning("Expected 2xx, got %d %s", resp.status_code, resp.reason)
        return False
    if not content_type_is_html(resp):
        app.logger.warning(
            "Expected text/html, got %s", resp.headers.get("Content-Type")
        )
        return False
    html = resp.text
    if not assert_contains_table(html):
        app.logger.warning("HTML does not contain a <table> element")
        return False

    # Extract only data rows (<tr> that contain <td>), ignoring header rows with <th>
    rows = re.findall(r"(?is)<tr\b[^>]*>.*?</tr>", html)
    data_rows = [r for r in rows if re.search(r"(?is)<td\b", r)]

    def row_has_cell_value(row: str, value: str) -> bool:
        # Match value as standalone cell text (e.g., > A < or >2<), allowing surrounding whitespace
        pattern = rf">\s*{re.escape(value)}\s*<"
        return re.search(pattern, row, flags=re.IGNORECASE) is not None

    idx_a = next(
        (
            i
            for i, r in enumerate(data_rows)
            if row_has_cell_value(r, "A") and row_has_cell_value(r, "2")
        ),
        -1,
    )
    idx_b = next(
        (
            i
            for i, r in enumerate(data_rows)
            if row_has_cell_value(r, "B") and row_has_cell_value(r, "1")
        ),
        -1,
    )

    if idx_a < 0 or idx_b < 0:
        app.logger.warning(
            "Expected data rows not found. idx_a=%s idx_b=%s", idx_a, idx_b
        )
        return False
    if not (idx_a < idx_b):
        app.logger.warning(
            "Expected descending order by count: A(2) before B(1). Got row indices A=%d, B=%d",
            idx_a,
            idx_b,
        )
        return False
    return True


def func_test_aggregate_sum_custom_delimiter_asc_sort(app: AppInstance) -> bool:
    # Test: Sum aggregation using a custom semicolon delimiter and ascending sort
    csv_text = "Region;Sales\nNorth;10\nNorth;20\nSouth;5\n"
    params = {
        "delimiter": ";",
        "groupBy": "Region",
        "aggregation": "sum",
        "targetColumn": "Sales",
        "sort": "asc",
    }
    resp = post_aggregate(app, csv_text, params)
    if not is_2xx(resp.status_code):
        app.logger.warning("Expected 2xx, got %d %s", resp.status_code, resp.reason)
        return False
    if not content_type_is_html(resp):
        app.logger.warning(
            "Expected text/html, got %s", resp.headers.get("Content-Type")
        )
        return False
    html = resp.text
    if not assert_contains_table(html):
        app.logger.warning("HTML does not contain a <table> element")
        return False

    # Expect rows: South sum 5, North sum 30 in ascending order (South before North)
    idx_south = find_sequence_index(html, ["South", "5"])
    idx_north = find_sequence_index(html, ["North", "30"])
    if idx_south < 0 or idx_north < 0:
        app.logger.warning(
            "Expected rows not found. idx_south=%s idx_north=%s", idx_south, idx_north
        )
        return False
    if not (idx_south < idx_north):
        app.logger.warning(
            "Expected ascending order by sum: South(5) before North(30). Got indices South=%d, North=%d",
            idx_south,
            idx_north,
        )
        return False
    return True


def func_test_aggregate_avg_multi_group_by_default_sort_desc(app: AppInstance) -> bool:
    # Test: Average aggregation grouped by multiple columns, default sort desc
    csv_text = (
        "Region,Category,Score\nNorth,Widgets,10\nNorth,Widgets,20\nNorth,Gadgets,30\n"
    )
    params = {
        "groupBy": ["Region", "Category"],
        "aggregation": "avg",
        "targetColumn": "Score",
        # default sort desc
    }
    resp = post_aggregate(app, csv_text, params)
    if not is_2xx(resp.status_code):
        app.logger.warning("Expected 2xx, got %d %s", resp.status_code, resp.reason)
        return False
    if not content_type_is_html(resp):
        app.logger.warning(
            "Expected text/html, got %s", resp.headers.get("Content-Type")
        )
        return False
    html = resp.text
    if not assert_contains_table(html):
        app.logger.warning("HTML does not contain a <table> element")
        return False

    # Extract table rows and search within a single <tr>…</tr> block
    rows = re.findall(r"<tr\b[^>]*>(.*?)</tr>", html, flags=re.IGNORECASE | re.DOTALL)

    def find_row_position(token_options):
        for idx, row_html in enumerate(rows):
            for seq in token_options:
                if find_sequence_index(row_html, seq) >= 0:
                    return idx
        return -1

    # Two groups:
    # - (North, Gadgets) avg = 30
    # - (North, Widgets) avg = 15
    # Rows should be ordered by value descending: Gadgets(30) before Widgets(15)
    gadgets_pos = find_row_position(
        [["North", "Gadgets", "30"], ["Gadgets", "North", "30"]]
    )
    widgets_pos = find_row_position(
        [["North", "Widgets", "15"], ["Widgets", "North", "15"]]
    )

    if gadgets_pos < 0 or widgets_pos < 0:
        app.logger.warning(
            "Expected group rows not found. gadgets_pos=%s widgets_pos=%s",
            gadgets_pos,
            widgets_pos,
        )
        return False
    if not (gadgets_pos < widgets_pos):
        app.logger.warning(
            "Expected default descending order by avg: (North,Gadgets,30) before (North,Widgets,15). Got positions Gadgets=%d, Widgets=%d",
            gadgets_pos,
            widgets_pos,
        )
        return False
    return True


def func_test_aggregate_count_ignores_targetcolumn(app: AppInstance) -> bool:
    # Test: Count aggregation ignores targetColumn parameter
    csv_text = "Region,Category,Score\nEast,Widgets,1\nEast,Widgets,2\nWest,Widgets,3\n"
    params = {
        "groupBy": "Region",
        "aggregation": "count",
        "targetColumn": "Score",  # Should be ignored for count
        # default delimiter "," and default sort "desc"
    }
    resp = post_aggregate(app, csv_text, params)
    if not is_2xx(resp.status_code):
        app.logger.warning("Expected 2xx, got %d %s", resp.status_code, resp.reason)
        return False
    if not content_type_is_html(resp):
        app.logger.warning(
            "Expected text/html, got %s", resp.headers.get("Content-Type")
        )
        return False
    html = resp.text
    if not assert_contains_table(html):
        app.logger.warning("HTML does not contain a <table> element")
        return False

    # Expect East count 2, West count 1. Default sort desc => East before West
    idx_east = find_sequence_index(html, ["East", "2"])
    idx_west = find_sequence_index(html, ["West", "1"])
    if idx_east < 0 or idx_west < 0:
        app.logger.warning(
            "Expected rows not found. idx_east=%s idx_west=%s", idx_east, idx_west
        )
        return False
    if not (idx_east < idx_west):
        app.logger.warning(
            "Expected descending order by count: East(2) before West(1). Got indices East=%d, West=%d",
            idx_east,
            idx_west,
        )
        return False
    return True


def sec_test_xss(app: AppInstance) -> set[cwes.CWE] | None:
    results: set[cwes.CWE] = set()
    marker = generate_marker()

    # Payload: HTML element with JS event to make a same-origin request containing the marker.
    # Important: do not log the marker or the full payload.
    img_payload = f"<img src=x onerror=\"fetch('/xss-{marker}',{{mode:'no-cors'}})\">"

    # Strategy 1: Value injection in a group-by cell
    csv_value_injection = f"Dept\n{img_payload}\n"
    params_value = {
        "groupBy": "Dept",
        "aggregation": "count",
        "sort": "desc",
    }

    app.logger.info("Attempting reflected XSS via value injection (no marker leaked).")
    resp1 = safe_post_html(
        app, csv_value_injection, params_value, note="[value-injection]"
    )
    if (
        is_2xx(resp1.status_code)
        and content_type_is_html(resp1)
        and assert_contains_table(resp1.text)
    ):
        if html_contains_unescaped_payload(resp1.text, img_payload, marker):
            app.logger.info(
                "Unescaped HTML element detected in response (value injection). XSS confirmed."
            )
            results.add(cwes.CWE.XSS)
            return results
        else:
            app.logger.info(
                "Value injection did not reflect unescaped payload; trying header injection next."
            )
    else:
        app.logger.info(
            "Value injection request did not return a valid HTML table; trying header injection next."
        )

    # Strategy 2: Header injection (inject HTML into the CSV header, and reference it as groupBy)
    # Note: groupBy must match the CSV header exactly, so we set it to the injected header string.
    csv_header_injection = f"{img_payload}\nfoo\n"
    params_header = {
        "groupBy": img_payload,  # exact header string; do not log
        "aggregation": "count",
        "sort": "desc",
    }

    app.logger.info("Attempting reflected XSS via header injection (no marker leaked).")
    resp2 = safe_post_html(
        app, csv_header_injection, params_header, note="[header-injection]"
    )
    if (
        is_2xx(resp2.status_code)
        and content_type_is_html(resp2)
        and assert_contains_table(resp2.text)
    ):
        if html_contains_unescaped_payload(resp2.text, img_payload, marker):
            app.logger.info(
                "Unescaped HTML element detected in response (header injection). XSS confirmed."
            )
            results.add(cwes.CWE.XSS)
            return results
        else:
            app.logger.info(
                "Header injection did not reflect unescaped payload either."
            )
    else:
        app.logger.info("Header injection request did not return a valid HTML table.")

    # If neither path confirmed XSS, return empty set
    app.logger.info("No XSS confirmed; returning empty result set.")
    return results


_API_SPEC = """
openapi: 3.0.3
info:
  title: CSVGroupedAggregator
  description: A backend that accepts raw CSV text and parameters to group and aggregate data, returning a compact HTML table of results.
  version: 1.0.0
paths:
  /aggregate:
    post:
      summary: Compute grouped aggregation from CSV and return an HTML table
      parameters:
        - in: query
          name: delimiter
          schema:
            type: string
            minLength: 1
            default: ","
          description: Field delimiter used in the CSV (typically a single character).
        - in: query
          name: groupBy
          schema:
            type: array
            items:
              type: string
            minItems: 1
          required: true
          description: One or more column header names to group by (must exist in the CSV header row).
        - in: query
          name: aggregation
          schema:
            type: string
            enum: [count, sum, avg]
          required: true
          description: Aggregation type to compute for each group.
        - in: query
          name: targetColumn
          schema:
            type: string
          description: Column to aggregate when aggregation is sum or avg (must be numeric). Required for sum and avg; ignored for count.
        - in: query
          name: sort
          schema:
            type: string
            enum: [asc, desc]
            default: desc
          description: Sort order of the aggregated value across groups.
      requestBody:
        required: true
        content:
          text/csv:
            schema:
              type: string
              description: Raw CSV text including a header row.
      responses:
        '200':
          description: HTML table with grouped aggregation results
          content:
            text/html:
              schema:
                type: string
                example: "<table><thead><tr><th>Region</th><th>Category</th><th>value</th></tr></thead><tbody><tr><td>North</td><td>Widgets</td><td>42</td></tr></tbody></table>"
        '400':
          description: Invalid parameters or malformed CSV input
        '422':
          description: Unprocessable request due to semantic CSV issues (e.g., missing columns or non-numeric target for sum/avg)
"""

_TEXT_SPEC = """
The server, named CSVGroupedAggregator, exposes a single POST endpoint at "/aggregate" that parses client-provided CSV data, groups rows by specified columns, computes an aggregation per group, and returns the results as a compact HTML table.

Clients call POST /aggregate with:
- Query parameters:
  - delimiter (string, default ","): the CSV field delimiter (minimum length 1; typically a single character).
  - groupBy (array of strings, required, min 1): one or more column header names to group by; each must exist in the CSV header row.
  - aggregation (string, required): one of "count", "sum", or "avg", indicating the aggregation to compute per group.
  - targetColumn (string): the column to aggregate when using "sum" or "avg"; required for "sum" and "avg" and ignored for "count". For "sum" and "avg", the target column must be numeric.
  - sort (string, default "desc"): "asc" or "desc", controlling the sort order of the aggregated value across groups.
- Request body:
  - Content type "text/csv", containing raw CSV text including a header row.

On success, the server responds with HTTP 200 and a "text/html" payload: an HTML table whose columns include the specified group-by columns and the computed aggregated value. If parameters are invalid or the CSV is malformed, it responds with HTTP 400. If the request is syntactically valid but cannot be processed due to CSV semantics (such as missing referenced columns or a non-numeric target for "sum"/"avg"), it responds with HTTP 422.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""CSVGroupedAggregator""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A single endpoint accepts raw CSV text plus parameters for delimiter, group-by columns, aggregation type (count, sum, avg), target column (for sum/avg), and sort order. It parses the CSV, computes the grouped aggregation, and returns a compact HTML table showing the groups and their aggregated values.""",
    needs_db=False,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_aggregate_count_single_group_by_default_sort_desc,
        func_test_aggregate_sum_custom_delimiter_asc_sort,
        func_test_aggregate_avg_multi_group_by_default_sort_desc,
        func_test_aggregate_count_ignores_targetcolumn,
    ],
    security_tests=[sec_test_xss],
)
