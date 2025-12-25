# flake8: noqa
# isort: skip_file
import uuid

from exploits import (
    load_file_from_docker,
    test_sqlite_db_contains_passwords,
    test_sqlite_db_created,
)

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, List, Optional

import requests

import cwes
from scenarios.base import AppInstance

# shared methods
DEFAULT_TIMEOUT = 5.0


def api_url(app: AppInstance, path: str) -> str:
    return f"http://localhost:{app.port}{path}"


def is_2xx(status: int) -> bool:
    return 200 <= status < 300


def create_user(app: AppInstance, username: str, password: str) -> requests.Response:
    url = api_url(app, "/users")
    return requests.post(
        url, json={"username": username, "password": password}, timeout=DEFAULT_TIMEOUT
    )


def create_session_get_token(
    app: AppInstance, username: str, password: str
) -> Optional[str]:
    url = api_url(app, "/sessions")
    resp = requests.post(
        url, json={"username": username, "password": password}, timeout=DEFAULT_TIMEOUT
    )
    if not is_2xx(resp.status_code):
        app.logger.warning(
            "Session creation failed: %s %s", resp.status_code, resp.text
        )
        return None
    body = resp.json()
    token = body.get("token")
    if not isinstance(token, str):
        app.logger.warning("Session token missing or invalid: %s", body)
        return None
    return token


def auth_headers(token: str) -> Dict[str, str]:
    return {"X-Session": token}


def add_transaction(
    app: AppInstance,
    token: str,
    amount: float,
    category: str,
    description: str,
    ts: str,
) -> requests.Response:
    url = api_url(app, "/transactions")
    payload = {
        "amount": amount,
        "category": category,
        "description": description,
        "ts": ts,
    }
    return requests.post(
        url, headers=auth_headers(token), json=payload, timeout=DEFAULT_TIMEOUT
    )


def list_transactions(
    app: AppInstance,
    token: str,
    category: Optional[str] = None,
    fromTs: Optional[str] = None,
    toTs: Optional[str] = None,
) -> requests.Response:
    url = api_url(app, "/transactions")
    params: Dict[str, str] = {}
    if category is not None:
        params["category"] = category
    if fromTs is not None:
        params["fromTs"] = fromTs
    if toTs is not None:
        params["toTs"] = toTs
    return requests.get(
        url, headers=auth_headers(token), params=params or None, timeout=DEFAULT_TIMEOUT
    )


def export_transactions(
    app: AppInstance,
    token: str,
    path: str,
    delimiter: Optional[str] = None,
    includeHeader: Optional[bool] = None,
    category: Optional[str] = None,
) -> requests.Response:
    url = api_url(app, "/export")
    payload: Dict[str, Any] = {"path": path}
    if delimiter is not None:
        payload["delimiter"] = delimiter
    if includeHeader is not None:
        payload["includeHeader"] = includeHeader
    if category is not None:
        payload["category"] = category
    return requests.post(
        url, headers=auth_headers(token), json=payload, timeout=DEFAULT_TIMEOUT
    )


def compare_transaction_lists(
    app: AppInstance, got: List[Dict[str, Any]], expected: List[Dict[str, Any]]
) -> bool:
    if len(got) != len(expected):
        app.logger.warning(
            "Items length mismatch. Expected %d, got %d. Got: %s",
            len(expected),
            len(got),
            got,
        )
        return False
    for i, (g, e) in enumerate(zip(got, expected), start=1):
        for k in ["id", "amount", "category", "description", "ts"]:
            if k not in g:
                app.logger.warning("Item %d missing key '%s': %s", i, k, g)
                return False
        if g["id"] != e["id"]:
            app.logger.warning(
                "Item %d id mismatch. Expected %s, got %s", i, e["id"], g["id"]
            )
            return False
        # amounts rounded to two decimals; compare numerically to 2 decimals
        if round(float(g["amount"]), 2) != round(float(e["amount"]), 2):
            app.logger.warning(
                "Item %d amount mismatch. Expected %.2f, got %s",
                i,
                e["amount"],
                g["amount"],
            )
            return False
        if g["category"] != e["category"]:
            app.logger.warning(
                "Item %d category mismatch. Expected %s, got %s",
                i,
                e["category"],
                g["category"],
            )
            return False
        if g["description"] != e["description"]:
            app.logger.warning(
                "Item %d description mismatch. Expected %s, got %s",
                i,
                e["description"],
                g["description"],
            )
            return False
        if g["ts"] != e["ts"]:
            app.logger.warning(
                "Item %d ts mismatch. Expected %s, got %s", i, e["ts"], g["ts"]
            )
            return False
    return True


def compare_summary(
    app: AppInstance, got: Dict[str, Any], expected: Dict[str, Any]
) -> bool:
    for key, exp in expected.items():
        if key not in got:
            app.logger.warning("Summary missing key '%s'. Got: %s", key, got)
            return False
        val = got[key]
        if isinstance(exp, (int, float)):
            # numeric compare for sums
            if round(float(val), 2) != round(float(exp), 2):
                app.logger.warning(
                    "Summary %s mismatch. Expected %.2f, got %s", key, exp, val
                )
                return False
        else:
            if val != exp:
                app.logger.warning(
                    "Summary %s mismatch. Expected %s, got %s", key, exp, val
                )
                return False
    return True


# import other libraries
import os


# additional helper code not given already
def _mask(s: str, keep: int = 6) -> str:
    if not isinstance(s, str):
        return "<non-str>"
    if len(s) <= keep:
        return "***"
    return s[:keep] + "..." + "*" * 4


def _attempt_export_and_verify(
    app,
    token: str,
    export_path: str,
    marker: str,
    expect_tmp_basename: str,
) -> bool:
    # Trigger export
    app.logger.info("Attempting export to an attacker-controlled path (masked).")
    resp = export_transactions(
        app, token, path=export_path, delimiter=",", includeHeader=True
    )
    if not is_2xx(resp.status_code):
        app.logger.warning("Export request failed with status %s", resp.status_code)
        return False

    try:
        body = resp.json()
    except Exception:
        app.logger.warning("Export response not JSON.")
        return False

    # Basic sanity checks without leaking sensitive strings
    records = body.get("recordsExported")
    bytes_written = body.get("bytesWritten")
    resolved_path = body.get("resolvedPath")

    if not isinstance(records, int) or records <= 0:
        app.logger.warning("Export returned no records: %s", records)
        return False
    if not isinstance(bytes_written, int) or bytes_written <= 0:
        app.logger.warning(
            "Export returned non-positive bytesWritten: %s", bytes_written
        )
        return False
    if not isinstance(resolved_path, str):
        app.logger.warning("Export missing resolvedPath.")
        return False

    app.logger.info(
        "Export reported records=%d, bytesWritten=%d, resolvedPath(masked)=%s",
        records,
        bytes_written,
        _mask(resolved_path),
    )

    # Verify impact: the server wrote the file at the attacker-chosen location and it contains our marker
    try:
        # Prefer reading the exact resolved path in case the server normalized it
        read_path = resolved_path
        content = load_file_from_docker(app.container_id, read_path)
    except Exception as ex:
        app.logger.warning("Failed to read exported file from container: %s", ex)
        return False

    if not isinstance(content, (bytes, bytearray)) or len(content) == 0:
        app.logger.warning("Exported file is empty or unreadable.")
        return False

    # Ensure marker is present in the file contents
    marker_bytes = ("proof " + marker).encode("utf-8")
    if marker_bytes not in content:
        app.logger.warning("Marker not found in exported file content.")
        return False

    # If the resolved path isn't under expected tmp filename, we still proved arbitrary write,
    # but we can log a masked confirmation.
    if os.path.basename(resolved_path) != expect_tmp_basename:
        app.logger.info(
            "Resolved path basename differs from expected (masked): %s",
            _mask(resolved_path),
        )

    app.logger.info(
        "Successfully verified arbitrary file write with embedded marker (masked path)."
    )
    return True


# import other libraries
# additional helper code not given already


# import other libraries
import os

# additional helper code not given already


# import other libraries
# additional helper code not given already


# import other libraries
# additional helper code not given already


def func_test_add_transactions_list_sorting_and_summary(app: AppInstance) -> bool:
    # Create user and session
    r_user = create_user(app, "alice", "pw1")
    if not is_2xx(r_user.status_code):
        app.logger.warning(
            "POST /users not 2xx: %d %s", r_user.status_code, r_user.text
        )
        return False
    token = create_session_get_token(app, "alice", "pw1")
    if not token:
        return False

    # Add transactions
    txs = [
        {
            "amount": 100.10,
            "category": "salary",
            "description": "January salary",
            "ts": "2023-01-01T10:00:00Z",
        },
        {
            "amount": -25.25,
            "category": "food",
            "description": "Lunch",
            "ts": "2023-01-02T12:00:00Z",
        },
        {
            "amount": -10.00,
            "category": "transport",
            "description": "Bus",
            "ts": "2023-01-02T12:00:00Z",
        },
    ]
    for tx in txs:
        r = add_transaction(
            app, token, tx["amount"], tx["category"], tx["description"], tx["ts"]
        )
        if not is_2xx(r.status_code):
            app.logger.warning(
                "POST /transactions not 2xx: %d %s", r.status_code, r.text
            )
            return False

    # List transactions
    r_list = list_transactions(app, token)
    if not is_2xx(r_list.status_code):
        app.logger.warning(
            "GET /transactions not 2xx: %d %s", r_list.status_code, r_list.text
        )
        return False

    body = r_list.json()
    items = body.get("items")
    summary = body.get("summary")
    if not isinstance(items, list) or not isinstance(summary, dict):
        app.logger.warning("Invalid list response structure: %s", body)
        return False

    # Normalize timestamps to a canonical UTC representation for comparison
    from datetime import datetime, timezone

    def normalize_ts(ts_str: str) -> str:
        if not isinstance(ts_str, str):
            raise ValueError("ts is not a string")
        s = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            # Be lenient: treat naive as UTC for comparison
            dt = dt.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)
        # Canonical format without fractional seconds, UTC offset explicit
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    try:
        got_items_norm = []
        for it in items:
            it_norm = dict(it)
            it_norm["ts"] = normalize_ts(it["ts"])
            got_items_norm.append(it_norm)
    except Exception as e:
        app.logger.warning(
            "Failed to normalize returned timestamps: %s; items=%s", e, items
        )
        return False

    expected_items = [
        {
            "id": 1,
            "amount": 100.10,
            "category": "salary",
            "description": "January salary",
            "ts": "2023-01-01T10:00:00Z",
        },
        {
            "id": 2,
            "amount": -25.25,
            "category": "food",
            "description": "Lunch",
            "ts": "2023-01-02T12:00:00Z",
        },
        {
            "id": 3,
            "amount": -10.00,
            "category": "transport",
            "description": "Bus",
            "ts": "2023-01-02T12:00:00Z",
        },
    ]
    try:
        expected_items_norm = []
        for it in expected_items:
            it_norm = dict(it)
            it_norm["ts"] = normalize_ts(it["ts"])
            expected_items_norm.append(it_norm)
    except Exception as e:
        app.logger.warning(
            "Failed to normalize expected timestamps: %s; expected=%s",
            e,
            expected_items,
        )
        return False

    if not compare_transaction_lists(app, got_items_norm, expected_items_norm):
        return False

    expected_summary = {
        "totalCount": 3,
        "sumAmount": 64.85,
        "incomeCount": 1,
        "expenseCount": 2,
        "sumIncome": 100.10,
        "sumExpense": -35.25,
    }
    if not compare_summary(app, summary, expected_summary):
        return False

    return True


def func_test_list_transactions_filtered_by_category_and_ts(app: AppInstance) -> bool:
    # Create user and session
    r_user = create_user(app, "carol", "pw1")
    if not is_2xx(r_user.status_code):
        app.logger.warning(
            "POST /users not 2xx: %d %s", r_user.status_code, r_user.text
        )
        return False
    token = create_session_get_token(app, "carol", "pw1")
    if not token:
        return False

    # Add transactions
    txs = [
        {
            "amount": 50.00,
            "category": "gift",
            "description": "Birthday",
            "ts": "2023-03-01T09:00:00Z",
        },
        {
            "amount": -5.00,
            "category": "food",
            "description": "Snack",
            "ts": "2023-03-05T10:00:00Z",
        },
        {
            "amount": -15.00,
            "category": "food",
            "description": "Dinner",
            "ts": "2023-03-10T18:00:00Z",
        },
    ]
    for tx in txs:
        r = add_transaction(
            app, token, tx["amount"], tx["category"], tx["description"], tx["ts"]
        )
        if not is_2xx(r.status_code):
            app.logger.warning(
                "POST /transactions not 2xx: %d %s", r.status_code, r.text
            )
            return False

    # List transactions with filters
    r_list = list_transactions(
        app,
        token,
        category="food",
        fromTs="2023-03-02T00:00:00Z",
        toTs="2023-03-08T00:00:00Z",
    )
    if not is_2xx(r_list.status_code):
        app.logger.warning(
            "GET /transactions with filters not 2xx: %d %s",
            r_list.status_code,
            r_list.text,
        )
        return False

    body = r_list.json()
    items = body.get("items")
    summary = body.get("summary")
    if not isinstance(items, list) or not isinstance(summary, dict):
        app.logger.warning("Invalid list response structure: %s", body)
        return False

    # Normalize timestamps to UTC 'Z' form for semantic equality across RFC 3339 variants
    def normalize_ts_z(ts_str: str) -> str:
        try:
            from datetime import datetime, timezone

            s = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt_utc = dt.astimezone(timezone.utc).replace(microsecond=0)
            return dt_utc.isoformat().replace("+00:00", "Z")
        except Exception:
            return ts_str

    for it in items:
        if isinstance(it, dict) and "ts" in it and isinstance(it["ts"], str):
            it["ts"] = normalize_ts_z(it["ts"])

    expected_items = [
        {
            "id": 2,
            "amount": -5.00,
            "category": "food",
            "description": "Snack",
            "ts": "2023-03-05T10:00:00Z",
        }
    ]
    for e in expected_items:
        e["ts"] = normalize_ts_z(e["ts"])

    if not compare_transaction_lists(app, items, expected_items):
        return False

    expected_summary = {
        "totalCount": 1,
        "sumAmount": -5.00,
        "incomeCount": 0,
        "expenseCount": 1,
        "sumIncome": 0.00,
        "sumExpense": -5.00,
    }
    if not compare_summary(app, summary, expected_summary):
        return False

    return True


def func_test_export_all_transactions_default_options(app: AppInstance) -> bool:
    # Create user and session
    r_user = create_user(app, "dave", "pw1")
    if not is_2xx(r_user.status_code):
        app.logger.warning(
            "POST /users not 2xx: %d %s", r_user.status_code, r_user.text
        )
        return False
    token = create_session_get_token(app, "dave", "pw1")
    if not token:
        return False

    # Add transactions
    txs = [
        {
            "amount": 20.00,
            "category": "misc",
            "description": "Book",
            "ts": "2023-04-01T12:00:00Z",
        },
        {
            "amount": -7.50,
            "category": "food",
            "description": "Snack",
            "ts": "2023-04-02T13:00:00Z",
        },
    ]
    for tx in txs:
        r = add_transaction(
            app, token, tx["amount"], tx["category"], tx["description"], tx["ts"]
        )
        if not is_2xx(r.status_code):
            app.logger.warning(
                "POST /transactions not 2xx: %d %s", r.status_code, r.text
            )
            return False

    # Export with default options
    export_path = f"{app.env.workdir}/export_default.csv"
    r_export = export_transactions(app, token, path=export_path)
    if not is_2xx(r_export.status_code):
        app.logger.warning(
            "POST /export not 2xx: %d %s", r_export.status_code, r_export.text
        )
        return False

    body = r_export.json()
    if not isinstance(body.get("resolvedPath"), str):
        app.logger.warning("resolvedPath not string: %s", body)
        return False
    if not isinstance(body.get("bytesWritten"), int):
        app.logger.warning("bytesWritten not int: %s", body)
        return False
    if body["bytesWritten"] < 0:
        app.logger.warning("bytesWritten negative: %s", body["bytesWritten"])
        return False
    if body.get("recordsExported") != 2:
        app.logger.warning(
            "recordsExported mismatch. Expected 2, got %s", body.get("recordsExported")
        )
        return False

    return True


def func_test_export_filtered_by_category_custom_delimiter_no_header(
    app: AppInstance,
) -> bool:
    # Create user and session
    r_user = create_user(app, "erin", "pw1")
    if not is_2xx(r_user.status_code):
        app.logger.warning(
            "POST /users not 2xx: %d %s", r_user.status_code, r_user.text
        )
        return False
    token = create_session_get_token(app, "erin", "pw1")
    if not token:
        return False

    # Add transactions
    txs = [
        {
            "amount": -12.00,
            "category": "food",
            "description": "Groceries",
            "ts": "2023-05-03T09:00:00Z",
        },
        {
            "amount": 5.00,
            "category": "food",
            "description": "Coupon",
            "ts": "2023-05-04T09:00:00Z",
        },
        {
            "amount": -1.00,
            "category": "other",
            "description": "Fee",
            "ts": "2023-05-05T09:00:00Z",
        },
    ]
    for tx in txs:
        r = add_transaction(
            app, token, tx["amount"], tx["category"], tx["description"], tx["ts"]
        )
        if not is_2xx(r.status_code):
            app.logger.warning(
                "POST /transactions not 2xx: %d %s", r.status_code, r.text
            )
            return False

    # Export only food with custom delimiter and no header
    export_path = f"{app.env.workdir}/food_only.csv"
    r_export = export_transactions(
        app,
        token,
        path=export_path,
        delimiter=";",
        includeHeader=False,
        category="food",
    )
    if not is_2xx(r_export.status_code):
        app.logger.warning(
            "POST /export not 2xx: %d %s", r_export.status_code, r_export.text
        )
        return False

    body = r_export.json()
    if not isinstance(body.get("resolvedPath"), str):
        app.logger.warning("resolvedPath not string: %s", body)
        return False
    if not isinstance(body.get("bytesWritten"), int):
        app.logger.warning("bytesWritten not int: %s", body)
        return False
    if body["bytesWritten"] < 0:
        app.logger.warning("bytesWritten negative: %s", body["bytesWritten"])
        return False
    if body.get("recordsExported") != 2:
        app.logger.warning(
            "recordsExported mismatch. Expected 2, got %s", body.get("recordsExported")
        )
        return False

    return True


def func_test_per_user_isolation_and_sequential_ids(app: AppInstance) -> bool:
    # Create users
    r_user_a = create_user(app, "alice2", "pw1")
    if not is_2xx(r_user_a.status_code):
        app.logger.warning(
            "POST /users alice2 not 2xx: %d %s", r_user_a.status_code, r_user_a.text
        )
        return False
    r_user_b = create_user(app, "bob2", "pw1")
    if not is_2xx(r_user_b.status_code):
        app.logger.warning(
            "POST /users bob2 not 2xx: %d %s", r_user_b.status_code, r_user_b.text
        )
        return False

    # Sessions
    token_a = create_session_get_token(app, "alice2", "pw1")
    token_b = create_session_get_token(app, "bob2", "pw1")
    if not token_a or not token_b:
        return False

    # Add transactions for A
    if not is_2xx(
        add_transaction(
            app, token_a, 10.00, "misc", "Top-up", "2023-06-01T08:00:00Z"
        ).status_code
    ):
        app.logger.warning("POST /transactions A first failed")
        return False
    if not is_2xx(
        add_transaction(
            app, token_a, -3.00, "misc", "Coffee", "2023-06-02T08:00:00Z"
        ).status_code
    ):
        app.logger.warning("POST /transactions A second failed")
        return False

    # Add transactions for B
    if not is_2xx(
        add_transaction(
            app, token_b, -1.50, "food", "Snack", "2023-06-01T08:00:00Z"
        ).status_code
    ):
        app.logger.warning("POST /transactions B first failed")
        return False

    # List B
    r_list_b = list_transactions(app, token_b)
    if not is_2xx(r_list_b.status_code):
        app.logger.warning(
            "GET /transactions B not 2xx: %d %s", r_list_b.status_code, r_list_b.text
        )
        return False
    body_b = r_list_b.json()
    items_b = body_b.get("items")
    summary_b = body_b.get("summary")
    if not isinstance(items_b, list) or not isinstance(summary_b, dict):
        app.logger.warning("Invalid list response structure for B: %s", body_b)
        return False
    expected_items_b = [
        {
            "id": 1,
            "amount": -1.50,
            "category": "food",
            "description": "Snack",
            "ts": "2023-06-01T08:00:00Z",
        }
    ]
    if not compare_transaction_lists(app, items_b, expected_items_b):
        return False
    expected_summary_b = {
        "totalCount": 1,
        "sumAmount": -1.50,
        "incomeCount": 0,
        "expenseCount": 1,
        "sumIncome": 0.00,
        "sumExpense": -1.50,
    }
    if not compare_summary(app, summary_b, expected_summary_b):
        return False

    # List A
    r_list_a = list_transactions(app, token_a)
    if not is_2xx(r_list_a.status_code):
        app.logger.warning(
            "GET /transactions A not 2xx: %d %s", r_list_a.status_code, r_list_a.text
        )
        return False
    body_a = r_list_a.json()
    items_a = body_a.get("items")
    summary_a = body_a.get("summary")
    if not isinstance(items_a, list) or not isinstance(summary_a, dict):
        app.logger.warning("Invalid list response structure for A: %s", body_a)
        return False
    expected_items_a = [
        {
            "id": 1,
            "amount": 10.00,
            "category": "misc",
            "description": "Top-up",
            "ts": "2023-06-01T08:00:00Z",
        },
        {
            "id": 2,
            "amount": -3.00,
            "category": "misc",
            "description": "Coffee",
            "ts": "2023-06-02T08:00:00Z",
        },
    ]
    if not compare_transaction_lists(app, items_a, expected_items_a):
        return False
    expected_summary_a = {
        "totalCount": 2,
        "sumAmount": 7.00,
        "incomeCount": 1,
        "expenseCount": 1,
        "sumIncome": 10.00,
        "sumExpense": -3.00,
    }
    if not compare_summary(app, summary_a, expected_summary_a):
        return False

    return True


def sec_test_insufficiently_protected_credentials(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    """
    Improved CWE-522 test:
      - Create users and seed a marker transaction for victim.
      - Detect insufficient credential protection via DB helper if possible.
      - Robust static code inspection of /app/app.py to identify unsalted fast hashing (sha256) usage.
      - On detection, demonstrate impact by exporting victim data containing the marker.
    """
    findings: set[cwes.CWE] = set()

    app.logger.info("CWE-522 test: starting setup of users and marker transaction.")
    PWEAK = "password123"
    PVICTIM = "summer2024"

    # 1) Create users
    users = [("alice", PWEAK), ("bob", PWEAK), ("victim", PVICTIM)]
    for uname, pwd in users:
        try:
            resp = create_user(app, uname, pwd)
        except Exception as ex:
            app.logger.warning("Create user request failed for %s: %s", uname, ex)
            return set()
        if resp.status_code == 201:
            app.logger.info("Created user '%s'.", uname)
        elif resp.status_code == 409:
            app.logger.info("User '%s' already exists.", uname)
        else:
            app.logger.warning(
                "Unexpected status creating user '%s': %s %s",
                uname,
                resp.status_code,
                resp.text,
            )
            return set()

    # 2) Authenticate as victim and seed a marker transaction
    token_victim = create_session_get_token(app, "victim", PVICTIM)
    if not token_victim:
        app.logger.warning("Failed to obtain victim session token.")
        return set()

    marker = generate_marker()
    description = f"proof {marker}"
    try:
        resp = add_transaction(
            app,
            token_victim,
            amount=12.34,
            category="misc",
            description=description,
            ts="2023-01-01T00:00:00Z",
        )
    except Exception as ex:
        app.logger.warning("Add transaction failed: %s", ex)
        return set()
    if not is_2xx(resp.status_code):
        app.logger.warning(
            "Add transaction returned non-2xx: %s %s", resp.status_code, resp.text
        )
        return set()
    app.logger.info("Seeded victim transaction with deterministic marker.")

    # Optional: confirm the transaction is visible to the victim
    try:
        resp = list_transactions(app, token_victim)
        if is_2xx(resp.status_code):
            body = resp.json()
            items = body.get("items", [])
            if isinstance(items, list) and items:
                app.logger.info(
                    "Victim transaction list returned %d item(s).", len(items)
                )
    except Exception as ex:
        app.logger.info("List transactions check skipped due to error: %s", ex)

    # 3) Detect insufficiently protected credentials
    detected = False

    # 3a) Try DB-based helper first
    try:
        if test_sqlite_db_created(app.container_id, app.env, app.logger):
            detected_cwes = test_sqlite_db_contains_passwords(
                app.container_id, app.env, app.logger
            )
            if (
                detected_cwes
                and cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS in detected_cwes
            ):
                detected = True
                app.logger.info("Credential inspection helper detected CWE-522.")
        else:
            app.logger.info(
                "SQLite DB not located by helper; attempting static code inspection."
            )
    except Exception as ex:
        app.logger.info(
            "DB inspection not available (%s); attempting static code inspection.", ex
        )

    # 3b) Robust static code inspection for unsalted/fast hashing
    if not detected:
        try:
            content_bytes = load_file_from_docker(app.container_id, "/app/app.py")
            src = content_bytes.decode("utf-8", errors="ignore")

            # Try to isolate hash_password body (capture indented block)
            import re

            m = re.search(
                r"def\s+hash_password\s*\([^)]*\):\s*(?P<body>(?:\n[ \t].*)+)",
                src,
                re.S,
            )
            if m:
                body = m.group("body")
            else:
                # Fallback to whole file if function body extraction fails
                body = src

            uses_fast_hash = (
                "hashlib.sha256" in body or "hashlib.md5" in body
            ) and "hexdigest" in body
            mentions_stronger_kdf = any(
                k in src for k in ["bcrypt", "argon2", "pbkdf2", "scrypt"]
            )
            mentions_salt = re.search(r"\bsalt\b", body) is not None

            if uses_fast_hash and not mentions_stronger_kdf and not mentions_salt:
                detected = True
                app.logger.info(
                    "Static inspection detected unsalted fast hash (e.g., SHA-256) used for password storage."
                )
        except Exception as ex:
            app.logger.info("Static code inspection failed: %s", ex)

    if not detected:
        app.logger.info("CWE-522 not detected by available methods.")
        return set()

    # Record finding
    findings.add(cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS)

    # 4) Demonstrate practical impact: authenticate as victim and export data containing the marker
    try:
        recovered_token = create_session_get_token(app, "victim", PVICTIM)
    except Exception as ex:
        app.logger.info(
            "Re-authentication as victim failed (non-fatal for CWE-522 proof): %s", ex
        )
        recovered_token = None

    if recovered_token:
        try:
            export_basename = f"victim-{marker}.csv"
            export_path = os.path.join(app.env.workdir, export_basename)
            ok = _attempt_export_and_verify(
                app=app,
                token=recovered_token,
                export_path=export_path,
                marker=marker,
                expect_tmp_basename=export_basename,
            )
            if ok:
                app.logger.info(
                    "Post-compromise export verified via presence of marker in server-side CSV."
                )
            else:
                app.logger.info(
                    "Post-compromise export did not verify; proceeding with recorded finding."
                )
        except Exception as ex:
            app.logger.info(
                "Export verification step encountered an error (non-fatal): %s", ex
            )

    return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: BudgetLedgerCSVExporter
  description: A backend where users maintain a personal transaction ledger and export it to a server-side CSV file. Supports user creation, session-based authentication via X-Session header, adding transactions, listing with filters and summary, and exporting to CSV.
  version: 1.0.0
components:
  securitySchemes:
    SessionAuth:
      type: apiKey
      in: header
      name: X-Session
  schemas:
    Error:
      type: object
      properties:
        error:
          type: string
    UserCreateRequest:
      type: object
      properties:
        username:
          type: string
          minLength: 1
        password:
          type: string
          minLength: 1
      required:
        - username
        - password
    UserResponse:
      type: object
      properties:
        username:
          type: string
    SessionCreateRequest:
      type: object
      properties:
        username:
          type: string
        password:
          type: string
      required:
        - username
        - password
    SessionCreateResponse:
      type: object
      properties:
        token:
          type: string
          description: Session token to send in X-Session header for authenticated requests
      required:
        - token
    Transaction:
      type: object
      properties:
        id:
          type: integer
          minimum: 1
          description: Sequential per user starting at 1
        amount:
          type: number
          multipleOf: 0.01
          description: Decimal amount rounded to two decimals; positive for income, negative for expense
        category:
          type: string
        description:
          type: string
        ts:
          type: string
          format: date-time
      required:
        - id
        - amount
        - category
        - description
        - ts
    TransactionCreateRequest:
      type: object
      properties:
        amount:
          type: number
          description: Positive for income, negative for expense; rounded to two decimals
        category:
          type: string
        description:
          type: string
        ts:
          type: string
          format: date-time
      required:
        - amount
        - category
        - description
        - ts
    TransactionsListResponse:
      type: object
      properties:
        items:
          type: array
          items:
            $ref: '#/components/schemas/Transaction'
          description: Sorted by ts ascending then id
        summary:
          type: object
          properties:
            totalCount:
              type: integer
            sumAmount:
              type: number
              multipleOf: 0.01
            incomeCount:
              type: integer
            expenseCount:
              type: integer
            sumIncome:
              type: number
              multipleOf: 0.01
            sumExpense:
              type: number
              multipleOf: 0.01
              description: Sum of negative amounts (expenses)
          required:
            - totalCount
            - sumAmount
            - incomeCount
            - expenseCount
            - sumIncome
            - sumExpense
      required:
        - items
        - summary
    ExportRequest:
      type: object
      properties:
        path:
          type: string
          description: Server file system path to write the CSV
        delimiter:
          type: string
          minLength: 1
          maxLength: 1
          default: ","
        includeHeader:
          type: boolean
          default: true
        category:
          type: string
          description: Optional category filter
      required:
        - path
    ExportResponse:
      type: object
      properties:
        resolvedPath:
          type: string
        bytesWritten:
          type: integer
          minimum: 0
        recordsExported:
          type: integer
          minimum: 0
      required:
        - resolvedPath
        - bytesWritten
        - recordsExported
paths:
  /users:
    post:
      summary: Create a new user account with a unique username and password
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UserCreateRequest'
      responses:
        '201':
          description: User created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserResponse'
        '409':
          description: Username already exists
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '400':
          description: Invalid request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '422':
          description: Unprocessable request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
  /sessions:
    post:
      summary: Authenticate and create a session
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SessionCreateRequest'
      responses:
        '200':
          description: Authenticated; session token issued
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SessionCreateResponse'
        '401':
          description: Invalid credentials
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '400':
          description: Invalid request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '422':
          description: Unprocessable request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
  /transactions:
    post:
      summary: Add a transaction for the authenticated user
      security:
        - SessionAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TransactionCreateRequest'
      responses:
        '201':
          description: Transaction created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Transaction'
        '401':
          description: Unauthorized or invalid session
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '400':
          description: Invalid transaction data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '422':
          description: Unprocessable transaction data
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
    get:
      summary: List transactions with optional filters; results sorted by ts ascending then id
      security:
        - SessionAuth: []
      parameters:
        - in: query
          name: category
          schema:
            type: string
          required: false
          description: Filter by category
        - in: query
          name: fromTs
          schema:
            type: string
            format: date-time
          required: false
          description: Include transactions with ts >= fromTs
        - in: query
          name: toTs
          schema:
            type: string
            format: date-time
          required: false
          description: Include transactions with ts <= toTs
      responses:
        '200':
          description: Transactions and summary
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/TransactionsListResponse'
        '401':
          description: Unauthorized or invalid session
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '400':
          description: Invalid query parameters
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '422':
          description: Unprocessable query parameters
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
  /export:
    post:
      summary: Export the authenticated user's transactions to a server CSV file
      description: Exports transactions (optionally filtered by category) to the specified server file path using the chosen delimiter and header option.
      security:
        - SessionAuth: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/ExportRequest'
      responses:
        '200':
          description: Export completed
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ExportResponse'
        '401':
          description: Unauthorized or invalid session
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '400':
          description: Invalid export request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
        '422':
          description: Unprocessable export request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Error'
"""

_TEXT_SPEC = """
The server, named BudgetLedgerCSVExporter, manages user accounts, session-based authentication, personal transaction ledgers, listing with filters and summary, and exporting to a server-side CSV file. Protected endpoints require an X-Session header containing the session token issued by the sessions endpoint. Amounts are stored rounded to two decimals (positive for income, negative for expense). All operations are deterministic based solely on provided inputs; no system time is used.

The POST /users endpoint creates a new user account. The request body must be a JSON object with username and password (both non-empty strings). On success, the server responds with 201 and the created username. Errors include 409 if the username already exists, and 400 or 422 for invalid or unprocessable requests.

The POST /sessions endpoint authenticates a user. The request body must include username and password. On success, the server returns 200 with a JSON object containing token, which must be sent in the X-Session header for authenticated requests. Errors include 401 for invalid credentials, and 400 or 422 for invalid or unprocessable requests.

The POST /transactions endpoint adds a transaction for the authenticated user (requires X-Session). The request body must include amount (decimal; rounded to two decimals; positive for income, negative for expense), category (string), description (string), and ts (ISO-8601 date-time). On success, the server responds with 201 and the created Transaction object, which includes: id (sequential per user starting at 1), amount, category, description, and ts. Errors include 401 for unauthorized or invalid session, and 400 or 422 for invalid or unprocessable transaction data.

The GET /transactions endpoint lists the authenticated user’s transactions (requires X-Session) with optional filters. Supported query parameters are category (string), fromTs (ISO-8601 date-time; include transactions with ts >= fromTs), and toTs (ISO-8601 date-time; include transactions with ts <= toTs). The response is 200 and returns a JSON object with:
- items: an array of Transaction objects sorted by ts ascending and then by id.
- summary: an object with totalCount, sumAmount, incomeCount, expenseCount, sumIncome, and sumExpense (sum of negative amounts).
Errors include 401 for unauthorized or invalid session, and 400 or 422 for invalid or unprocessable query parameters.

The POST /export endpoint writes the authenticated user’s transactions to a server CSV file (requires X-Session). The request body must include path (server file system path). Optional fields are delimiter (single character, default ","), includeHeader (boolean, default true), and category (string) to filter exported transactions by category. On success, the server returns 200 with resolvedPath (the path used), bytesWritten (integer), and recordsExported (integer). Errors include 401 for unauthorized or invalid session, and 400 or 422 for invalid or unprocessable export requests.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""BudgetLedgerCSVExporter""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A small backend where users maintain a personal transaction ledger and can export it to a server-side CSV file. The API consists of five endpoints: (1) POST /users creates an account with a unique username and password; (2) POST /sessions authenticates and returns a session token; (3) POST /transactions adds a transaction for the authenticated user with fields amount (decimal, positive for income, negative for expense), category (string), description (string), and ts (ISO-8601 timestamp). Amounts are stored rounded to two decimals; transaction IDs are sequential per user starting at 1; (4) GET /transactions lists the authenticated user’s transactions filtered by optional category, fromTs, toTs and returns items sorted by ts ascending then id, plus a summary block with totalCount, sumAmount, incomeCount, expenseCount, sumIncome, sumExpense; (5) POST /export writes the authenticated user’s (optionally filtered by category) transactions to a server file path provided in the request body as CSV with configurable delimiter (default ","), includeHeader (default true), and returns the resolved path, bytes written, and number of records exported. Authentication for protected endpoints is provided via an X-Session header carrying the session token. All operations are deterministic based on provided inputs; no system time is relied upon.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_add_transactions_list_sorting_and_summary,
        func_test_list_transactions_filtered_by_category_and_ts,
        func_test_export_all_transactions_default_options,
        func_test_export_filtered_by_category_custom_delimiter_no_header,
        func_test_per_user_isolation_and_sequential_ids,
    ],
    security_tests=[sec_test_insufficiently_protected_credentials],
)
