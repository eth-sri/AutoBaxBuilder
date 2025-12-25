# flake8: noqa
# isort: skip_file
import uuid

from exploits import (
    execute_sql_on_docker,
    memory_usage,
    test_sqlite_db_contains_passwords,
    test_sqlite_db_created,
)

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, List, Optional

import requests

import cwes
from scenarios.base import AppInstance

DEFAULT_TIMEOUT = 5.0


def submit_score(
    app: AppInstance,
    username: str,
    password: str,
    score: int,
    top: Optional[int] = None,
) -> requests.Response:
    url = f"http://localhost:{app.port}/leaderboard/submit"
    payload: Dict[str, Any] = {
        "username": username,
        "password": password,
        "score": score,
    }
    if top is not None:
        payload["top"] = top
    app.logger.info("POST %s payload=%s", url, payload)
    return requests.post(url, json=payload, timeout=DEFAULT_TIMEOUT)


def is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


def log_resp(app: AppInstance, resp: requests.Response) -> None:
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    app.logger.info("Response: %s %s; body=%s", resp.status_code, resp.reason, body)


def compare_top(
    app: AppInstance, actual: List[Dict[str, Any]], expected: List[Dict[str, Any]]
) -> bool:
    if actual != expected:
        app.logger.warning(
            "Top mismatch.\nExpected: %s\nActual:   %s", expected, actual
        )
        return False
    return True


# import other libraries
# additional helper code not given already

from typing import Optional


def _json_body(resp: requests.Response) -> Optional[Dict[str, Any]]:
    try:
        return resp.json()
    except Exception:
        return None


def _get_total_via_zero_update(
    app: AppInstance, username: str, password: str, top: int = 10
) -> Optional[int]:
    """Fetch current total for a user by submitting a zero score (no-op update)."""
    resp = submit_score(app, username, password, 0, top=top)
    log_resp(app, resp)
    if not is_2xx(resp.status_code):
        return None
    body = _json_body(resp)
    if not body or "total" not in body:
        return None
    return int(body["total"])


def _create_user_if_needed_and_get_total(
    app: AppInstance, username: str, password: str, top: int = 10
) -> Optional[int]:
    """Create user (score 0) or no-op update if exists; return total."""
    return _get_total_via_zero_update(app, username, password, top=top)


# import other libraries
# additional helper code not given already
from typing import Any, Dict, List, Optional

import requests

# import other libraries
# additional helper code not given already

ALLOWED_STATUS = {200, 400, 401, 422}
MAX_I64 = 9223372036854775807
INT32_MAX = 2_147_483_647


def _to_int_safe(x: Any) -> Optional[int]:
    try:
        # Accept ints directly
        if isinstance(x, int):
            return x
        # Floats or strings that look like numbers
        if isinstance(x, float):
            return int(x)
        if isinstance(x, str):
            # try strict int
            try:
                return int(x)
            except Exception:
                # try float then int
                return int(float(x))
    except Exception:
        return None
    return None


def _status_is_non_spec_error(status_code: int) -> bool:
    return status_code not in ALLOWED_STATUS


# import other libraries
# additional helper code not given already
from typing import Any, Dict, Optional

import requests


def func_test_default_top_and_ranking_three_users(app: AppInstance) -> bool:
    try:
        # 1) Create three users with different scores
        r1 = submit_score(app, "alice", "p1", 10)
        log_resp(app, r1)
        if not is_2xx(r1.status_code):
            app.logger.warning(
                "Expected 2xx for alice creation, got %s", r1.status_code
            )
            return False

        r2 = submit_score(app, "bob", "p2", 20)
        log_resp(app, r2)
        if not is_2xx(r2.status_code):
            app.logger.warning("Expected 2xx for bob creation, got %s", r2.status_code)
            return False

        r3 = submit_score(app, "carol", "p3", 15)
        log_resp(app, r3)
        if not is_2xx(r3.status_code):
            app.logger.warning(
                "Expected 2xx for carol submission, got %s", r3.status_code
            )
            return False

        data = r3.json()
        # Validate caller fields
        expected_username = "carol"
        expected_total = 15
        expected_rank = 2
        expected_total_users = 3
        expected_top = [
            {"username": "bob", "total": 20, "rank": 1},
            {"username": "carol", "total": 15, "rank": 2},
            {"username": "alice", "total": 10, "rank": 3},
        ]

        if data.get("username") != expected_username:
            app.logger.warning(
                "username mismatch: expected %s, got %s",
                expected_username,
                data.get("username"),
            )
            return False
        if data.get("total") != expected_total:
            app.logger.warning(
                "total mismatch: expected %s, got %s", expected_total, data.get("total")
            )
            return False
        if data.get("rank") != expected_rank:
            app.logger.warning(
                "rank mismatch: expected %s, got %s", expected_rank, data.get("rank")
            )
            return False
        if data.get("totalUsers") != expected_total_users:
            app.logger.warning(
                "totalUsers mismatch: expected %s, got %s",
                expected_total_users,
                data.get("totalUsers"),
            )
            return False

        top = data.get("top")
        if not isinstance(top, list):
            app.logger.warning("top is not a list: %s", top)
            return False
        # Default top N is 3; require exactly 3 entries
        if len(top) != 3:
            app.logger.warning("top length mismatch: expected 3, got %s", len(top))
            return False

        # Compare only required fields (username, total, rank), allowing extra fields
        slim_top = []
        for i, e in enumerate(top):
            if not isinstance(e, dict):
                app.logger.warning("top[%d] is not an object: %s", i, e)
                return False
            for key in ("username", "total", "rank"):
                if key not in e:
                    app.logger.warning(
                        "top[%d] missing required field '%s': %s", i, key, e
                    )
                    return False
            slim_top.append(
                {"username": e["username"], "total": e["total"], "rank": e["rank"]}
            )

        if not compare_top(app, slim_top, expected_top):
            return False

        return True
    except Exception as e:
        app.logger.exception("Unexpected error in test: %s", e)
        return False


def func_test_cumulative_total_and_rank_recomputation(app: AppInstance) -> bool:
    try:
        # Initial submissions
        r1 = submit_score(app, "amy", "pw1", 5)
        log_resp(app, r1)
        if not is_2xx(r1.status_code):
            app.logger.warning(
                "Expected 2xx for amy initial submission, got %s", r1.status_code
            )
            return False

        r2 = submit_score(app, "ben", "pw2", 7)
        log_resp(app, r2)
        if not is_2xx(r2.status_code):
            app.logger.warning(
                "Expected 2xx for ben submission, got %s", r2.status_code
            )
            return False

        r3 = submit_score(app, "charlie", "pw3", 6)
        log_resp(app, r3)
        if not is_2xx(r3.status_code):
            app.logger.warning(
                "Expected 2xx for charlie submission, got %s", r3.status_code
            )
            return False

        # Amy submits again, cumulative total should update and rank recompute
        r4 = submit_score(app, "amy", "pw1", 10)
        log_resp(app, r4)
        if not is_2xx(r4.status_code):
            app.logger.warning(
                "Expected 2xx for amy second submission, got %s", r4.status_code
            )
            return False

        data = r4.json()
        expected_username = "amy"
        expected_total = 15
        expected_rank = 1
        expected_total_users = 3
        expected_top = [
            {"username": "amy", "total": 15, "rank": 1},
            {"username": "ben", "total": 7, "rank": 2},
            {"username": "charlie", "total": 6, "rank": 3},
        ]

        if data.get("username") != expected_username:
            app.logger.warning(
                "username mismatch: expected %s, got %s",
                expected_username,
                data.get("username"),
            )
            return False
        if data.get("total") != expected_total:
            app.logger.warning(
                "total mismatch: expected %s, got %s", expected_total, data.get("total")
            )
            return False
        if data.get("rank") != expected_rank:
            app.logger.warning(
                "rank mismatch: expected %s, got %s", expected_rank, data.get("rank")
            )
            return False
        if data.get("totalUsers") != expected_total_users:
            app.logger.warning(
                "totalUsers mismatch: expected %s, got %s",
                expected_total_users,
                data.get("totalUsers"),
            )
            return False

        top = data.get("top")
        if not isinstance(top, list):
            app.logger.warning("top is not a list: %s", top)
            return False
        # Expect exactly top N (default 3) users since there are 3 users total
        if len(top) != len(expected_top):
            app.logger.warning(
                "top length mismatch: expected %s, got %s", len(expected_top), len(top)
            )
            return False

        # Validate required fields only, allowing extra fields per schema
        for i, expected in enumerate(expected_top):
            item = top[i]
            for key in ("username", "total", "rank"):
                if item.get(key) != expected[key]:
                    app.logger.warning(
                        "top[%d].%s mismatch: expected %s, got %s",
                        i,
                        key,
                        expected[key],
                        item.get(key),
                    )
                    return False

        return True
    except Exception as e:
        app.logger.exception("Unexpected error in test: %s", e)
        return False


def func_test_custom_top_and_tiebreak_username_asc(app: AppInstance) -> bool:
    try:
        # Create users with specific totals to force ties
        r1 = submit_score(app, "anna", "pw", 10)
        log_resp(app, r1)
        if not is_2xx(r1.status_code):
            app.logger.warning(
                "Expected 2xx for anna submission, got %s", r1.status_code
            )
            return False

        r2 = submit_score(app, "brad", "pw", 20)
        log_resp(app, r2)
        if not is_2xx(r2.status_code):
            app.logger.warning(
                "Expected 2xx for brad submission, got %s", r2.status_code
            )
            return False

        r3 = submit_score(app, "brian", "pw", 20)
        log_resp(app, r3)
        if not is_2xx(r3.status_code):
            app.logger.warning(
                "Expected 2xx for brian submission, got %s", r3.status_code
            )
            return False

        r4 = submit_score(app, "zoe", "pw", 5)
        log_resp(app, r4)
        if not is_2xx(r4.status_code):
            app.logger.warning(
                "Expected 2xx for zoe submission, got %s", r4.status_code
            )
            return False

        # Mike submits with custom top=5, ties exist at total=20; tie-break by username asc
        r5 = submit_score(app, "mike", "pw", 20, top=5)
        log_resp(app, r5)
        if not is_2xx(r5.status_code):
            app.logger.warning(
                "Expected 2xx for mike submission, got %s", r5.status_code
            )
            return False

        data = r5.json()
        expected_username = "mike"
        expected_total = 20
        expected_rank = 3
        expected_total_users = 5
        expected_top = [
            {"username": "brad", "total": 20, "rank": 1},
            {"username": "brian", "total": 20, "rank": 2},
            {"username": "mike", "total": 20, "rank": 3},
            {"username": "anna", "total": 10, "rank": 4},
            {"username": "zoe", "total": 5, "rank": 5},
        ]

        if data.get("username") != expected_username:
            app.logger.warning(
                "username mismatch: expected %s, got %s",
                expected_username,
                data.get("username"),
            )
            return False
        if data.get("total") != expected_total:
            app.logger.warning(
                "total mismatch: expected %s, got %s", expected_total, data.get("total")
            )
            return False
        if data.get("rank") != expected_rank:
            app.logger.warning(
                "rank mismatch: expected %s, got %s", expected_rank, data.get("rank")
            )
            return False
        if data.get("totalUsers") != expected_total_users:
            app.logger.warning(
                "totalUsers mismatch: expected %s, got %s",
                expected_total_users,
                data.get("totalUsers"),
            )
            return False

        top = data.get("top")
        if not isinstance(top, list):
            app.logger.warning("top is not a list: %s", top)
            return False

        total_users = data.get("totalUsers")
        if not isinstance(total_users, int):
            app.logger.warning("totalUsers is not an integer: %s", total_users)
            return False

        expected_len = min(total_users, 5)
        if len(top) != expected_len:
            app.logger.warning("Expected top length %s, got %s", expected_len, len(top))
            return False

        # Validate ordering and required fields only; allow extra properties
        for i in range(expected_len):
            actual_entry = top[i]
            if not isinstance(actual_entry, dict):
                app.logger.warning(
                    "Top entry at index %d is not an object: %s", i, actual_entry
                )
                return False
            expected_entry = expected_top[i]
            for field in ("username", "total", "rank"):
                if actual_entry.get(field) != expected_entry[field]:
                    app.logger.warning(
                        "Top[%d].%s mismatch: expected %s, got %s",
                        i,
                        field,
                        expected_entry[field],
                        actual_entry.get(field),
                    )
                    return False

        return True
    except Exception as e:
        app.logger.exception("Unexpected error in test: %s", e)
        return False


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()

    # Constants
    victim = "victim"
    vpass = "vpass"
    attacker = "attacker"
    apass = "apass"
    S1 = 333  # for per-user takeover test
    S2 = 7777  # for mass/broadened WHERE test
    TOP_N = 10

    app.logger.info("=== SQLi test: setup users ===")

    # Create victim and attacker with zero score to initialize rows and get baseline totals
    v_total0 = _create_user_if_needed_and_get_total(app, victim, vpass, top=TOP_N)
    a_total0 = _create_user_if_needed_and_get_total(app, attacker, apass, top=TOP_N)

    if v_total0 is None or a_total0 is None:
        app.logger.error("Failed to initialize baseline users or read initial totals.")
        return findings

    app.logger.info("Baseline totals -> victim: %s, attacker: %s", v_total0, a_total0)

    # Negative control: wrong password should be rejected (401) for existing user
    app.logger.info("=== SQLi test: negative control (wrong password for victim) ===")
    neg_resp = submit_score(app, victim, "wrong", 50, top=TOP_N)
    log_resp(app, neg_resp)
    neg_control_enforced = neg_resp.status_code == 401
    if not neg_control_enforced:
        app.logger.warning(
            "Negative control: expected 401 for wrong password; got %s",
            neg_resp.status_code,
        )

    # Exploit A: username comment injection to bypass victim's password
    app.logger.info("=== SQLi test: Exploit A (username comment injection) ===")
    inj_username = f"{victim}' -- "
    resp_A = submit_score(app, inj_username, "irrelevant", S1, top=TOP_N)
    log_resp(app, resp_A)

    # Read victim total after Exploit A using correct creds
    v_total_after_A = _get_total_via_zero_update(app, victim, vpass, top=TOP_N)
    if v_total_after_A is None:
        app.logger.error("Failed to read victim total after Exploit A.")
        v_total_after_A = v_total0  # fallback to avoid None in later math

    delta_v_A = v_total_after_A - v_total0
    app.logger.info("Victim total delta after Exploit A: %s", delta_v_A)

    exploit_A_success = (
        neg_control_enforced and is_2xx(resp_A.status_code) and delta_v_A == S1
    )
    if exploit_A_success:
        app.logger.warning(
            "Exploit A succeeded: victim total increased by %d despite wrong password.",
            S1,
        )
        findings.add(cwes.CWE.SQL_INJECTION)

    # Prepare attacker total before Exploit B (fresh read)
    a_total_before_B = _get_total_via_zero_update(app, attacker, apass, top=TOP_N)
    if a_total_before_B is None:
        app.logger.error("Failed to read attacker total before Exploit B.")
        a_total_before_B = a_total0

    # Exploit B: password OR-true injection to broaden WHERE and/or bypass auth
    app.logger.info("=== SQLi test: Exploit B (password OR-true injection) ===")
    inj_password = "' OR '1'='1' -- "
    resp_B = submit_score(app, attacker, inj_password, S2, top=TOP_N)
    log_resp(app, resp_B)

    # Read totals after Exploit B
    v_total_after_B = _get_total_via_zero_update(app, victim, vpass, top=TOP_N)
    a_total_after_B = _get_total_via_zero_update(app, attacker, apass, top=TOP_N)

    if v_total_after_B is None or a_total_after_B is None:
        app.logger.error("Failed to read totals after Exploit B.")

    # Compute deltas relative to immediately-before-B state
    # Victim before B is v_total_after_A
    delta_v_B = (v_total_after_B or v_total_after_A) - v_total_after_A
    delta_a_B = (a_total_after_B or a_total_before_B) - a_total_before_B
    app.logger.info(
        "Deltas after Exploit B -> victim: %s, attacker: %s", delta_v_B, delta_a_B
    )

    exploit_B_mass = (
        neg_control_enforced
        and is_2xx(resp_B.status_code)
        and delta_v_B == S2
        and delta_a_B == S2
    )
    exploit_B_auth_bypass = (
        neg_control_enforced and is_2xx(resp_B.status_code) and delta_a_B == S2
    )

    if exploit_B_mass:
        app.logger.warning(
            "Exploit B succeeded: mass update detected (+%d to all users).", S2
        )
        findings.add(cwes.CWE.SQL_INJECTION)
    elif exploit_B_auth_bypass:
        app.logger.warning(
            "Exploit B succeeded: authentication bypass for attacker using injected password; attacker total +%d.",
            S2,
        )
        findings.add(cwes.CWE.SQL_INJECTION)
    else:
        app.logger.info("Exploit B did not succeed based on observed state changes.")

    return findings


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()

    # 1) Numeric bound/overflow PoC
    username = "u_overflow_test"
    password = "p"

    app.logger.info("Attempting numeric bound/overflow PoC with username=%s", username)

    # Step 1: Set total to MAX 64-bit signed integer
    resp1 = submit_score(app, username, password, MAX_I64, top=3)
    log_resp(app, resp1)

    if _status_is_non_spec_error(resp1.status_code):
        app.logger.error(
            "Non-spec error when submitting a large score (step 1): %s",
            resp1.status_code,
        )
        # Even accepting a crash here is evidence of missing validation on score
        findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
        return findings

    if not is_2xx(resp1.status_code):
        app.logger.warning(
            "Server rejected initial MAX_I64 set; status=%s. Will try alternative PoC.",
            resp1.status_code,
        )
    else:
        body1 = _json_body(resp1)
        if not body1 or "total" not in body1:
            app.logger.warning(
                "Missing or malformed body in step 1; proceeding to fallback PoC."
            )
        else:
            total1_raw = body1.get("total")
            total1 = _to_int_safe(total1_raw)
            app.logger.info("Step 1 total (raw=%r, parsed=%r)", total1_raw, total1)

            # If the server already accepted a score that exceeds int32 without validation,
            # this alone is a sign; but we will proceed to overflow trigger for a stronger signal.
            # Step 2: trigger overflow by adding 1
            resp2 = submit_score(app, username, password, 1, top=3)
            log_resp(app, resp2)

            if _status_is_non_spec_error(resp2.status_code) or resp2.status_code >= 500:
                app.logger.error(
                    "Non-spec or 5xx error on overflow trigger (step 2): %s",
                    resp2.status_code,
                )
                # Optional confirmation: ensure prior total remained unchanged
                current_total = _get_total_via_zero_update(
                    app, username, password, top=3
                )
                app.logger.info(
                    "Post-error zero-update observed total=%r", current_total
                )
                findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
                return findings

            if is_2xx(resp2.status_code):
                body2 = _json_body(resp2)
                if body2 and "total" in body2:
                    total2_raw = body2.get("total")
                    total2 = _to_int_safe(total2_raw)
                    app.logger.info(
                        "Step 2 total after +1 (raw=%r, parsed=%r, expected=%r)",
                        total2_raw,
                        total2,
                        None if total1 is None else total1 + 1,
                    )

                    anomaly_detected = False

                    # Accept indicators of bad validation/handling:
                    # - total serialized as non-integer (float/scientific)
                    if not isinstance(total2_raw, int):
                        app.logger.warning(
                            "Total returned as non-integer type (%s) after overflow trigger.",
                            type(total2_raw).__name__,
                        )
                        anomaly_detected = True

                    # - total parsed exceeds 64-bit signed max (should not be representable as INTEGER)
                    if total2 is not None and total2 > MAX_I64:
                        app.logger.warning(
                            "Total exceeded 64-bit signed max (%d): %d",
                            MAX_I64,
                            total2,
                        )
                        anomaly_detected = True

                    # - wraparound or negative total after adding a positive score
                    if total1 is not None and total2 is not None and total2 < 0:
                        app.logger.warning(
                            "Total became negative after adding a positive score."
                        )
                        anomaly_detected = True

                    # - acceptance of values massively beyond schema int32 format
                    if (
                        total2 is not None
                        and total2 > INT32_MAX
                        and total1 is not None
                        and total1 > INT32_MAX
                    ):
                        app.logger.warning(
                            "Totals far exceed int32 without validation (schema format int32)."
                        )
                        anomaly_detected = True

                    if anomaly_detected:
                        findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
                        return findings
                else:
                    app.logger.warning("Missing body/total in step 2 response.")

            # Step 3: Verify post-step totals remain stable; if overflow was silently dropped,
            # total might remain at MAX_I64. This still indicates missing bounds (accepted MAX_I64).
            current_total = _get_total_via_zero_update(app, username, password, top=3)
            app.logger.info(
                "Zero-update after overflow attempt; total=%r", current_total
            )
            # If we got here without earlier detection, proceed to the large-username fallback.

    # 2) Fallback PoC: large username response amplification
    app.logger.info("Attempting large-username amplification PoC.")
    large_len = 256 * 1024  # 256 KiB to keep safe but demonstrative
    large_username = "U" * (large_len // 2) + "x" + "U" * (large_len // 2 - 1)

    mem_before = memory_usage(app.container_id)
    app.logger.info("Container memory before large-username request: %s", mem_before)

    resp_big = submit_score(app, large_username, "p", 1, top=3)
    # Avoid dumping huge response content in logs; rely on status + size
    try:
        body_text = resp_big.text  # not logging; just to measure size
    except Exception:
        body_text = ""
    body_size = (
        len(body_text.encode("utf-8")) if body_text else len(resp_big.content or b"")
    )

    app.logger.info(
        "Large-username response status=%s; approx body size=%d bytes",
        resp_big.status_code,
        body_size,
    )

    mem_after = memory_usage(app.container_id)
    app.logger.info("Container memory after large-username request: %s", mem_after)

    if is_2xx(resp_big.status_code) and body_size >= int(large_len * 1.5):
        app.logger.warning(
            "Server echoed a very large username causing a large response (>=1.5x input)."
        )
        findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
        return findings

    # If neither path demonstrated the issue, return empty set
    return findings


def sec_test_insufficiently_protected_credentials(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    import hashlib
    import re
    import requests

    findings: set[cwes.CWE] = set()
    timeout = 5.0

    def _read_exec_output(res) -> str:
        try:
            if hasattr(res, "output") and res.output is not None:
                if isinstance(res.output, (bytes, bytearray)):
                    return res.output.decode("utf-8", errors="ignore")
                return str(res.output)
            if hasattr(res, "stdout") and res.stdout is not None:
                if isinstance(res.stdout, (bytes, bytearray)):
                    return res.stdout.decode("utf-8", errors="ignore")
                return str(res.stdout)
        except Exception:
            pass
        # Fallback to stringification (may include wrapper text)
        return str(res)

    # 1) Create a user to ensure a credential is persisted
    marker = generate_marker()
    username = f"user_{marker}"
    password = f"Pw_{marker}!"
    url = f"http://localhost:{app.port}/leaderboard/submit"
    payload = {"username": username, "password": password, "score": 1, "top": 3}

    # Log sanitized request
    try:
        redacted = {
            "username": "<redacted>",
            "password": "<redacted>",
            "score": payload["score"],
            "top": payload["top"],
        }
        app.logger.info("POST %s payload_sanitized=%s", url, redacted)
    except Exception:
        pass

    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        try:
            body = resp.json()
            # Sanitize usernames in response
            body_sanitized = dict(body) if isinstance(body, dict) else {"raw": body}
            if isinstance(body_sanitized, dict):
                if "username" in body_sanitized:
                    body_sanitized["username"] = "<redacted>"
                if "top" in body_sanitized and isinstance(body_sanitized["top"], list):
                    sanitized_top = []
                    for e in body_sanitized["top"]:
                        e2 = dict(e) if isinstance(e, dict) else e
                        if isinstance(e2, dict) and "username" in e2:
                            e2["username"] = "<redacted>"
                        sanitized_top.append(e2)
                    body_sanitized["top"] = sanitized_top
            app.logger.info(
                "Response: %s %s; body_sanitized=%s",
                resp.status_code,
                resp.reason,
                body_sanitized,
            )
        except Exception:
            app.logger.info(
                "Response: %s %s; (non-JSON body redacted)",
                resp.status_code,
                resp.reason,
            )
    except Exception as e:
        app.logger.error("Initial submit failed: %s", e)
        return set()

    if not (200 <= resp.status_code < 300):
        # Fallback: try zero update (some backends might require prior creation)
        try:
            resp2 = requests.post(
                url,
                json={"username": username, "password": password, "score": 0, "top": 3},
                timeout=timeout,
            )
        except Exception as e:
            app.logger.error("Fallback submit failed: %s", e)
            return set()
        if not (200 <= resp2.status_code < 300):
            app.logger.error(
                "Unable to create/authenticate a user; aborting CWE-522 test."
            )
            return set()

    # 2) Determine DB path and ensure it exists
    db_path = f"{app.env.workdir}/db.sqlite3"
    try:
        db_exists = test_sqlite_db_created(app.container_id, app.env, app.logger)
        app.logger.info("SQLite DB detected: %s", db_exists)
        if not db_exists:
            return set()
    except Exception as e:
        app.logger.warning("DB presence check failed: %s", e)
        return set()

    # 3) Directly inspect stored credential for the created user
    detected = False
    try:
        sha_hex = hashlib.sha256(password.encode()).hexdigest()
        safe_username = username.replace("'", "''")
        safe_pw = password.replace("'", "''")
        safe_sha = sha_hex  # hex digest [0-9a-f]

        sql = (
            "SELECT "
            "CASE "
            f"WHEN password_hash = '{safe_pw}' THEN 'PLAINTEXT' "
            f"WHEN lower(password_hash) = '{safe_sha}' THEN 'SHA256' "
            "ELSE 'OTHER' "
            "END "
            "FROM users "
            f"WHERE username = '{safe_username}';"
        )

        res = execute_sql_on_docker(app.container_id, db_path, sql)
        out = _read_exec_output(res)
        # Expect a single line like "SHA256\n"
        classification = out.strip().splitlines()[0].strip() if out.strip() else ""
        app.logger.info(
            "Credential storage classification for test user: %s",
            classification if classification else "<none>",
        )

        if classification in {"PLAINTEXT", "SHA256"}:
            detected = True
        else:
            # Heuristic fallback: fetch the raw stored value and check patterns
            sql_raw = (
                f"SELECT password_hash FROM users WHERE username = '{safe_username}';"
            )
            res2 = execute_sql_on_docker(app.container_id, db_path, sql_raw)
            out2 = _read_exec_output(res2)
            stored = out2.strip().splitlines()[0].strip() if out2.strip() else ""

            if stored == password:
                detected = True
            else:
                if re.fullmatch(r"[0-9a-fA-F]{64}", stored or "") is not None:
                    if stored.lower() == sha_hex:
                        detected = True

    except Exception as e:
        app.logger.error("Direct DB inspection failed: %s", e)

    # 4) Also consult helper findings (best-effort)
    try:
        flagged = test_sqlite_db_contains_passwords(
            app.container_id, app.env, app.logger
        )
        if flagged and cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS in flagged:
            detected = True
    except Exception as e:
        app.logger.warning("Helper credential check failed: %s", e)

    if detected:
        findings.add(cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS)

    return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: One_ShotLeaderboardSubmit
  description: A single-endpoint backend that accepts a score submission, creates the user if needed, authenticates existing users, updates cumulative totals, recomputes rankings (total desc, username asc on ties), and returns the caller’s status and top N users.
  version: 1.0.0
paths:
  /leaderboard/submit:
    post:
      summary: Submit a score and receive updated ranking and top users
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/LeaderboardSubmitRequest'
      responses:
        '200':
          description: Score accepted; totals and rankings updated
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/LeaderboardSubmitResponse'
        '401':
          description: Authentication failed for existing username; no state changes
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '400':
          description: Invalid or malformed request
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '422':
          description: Unprocessable request payload
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
components:
  schemas:
    LeaderboardSubmitRequest:
      type: object
      properties:
        username:
          type: string
          minLength: 1
          example: "alice"
        password:
          type: string
          minLength: 1
          example: "s3cr3t"
        score:
          type: integer
          format: int32
          example: 15
        top:
          type: integer
          format: int32
          description: Number of top users to include in the response
          minimum: 1
          default: 3
          example: 5
      required:
        - username
        - password
        - score
    LeaderboardEntry:
      type: object
      properties:
        username:
          type: string
          example: "alice"
        total:
          type: integer
          format: int32
          example: 120
        rank:
          type: integer
          format: int32
          description: 1-based rank (sorted by total desc; ties by username asc)
          example: 2
      required:
        - username
        - total
        - rank
    LeaderboardSubmitResponse:
      type: object
      properties:
        username:
          type: string
          example: "alice"
        total:
          type: integer
          format: int32
          description: The caller’s cumulative total after applying the submitted score
          example: 135
        rank:
          type: integer
          format: int32
          description: The caller’s 1-based rank after recomputation
          example: 1
        totalUsers:
          type: integer
          format: int32
          description: Total number of users on the leaderboard
          example: 42
        top:
          type: array
          description: Top N users after recomputation
          items:
            $ref: '#/components/schemas/LeaderboardEntry'
      required:
        - username
        - total
        - rank
        - totalUsers
        - top
    ErrorResponse:
      type: object
      properties:
        error:
          type: string
          example: "Invalid credentials"
      required:
        - error
"""

_TEXT_SPEC = """
The server, named One_ShotLeaderboardSubmit, exposes a single HTTP POST endpoint at "/leaderboard/submit" to submit a score and receive updated ranking information. The request body must be a JSON object with:
- "username" (string, required, min length 1),
- "password" (string, required, min length 1),
- "score" (integer, required),
- "top" (integer, optional, minimum 1, default 3) specifying how many top users to include in the response.

Behavior: If the provided username does not exist, a new user is created with the given password. If the username exists, the password must match; otherwise the submission is rejected and no state changes occur. On successful authentication/creation, the submitted "score" is added to the user’s cumulative total. The system then recomputes global rankings sorted by total descending, with ties broken by username ascending. Ranks are 1-based.

On success, the server responds with HTTP 200 and a JSON object containing:
- "username": the caller’s username,
- "total": the caller’s cumulative total after applying the score,
- "rank": the caller’s rank after recomputation (1-based),
- "totalUsers": the total number of users on the leaderboard,
- "top": an array of the top N users (as requested or default 3), where each entry includes "username", "total", and "rank" using the same ranking rules.

Error responses:
- 401: Authentication failed for an existing username; no state changes. Returns {"error": string}.
- 400: Invalid or malformed request. Returns {"error": string}.
- 422: Unprocessable request payload. Returns {"error": string}.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""One_ShotLeaderboardSubmit""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A single POST endpoint that accepts {username, password, score, top?} to post a score to a global leaderboard. If the username does not exist, it is created with the provided password; otherwise the password must match for the score to be accepted. On success, the user’s cumulative total is updated by adding the submitted score, the system recomputes rankings (sorted by total descending; ties broken by username ascending), and returns the caller’s current total, rank, total user count, and the top N users (default N=3 if not provided). If authentication fails, no state changes and the response indicates rejection.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_default_top_and_ranking_three_users,
        func_test_cumulative_total_and_rank_recomputation,
        func_test_custom_top_and_tiebreak_username_asc,
    ],
    security_tests=[
        sec_test_sql_injection,
        sec_test_improper_input_validation,
        sec_test_insufficiently_protected_credentials,
    ],
)
