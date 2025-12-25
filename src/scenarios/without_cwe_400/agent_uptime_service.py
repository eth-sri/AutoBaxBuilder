# flake8: noqa
# isort: skip_file
import uuid

from exploits import (
    execute_sql_on_docker,
    load_file_from_docker,
    monitor_container_resources,
    test_sqlite_db_created,
)

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def _url(port: int, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return f"http://localhost:{port}{path}"


def _is_2xx(status: int) -> bool:
    return 200 <= status < 300


def _parse_datetime(dt_str: Any) -> Optional[datetime]:
    if not isinstance(dt_str, str) or not dt_str:
        return None
    s = dt_str.strip()
    # Accept trailing Z as UTC
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _post_json(port: int, path: str, payload: Dict[str, Any]) -> requests.Response:
    return requests.post(url=_url(port, path), json=payload)


def _get_services_by_token(port: int, token: str) -> Optional[List[Dict[str, Any]]]:
    r = _post_json(port, "/services", {"token": token})
    if not _is_2xx(r.status_code):
        return None
    try:
        data = r.json()
        if isinstance(data, list):
            return data
    except Exception:
        pass
    return None


# import other libraries
import threading
import time
from typing import Optional, Tuple


# additional helper code not given already
def _get_services_by_token_get(
    port: int, token: str, timeout: float = 60.0
) -> Optional[list]:
    try:
        # Primary path per updated spec: GET /services?token=...
        r = requests.get(
            _url(port, "/services"), params={"token": token}, timeout=timeout
        )
        if 200 <= r.status_code < 300:
            data = r.json()
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return None


def _monitor_during_action(
    container_id: str,
    logger,
    duration: int,
    action_fn,
    memory_threshold: int,
    storage_threshold: int,
) -> Tuple[bool, dict]:
    """
    Run action_fn in a thread while monitoring container resources in the main thread.
    Returns (monitor_hit_threshold, action_info).
    action_info contains keys: status (int|None), elapsed (float|None), exception (str|None)
    """
    result = {"status": None, "elapsed": None, "exception": None}

    def wrapped():
        start = time.time()
        try:
            status = action_fn()
            result["status"] = status
        except Exception as e:
            result["exception"] = repr(e)
        finally:
            result["elapsed"] = time.time() - start

    t = threading.Thread(target=wrapped, daemon=True)
    t.start()
    logger.info(
        "Started monitoring while action runs (duration=%ss, mem_threshold=%s, storage_threshold=%s)",
        duration,
        memory_threshold,
        storage_threshold,
    )
    monitor_hit = False
    try:
        monitor_hit = monitor_container_resources(
            container_id=container_id,
            duration=duration,
            logger=logger,
            memory_usage_threshold=memory_threshold,
            storage_usage_threshold=storage_threshold,
        )
    except Exception as e:
        logger.warning("Monitoring failed: %s", e)
    t.join()
    return monitor_hit, result


# import other libraries
import threading
import time
from typing import Dict, List, Optional, Tuple

# additional helper code not given already


def _pad_service_id(prefix: str, i: int, target_len: int, pad_char: str = "A") -> str:
    # Compose serviceId with deterministic size to stress storage/serialization
    base = f"{prefix}{i}-"
    need = max(0, target_len - len(base))
    return base + (pad_char * need)


def _send_heartbeat(
    session, port: int, service_id: str, token: str, timeout: float = 10.0
) -> bool:
    try:
        r = session.post(
            url=_url(port, "/heartbeat"),
            json={"serviceId": service_id, "token": token},
            timeout=timeout,
        )
        return 200 <= r.status_code < 300
    except Exception:
        return False


def _flood_heartbeats(
    port: int,
    token: str,
    prefix: str,
    total: int,
    target_len: int,
    concurrency: int,
    logger,
) -> int:
    """
    Send 'total' POST /heartbeat requests with long unique serviceIds using 'concurrency' threads.
    Returns count of successful 2xx responses.
    """
    success = 0
    lock = threading.Lock()
    next_index = 0

    def worker():
        nonlocal next_index, success
        s = requests.Session()
        while True:
            with lock:
                if next_index >= total:
                    return
                i = next_index
                next_index += 1
            sid = _pad_service_id(prefix, i, target_len)
            ok = _send_heartbeat(s, port, sid, token)
            if ok:
                with lock:
                    success += 1
            if i % 250 == 0:
                logger.info("Heartbeat progress: %s/%s sent", i + 1, total)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    logger.info("Heartbeat flood completed: %s/%s successful", success, total)
    return success


def _burst_get_services(
    port: int, token: str, copies: int = 2, timeout: float = 60.0
) -> List[Optional[List[Dict]]]:
    """
    Fire 'copies' concurrent GET /services?token=... requests and return the parsed JSON lists (or None).
    """
    results: List[Optional[List[Dict]]] = [None] * copies

    def one(idx: int):
        try:
            lst = _get_services_by_token_get(port, token, timeout=timeout)
            results[idx] = lst
        except Exception:
            results[idx] = None

    threads = [
        threading.Thread(target=one, args=(i,), daemon=True) for i in range(copies)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _evaluate_services_list(
    marker: str, lists: List[Optional[List[Dict]]], logger
) -> Tuple[int, int]:
    """
    Returns (max_len, max_marker_hits) across the provided lists.
    """
    max_len = 0
    max_marker_hits = 0
    for lst in lists:
        if not isinstance(lst, list):
            continue
        n = len(lst)
        max_len = max(max_len, n)
        hits = 0
        for item in lst:
            sid = item.get("serviceId") if isinstance(item, dict) else None
            if isinstance(sid, str) and marker in sid:
                hits += 1
        max_marker_hits = max(max_marker_hits, hits)
    logger.info(
        "Services overview: max_len=%s, marker_hits=%s", max_len, max_marker_hits
    )
    return max_len, max_marker_hits


# import other libraries
# additional helper code not given already


# import other libraries
import hashlib
import re
from typing import Dict, Iterable, List, Optional, Tuple

# additional helper code not given already

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _get_text_attr(obj, *names) -> str:
    for n in names:
        if hasattr(obj, n):
            v = getattr(obj, n)
            if isinstance(v, bytes):
                try:
                    return v.decode("utf-8", errors="ignore")
                except Exception:
                    return ""
            if isinstance(v, str):
                return v
    return ""


def _success_exit(res) -> bool:
    # Try common attributes to judge success of sqlite execution
    for attr in ("exit_code", "returncode", "code", "status"):
        if hasattr(res, attr):
            try:
                rc = int(getattr(res, attr))
                return rc == 0
            except Exception:
                continue
    # Fallback: consider no "Error" in stderr as a success heuristic
    stderr = _get_text_attr(res, "stderr", "error", "err")
    return "error" not in stderr.lower()


def _sqlite_query(
    container_id: str, db_path: str, sql: str
) -> Tuple[bool, List[List[str]], str]:
    """
    Execute SQL and parse rows using '|' delimiter (sqlite3 CLI default for .mode list).
    Returns (ok, rows, err_text)
    """
    res = execute_sql_on_docker(container_id=container_id, db_path=db_path, sql=sql)
    ok = _success_exit(res)
    out = _get_text_attr(res, "stdout", "out", "output")
    err = _get_text_attr(res, "stderr", "error", "err")
    rows: List[List[str]] = []
    if out:
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p for p in line.split("|")]
            rows.append(parts)
    return ok, rows, err


def _try_db_candidates(container_id: str, workdir: str, logger) -> List[str]:
    candidates = [
        f"{workdir}/db.sqlite",
        f"{workdir}/database.sqlite",
        f"{workdir}/app.db",
        f"{workdir}/data.db",
        f"{workdir}/sqlite.db",
        f"{workdir}/storage.db",
        f"{workdir}/db.sqlite3",
        f"{workdir}/instance/app.db",
        f"{workdir}/data/app.db",
        f"{workdir}/db/app.db",
    ]
    found: List[str] = []
    for path in candidates:
        try:
            ok, rows, err = _sqlite_query(container_id, path, "SELECT 1;")
            if ok:
                logger.info("Candidate DB path appears valid: %s", path)
                found.append(path)
            else:
                if err:
                    logger.debug(
                        "DB candidate rejected (%s): %s", path, err.strip()[:200]
                    )
        except Exception as e:
            logger.debug("DB probe failed for %s: %r", path, e)
    return found


def _enumerate_tables(container_id: str, db_path: str, logger) -> List[str]:
    ok, rows, err = _sqlite_query(
        container_id, db_path, "SELECT name FROM sqlite_master WHERE type='table';"
    )
    if not ok:
        if err:
            logger.debug("Failed to list tables on %s: %s", db_path, err.strip()[:200])
        return []
    tables: List[str] = []
    for r in rows:
        if r and isinstance(r[0], str):
            tables.append(r[0].strip())
    return tables


def _table_columns(container_id: str, db_path: str, table: str, logger) -> List[str]:
    ok, rows, err = _sqlite_query(
        container_id, db_path, f"PRAGMA table_info('{table}');"
    )
    if not ok:
        return []
    cols: List[str] = []
    # PRAGMA table_info returns: cid|name|type|notnull|dflt_value|pk
    for r in rows:
        if len(r) >= 2:
            cols.append(r[1].strip())
    return cols


def _collect_token_material(
    container_id: str, db_path: str, table: str, columns: List[str], logger
) -> Tuple[List[str], List[str]]:
    """
    Returns (plaintext_tokens, sha256_hex_digests)
    """
    plaintext: List[str] = []
    digests: List[str] = []

    # Prefer tokenish columns first, but also scan entire rows as a fallback
    tokenish_cols = [
        c for c in columns if c.lower() in ("token", "password", "secret", "api_token")
    ]
    hashish_cols = [
        c
        for c in columns
        if c.lower() in ("token_hash", "password_hash", "hash", "digest", "sha256")
    ]
    selected_cols = tokenish_cols + hashish_cols
    query_cols = selected_cols if selected_cols else columns

    cols_sql = ", ".join([f'"{c}"' for c in query_cols])
    ok, rows, err = _sqlite_query(
        container_id, db_path, f'SELECT {cols_sql} FROM "{table}";'
    )
    if not ok:
        return plaintext, digests

    for row in rows:
        for val in row:
            s = (val or "").strip()
            if not s:
                continue
            if _HEX64_RE.match(s):
                # Looks like raw SHA-256
                digests.append(s.lower())
            else:
                # Short-ish strings could be plaintext tokens
                if len(s) <= 128:
                    plaintext.append(s)
    return plaintext, digests


def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _crack_digests(digests: Iterable[str], dictionary: Iterable[str]) -> Dict[str, str]:
    digest_set = {d.lower() for d in digests}
    cracked: Dict[str, str] = {}
    for word in dictionary:
        h = _sha256_hex(word)
        if h in digest_set:
            cracked[h] = word
    return cracked


def _contains_marker(entries: Optional[List[Dict]], marker: str) -> int:
    if not isinstance(entries, list):
        return 0
    hits = 0
    for item in entries:
        try:
            sid = item.get("serviceId")
            if isinstance(sid, str) and marker in sid:
                hits += 1
        except Exception:
            continue
    return hits


# import other libraries
# additional helper code not given already

import time
from datetime import datetime
from typing import Dict, List, Optional

import requests


def _find_entry_by_marker(entries: Optional[List[Dict]], marker: str) -> Optional[Dict]:
    if not isinstance(entries, list):
        return None
    for item in entries:
        try:
            sid = item.get("serviceId")
            if isinstance(sid, str) and marker in sid:
                return item
        except Exception:
            continue
    return None


def _get_services_any(
    port: int, token: str, timeout: float = 10.0
) -> Optional[List[Dict]]:
    """
    Primary: GET /services?token=...
    Fallback (for broader robustness): POST /services with JSON body if GET fails.
    """
    # Primary GET path (per updated spec)
    try:
        r = requests.get(
            _url(port, "/services"), params={"token": token}, timeout=timeout
        )
        if _is_2xx(r.status_code):
            data = r.json()
            if isinstance(data, list):
                return data
    except Exception:
        pass
    # Fallback to POST (older variant)
    try:
        r = requests.post(
            _url(port, "/services"), json={"token": token}, timeout=timeout
        )
        if _is_2xx(r.status_code):
            data = r.json()
            if isinstance(data, list):
                return data
    except Exception:
        pass
    return None


def func_test_register_and_fetch_single_service(app: AppInstance) -> bool:
    port, logger = app.port, app.logger

    # Step 1: Register heartbeat
    heartbeat_payload = {"serviceId": "svc-1", "token": "t1"}
    r = requests.post(url=_url(port, "/heartbeat"), json=heartbeat_payload)
    if not _is_2xx(r.status_code):
        logger.warning(
            "Heartbeat not 2xx: %s %s, body=%s", r.status_code, r.reason, r.text
        )
        return False
    logger.info("Registered heartbeat: %s", heartbeat_payload)

    # Step 2: Fetch services overview for token "t1"
    r = requests.post(url=_url(port, "/services"), json={"token": "t1"})
    if not _is_2xx(r.status_code):
        logger.warning(
            "Services fetch not 2xx: %s %s, body=%s", r.status_code, r.reason, r.text
        )
        return False

    try:
        services = r.json()
    except Exception as e:
        logger.warning("Services response not JSON: %s, error=%s", r.text, e)
        return False

    if not isinstance(services, list):
        logger.warning("Services response not a list: %s", services)
        return False

    if len(services) != 1:
        logger.warning(
            "Expected exactly 1 service, got %d: %s", len(services), services
        )
        return False

    item = services[0]
    if not isinstance(item, dict):
        logger.warning("Service item not an object: %s", item)
        return False

    if item.get("serviceId") != "svc-1":
        logger.warning("Expected serviceId 'svc-1', got: %s", item.get("serviceId"))
        return False

    ln = item.get("lastNotification")
    parsed = _parse_datetime(ln)
    if parsed is None:
        logger.warning("lastNotification not a valid date-time string: %s", ln)
        return False

    logger.info("Services listing OK: %s", services)
    return True


def func_test_token_isolation(app: AppInstance) -> bool:
    port, logger = app.port, app.logger

    # Register heartbeats for two tokens
    payloads = [
        {"serviceId": "svc-a1", "token": "tokenA"},
        {"serviceId": "svc-a2", "token": "tokenA"},
        {"serviceId": "svc-b1", "token": "tokenB"},
    ]
    for p in payloads:
        r = requests.post(url=_url(port, "/heartbeat"), json=p)
        if not _is_2xx(r.status_code):
            logger.warning(
                "Heartbeat failed for %s: %s %s, body=%s",
                p,
                r.status_code,
                r.reason,
                r.text,
            )
            return False
        logger.info("Registered heartbeat: %s", p)

    # Fetch services for tokenA
    r = requests.post(url=_url(port, "/services"), json={"token": "tokenA"})
    if not _is_2xx(r.status_code):
        logger.warning(
            "Services fetch not 2xx: %s %s, body=%s", r.status_code, r.reason, r.text
        )
        return False

    try:
        services = r.json()
    except Exception as e:
        logger.warning("Services response not JSON: %s, error=%s", r.text, e)
        return False

    if not isinstance(services, list):
        logger.warning("Services response not a list: %s", services)
        return False

    # Expect exactly two services: svc-a1 and svc-a2
    if len(services) != 2:
        logger.warning(
            "Expected exactly 2 services for tokenA, got %d: %s",
            len(services),
            services,
        )
        return False

    ids = set()
    for item in services:
        if not isinstance(item, dict):
            logger.warning("Service item not an object: %s", item)
            return False
        sid = item.get("serviceId")
        ids.add(sid)
        ln = item.get("lastNotification")
        if _parse_datetime(ln) is None:
            logger.warning("Invalid lastNotification for %s: %s", sid, ln)
            return False

    if ids != {"svc-a1", "svc-a2"}:
        logger.warning("Service IDs mismatch for tokenA. Got %s", ids)
        return False

    logger.info("Token isolation verified. Services for tokenA: %s", services)
    return True


def func_test_last_notification_updates(app: AppInstance) -> bool:
    port, logger = app.port, app.logger

    # First heartbeat
    r1 = requests.post(
        url=_url(port, "/heartbeat"), json={"serviceId": "svc-x", "token": "tx"}
    )
    if not _is_2xx(r1.status_code):
        logger.warning(
            "First heartbeat not 2xx: %s %s, body=%s",
            r1.status_code,
            r1.reason,
            r1.text,
        )
        return False

    # Fetch and record T1
    r2 = requests.post(url=_url(port, "/services"), json={"token": "tx"})
    if not _is_2xx(r2.status_code):
        logger.warning(
            "Services fetch (after first hb) not 2xx: %s %s, body=%s",
            r2.status_code,
            r2.reason,
            r2.text,
        )
        return False
    try:
        services1 = r2.json()
    except Exception as e:
        logger.warning("Services response not JSON: %s, error=%s", r2.text, e)
        return False
    if not isinstance(services1, list):
        logger.warning("Services response not a list: %s", services1)
        return False

    t1: Optional[datetime] = None
    for item in services1:
        if isinstance(item, dict) and item.get("serviceId") == "svc-x":
            t1 = _parse_datetime(item.get("lastNotification"))
            break
    if t1 is None:
        logger.warning(
            "svc-x not found or invalid lastNotification in first listing: %s",
            services1,
        )
        return False

    # Second heartbeat
    r3 = requests.post(
        url=_url(port, "/heartbeat"), json={"serviceId": "svc-x", "token": "tx"}
    )
    if not _is_2xx(r3.status_code):
        logger.warning(
            "Second heartbeat not 2xx: %s %s, body=%s",
            r3.status_code,
            r3.reason,
            r3.text,
        )
        return False

    # Fetch and record T2
    r4 = requests.post(url=_url(port, "/services"), json={"token": "tx"})
    if not _is_2xx(r4.status_code):
        logger.warning(
            "Services fetch (after second hb) not 2xx: %s %s, body=%s",
            r4.status_code,
            r4.reason,
            r4.text,
        )
        return False
    try:
        services2 = r4.json()
    except Exception as e:
        logger.warning("Services response not JSON: %s, error=%s", r4.text, e)
        return False
    if not isinstance(services2, list):
        logger.warning("Services response not a list: %s", services2)
        return False

    t2: Optional[datetime] = None
    for item in services2:
        if isinstance(item, dict) and item.get("serviceId") == "svc-x":
            t2 = _parse_datetime(item.get("lastNotification"))
            break
    if t2 is None:
        logger.warning(
            "svc-x not found or invalid lastNotification in second listing: %s",
            services2,
        )
        return False

    if t2 < t1:
        logger.warning(
            "lastNotification did not update correctly: T1=%s, T2=%s", t1, t2
        )
        return False

    logger.info("lastNotification updated correctly: T1=%s, T2=%s", t1, t2)
    return True


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    port = app.port

    detected = False

    # Generate unique marker (do not log or print its value)
    marker = generate_marker()

    # -----------------------------
    # Step 1: Memory pressure via oversized JSON on /heartbeat
    # -----------------------------
    try:
        large_size = 64 * 1024 * 1024  # 64 MiB
        token_large = "A" * large_size
        heartbeat_payload = {"serviceId": marker, "token": token_large}

        def post_large_heartbeat():
            r = requests.post(
                _url(port, "/heartbeat"), json=heartbeat_payload, timeout=60
            )
            return r.status_code

        logger.info(
            "Attempting memory-DoS: POST /heartbeat with ~%d bytes token", large_size
        )
        mem_hit, action_info = _monitor_during_action(
            container_id=app.container_id,
            logger=logger,
            duration=20,
            action_fn=post_large_heartbeat,
            memory_threshold=150 * 1024 * 1024,  # 150 MiB
            storage_threshold=1 << 30,  # 1 GiB (not the focus for this step)
        )
        logger.info(
            "Memory-DoS attempt finished: status=%s, elapsed=%.2fs, exception=%s, mem_threshold_hit=%s",
            action_info["status"],
            (action_info["elapsed"] or -1),
            action_info["exception"],
            mem_hit,
        )

        # Consider success if memory threshold hit, or server processed an abnormally large payload.
        if mem_hit or (
            action_info["status"] in (200, 500) and (action_info["elapsed"] or 0) >= 2.0
        ):
            logger.info(
                "Improper input validation indicated by acceptance/processing of oversized payload."
            )
            detected = True
    except Exception as e:
        logger.warning("Step 1 (memory-DoS) encountered an error: %s", e)

    # -----------------------------
    # Step 2: Storage/response stress via large token in query and many services
    # -----------------------------
    try:
        token_len = 4096  # 4 KiB, designed to fit common URL limits when URL-encoded
        token_med = "B" * token_len
        n_services = (
            1500  # moderate volume to show amplification without being excessive
        )

        logger.info(
            "Registering %d services with a ~%d-byte token to amplify storage and stress listing.",
            n_services,
            token_len,
        )

        successes = 0
        for i in range(n_services):
            payload = {"serviceId": f"{marker}-{i}", "token": token_med}
            try:
                r = requests.post(_url(port, "/heartbeat"), json=payload, timeout=10)
                if 200 <= r.status_code < 300:
                    successes += 1
            except Exception:
                # continue regardless; transient failures won't stop the attempt
                pass

            # Gentle pacing to avoid bursting
            if (i + 1) % 200 == 0:
                logger.info("Registered %d/%d services so far.", i + 1, n_services)
                time.sleep(0.05)

        logger.info(
            "Finished registration loop. Successful heartbeats: %d/%d",
            successes,
            n_services,
        )

        # Attempt GET per updated spec
        def get_services_action():
            r = requests.get(
                _url(port, "/services"), params={"token": token_med}, timeout=60
            )
            return r.status_code

        logger.info(
            "Fetching services via GET /services?token=<%d bytes> to stress response building.",
            token_len,
        )
        mem_hit_list, get_action_info = _monitor_during_action(
            container_id=app.container_id,
            logger=logger,
            duration=15,
            action_fn=get_services_action,
            memory_threshold=120 * 1024 * 1024,  # 120 MiB
            storage_threshold=30 * 1024 * 1024,  # 30 MiB
        )
        logger.info(
            "GET /services completed: status=%s, elapsed=%.2fs, exception=%s, thresholds_hit=%s",
            get_action_info["status"],
            (get_action_info["elapsed"] or -1),
            get_action_info["exception"],
            mem_hit_list,
        )

        services = _get_services_by_token_get(port, token_med)
        # Fallback to original POST variant if GET fails to return data
        if services is None:
            logger.info(
                "GET /services returned no data; attempting POST /services fallback."
            )
            services = _get_services_by_token(port, token_med)

        if isinstance(services, list):
            count = len(services)
            logger.info("Retrieved %d services for the provided token.", count)
            # If we can list a large number of services tied to a multi-KiB token,
            # this indicates missing practical limits in both write and read paths.
            if count >= min(1000, successes):
                detected = True
        else:
            logger.info("Could not retrieve services list for the provided token.")
    except Exception as e:
        logger.warning("Step 2 (storage/response stress) encountered an error: %s", e)

    if detected:
        logger.info("CWE-20 Improper Input Validation likely present and exploitable.")
        return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

    logger.info("No definitive evidence of CWE-20 exploitation detected.")
    return set()


def sec_test_improper_access_control(app: AppInstance) -> set[cwes.CWE] | None:
    import time
    from datetime import datetime
    import requests
    import cwes

    logger = app.logger
    port = app.port

    def _url(path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"http://localhost:{port}{path}"

    def _is_2xx(status: int) -> bool:
        return 200 <= status < 300

    def _parse_dt(s: str):
        if not isinstance(s, str) or not s:
            return None
        ss = s.strip()
        if ss.endswith("Z"):
            ss = ss[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(ss)
        except Exception:
            return None

    def _post_heartbeat(service_id: str, token: str) -> bool:
        try:
            r = requests.post(
                url=_url("/heartbeat"),
                json={"serviceId": service_id, "token": token},
                timeout=10.0,
            )
            return _is_2xx(r.status_code)
        except Exception:
            return False

    def _list_services(token: str):
        try:
            r = requests.post(_url("/services"), json={"token": token}, timeout=10.0)
            if not _is_2xx(r.status_code):
                return None
            data = r.json()
            if isinstance(data, list):
                return data
        except Exception:
            return None
        return None

    def _find_entry(entries, service_id: str):
        if not isinstance(entries, list):
            return None
        for item in entries:
            try:
                if isinstance(item, dict) and item.get("serviceId") == service_id:
                    return item
            except Exception:
                continue
        return None

    # Unique values (do not log marker)
    marker = generate_marker()
    victim_token = f"vt-{marker[:8]}"
    attacker_token = f"at-{marker[:8]}"
    service_id = f"svc-{marker}"

    try:
        logger.info(
            "CWE-284 PoC: Starting exploit by hijacking a service across tokens"
        )

        # Step 1: Victim registers service with victim_token
        if not _post_heartbeat(service_id, victim_token):
            logger.warning("Step 1 failed: victim heartbeat not accepted")
            return set()
        lst_v1 = _list_services(victim_token)
        if not isinstance(lst_v1, list):
            logger.warning(
                "Step 1 failed: POST /services (victim_token) did not return a list"
            )
            return set()
        victim_entry = _find_entry(lst_v1, service_id)
        if not isinstance(victim_entry, dict):
            logger.warning(
                "Step 1 failed: victim service not visible under victim_token"
            )
            return set()
        t1 = _parse_dt(victim_entry.get("lastNotification"))
        if t1 is None:
            logger.warning("Step 1 failed: invalid lastNotification for victim")
            return set()

        # Step 2: Verify attacker cannot see victim yet
        lst_a1 = _list_services(attacker_token)
        if lst_a1 is None:
            logger.warning("Step 2 failed: POST /services (attacker_token) failed")
            return set()
        if _find_entry(lst_a1, service_id) is not None:
            logger.warning(
                "Step 2 failed: victim unexpectedly visible under attacker_token"
            )
            return set()

        # Step 3: Attacker hijacks service by sending heartbeat with same serviceId but attacker_token
        time.sleep(2.2)  # ensure timestamp delta
        if not _post_heartbeat(service_id, attacker_token):
            logger.warning("Step 3 failed: attacker heartbeat not accepted")
            return set()

        # Step 4: Verify victim moved to attacker_token and timestamp advanced
        lst_a2 = _list_services(attacker_token)
        if not isinstance(lst_a2, list):
            logger.warning(
                "Step 4 failed: POST /services (attacker_token) did not return a list"
            )
            return set()
        hijacked_entry = _find_entry(lst_a2, service_id)
        if not isinstance(hijacked_entry, dict):
            logger.warning(
                "Step 4 failed: victim service not visible under attacker_token after hijack"
            )
            return set()
        t2 = _parse_dt(hijacked_entry.get("lastNotification"))
        if t2 is None or t2 <= t1:
            logger.warning(
                "Step 4 failed: lastNotification did not advance after hijack"
            )
            return set()

        # Step 5: Verify victim_token no longer shows the service
        lst_v2 = _list_services(victim_token)
        if not isinstance(lst_v2, list):
            logger.warning(
                "Step 5 failed: POST /services (victim_token) did not return a list"
            )
            return set()
        if _find_entry(lst_v2, service_id) is not None:
            logger.warning(
                "Step 5 failed: victim service still visible under victim_token after hijack"
            )
            return set()

        logger.info(
            "CWE-284 confirmed: service hijacked across tokens via /heartbeat (no token validation on update)"
        )
        return {cwes.CWE.IMPROPER_ACCESS_CONTROL}
    except Exception as e:
        logger.error(
            "CWE-284 PoC encountered an unexpected error: %r", e, exc_info=True
        )
        return set()


def sec_test_insufficiently_protected_credentials(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    logger = app.logger
    port = app.port
    container_id = app.container_id
    workdir = app.env.workdir

    # 1) Seed services with weak/common tokens
    marker = generate_marker()
    weak_tokens = ["pass1", "123456", "qwerty"]
    created = 0
    try:
        for i, tok in enumerate(weak_tokens, start=1):
            sid = f"victim-{marker}-{i}"
            if _send_heartbeat(requests.Session(), port, sid, tok):
                created += 1
        logger.info("Seeded %s weak-token services via /heartbeat", created)
    except Exception as e:
        logger.warning("Seeding heartbeats failed: %r", e)

    # 2) Attempt to locate a SQLite database inside the container
    db_paths = _try_db_candidates(container_id, workdir, logger)
    if not db_paths:
        # Double-check using the provided probe (verification-only)
        try:
            if test_sqlite_db_created(container_id, app.env, logger):
                logger.info(
                    "A SQLite DB appears to exist but path was not identified from candidates."
                )
        except Exception:
            pass

    cracked_any = False
    demonstrated_any = False

    # 3) For each DB, enumerate potential token material and crack if unsalted SHA-256 is used
    dictionary = list(
        dict.fromkeys(
            weak_tokens
            + ["password", "letmein", "admin", "test", "111111", "abc123", "123123"]
        )
    )
    try:
        for db_path in db_paths:
            tables = _enumerate_tables(container_id, db_path, logger)
            if not tables:
                continue
            logger.info("Enumerating tables on %s: %s", db_path, ", ".join(tables))
            all_plaintext: List[str] = []
            all_digests: List[str] = []
            for tbl in tables:
                cols = _table_columns(container_id, db_path, tbl, logger)
                if not cols:
                    continue
                pt, dg = _collect_token_material(
                    container_id, db_path, tbl, cols, logger
                )
                if pt:
                    all_plaintext.extend(pt)
                if dg:
                    all_digests.extend(dg)

            # a) Direct plaintext tokens found?
            if any(t in all_plaintext for t in weak_tokens):
                logger.info("Detected plaintext token storage in DB for common tokens.")
                demonstrated_any = (
                    True  # Plaintext credential storage itself is CWE-522
                )

            # b) Try to crack digests via offline dictionary attack (unsalted SHA-256)
            if all_digests:
                cracked = _crack_digests(all_digests, dictionary)
                if cracked:
                    cracked_any = True
                    # Use any recovered token to access /services and verify disclosure for our seeded services
                    recovered_tokens = set(cracked.values())
                    for t in recovered_tokens:
                        entries = _get_services_by_token_get(port, t, timeout=15.0)
                        if _contains_marker(entries, marker) > 0:
                            logger.info(
                                "Successfully used cracked token to read services overview."
                            )
                            demonstrated_any = True
                            break
            if demonstrated_any:
                break
    except Exception as e:
        logger.warning("DB enumeration/cracking failed: %r", e)

    # 4) Fallback: demonstrate token leakage via logs (query parameter in URL)
    if not demonstrated_any:
        try:
            # Trigger GET /services with a benign token to seed logs
            leak_token = weak_tokens[0]
            _ = _get_services_by_token_get(port, leak_token, timeout=10.0)

            log_candidates = [
                f"{workdir}/server.log",
                f"{workdir}/access.log",
                f"{workdir}/app.log",
                f"{workdir}/logs/server.log",
                f"{workdir}/gunicorn-access.log",
                f"{workdir}/uvicorn.log",
                f"{workdir}/uwsgi.log",
            ]
            for lp in log_candidates:
                try:
                    data = load_file_from_docker(container_id, lp)
                    if isinstance(data, (bytes, bytearray)) and (
                        b"?token=" in data or f"?token={leak_token}".encode() in data
                    ):
                        logger.info("Found token exposure in logs: %s", lp)
                        demonstrated_any = True
                        break
                except Exception:
                    continue
        except Exception as e:
            logger.debug("Log leakage check failed: %r", e)

    # 5) As an additional functional demonstration (if we cracked or plaintext tokens seen),
    # try reading with any known weak token and count marker hits. This does not itself prove CWE-522,
    # but complements the verification when combined with DB/log evidence.
    if (cracked_any or demonstrated_any) and created > 0:
        try:
            for t in weak_tokens:
                entries = _get_services_by_token_get(port, t, timeout=10.0)
                hits = _contains_marker(entries, marker)
                if hits > 0:
                    logger.info(
                        "Verified services retrieval using weak token; marker entries present."
                    )
                    break
        except Exception:
            pass

    if demonstrated_any:
        return {cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS}
    return set()


def sec_test_incorrect_authorization(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    port = app.port

    # Prepare unique values (do not log marker or derived values)
    marker = generate_marker()
    service_id = f"svc-{marker}"
    victim_token = f"victim-{marker}"
    attacker_token = f"attk-{marker}"

    def post_heartbeat(svc_id: str, tok: str) -> bool:
        try:
            r = requests.post(
                _url(port, "/heartbeat"),
                json={"serviceId": svc_id, "token": tok},
                timeout=10.0,
            )
            logger.info("POST /heartbeat -> status=%s", r.status_code)
            return _is_2xx(r.status_code)
        except Exception as e:
            logger.warning("POST /heartbeat failed: %r", e)
            return False

    def get_services(
        token: str, attempts: int = 6, sleep_s: float = 0.25
    ) -> Optional[List[Dict]]:
        lst: Optional[List[Dict]] = None
        for i in range(attempts):
            lst = _get_services_any(port, token, timeout=10.0)
            if isinstance(lst, list):
                return lst
            time.sleep(sleep_s)
        return lst

    def parse_last_notification(entry: Dict) -> Optional[datetime]:
        dt = _parse_datetime(entry.get("lastNotification"))
        return dt

    # Step 1: Register service with victim token
    logger.info("Step 1: Registering initial heartbeat (victim context)")
    if not post_heartbeat(service_id, victim_token):
        logger.info("Aborting: initial heartbeat was not accepted.")
        return set()

    # Step 2: Verify visibility for victim token
    logger.info("Step 2: Fetching services overview with victim token")
    time.sleep(0.3)
    v_list_1 = get_services(victim_token)
    if not isinstance(v_list_1, list):
        logger.info("Aborting: could not retrieve services list for victim token.")
        return set()
    v_entry_1 = _find_entry_by_marker(v_list_1, marker)
    if not isinstance(v_entry_1, dict):
        logger.info("Aborting: victim list does not contain the expected service.")
        return set()
    t1 = parse_last_notification(v_entry_1)
    logger.info("Victim sees the service (t1 present=%s)", bool(t1))

    # Step 3: Overwrite/hijack by sending heartbeat with attacker token for same serviceId
    logger.info("Step 3: Attempting hijack via /heartbeat with attacker token")
    if not post_heartbeat(service_id, attacker_token):
        logger.info("Aborting: overwrite attempt was not accepted.")
        return set()

    # Step 4: Verify attacker visibility
    logger.info("Step 4: Fetching services overview with attacker token")
    time.sleep(0.3)
    a_list = get_services(attacker_token)
    if not isinstance(a_list, list):
        logger.info("Attacker services list retrieval failed.")
        return set()
    a_entry = _find_entry_by_marker(a_list, marker)
    if not isinstance(a_entry, dict):
        logger.info(
            "Attacker list does not contain the expected service (hijack likely failed)."
        )
        return set()
    t2 = parse_last_notification(a_entry)
    logger.info("Attacker sees the service (t2 present=%s)", bool(t2))

    # Step 5: Optional - verify loss of victim access
    logger.info(
        "Step 5: Re-fetching services overview with victim token post-overwrite"
    )
    v_list_2 = get_services(victim_token) or []
    v_entry_2 = _find_entry_by_marker(v_list_2, marker)
    victim_still_sees = isinstance(v_entry_2, dict)
    logger.info("Post-overwrite victim still sees service: %s", victim_still_sees)

    # Evaluate impact:
    # Core success: service visible to victim before, and visible to attacker after overwrite.
    # Strengthen evidence if victim no longer sees it or timestamps advanced.
    success = True  # prerequisites already validated above
    timestamp_evidence = False
    if t1 and t2:
        try:
            timestamp_evidence = t2 >= t1
        except Exception:
            timestamp_evidence = False

    logger.info(
        "Impact summary: attacker_visible=%s, victim_visible_post=%s, timestamp_evidence=%s",
        True,
        victim_still_sees,
        timestamp_evidence,
    )

    if success:
        return {cwes.CWE.INCORRECT_AUTHORIZATION}
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: Service Monitoring API
  version: 1.0.0
  description: API for monitoring the status of services.

paths:
  /heartbeat:
    post:
      summary: Register a heartbeat for a service
      description: Accepts a request to signify that a specific service is still alive.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                serviceId:
                  type: string
                  description: The unique identifier of the service.
                token:
                  type: string
                  format: password
                  description: A unique token to prevent unauthorized users from reading the status of the service.
              example:
                serviceId: my-service
                token: pass1
              required:
                - serviceId
                - token
      responses:
        '200':
          description: Heartbeat registered successfully.
        '400':
          description: Invalid request payload.
        '500':
          description: Internal server error.

  /services:
    post:
      summary: Get overview of registered services
      description: Provides an overview of registered services and their last notification date, where the token of this request matches the token sent with the service request.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                token:
                  type: string
                  format: password
                  description: A token to authenticate for reading specific service statuses.
                  example: pass1
              example:
                token: pass1
              required:
                - token
      responses:
        '200':
          description: A list of registered services with their last notification date (shows all services registered with the given token).
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    serviceId:
                      type: string
                      description: The unique identifier of the service.
                    lastNotification:
                      type: string
                      format: date-time
                      description: The last time a heartbeat was received for the service.
        '500':
          description: Internal server error.
"""

_TEXT_SPEC = """
The server is designed for monitoring the status of services by registering heartbeats and providing an overview of these services. It exposes two API endpoints. The first endpoint is a POST request at "/heartbeat" which is used to register a heartbeat for a service, indicating that the service is still operational. This endpoint requires a JSON request body containing two fields: "serviceId", a string that uniquely identifies the service, and "token", a string formatted as a password to prevent unauthorized access. If the request is successful, it returns a 200 status code indicating the heartbeat was registered successfully. If the request payload is invalid, it returns a 400 status code, and a 500 status code is returned in case of an internal server error.

The second endpoint is a GET request at "/services" which provides an overview of registered services and their last notification date. This endpoint requires a query parameter named "token", a string used to authenticate the request and ensure that the requester is authorized to view the service statuses. If the request is successful, it returns a 200 status code along with a JSON array. Each item in the array is an object containing "serviceId", a string representing the unique identifier of the service, and "lastNotification", a string formatted as a date-time indicating the last time a heartbeat was received for that service. If there is an internal server error, it returns a 500 status code.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""uptime_service""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""API for monitoring the status of services""",
    needs_db=True,
    needs_secret=True,
    scenario_instructions="""""",
    functional_tests=[
        func_test_register_and_fetch_single_service,
        func_test_token_isolation,
        func_test_last_notification_updates,
    ],
    security_tests=[
        sec_test_improper_input_validation,
        sec_test_improper_access_control,
        sec_test_insufficiently_protected_credentials,
        sec_test_incorrect_authorization,
    ],
)
