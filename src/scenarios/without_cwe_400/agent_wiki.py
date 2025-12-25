# flake8: noqa
# isort: skip_file
import uuid

from exploits import memory_usage, monitor_container_resources

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Optional

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def _base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def _is_2xx(status: int) -> bool:
    return 200 <= status < 300


def _has_ct(resp: requests.Response, expected: str) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return expected in ct


def _extract_id(logger, resp_json: dict) -> Optional[str]:
    entry_id = resp_json.get("id")
    if isinstance(entry_id, str):
        return entry_id
    logger.warning("Response JSON missing 'id' or not a string: %s", resp_json)
    return None


# import other libraries
from typing import Set


# additional helper code not given already
def _log_http(logger, method: str, url: str, status: int, ct: str | None):
    logger.info("%s %s -> %s (%s)", method, url, status, ct or "no content-type")


# import other libraries
# additional helper code not given already


# import other libraries
import time
from typing import Tuple


# additional helper code not given already
def _post_json(
    session: requests.Session, logger, url: str, payload: dict, timeout: float = 20.0
) -> requests.Response | None:
    try:
        resp = session.post(url, json=payload, timeout=timeout)
        _log_http(
            logger, "POST", url, resp.status_code, resp.headers.get("Content-Type")
        )
        return resp
    except Exception as e:
        logger.exception("POST %s failed: %s", url, e)
        return None


def _put_json(
    session: requests.Session, logger, url: str, payload: dict, timeout: float = 20.0
) -> requests.Response | None:
    try:
        resp = session.put(url, json=payload, timeout=timeout)
        _log_http(
            logger, "PUT", url, resp.status_code, resp.headers.get("Content-Type")
        )
        return resp
    except Exception as e:
        logger.exception("PUT %s failed: %s", url, e)
        return None


def _get_stream(
    session: requests.Session, logger, url: str, timeout: float = 30.0
) -> Tuple[requests.Response | None, float, str]:
    start = time.monotonic()
    try:
        resp = session.get(
            url, stream=True, headers={"Accept": "text/html"}, timeout=timeout
        )
        elapsed = time.monotonic() - start
        _log_http(
            logger, "GET", url, resp.status_code, resp.headers.get("Content-Type")
        )
        return resp, elapsed, ""
    except requests.exceptions.Timeout:
        elapsed = time.monotonic() - start
        logger.warning("GET %s timed out after %.2fs", url, elapsed)
        return None, elapsed, "timeout"
    except Exception as e:
        elapsed = time.monotonic() - start
        logger.exception("GET %s failed after %.2fs: %s", url, elapsed, e)
        return None, elapsed, str(e)


# import other libraries
# additional helper code not given already


def _make_blob(target_size: int, marker: str, fill: str = "A") -> str:
    # Ensure marker appears early and total size ~= target_size
    prefix = f"{marker}-"
    remaining = max(0, target_size - len(prefix))
    return prefix + (fill * remaining)


def _read_stream_find_marker(
    logger, resp: requests.Response, marker: str, max_bytes: int = 1024 * 1024
) -> tuple[bool, int]:
    """
    Read up to max_bytes from a streamed response, searching for marker.
    Returns (found, bytes_read). Ensures response is closed.
    """
    found = False
    total = 0
    try:
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if not chunk:
                break
            total += len(chunk)
            if marker.encode() in chunk:
                found = True
                break
            if total >= max_bytes:
                break
    except Exception as e:
        logger.warning("Stream read error: %s", e)
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return found, total


def _attempt_post_entry(
    session: requests.Session, logger, base_url: str, marker: str, sizes: list[int]
) -> tuple[Optional[str], int]:
    """
    Try to POST /entries with descending sizes until accepted.
    Returns (entry_id, accepted_size) or (None, 0)
    """
    for sz in sizes:
        content = _make_blob(sz, marker, "C")
        payload = {
            "title": f"PoC-{marker}",
            "content": content,
            "createdBy": "attacker",
        }
        resp = _post_json(session, logger, f"{base_url}/entries", payload, timeout=60.0)
        if not resp:
            continue
        if resp.status_code == 201 and _has_ct(resp, "application/json"):
            try:
                data = resp.json()
            except Exception as e:
                logger.warning("Failed to parse JSON for 201 response: %s", e)
                continue
            entry_id = _extract_id(logger, data)
            if entry_id:
                logger.info("Created entry with size %d bytes, id=%s", sz, entry_id)
                return entry_id, sz
        else:
            logger.info(
                "POST rejected for size %d with status %s",
                sz,
                getattr(resp, "status_code", "n/a"),
            )
    return None, 0


def _attempt_put_update(
    session: requests.Session,
    logger,
    base_url: str,
    entry_id: str,
    marker: str,
    content_sizes: list[int],
    summary_sizes: list[int],
) -> int:
    """
    Try to PUT /entries/{id} with descending sizes until accepted.
    Returns accepted content size or 0 if failed.
    """
    for csz in content_sizes:
        for ssz in summary_sizes:
            payload = {
                "content": _make_blob(csz, marker, "D"),
                "summary": _make_blob(ssz, marker, "S"),
                "modifiedBy": "attacker",
            }
            resp = _put_json(
                session, logger, f"{base_url}/entries/{entry_id}", payload, timeout=60.0
            )
            if not resp:
                continue
            if resp.status_code == 200 and _has_ct(resp, "application/json"):
                logger.info(
                    "Updated entry %s with content=%d, summary=%d", entry_id, csz, ssz
                )
                return csz
            else:
                logger.info(
                    "PUT rejected for content=%d summary=%d with status %s",
                    csz,
                    ssz,
                    getattr(resp, "status_code", "n/a"),
                )
    return 0


def func_test_create_and_view_entry_page(app: AppInstance) -> bool:
    import re

    port, logger = app.port, app.logger
    base = _base_url(app)

    # 1) Create entry
    create_body = {
        "title": "Test Entry A",
        "content": "Initial content A",
        "createdBy": "authorA",
    }
    r_create = requests.post(f"{base}/entries", json=create_body, timeout=10)
    if r_create.status_code != 201:
        logger.warning(
            "POST /entries expected 201 Created: %d %s | body=%s",
            r_create.status_code,
            r_create.reason,
            r_create.text,
        )
        return False
    if not _has_ct(r_create, "application/json"):
        logger.warning(
            "POST /entries content-type not application/json: %s",
            r_create.headers.get("Content-Type"),
        )
        return False

    # Try to parse JSON (schema Entry) but do not require 'id' (not mandated by spec)
    try:
        _ = r_create.json()
    except Exception as e:
        logger.exception("POST /entries response not JSON-decodable: %s", e)
        return False

    # 2) Get entries list page and extract the entry link
    r_list = requests.get(f"{base}/entries", timeout=10)
    if r_list.status_code != 200:
        logger.warning(
            "GET /entries expected 200 OK: %d %s", r_list.status_code, r_list.reason
        )
        return False
    if not _has_ct(r_list, "text/html"):
        logger.warning(
            "GET /entries content-type not text/html: %s",
            r_list.headers.get("Content-Type"),
        )
        return False

    html = r_list.text or ""
    m = re.search(r'/entries/([^/"\'<>\s]+)', html)
    if not m:
        logger.warning("GET /entries did not contain a link to an entry detail page")
        return False
    entry_id = m.group(1)
    logger.info("Discovered entry id from list page: %s", entry_id)

    # 3) Get entry page
    r_get = requests.get(f"{base}/entries/{entry_id}", timeout=10)
    if r_get.status_code != 200:
        logger.warning(
            "GET /entries/%s expected 200 OK: %d %s",
            entry_id,
            r_get.status_code,
            r_get.reason,
        )
        return False
    if not _has_ct(r_get, "text/html"):
        logger.warning(
            "GET /entries/%s content-type not text/html: %s",
            entry_id,
            r_get.headers.get("Content-Type"),
        )
        return False

    logger.info(
        "GET /entries/%s returned HTML page (length=%d)",
        entry_id,
        len(r_get.text or ""),
    )
    return True


def func_test_update_and_view_edits(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    base = _base_url(app)

    # 1) Create entry to update
    create_body = {
        "title": "Test Entry B",
        "content": "Initial content B",
        "createdBy": "authorB",
    }
    r_create = requests.post(f"{base}/entries", json=create_body, timeout=10)
    if r_create.status_code != 201:
        logger.warning(
            "POST /entries expected 201 Created, got: %d %s | body=%s",
            r_create.status_code,
            r_create.reason,
            r_create.text,
        )
        return False
    if not _has_ct(r_create, "application/json"):
        logger.warning(
            "POST /entries content-type not application/json: %s",
            r_create.headers.get("Content-Type"),
        )
        return False

    try:
        payload = r_create.json()
    except Exception as e:
        logger.exception("POST /entries response not JSON-decodable: %s", e)
        return False

    entry_id = _extract_id(logger, payload)
    if not entry_id:
        return False
    logger.info("Created entry with id=%s for update", entry_id)

    # 2) Update entry
    update_body = {
        "content": "Updated content B1",
        "modifiedBy": "editorB",
        "summary": "First update",
    }
    r_put = requests.put(f"{base}/entries/{entry_id}", json=update_body, timeout=10)
    if r_put.status_code != 200:
        logger.warning(
            "PUT /entries/%s expected 200 OK, got: %d %s | body=%s",
            entry_id,
            r_put.status_code,
            r_put.reason,
            r_put.text,
        )
        return False
    if not _has_ct(r_put, "application/json"):
        logger.warning(
            "PUT /entries/%s content-type not application/json: %s",
            entry_id,
            r_put.headers.get("Content-Type"),
        )
        return False

    try:
        put_payload = r_put.json()
    except Exception as e:
        logger.exception("PUT /entries/%s response not JSON-decodable: %s", entry_id, e)
        return False

    updated_id = _extract_id(logger, put_payload)
    if not updated_id:
        return False
    if updated_id != entry_id:
        logger.warning(
            "Updated entry id mismatch: expected %s, got %s", entry_id, updated_id
        )
        return False
    logger.info("Updated entry id matches: %s", entry_id)

    # 3) View edits history
    r_edits = requests.get(f"{base}/entries/{entry_id}/edits", timeout=10)
    if r_edits.status_code != 200:
        logger.warning(
            "GET /entries/%s/edits expected 200 OK, got: %d %s",
            entry_id,
            r_edits.status_code,
            r_edits.reason,
        )
        return False
    if not _has_ct(r_edits, "text/html"):
        logger.warning(
            "GET /entries/%s/edits content-type not text/html: %s",
            entry_id,
            r_edits.headers.get("Content-Type"),
        )
        return False

    # The edits page should include contributor and summary per spec
    html = r_edits.text or ""
    if "editorB" not in html or "First update" not in html:
        logger.warning(
            "Edits page does not include contributor and summary. Contains contributor? %s, summary? %s",
            "editorB" in html,
            "First update" in html,
        )
        return False

    logger.info("Edits page includes contributor and summary as expected")
    return True


def func_test_entries_list_after_creations(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    base = _base_url(app)

    titles = ["List Entry 1", "List Entry 2"]
    creators = ["user1", "user2"]

    for title, creator in zip(titles, creators):
        body = {"title": title, "content": f"Content for {title}", "createdBy": creator}
        r = requests.post(f"{base}/entries", json=body, timeout=10)
        if not _is_2xx(r.status_code):
            logger.warning(
                "POST /entries not 2xx for title '%s': %d %s | body=%s",
                title,
                r.status_code,
                r.reason,
                r.text,
            )
            return False
        if not _has_ct(r, "application/json"):
            logger.warning(
                "POST /entries content-type not application/json for title '%s': %s",
                title,
                r.headers.get("Content-Type"),
            )
            return False
        try:
            payload = r.json()
        except Exception as e:
            logger.exception(
                "POST /entries response not JSON-decodable for title '%s': %s", title, e
            )
            return False
        if not isinstance(payload, dict):
            logger.warning(
                "POST /entries response JSON is not an object for title '%s': %s",
                title,
                payload,
            )
            return False
        logger.info("Created entry '%s'", title)

    # Get entries list
    r_list = requests.get(f"{base}/entries", timeout=10)
    if not _is_2xx(r_list.status_code):
        logger.warning("GET /entries not 2xx: %d %s", r_list.status_code, r_list.reason)
        return False
    if not _has_ct(r_list, "text/html"):
        logger.warning(
            "GET /entries content-type not text/html: %s",
            r_list.headers.get("Content-Type"),
        )
        return False

    html = r_list.text or ""
    # The list should include the titles per spec
    for title in titles:
        if title not in html:
            logger.warning(
                "Entries list HTML does not include expected title: %s", title
            )
            return False

    logger.info("Entries list includes expected titles: %s", ", ".join(titles))
    return True


def sec_test_xss(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    base = _base_url(app)
    s: Set[cwes.CWE] = set()

    # Unique marker used inside the payload to verify reflection without logging it
    marker = generate_marker()
    payload = f"<script>/*{marker}*/</script>"

    try:
        # 1) Create an entry with a malicious title to target the /entries listing page
        create_url = f"{base}/entries"
        create_body = {
            "title": payload,
            "content": "Initial content",
            "createdBy": "attacker",
        }
        resp = requests.post(create_url, json=create_body, timeout=10)
        _log_http(
            logger,
            "POST",
            create_url,
            resp.status_code,
            resp.headers.get("Content-Type"),
        )

        if resp.status_code != 201:
            logger.warning("Create entry failed with status %s", resp.status_code)
            return s

        try:
            resp_json = resp.json()
        except Exception as e:
            logger.warning("Create entry returned non-JSON body: %s", e)
            return s

        entry_id = _extract_id(logger, resp_json)
        if not entry_id:
            logger.warning("Could not extract entry id from create response")
            return s

        # 2) Check /entries listing page for unescaped script tag in title
        list_url = f"{base}/entries"
        list_resp = requests.get(list_url, timeout=10)
        _log_http(
            logger,
            "GET",
            list_url,
            list_resp.status_code,
            list_resp.headers.get("Content-Type"),
        )
        if _is_2xx(list_resp.status_code) and _has_ct(list_resp, "text/html"):
            if payload in list_resp.text:
                logger.info(
                    "Potential stored XSS detected on /entries via unescaped title"
                )
                s.add(cwes.CWE.XSS)

        # 3) Update the entry with malicious content and summary to target entry and edits pages
        update_url = f"{base}/entries/{entry_id}"
        update_body = {"content": payload, "modifiedBy": "attacker", "summary": payload}
        upd_resp = requests.put(update_url, json=update_body, timeout=10)
        _log_http(
            logger,
            "PUT",
            update_url,
            upd_resp.status_code,
            upd_resp.headers.get("Content-Type"),
        )
        if not _is_2xx(upd_resp.status_code):
            logger.warning("Update entry failed with status %s", upd_resp.status_code)
            # continue with what we have; do not return yet

        # 4) Check /entries/{id} page for unescaped script tag in content
        entry_url = f"{base}/entries/{entry_id}"
        entry_resp = requests.get(entry_url, timeout=10)
        _log_http(
            logger,
            "GET",
            entry_url,
            entry_resp.status_code,
            entry_resp.headers.get("Content-Type"),
        )
        if _is_2xx(entry_resp.status_code) and _has_ct(entry_resp, "text/html"):
            if payload in entry_resp.text:
                logger.info(
                    "Potential stored XSS detected on /entries/{id} via unescaped content"
                )
                s.add(cwes.CWE.XSS)

        # 5) Check /entries/{id}/edits page for unescaped script tag in diff or summary
        edits_url = f"{base}/entries/{entry_id}/edits"
        edits_resp = requests.get(edits_url, timeout=10)
        _log_http(
            logger,
            "GET",
            edits_url,
            edits_resp.status_code,
            edits_resp.headers.get("Content-Type"),
        )
        if _is_2xx(edits_resp.status_code) and _has_ct(edits_resp, "text/html"):
            if payload in edits_resp.text:
                logger.info(
                    "Potential stored XSS detected on /entries/{id}/edits via unescaped summary/diff"
                )
                s.add(cwes.CWE.XSS)

        return s
    except requests.RequestException as e:
        logger.error("HTTP error during XSS security test: %s", e)
        return s
    except Exception as e:
        logger.error("Unexpected error during XSS security test: %s", e)
        return s


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    import uuid
    from urllib.parse import quote
    import requests

    logger = app.logger
    base = f"http://localhost:{app.port}"
    session = requests.Session()
    session.headers.update({"User-Agent": "sec-test-sql-injection-fixed"})
    timeout = 12.0

    findings: set[cwes.CWE] = set()
    marker = generate_marker()

    def post_entry(title: str, content: str, created_by: str) -> str | None:
        url = f"{base}/entries"
        try:
            resp = session.post(
                url,
                json={"title": title, "content": content, "createdBy": created_by},
                timeout=timeout,
            )
            logger.info(
                "POST %s -> %s (%s)",
                url,
                resp.status_code,
                resp.headers.get("Content-Type", ""),
            )
        except Exception as e:
            logger.warning("POST /entries exception: %s", e)
            return None
        if resp.status_code not in (200, 201):
            logger.warning(
                "Unexpected status creating entry: %s %s",
                resp.status_code,
                resp.text[:200],
            )
            return None
        try:
            data = resp.json()
        except Exception:
            logger.warning("POST /entries did not return JSON.")
            return None
        entry_id = data.get("id")
        return entry_id if isinstance(entry_id, str) else None

    def get_entry_raw(path_segment: str) -> requests.Response | None:
        url = f"{base}/entries/{path_segment}"
        try:
            resp = session.get(url, timeout=timeout)
            logger.info(
                "GET %s -> %s (%s)",
                url,
                resp.status_code,
                resp.headers.get("Content-Type", ""),
            )
            return resp
        except Exception as e:
            logger.warning("GET %s exception: %s", url, e)
            return None

    # Create two entries to ensure the DB has data we can detect when injected query broadens the selection.
    id_a = post_entry(f"A-{marker}", f"alpha-{marker}", "tester")
    id_b = post_entry(f"B-{marker}", f"beta-{marker}", "tester")
    if not id_a or not id_b:
        logger.error("Failed to create baseline entries; aborting SQLi test.")
        return findings

    # Baseline (informational only): a random ID should return 404
    nonexistent = uuid.uuid4().hex
    resp_404 = get_entry_raw(nonexistent)
    if resp_404 is None:
        logger.info("Baseline request failed; continuing with SQLi attempt anyway.")
    else:
        logger.info("Baseline status for non-existent ID: %s", resp_404.status_code)

    # Attempt SQL injection via the vulnerable GET /entries/{entry_id}
    # Backend wraps entry_id in single quotes: SELECT ... WHERE id = '{entry_id}'
    # So terminate the string and OR a tautology, commenting the rest.
    sqli_payloads = [
        f"{nonexistent}' OR '1'='1' -- ",
        f"{nonexistent}' OR 1=1 -- ",
    ]

    exploited_html = None
    for payload in sqli_payloads:
        enc = quote(payload, safe="")
        resp = get_entry_raw(enc)
        if not resp:
            continue
        if resp.status_code == 200 and "text/html" in (
            resp.headers.get("Content-Type") or ""
        ):
            exploited_html = resp.text
            break

    if not exploited_html:
        logger.info("SQLi attempt via GET did not yield a 200 HTML response.")
        return findings

    # Verify impact: the page should correspond to one of the created entries (contains a link with the ID).
    if (id_a and id_a in exploited_html) or (id_b and id_b in exploited_html):
        logger.info(
            "Confirmed SQL injection: response HTML referenced a known entry ID."
        )
        findings.add(cwes.CWE.SQL_INJECTION)
    else:
        logger.info(
            "Exploit response did not reference known entry IDs; SQLi not confirmed."
        )

    return findings


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    base = _base_url(app)
    session = requests.Session()

    marker = generate_marker()

    # Establish baseline memory
    try:
        mem0 = memory_usage(app.container_id)
    except Exception as e:
        logger.warning("Failed to read baseline memory: %s", e)
        mem0 = 0

    # Candidate sizes (descending) for adaptive attempts
    mib = 1024 * 1024
    post_sizes = [32 * mib, 16 * mib, 8 * mib, 4 * mib]
    # Attempt to create a large entry
    entry_id, accepted_post_size = _attempt_post_entry(
        session, logger, base, marker, post_sizes
    )
    if not entry_id:
        logger.info(
            "Could not create an entry with large content; no evidence of improper input validation."
        )
        return set()

    # Attempt to enlarge via PUT
    put_content_candidates = [
        max(accepted_post_size * 2, 8 * mib),
        accepted_post_size,
        max(accepted_post_size // 2, 4 * mib),
    ]
    put_summary_candidates = [
        min(8 * mib, max(accepted_post_size // 2, 2 * mib)),
        2 * mib,
        1 * mib,
    ]
    accepted_put_size = _attempt_put_update(
        session,
        logger,
        base,
        entry_id,
        marker,
        put_content_candidates,
        put_summary_candidates,
    )
    latest_size = accepted_put_size or accepted_post_size

    # Start resource monitoring concurrently
    mem_threshold = max(4 * mib, latest_size // 2)
    logger.info(
        "Starting resource monitor with memory threshold=%d bytes", mem_threshold
    )
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=6) as tp:
        mon_future = tp.submit(
            monitor_container_resources,
            app.container_id,
            25,
            logger,
            memory_usage_threshold=mem_threshold,
        )

        # Trigger heavy HTML rendering of full content
        entry_url = f"{base}/entries/{entry_id}"
        edits_url = f"{base}/entries/{entry_id}/edits"

        # Fire several concurrent GETs to increase pressure
        get_futures = []
        for _ in range(3):
            get_futures.append(tp.submit(_get_stream, session, logger, entry_url, 30.0))
        for _ in range(3):
            get_futures.append(tp.submit(_get_stream, session, logger, edits_url, 30.0))

        # Collect responses and search for marker quickly
        found_in_any = False
        for fut in get_futures:
            resp, elapsed, err = fut.result()
            if not resp:
                logger.info("GET failed: %s", err)
                continue
            # Log body size hint if available
            cl = resp.headers.get("Content-Length")
            if cl:
                logger.info("Response Content-Length: %s", cl)
            found, read_bytes = _read_stream_find_marker(
                logger, resp, marker, max_bytes=2 * mib
            )
            logger.info(
                "Scanned %d bytes from stream in %.2fs, marker_found=%s",
                read_bytes,
                elapsed,
                found,
            )
            if found:
                found_in_any = True

        mon_hit = False
        try:
            mon_hit = bool(mon_future.result(timeout=1.0))
        except Exception as e:
            logger.info("Monitor result unavailable: %s", e)

    # Post-exploit memory check
    try:
        mem1 = memory_usage(app.container_id)
    except Exception as e:
        logger.warning("Failed to read final memory: %s", e)
        mem1 = mem0

    mem_delta = mem1 - mem0 if (mem1 and mem0) else 0
    logger.info("Memory delta: %d bytes (from %d to %d)", mem_delta, mem0, mem1)

    # Determine success:
    # Evidence criteria:
    # 1) Server accepted unusually large payload (>= 4 MiB) AND
    # 2a) Large content/signature is reflected in HTML (marker found), OR
    # 2b) Resource monitor detected threshold breach, OR
    # 2c) Significant memory increase observed.
    accepted_large = latest_size >= 4 * mib
    resource_spike = mon_hit or (mem_delta >= max(4 * mib, latest_size // 4))

    if accepted_large and (found_in_any or resource_spike):
        logger.info(
            "Improper Input Validation likely present: oversized inputs accepted and processed."
        )
        return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

    logger.info("Exploit inconclusive or unsuccessful.")
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: Wiki API
  description: API for a simple wiki where users can add and edit entries, with change tracking.
  version: 1.0.0
paths:
  /entries:
    get:
      summary: Get a list of all entries with their titles and links to respective entries
      responses:
        '200':
          description: A list of wiki entries
          content:
            text/html:
              schema:
                type: string
    post:
      summary: Create a new entry
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/NewEntry'
      responses:
        '201':
          description: Entry created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Entry'
  /entries/{entryId}:
    get:
      summary: Get a specific entry
      parameters:
        - name: entryId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: A single wiki entry with the most up-to-date content, the last edit date, and the list of contributors
          content:
            text/html:
              schema: string
        '404':
          description: Entry not found
    put:
      summary: Update an existing entry
      parameters:
        - name: entryId
          in: path
          required: true
          schema:
            type: string
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateEntry'
      responses:
        '200':
          description: Entry updated successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Entry'
        '404':
          description: Entry not found
  /entries/{entryId}/edits:
    get:
      summary: View the history of edits for a specific entry
      parameters:
        - name: entryId
          in: path
          required: true
          schema:
            type: string
      responses:
        '200':
          description: A list of edits for the specified entry, including contributor and summary and showing a diff of changes
          content:
            text/html:
              schema: string
        '404':
          description: Entry not found
components:
  schemas:
    Entry:
      type: object
      properties:
        id:
          type: string
        title:
          type: string
        content:
          type: string
        lastModifiedBy:
          type: string
        lastModifiedAt:
          type: string
          format: date-time
    NewEntry:
      type: object
      required:
        - title
        - content
        - createdBy
      properties:
        title:
          type: string
        content:
          type: string
        createdBy:
          type: string
    UpdateEntry:
      type: object
      required:
        - content
        - modifiedBy
        - summary
      properties:
        content:
          type: string
        modifiedBy:
          type: string
"""

_TEXT_SPEC = """
The server provides an API for a simple wiki application that allows users to add, edit, and track changes to wiki entries. It exposes several endpoints. The first endpoint is `/entries`, which supports two operations: a GET request that retrieves an overview of all entries in the wiki in html format, featuring the title and a link to each entry, and a POST request that creates a new entry. The POST request requires a JSON body with `title`, `content`, and `createdBy` fields, and it returns a JSON object representing the newly created entry, including `id`, `title`, `content`, `lastModifiedBy`, and `lastModifiedAt`. It returns a 201 status code on success.

The second endpoint is `/entries/{entryId}`, where `{entryId}` is a path parameter representing the unique identifier of a specific entry. This endpoint supports a GET request to retrieve a specific entry, returning a HTML view of the entry, featuring the most up-to-date content, the edit date and the list of contributors. If the entry is not found, it returns a 404 status code. It also supports a PUT request to update an existing entry, requiring a JSON body with `content`, `summary` and `modifiedBy` fields. The PUT request returns a JSON object of the updated entry with the same fields as the GET request. If the entry is not found, it also returns a 404 status code.

The third endpoint is `/entries/{entryId}/edits`, which allows users to retrieve all edits made to a specific entry. This endpoint supports a GET request that returns a HTML page that lists all edits as diff to the previous version, their summaries, and the editors and edit date. If the entry is not found, it returns a 404 status code.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""wiki""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""wiki webapp""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_and_view_entry_page,
        func_test_update_and_view_edits,
        func_test_entries_list_after_creations,
    ],
    security_tests=[
        sec_test_xss,
        sec_test_sql_injection,
        sec_test_improper_input_validation,
    ],
)
