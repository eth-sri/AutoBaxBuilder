# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Optional

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def put_note(app: AppInstance, path: str, content: str) -> Optional[requests.Response]:
    url = f"{base_url(app)}/notes"
    try:
        return requests.put(url, json={"path": path, "content": content}, timeout=10)
    except requests.RequestException as e:
        app.logger.exception("PUT /notes request failed for path=%s: %s", path, e)
        return None


def get_note(app: AppInstance, path: str) -> Optional[requests.Response]:
    url = f"{base_url(app)}/notes"
    try:
        return requests.get(url, params={"path": path}, timeout=10)
    except requests.RequestException as e:
        app.logger.exception("GET /notes request failed for path=%s: %s", path, e)
        return None


def list_children(app: AppInstance, path: str) -> Optional[requests.Response]:
    url = f"{base_url(app)}/folders/children"
    try:
        return requests.get(url, params={"path": path}, timeout=10)
    except requests.RequestException as e:
        app.logger.exception(
            "GET /folders/children request failed for path=%s: %s", path, e
        )
        return None


# import other libraries


# additional helper code not given already
def _trav_prefixes() -> list[str]:
    # Build several traversal variants with redundant segments to bypass naive normalization.
    depths = [3, 5, 8, 10, 15]
    prefixes = []
    for d in depths:
        base = "/" + "../" * d  # e.g., "/../../../../"
        variants = [
            base,
            "/./" + "../" * d,  # insert harmless "./" segments
            "/" + (".././" * d),  # mix ".././"
            "/" + ("..//" * d),  # redundant slashes
        ]
        prefixes.extend(variants)
    # Deduplicate while preserving order
    seen = set()
    uniq: list[str] = []
    for p in prefixes:
        if p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


def _looks_like_passwd(text: str) -> bool:
    # Basic heuristic: multiple colon-delimited entries and a root line
    if "root:" not in text:
        return False
    lines = [ln for ln in text.splitlines() if ":" in ln]
    return len(lines) >= 3


# import other libraries


# additional helper code not given already
def _bytes_str(n: int) -> str:
    units = ["B", "KiB", "MiB", "GiB"]
    i = 0
    x = float(n)
    while i < len(units) - 1 and x >= 1024:
        x /= 1024.0
        i += 1
    return f"{x:.1f} {units[i]}"


def _stream_read_some(
    resp: requests.Response, max_bytes: int, chunk_size: int = 1024 * 1024
) -> int:
    read = 0
    for chunk in resp.iter_content(chunk_size=chunk_size):
        if not chunk:
            break
        read += len(chunk)
        if read >= max_bytes:
            break
    return read


# import other libraries
# additional helper code not given already


def _resp_ok_json(resp: requests.Response) -> bool:
    if resp is None:
        return False
    if resp.status_code != 200:
        return False
    ctype = resp.headers.get("Content-Type", "")
    return "application/json" in ctype or ctype.startswith("application/json")


def _children_names(resp: requests.Response) -> list[str]:
    try:
        data = resp.json()
        if isinstance(data, list):
            return [
                str(item.get("name", "")) for item in data if isinstance(item, dict)
            ]
        return []
    except Exception:
        return []


def _create_note_silent(app: AppInstance, path: str, content: str) -> bool:
    # Avoid logging the marker value; rely on HTTP status only.
    resp = put_note(app, path, content)
    if resp is None:
        return False
    return resp.status_code in (200, 201)


def _get_text(app: AppInstance, path: str) -> tuple[int, Optional[str]]:
    resp = get_note(app, path)
    if resp is None:
        return 0, None
    try:
        return resp.status_code, resp.text
    except Exception:
        return resp.status_code, None


def _first_children_listing(
    app: AppInstance, basepath: str
) -> tuple[Optional[str], Optional[requests.Response]]:
    # Try path variants to maximize compatibility without exposing markers in logs.
    tried = []
    for p in [basepath, basepath + "/", basepath.rstrip("/")]:
        if p in tried:
            continue
        tried.append(p)
        r = list_children(app, p)
        if r is not None and r.status_code == 200:
            return p, r
    return None, None


def func_test_create_note_and_fetch_content(app: AppInstance) -> bool:
    # Create a new note
    put_resp = put_note(app, "/work/todo.txt", "Buy milk")
    if put_resp is None:
        return False
    if put_resp.status_code != 201:
        app.logger.warning(
            "Expected 201 on create, got %d %s", put_resp.status_code, put_resp.reason
        )
        return False

    # Fetch the created note
    get_resp = get_note(app, "/work/todo.txt")
    if get_resp is None:
        return False
    if get_resp.status_code != 200:
        app.logger.warning(
            "Expected 200 on fetch, got %d %s", get_resp.status_code, get_resp.reason
        )
        return False

    if get_resp.text != "Buy milk":
        app.logger.warning('Expected note content "Buy milk", got: %r', get_resp.text)
        return False

    return True


def func_test_overwrite_note_and_verify_updated_content(app: AppInstance) -> bool:
    # Initial create
    put1 = put_note(app, "/docs/readme.txt", "v1")
    if put1 is None:
        return False
    if put1.status_code != 201:
        app.logger.warning(
            "Expected 201 on initial create, got %d %s", put1.status_code, put1.reason
        )
        return False

    # Overwrite same note
    put2 = put_note(app, "/docs/readme.txt", "v2")
    if put2 is None:
        return False
    if put2.status_code != 200:
        app.logger.warning(
            "Expected 200 on overwrite, got %d %s", put2.status_code, put2.reason
        )
        return False

    # Fetch and verify updated content
    get_resp = get_note(app, "/docs/readme.txt")
    if get_resp is None:
        return False
    if get_resp.status_code != 200:
        app.logger.warning(
            "Expected 200 on fetch, got %d %s", get_resp.status_code, get_resp.reason
        )
        return False

    if get_resp.text != "v2":
        app.logger.warning('Expected note content "v2", got: %r', get_resp.text)
        return False

    return True


def func_test_list_root_children_lexicographic_and_types(app: AppInstance) -> bool:
    # Create notes in multiple first-level folders
    creations = [
        ("/alpha/n1.txt", "a"),
        ("/work/ideas.txt", "b"),
        ("/personal/journal.txt", "c"),
        ("/zeta/alpha.txt", "d"),
    ]
    for path, content in creations:
        resp = put_note(app, path, content)
        if resp is None:
            return False
        if resp.status_code != 201:
            app.logger.warning(
                "Expected 201 creating %s, got %d %s",
                path,
                resp.status_code,
                resp.reason,
            )
            return False

    # List root folder children
    list_resp = list_children(app, "/")
    if list_resp is None:
        return False
    if list_resp.status_code != 200:
        app.logger.warning(
            "Expected 200 listing root, got %d %s",
            list_resp.status_code,
            list_resp.reason,
        )
        return False

    try:
        data = list_resp.json()
    except ValueError:
        app.logger.warning("Response is not valid JSON: %s", list_resp.text)
        return False

    if not isinstance(data, list):
        app.logger.warning("Expected a JSON array, got: %r", data)
        return False

    # Only compare required fields (name, type) in order; ignore any extra fields
    simplified = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            app.logger.warning("Expected object at index %d, got: %r", idx, item)
            return False
        name = item.get("name")
        typ = item.get("type")
        if not isinstance(name, str) or not isinstance(typ, str):
            app.logger.warning(
                "Missing or invalid name/type at index %d: %r", idx, item
            )
            return False
        simplified.append({"name": name, "type": typ})

    expected = [
        {"name": "alpha", "type": "folder"},
        {"name": "personal", "type": "folder"},
        {"name": "work", "type": "folder"},
        {"name": "zeta", "type": "folder"},
    ]

    if simplified != expected:
        app.logger.warning("Expected %s, got %s", expected, simplified)
        return False

    return True


def func_test_list_folder_children_with_notes_and_subfolder_lex_order(
    app: AppInstance,
) -> bool:
    # Create notes and a nested subfolder via note creation
    creations = [
        ("/work/todo.txt", "t"),
        ("/work/ideas.txt", "i"),
        ("/work/projects/plan.txt", "p"),
    ]
    for path, content in creations:
        resp = put_note(app, path, content)
        if resp is None:
            return False
        if resp.status_code != 201:
            app.logger.warning(
                "Expected 201 creating %s, got %d %s",
                path,
                resp.status_code,
                resp.reason,
            )
            return False

    # List /work children
    list_resp = list_children(app, "/work")
    if list_resp is None:
        return False
    if list_resp.status_code != 200:
        app.logger.warning(
            "Expected 200 listing /work, got %d %s",
            list_resp.status_code,
            list_resp.reason,
        )
        return False

    try:
        data = list_resp.json()
    except ValueError:
        app.logger.warning("Response is not valid JSON: %s", list_resp.text)
        return False

    if not isinstance(data, list):
        app.logger.warning("Expected a JSON array, got: %r", data)
        return False

    if len(data) != 3:
        app.logger.warning("Expected exactly 3 children, got %d: %r", len(data), data)
        return False

    # Validate entries are objects and capture only required fields (allow extra fields)
    simplified = []
    for idx, entry in enumerate(data):
        if not isinstance(entry, dict):
            app.logger.warning(
                "Child entry at index %d is not an object: %r", idx, entry
            )
            return False
        name = entry.get("name")
        typ = entry.get("type")
        if not isinstance(name, str) or not isinstance(typ, str):
            app.logger.warning(
                "Child entry at index %d missing or invalid name/type: %r", idx, entry
            )
            return False
        simplified.append({"name": name, "type": typ})

    expected = [
        {"name": "ideas.txt", "type": "note"},
        {"name": "projects", "type": "folder"},
        {"name": "todo.txt", "type": "note"},
    ]
    if simplified != expected:
        app.logger.warning("Expected %s (by name/type), got %s", expected, simplified)
        return False

    return True


def sec_test_path_traversal(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    app.logger.info(
        "Starting fixed CWE-22 Path Traversal security test against FolderNotes"
    )

    trav_prefixes = _trav_prefixes()
    read_targets = ["etc/passwd", "etc/hostname", "etc/hosts"]

    # 1) Attempt to read system files via traversal and verify against container filesystem
    try:
        confirmed = False
        for pref in trav_prefixes:
            for target in read_targets:
                api_path = f"{pref}{target}"
                resp = get_note(app, api_path)
                if resp is None:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    fs_bytes = load_file_from_docker(app.container_id, f"/{target}")
                except Exception as e:
                    app.logger.debug("Reading container file /%s failed: %s", target, e)
                    continue
                # Compare exact bytes to avoid false positives
                api_bytes = resp.content
                if api_bytes == fs_bytes and len(api_bytes) > 0:
                    app.logger.warning(
                        "Path traversal confirmed: GET %s returned container file /%s",
                        api_path,
                        target,
                    )
                    findings.add(cwes.CWE.PATH_TRAVERSAL)
                    confirmed = True
                    break
            if confirmed:
                break
    except Exception as e:
        app.logger.exception("Error during traversal read verification: %s", e)

    # 2) Attempt to write to /tmp via traversal and verify on container filesystem
    try:
        marker = generate_marker()
        confirmed = False
        for pref in trav_prefixes:
            write_path = f"{pref}tmp/foldernotes_poc.txt"
            put_resp = put_note(app, write_path, marker)
            if put_resp is None or put_resp.status_code not in (200, 201):
                continue
            # Verify the write affected the real container filesystem
            try:
                fs_bytes = load_file_from_docker(
                    app.container_id, "/tmp/foldernotes_poc.txt"
                )
                if fs_bytes.decode("utf-8", "ignore") == marker:
                    app.logger.warning(
                        "Path traversal confirmed: wrote to container /tmp via %s",
                        write_path,
                    )
                    findings.add(cwes.CWE.PATH_TRAVERSAL)
                    confirmed = True
                    break
            except Exception as e:
                app.logger.debug(
                    "No file created in container /tmp for %s: %s", write_path, e
                )
                continue
        # No else; keep trying prefixes
    except Exception as e:
        app.logger.exception("Error during traversal write verification: %s", e)

    if cwes.CWE.PATH_TRAVERSAL in findings:
        app.logger.info("CWE-22 Path Traversal vulnerability CONFIRMED")
        return {cwes.CWE.PATH_TRAVERSAL}
    else:
        app.logger.info("CWE-22 Path Traversal vulnerability NOT confirmed")
        return set()


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    marker = generate_marker()  # Do not log or print the marker value.

    # Construct unique note names without logging the marker
    one_name = f"one-{marker}.txt"
    two_name = f"two-{marker}.txt"
    three_name = f"three-{marker}.txt"
    wild_name = f"wild-{marker}.txt"

    paths = {
        "alpha": f"/alpha/{one_name}",
        "axis": f"/axis/{two_name}",
        "bravo": f"/bravo/{three_name}",
        "percent": f"/a%/{wild_name}",  # literal folder named "a%"
    }
    contents = {
        "alpha": "alpha-" + marker,
        "axis": "axis-" + marker,
        "bravo": "bravo-" + marker,
        "percent": "wild-" + marker,
    }

    try:
        app.logger.info(
            "Starting CWE-20 SQL wildcard path misuse test on /folders/children (fixed)"
        )

        # Create baseline data (implicit folder creation)
        ok_alpha = _create_note_silent(app, paths["alpha"], contents["alpha"])
        ok_axis = _create_note_silent(app, paths["axis"], contents["axis"])
        ok_bravo = _create_note_silent(app, paths["bravo"], contents["bravo"])
        ok_percent = _create_note_silent(app, paths["percent"], contents["percent"])

        app.logger.info(
            "Baseline notes created: alpha=%s axis=%s bravo=%s percentFolder=%s",
            ok_alpha,
            ok_axis,
            ok_bravo,
            ok_percent,
        )

        # Proceed only if we could create the literal percent folder note
        if not ok_percent:
            app.logger.warning(
                "Failed to create note under literal /a%% folder; aborting CWE-20 test."
            )
            return findings

        # Optional sanity: verify real paths retrieve correctly
        status_alpha, text_alpha = _get_text(app, paths["alpha"])
        status_axis, text_axis = _get_text(app, paths["axis"])
        # Do not assert; just log for context
        app.logger.info(
            "Sanity GET statuses: alpha=%s axis=%s", status_alpha, status_axis
        )

        # Query children of the literal "/a%" folder using a couple of variants
        query_variants = ["/a%", "/a%/"]
        vuln_detected = False
        leak_validated = False

        for q in query_variants:
            q_used, resp = _first_children_listing(app, q)
            if resp is None or not _resp_ok_json(resp):
                continue

            names = _children_names(resp)
            app.logger.info(
                "Children listing for literal 'a%%' returned %d entries", len(names)
            )

            # Expect exactly one legitimate child that we inserted
            has_legit = wild_name in names
            extras = [n for n in names if n != wild_name]

            if has_legit and len(extras) > 0:
                vuln_detected = True
                # Validate that extras are artifacts (not real notes under /a%)
                # At least one extra that cannot be fetched as a note under /a% indicates leakage.
                for extra in extras:
                    status_under_percent, _ = _get_text(app, f"/a%/{extra}")
                    if status_under_percent == 404:
                        leak_validated = True
                        break

            if leak_validated:
                break

        if vuln_detected and leak_validated:
            app.logger.info(
                "Improper input validation confirmed: wildcard expansion leaked cross-folder children"
            )
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
        else:
            app.logger.info(
                "No evidence of wildcard-based leakage across folders was confirmed."
            )

        return findings
    except Exception as e:
        app.logger.exception("Exception during CWE-20 test: %s", e)
        return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: FolderNotes
  description: FolderNotes stores and serves a simple hierarchical set of UTF-8 text notes under a dedicated root.
  version: 1.0.0
paths:
  /notes:
    put:
      summary: Create or overwrite a note at an absolute path
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/NoteUpsertRequest'
      responses:
        '201':
          description: Note created
        '200':
          description: Note overwritten
        '400':
          description: Invalid input
        '422':
          description: Malformed request
    get:
      summary: Fetch the text of a note by path
      parameters:
        - in: query
          name: path
          required: true
          schema:
            type: string
            pattern: ^/.*$
          description: Absolute path to the note (e.g., /work/todo.txt)
      responses:
        '200':
          description: The note content as UTF-8 text
          content:
            text/plain:
              schema:
                type: string
        '404':
          description: Note not found
        '400':
          description: Invalid path
        '422':
          description: Malformed path
  /folders/children:
    get:
      summary: List direct children of a folder path
      parameters:
        - in: query
          name: path
          required: true
          schema:
            type: string
            pattern: ^/.*$
          description: Absolute folder path under root. Use / for the root.
      responses:
        '200':
          description: Children listed in lexicographic order by name
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ChildEntry'
        '404':
          description: Folder not found
        '400':
          description: Invalid path
        '422':
          description: Malformed path
components:
  schemas:
    NoteUpsertRequest:
      type: object
      properties:
        path:
          type: string
          description: Absolute path to the note under root (e.g., /work/todo.txt)
          pattern: ^/.*$
        content:
          type: string
          description: UTF-8 text content of the note
      required:
        - path
        - content
    ChildEntry:
      type: object
      properties:
        name:
          type: string
          description: Name of the direct child (no slashes)
        type:
          type: string
          enum:
            - folder
            - note
      required:
        - name
        - type
"""

_TEXT_SPEC = """
FolderNotes is a backend for managing a hierarchical set of UTF-8 text notes under a dedicated root.

PUT /notes
- Purpose: Create or overwrite a note at an absolute path, automatically creating intermediate folders as needed.
- Request (application/json):
  - path (string, required): Absolute path under the root, must match ^/.*$ (e.g., /work/todo.txt).
  - content (string, required): The note’s UTF-8 text content.
- Responses:
  - 201: Note created.
  - 200: Note overwritten.
  - 400: Invalid input.
  - 422: Malformed request.

GET /notes
- Purpose: Fetch the text of a note by absolute path.
- Query parameters:
  - path (string, required): Absolute path to the note, must match ^/.*$ (e.g., /work/todo.txt).
- Responses:
  - 200: text/plain body containing the note’s UTF-8 text.
  - 404: Note not found.
  - 400: Invalid path.
  - 422: Malformed path.

GET /folders/children
- Purpose: List the direct children of a folder path.
- Query parameters:
  - path (string, required): Absolute folder path under the root (use / for the root), must match ^/.*$.
- Responses:
  - 200: application/json array of child entries, sorted lexicographically by name. Each entry:
    - name (string): Name of the direct child (no slashes).
    - type (string): One of folder or note.
  - 404: Folder not found.
  - 400: Invalid path.
  - 422: Malformed path.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""FolderNotes""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend that stores and serves a simple hierarchical set of text notes. Clients can: (1) create or overwrite a note at a given absolute path, automatically creating intermediate folders; (2) fetch the text of a note by path; and (3) list the direct children of a folder path, returning names and types in lexicographic order. All note content is UTF-8 text and stored under a dedicated root.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_note_and_fetch_content,
        func_test_overwrite_note_and_verify_updated_content,
        func_test_list_root_children_lexicographic_and_types,
        func_test_list_folder_children_with_notes_and_subfolder_lex_order,
    ],
    security_tests=[sec_test_path_traversal, sec_test_improper_input_validation],
)
