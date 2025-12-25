# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker, place_file_on_docker

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, List, Optional

import requests

import cwes
from scenarios.base import AppInstance

# shared methods
DEFAULT_TIMEOUT = 5.0


def files_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}/files"


def post_files(app: AppInstance, payload: Dict[str, Any]) -> requests.Response:
    app.logger.info("POST %s | payload=%s", files_url(app), payload)
    resp = requests.post(files_url(app), json=payload, timeout=DEFAULT_TIMEOUT)
    app.logger.info(
        "Response: %s %s | body=%s", resp.status_code, resp.reason, safe_json(resp)
    )
    return resp


def is_2xx(code: int) -> bool:
    return 200 <= code < 300


def safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return resp.text


# import other libraries
from typing import Optional, Tuple


# additional helper code not given already
def _read_request_no_body_log(app, payload) -> Optional[str]:
    try:
        app.logger.info(
            "POST %s | action=read | payload=%s",
            files_url(app),
            {k: payload[k] for k in ("action", "workspace", "path")},
        )
        resp = requests.post(files_url(app), json=payload, timeout=DEFAULT_TIMEOUT)
        app.logger.info("Response: %s %s", resp.status_code, resp.reason)
        if not is_2xx(resp.status_code):
            return None
        data = resp.json()
        # Return content without logging it to avoid leaking the marker
        return data.get("content")
    except Exception as e:
        app.logger.exception("Read request failed: %s", e)
        return None


def _write_request(app, payload) -> bool:
    try:
        resp = post_files(app, payload)
        if not is_2xx(resp.status_code):
            return False
        body = resp.json()
        return isinstance(body, dict) and isinstance(
            body.get("bytesWritten", None), int
        )
    except Exception as e:
        app.logger.exception("Write request failed: %s", e)
        return False


def _delete_request(app, payload) -> bool:
    try:
        resp = post_files(app, payload)
        if not is_2xx(resp.status_code):
            return False
        body = resp.json()
        return isinstance(body, dict) and bool(body.get("deleted", False))
    except Exception as e:
        app.logger.exception("Delete request failed: %s", e)
        return False


# import other libraries
import uuid
from typing import Any, Dict, List, Optional, Tuple

import requests


# additional helper code not given already
def _post_json_sanitized(
    app,
    payload: Dict[str, Any],
    timeout: float,
    redact_keys: Tuple[str, ...] = ("content",),
) -> Optional[requests.Response]:
    try:
        # Build a sanitized log payload without large content
        sanitized = {}
        for k, v in payload.items():
            if k in redact_keys and isinstance(v, str):
                sanitized[k] = f"<redacted:str:{len(v)}>"
            else:
                sanitized[k] = v
        app.logger.info("POST %s | payload=%s", files_url(app), sanitized)
        resp = requests.post(files_url(app), json=payload, timeout=timeout)
        app.logger.info("Response: %s %s", resp.status_code, resp.reason)
        return resp
    except Exception as e:
        app.logger.exception("POST failed: %s", e)
        return None


def _write_request_no_body_log(
    app, payload: Dict[str, Any], timeout: float = 30.0
) -> Optional[int]:
    resp = _post_json_sanitized(app, payload, timeout, redact_keys=("content",))
    if resp is None:
        return None
    if not is_2xx(resp.status_code):
        return None
    try:
        data = resp.json()
        bw = data.get("bytesWritten")
        return int(bw) if isinstance(bw, int) else None
    except Exception as e:
        app.logger.exception("Write response parsing failed: %s", e)
        return None


def _read_request_with_timeout(
    app, payload: Dict[str, Any], timeout: float = 30.0
) -> Optional[str]:
    try:
        # Avoid logging content; log only metadata
        app.logger.info(
            "POST %s | action=read | payload=%s",
            files_url(app),
            {k: payload[k] for k in ("action", "workspace", "path")},
        )
        resp = requests.post(files_url(app), json=payload, timeout=timeout)
        app.logger.info("Response: %s %s", resp.status_code, resp.reason)
        if not is_2xx(resp.status_code):
            return None
        data = resp.json()
        return data.get("content")
    except Exception as e:
        app.logger.exception("Read request failed: %s", e)
        return None


def _list_request_no_body_log(
    app, payload: Dict[str, Any], timeout: float = 15.0
) -> Optional[List[str]]:
    resp = _post_json_sanitized(app, payload, timeout, redact_keys=())
    if resp is None:
        return None
    if not is_2xx(resp.status_code):
        return None
    try:
        data = resp.json()
        files = data.get("files")
        if isinstance(files, list):
            return [str(x) for x in files]
        return None
    except Exception as e:
        app.logger.exception("List response parsing failed: %s", e)
        return None


def _bulk_small_writes(
    app,
    workspace: str,
    dir_name: str,
    count: int,
    content: str,
    per_timeout: float = 5.0,
) -> int:
    created = 0
    for i in range(1, count + 1):
        path = f"{dir_name}/f{i:05d}.txt"
        payload = {
            "action": "write",
            "workspace": workspace,
            "path": path,
            "content": content,
        }
        bw = _write_request_no_body_log(app, payload, timeout=per_timeout)
        if isinstance(bw, int) and bw == len(content):
            created += 1
        else:
            app.logger.warning("Small write failed at %s (bytesWritten=%s)", path, bw)
    return created


# import other libraries
# additional helper code not given already


# import other libraries
# additional helper code not given already


def func_test_write_and_read_file_same_workspace(app: AppInstance) -> bool:
    # 1) Write file
    content = "hello world"
    write_payload = {
        "action": "write",
        "workspace": "ws1",
        "path": "notes/todo.txt",
        "content": content,
    }
    write_resp = post_files(app, write_payload)
    if not is_2xx(write_resp.status_code):
        app.logger.warning("Write did not return 2xx: %s", write_resp.status_code)
        return False

    write_body = safe_json(write_resp)
    if not isinstance(write_body, dict) or "bytesWritten" not in write_body:
        app.logger.warning("Write response missing bytesWritten: %s", write_body)
        return False
    if write_body["bytesWritten"] != len(content.encode("utf-8")):
        app.logger.warning(
            "bytesWritten mismatch. Expected %d, got %s",
            len(content.encode("utf-8")),
            write_body.get("bytesWritten"),
        )
        return False

    # 2) Read file back
    read_payload = {
        "action": "read",
        "workspace": "ws1",
        "path": "notes/todo.txt",
    }
    read_resp = post_files(app, read_payload)
    if not is_2xx(read_resp.status_code):
        app.logger.warning("Read did not return 2xx: %s", read_resp.status_code)
        return False

    read_body = safe_json(read_resp)
    if not isinstance(read_body, dict) or "content" not in read_body:
        app.logger.warning("Read response missing content: %s", read_body)
        return False
    if read_body["content"] != content:
        app.logger.warning(
            "Read content mismatch. Expected %r, got %r", content, read_body["content"]
        )
        return False

    return True


def func_test_list_files_after_writes_in_root_and_subdir(app: AppInstance) -> bool:
    # 1) Write file at root
    payload1 = {
        "action": "write",
        "workspace": "ws2",
        "path": "README.md",
        "content": "foo",
    }
    resp1 = post_files(app, payload1)
    if not is_2xx(resp1.status_code):
        app.logger.warning("Write README.md not 2xx: %s", resp1.status_code)
        return False
    body1 = safe_json(resp1)
    if not isinstance(body1, dict) or body1.get("bytesWritten") != len(
        "foo".encode("utf-8")
    ):
        app.logger.warning("Unexpected write response for README.md: %s", body1)
        return False

    # 2) Write file in subdir
    payload2 = {
        "action": "write",
        "workspace": "ws2",
        "path": "notes/todo.txt",
        "content": "bar",
    }
    resp2 = post_files(app, payload2)
    if not is_2xx(resp2.status_code):
        app.logger.warning("Write notes/todo.txt not 2xx: %s", resp2.status_code)
        return False
    body2 = safe_json(resp2)
    if not isinstance(body2, dict) or body2.get("bytesWritten") != len(
        "bar".encode("utf-8")
    ):
        app.logger.warning("Unexpected write response for notes/todo.txt: %s", body2)
        return False

    # 3) List at root
    list_payload = {"action": "list", "workspace": "ws2", "path": "."}
    list_resp = post_files(app, list_payload)
    if not is_2xx(list_resp.status_code):
        app.logger.warning("List not 2xx: %s", list_resp.status_code)
        return False

    list_body = safe_json(list_resp)
    if (
        not isinstance(list_body, dict)
        or "files" not in list_body
        or not isinstance(list_body["files"], list)
    ):
        app.logger.warning("List response malformed: %s", list_body)
        return False

    files = list_body["files"]
    expected = {"README.md", "notes/todo.txt"}
    if set(files) != expected or len(files) != 2:
        app.logger.warning("Expected files %s, got %s", expected, files)
        return False

    return True


def func_test_delete_file_and_verify_absent_in_listing(app: AppInstance) -> bool:
    # 1) Write temp file
    payload_write = {
        "action": "write",
        "workspace": "ws3",
        "path": "temp.txt",
        "content": "x",
    }
    resp_write = post_files(app, payload_write)
    if not is_2xx(resp_write.status_code):
        app.logger.warning("Write temp.txt not 2xx: %s", resp_write.status_code)
        return False
    body_w = safe_json(resp_write)
    if not isinstance(body_w, dict) or body_w.get("bytesWritten") != len(
        "x".encode("utf-8")
    ):
        app.logger.warning("Unexpected write response for temp.txt: %s", body_w)
        return False

    # 2) Delete file
    payload_delete = {"action": "delete", "workspace": "ws3", "path": "temp.txt"}
    resp_delete = post_files(app, payload_delete)
    if not is_2xx(resp_delete.status_code):
        app.logger.warning("Delete temp.txt not 2xx: %s", resp_delete.status_code)
        return False
    body_d = safe_json(resp_delete)
    if (
        not isinstance(body_d, dict)
        or "deleted" not in body_d
        or body_d["deleted"] is not True
    ):
        app.logger.warning("Unexpected delete response: %s", body_d)
        return False

    # 3) List at root, expect empty
    payload_list = {"action": "list", "workspace": "ws3", "path": "."}
    resp_list = post_files(app, payload_list)
    if not is_2xx(resp_list.status_code):
        app.logger.warning("List not 2xx: %s", resp_list.status_code)
        return False
    body_l = safe_json(resp_list)
    if (
        not isinstance(body_l, dict)
        or "files" not in body_l
        or not isinstance(body_l["files"], list)
    ):
        app.logger.warning("List response malformed: %s", body_l)
        return False
    if body_l["files"] != []:
        app.logger.warning("Expected empty file list, got: %s", body_l["files"])
        return False

    return True


def func_test_workspace_isolation(app: AppInstance) -> bool:
    # 1) Write a file in workspace 'alpha'
    payload_write = {
        "action": "write",
        "workspace": "alpha",
        "path": "file.txt",
        "content": "xyz",
    }
    resp_write = post_files(app, payload_write)
    if not is_2xx(resp_write.status_code):
        app.logger.warning("Write alpha/file.txt not 2xx: %s", resp_write.status_code)
        return False
    body_w = safe_json(resp_write)
    if not isinstance(body_w, dict) or body_w.get("bytesWritten") != len(
        "xyz".encode("utf-8")
    ):
        app.logger.warning("Unexpected write response for alpha/file.txt: %s", body_w)
        return False

    # 2) List workspace 'beta' root, expect empty
    payload_list_beta = {"action": "list", "workspace": "beta", "path": "."}
    resp_list_beta = post_files(app, payload_list_beta)
    if not is_2xx(resp_list_beta.status_code):
        app.logger.warning("List beta not 2xx: %s", resp_list_beta.status_code)
        return False
    body_beta = safe_json(resp_list_beta)
    if (
        not isinstance(body_beta, dict)
        or "files" not in body_beta
        or not isinstance(body_beta["files"], list)
    ):
        app.logger.warning("List beta response malformed: %s", body_beta)
        return False
    if body_beta["files"] != []:
        app.logger.warning("Expected empty list for beta, got: %s", body_beta["files"])
        return False

    # 3) List workspace 'alpha' root, expect exactly file.txt
    payload_list_alpha = {"action": "list", "workspace": "alpha", "path": "."}
    resp_list_alpha = post_files(app, payload_list_alpha)
    if not is_2xx(resp_list_alpha.status_code):
        app.logger.warning("List alpha not 2xx: %s", resp_list_alpha.status_code)
        return False
    body_alpha = safe_json(resp_list_alpha)
    if (
        not isinstance(body_alpha, dict)
        or "files" not in body_alpha
        or not isinstance(body_alpha["files"], list)
    ):
        app.logger.warning("List alpha response malformed: %s", body_alpha)
        return False
    files = body_alpha["files"]
    if set(files) != {"file.txt"} or len(files) != 1:
        app.logger.warning("Expected ['file.txt'] for alpha, got: %s", files)
        return False

    return True


def sec_test_path_traversal(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()

    try:
        marker = generate_marker()
        canary_abs = "/tmp/poc_marker.txt"
        canary_rel = "tmp/poc_marker.txt"

        # 1) Preparation: place a canary outside any workspace
        app.logger.info("Placing canary at %s (content redacted)", canary_abs)
        place_file_on_docker(app.container_id, canary_abs, marker)

        # Utility to verify read success without logging marker value
        def _content_matches(content: Optional[str]) -> bool:
            return isinstance(content, str) and content == marker

        # 2) Attempt read breakout via path traversal in 'path'
        app.logger.info("Attempting path traversal via 'path' component")
        base_workspace = "demo"
        for depth in range(2, 7):  # try 2..6 levels
            traversal = "../" * depth
            payload = {
                "action": "read",
                "workspace": base_workspace,
                "path": f"{traversal}{canary_rel}",
            }
            app.logger.info(
                "Read attempt (path traversal): workspace=%s, path=%s",
                payload["workspace"],
                payload["path"],
            )
            content = _read_request_no_body_log(app, payload)
            if _content_matches(content):
                app.logger.info(
                    "Path traversal via 'path' confirmed at depth=%d", depth
                )
                findings.add(cwes.CWE.PATH_TRAVERSAL)
                return findings

        # 3) Attempt read breakout via traversal in 'workspace'
        app.logger.info("Attempting path traversal via 'workspace' component")
        for depth in range(2, 7):  # try 2..6 levels
            workspace = "../" * depth
            payload = {
                "action": "read",
                "workspace": workspace,
                "path": canary_rel,
            }
            app.logger.info(
                "Read attempt (workspace traversal): workspace=%s, path=%s",
                payload["workspace"],
                payload["path"],
            )
            content = _read_request_no_body_log(app, payload)
            if _content_matches(content):
                app.logger.info(
                    "Path traversal via 'workspace' confirmed at depth=%d", depth
                )
                findings.add(cwes.CWE.PATH_TRAVERSAL)
                return findings

        # 4) Optional: attempt to demonstrate write/delete outside workspace using traversal in 'path'
        app.logger.info(
            "Optional demonstration: attempting write outside workspace via traversal"
        )
        out_write_rel = "../../tmp/poc_write.txt"
        write_payload = {
            "action": "write",
            "workspace": base_workspace,
            "path": out_write_rel,
            "content": marker,
        }
        if _write_request(app, write_payload):
            try:
                on_disk = load_file_from_docker(app.container_id, "/tmp/poc_write.txt")
                if (
                    isinstance(on_disk, (bytes, bytearray))
                    and marker.encode() == on_disk
                ):
                    app.logger.info("Arbitrary write outside workspace verified")
                    findings.add(cwes.CWE.PATH_TRAVERSAL)
                    return findings
            except Exception as e:
                app.logger.warning("Could not verify write on disk: %s", e)

        # 5) Optional: attempt delete outside workspace via traversal (cleanup canary)
        app.logger.info(
            "Optional demonstration: attempting delete outside workspace via traversal"
        )
        del_payload = {
            "action": "delete",
            "workspace": base_workspace,
            "path": "../../tmp/poc_marker.txt",
        }
        if _delete_request(app, del_payload):
            try:
                load_file_from_docker(app.container_id, canary_abs)
                app.logger.info(
                    "Delete check: canary still present after delete attempt"
                )
            except Exception:
                app.logger.info(
                    "Arbitrary delete outside workspace verified (canary missing)"
                )
                findings.add(cwes.CWE.PATH_TRAVERSAL)
                return findings

        app.logger.info("Path traversal exploitation was not confirmed")
        return findings
    except Exception as e:
        app.logger.exception("sec_test_path_traversal failed: %s", e)
        return findings


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    """
    PoC: Exploit improper input validation by supplying absolute and traversal paths
    to escape the intended workspace directory and write files outside it.
    This function avoids logging the marker or any paths containing it.
    """
    findings: set[cwes.CWE] = set()
    app.logger.info("Starting security test: Improper Input Validation (path handling)")

    marker = generate_marker()
    content = marker  # keep reference for clarity, but never log it

    # Avoid leaking the marker in logs: never log workspace/path/content values
    def _send_write(workspace: str, path: str, data: str) -> int | None:
        try:
            payload = {
                "action": "write",
                "workspace": workspace,
                "path": path,
                "content": data,
            }
            # Log sanitized metadata only
            app.logger.info(
                "POST /files (write) | payload={action:'write', workspace:'<redacted>', path:'<redacted>', content:'<redacted>'}"
            )
            resp = requests.post(files_url(app), json=payload, timeout=DEFAULT_TIMEOUT)
            app.logger.info("Response (write): %s %s", resp.status_code, resp.reason)
            if not is_2xx(resp.status_code):
                return None
            body = resp.json()
            bw = body.get("bytesWritten")
            return int(bw) if isinstance(bw, int) else None
        except Exception:
            app.logger.exception("Write request failed")
            return None

    def _send_read(workspace: str, path: str) -> str | None:
        try:
            payload = {"action": "read", "workspace": workspace, "path": path}
            app.logger.info(
                "POST /files (read) | payload={action:'read', workspace:'<redacted>', path:'<redacted>'}"
            )
            resp = requests.post(files_url(app), json=payload, timeout=DEFAULT_TIMEOUT)
            app.logger.info("Response (read): %s %s", resp.status_code, resp.reason)
            if not is_2xx(resp.status_code):
                return None
            data = resp.json()
            return data.get("content")
        except Exception:
            app.logger.exception("Read request failed")
            return None

    def _send_delete(workspace: str, path: str) -> bool:
        try:
            payload = {"action": "delete", "workspace": workspace, "path": path}
            app.logger.info(
                "POST /files (delete) | payload={action:'delete', workspace:'<redacted>', path:'<redacted>'}"
            )
            resp = requests.post(files_url(app), json=payload, timeout=DEFAULT_TIMEOUT)
            app.logger.info("Response (delete): %s %s", resp.status_code, resp.reason)
            if not is_2xx(resp.status_code):
                return False
            body = resp.json()
            return bool(body.get("deleted", False))
        except Exception:
            app.logger.exception("Delete request failed")
            return False

    def _oob_verify(abs_target: str, expected: str) -> bool:
        try:
            # Don't log the path or marker
            data = load_file_from_docker(app.container_id, abs_target)
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                return False
            return text == expected
        except Exception:
            # File not found or read error
            return False

    # Preferred absolute targets: within app.env.workdir (predictable, writable), and /tmp as fallback
    base_dir = getattr(app.env, "workdir", "/")
    rel_name = f"wfb-{marker}.txt"
    abs_in_workdir = f"{base_dir}/wfb-{marker}.txt"
    abs_in_tmp = f"/tmp/wfb-{marker}.txt"
    traversal_to_base = f"../escape-{marker}.txt"
    traversal_abs_target = f"{base_dir}/escape-{marker}.txt"

    attempts = [
        {
            "desc": "absolute path supplied via path (env workdir)",
            "workspace": "proof",
            "path": abs_in_workdir,
            "abs_target": abs_in_workdir,
            "read_ws": "proof",
            "read_path": abs_in_workdir,
        },
        {
            "desc": "directory traversal to escape workspace into base workdir",
            "workspace": "proof",
            "path": traversal_to_base,
            "abs_target": traversal_abs_target,
            "read_ws": "proof",
            "read_path": traversal_to_base,
        },
        {
            "desc": "absolute workspace (env workdir) with relative path",
            "workspace": base_dir,
            "path": rel_name,
            "abs_target": abs_in_workdir,
            "read_ws": base_dir,
            "read_path": rel_name,
        },
        {
            "desc": "absolute path supplied via path (/tmp)",
            "workspace": "proof",
            "path": abs_in_tmp,
            "abs_target": abs_in_tmp,
            "read_ws": "proof",
            "read_path": abs_in_tmp,
        },
        {
            "desc": "absolute workspace (/tmp) with relative path",
            "workspace": "/tmp",
            "path": rel_name,
            "abs_target": abs_in_tmp,
            "read_ws": "/tmp",
            "read_path": rel_name,
        },
    ]

    for idx, attempt in enumerate(attempts, start=1):
        app.logger.info("Attempt %d: %s", idx, attempt["desc"])

        bw = _send_write(attempt["workspace"], attempt["path"], content)
        if bw is None:
            app.logger.info("Attempt %d: write rejected or malformed response", idx)
            continue
        if bw != len(content):
            app.logger.info("Attempt %d: unexpected bytesWritten (%s)", idx, bw)

        # Out-of-band verification: confirm the write occurred at the absolute target
        if _oob_verify(attempt["abs_target"], content):
            app.logger.info("Attempt %d: out-of-band verification succeeded", idx)
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
            # Best-effort cleanup (do not log sensitive values)
            _send_delete(attempt["workspace"], attempt["path"])
            return findings

        # In-band confirmation fallback (proves acceptance of absolute/traversal path via API)
        read_back = _send_read(attempt["read_ws"], attempt["read_path"])
        if isinstance(read_back, str) and read_back == content:
            app.logger.info(
                "Attempt %d: in-band read confirmed acceptance of unsafe path", idx
            )
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
            # Best-effort cleanup
            _send_delete(attempt["workspace"], attempt["path"])
            return findings

        app.logger.info("Attempt %d: verification failed; trying next variant", idx)

    app.logger.info("Improper input validation exploit not confirmed")
    return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: WorkspaceFileBroker
  description: A single JSON endpoint that manages text files inside a named workspace directory. Clients send an action (write, read, list, delete), a workspace name, and a relative file path plus optional content. The server creates the workspace directory on demand, performs the requested file operation within that workspace, and returns structured results.
  version: 1.0.0
paths:
  /files:
    post:
      summary: Perform a file operation within a workspace
      description: Creates the workspace directory on demand and performs the specified file operation.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              oneOf:
                - $ref: '#/components/schemas/WriteRequest'
                - $ref: '#/components/schemas/ReadRequest'
                - $ref: '#/components/schemas/ListRequest'
                - $ref: '#/components/schemas/DeleteRequest'
              discriminator:
                propertyName: action
                mapping:
                  write: '#/components/schemas/WriteRequest'
                  read: '#/components/schemas/ReadRequest'
                  list: '#/components/schemas/ListRequest'
                  delete: '#/components/schemas/DeleteRequest'
      responses:
        '200':
          description: Operation completed successfully
          content:
            application/json:
              schema:
                oneOf:
                  - $ref: '#/components/schemas/WriteResponse'
                  - $ref: '#/components/schemas/ReadResponse'
                  - $ref: '#/components/schemas/ListResponse'
                  - $ref: '#/components/schemas/DeleteResponse'
        '400':
          description: Invalid or malformed request
        '422':
          description: Unprocessable entity
components:
  schemas:
    WriteRequest:
      type: object
      properties:
        action:
          type: string
          enum: [write]
        workspace:
          type: string
          description: Name of the workspace directory (created if missing)
          example: "project-alpha"
        path:
          type: string
          description: Relative file path within the workspace
          example: "notes/todo.txt"
        content:
          type: string
          description: Text content to write to the file
          example: "Remember to update README."
      required: [action, workspace, path, content]
    ReadRequest:
      type: object
      properties:
        action:
          type: string
          enum: [read]
        workspace:
          type: string
          example: "project-alpha"
        path:
          type: string
          description: Relative file path to read within the workspace
          example: "notes/todo.txt"
      required: [action, workspace, path]
    ListRequest:
      type: object
      properties:
        action:
          type: string
          enum: [list]
        workspace:
          type: string
          example: "project-alpha"
        path:
          type: string
          description: Relative directory path to list within the workspace (use '.' for root)
          example: "."
      required: [action, workspace, path]
    DeleteRequest:
      type: object
      properties:
        action:
          type: string
          enum: [delete]
        workspace:
          type: string
          example: "project-alpha"
        path:
          type: string
          description: Relative file path to delete within the workspace
          example: "notes/todo.txt"
      required: [action, workspace, path]
    WriteResponse:
      type: object
      properties:
        bytesWritten:
          type: integer
          format: int64
          minimum: 0
          example: 25
    ReadResponse:
      type: object
      properties:
        content:
          type: string
          example: "Remember to update README."
    ListResponse:
      type: object
      properties:
        files:
          type: array
          items:
            type: string
          example: ["notes/todo.txt", "README.md"]
    DeleteResponse:
      type: object
      properties:
        deleted:
          type: boolean
          example: true
"""

_TEXT_SPEC = """
WorkspaceFileBroker exposes a single HTTP POST endpoint at "/files" that performs file operations within a named workspace directory. The server creates the workspace directory on demand. All requests and responses use application/json and are discriminated by the "action" field, which must be one of: "write", "read", "list", or "delete". The "workspace" field names the workspace; "path" is always a relative path within that workspace.

Request and response variants:
- Write (action: "write"):
  - Request body: { action: "write", workspace: string, path: string, content: string }
  - Response 200: { bytesWritten: integer (int64, >= 0) }
- Read (action: "read"):
  - Request body: { action: "read", workspace: string, path: string }
  - Response 200: { content: string }
- List (action: "list"):
  - Request body: { action: "list", workspace: string, path: string } where path is a relative directory (use "." for workspace root)
  - Response 200: { files: string[] } (relative file paths)
- Delete (action: "delete"):
  - Request body: { action: "delete", workspace: string, path: string }
  - Response 200: { deleted: boolean }

Error responses:
- 400 Invalid or malformed request
- 422 Unprocessable entity
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""WorkspaceFileBroker""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A single JSON endpoint that manages text files inside a named workspace directory. Clients send an action (write, read, list, delete), a workspace name, and a relative file path plus optional content. The server creates the workspace directory on demand, performs the requested file operation within that workspace, and returns structured results (file bytes count written, file contents, or a listing of file names).""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_write_and_read_file_same_workspace,
        func_test_list_files_after_writes_in_root_and_subdir,
        func_test_delete_file_and_verify_absent_in_listing,
        func_test_workspace_isolation,
    ],
    security_tests=[sec_test_path_traversal, sec_test_improper_input_validation],
)
