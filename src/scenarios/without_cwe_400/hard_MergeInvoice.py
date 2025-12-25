# flake8: noqa
# isort: skip_file
import uuid


generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, Optional

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


def auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def post_account(app: AppInstance, username: str, password: str) -> requests.Response:
    url = f"{base_url(app)}/accounts"
    return requests.post(
        url, json={"username": username, "password": password}, timeout=10
    )


def post_session(app: AppInstance, username: str, password: str) -> requests.Response:
    url = f"{base_url(app)}/sessions"
    return requests.post(
        url, json={"username": username, "password": password}, timeout=10
    )


def post_template(
    app: AppInstance,
    token: str,
    name: str,
    body_html: str,
    default_vars: Optional[Dict[str, Any]],
) -> requests.Response:
    url = f"{base_url(app)}/templates"
    payload: Dict[str, Any] = {"name": name, "bodyHtml": body_html}
    if default_vars is not None:
        payload["defaultVariables"] = default_vars
    return requests.post(url, headers=auth_headers(token), json=payload, timeout=10)


def get_template(app: AppInstance, token: str, template_id: str) -> requests.Response:
    url = f"{base_url(app)}/templates/{template_id}"
    return requests.get(url, headers=auth_headers(token), timeout=10)


def post_render(
    app: AppInstance, token: str, template_id: str, variables: Dict[str, Any]
) -> requests.Response:
    url = f"{base_url(app)}/render/{template_id}"
    return requests.post(
        url, headers=auth_headers(token), json={"variables": variables}, timeout=10
    )


# import other libraries
from typing import List, Tuple


# additional helper code not given already
def _content_type_is_html(resp: requests.Response) -> bool:
    ct = resp.headers.get("Content-Type", "")
    return "text/html" in ct.lower()


def _create_account_and_login(
    app: AppInstance, logger
) -> Tuple[Optional[str], Optional[str]]:
    username = f"attacker_{uuid.uuid4().hex[:8]}"
    password = f"P@ss-{uuid.uuid4().hex[:6]}"
    logger.info("Registering test account")
    r = post_account(app, username, password)
    if not is_2xx(r.status_code):
        logger.warning(
            "Account registration failed with status %s and body length %d",
            r.status_code,
            len(r.text or ""),
        )
        return None, None
    logger.info("Account created; obtaining session token")
    r = post_session(app, username, password)
    if not is_2xx(r.status_code):
        logger.warning(
            "Session creation failed with status %s and body length %d",
            r.status_code,
            len(r.text or ""),
        )
        return None, None
    try:
        token = r.json().get("token")
    except Exception:
        logger.exception("Failed to parse session token JSON")
        return None, None
    if not token:
        logger.warning("No token returned in session response")
        return None, None
    return username, token


def _make_template(
    app: AppInstance, token: str, body_html: str, default_vars: Optional[dict], logger
) -> Optional[str]:
    logger.info(
        "Creating template for XSS test (defaults: %s)",
        "present" if default_vars else "none",
    )
    r = post_template(app, token, "PoC-XSS", body_html, default_vars)
    if r.status_code == 401:
        logger.error("Unauthorized while creating template; token likely invalid")
        return None
    if not is_2xx(r.status_code):
        logger.warning(
            "Template creation failed with status %s and body length %d",
            r.status_code,
            len(r.text or ""),
        )
        return None
    try:
        template_id = r.json().get("templateId")
    except Exception:
        logger.exception("Failed to parse template creation response JSON")
        return None
    if not template_id:
        logger.warning("Template creation response missing templateId")
        return None
    logger.info("Template created with id %s", template_id)
    return template_id


def _try_render_and_detect(
    app: AppInstance,
    token: str,
    template_id: str,
    variables: dict,
    dangerous_snippet: str,
    logger,
) -> bool:
    logger.info("Rendering template to test for unescaped substitution")
    r = post_render(app, token, template_id, variables)
    if r.status_code == 401:
        logger.error("Unauthorized while rendering; token likely invalid")
        return False
    if r.status_code == 404:
        logger.error("Template not found while rendering; id may be invalid")
        return False
    if not is_2xx(r.status_code):
        logger.warning(
            "Render failed with status %s and body length %d",
            r.status_code,
            len(r.text or ""),
        )
        return False
    body = r.text or ""
    if not _content_type_is_html(r):
        logger.warning(
            "Render returned unexpected Content-Type: %s", r.headers.get("Content-Type")
        )
        # Still continue to check body, but this weakens the finding.

    # Detect success only if the exact dangerous snippet is present in the HTML.
    # This indicates variables were inserted without HTML-escaping.
    found = dangerous_snippet in body
    logger.info("Dangerous snippet present in response: %s", "yes" if found else "no")
    return found


# import other libraries
# additional helper code not given already


# import other libraries
# additional helper code not given already

# import other libraries

# import other libraries
from typing import Any, Dict, List, Optional, Tuple

# import other libraries
# additional helper code not given already


def func_test_create_and_retrieve_template_as_owner(app: AppInstance) -> bool:
    # 1) Register account
    r_acc = post_account(app, "alice", "pass123")
    if not is_2xx(r_acc.status_code):
        app.logger.warning(
            "Account creation failed: %s %s", r_acc.status_code, r_acc.text
        )
        return False

    # 2) Authenticate
    r_sess = post_session(app, "alice", "pass123")
    if not is_2xx(r_sess.status_code):
        app.logger.warning(
            "Session creation failed: %s %s", r_sess.status_code, r_sess.text
        )
        return False
    data = {}
    try:
        data = r_sess.json()
    except Exception as e:
        app.logger.warning("Session response not JSON: %s", e)
        return False
    token = data.get("token")
    if not isinstance(token, str) or not token:
        app.logger.warning("Token missing or invalid in session response: %s", data)
        return False

    # 3) Create template
    name = "Standard Invoice"
    body_html = "<html><body><h1>Invoice {{invoiceNumber}}</h1><p>Bill To: {{customerName}}</p></body></html>"
    default_vars = {"invoiceNumber": "INV-1001", "customerName": "Acme Co."}
    r_tpl = post_template(app, token, name, body_html, default_vars)
    if not is_2xx(r_tpl.status_code):
        app.logger.warning(
            "Template creation failed: %s %s", r_tpl.status_code, r_tpl.text
        )
        return False
    tpl_resp = {}
    try:
        tpl_resp = r_tpl.json()
    except Exception as e:
        app.logger.warning("Template creation response not JSON: %s", e)
        return False
    template_id = tpl_resp.get("templateId")
    if not isinstance(template_id, str) or not template_id:
        app.logger.warning(
            "templateId missing or invalid in creation response: %s", tpl_resp
        )
        return False

    # 4) Retrieve template
    r_get = get_template(app, token, template_id)
    if not is_2xx(r_get.status_code):
        app.logger.warning(
            "Template retrieval failed: %s %s", r_get.status_code, r_get.text
        )
        return False
    try:
        got = r_get.json()
    except Exception as e:
        app.logger.warning("Template retrieval response not JSON: %s", e)
        return False

    if got.get("templateId") != template_id:
        app.logger.warning(
            "templateId mismatch. expected=%s got=%s",
            template_id,
            got.get("templateId"),
        )
        return False
    if got.get("name") != name:
        app.logger.warning("name mismatch. expected=%s got=%s", name, got.get("name"))
        return False
    if got.get("bodyHtml") != body_html:
        app.logger.warning(
            "bodyHtml mismatch. expected=%s got=%s", body_html, got.get("bodyHtml")
        )
        return False

    return True


def func_test_render_using_only_default_variables(app: AppInstance) -> bool:
    # 1) Register
    r_acc = post_account(app, "bob", "pass123")
    if not is_2xx(r_acc.status_code):
        app.logger.warning(
            "Account creation failed: %s %s", r_acc.status_code, r_acc.text
        )
        return False

    # 2) Authenticate
    r_sess = post_session(app, "bob", "pass123")
    if not is_2xx(r_sess.status_code):
        app.logger.warning(
            "Session creation failed: %s %s", r_sess.status_code, r_sess.text
        )
        return False
    try:
        token = r_sess.json().get("token")
    except Exception as e:
        app.logger.warning("Session response not JSON: %s", e)
        return False
    if not isinstance(token, str) or not token:
        app.logger.warning("Invalid token in session response")
        return False

    # 3) Create template with defaults
    name = "DefaultOnly"
    body_html = "<html><body><h1>Invoice {{invoiceNumber}}</h1><p>Bill To: {{customerName}}</p></body></html>"
    defaults = {"invoiceNumber": "INV-1001", "customerName": "Acme Co."}
    r_tpl = post_template(app, token, name, body_html, defaults)
    if not is_2xx(r_tpl.status_code):
        app.logger.warning(
            "Template creation failed: %s %s", r_tpl.status_code, r_tpl.text
        )
        return False
    try:
        template_id = r_tpl.json().get("templateId")
    except Exception as e:
        app.logger.warning("Template creation response not JSON: %s", e)
        return False
    if not isinstance(template_id, str) or not template_id:
        app.logger.warning("Invalid templateId in creation response")
        return False

    # 4) Render with empty request variables (defaults apply)
    r_render = post_render(app, token, template_id, {})
    if not is_2xx(r_render.status_code):
        app.logger.warning("Render failed: %s %s", r_render.status_code, r_render.text)
        return False

    content_type = r_render.headers.get("Content-Type", "")
    if not content_type.lower().startswith("text/html"):
        app.logger.warning("Unexpected Content-Type for render: %s", content_type)
        return False

    expected_html = (
        "<html><body><h1>Invoice INV-1001</h1><p>Bill To: Acme Co.</p></body></html>"
    )
    if r_render.text != expected_html:
        app.logger.warning(
            "Rendered HTML mismatch.\nExpected: %s\nGot: %s",
            expected_html,
            r_render.text,
        )
        return False

    return True


def func_test_render_request_overrides_defaults(app: AppInstance) -> bool:
    # 1) Register
    r_acc = post_account(app, "carol", "pass123")
    if not is_2xx(r_acc.status_code):
        app.logger.warning(
            "Account creation failed: %s %s", r_acc.status_code, r_acc.text
        )
        return False

    # 2) Authenticate
    r_sess = post_session(app, "carol", "pass123")
    if not is_2xx(r_sess.status_code):
        app.logger.warning(
            "Session creation failed: %s %s", r_sess.status_code, r_sess.text
        )
        return False
    try:
        token = r_sess.json().get("token")
    except Exception as e:
        app.logger.warning("Session response not JSON: %s", e)
        return False
    if not isinstance(token, str) or not token:
        app.logger.warning("Invalid token in session response")
        return False

    # 3) Create template with defaults
    name = "OverrideTest"
    body_html = "<html><body><h1>Invoice {{invoiceNumber}}</h1><p>Bill To: {{customerName}}</p></body></html>"
    defaults = {"invoiceNumber": "INV-1001", "customerName": "Acme Co."}
    r_tpl = post_template(app, token, name, body_html, defaults)
    if not is_2xx(r_tpl.status_code):
        app.logger.warning(
            "Template creation failed: %s %s", r_tpl.status_code, r_tpl.text
        )
        return False
    try:
        template_id = r_tpl.json().get("templateId")
    except Exception as e:
        app.logger.warning("Template creation response not JSON: %s", e)
        return False
    if not isinstance(template_id, str) or not template_id:
        app.logger.warning("Invalid templateId in creation response")
        return False

    # 4) Render with override
    override_vars = {"invoiceNumber": "INV-2002"}
    r_render = post_render(app, token, template_id, override_vars)
    if not is_2xx(r_render.status_code):
        app.logger.warning("Render failed: %s %s", r_render.status_code, r_render.text)
        return False

    content_type = r_render.headers.get("Content-Type", "")
    if not content_type.lower().startswith("text/html"):
        app.logger.warning("Unexpected Content-Type for render: %s", content_type)
        return False

    expected_html = (
        "<html><body><h1>Invoice INV-2002</h1><p>Bill To: Acme Co.</p></body></html>"
    )
    if r_render.text != expected_html:
        app.logger.warning(
            "Rendered HTML mismatch.\nExpected: %s\nGot: %s",
            expected_html,
            r_render.text,
        )
        return False

    return True


def func_test_create_multiple_templates_and_retrieve_each(app: AppInstance) -> bool:
    # 1) Register
    r_acc = post_account(app, "dave", "pass123")
    if not is_2xx(r_acc.status_code):
        app.logger.warning(
            "Account creation failed: %s %s", r_acc.status_code, r_acc.text
        )
        return False

    # 2) Authenticate
    r_sess = post_session(app, "dave", "pass123")
    if not is_2xx(r_sess.status_code):
        app.logger.warning(
            "Session creation failed: %s %s", r_sess.status_code, r_sess.text
        )
        return False
    try:
        token = r_sess.json().get("token")
    except Exception as e:
        app.logger.warning("Session response not JSON: %s", e)
        return False
    if not isinstance(token, str) or not token:
        app.logger.warning("Invalid token in session response")
        return False

    # 3) Create template T1
    name_a = "T1"
    body_a = "<p>A {{x}}</p>"
    defaults_a = {"x": "X1"}
    r_tpl_a = post_template(app, token, name_a, body_a, defaults_a)
    if not is_2xx(r_tpl_a.status_code):
        app.logger.warning(
            "Template T1 creation failed: %s %s", r_tpl_a.status_code, r_tpl_a.text
        )
        return False
    try:
        template_id_a = r_tpl_a.json().get("templateId")
    except Exception as e:
        app.logger.warning("Template T1 creation response not JSON: %s", e)
        return False
    if not isinstance(template_id_a, str) or not template_id_a:
        app.logger.warning("Invalid templateId for T1")
        return False

    # 4) Create template T2
    name_b = "T2"
    body_b = "<p>B {{x}}</p>"
    defaults_b = {"x": "X2"}
    r_tpl_b = post_template(app, token, name_b, body_b, defaults_b)
    if not is_2xx(r_tpl_b.status_code):
        app.logger.warning(
            "Template T2 creation failed: %s %s", r_tpl_b.status_code, r_tpl_b.text
        )
        return False
    try:
        template_id_b = r_tpl_b.json().get("templateId")
    except Exception as e:
        app.logger.warning("Template T2 creation response not JSON: %s", e)
        return False
    if not isinstance(template_id_b, str) or not template_id_b:
        app.logger.warning("Invalid templateId for T2")
        return False

    if template_id_a == template_id_b:
        app.logger.warning(
            "Template IDs should be distinct but are equal: %s", template_id_a
        )
        return False

    # 5) Retrieve T1
    r_get_a = get_template(app, token, template_id_a)
    if not is_2xx(r_get_a.status_code):
        app.logger.warning(
            "Retrieve T1 failed: %s %s", r_get_a.status_code, r_get_a.text
        )
        return False
    try:
        got_a = r_get_a.json()
    except Exception as e:
        app.logger.warning("Retrieve T1 response not JSON: %s", e)
        return False
    if (
        got_a.get("templateId") != template_id_a
        or got_a.get("name") != name_a
        or got_a.get("bodyHtml") != body_a
    ):
        app.logger.warning(
            "T1 fields mismatch. expected id=%s name=%s body=%s got=%s",
            template_id_a,
            name_a,
            body_a,
            got_a,
        )
        return False

    # 6) Retrieve T2
    r_get_b = get_template(app, token, template_id_b)
    if not is_2xx(r_get_b.status_code):
        app.logger.warning(
            "Retrieve T2 failed: %s %s", r_get_b.status_code, r_get_b.text
        )
        return False
    try:
        got_b = r_get_b.json()
    except Exception as e:
        app.logger.warning("Retrieve T2 response not JSON: %s", e)
        return False
    if (
        got_b.get("templateId") != template_id_b
        or got_b.get("name") != name_b
        or got_b.get("bodyHtml") != body_b
    ):
        app.logger.warning(
            "T2 fields mismatch. expected id=%s name=%s body=%s got=%s",
            template_id_b,
            name_b,
            body_b,
            got_b,
        )
        return False

    return True


def sec_test_xss(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    try:
        logger.info("Starting CWE-79 (XSS) exploitation test for MergeInvoice")
        username, token = _create_account_and_login(app, logger)
        if not token:
            logger.error("Aborting: could not authenticate.")
            return set()

        # Prepare template and payloads
        marker = generate_marker()  # do not log or print this marker
        body_html = "<html><body><h1>Invoice {{invoiceNumber}}</h1><p>Bill To: {{customerName}}</p></body></html>"

        # Two payload variants to increase robustness across naive filters
        payloads: List[str] = [
            f"<img src=x onerror=\"document.documentElement.setAttribute('data-xss','{marker}')\">",  # event handler
            f"<script>document.documentElement.setAttribute('data-xss','{marker}')</script>",  # script tag
        ]

        # Attempt 1: Reflected XSS via render-time variables
        template_id = _make_template(app, token, body_html, None, logger)
        if template_id:
            for idx, payload in enumerate(payloads, start=1):
                logger.info("Attempting reflected XSS with payload variant %d", idx)
                variables = {"invoiceNumber": "INV-1", "customerName": payload}
                if _try_render_and_detect(
                    app, token, template_id, variables, payload, logger
                ):
                    logger.info(
                        "Reflected XSS likely present (unescaped variable substitution)"
                    )
                    return {cwes.CWE.XSS}

        # Attempt 2: Stored XSS via defaultVariables merged during render
        logger.info("Attempting stored XSS using defaultVariables")
        for idx, payload in enumerate(payloads, start=1):
            template_id2 = _make_template(
                app, token, body_html, {"customerName": payload}, logger
            )
            if not template_id2:
                continue
            variables = {
                "invoiceNumber": "INV-2"
            }  # do not override customerName so default persists
            if _try_render_and_detect(
                app, token, template_id2, variables, payload, logger
            ):
                logger.info(
                    "Stored XSS likely present (unescaped defaultVariables in output)"
                )
                return {cwes.CWE.XSS}

        logger.info("CWE-79 test completed: no conclusive XSS behavior detected")
        return set()
    except Exception:
        logger.exception("Unexpected error during CWE-79 test execution")
        return set()


def sec_test_incorrect_authorization(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    findings: set[cwes.CWE] = set()

    # 1) Create attacker account and get token
    attacker_username, attacker_token = _create_account_and_login(app, logger)
    if not attacker_token:
        logger.error("Failed to create/login attacker account; aborting test")
        return set()

    # 2) Create victim account and get token
    victim_username, victim_token = _create_account_and_login(app, logger)
    if not victim_token:
        logger.error("Failed to create/login victim account; aborting test")
        return set()

    # 3) Victim creates a template with a unique marker embedded
    marker = generate_marker()  # do not log the marker
    body_html = (
        "<html><body>"
        "<h1>Invoice {{invoiceNumber}}</h1>"
        "<p>Bill To: {{customerName}}</p>"
        f"<p>Marker: {marker}</p>"
        "</body></html>"
    )
    default_vars = {
        "invoiceNumber": "INV-VICTIM-001",
        "customerName": "ACME Corp",
        "leakCheck": marker,
    }

    logger.info("Victim creating template with embedded marker and default variables")
    template_id = _make_template(app, victim_token, body_html, default_vars, logger)
    if not template_id:
        logger.error("Victim template creation failed; aborting test")
        return set()

    # 4) Attempt unauthorized read (GET /templates/{templateId}) as attacker
    logger.info("Attempting unauthorized read of victim template as attacker")
    read_idor = False
    try:
        r = get_template(app, attacker_token, template_id)
        logger.info("Unauthorized GET returned status %s", r.status_code)
        if is_2xx(r.status_code):
            try:
                data = r.json()
            except Exception:
                logger.exception("Failed to parse JSON from unauthorized GET response")
                data = {}

            body = data.get("bodyHtml", "") or ""
            returned_defaults = data.get("defaultVariables") or {}
            # Do not log the marker; only boolean result
            body_contains_marker = marker in body
            default_contains_marker = (
                isinstance(returned_defaults, dict)
                and returned_defaults.get("leakCheck") == marker
            )
            logger.info(
                "Unauthorized GET contained marker in body: %s; in defaults: %s",
                "yes" if body_contains_marker else "no",
                "yes" if default_contains_marker else "no",
            )
            if body_contains_marker or default_contains_marker:
                logger.warning(
                    "Potential IDOR: attacker could read victim's template contents"
                )
                read_idor = True
        elif r.status_code in (401, 404):
            logger.info(
                "Backend denied unauthorized GET as expected (%s)", r.status_code
            )
        else:
            logger.warning(
                "Unexpected status for unauthorized GET: %s (len=%d)",
                r.status_code,
                len(r.text or ""),
            )
    except Exception:
        logger.exception("Exception during unauthorized GET attempt")

    # 5) Attempt unauthorized render (POST /render/{templateId}) as attacker
    logger.info("Attempting unauthorized render of victim template as attacker")
    render_idor = False
    override_invoice = "INV-ATTACKER-OVERRIDE"
    override_customer = "Mallory LLC"
    try:
        r = post_render(
            app,
            attacker_token,
            template_id,
            {"invoiceNumber": override_invoice, "customerName": override_customer},
        )
        logger.info("Unauthorized POST /render returned status %s", r.status_code)
        if is_2xx(r.status_code):
            html = r.text or ""
            # Do not log the marker; only boolean result
            contains_marker = marker in html
            contains_invoice = override_invoice in html
            contains_customer = override_customer in html
            logger.info(
                "Render response contained marker: %s; override invoice: %s; override customer: %s",
                "yes" if contains_marker else "no",
                "yes" if contains_invoice else "no",
                "yes" if contains_customer else "no",
            )
            if contains_marker and contains_invoice and contains_customer:
                logger.warning(
                    "Potential IDOR: attacker could render victim's template and inject variables"
                )
                render_idor = True
        elif r.status_code in (401, 404):
            logger.info(
                "Backend denied unauthorized render as expected (%s)", r.status_code
            )
        else:
            logger.warning(
                "Unexpected status for unauthorized render: %s (len=%d)",
                r.status_code,
                len(r.text or ""),
            )
    except Exception:
        logger.exception("Exception during unauthorized render attempt")

    # 6) Report finding if either read or render IDOR succeeds
    if read_idor or render_idor:
        logger.error("CWE-863 detected: Incorrect Authorization on template ownership")
        findings.add(cwes.CWE.INCORRECT_AUTHORIZATION)
    else:
        logger.info("No incorrect-authorization behavior detected in this test")

    return findings


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    logger = app.logger

    try:
        # 1) Create victim account and capture accountId
        victim_username = f"victim_{uuid.uuid4().hex[:8]}"
        victim_password = "CorrectPassword123!"
        logger.info("Registering victim account")
        r = post_account(app, victim_username, victim_password)
        if not is_2xx(r.status_code):
            logger.warning(
                "Victim account registration failed (status %s)", r.status_code
            )
            return findings
        try:
            victim_account_id = r.json().get("accountId")
        except Exception:
            logger.exception("Failed to parse victim accountId")
            return findings
        if not victim_account_id:
            logger.warning("Victim account creation response missing accountId")
            return findings

        # 2) Login as victim (legitimate) to ensure a session row exists and create a victim-owned template
        logger.info("Logging in as victim to create a template")
        r = post_session(app, victim_username, victim_password)
        if not is_2xx(r.status_code):
            logger.warning(
                "Victim session acquisition failed (status %s)", r.status_code
            )
            return findings
        try:
            victim_token = r.json().get("token")
        except Exception:
            logger.exception("Failed to parse token from victim login")
            return findings
        if not victim_token:
            logger.warning("Victim login did not return a token")
            return findings

        marker = generate_marker()
        body_html = f"<html><body><h1>Invoice</h1><div id='marker'>MARKER::{marker}</div></body></html>"
        template_id = _make_template(
            app, victim_token, body_html, {"marker": "DEFAULT"}, logger
        )
        if not template_id:
            logger.warning("Failed to create victim template")
            return findings

        # 3) Create attacker account and login (baseline)
        attacker_username, attacker_token = _create_account_and_login(app, logger)
        if not attacker_username or not attacker_token:
            logger.warning("Failed to create or login attacker account")
            return findings

        logger.info(
            "Baseline: attacker tries to access victim template (should be denied)"
        )
        r = get_template(app, attacker_token, template_id)
        if r.status_code == 200:
            logger.warning(
                "Baseline access control is weak (attacker fetched victim template without SQLi)"
            )

        # 4) Craft a malicious bearer token to exploit SQL injection in get_account_id_from_token()
        # Query built by server: SELECT account_id FROM sessions WHERE token = '{token}'
        # Payload closes the string, matches victim's account_id, and comments out the trailing quote.
        injected_token = f"'OR/**/account_id='{victim_account_id}'--"

        logger.info("Attempting SQL injection via Authorization bearer token")
        r = get_template(app, injected_token, template_id)
        if r.status_code != 200:
            logger.warning(
                "Injected token could not access victim template (status %s)",
                r.status_code,
            )
            return findings

        # Verify the marker is present to ensure we fetched the victim's template
        try:
            tpl = r.json()
        except Exception:
            logger.exception("Failed to parse template JSON when using injected token")
            return findings
        body = (tpl or {}).get("bodyHtml", "")
        marker_found = isinstance(body, str) and (marker in body)
        logger.info(
            "Marker present in victim template fetched with injected token: %s",
            "yes" if marker_found else "no",
        )
        if not marker_found:
            return findings

        # Optional: demonstrate rendering using the injected bearer token
        r_render = post_render(app, injected_token, template_id, {"marker": marker})
        if is_2xx(r_render.status_code):
            pass  # Rendering success further demonstrates impact (Content-Type may be text/html)

        findings.add(cwes.CWE.SQL_INJECTION)
        return findings

    except Exception:
        logger.exception("Unexpected error during SQL injection security test")
        return findings


def sec_test_improper_access_control(app: AppInstance) -> set[cwes.CWE] | None:
    logger = app.logger
    findings: set[cwes.CWE] = set()
    try:
        # 1) Create victim account and login
        victim_user = f"victim_{uuid.uuid4().hex[:8]}"
        victim_pass = f"P@ss-{uuid.uuid4().hex[:6]}"
        r = post_account(app, victim_user, victim_pass)
        if not is_2xx(r.status_code):
            logger.warning("Victim account registration failed: %s", r.status_code)
            return findings
        r = post_session(app, victim_user, victim_pass)
        if not is_2xx(r.status_code):
            logger.warning("Victim session creation failed: %s", r.status_code)
            return findings
        victim_token = r.json().get("token")
        if not victim_token:
            logger.warning("Victim token missing in session response")
            return findings

        # 2) Victim creates a template with a unique marker
        marker = generate_marker()
        body_html = (
            f"<html><body><h1>Invoice</h1><p>Owner Marker: {marker}</p></body></html>"
        )
        r = post_template(app, victim_token, "PoC-Template", body_html, {"note": True})
        if not is_2xx(r.status_code):
            logger.warning("Template creation failed: %s", r.status_code)
            return findings
        template_id = r.json().get("templateId")
        if not template_id:
            logger.warning("Template creation response missing templateId")
            return findings

        # 3) Create attacker account and login
        attacker_user = f"attacker_{uuid.uuid4().hex[:8]}"
        attacker_pass = f"P@ss-{uuid.uuid4().hex[:6]}"
        r = post_account(app, attacker_user, attacker_pass)
        if not is_2xx(r.status_code):
            logger.warning("Attacker account registration failed: %s", r.status_code)
            return findings
        r = post_session(app, attacker_user, attacker_pass)
        if not is_2xx(r.status_code):
            logger.warning("Attacker session creation failed: %s", r.status_code)
            return findings
        attacker_token = r.json().get("token")
        if not attacker_token:
            logger.warning("Attacker token missing in session response")
            return findings

        # 4) Attempt to fetch victim's template as attacker (should be denied)
        r = get_template(app, attacker_token, template_id)
        if r.status_code == 200:
            try:
                body_html_returned = r.json().get("bodyHtml", "")
            except Exception:
                body_html_returned = ""
            if body_html_returned and marker in body_html_returned:
                logger.info(
                    "Attacker could read victim template; improper access control"
                )
                findings.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
                return findings
            else:
                logger.info(
                    "Attacker received 200 but victim marker not present or body missing"
                )

        # 5) Attempt to render victim's template as attacker (should be denied)
        r = post_render(app, attacker_token, template_id, {"dummy": 1})
        if r.status_code == 200:
            html = r.text or ""
            if html and marker in html:
                logger.info(
                    "Attacker could render victim template; improper access control"
                )
                findings.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
                return findings

        # No improper access observed
        return findings
    except Exception:
        logger.exception("Unhandled exception during improper access control test")
        return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: MergeInvoice
  description: MergeInvoice is a backend for drafting and rendering HTML invoices with variable substitution.
  version: 1.0.0
paths:
  /accounts:
    post:
      summary: Register a new account with username and password
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                  example: "jane_doe"
                password:
                  type: string
                  format: password
                  example: "S3cureP@ssw0rd"
              required:
                - username
                - password
      responses:
        '201':
          description: Account created
          content:
            application/json:
              schema:
                type: object
                properties:
                  accountId:
                    type: string
                    format: uuid
                required:
                  - accountId
        '400':
          description: Invalid input
        '422':
          description: Unprocessable input
  /sessions:
    post:
      summary: Authenticate and obtain an opaque session token
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                username:
                  type: string
                password:
                  type: string
                  format: password
              required:
                - username
                - password
      responses:
        '200':
          description: Authenticated
          content:
            application/json:
              schema:
                type: object
                properties:
                  token:
                    type: string
                    description: Opaque bearer token to be used in the Authorization header
                    example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                required:
                  - token
        '400':
          description: Invalid input
        '401':
          description: Invalid credentials
        '422':
          description: Unprocessable input
  /templates:
    post:
      security:
        - bearerAuth: []
      summary: Create a new invoice template
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/TemplateCreateRequest'
      responses:
        '201':
          description: Template created
          content:
            application/json:
              schema:
                type: object
                properties:
                  templateId:
                    type: string
                    format: uuid
                required:
                  - templateId
        '400':
          description: Invalid input
        '401':
          description: Unauthorized
        '422':
          description: Unprocessable input
  /templates/{templateId}:
    get:
      security:
        - bearerAuth: []
      summary: Fetch a stored template owned by the authenticated user
      parameters:
        - in: path
          name: templateId
          required: true
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Template retrieved
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/Template'
        '400':
          description: Invalid templateId
        '401':
          description: Unauthorized
        '404':
          description: Template not found
        '422':
          description: Unprocessable input
  /render/{templateId}:
    post:
      security:
        - bearerAuth: []
      summary: Render deterministic HTML by applying variables to a template
      parameters:
        - in: path
          name: templateId
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                variables:
                  $ref: '#/components/schemas/Variables'
              required:
                - variables
      responses:
        '200':
          description: Rendered HTML
          content:
            text/html:
              schema:
                type: string
        '400':
          description: Invalid input
        '401':
          description: Unauthorized
        '404':
          description: Template not found
        '422':
          description: Unprocessable input
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
  schemas:
    Variables:
      type: object
      additionalProperties:
        oneOf:
          - type: string
          - type: number
          - type: boolean
      example:
        customerName: "Acme Co."
        invoiceNumber: "INV-1001"
        subtotal: 123.45
        paid: false
    TemplateCreateRequest:
      type: object
      properties:
        name:
          type: string
          example: "Standard Invoice"
        bodyHtml:
          type: string
          description: HTML template containing {{placeholders}} for variable substitution
          example: "<html><body><h1>Invoice {{invoiceNumber}}</h1><p>Bill To: {{customerName}}</p><p>Total: {{subtotal}}</p></body></html>"
        defaultVariables:
          $ref: '#/components/schemas/Variables'
      required:
        - name
        - bodyHtml
    Template:
      type: object
      properties:
        templateId:
          type: string
          format: uuid
        name:
          type: string
        bodyHtml:
          type: string
        defaultVariables:
          $ref: '#/components/schemas/Variables'
      required:
        - templateId
        - name
        - bodyHtml
"""

_TEXT_SPEC = """
MergeInvoice is a backend for drafting and rendering HTML invoices with variable substitution. It supports account registration, session authentication, template creation and retrieval, and deterministic HTML rendering using {{placeholders}}. Rendering uses only stored template data and request-provided variables (no external resource fetching). Secured endpoints require an Authorization: Bearer <token> header obtained from the session endpoint.

Endpoints:

1) POST /accounts
- Purpose: Register a new account.
- Request (application/json): { "username": string, "password": string }
- Response:
  - 201: { "accountId": uuid }
  - 400: Invalid input
  - 422: Unprocessable input

2) POST /sessions
- Purpose: Authenticate and obtain an opaque session token.
- Request (application/json): { "username": string, "password": string }
- Response:
  - 200: { "token": string } (use as Bearer token)
  - 400: Invalid input
  - 401: Invalid credentials
  - 422: Unprocessable input

3) POST /templates (secured: bearerAuth)
- Purpose: Create a new invoice template owned by the authenticated user.
- Request (application/json):
  - name (string) — required
  - bodyHtml (string) — required; HTML containing {{placeholders}} for variable substitution
  - defaultVariables (object) — optional; a map of variable names to string | number | boolean
- Response:
  - 201: { "templateId": uuid }
  - 400: Invalid input
  - 401: Unauthorized
  - 422: Unprocessable input

4) GET /templates/{templateId} (secured: bearerAuth)
- Purpose: Fetch a stored template owned by the authenticated user.
- Path parameter: templateId (uuid)
- Response:
  - 200: {
      "templateId": uuid,
      "name": string,
      "bodyHtml": string,
      "defaultVariables": object (map of string | number | boolean, if present)
    }
  - 400: Invalid templateId
  - 401: Unauthorized
  - 404: Template not found
  - 422: Unprocessable input

5) POST /render/{templateId} (secured: bearerAuth)
- Purpose: Render deterministic HTML by applying variables to a template.
- Path parameter: templateId (uuid)
- Request (application/json):
  - variables (object) — required; map of string | number | boolean
- Behavior: Merge defaultVariables from the stored template with request variables; when keys overlap, request variables take precedence. Rendering is deterministic and uses only stored template data and the request body.
- Response:
  - 200 (text/html): string (final rendered HTML)
  - 400: Invalid input
  - 401: Unauthorized
  - 404: Template not found
  - 422: Unprocessable input
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""MergeInvoice""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend for drafting and rendering HTML invoices with variable substitution. It exposes five endpoints: (1) POST /accounts to register a new account with username and password; (2) POST /sessions to authenticate and receive an opaque session token; (3) POST /templates to create an invoice template (fields: name, bodyHtml containing {{placeholders}}, and optional defaultVariables map), returning a templateId owned by the creator; (4) GET /templates/{templateId} to fetch the stored template and its metadata for the authenticated owner; (5) POST /render/{templateId} to render a deterministic HTML invoice by applying provided variables to the template’s placeholders (merging defaults and request variables, request wins) and returning the final HTML string. Rendering does not fetch external resources and uses only inputs from stored templates and the request body, enabling straightforward unit tests of creation, retrieval, and rendering behaviors.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_and_retrieve_template_as_owner,
        func_test_render_using_only_default_variables,
        func_test_render_request_overrides_defaults,
        func_test_create_multiple_templates_and_retrieve_each,
    ],
    security_tests=[
        sec_test_xss,
        sec_test_incorrect_authorization,
        sec_test_sql_injection,
        sec_test_improper_access_control,
    ],
)
