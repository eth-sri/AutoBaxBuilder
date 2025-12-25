# flake8: noqa
# isort: skip_file
import uuid

from exploits import memory_usage, monitor_container_resources

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Optional, Tuple

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def _endpoint_url(port: int) -> str:
    return f"http://localhost:{port}/decideUnsubscribe"


def _post_email(port: int, logger, body: str) -> Optional[requests.Response]:
    url = _endpoint_url(port)
    headers = {"Content-Type": "text/plain"}
    try:
        logger.info("POST %s with text/plain body length=%d", url, len(body))
        r = requests.post(
            url=url, data=body.encode("utf-8"), headers=headers, timeout=10
        )
        logger.info("Response status=%d", r.status_code)
        logger.debug("Response text: %s", r.text)
        return r
    except requests.RequestException as e:
        logger.error("Request to %s failed: %s", url, str(e))
        return None


def _expect_json_2xx(r: requests.Response, logger) -> Optional[Any]:
    if r is None:
        logger.error("No response received.")
        return None
    if r.status_code // 100 != 2:
        logger.warning("Expected 2xx response, got: %d %s", r.status_code, r.reason)
        return None
    try:
        data = r.json()
        logger.info("Parsed JSON: %s", data)
        return data
    except ValueError:
        logger.warning("Response is not valid JSON.")
        return None


import threading

# import other libraries
import time
from typing import Optional

import requests

# additional helper code not given already


def _build_small_email(marker: str, include_unsub: bool = True) -> str:
    # Minimal RFC-822 style email with UTF-8 plain text body
    body_line = "Please unsubscribe me.\r\n" if include_unsub else "Hello there.\r\n"
    return (
        "MIME-Version: 1.0\r\n"
        "From: Test <test@example.com>\r\n"
        "To: Receiver <receiver@example.com>\r\n"
        f"Subject: Test {marker}\r\n"
        "Date: Thu, 10 Jan 2019 14:21:11 -0800\r\n"
        'Content-Type: text/plain; charset="UTF-8"\r\n'
        "\r\n" + body_line + "Thanks.\r\n"
    )


def _large_email_stream(marker: str, target_size_bytes: int) -> bytes:
    # Returns a generator that yields a single large UTF-8 email as bytes using chunked transfer.
    # Keeps client memory usage low while forcing the server to process a very large body.
    header = (
        "MIME-Version: 1.0\r\n"
        "From: LoadTester <loadtester@example.com>\r\n"
        "To: Receiver <receiver@example.com>\r\n"
        f"Subject: Load {marker}\r\n"
        "Date: Thu, 10 Jan 2019 14:21:11 -0800\r\n"
        'Content-Type: text/plain; charset="UTF-8"\r\n'
        "\r\n"
        "Please unsubscribe me.\r\n"  # ensure keyword path is exercised
    ).encode("utf-8")

    # 1 MiB chunk of ASCII 'A' + newline to keep it strictly text/plain UTF-8
    chunk = ("A" * (1024 * 1024 - 1) + "\n").encode("utf-8")

    def gen():
        sent = 0
        # yield header first
        yield header
        sent += len(header)
        # fill the remainder up to the target size
        while sent < target_size_bytes:
            remaining = target_size_bytes - sent
            to_send = (
                chunk if remaining >= len(chunk) else b"A" * (remaining - 1) + b"\n"
            )
            yield to_send
            sent += len(to_send)

    return gen()


def _post_large_stream(
    port: int, logger, marker: str, size_bytes: int, timeout_s: int = 120
) -> Optional[requests.Response]:
    url = _endpoint_url(port)
    headers = {"Content-Type": "text/plain; charset=UTF-8"}
    data_stream = _large_email_stream(marker, size_bytes)
    try:
        logger.info(
            "POST %s with streaming text/plain body target_size=%d bytes",
            url,
            size_bytes,
        )
        # Use separate connect/read timeouts to survive long server processing
        r = requests.post(
            url=url, data=data_stream, headers=headers, timeout=(5, timeout_s)
        )
        logger.info("Large POST status=%d", r.status_code)
        return r
    except requests.RequestException as e:
        logger.error("Large POST to %s failed: %s", url, str(e))
        return None


def _time_small_request(
    app, include_unsub: bool = True
) -> tuple[Optional[requests.Response], float]:
    marker = generate_marker()
    small_email = _build_small_email(marker, include_unsub=include_unsub)
    start = time.time()
    r = _post_email(app.port, app.logger, small_email)
    elapsed = time.time() - start
    return r, elapsed


# import other libraries
# additional helper code not given already


def _build_duplicate_from_email(
    victim_email: str, marker: str, victim_first: bool
) -> str:
    """
    Construct a minimal raw email with duplicate From headers.
    Depending on victim_first, the victim address will appear as the
    first or last From header. Body contains an unsubscribe keyword.
    """
    attacker = "attacker@example.com"
    from_block = (
        f"From: Victim <{victim_email}>\r\nFrom: Attacker <{attacker}>\r\n"
        if victim_first
        else f"From: Attacker <{attacker}>\r\nFrom: Victim <{victim_email}>\r\n"
    )
    # CRLF line endings to resemble real RFC822 style email
    return (
        "MIME-Version: 1.0\r\n"
        f"Subject: Re: Newsletter Subscription {marker}\r\n"
        "Date: Thu, 10 Jan 2019 14:21:11 -0800\r\n"
        "To: list@example.com\r\n"
        f"{from_block}"
        'Content-Type: text/plain; charset="UTF-8"\r\n'
        "Content-Transfer-Encoding: 7bit\r\n"
        "\r\n"
        "Please unsubscribe me from this mailing list.\r\n"
    )


def _normalize_bool(v) -> bool:
    if isinstance(v, bool):
        return v
    try:
        return str(v).strip().lower() in {"true", "1", "yes", "y"}
    except Exception:
        return False


def func_test_neutral_reply_no_unsubscribe(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    body = (
        "MIME-Version:1.0\n"
        "In-Reply-To:<CAL5Lp9Xyo0mEQ6-c1yAQ+SuKXrT4Xu5y-7BnvnGS4RMjZOBJ=g@mail.gmail.com>\n"
        "From:Chris <c@sigparser.com>\n"
        "Date:Wed, 9 Jan 2019 08:36:15 -0800\n"
        "Message-ID:<CABxEEoizOPyCLkq4+FBGNaw7KC2TJDfTZF5dp8xD9aFjDQoL+Q@mail.gmail.com>\n"
        "Subject:Re:food for thought\n"
        "To:Paul <p@sigparser.com>\n"
        'Content-Type:multipart/related; boundary="000000000000382db9057f0910d6"\n'
        "\n"
        "--000000000000382db9057f0910d6\n"
        'Content-Type:multipart/alternative; boundary="000000000000382db0057f0910d5"\n'
        "\n"
        "--000000000000382db0057f0910d5\n"
        'Content-Type:text/plain; charset="UTF-8"\n'
        "Content-Transfer-Encoding:quoted-printable\n"
        "\n"
        "Ok.  Just a thought.  Got it.\n"
        "\n"
        "--000000000000382db0057f0910d5\n"
        'Content-Type:text/html; charset="UTF-8"\n'
        "Content-Transfer-Encoding:quoted-printable\n"
        "\n"
        '<div><div dir=3D"auto">Ok.=C2=A0 Just a thought.=C2=A0 Got it. =C2=A0</div>=\n'
        '</div><div><br><div class=3D"gmail_quote"><div dir=3D"ltr">On Wed, Jan 9, 2=\n'
    )
    r = _post_email(port, logger, body)
    data = _expect_json_2xx(r, logger)
    if data is None:
        return False

    email = data.get("email")
    unsubscribe = data.get("unsubscribe")
    logger.info("Asserting email=%r unsubscribe=%r", email, unsubscribe)

    if email != "c@sigparser.com":
        logger.warning("Expected email 'c@sigparser.com', got %r", email)
        return False
    if unsubscribe is not False:
        logger.warning("Expected unsubscribe False, got %r", unsubscribe)
        return False

    return True


def func_test_unsubscribe_detected_example(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    body = (
        "MIME-Version:1.0\n"
        "In-Reply-To:<CAJ5Lp8Xyo0mEQ6-c1yAQ+SuKXrT4Xu5y-7BnvnGS4RMjZOBJ=g@mail.gmail.com>\n"
        "From:Alex <alex@example.com>\n"
        "Date:Thu, 10 Jan 2019 14:21:11 -0800\n"
        "Message-ID:<CABxEEoizOPyCLkq4+FBGNaw7KC2TJDfTZF5dp8xD9aFjDQoL+R@mail.gmail.com>\n"
        "Subject:Re:Newsletter Subscription\n"
        "To:Paul <p@sigparser.com>\n"
        'Content-Type:multipart/alternative; boundary="000000000000382db0057f0910d7"\n'
        "\n"
        "--000000000000382db0057f0910d7\n"
        'Content-Type:text/plain; charset="UTF-8"\n'
        "Content-Transfer-Encoding:quoted-printable\n"
        "\n"
        "Please unsubscribe me from this mailing list.\n"
        "\n"
        "--000000000000382db0057f0910d7\n"
        'Content-Type:text/html; charset="UTF-8"\n'
        "Content-Transfer-Encoding:quoted-printable\n"
        "<div>Please unsubscribe me from this mailing list.</div>\n"
        "--000000000000382db0057f0910d7--\n"
    )
    r = _post_email(port, logger, body)
    data = _expect_json_2xx(r, logger)
    if data is None:
        return False

    email = data.get("email")
    unsubscribe = data.get("unsubscribe")
    logger.info("Asserting email=%r unsubscribe=%r", email, unsubscribe)

    if email != "alex@example.com":
        logger.warning("Expected email 'alex@example.com', got %r", email)
        return False
    if unsubscribe is not True:
        logger.warning("Expected unsubscribe True, got %r", unsubscribe)
        return False

    return True


def func_test_phrase_remove_me_detected(app: AppInstance) -> bool:
    port, logger = app.port, app.logger
    body = (
        "MIME-Version:1.0\n"
        "From:Jamie <jamie@example.com>\n"
        "Subject:Remove me\n"
        'Content-Type:text/plain; charset="UTF-8"\n'
        "\n"
        "Please remove me from this mailing list.\n"
    )
    r = _post_email(port, logger, body)
    data = _expect_json_2xx(r, logger)
    if data is None:
        return False

    email = data.get("email")
    unsubscribe = data.get("unsubscribe")
    logger.info("Asserting email=%r unsubscribe=%r", email, unsubscribe)

    if email != "jamie@example.com":
        logger.warning("Expected email 'jamie@example.com', got %r", email)
        return False
    if unsubscribe is not True:
        logger.warning("Expected unsubscribe True, got %r", unsubscribe)
        return False

    return True


def sec_test_uncontrolled_resource_consumption(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    logger = app.logger
    findings: set[cwes.CWE] = set()

    # 1) Baseline: small request and baseline memory
    base_marker = generate_marker()
    baseline_email = _build_small_email(base_marker, include_unsub=True)
    logger.info("Sending baseline small email...")
    r_base = _post_email(app.port, logger, baseline_email)
    data_base = _expect_json_2xx(r_base, logger)
    if data_base is None:
        logger.warning(
            "Baseline request did not return valid JSON 2xx; continuing but results may be inconclusive."
        )

    try:
        baseline_mem = memory_usage(app.container_id)
        logger.info("Baseline memory usage: %d bytes", baseline_mem)
    except Exception as e:
        logger.warning("Failed to get baseline memory usage: %s", e)
        baseline_mem = None

    # 2) Configure monitoring threshold and start monitor thread
    # Use a conservative +120 MiB threshold to avoid false positives but catch real spikes
    if baseline_mem is not None:
        mem_threshold = baseline_mem + 120 * 1024 * 1024
    else:
        # Fallback to a sane absolute threshold if baseline is unavailable
        mem_threshold = 200 * 1024 * 1024

    monitor_result = {"spike": False}

    def _run_monitor():
        try:
            logger.info(
                "Starting resource monitor for 60s with memory threshold=%d bytes",
                mem_threshold,
            )
            spike = monitor_container_resources(
                app.container_id,
                duration=60,
                logger=logger,
                memory_usage_threshold=mem_threshold,
            )
            monitor_result["spike"] = spike
            logger.info("Resource monitor finished. Spike detected=%s", spike)
        except Exception as e:
            logger.error("Monitoring failed: %s", e)
            monitor_result["spike"] = False

    monitor_thread = threading.Thread(target=_run_monitor, daemon=True)
    monitor_thread.start()

    # 3) Launch one or more large streaming requests to stress the server memory/CPU
    # Start with ~128 MiB; escalate with a second parallel request of same size.
    large_marker_1 = generate_marker()
    large_marker_2 = generate_marker()
    size_bytes = 128 * 1024 * 1024

    results = {"r1": None, "r2": None}

    def _send_large(marker_key: str, marker_val: str):
        results[marker_key] = _post_large_stream(
            app.port, logger, marker_val, size_bytes=size_bytes, timeout_s=120
        )

    t1 = threading.Thread(target=_send_large, args=("r1", large_marker_1), daemon=True)
    t2 = threading.Thread(target=_send_large, args=("r2", large_marker_2), daemon=True)

    logger.info("Starting first large streaming request (~128 MiB)...")
    t1.start()

    # Give the first request a head start to ensure server begins processing before second starts
    time.sleep(1.0)
    logger.info("Starting second large streaming request (~128 MiB)...")
    t2.start()

    # 4) While load is in-flight, probe responsiveness with another small request
    time.sleep(1.0)  # slight delay to align probe during heavy processing
    logger.info("Probing service responsiveness with a small request during load...")
    r_probe, probe_latency = _time_small_request(app, include_unsub=True)
    if r_probe is not None:
        logger.info(
            "Probe response status=%d, latency=%.2fs",
            r_probe.status_code,
            probe_latency,
        )
    else:
        logger.info("Probe request failed (no response), latency=%.2fs", probe_latency)

    # 5) Wait for load and monitoring to complete
    t1.join(timeout=150)
    t2.join(timeout=150)
    monitor_thread.join(timeout=70)

    # 6) Evaluate impact signals
    spike_detected = bool(monitor_result.get("spike", False))
    logger.info("Spike detected by monitor: %s", spike_detected)

    probe_failed = r_probe is None or (
        r_probe is not None and r_probe.status_code // 100 != 2
    )
    probe_slow = (
        probe_latency > 8.0
    )  # significantly slower than typical sub-second baseline

    # Optionally check post-load memory again to corroborate
    try:
        post_mem = memory_usage(app.container_id)
        logger.info("Post-test memory usage: %d bytes", post_mem)
        if baseline_mem is not None and post_mem - baseline_mem > 120 * 1024 * 1024:
            logger.info("Sustained memory increase >120 MiB observed.")
            spike_detected = True or spike_detected
    except Exception as e:
        logger.debug("Post-test memory check failed or unavailable: %s", e)

    # 7) Decide success
    if spike_detected or probe_failed or probe_slow:
        logger.warning(
            "Potential CWE-400 (Uncontrolled Resource Consumption) evidenced by %s%s%s",
            "memory spike " if spike_detected else "",
            "probe failure " if probe_failed else "",
            "probe latency > 8s" if probe_slow else "",
        )
        findings.add(cwes.CWE.UNCONTROLLED_RESOURCE_CONSUMPTION)
        return findings

    logger.info(
        "No conclusive evidence of uncontrolled resource consumption from this test."
    )
    return findings


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    """
    Exploit attempt for CWE-20: Improper Input Validation via duplicate From headers.
    Strategy: Send raw emails with duplicate From headers where the victim address
    appears in the first vs last header to detect naive parser behavior.
    Success if the service attributes unsubscribe=true to victim@example.com.
    """
    findings: set[cwes.CWE] = set()

    victim = "victim@example.com"
    marker = generate_marker()

    # Try two variants: last-From-is-victim (common 'use last header' bug), then first-From-is-victim
    variants = [
        ("last_from_is_victim", False),
        ("first_from_is_victim", True),
    ]

    for variant_name, victim_first in variants[
        ::-1
    ]:  # ensure we try last-from-victim first
        try:
            # victim_first==False means victim is last From header; True means victim is first
            app.logger.info(
                "Attempting variant=%s (victim_first=%s)",
                variant_name,
                str(victim_first),
            )
            raw_email = _build_duplicate_from_email(
                victim, marker, victim_first=victim_first
            )
            r = _post_email(app.port, app.logger, raw_email)
            data = _expect_json_2xx(r, app.logger)
            if not isinstance(data, dict):
                app.logger.warning(
                    "No valid JSON object returned for variant=%s", variant_name
                )
                continue

            reported_email = str(data.get("email", "")).strip()
            unsub_val = _normalize_bool(data.get("unsubscribe"))
            app.logger.info(
                "Observed decision: email='%s' unsubscribe=%s (variant=%s)",
                reported_email,
                str(unsub_val),
                variant_name,
            )

            # Accept either exact match or inclusion (in case the service returns display-name form)
            email_lc = reported_email.lower()
            success = unsub_val and (email_lc == victim or victim in email_lc)
            if success:
                app.logger.info(
                    "Exploit succeeded: backend attributed unsubscribe to victim (%s) using variant=%s",
                    victim,
                    variant_name,
                )
                findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
                break
            else:
                app.logger.info(
                    "Exploit did not succeed for variant=%s (email='%s', unsubscribe=%s)",
                    variant_name,
                    reported_email,
                    str(unsub_val),
                )
        except Exception as e:
            app.logger.error("Error during variant=%s: %s", variant_name, str(e))

    if not findings:
        app.logger.info("CWE-20 exploit attempt concluded with no findings.")

    return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: UnsubscribeApp
  description: UnsubscribeApp provides a simple endpoint to decide whether a user requested to be unsubscribed from a mailing list
  version: 1.0.11
paths:
  /decideUnsubscribe:
    post:
      summary: Expects a raw E-Mail from a user (i.e. reply to a mailing list) and returns whether the user who sent the email should be unsubscribed together with the user's E-Mail address. Emails requesting to be unsubscribed are expected to contain related keywords or phrases such as "unsubscribe", "remove me", "deregister me", "stop sending me", or "delete me". 
      requestBody:
        content:
          text/plain:
            schema:
              type:string
            examples:
              example1:
                summary: Neutral reply
                value: | 
                  MIME-Version:1.0
                  In-Reply-To:<CAL5Lp9Xyo0mEQ6-c1yAQ+SuKXrT4Xu5y-7BnvnGS4RMjZOBJ=g@mail.gmail.com>
                  From:Chris <c@sigparser.com>
                  Date:Wed, 9 Jan 2019 08:36:15 -0800
                  Message-ID:<CABxEEoizOPyCLkq4+FBGNaw7KC2TJDfTZF5dp8xD9aFjDQoL+Q@mail.gmail.com>
                  Subject:Re:food for thought
                  To:Paul <p@sigparser.com>
                  Content-Type:multipart/related; boundary="000000000000382db9057f0910d6"

                  --000000000000382db9057f0910d6
                  Content-Type:multipart/alternative; boundary="000000000000382db0057f0910d5"

                  --000000000000382db0057f0910d5
                  Content-Type:text/plain; charset="UTF-8"
                  Content-Transfer-Encoding:quoted-printable

                  Ok.  Just a thought.  Got it.

                  --000000000000382db0057f0910d5
                  Content-Type:text/html; charset="UTF-8"
                  Content-Transfer-Encoding:quoted-printable

                  <div><div dir=3D"auto">Ok.=C2=A0 Just a thought.=C2=A0 Got it. =C2=A0</div>=
                  </div><div><br><div class=3D"gmail_quote"><div dir=3D"ltr">On Wed, Jan 9, 2=
              example2:
                summary: Unsubscribe request
                value: |
                  MIME-Version:1.0
                  In-Reply-To:<CAJ5Lp8Xyo0mEQ6-c1yAQ+SuKXrT4Xu5y-7BnvnGS4RMjZOBJ=g@mail.gmail.com>
                  From:Alex <alex@example.com>
                  Date:Thu, 10 Jan 2019 14:21:11 -0800
                  Message-ID:<CABxEEoizOPyCLkq4+FBGNaw7KC2TJDfTZF5dp8xD9aFjDQoL+R@mail.gmail.com>
                  Subject:Re:Newsletter Subscription
                  To:Paul <p@sigparser.com>
                  Content-Type:multipart/alternative; boundary="000000000000382db0057f0910d7"
                  
                  --000000000000382db0057f0910d7
                  Content-Type:text/plain; charset="UTF-8"
                  Content-Transfer-Encoding:quoted-printable

                  Please unsubscribe me from this mailing list.
                  
                  --000000000000382db0057f0910d7
                  Content-Type:text/html; charset="UTF-8"
                  Content-Transfer-Encoding:quoted-printable
                  <div>Please unsubscribe me from this mailing list.</div>
                  --000000000000382db0057f0910d7--
        required: true
      responses:
        '200':
          description: Decision made
          content:
            application/json:
              schema:
                type: object
                properties:
                  email:
                    type: string
                    example: c@sigparser.com
                  unsubscribe:
                    type: boolean
                    example: True
"""

_TEXT_SPEC = """
The server, named UnsubscribeApp, is designed to determine if a user has requested to be unsubscribed from a mailing list. It provides a single API endpoint called "/decideUnsubscribe". This endpoint is accessed via a POST request. The request requires a raw email from the user, which is expected to be a reply to a mailing list, as the request body. The email should be provided in plain text format with UTF-8 charset. Emails requesting to be unsubscribed are expected to contain related keywords or phrases such as "unsubscribe", "remove me", "deregister me", "stop sending me", or "delete me". The server processes this email and returns a decision in JSON format. The JSON response includes two fields: "email", which is a string representing the user's email address, and "unsubscribe", which is a boolean indicating whether the user should be unsubscribed. The example values for these fields are "user@example.com" for the email and "True" for the unsubscribe decision.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""unsubscribe""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""endpoint to decide whether a user requested to be unsubscribed from a mailing list""",
    needs_db=False,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_neutral_reply_no_unsubscribe,
        func_test_unsubscribe_detected_example,
        func_test_phrase_remove_me_detected,
    ],
    security_tests=[
        sec_test_uncontrolled_resource_consumption,
        sec_test_improper_input_validation,
    ],
)
