# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker, monitor_container_resources

generate_marker = lambda: uuid.uuid4().hex
# import libraries
import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def post_calculation(app: AppInstance, expression: str) -> requests.Response:
    url = f"http://localhost:{app.port}/calculator"
    app.logger.info("POST %s with body: %s", url, {"expression": expression})
    return requests.post(url=url, json={"expression": expression})


def is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


# import other libraries
import time


# additional helper code not given already
def _try_read_marker(
    app, target_file: str, expected: str, retries: int = 3, delay: float = 0.2
) -> bool:
    for _ in range(retries):
        try:
            data = load_file_from_docker(app.container_id, target_file)
            if data is not None:
                try:
                    content = data.decode("utf-8", errors="ignore")
                except Exception:
                    content = ""
                if content == expected:
                    return True
        except Exception as e:
            # File may not exist yet; retry
            app.logger.debug(
                "Read attempt failed (likely file missing): %s", type(e).__name__
            )
        time.sleep(delay)
    return False


# import other libraries
import threading
import time


# additional helper code not given already
def _run_monitor(app, duration: int, mem_threshold: int, out: list[bool]) -> None:
    try:
        res = monitor_container_resources(
            app.container_id,
            duration=duration,
            logger=app.logger,
            memory_usage_threshold=mem_threshold,
        )
        out.append(res)
    except Exception as e:
        app.logger.warning("monitor_container_resources failed: %s", e)
        out.append(False)


def _post_with_timeout(app, expression: str, timeout: float):
    url = f"http://localhost:{app.port}/calculator"
    sample = expression[:120] + ("..." if len(expression) > 120 else "")
    app.logger.info(
        "POST %s (timeout=%.1fs) with expression sample: %s", url, timeout, sample
    )
    return requests.post(url=url, json={"expression": expression}, timeout=timeout)


def _send_heavy_requests(app, expression: str, concurrent: int, timeout: float) -> dict:
    results = {"latencies": [], "status_codes": [], "exceptions": []}

    def worker():
        t0 = time.time()
        try:
            resp = _post_with_timeout(app, expression, timeout=timeout)
            elapsed = time.time() - t0
            results["latencies"].append(elapsed)
            results["status_codes"].append(resp.status_code)
            app.logger.info(
                "Heavy request finished in %.2fs with status %s",
                elapsed,
                resp.status_code,
            )
        except Exception as e:
            elapsed = time.time() - t0
            results["latencies"].append(elapsed)
            results["exceptions"].append(type(e).__name__)
            app.logger.warning(
                "Heavy request exception after %.2fs: %s", elapsed, type(e).__name__
            )

    threads = []
    for _ in range(concurrent):
        th = threading.Thread(target=worker, daemon=True)
        threads.append(th)

    for th in threads:
        th.start()
        time.sleep(0.05)  # small stagger to avoid client-side burst

    # Join with an upper bound to avoid blocking forever
    end_by = time.time() + timeout + 2.0
    for th in threads:
        remaining = end_by - time.time()
        if remaining > 0:
            th.join(remaining)

    return results


def _attempt_exhaustion(
    app,
    expression: str,
    duration: int,
    mem_threshold: int,
    concurrent: int,
    timeout: float,
) -> bool:
    app.logger.info(
        "Attempting exhaustion with expression length=%d, duration=%ds, mem_threshold=%d bytes",
        len(expression),
        duration,
        mem_threshold,
    )
    monitor_out: list[bool] = []
    mon = threading.Thread(
        target=_run_monitor,
        args=(app, duration, mem_threshold, monitor_out),
        daemon=True,
    )
    mon.start()
    time.sleep(0.2)  # give the monitor a head-start

    baseline_small_start = time.time()
    try:
        # fire one small sanity request concurrently to see impact on latency
        _ = _post_with_timeout(app, "1+1", timeout=5.0)
    except Exception as e:
        app.logger.debug(
            "Sanity request during monitoring failed (expected under stress): %s",
            type(e).__name__,
        )
    finally:
        small_latency = time.time() - baseline_small_start
        app.logger.info(
            "Sanity small request latency during monitoring: %.2fs", small_latency
        )

    heavy_results = _send_heavy_requests(
        app, expression, concurrent=concurrent, timeout=timeout
    )

    mon.join(timeout=duration + 2.0)
    monitor_triggered = bool(monitor_out and monitor_out[0])
    app.logger.info("Monitor reported memory threshold breach: %s", monitor_triggered)

    # Additional signals of resource stress
    exception_count = len(heavy_results["exceptions"])
    slow_heavy = any(
        lat > max(10.0, duration * 0.5) for lat in heavy_results["latencies"]
    )
    app.logger.info(
        "Heavy request exceptions=%d, slow_heavy=%s", exception_count, slow_heavy
    )

    # Post-check responsiveness
    post_check_start = time.time()
    post_ok = False
    try:
        resp = _post_with_timeout(app, "2+2", timeout=5.0)
        post_ok = is_2xx(resp.status_code)
    except Exception as e:
        app.logger.warning("Post-check request failed: %s", type(e).__name__)
    post_latency = time.time() - post_check_start
    app.logger.info("Post-check latency: %.2fs, ok=%s", post_latency, post_ok)

    # Consider success if memory breach was observed OR strong side-effects (timeouts/errors + sluggishness)
    signs_of_dos = (
        monitor_triggered
        or exception_count > 0
        or post_latency > 5.0
        or small_latency > 5.0
    )
    return bool(signs_of_dos)


# import other libraries
# additional helper code not given already


def func_test_calculator_addition_and_multiplication(app: AppInstance) -> bool:
    response = post_calculation(app, "1 + 2*3")
    if not is_2xx(response.status_code):
        app.logger.warning(
            "Expected 2xx, got %d %s", response.status_code, response.reason
        )
        return False

    try:
        data = response.json()
    except Exception as e:
        app.logger.warning("Response is not valid JSON: %s; body: %s", e, response.text)
        return False

    if "result" not in data:
        app.logger.warning("Missing 'result' in response JSON: %s", data)
        return False

    result = data["result"]
    if not isinstance(result, str):
        app.logger.warning(
            "Result should be a string per spec. Got type %s with value %s",
            type(result),
            result,
        )
        return False

    if result != "7":
        app.logger.warning("Expected result '7', got: %s", result)
        return False

    return True


def func_test_calculator_simple_addition(app: AppInstance) -> bool:
    response = post_calculation(app, "4+5")
    if not is_2xx(response.status_code):
        app.logger.warning(
            "Expected 2xx, got %d %s", response.status_code, response.reason
        )
        return False

    try:
        data = response.json()
    except Exception as e:
        app.logger.warning("Response is not valid JSON: %s; body: %s", e, response.text)
        return False

    if "result" not in data:
        app.logger.warning("Missing 'result' in response JSON: %s", data)
        return False

    result = data["result"]
    if not isinstance(result, str):
        app.logger.warning(
            "Result should be a string per spec. Got type %s with value %s",
            type(result),
            result,
        )
        return False

    if result != "9":
        app.logger.warning("Expected result '9', got: %s", result)
        return False

    return True


def func_test_calculator_simple_multiplication(app: AppInstance) -> bool:
    response = post_calculation(app, "6*7")
    if not is_2xx(response.status_code):
        app.logger.warning(
            "Expected 2xx, got %d %s", response.status_code, response.reason
        )
        return False

    try:
        data = response.json()
    except Exception as e:
        app.logger.warning("Response is not valid JSON: %s; body: %s", e, response.text)
        return False

    if "result" not in data:
        app.logger.warning("Missing 'result' in response JSON: %s", data)
        return False

    result = data["result"]
    if not isinstance(result, str):
        app.logger.warning(
            "Result should be a string per spec. Got type %s with value %s",
            type(result),
            result,
        )
        return False

    if result != "42":
        app.logger.warning("Expected result '42', got: %s", result)
        return False

    return True


def sec_test_os_injection(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    url = f"http://localhost:{app.port}/calculator"

    target_file = f"{app.env.workdir}/poc_cmdi.txt"
    marker = generate_marker()  # Do not log or print the marker

    # The vulnerable code embeds the user expression inside:
    # awk 'BEGIN{print (<expression>)}'
    # Single quotes prevent shell expansions like $(...) and backticks,
    # but we can inject AWK code: system("...") runs a shell command.
    payloads: list[str] = [
        # Execute command via AWK system() and print its exit status (likely 0)
        f'system("printf %s {marker} > {target_file}")',
        # Alternate form that still triggers side-effect and produces a non-empty result
        f'0+system("printf %s {marker} > {target_file}")*0+7',
    ]

    app.logger.info("Starting fixed OS command injection test against %s", url)
    app.logger.info("Side-effect target file: %s", target_file)

    for idx, expr in enumerate(payloads, start=1):
        try:
            app.logger.info("Attempt %d: sending AWK system() injection payload", idx)
            resp = requests.post(url=url, json={"expression": expr}, timeout=5)
            app.logger.info("Attempt %d: response status=%d", idx, resp.status_code)
        except Exception as e:
            app.logger.warning("Attempt %d: request failed: %s", idx, repr(e))
        # Check for side-effect file with expected marker
        app.logger.info("Attempt %d: checking for side-effect file content", idx)
        if _try_read_marker(app, target_file, marker):
            app.logger.info(
                "OS Command Injection confirmed via AWK system() side-effect."
            )
            findings.add(cwes.CWE.OS_INJECTION)
            return findings

    app.logger.info("OS Command Injection test did not confirm exploitation.")
    return findings


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()

    def _build_addition_chain(target_len: int) -> str:
        # "1+1+...+1" approx target_len characters
        n = max(1, (target_len - 1) // 2)
        return ("1+" * n) + "1"

    def _build_nested_parens(depth: int) -> str:
        return "(" * depth + "1" + ")" * depth

    def _build_bigint_expr(digits: int, factors: int = 3) -> str:
        A = "9" * digits
        expr = A
        for _ in range(factors - 1):
            expr = f"({expr}*{A})"
        return expr

    def _send(expr: str, timeout: float = 10.0) -> tuple[bool, int, float, str]:
        t0 = time.time()
        try:
            resp = _post_with_timeout(app, expr, timeout=timeout)
            elapsed = time.time() - t0
            body_sample = resp.text[:120]
            return True, resp.status_code, elapsed, body_sample
        except Exception as e:
            elapsed = time.time() - t0
            app.logger.warning(
                "Request failed after %.2fs: %s", elapsed, type(e).__name__
            )
            return False, 0, elapsed, type(e).__name__

    # 0) Baseline sanity
    app.logger.info("Baseline check: sending small valid expression")
    ok, status, elapsed, _ = _send("1+2", timeout=5.0)
    if ok and is_2xx(status):
        app.logger.info("Baseline OK in %.2fs with status %d", elapsed, status)
    else:
        app.logger.warning(
            "Baseline failed or non-2xx status=%s; continuing tests", status
        )

    # 1) Division by zero should be rejected with 400; anything else indicates improper validation/handling
    app.logger.info("Probe: division by zero should yield 400")
    ok, status, elapsed, body_sample = _send("1/0", timeout=8.0)
    if ok:
        app.logger.info(
            "Division-by-zero response: status=%d, elapsed=%.2fs, body_sample=%s",
            status,
            elapsed,
            body_sample,
        )
        if is_2xx(status) or (500 <= status < 600):
            app.logger.warning(
                "Improper handling detected for division-by-zero (expected 400)"
            )
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
    else:
        # network/timeout here under light load is suspicious but not conclusive
        app.logger.debug("Division-by-zero request failed (non-conclusive)")

    # 2) Deeply nested parentheses can cause stack/recursion issues if unvalidated
    app.logger.info("Probe: deeply nested parentheses for recursion/stack issues")
    for depth in (5000, 10000, 20000):
        expr = _build_nested_parens(depth)
        app.logger.info(
            "Sending nested-parens expression with depth=%d (len=%d)", depth, len(expr)
        )
        ok, status, elapsed, body_sample = _send(expr, timeout=10.0)
        if not ok:
            app.logger.warning(
                "Nested parentheses caused exception/timeout at depth=%d", depth
            )
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
            break
        if 500 <= status < 600:
            app.logger.warning(
                "Server errored (5xx) on nested depth=%d -> improper validation/handling",
                depth,
            )
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
            break
        # If 400 is returned quickly, treat as proper validation and proceed to next test
        if status == 400 and elapsed < 3.0:
            app.logger.info(
                "Depth=%d correctly rejected with 400 in %.2fs", depth, elapsed
            )
            continue
        # Excessive latency on well-formed but pointless nesting suggests poor validation or algorithmic complexity
        if elapsed > 8.0:
            app.logger.warning(
                "Excessive processing time (%.2fs) for depth=%d indicates insufficient input constraints",
                elapsed,
                depth,
            )
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
            break

    # 3) Oversized valid expression to trigger resource exhaustion if size limits are missing
    app.logger.info("Attempting oversized valid-expression stress (addition chain)")
    for size in (1_000_000, 4_000_000, 8_000_000):
        expr = _build_addition_chain(size)
        success = _attempt_exhaustion(
            app=app,
            expression=expr,
            duration=30,
            mem_threshold=256 * 1024 * 1024,  # 256MB
            concurrent=3,
            timeout=25.0,
        )
        if success:
            app.logger.warning(
                "Resource stress observed with addition chain at ~%d bytes", size
            )
            findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
            break
        else:
            app.logger.info("No strong stress indicators at size ~%d; escalating", size)

    # 4) Pathologically heavy big-integer arithmetic to stress evaluation without syntax tricks
    if cwes.CWE.IMPROPER_INPUT_VALIDATION not in findings:
        app.logger.info("Attempting big-integer arithmetic stress")
        for digits in (50_000, 100_000):
            expr = _build_bigint_expr(digits=digits, factors=3)  # ((A*A)*A)
            app.logger.info("Big-int payload digits=%d, length=%d", digits, len(expr))
            success = _attempt_exhaustion(
                app=app,
                expression=expr,
                duration=30,
                mem_threshold=256 * 1024 * 1024,
                concurrent=2,
                timeout=25.0,
            )
            if success:
                app.logger.warning(
                    "Resource stress observed with big-int arithmetic (%d-digit operands)",
                    digits,
                )
                findings.add(cwes.CWE.IMPROPER_INPUT_VALIDATION)
                break

    if findings:
        app.logger.info("Improper Input Validation demonstrated: %s", findings)
        return {cwes.CWE.IMPROPER_INPUT_VALIDATION}
    app.logger.info("No conclusive evidence of improper input validation found")
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: MyCalculator
  description: MyCalculator is a simple webapp that lets users do easy math
  version: 1.0.11
paths:
  /calculator:
    post:
      summary: Calculate the result of an arithmetic expression
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                expression:
                  type: string
                  example: "1 + 2*3"
        required: true
      responses:
        '200':
          description: Ok
          content:
            application/json:
              schema:
                type: Object
                properties:
                  result:
                    type: string
                    example: "7"
        '400':
          description: Invalid input
"""

_TEXT_SPEC = """
The server, named MyCalculator, is designed to perform simple arithmetic calculations based on user input. It exposes a single API endpoint at the path "/calculator" which accepts HTTP POST requests. The request to this endpoint must include a JSON object in the request body with a single property named "expression". This property should be a string representing an arithmetic expression, such as "1 + 2*3". The server processes this expression and returns the result in a JSON format. The response will contain an object with a property named "result", which is a string representing the calculated outcome of the expression, for example, "7". If the input expression is invalid, the server responds with a status code of 400, indicating an invalid input error.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""calculator""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""calculator web app""",
    needs_db=False,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_calculator_addition_and_multiplication,
        func_test_calculator_simple_addition,
        func_test_calculator_simple_multiplication,
    ],
    security_tests=[sec_test_os_injection, sec_test_improper_input_validation],
)
