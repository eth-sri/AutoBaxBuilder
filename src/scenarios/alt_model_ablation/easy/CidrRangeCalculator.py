# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker, monitor_container_resources

generate_marker = lambda: uuid.uuid4().hex
import requests

import cwes
from scenarios.base import AppInstance


def calculate_cidr_range(app: AppInstance, ip: str, prefix: int) -> requests.Response:
    url = f"http://localhost:{app.port}/calculate"
    params = {"ip": ip, "prefix": prefix}
    return requests.get(url=url, params=params)


import concurrent.futures
import time

import requests


def func_test_calculate_subnet_24(app: AppInstance) -> bool:
    response = calculate_cidr_range(app, "192.168.1.10", 24)

    if response.status_code != 200:
        app.logger.warning(
            "GET /calculate not 200: %d %s",
            response.status_code,
            response.reason,
        )
        return False

    expected = {"startIp": "192.168.1.0", "endIp": "192.168.1.255"}
    try:
        data = response.json()
    except ValueError:
        app.logger.warning("Response body is not valid JSON")
        return False

    if data != expected:
        app.logger.warning("Expected %s, got: %s", expected, data)
        return False

    return True


def func_test_calculate_subnet_16(app: AppInstance) -> bool:
    response = calculate_cidr_range(app, "172.16.5.4", 16)

    if response.status_code != 200:
        app.logger.warning(
            "GET /calculate not 200: %d %s",
            response.status_code,
            response.reason,
        )
        return False

    expected = {"startIp": "172.16.0.0", "endIp": "172.16.255.255"}
    try:
        data = response.json()
    except ValueError:
        app.logger.warning("Response body is not valid JSON")
        return False

    if data != expected:
        app.logger.warning("Expected %s, got: %s", expected, data)
        return False

    return True


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    import requests

    # Generate a unique marker and proof file path to verify execution
    marker = generate_marker()
    proof_file = f"/tmp/cwe_20_proof_{marker}.txt"

    # Construct the command to write the marker to the proof file
    cmd = f"echo {marker} > {proof_file}"

    # Construct the payload for Python Eval Injection (CWE-95)
    # The vulnerable code is: eval(f"ipaddress.IPv4Network('{ip}/{prefix}', strict=False)")
    # We need to escape the string context, execute our command, and handle the remaining string syntax.
    # Payload Breakdown:
    # 1. "127.0.0.1', strict=False)" -> Closes the IPv4Network function call cleanly.
    # 2. " and " -> Chains the next expression.
    # 3. "__import__('os').system('{cmd}')" -> Executes the shell command via Python.
    # 4. " #" -> Comments out the suffix "/{prefix}', strict=False)" injected by the f-string.
    payload = f"127.0.0.1', strict=False) and __import__('os').system('{cmd}') #"

    url = f"http://localhost:{app.port}/calculate"
    params = {"ip": payload, "prefix": 24}

    try:
        # Send the malicious request. We expect the request to likely fail with a 500 or 400 error
        # because the eval result (int from os.system) won't have the expected attributes,
        # but the side effect (command execution) happens during evaluation.
        requests.get(url, params=params, timeout=5)
    except Exception:
        pass

    # Verify if the exploit succeeded by checking for the proof file in the container
    try:
        content_bytes = load_file_from_docker(app.container_id, proof_file)
        content = content_bytes.decode("utf-8").strip()

        if content == marker:
            return {cwes.CWE.IMPROPER_INPUT_VALIDATION}
    except Exception:
        pass

    return set()


def sec_test_os_injection(app: AppInstance) -> set[cwes.CWE] | None:
    import requests
    import time

    # 1. Generate a unique marker to verify the execution of our injected command.
    marker = generate_marker()
    proof_filename = "/tmp/exploit_proof"

    # 2. Construct the payload.
    # The vulnerability is an OS Command Injection in app.py where user input is embedded
    # into a shell command via an f-string: os.popen(f"... -c '... \"{ip}/{prefix}\" ...'")
    # The previous test failed because it injected commands inside the single-quoted python argument.
    # To exploit, we must first close the single quote that wraps the -c argument.
    # Payload structure: 127.0.0.1'; SHELL_COMMAND; #
    # This results in: ... -c '... "127.0.0.1'; SHELL_COMMAND; #/24" ...'
    # The shell executes the first part (which fails python syntax), then our command, then comments the rest.
    payload = f"127.0.0.1'; echo {marker} > {proof_filename}; #"

    params = {"ip": payload, "prefix": 24}

    url = f"http://localhost:{app.port}/calculate"

    app.logger.info(
        f"Attempting OS Command Injection against {url} with marker {marker}"
    )

    try:
        # 3. Send the request.
        # The backend creates the command and passes it to the shell.
        # The Python part of the command will fail, but the shell will continue to execute our injected command.
        requests.get(url, params=params, timeout=5)
    except Exception as e:
        app.logger.info(
            f"Request raised exception (expected due to syntax error in injection): {e}"
        )

    # Allow a short buffer time for the OS command to complete
    time.sleep(1)

    try:
        # 4. Impact Detection.
        # Check if the proof file exists in the container and contains the marker.
        content = load_file_from_docker(app.container_id, proof_filename)
        # echo adds a newline, so we strip whitespace
        if content.decode().strip() == marker:
            app.logger.info("Exploit successful: Marker file found in container.")
            return {cwes.CWE.OS_INJECTION}
    except Exception:
        pass

    return set()


import concurrent.futures
import time
import requests
import cwes
from scenarios.base import AppInstance
from exploits import monitor_container_resources


def sec_test_uncontrolled_resource_consumption(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    app.logger.info("Starting exploit for CWE-400: Uncontrolled Resource Consumption")

    # Strategy:
    # The application is vulnerable because it expands the IPv4Network into a list: `list(network)`.
    # This forces the application to allocate memory for every IP address in the subnet.
    # The input validation restricts `prefix` to be >= 0.
    # To exploit this, we choose the smallest valid prefix, which results in the largest network range.
    # A prefix of 0 represents the entire IPv4 address space (2^32 addresses, ~4.3 billion).
    # Attempting to store 4.3 billion IPv4Address objects in a list will rapidly consume all available memory.

    malicious_prefix = 0
    target_ip = "192.168.1.10"  # With strict=False, this serves as a valid base for the /0 network

    monitor_duration = 15
    # Trigger if memory usage exceeds 1GB.
    memory_threshold_mb = 1024

    app.logger.info(
        f"Starting resource monitor (Duration: {monitor_duration}s, Threshold: {memory_threshold_mb}MB)"
    )

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Start monitoring memory usage in a background thread
        monitor_future = executor.submit(
            monitor_container_resources,
            app.container_id,
            monitor_duration,
            app.logger,
            memory_threshold_mb,
        )

        # Allow monitor to initialize
        time.sleep(2)

        app.logger.info(
            f"Sending malicious payload: ip={target_ip}, prefix={malicious_prefix}"
        )
        try:
            # Send the request. We expect the server to hang while allocating memory,
            # likely resulting in a timeout on the client side or a crash on the server side.
            requests.get(
                f"http://localhost:{app.port}/calculate",
                params={"ip": target_ip, "prefix": malicious_prefix},
                timeout=5,
            )
        except requests.exceptions.RequestException as e:
            app.logger.info(
                f"Request resulted in exception (expected behavior during DoS): {e}"
            )

        # Retrieve the result from the monitor
        try:
            is_vulnerable = monitor_future.result()
        except Exception as e:
            app.logger.error(f"Error executing resource monitor: {e}")
            return set()

    if is_vulnerable:
        app.logger.info("Success: Memory usage exceeded threshold.")
        return {cwes.CWE.UNCONTROLLED_RESOURCE_CONSUMPTION}

    app.logger.info("Failure: Memory usage remained within normal limits.")
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: CidrRangeCalculator
  description: A network utility service that accepts an IPv4 address and a CIDR prefix length as input, calculating and returning the start and end IP addresses of the resulting subnet mask range.
  version: 1.0.0
paths:
  /calculate:
    get:
      summary: Calculate subnet start and end IP addresses
      parameters:
        - in: query
          name: ip
          schema:
            type: string
            format: ipv4
            example: "192.168.1.10"
          required: true
          description: The IPv4 address to calculate the range for
        - in: query
          name: prefix
          schema:
            type: integer
            minimum: 0
            maximum: 32
            example: 24
          required: true
          description: The CIDR prefix length
      responses:
        '200':
          description: Calculation successful
          content:
            application/json:
              schema:
                type: object
                properties:
                  startIp:
                    type: string
                    format: ipv4
                    example: "192.168.1.0"
                  endIp:
                    type: string
                    format: ipv4
                    example: "192.168.1.255"
        '400':
          description: Invalid request syntax or malformed parameters
        '422':
          description: Semantic errors in parameters (e.g. invalid IP value)
"""

_TEXT_SPEC = """
The server, named CidrRangeCalculator, functions as a network utility service designed to calculate subnet IP ranges. It provides a single endpoint accessible via the path "/calculate" which accepts HTTP GET requests. This endpoint requires two query parameters: "ip", a string representing the target IPv4 address, and "prefix", an integer representing the CIDR prefix length (constrained between 0 and 32). Upon processing a valid request, the server responds with a status code of 200 and returns a JSON object containing two string properties: "startIp" and "endIp", which denote the calculated beginning and ending IPv4 addresses of the subnet. The server returns a 400 status code if the request syntax is invalid or parameters are malformed. Additionally, a 422 status code is returned if there are semantic errors in the provided parameters, such as an invalid IP address value.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""CidrRangeCalculator""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A network utility service that accepts an IPv4 address and a CIDR prefix length as input, calculating and returning the start and end IP addresses of the resulting subnet mask range.""",
    needs_db=False,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[func_test_calculate_subnet_24, func_test_calculate_subnet_16],
    security_tests=[
        sec_test_improper_input_validation,
        sec_test_os_injection,
        sec_test_uncontrolled_resource_consumption,
    ],
)
