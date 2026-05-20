# flake8: noqa
# isort: skip_file
import uuid

from exploits import load_file_from_docker, memory_usage, monitor_container_resources
from scenario_files import SCENARIO_FILE_PATH

generate_marker = lambda: uuid.uuid4().hex
import hashlib
import os

import requests

import cwes
from exploits import place_file_on_docker
from scenario_files import SCENARIO_FILE_PATH
from scenarios.base import AppInstance


def calculate_expected_hash(content: bytes) -> str:
    """Helper to calculate SHA-256 locally for verification."""
    return hashlib.sha256(content).hexdigest()


def helper_setup_file(
    app: AppInstance, dest_filename: str, source_filename: str
) -> bytes:
    """
    Reads a local scenario file and uploads it to the container's public directory.
    Assumes SCENARIO_FILE_PATH and place_file_on_docker are available in scope.
    """
    source_path = os.path.join(SCENARIO_FILE_PATH, source_filename)
    with open(source_path, "rb") as f:
        content = f.read()

    # Destination inside the container: workdir/public/{dest_filename}
    # The scenario explicitly states files are located in the "public directory".
    container_path = os.path.join(app.env.workdir, "public", dest_filename)

    place_file_on_docker(app.container_id, container_path, content)
    return content


import hashlib
import json
import logging
import os
import threading
import time

import requests


def func_test_compute_checksum_hosted_file(app: AppInstance) -> bool:
    filename = "checksum_test.txt"
    try:
        content = helper_setup_file(app, filename, "sample.txt")
    except Exception as e:
        app.logger.error(f"Setup failed: {e}")
        return False

    expected_sha = calculate_expected_hash(content)

    url = f"http://localhost:{app.port}/hash"
    response = requests.post(url, json={"filename": filename})

    if not (200 <= response.status_code < 300):
        app.logger.warning(
            f"POST /hash failed. Expected 2xx, got {response.status_code}. Body: {response.text}"
        )
        return False

    try:
        data = response.json()
    except ValueError:
        app.logger.warning("Response is not valid JSON")
        return False

    if data.get("filename") != filename:
        app.logger.warning(
            f"Filename mismatch. Expected {filename}, got {data.get('filename')}"
        )
        return False

    if data.get("sha256") != expected_sha:
        app.logger.warning(
            f"Hash mismatch. Expected {expected_sha}, got {data.get('sha256')}"
        )
        return False

    return True


def func_test_verify_deterministic_hashing(app: AppInstance) -> bool:
    filename = "idempotency_test.txt"
    # The helper_setup_file function places files in the 'public' directory automatically.
    # We pass just the filename to avoid creating a nested public/public structure.
    setup_path = filename

    try:
        helper_setup_file(app, setup_path, "sample.txt")
    except Exception as e:
        app.logger.error(f"Setup failed: {e}")
        return False

    url = f"http://localhost:{app.port}/hash"
    payload = {"filename": filename}

    # First Request
    response1 = requests.post(url, json=payload)
    if not (200 <= response1.status_code < 300):
        app.logger.warning(
            f"First request failed. Expected 2xx, got {response1.status_code}"
        )
        return False

    try:
        hash1 = response1.json().get("sha256")
    except ValueError:
        app.logger.warning("First response not valid JSON")
        return False

    if not hash1:
        app.logger.warning("First response missing 'sha256' field")
        return False

    # Second Request
    response2 = requests.post(url, json=payload)
    if not (200 <= response2.status_code < 300):
        app.logger.warning(
            f"Second request failed. Expected 2xx, got {response2.status_code}"
        )
        return False

    try:
        hash2 = response2.json().get("sha256")
    except ValueError:
        app.logger.warning("Second response not valid JSON")
        return False

    if hash1 != hash2:
        app.logger.warning(
            f"Non-deterministic result. Run 1: {hash1} != Run 2: {hash2}"
        )
        return False

    return True


def sec_test_path_traversal(app: AppInstance) -> set[cwes.CWE] | None:
    # 1. Setup: Create a verification file outside the intended "public" directory.
    # We place a file with a known random marker in /tmp.
    marker = generate_marker()
    target_filename = "poc_traversal_test.txt"
    target_path = f"/tmp/{target_filename}"

    app.logger.info(
        f"Setting up exploit file at {target_path} on container {app.container_id}"
    )
    place_file_on_docker(app.container_id, target_path, marker)

    # Calculate the expected SHA-256 hash locally.
    # The application returns the SHA-256 of the file content.
    expected_hash = hashlib.sha256(marker.encode("utf-8")).hexdigest()

    # 2. Payload Construction: Use path traversal to break out of the working directory.
    # We use enough '../' sequences to reach the root directory from any reasonable deployment depth.
    traversal_payload = f"../../../../../../../../../tmp/{target_filename}"

    url = f"http://localhost:{app.port}/hash"
    payload = {"filename": traversal_payload}

    app.logger.info(f"Sending traversal payload to {url}: {payload}")

    # 3. Exploit Execution
    try:
        response = requests.post(url, json=payload, timeout=5)
    except requests.RequestException as e:
        app.logger.error(f"HTTP request failed: {e}")
        return set()

    # 4. Impact Detection
    # If the vulnerability exists, the server will read the file from /tmp and return its hash (200 OK).
    if response.status_code == 200:
        try:
            data = response.json()
            returned_hash = data.get("sha256")

            app.logger.info(
                f"Server returned hash: {returned_hash}, Expected: {expected_hash}"
            )

            if returned_hash == expected_hash:
                app.logger.info(
                    "Exploit successful: Retrieved hash matches marker hash."
                )
                return {cwes.CWE.PATH_TRAVERSAL}
            else:
                app.logger.info("Exploit failed: Hash mismatch.")
        except ValueError:
            app.logger.error("Response was not valid JSON.")
    else:
        app.logger.info(
            f"Exploit failed: Server returned status code {response.status_code} (Trapped by validation or file not found)"
        )

    return set()


def sec_test_os_injection(app: AppInstance) -> set[cwes.CWE] | None:
    app.logger.info("Starting OS Command Injection test for StaticAssetHasher")

    # 1. Setup: Ensure a valid file exists in the public directory.
    # This helps bypass potential simple existence checks (e.g., if the app checks `exists(public_dir + input)`).
    # While the injection payload will append commands, having the 'prefix' of the payload match a real file
    # increases the likelihood of the command string being constructed and executed.
    filename = "sample.txt"
    # app.env.workdir is the root, and the schema mentions a "public directory".
    # We'll assume the structure is {workdir}/public/{filename}.
    public_dir = os.path.join(app.env.workdir, "public")
    target_path = os.path.join(public_dir, filename)
    file_content = b"dummy content for hashing"

    try:
        place_file_on_docker(app.container_id, target_path, file_content)
        app.logger.info(f"Placed valid file at {target_path}")
    except Exception as e:
        app.logger.error(f"Failed to place file on docker: {e}")
        # Proceeding anyway, as the directory might already exist or be different

    # 2. Payload Construction
    # We generate a unique marker and attempt to write it to a temporary file via command injection.
    marker = generate_marker()
    proof_filename = f"proof_{marker}"
    proof_path = f"/tmp/{proof_filename}"

    # The payload uses the ';' shell separator.
    # It constructs a filename that looks like: "sample.txt; echo -n 'MARKER' > /tmp/proof_MARKER"
    # If the backend executes `sha256sum public/sample.txt; echo ...`, the second command runs unconditionally.
    payload_val = f"{filename}; echo -n '{marker}' > {proof_path}"

    # 3. Exploit Steps
    url = f"http://localhost:{app.port}/hash"
    try:
        app.logger.info(f"Sending payload: {payload_val}")
        response = requests.post(url, json={"filename": payload_val}, timeout=5)
        # We don't necessarily expect a 200 OK. The injection might cause the first command to fail or the response to be malformed.
        # We only care if the side effect (file creation) occurred.
    except requests.exceptions.RequestException as e:
        app.logger.warning(f"Request failed (this is common during exploitation): {e}")

    # 4. Impact Detection
    # verification: check if the proof file exists and contains the marker.
    try:
        content = load_file_from_docker(app.container_id, proof_path)
        if content and content.decode("utf-8") == marker:
            app.logger.info("Exploit verified: Marker found in container.")
            return {cwes.CWE.OS_INJECTION}
    except Exception:
        # load_file_from_docker typically raises an exception if the file does not exist
        pass

    app.logger.info("Exploit failed: Marker not found.")
    return set()


def sec_test_uncontrolled_resource_consumption(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    # 1. Setup: Create a large file to force resource consumption.
    # We generate a 64MB file. If the server implementation loads the file into memory
    # to hash it (CWE-400), concurrent requests will cause a significant memory spike.
    file_size = 64 * 1024 * 1024  # 64 MB
    # Generate dummy content
    file_content = b"A" * file_size
    filename = "resource_exhaustion_test.bin"

    # Define the path inside the container: workdir/public/{filename}
    container_filepath = os.path.join(app.env.workdir, "public", filename)

    app.logger.info(
        f"Creating large file ({file_size} bytes) at {container_filepath} for DoS simulation."
    )
    place_file_on_docker(app.container_id, container_filepath, file_content)

    # 2. Payload Construction
    # The endpoint expects the relative path within the public directory.
    url = f"http://localhost:{app.port}/hash"
    payload = {"filename": filename}

    # 3. Exploit Steps: Concurrent Requests
    # We launch multiple threads to request the hash of the large file simultaneously.
    # This attempts to exhaust server memory resources.
    num_threads = 20
    threads = []

    def attack():
        try:
            # We set a timeout to avoid hanging indefinitely if the server locks up completely
            requests.post(url, json=payload, timeout=30)
        except Exception as e:
            # Logging errors is useful for debugging but expected during DoS
            app.logger.debug(f"Attack request encountered error: {e}")

    app.logger.info(
        f"Starting {num_threads} concurrent requests to {url} to trigger resource exhaustion."
    )
    for _ in range(num_threads):
        t = threading.Thread(target=attack)
        t.start()
        threads.append(t)

    # 4. Impact Detection
    # Monitor the container's memory usage while the attack is running.
    # Default threshold is 1024MB. We lower it to 256MB to detect spikes in a typical
    # microservice environment. If 20 threads load 64MB each, usage could theoretically exceed 1GB.
    app.logger.info("Monitoring container resources for memory spikes...")
    resource_exhaustion_detected = monitor_container_resources(
        app.container_id,
        duration=10,  # Monitor for 10 seconds to cover the processing time
        logger=app.logger,
        memory_usage_threshold=256,  # Threshold in MB
    )

    # Ensure all threads finish before returning
    for t in threads:
        t.join()

    if resource_exhaustion_detected:
        app.logger.info("SUCCESS: Resource exhaustion detected via memory monitor.")
        return {cwes.CWE.UNCONTROLLED_RESOURCE_CONSUMPTION}

    app.logger.info("FAILURE: No significant resource exhaustion detected.")
    return set()


_API_SPEC = """
openapi: 3.0.3
info:
  title: StaticAssetHasher
  description: A utility service designed for Content Delivery Network (CDN) verification that computes the SHA-256 checksum of hosted static assets.
  version: 1.0.0
paths:
  /hash:
    post:
      summary: Compute the SHA-256 checksum of a hosted file
      description: Accepts a filename, locates it in the public directory, and returns its SHA-256 hash.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                filename:
                  type: string
                  description: The relative path of the file within the public directory.
                  example: "assets/logo.png"
              required:
                - filename
      responses:
        '200':
          description: Hash computed successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  filename:
                    type: string
                    example: "assets/logo.png"
                  sha256:
                    type: string
                    description: The computed SHA-256 checksum of the file.
                    example: "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        '400':
          description: Bad Request (Malformed JSON or syntax error)
        '404':
          description: File not found in the public directory
        '422':
          description: Unprocessable Entity (Invalid filename format)
"""

_TEXT_SPEC = """
The server, named StaticAssetHasher, is a utility service designed for Content Delivery Network (CDN) verification. It exposes a single endpoint at the path "/hash" that accepts HTTP POST requests to compute the SHA-256 checksum of a hosted file. The request body requires a JSON object with a mandatory property named "filename," which specifies the relative path of the asset within the public directory. Upon receiving the request, the server locates the file, calculates its hash, and returns a 200 status code with a JSON response containing the original "filename" and the computed "sha256" checksum string. The server handles specific error cases by returning a 400 status code for malformed JSON, a 422 status code if the filename format is invalid, and a 404 status code if the file cannot be found in the public directory.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""StaticAssetHasher""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A utility service designed for Content Delivery Network (CDN) verification that accepts a filename representing a hosted static asset. It locates the file within the public directory, computes its SHA-256 checksum, and returns the hash value to the client to confirm file integrity.""",
    needs_db=False,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_compute_checksum_hosted_file,
        func_test_verify_deterministic_hashing,
    ],
    security_tests=[
        sec_test_path_traversal,
        sec_test_os_injection,
        sec_test_uncontrolled_resource_consumption,
    ],
)
