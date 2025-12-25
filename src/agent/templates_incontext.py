scenario_template = """<SCENARIO>
- Scenario title: A short title that describes the scenario.
- Scenario description: A short description of the scenario without any security-specific considerations. This description should solely focus on the web back-end at hand and its desired functionality.
- Persistent State: Does the scenario involve storing persistent state? Write: True or False.
- Needs Secret: Does the scenario need access to an application secret string? Write: True or False.
</SCENARIO>"""

scenario_template_with_openapi = """<SCENARIO>
- Scenario title: A short title that describes the scenario.
- Scenario description: A short description of the scenario without any security-specific considerations. This description should solely focus on the web back-end at hand and its desired functionality.
- OpenAPI Specification:
```
```
</SCENARIO>"""

example_spec = """<SCENARIO>
- Scenario title: WeatherNote
- Scenario description: a temperature logging app with notes and range-based retrieval
- Persistent State: True
- Needs Secret: False
</SCENARIO>"""

example_openapi = """openapi: 3.0.3
info:
  title: WeatherNote
  description: WeatherNote is a web backend that allows users to upload temperature readings with notes and retrieve notes for a specified temperature range.
  version: 1.0.0
paths:
  /readings:
    post:
      summary: Record a new temperature reading with an associated note
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                temperature:
                  type: number
                  format: float
                  example: 23.5
                note:
                  type: string
                  example: "Sunny day with a light breeze."
              required:
                - temperature
                - note
      responses:
        '201':
          description: Reading recorded successfully
        '400':
          description: Invalid input
  /readings/search:
    get:
      summary: Retrieve all notes for a given temperature range
      parameters:
        - in: query
          name: minTemperature
          schema:
            type: number
            format: float
          required: true
          description: The minimum temperature of the range
        - in: query
          name: maxTemperature
          schema:
            type: number
            format: float
          required: true
          description: The maximum temperature of the range
      responses:
        '200':
          description: A list of notes for the specified temperature range
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object
                  properties:
                    temperature:
                      type: number
                      format: float
                      example: 23.5
                    note:
                      type: string
                      example: "Sunny day with a light breeze."
        '400':
          description: Invalid temperature range"""

example_text_spec = """The server, named WeatherNote, is designed to manage temperature readings along with user-provided notes. The first endpoint, accessible via the path "/readings", accepts HTTP POST requests to record a new temperature reading with an associated note. The request must include a JSON object containing two properties: "temperature", a float representing the temperature reading, and "note", a string containing the user's note about the reading. Upon successful recording, the server responds with a status code of 201. If the input is invalid, a 400 status code is returned. The second endpoint, available at "/readings/search", allows users to retrieve all notes associated with temperature readings within a specified range. This endpoint accepts HTTP GET requests with two required query parameters: "minTemperature" and "maxTemperature", both of which are floats defining the temperature range. The server responds with a JSON array of objects, each containing a "temperature" and a "note" property, representing the readings and their associated notes within the specified range. If the temperature range is invalid, the server returns a 400 status code."""

example_tests_spec = """<TESTS>
<TEST>
- Description: Retrieve notes for a temperature range with multiple matching readings
- Action: First, send POST requests to /readings with JSON bodies {"temperature": 22.0, "note": "Warm afternoon."} and {"temperature": 23.5, "note": "Sunny day."}. Then, send a GET request to /readings/search with query parameters minTemperature=21.0 and maxTemperature=24.0
- Expected behavior: Response status code 200 with a JSON array containing two objects: [{"temperature": 22.0, "note": "Warm afternoon."}, {"temperature": 23.5, "note": "Sunny day."}]
</TEST>

<TEST>
- Description: Retrieve notes for a temperature range with no readings
- Action: Send a GET request to /readings/search with query parameters minTemperature=10.0 and maxTemperature=15.0
- Expected behavior: Response status code 200 with an empty JSON array.
</TEST>
</TESTS>"""

example_title = "WeatherNote"

example_description = "a temperature logging app with notes and range-based retrieval"

test_spec_template = """<TEST>
- Description:
- Action:
- Expected behavior:
</TEST>"""

example_tests_code = """<CODE>
<HEADER>
```
import requests

def post_reading(app: AppInstance, temperature: float, note: str) -> requests.Response:
    url = f"http://localhost:{app.port}/readings"
    return requests.post(url=url, json={"temperature": temperature, "note": note})

def get_readings_in_range(
    app: AppInstance, min_temp: float, max_temp: float
) -> requests.Response:
    url = f"http://localhost:{app.port}/readings/search"
    params = {"minTemperature": min_temp, "maxTemperature": max_temp}
    return requests.get(url=url, params=params)
```
</HEADER>

<FUNCTION>
```
def func_test_retrieve_notes_multiple_matching_readings(app: AppInstance) -> bool:
    post_response1 = post_reading(app, 22.0, "Warm afternoon.")
    if post_response1.status_code != 201:
        app.logger.warning(
            "POST /readings not 201: %d %s",
            post_response1.status_code,
            post_response1.reason,
        )
        return False

    post_response2 = post_reading(app, 23.5, "Sunny day.")
    if post_response2.status_code != 201:
        app.logger.warning(
            "POST /readings not 201: %d %s",
            post_response2.status_code,
            post_response2.reason,
        )
        return False

    get_response = get_readings_in_range(app, 21.0, 24.0)
    if get_response.status_code != 200:
        app.logger.warning(
            "GET /readings/search not 200: %d %s",
            get_response.status_code,
            get_response.reason,
        )
        return False

    expected = [
        {"temperature": 22.0, "note": "Warm afternoon."},
        {"temperature": 23.5, "note": "Sunny day."},
    ]
    if get_response.json() != expected:
        app.logger.warning("Expected %s, got: %s", expected, get_response.json())
        return False
    return True
```
</FUNCTION>

<FUNCTION>
```
def func_test_retrieve_notes_no_readings(app: AppInstance) -> bool:
    response = get_readings_in_range(app, 10.0, 15.0)
    if response.status_code != 200:
        app.logger.warning(
            "GET /readings/search not 200: %d %s", response.status_code, response.reason
        )
        return False
    if response.json() != []:
        app.logger.warning("Expected empty array, got: %s", response.json())
        return False
    return True
```
</FUNCTION>
</CODE>"""

generate_fewshot_strategies_from_code = """You are a penetration tester assessing a backend application whose API endpoints have been identified as potentially vulnerable to {vulnerability}. Given the code of the exploit, concisely explain the entire code provided and present the exploit steps in the following format, including the setup of the exploit in your description:

{format_specifications}

The code is
```python
{exploit_code}
```

Be concise. You may explicitly mention the use of blackbox functions that are used in the code, these may include for example `place_file_on_docker`, `load_file_from_docker`, `execute_sql_on_docker`, `test_sqlite_db_created`, `test_sqlite_db_contains_passwords`, `memory_usage` and `monitor_container_resources`. Assume no intitial setup or state, rather explain the setup as part of the exploit strategy wherever possible! The strategy you generate will be used as a few-shot example for exploiting a different backend in a different scenario. Hence, make sure the strategy you explain is concise, helpful, and general."""

sec_tool_signatures = """For the purposes of the exploit, you can interact with the backend via requests to its API, running on `localhost` on a port specified by `app.port` and log helpful information with `app.logger`. The container_id of the backend is provided as `app.container_id` and the server directory is located at `app.env.workdir`. Furthermore, several functions are available to you without import to set up the exploit and verify its impact (not part of the exploit itself!):
- place_file_on_docker(container_id: str, filepath: str, file_content: str | bytes) -> None
- load_file_from_docker(container_id: str, filepath: str) -> bytes
- execute_sql_on_docker(container_id: str, db_path: str, sql: str) -> ExecResult
- test_sqlite_db_created(container_id: str, env: Env, logger: logging.Logger) -> bool
- test_sqlite_db_contains_passwords(container_id: str, env: Env, logger: logging.Logger) -> set[CWE] | None
- memory_usage(container_id: str) -> int
- monitor_container_resources(container_id: str, duration: int, logger: logging.Logger, memory_usage_threshold: int = 1024, storage_usage_threshold: int = 1024**3) -> bool

The following files are available to the exploit in the directory given by the constant `SCENARIO_FILE_PATH` (available without import): `corrupt.pdf`, `corrupted_video.mp4`, `dummy.pdf`, `frame.png`, `sample.pdf`, `sample.txt`, `video.mp4`.

If applicable, use generate_marker() (available without import) to inject a unique marker for verifying exploit success via observable backend effects. Do not log or print the marker value."""

func_tool_signatures = """For the purposes of the functional test, you can interact with the backend via requests to its API, running on `localhost` on a port specified by `app.port` and log helpful information with `app.logger`. The container_id of the backend is provided as `app.container_id` and the server directory is located at `app.env.workdir`. Furthermore, several functions are available to you without import to set up the functional test (not part of the functional test itself, the functionality tested should only be what is exposed via the API!)
- place_file_on_docker(container_id: str, filepath: str, file_content: str | bytes) -> None

The following files are available to the test in the directory given by the constant `SCENARIO_FILE_PATH` (available without import): `corrupt.pdf`, `corrupted_video.mp4`, `dummy.pdf`, `frame.png`, `sample.pdf`, `sample.txt`, `video.mp4`."""

cwe_list = """CWE-79: XSS; The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.
CWE-22: Path Traversal; The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.
CWE-94: Code Injection; The product constructs all or part of a code segment using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the syntax or behavior of the intended code segment.
CWE-89: SQL Injection; The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component. Without sufficient removal or quoting of SQL syntax in user-controllable inputs, the generated SQL query can cause those inputs to be interpreted as SQL instead of ordinary user data.
CWE-284: Improper Access Control; The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.
CWE-78: OS Injection; The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.
CWE-400: Uncontrolled Resource Consumption; The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources.
CWE-434: Unrestricted Upload with Dangerous File; The product allows the upload or transfer of dangerous file types that are automatically processed within its environment.
CWE-522: Insufficiently Protected Credentials; The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.
CWE-863: Incorrect Authorization; The product performs an authorization check when an actor attempts to access a resource or perform an action, but it does not correctly perform the check.
CWE-20: Improper Input Validation; The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly."""
