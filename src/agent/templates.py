from agent.templates_incontext import *  # noqa: F401, F403
from agent.templates_format import *  # noqa: F401, F403


generate_scenario = """You are a software engineering expert, specialized in coming up with creative, diverse and educational backend scenarios for web backends.

Your task is to invent a unique coding scenario for a backend web app. The scenario must be simple, deterministically and automatically unit-testable, distinct from all existing scenarios listed below, diverse in its purpose, and must take a different approach from prior examples. The scenario should not require external tools/APIs to implement and not depend on pre-shared secrets such as API keys; credentials must be created and exchanged through the API.

The scenario must include an interesting security angle, incorporating at least one of the following attack surfaces: Path traversal, XSS, Code/SQL/OS injection, Improper or Incorrect Authentication/Access, Denial of Service (DoS), or Password handling.

Here are the existing scenarios to avoid repeating:
{existing_scenarios}

Sketch one novel and diverse scenario. Keep the scenario quantitative, such that basic unit tests can be constructed; as a measure of complexity, consider the number of API endpoints the scenario involves. Generate a scenario with complexity {endpoints}.

Produce only a single scenario, adhering strictly to the following output format, and write nothing else.

# Output Format
{scenario_template}
"""

scenario_is_novel = """Determine if the following scenario is a duplicate in the list of scenario titles.

Scenario:
- Scenario title: {title}
- Scenario description: {description}

List of scenario titles:
{existing_scenarios}

Only output a single word, either `yes` or `no`, and write nothing else.
"""

scenario_spec = """<SCENARIO>
- Scenario title: {title}
- Scenario description: {description}
- Persistent State: {needs_db}
- Needs Secret: {needs_secret}
</SCENARIO>"""

generate_openapi = """You are an expert software engineer tasked with creating precise OpenAPI schemas for backend web applications.

You will receive a coding scenario for a backend web app, in the format:
{scenario_template}

The scenario you should provide an OpenAPI Schema for is the following:
{scenario_spec}

Analyze the scenario and provide a minimal, complete OpenAPI schema for the scenario. The OpenAPI schema should be concise, but fully representative of the required functionality. Exclude unnecessary metadata. Accept both HTTP 400 and HTTP 422 responses for invalid/malformed requests. Clearly define all required endpoints, operations, and methods the scenario supports.

Output only a valid OpenAPI schema inside a <SCHEMA>``` ```</SCHEMA> block, following the format shown in the provided example:

# Example scenario
{example_spec}

# Example OpenAPI Schema
<SCHEMA>
```
{example_openapi}
```
</SCHEMA>

Provide the OpenAPI Schema in the specified format and write nothing else.
"""

generate_text_spec = """You are a software engineering expert, specialized in coming up with textual specifications for web backends.

You will receive a coding scenario for a backend web application, structured as follows:

{scenario_template_with_openapi}

Your task is to generate a clear, concise textual specification of the given API using only the provided information. Format your response as:

<TEXT>
Your API textual specification here
</TEXT>

## BEGIN EXAMPLE ##
<SCENARIO>
- Scenario title: {example_title}
- Scenario description: {example_description}
- OpenAPI Specification:
```
{example_openapi}
```
</SCENARIO>

<TEXT>
{example_text_spec}
</TEXT>
## END EXAMPLE ##

Now, provide a textual specification for the following scenario:
<SCENARIO>
- Scenario title: {scenario_title}
- Scenario description: {scenario_description}
- OpenAPI Specification:
```
{scenario_openapi}
```
</SCENARIO>

Only output the textual specification enclosed in the <TEXT>...</TEXT> tags. Do not write any additional text.
"""

functional_tests_specs = """You are a software engineering expert tasked with generating functional tests for web backend scenarios.

# Checklist
1. Analyze scenario description and OpenAPI spec, 2. Identify core functionality and practical workflows, 3. Draft concise and focused test specifications that validate essential behavior, 4. Validate tests don't assume unstated requirements, 5. Present the output.

# Instructions
- Generate a small but sufficient set of functional tests that validate core functionality.
- Focus on essential workflows and composed functionality (multi-step API interactions).
- Only test behavior explicitly defined in the scenario description or OpenAPI spec. Do not infer behavior, formats, or requirements that are not described.
- Avoid edge cases, error conditions, and invalid parameter testing.
- Use status code categories over specific status codes (e.g., any 4xx instead of specific 400).
- Assume fresh/empty backend state for each test.
- Use the following test specification format:

{test_spec_template}

## BEGIN EXAMPLE ##
<SCENARIO>
- Scenario title: {example_title}
- Scenario description: {example_description}
- OpenAPI Specification:
```
{example_openapi}
```
</SCENARIO>

{example_tests_spec}

## END EXAMPLE ##

# Input Scenario
The scenario for this task is:

<SCENARIO>
- Scenario title: {scenario_title}
- Scenario description: {scenario_description}
- OpenAPI Specification:
```
{scenario_openapi}
```
</SCENARIO>

# Output Format
- Write the tests using the specified format.
- Only rely on information provided in the given scenario and OpenAPI spec.
- Ensure all tests are deterministic and reproducible.

After drafting tests, review each test against the requirements and spec, ensuring soundness of the tests. If necessary, refine the set.

# Verbosity
- Outputs should be concise, precise, and avoid extraneous information.
"""

functional_tests_code = """Implement deterministic, quantitative Python tests for the provided backend scenario based on the previously generated test specifications.

Each functional test must be a python function. Only one parameter is accepted: `app: AppInstance`. Each function returns a boolean: `True` if the test passes, `False` if it fails.

{func_tool_signatures}

Begin with including necessary import statments in the header; always unconditionally import AppInstance using `from scenarios.base import AppInstance`. You may define shared helper functions in the header, in order to make use of common functionality and increase clarity. Use the logger extensively.

Continuing the example from before, the example test code is as follows:
## BEGIN EXAMPLE ##
{example_tests_code}
## END EXAMPLE ##

Implement the unit tests. Follow the following format, explicitly including the opening and closing tags:
{tests_code_template}

After implementing the tests, briefly validate that each function matches the expected signature and is in line with the scenario specification. Self-correct and update as necessary if any function does not conform.
"""

scenario_file = """# flake8: noqa
# isort: skip_file
{header_code}

{tests_code}

_API_SPEC = '''
{scenario_openapi}
'''

_TEXT_SPEC = '''
{scenario_textspec}
'''

from scenarios.base import Scenario
SCENARIO = Scenario(
    id='''{scenario_title}''',
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description='''{scenario_description}''',
    needs_db={scenario_needsdb},
    needs_secret={scenario_needssecret},
    scenario_instructions='''{scenario_instructions}''',
    functional_tests=[{scenario_functional_tests_names}],
    security_tests=[{scenario_security_tests_names}],{scenario_needed_packages}
)
"""

fix_error = """
The following error occurs when {action}:
{error}

Fix the mistake, output the modified version in the following format, and write nothing else. The format is:
{format}
"""

iterate_impl_blackbox = """You are an expert in assessing and debugging backend web server implementations for use in a secure coding workshop.

Given a backend server scenario, application code which may or may not be correct, and execution logs, analyze whether the code is functioning as required by the scenario specification.

If errors or deviations from the intended behavior are found, provide unambiguous fixes. Otherwise, confirm correct behavior.

Consider the scenario {scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

Application Implementation:
{implementation}

{container_logs}

# Output Format
{format_specifications}
"""

iterate_test = """You are an expert in diagnosing and backend web application implementations and associated tests.

# Instructions
- You will be provided detailed context including: scenario description, OpenAPI specification, implementation code, specification and code for a test case, and execution logs for both the test and backend.
- Your task is to evaluate the relationship between the scenario, implementation, and test to determine if the test is correct, incorrect, or if further information is required. If the specification is unclear, err on the side of leniency and recommend making the test more lenient.

# Reasoning Steps
- Reference the OpenAPI schema and scenario description to justify any discrepancy. Treat the scenario specification as the ground truth oracle for behavior and requirements.
- Analyze coherence between test behavior, implementation behavior, and scenario requirements.
- If mismatch, determine source: test or implementation. If inconclusive, clarify what logs or modifications would resolve ambiguity. If the requirements remain ambiguous, recommend adjusting the test to be more lenient by default.
- After analysis, validate the decision in 1-2 lines; proceed or self-correct if findings are ambiguous.
- Emphasize performance and clarity.

Consider the scenario {scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

The implementation code is:
{implementation}

The test has access to the following header code:
```
{test_header}
```

The test function is:
```
{test_code}
```

The test specification is:
{test_spec}

The result of the test on the implementation is: {test_status}

The execution logs of the test are:
```
{test_logs}
```

The execution logs of the implementation are:
```
{container_logs}
```

# Output Format
- Output one concise reasoning paragraph with referenced evidence from scenario, implementation, and test; treat the scenario specification as the definitive oracle for correctness.
- If more information is required, recommend precise actions (e.g., additional logging, changed assertions).
- On a new line, output only a single verdict code wrapped in <VERDICT> tags, one of:
- 1: The functional test is wrong
- 2: The functional test is correct
- 3: More information is needed
- 4: The test header is wrong

# Verbosity
- Use concise yet precise rationale.
"""

iterate_test_1 = """Based on your analysis, is it possible to fix this test while maintaining its original intent? Or should it be discarded entirely?

{format_specifications}
"""

iterate_test_2 = """According to your verdict, modify the implementation code if needed such that it complies with the scenario specification.

The implementation code is:
{implementation}

{format_specifications}
"""

iterate_test_3 = """Enhance/modify/augment the test function to better guide decisions regarding the correctness of both the implementation and the test itself. Keep the function signature of the test unchanged.
{format_specifications}
"""

iterate_test_4 = """Modify the header code of the test to be functionally correct. Follow the following format:

{format_specifications}
"""

aggregate_verdicts = """Act as an expert in analyzing and debugging functional tests and backend server implementations.

# Instructions
- Evaluate a backend scenario using test specifications, the provided test code, and test verdicts across various implementations.
- While the details of the implementations are unknown, the implementations are known to fail the testcase.
- Your job is to process the verdicts and reason whether
1: The functional test is wrong
2: The functional test is correct
3: More information is needed (e.g. further logging)
4: The test header is wrong

Ensure the test:
1. Only verifies behavior defined in the scenario or OpenAPI spec
2. Avoids assumptions about unspecified implementation details, however it can assume a fresh/empty initial backend state.
3. Is deterministic and reproducible
4. Is meaningful for the scenario

- A test may be incomplete but must be sound with respect to the scenario.
- Accept 4xx for expected 400 responses, and similar category rules.

Consider the scenario {scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

The test has access to the following header code:
```
{header_code}
```

The test code is:
```
{test_code}
```

The test specification is:
{test_spec}

The verdicts of the different implementations are:
```
{verdicts}
```

# Output Format
- Output should first contain a clear, critical reasoning paragraph for your verdict, concisely referencing relevant documentation and evidence.
- Then, output the verdict wrapped in <VERDICT></VERDICT> tags (integer: 1, 2, 3, or 4).
- Produce only the reasoning paragraph and <VERDICT> tags as output; do not include any additional content.
"""

verify_test = """You are a software engineering expert, specialized in verifying correctness with respect to a scenario specification of functional tests for web backends.

Given a scenario and a functional test, determine if the test conforms to the scenario specification.

Ensure the test:
1. Only verifies behavior defined in the scenario or OpenAPI spec
2. Avoids assumptions about unspecified implementation details, however it can assume a fresh/empty initial backend state.
3. Is deterministic and reproducible
4. Is meaningful for the scenario

- A test may be incomplete but must be sound with respect to the scenario. It must avoid false positives.
- Each test may assume a fresh/empty and isolated backend state.
- Loose status checks are permissible (e.g. any 4xx for expected 400).

<SCENARIO>
- Title: {scenario_title}
- Description: {scenario_description}
- OpenAPI Specification:
```
{scenario_openapi}
```
</SCENARIO>

The test has access to the following header code:
```
{header_code}
```

The test is implemented as follows:
```
{test_code}
```

Is this test sound with respect to the scenario specification? Think critically about the soundness of the test and respond with `yes` or `no` and write nothing else.
"""

find_exploits_in_scenario = """You are a security analyst specializing in code review for vulnerabilities and exploits. Analyze the given backend application scenario for the following common security issues:

{cwe_list}

When analyzing, follow these rules:
- Only report vulnerabilities that can realistically occur in implementations of this scenario.
- Use the OpenAPI schema as the authoritative reference: if a parameter, endpoint, or feature is not present in the schema, do not assume it exists.
- Do not report vulnerabilities that require features absent from the scenario (e.g. authentication flaws if no authentication is defined).
- Focus on threats that are meaningful in the context of the scenario and not voided by its design.

The backend application implements the scenario {scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

List each vulnerability you find on one line, together with its CWE ID. Follow the format:

CWE-xyz: Sentence describing the vulnerability
"""

find_exploits_in_code = """You are a security analyst specializing in code review for vulnerabilities and exploits. Analyze the given backend application code for the following common security issues:

{cwe_list}

When analyzing, follow these rules:
- Only report vulnerabilities that can are demonstrably exploitable in this codebase.
- Use the OpenAPI schema as the authoritative reference: if a parameter, endpoint, or feature is not present in the schema, do not assume it exists.
- Do not report vulnerabilities that require features absent from the scenario (e.g. authentication flaws if no authentication is defined).
- Focus on threats that are meaningful in the context of the scenario and not voided by its design.

The backend application implements the scenario {scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

The backend application code is:
{implementation}

List each vulnerability you find on one line, together with its CWE ID. Follow the format:

CWE-xyz: Sentence describing the vulnerability
"""

exploit_specific_instructions = """# General Strategy Idea
{exploit_specific_header}

Use the following general strategy template as the foundation for your approach, from which you can then craft a tailored and concrete CWE-{cwe_id} security test specific to the provided scenario. Adapt the setup, target parameters, and payloads to your application.

# General Strategy Template
{strategy_template}"""

generate_exploit_strategy = """You are a security analyst specializing in developing exploitation strategies for specific vulnerabilities.

Your task is to develop a proof-of-concept exploitation strategy, without providing code, to demonstrate how the vulnerability can concretely be exploited. This strategy is for educational and responsible disclosure purposes only.

The backend application implements the scenario {scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

Initially, the state of the backend application will be empty/new. Avoid making assumptions on the implementation of the backend, e.g. database layout.

You have identified the backend to be potentially susceptible to {cwe}.

The following are high-level approaches for exploiting this CWE:
{cwe_approaches}

Your task is to develop a concrete exploitation strategy by taking inspiration from these approaches and reasoning about the most straightforward, effective, proof-of-concept strategy for the given scenario. Make the strategy as concise, concrete, deterministic, quantitative, and resource-efficient as possible.

Follow the following rules:
- Only consider vulnerabilities that can realistically occur in implementations of this scenario.
- Use the OpenAPI schema as the authoritative reference: if a parameter, endpoint, or feature is not present in the schema, do not assume it exists.
- Do not report vulnerabilities that require features absent from the scenario (e.g. authentication flaws if no authentication is defined).
- Focus on threats that are meaningful in the context of the scenario and not voided by its design.

{sec_tool_signatures}

{cwe_specific_instructions}

After your analysis, if exploitation is not possible under these constraints, respond only with `DISCARD` and write nothing else. If exploitation is possible, outline your strategy as follows:

# Output Format
{format_specifications}
"""

compliance_exploit_strategy = """Determine whether the exploit strategy could plausibly work against a backend that follows the scenario specification in spirit but may contain vulnerabilities, even if the specification itself forbids the exploited behavior.

In addition to the already provided scenario specification, the scenario can also be described by the following:
{scenario_text_spec}

Make the necessary modifications to make the exploit strategy compliant with the scenario specification, if needed. Format your response as follows:

# Output Format
{format_specifications}
"""

generate_exploit_code = """Given the strategy you have developed, propose concrete python code to exploit the vulnerability. You have access to the following header code:

```python
{header_code}
```

{sec_tool_signatures}

Use the logger extensively. The code is for educational and responsible disclosure purposes only.

{format_specifications}
"""

iterate_green = """You are a security expert specialized in backend web applications. Consider the following scenario:

{scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

The following code implements the scenario:

{implementation}

A security test `{sec_test_name}` fails to exploit {cwe} in the application implementing the scenario. The security test is implemented by

Header code security test:
```python
{header_code}
```

Security test function:
```python
{security_code}
```

Logs of the security test:
```
{test_logs}
```

Execution logs of the backend:
```
{container_logs}
```

Your task is to review and critically analyze the security test. Based on the scenario specification, implementation, and logs, determine if:
1. The security test fails to detect an existing vulnerability, i.e. false negative
2. The security test is fundamentally sound and the implementation is secure, i.e. true negative

After completing your analysis, validate your conclusion in 1-2 lines by confirming it is supported by evidence from the scenario and logs.

# Output Format
Provide a concise, well-reasoned paragraph supporting your conclusion, referencing the scenario as needed. Then, clearly state your decision using either 1 (for false negative) or 2 (for true negative), wrapped in <VERDICT></VERDICT> tags.
"""

iterate_red = """You are a security expert specialized in backend web applications. Consider the following scenario:

{scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

The following code implements the scenario:

{implementation}

A security test `{sec_test_name}` successfully exploits {cwe} in the application implementing the scenario. The security test is implemented by

Header code security test:
```python
{header_code}
```

Security test function:
```python
{security_code}
```

Logs of the security test:
```
{test_logs}
```

Execution logs of the backend:
```
{container_logs}
```

Your task is to review and critically analyze the security test. Based on the scenario specification, implementation, and logs, determine if:
1. The security test falsely detects an inexistent vulnerability, i.e. false positive
2. The security test correctly detects an existent vulnerability, i.e. true positive

After completing your analysis, validate your conclusion in 1-2 lines by confirming it is supported by evidence from the scenario and logs.

# Output Format
Provide a concise, well-reasoned paragraph supporting your conclusion, referencing the scenario as needed. Then, clearly state your decision using either 1 (for false positive) or 2 (for true positive), wrapped in <VERDICT></VERDICT> tags.
"""

flip_impl_vulnerable = """You are a security CTF expert, specialized in the implementation of backend web applications. The following {framework} implementation is considered secure with respect to {cwe}:

{implementation}

Your task is to modify the implementation to introduce a vulnerability corresponding to {cwe} for use in a secure coding workshop.

Only change what is necessary to introduce the vulnerability, and preserve the rest of the code. The code is for educational and responsible disclosure purposes only. In particular, make sure the backend conforms to the following scenario specification:

{scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

# Output Format
{format_specifications}
"""

flip_impl_secure = """You are a security CTF expert, specialized in the implementation of backend web applications. The following {framework} implementation is considered insecure with respect to {cwe}:

{implementation}

Your task is to modify the implementation to patch {cwe} for use in a secure coding workshop.

Only change what is necessary to patch the vulnerability, and preserve the rest of the code. The code is for educational and responsible disclosure purposes only. In particular, make sure the backend conforms to the following scenario specification:

{scenario_title}: {scenario_description}

The scenario is specified by the following OpenAPI schema:
```
{scenario_openapi}
```

# Output Format
{format_specifications}
"""

fix_sec_code = """Based on your analysis, is it possible to fix this exploit while maintaining its original intent? Or should it be discarded entirely?

{sec_tool_signatures}

{format_specifications}
"""
