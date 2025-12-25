import re

import agent.templates as templates
from agent.config import args, logger, reasoning_model
from agent.utils import AgentException, agentic_loop
from models import Conversation, Response


def parse_tests_spec(conversation: Conversation) -> list[str]:
    """Parses functional test specifications from the conversation."""
    raw_tests_spec = conversation.responses[-1].text
    pattern = r"<TEST>(.*?)</TEST>"
    tests = [test.strip() for test in re.findall(pattern, raw_tests_spec, re.DOTALL)]

    if raw_tests_spec.count("<TEST>") != raw_tests_spec.count("</TEST>"):
        raise AgentException("ParseError", "Mismatch of <TEST>'s and </TEST>'s")

    if raw_tests_spec.count("<TEST>") != len(tests):
        raise AgentException(
            "ParseError",
            f"Generated {raw_tests_spec.count('<TEST>')} tests but could only parse len(tests) of them.",
        )
    return tests


def generate_tests_spec(scenario: dict, conversation: Conversation) -> list[str]:
    """Generates functional test specifications for the scenario."""
    prompt = templates.functional_tests_specs.format(
        test_spec_template=templates.test_spec_template,
        example_title=templates.example_title,
        example_description=templates.example_description,
        example_openapi=templates.example_openapi,
        example_tests_spec=templates.example_tests_spec,
        scenario_title=scenario["title"],
        scenario_description=scenario["description"],
        scenario_openapi=scenario["schema"],
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = reasoning_model.generate(
        conversation,
        temperature=0,
        purpose="generate_functional_tests: generating functional test specifications",
    )
    conversation.add_message(response)

    logger.info(
        f"Generated {response.text.count('<TEST>')} functional tests for scenario {scenario['title']}"
    )

    return agentic_loop(
        conversation,
        parse_tests_spec,
        args.N_RETRIES,
        f"parsing functional test specifications for scenario {scenario['title']}",
        templates.test_spec_template,
    )


def parse_tests_code(
    conversation: Conversation, scenario: dict
) -> tuple[str, list[str], list[str]]:
    """Parses functional test code from the conversation."""
    raw_tests_code = conversation.responses[-1].text
    header_match = re.search(
        r"<HEADER>\s*```(?:python\s*)?(.*?)```\s*</HEADER>", raw_tests_code, re.DOTALL
    )
    function_matches = re.findall(
        r"<FUNCTION>\s*```(?:python\s*)?(.*?)```\s*</FUNCTION>",
        raw_tests_code,
        re.DOTALL,
    )

    if not header_match:
        raise AgentException(
            "ParseError",
            "Could not parse HEADER section.",
        )

    header_code = header_match.group(1).strip()

    if not function_matches:
        raise AgentException(
            "ParseError",
            "Could not parse FUNCTION sections.",
        )

    function_codes = [func.strip() for func in function_matches]

    # mismatch in functional test code snippets and number of tests in the spec
    if len(function_codes) != len(scenario["tests_spec"]):
        raise AgentException(
            "ConsistencyError",
            f"Generated specs for {len(scenario['tests_spec'])} testcases, yet parsed {len(function_codes)} corresponding code snippets. The python function for each testcase in the specification should be wrapped in one <FUNCTION> section.",
        )

    function_names = []
    for i, code in enumerate(function_codes, start=1):
        match = re.search(r"def\s+(\w+)\s*\(", code)
        if not match:
            raise AgentException(
                "ParseError",
                f"Not able to find a function definition in <FUNCTION> block {i}",
            )
        function_names.append(match.group(1))

    # check if code is compilable
    syntax_errors = []
    for i, code_block in enumerate([header_code, *function_codes]):
        try:
            compile(code_block, "<string>", "exec")
        except SyntaxError as e:
            if i == 0:
                syntax_errors.append(f"Unable to compile header, SyntaxError: {e}")
            else:
                syntax_errors.append(
                    f"Unable to compile {function_names[i-1]}, SyntaxError: {e}"
                )

    if syntax_errors:
        raise AgentException(
            f"{len(syntax_errors)} SyntaxError(s) found in the code:\n\n",
            "\n\n".join(syntax_errors),
        )

    return header_code, function_codes, function_names


def generate_tests_code(
    scenario: dict, conversation: Conversation
) -> tuple[str, list[str], list[str]]:
    """Generates Python code for the functional tests."""
    # scnenario_tests_spec_combined = (
    #     "<TESTS>\n<TEST>\n"
    #     + "\n</TEST>\n\n<TEST>\n".join(scenario["tests_spec"])
    #     + "\n</TEST>\n</TESTS>"
    # )
    prompt = templates.functional_tests_code.format(
        func_tool_signatures=templates.func_tool_signatures,
        tests_code_template=templates.tests_code_template,
        example_tests_code=templates.example_tests_code,
    )

    conversation.add_message(Response(role="user", text=prompt))
    response = reasoning_model.generate(
        conversation,
        temperature=0,
        purpose="generate_functional_tests: generating functional tests code",
    )
    conversation.add_message(response)

    logger.info("Generated functional tests code")

    # parse, verify consistency and check if compiles
    header_code, function_codes, function_names = agentic_loop(
        conversation,
        lambda c: parse_tests_code(c, scenario),
        args.N_RETRIES,
        "parsing, verifying consistency and compilability of the functional tests code",
        templates.tests_code_template,
    )

    # augment header code
    FUNCTEST_SIGNATURES = [
        "place_file_on_docker",
    ]

    if any(
        (signature in header_code or signature in function_codes)
        for signature in FUNCTEST_SIGNATURES
    ):
        header_code = (
            "from exploits import "
            + ", ".join(
                signature
                for signature in FUNCTEST_SIGNATURES
                if (signature in header_code or signature in function_codes)
            )
            + "\n"
            + header_code
        )

    return header_code, function_codes, function_names
