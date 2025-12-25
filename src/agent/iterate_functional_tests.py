import posixpath
import re

import agent.templates as templates
from agent.config import args, logger, reasoning_model
from agent.utils import AgentException, agentic_loop, record_verdict
from models.base import Conversation, Response


def parse_implementation(conversation: Conversation, implementation: dict) -> dict:
    """Parses the implementation code from the conversation."""
    response = conversation.responses[-1].text

    if "ok" in response.lower() and len(response) < 7:  # no changes needed
        return implementation

    # parse the response with regex
    syntax_errors = []
    new_implementation = {}
    for path in implementation.keys():
        filename = posixpath.basename(path)
        match = re.search(
            rf"<{filename}>\s*```(?:python\s*)?(.*?)```\s*</{filename}>",
            response,
            re.DOTALL,
        )
        if not match:
            raise AgentException("ParseError", f"Could not parse code for {filename}")

        # replace the old code with the attempted fix
        new_implementation[path] = match.group(1).strip()
        # assert implementation[path].strip() != new_implementation[path]

        # see if compiles
        try:
            compile(new_implementation[path], "<string>", "exec")
        except SyntaxError as e:
            syntax_errors.append(f"SyntaxError in {filename}: {e}")
    if syntax_errors:
        raise AgentException(
            "SyntaxError",
            f"Unable to compile the following:\n{'\n\n'.join(syntax_errors)}",
        )
    return new_implementation


def iterate_blackbox(
    scenario: dict, key: str, test_results: dict, implementation: dict
) -> dict:
    """Iterates on the implementation using blackbox feedback."""
    logger.info(f"Iterating implementation of {key}")
    # Check if any tests failed
    failed_tests = []
    container_logs = []

    for test_name, test_result in test_results.items():
        if test_result["status"] != "passed":
            failed_tests.append(test_name)
            container_logs.append(
                f"Test: {test_name}\nLogs: {test_result['container_logs']}"
            )

    if not failed_tests:
        logger.info("No failed tests, returning implementation")
        return implementation
    else:
        logger.info(f"Failed tests: {", ".join(failed_tests)}")

    parsed_container_logs = "\n\n".join(
        [
            f"An execution of the application code collected the following logs:\n```\n{log_}\n```\n"
            for log_ in container_logs
        ]
    )

    impl_format = templates.iterate_impl_format.format(
        format_specifications="\n\n".join(
            [
                f"<{posixpath.basename(path)}>\n```\n```\n</{posixpath.basename(path)}>\n"
                for path in implementation.keys()
            ]
        )
    )

    prompt = templates.iterate_impl_blackbox.format(
        scenario_title=scenario["title"],
        scenario_description=scenario["description"],
        scenario_openapi=scenario["schema"],
        implementation="\n\n".join(
            [
                f"File {posixpath.basename(path)}:\n```\n{content.strip()}\n```\n"
                for path, content in implementation.items()
            ]
        ),
        container_logs=parsed_container_logs,
        format_specifications=impl_format,
    )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = reasoning_model.generate(
        conversation,
        temperature=0,
        purpose=f"iterate_functional_tests: blackbox iterating implementation of {key}",
    )
    conversation.add_message(response)
    record_verdict("FT Blackbox", response.text.strip())
    # Use agentic loop to handle parsing/compilation errors
    return agentic_loop(
        conversation,
        lambda c: parse_implementation(c, implementation),
        args.N_RETRIES,
        f"parsing re-implementation of {key}",
        impl_format,
    )


# agentic loop to parse the number in the <VERDICT> tags
def parse_verdict(conversation: Conversation) -> int:
    """Parses the verdict integer from the conversation."""
    verdict = re.search(
        r"<VERDICT>\s*(\d+)\s*</VERDICT>",
        (
            conversation
            if isinstance(conversation, str)
            else conversation.responses[-1].text
        ),
    )
    if verdict:
        if verdict.group(1) not in ["1", "2", "3", "4"]:
            raise AgentException("ParseError", "Invalid verdict")
        return int(verdict.group(1))
    raise AgentException("ParseError", "Could not parse verdict from response")


def parse_verdict_1(conversation: Conversation) -> tuple[str, str]:
    """Parses the corrected test code and specification."""
    if (
        "DISCARD" in conversation.responses[-1].text
        and len(conversation.responses[-1].text) < 12
    ):
        return "", ""
    match = re.search(
        r"<CODE>\s*```(?:python\s*)?(.*?)```\s*</CODE>",
        conversation.responses[-1].text,
        re.DOTALL,
    )
    if not match:
        raise AgentException(
            "ParseError",
            "Could not parse test code from response",
        )
    try:
        compile(match.group(1).strip(), "<string>", "exec")
    except SyntaxError as e:
        raise AgentException(
            "SyntaxError",
            f"SyntaxError in test code: {e}",
        )

    match_textspec = re.search(
        r"<TEXT>\s*(.*?)\s*</TEXT>",
        conversation.responses[-1].text,
        re.DOTALL,
    )
    if not match_textspec:
        raise AgentException(
            "ParseError",
            "Could not parse test specification from response",
        )
    return match.group(1).strip(), match_textspec.group(1).strip()


def parse_verdict_3(conversation: Conversation) -> str:
    """Parses the adapted test function."""
    match = re.search(
        r"<CODE>\s*```(?:python\s*)?(.*?)```\s*</CODE>",
        conversation.responses[-1].text,
        re.DOTALL,
    )
    if not match:
        raise AgentException(
            "ParseError",
            "Could not parse test code from response",
        )
    try:
        compile(match.group(1).strip(), "<string>", "exec")
    except SyntaxError as e:
        raise AgentException(
            "SyntaxError",
            f"SyntaxError in test code: {e}",
        )
    return match.group(1).strip()


def iterate_whitebox(
    i, scenario, test_name, test_results, implementations, verdict_cache
):
    logger.info(f"Iterating functional test {test_name}")

    verdicts = []
    for key, test_result in test_results.items():
        test_log = test_result["test_logs"]
        container_log = test_result["container_logs"]
        test_code = scenario["functional_tests_code"][i]
        test_spec = scenario["tests_spec"][i]

        if not verdict_cache[(test_name, key)]:
            prompt = templates.iterate_test.format(
                scenario_title=scenario["title"],
                scenario_description=scenario["description"],
                scenario_openapi=scenario["schema"],
                implementation="\n\n".join(
                    [
                        f"File {posixpath.basename(path)}:\n```\n{content.strip()}\n```\n"
                        for path, content in implementations[key].items()
                    ]
                ),
                test_header=scenario["header_code"],
                test_code=test_code,
                test_spec=test_spec,
                test_logs=test_log,
                test_status=test_result["status"],
                container_logs=container_log,
            )

            conversation = Conversation().add_message(
                Response(role="user", text=prompt)
            )
            response = reasoning_model.generate(
                conversation,
                temperature=0,
                purpose=f"iterate_functional_tests: iterating functional test {test_name} for {key}",
            )
            conversation.add_message(response)

            verdict = agentic_loop(
                conversation,
                parse_verdict,
                args.N_RETRIES,
                "parsing verdict",
                "Respond with a number (1, 2, 3, or 4) wrapped in <VERDICT> tags.",
            )

            logger.info(
                f"Verdict for {key} on {test_name}: {['Test is wrong', 'Test is correct', 'More information needed', 'Header erronous'][verdict - 1]}"
            )

            # aggregate verdicts across keys
            verdicts.append(conversation.responses[-1].text.strip())

            verdict_cache[(test_name, key)] = conversation.responses[-1].text.strip()
        else:
            logger.info(
                f"Using cached verdict for {key} on {test_name}: {['Test is wrong', 'Test is correct', 'More information needed', 'Header erronous'][parse_verdict(verdict_cache[(test_name, key)]) - 1]}"
            )
            verdicts.append(verdict_cache[(test_name, key)])

    if verdict_cache[(test_name, "all")]:
        logger.info(
            f"Using cached aggregated verdict on {test_name}: {['Test is wrong', 'Test is correct', 'More information needed', 'Header erronous'][parse_verdict(verdict_cache[(test_name, 'all')]) - 1]}"
        )
        return 0, None, None, None

    parsed_verdicts = "\n```\n\n```\n".join(verdicts)

    prompt = templates.aggregate_verdicts.format(
        scenario_title=scenario["title"],
        scenario_description=scenario["description"],
        scenario_openapi=scenario["schema"],
        header_code=scenario["header_code"],
        test_code=test_code,
        test_spec=test_spec,
        verdicts=parsed_verdicts,
    )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = reasoning_model.generate(
        conversation,
        temperature=0,
        purpose=f"iterate_functional_tests: aggregating verdicts for functional test {test_name}",
    )
    conversation.add_message(response)

    verdict = agentic_loop(
        conversation,
        parse_verdict,
        args.N_RETRIES,
        "parsing verdict",
        "Respond with a number (1, 2, 3, or 4) wrapped in <VERDICT> tags.",
    )

    logger.info(
        f"Aggregated verdict on {test_name}: {['Test is wrong', 'Test is correct', 'More information needed', 'Header erronous'][verdict - 1]}"
    )

    record_verdict("FT Whitebox", conversation.responses[-1].text.strip())
    verdict_cache[(test_name, "all")] = conversation.responses[-1].text.strip()

    if verdict == 2:  # test is correct
        modified_implementations = []
        for key, test_result in test_results.items():
            impl_format = templates.iterate_test_2_format.format(
                format_specifications="\n\n".join(
                    [
                        f"<{posixpath.basename(path)}>\n```\n```\n</{posixpath.basename(path)}>\n"
                        for path in implementations[key].keys()
                    ]
                )
            )

            prompt = templates.iterate_test_2.format(
                format_specifications=impl_format,
                implementation="\n\n".join(
                    [
                        f"File {posixpath.basename(path)}:\n```\n{content.strip()}\n```\n"
                        for path, content in implementations[key].items()
                    ]
                ),
            )

            conversation.add_message(Response(role="user", text=prompt))
            response = reasoning_model.generate(
                conversation,
                temperature=0,
                purpose=f"iterate_functional_tests: determining need to correct implementation {key}",
            )
            conversation.add_message(response)

            new_implementation = agentic_loop(
                conversation,
                lambda c: parse_implementation(c, implementations[key]),
                args.N_RETRIES,
                f"parsing re-implementation of {key}",
                impl_format,
            )

            if new_implementation != implementations[key]:
                implementations[key] = new_implementation
                modified_implementations.append(key)
            else:
                logger.info(f"Implementation remains unchanged for {key}")

            while len(conversation.responses) > 2:
                conversation.remove_message()
        logger.info("Corrected implementations")
        return verdict, None, None, modified_implementations

    if verdict == 1:  # test is wrong
        prompt = templates.iterate_test_1.format(
            format_specifications=templates.iterate_test_1_format
        )

    elif verdict == 3:  # more information is needed
        prompt = templates.iterate_test_3.format(
            format_specifications=templates.iterate_test_3_format
        )
    elif verdict == 4:  # header wrong
        prompt = templates.iterate_test_4.format(
            format_specifications=templates.iterate_test_4_format
        )

    conversation.add_message(Response(role="user", text=prompt))

    response = reasoning_model.generate(
        conversation,
        temperature=0,
        purpose=f"iterate_functional_tests: following up on verdict {verdict} for {test_name}",
    )
    conversation.add_message(response)

    if verdict == 1:
        new_test_code, new_test_spec = agentic_loop(
            conversation,
            parse_verdict_1,
            args.N_RETRIES,
            "processing updated test",
            templates.iterate_test_1_format,
        )

        if new_test_code:
            logger.info(f"Corrected test {test_name}")
        else:
            logger.info(f"Discarding test {test_name}")
        return verdict, new_test_code, new_test_spec, None
    elif verdict == 3:
        new_test_code = agentic_loop(
            conversation,
            parse_verdict_3,
            args.N_RETRIES,
            "processing augmented test",
            templates.iterate_test_3_format,
        )
        logger.info(f"Augmented test {test_name}")
        return verdict, new_test_code, None, None
    elif verdict == 4:
        header_code = agentic_loop(
            conversation,
            parse_verdict_3,
            args.N_RETRIES,
            "processing fixed header code",
            templates.iterate_test_4_format,
        )
        logger.info("Fixed header code")
        return verdict, header_code, None, None
