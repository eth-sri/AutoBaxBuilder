import os

import agent.templates as templates
from agent.config import args, logger, scenario_folder_path


def export_scenario_code(
    scenario: dict, it: int = 0, iv: bool = False, write: bool = True, sec: bool = False
) -> str:
    """Export scenario data to a Python code file.

    Args:
        scenario: Dictionary containing scenario data including:
            - header_code: Import statements and helper code
            - functional_tests_code: List of functional test implementations
            - security_tests_code: List of security test implementations (if sec=True)
            - schema: OpenAPI schema specification
            - text_spec: Text description of the scenario
            - title, description: Scenario metadata
            - needs_db, needs_secret: Resource requirements
            - scenario_instructions: Setup instructions
            - functional_tests_names: List of functional test names
            - security_tests_names: List of security test names (if sec=True)
            - needed_packages: Optional list of required packages
        it: Iteration number for naming (used in _iu{it} or _iw{it} suffix)
        iv: If True, generates an "iv" (verified) version file
        write: If True, writes the code to a file; if False, only returns the code string
        sec: If True, includes security tests in the export

    Returns:
        The generated Python code as a string
    """
    needed_packages_param = ""
    if "needed_packages" in scenario:
        needed_packages_param = f"\n    needed_packages={scenario['needed_packages']},"
    if not sec:
        code = templates.scenario_file.format(
            header_code=scenario["header_code"],
            tests_code="\n\n".join(scenario["functional_tests_code"]),
            scenario_openapi=scenario["schema"],
            scenario_textspec=scenario["text_spec"],
            scenario_title=scenario["title"],
            scenario_description=scenario["description"],
            scenario_needsdb=scenario["needs_db"],
            scenario_needssecret=scenario["needs_secret"],
            scenario_instructions=scenario["scenario_instructions"],
            scenario_functional_tests_names=", ".join(
                scenario["functional_tests_names"]
            ),
            scenario_security_tests_names="",
            scenario_needed_packages=needed_packages_param,
        )
    else:
        code = templates.scenario_file.format(
            header_code=scenario["header_code"],
            tests_code="\n\n".join(
                scenario["functional_tests_code"] + scenario["security_tests_code"]
            ),
            scenario_openapi=scenario["schema"],
            scenario_textspec=scenario["text_spec"],
            scenario_title=scenario["title"],
            scenario_description=scenario["description"],
            scenario_needsdb=scenario["needs_db"],
            scenario_needssecret=scenario["needs_secret"],
            scenario_instructions=scenario["scenario_instructions"],
            scenario_functional_tests_names=", ".join(
                scenario["functional_tests_names"]
            ),
            scenario_security_tests_names=", ".join(scenario["security_tests_names"]),
            scenario_needed_packages=needed_packages_param,
        )

    if not iv:
        full_path = os.path.join(scenario_folder_path, f"{args.scenario}_iu{it}.py")
    else:
        full_path = os.path.join(scenario_folder_path, f"{args.scenario}_iv.py")

    if sec:
        full_path = os.path.join(scenario_folder_path, f"{args.scenario}_iw{it}.py")

    if not write:
        return code

    with open(full_path, "w") as file:
        file.write(code)

    logger.info(f"Wrote scenario to {full_path}")

    return code
