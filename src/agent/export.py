import importlib
import importlib.util
import os
import sys
from types import ModuleType

import agent.templates as templates
from agent.config import args, logger, scenario_folder_path


def exported_scenario_path(it: int = 0, iv: bool = False, sec: bool = False) -> str:
    if not iv:
        file_name = f"{args.scenario}_iu{it}.py"
    else:
        file_name = f"{args.scenario}_iv.py"

    if sec:
        file_name = f"{args.scenario}_iw{it}.py"

    return os.path.join(scenario_folder_path, file_name)


def load_exported_scenario_module(
    it: int = 0,
    iv: bool = False,
    sec: bool = False,
    target_globals: dict[str, object] | None = None,
) -> ModuleType:
    full_path = os.path.abspath(exported_scenario_path(it, iv, sec))
    module_dir = os.path.dirname(full_path)
    module_name = os.path.splitext(os.path.basename(full_path))[0]

    if not module_name.isidentifier():
        raise ValueError(f"Generated scenario module is not importable: {module_name}")

    if module_dir in sys.path:
        sys.path.remove(module_dir)
    sys.path.insert(0, module_dir)

    importlib.invalidate_caches()
    sys.modules.pop(module_name, None)

    spec = importlib.util.spec_from_file_location(module_name, full_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not import generated scenario module: {full_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    if target_globals is not None:
        target_globals.update(
            {
                name: value
                for name, value in vars(module).items()
                if not name.startswith("__")
            }
        )

    return module


def export_scenario_code(
    scenario: dict, it: int = 0, iv: bool = False, write: bool = True, sec: bool = False
) -> str:
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

    full_path = exported_scenario_path(it, iv, sec)

    if not write:
        return code

    with open(full_path, "w") as file:
        file.write(code)

    logger.info(f"Wrote scenario to {full_path}")

    return code
