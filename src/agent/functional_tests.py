# flake8: noqa F821
# mypy: disable-error-code=name-defined
import json
import os
import pickle
from collections import defaultdict
from pathlib import Path, PosixPath

from agent import export_scenario_code
from agent.config import args, get_baxbench_args, logger, scenario_folder_path
from agent.generate_functional_tests import generate_tests_code, generate_tests_spec
from agent.iterate_functional_tests import iterate_blackbox, iterate_whitebox
from agent.utils import (
    clean_code,
    deep_update,
    load_code,
    save_code,
    test_and_evaluate_baxbench,
    visualize_baxbench_eval,
)
from baxbench_wrapper import main as run_baxbench
from models import Conversation


def augment_header_functional_test_signatures(header_code: str, test_code: str) -> str:
    """Augments the header code with necessary imports based on the test code."""
    if test_code is None:
        return header_code
    if "SCENARIO_FILE_PATH" in header_code or "SCENARIO_FILE_PATH" in test_code:
        header_code = "from scenario_files import SCENARIO_FILE_PATH\n" + header_code
    if "place_file_on_docker" in header_code or "place_file_on_docker" in test_code:
        header_code = "from exploits import place_file_on_docker\n" + header_code
    return header_code


def generate_and_iterate_tests() -> None:
    """Generates and iterates on functional tests for the scenario."""
    logger.info("generating tests")

    if os.path.exists(os.path.join(scenario_folder_path, f"{args.scenario}_iu0.json")):
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_iu0.json"),
            "r",
            encoding="utf-8",
        ) as file:
            scenario = json.load(file)
            code = export_scenario_code(scenario, write=False)
    else:
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}.json"),
            "r",
            encoding="utf-8",
        ) as file:
            scenario = json.load(file)
            conversation = Conversation()
            scenario["tests_spec"] = generate_tests_spec(scenario, conversation)
            (
                scenario["header_code"],
                scenario["functional_tests_code"],
                scenario["functional_tests_names"],
            ) = generate_tests_code(scenario, conversation)
            scenario["header_code"] = clean_code(
                augment_header_functional_test_signatures(
                    scenario["header_code"],
                    "\n".join(scenario["functional_tests_code"]),
                )
            )
            scenario["all_tests_names"] = scenario["functional_tests_names"]
            assert (
                len(scenario["functional_tests_code"])
                == len(scenario["functional_tests_names"])
                == len(scenario["tests_spec"])
            ), "Mismatch in functional tests specs vs code"
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_iu0.json"), "w"
        ) as file:
            json.dump(scenario, file, indent=4)

        code = export_scenario_code(scenario)

    exec(code, globals())

    if os.path.exists(
        os.path.join(scenario_folder_path, f"{args.scenario}_tasklist.json")
    ):
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_tasklist.json"), "r"
        ) as file:
            task_dict = json.load(file)
    else:
        task_list = run_baxbench(get_baxbench_args("generate"), [SCENARIO])
        task_dict = {
            f"{task.env.language} {task.env.framework} {task.model}": str(
                task.get_code_dir(Path("./results"), 0)
            )
            for task in task_list
        }
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_tasklist.json"), "w"
        ) as file:
            json.dump(task_dict, file, indent=4)

    implementations = {}
    if os.path.exists(
        os.path.join(scenario_folder_path, f"{args.scenario}_implementations_it0.json")
    ):
        with open(
            os.path.join(
                scenario_folder_path, f"{args.scenario}_implementations_it0.json"
            ),
            "r",
        ) as file:
            raw_implementations = json.load(file)
            implementations = {
                k: {PosixPath(path): code for path, code in v.items()}
                for k, v in raw_implementations.items()
            }
    else:
        for key, code_dir_str in task_dict.items():
            implementations[key] = load_code(code_dir_str)
        with open(
            os.path.join(
                scenario_folder_path, f"{args.scenario}_implementations_it0.json"
            ),
            "w",
        ) as file:
            json.dump(
                {
                    k: {str(path): code for path, code in v.items()}
                    for k, v in implementations.items()
                },
                file,
                indent=4,
            )

    if os.path.exists(
        os.path.join(scenario_folder_path, f"{args.scenario}_results_it0.json")
    ):
        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_results_it0.json"), "r"
        ) as file:
            full_results = json.load(file)
    else:
        full_results = test_and_evaluate_baxbench(SCENARIO)

        with open(
            os.path.join(scenario_folder_path, f"{args.scenario}_results_it0.json"), "w"
        ) as file:
            json.dump(full_results, file, indent=4)

    visualize_baxbench_eval(
        full_results,
        0,
        highlight_x=scenario["functional_tests_names"],
        x_axis_labels=scenario["all_tests_names"],
    )

    keys = list(task_dict.keys())
    for it in range(1, args.N_SOL_STEPS + 1):
        if os.path.exists(
            os.path.join(
                scenario_folder_path, f"{args.scenario}_implementations_it{it}.json"
            )
        ) and os.path.exists(
            os.path.join(scenario_folder_path, f"{args.scenario}_results_it{it}.json")
        ):
            with open(
                os.path.join(
                    scenario_folder_path,
                    f"{args.scenario}_implementations_it{it}.json",
                ),
                "r",
            ) as file:
                raw_implementations = json.load(file)
                implementations = {
                    k: {PosixPath(path): code for path, code in v.items()}
                    for k, v in raw_implementations.items()
                }

            with open(
                os.path.join(
                    scenario_folder_path, f"{args.scenario}_results_it{it}.json"
                ),
                "r",
            ) as file:
                deep_update(full_results, json.load(file))
        else:
            modified_implementations = []
            for key in keys:
                model_results = {
                    test: test_results[key]
                    for test, test_results in full_results.items()
                }
                new_implementation = iterate_blackbox(
                    scenario, key, model_results, implementations[key]
                )
                if new_implementation != implementations[key]:
                    implementations[key] = new_implementation
                    save_code(implementations[key], task_dict[key])
                    modified_implementations.append(key)
                else:
                    logger.info(f"Implementation {it} remains unchanged for {key}")
            if modified_implementations:
                logger.info(
                    f"Testing re-implementation {it} for {', '.join(modified_implementations)}"
                )

                deep_update(
                    full_results,
                    test_and_evaluate_baxbench(
                        SCENARIO, [key.split()[-1] for key in modified_implementations]
                    ),
                )

            with open(
                os.path.join(
                    scenario_folder_path,
                    f"{args.scenario}_implementations_it{it}.json",
                ),
                "w",
            ) as file:
                json.dump(
                    {
                        k: {str(path): code for path, code in v.items()}
                        for k, v in implementations.items()
                    },
                    file,
                    indent=4,
                )

            with open(
                os.path.join(
                    scenario_folder_path, f"{args.scenario}_results_it{it}.json"
                ),
                "w",
            ) as file:
                json.dump(full_results, file, indent=4)

            visualize_baxbench_eval(
                full_results,
                it,
                highlight_y=modified_implementations,
                x_axis_labels=scenario["all_tests_names"],
            )
            if not modified_implementations:
                logger.info("No modified implementations, blackbox iteration converged")
                break

    # this is used to cache the verdicts of the functional tests
    # (test, implementation) -> verdict
    # (test, "all") -> aggregated verdict
    # this is used to avoid extra LLM calls for cases that haven't changed across iterations
    verdict_cache: defaultdict[tuple[str, str], str] = defaultdict(str)
    for it in range(1, args.N_TEST_STEPS + 1):
        modified_tests = []
        modified_implementations = []
        modified_header = False

        if os.path.exists(
            os.path.join(scenario_folder_path, f"{args.scenario}_iu{it}.json")
        ):
            with open(
                os.path.join(scenario_folder_path, f"{args.scenario}_iu{it}.json"), "r"
            ) as file:
                scenario = json.load(file)
            modified_header = True  # s.t. the iteration doesn't stop prematurely since the else block below is skipped
        else:
            i = 0
            while i < len(scenario["functional_tests_names"]):
                test = scenario["functional_tests_names"][i]
                if test not in full_results:
                    i += 1
                    continue
                results = full_results[test]
                # if any(result["status"] == "failed" for result in results.values()):
                logger.info(f"Iterating functional tests for {test}")

                verdict, test_code, test_spec, modified_implementations = (
                    iterate_whitebox(
                        i, scenario, test, results, implementations, verdict_cache
                    )
                )
                if verdict == 0:  # cached verdict
                    pass
                elif verdict == 1:  # test is wrong
                    # Reset verdict cache entries for the modified/discarded test
                    for impl_key in keys:
                        verdict_cache[
                            (scenario["functional_tests_names"][i], impl_key)
                        ] = ""
                    verdict_cache[(scenario["functional_tests_names"][i], "all")] = ""
                    modified_tests.append(scenario["functional_tests_names"][i])

                    if test_code:  # test was fixed
                        scenario["functional_tests_code"][i] = test_code
                        scenario["tests_spec"][i] = test_spec
                    else:  # test was discarded
                        modified_tests.append(scenario["functional_tests_names"][i])
                        del scenario["functional_tests_code"][i]
                        del scenario["functional_tests_names"][i]
                        del scenario["tests_spec"][i]
                        continue
                elif (
                    modified_implementations
                ):  # i.e. verdict 2: test is correct PLUS impl changed

                    # reset verdict cache for modified implementations
                    for test_key in scenario["functional_tests_names"]:
                        verdict_cache[(test_key, "all")] = ""
                        for impl_key in modified_implementations:
                            verdict_cache[(test_key, impl_key)] = ""
                    break
                elif verdict == 3:  # more info needed
                    # Reset verdict cache entries for the augmented test
                    for impl_key in keys:
                        verdict_cache[
                            (scenario["functional_tests_names"][i], impl_key)
                        ] = ""
                    verdict_cache[(scenario["functional_tests_names"][i], "all")] = ""
                    scenario["functional_tests_code"][i] = test_code
                    modified_tests.append(scenario["functional_tests_names"][i])
                elif verdict == 4:
                    # Reset all verdict cache entries
                    for test_key in scenario["functional_tests_names"]:
                        for impl_key in keys:
                            verdict_cache[(test_key, impl_key)] = ""
                        verdict_cache[(test_key, "all")] = ""
                    scenario["header_code"] = test_code

                scenario["header_code"] = clean_code(
                    augment_header_functional_test_signatures(
                        scenario["header_code"], test_code
                    )
                )
                i += 1
            with open(
                os.path.join(scenario_folder_path, f"{args.scenario}_iu{it}.json"), "w"
            ) as file:
                json.dump(scenario, file, indent=4)

        # save/load implementations of current iteration
        if os.path.exists(
            os.path.join(
                scenario_folder_path, f"{args.scenario}_implementations_iu{it}.json"
            )
        ):
            with open(
                os.path.join(
                    scenario_folder_path, f"{args.scenario}_implementations_iu{it}.json"
                ),
                "r",
            ) as file:
                raw_implementations = json.load(file)
                implementations = {
                    k: {PosixPath(path): code for path, code in v.items()}
                    for k, v in raw_implementations.items()
                }
        else:
            for key, code_dir_str in task_dict.items():
                save_code(implementations[key], code_dir_str)
            with open(
                os.path.join(
                    scenario_folder_path, f"{args.scenario}_implementations_iu{it}.json"
                ),
                "w",
            ) as file:
                json.dump(
                    {
                        k: {str(path): code for path, code in v.items()}
                        for k, v in implementations.items()
                    },
                    file,
                    indent=4,
                )

        # save/load results of current iteration
        if os.path.exists(
            os.path.join(scenario_folder_path, f"{args.scenario}_results_iu{it}.json")
        ):
            with open(
                os.path.join(
                    scenario_folder_path, f"{args.scenario}_results_iu{it}.json"
                ),
                "r",
            ) as file:
                deep_update(full_results, json.load(file))
        else:
            code = export_scenario_code(scenario, it)
            exec(code, globals())

            deep_update(full_results, test_and_evaluate_baxbench(SCENARIO))

            with open(
                os.path.join(
                    scenario_folder_path, f"{args.scenario}_results_iu{it}.json"
                ),
                "w",
            ) as file:
                json.dump(full_results, file, indent=4)

        visualize_baxbench_eval(
            full_results,
            it,
            iu=True,
            highlight_x=modified_tests,
            highlight_y=modified_implementations,
            x_axis_labels=scenario["all_tests_names"],
        )

        if not modified_tests and not modified_implementations and not modified_header:
            logger.info(
                "No modified tests, implementations, or header, whitebox iteration converged"
            )
            break
