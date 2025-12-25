"""Utility functions for AutoBaxBuilder.

This module provides various utility functions including:
- Agentic loop for error recovery
- Code formatting and cleaning
- BaxBench test execution and evaluation
- Visualization of test results
- File I/O operations for code
"""

import os
import pathlib
import sys
from datetime import datetime

import black
import isort
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

import agent.templates as templates
from agent.config import (
    args,
    get_baxbench_args,
    logger,
    reasoning_model,
    scenario_folder_path,
)
from baxbench_wrapper import main as run_baxbench
from models import Response


class AgentException(Exception):
    """Supports the implementation of fixing errors with an agentic loop"""

    def __init__(self, name, description):
        self.name = name
        self.description = description
        super().__init__(f"Error {name}: {description}")


def agentic_loop(
    conversation, f, N, action, format_requirements, model_=reasoning_model
):
    """
    Execute a retry loop with model-based error recovery.

    This function attempts to execute a validation function up to N times,
    prompting the model to fix errors when they occur.

    Invariant: f(conversation) must either return a valid result or raise an exception
    """

    logger.info(action)

    i = 0
    while i <= N:
        try:
            y = f(conversation)
        except Exception as e:
            logger.warning(e)
            record_verdict("Error", str(e))

            prompt = templates.fix_error.format(
                action=action,
                error=str(e),
                format=format_requirements,
            )
        else:
            logger.info(f"Successful in {action}")
            return y

        if i < N:
            logger.warning("retrying...")
            conversation.add_message(Response(role="user", text=prompt))
            response = model_.generate(
                conversation, temperature=0, purpose=f"utils: agentic loop for {action}"
            )
            conversation.add_message(response)
        i += 1
    logger.warning(conversation)
    logger.error("aborting...")
    sys.exit(f"Could not recover from error in {action}")


def visualize_baxbench_eval(
    test_results,
    it,
    iu=False,
    iw=False,
    iv=False,
    highlight_x=None,
    highlight_y=None,
    x_axis_labels=None,
):
    """Generate a heatmap visualization of BaxBench test results."""
    data = []

    for test, results in test_results.items():
        for key, result in results.items():
            lang, framework, model_name = key.split()
            data.append([lang + " " + framework, model_name, test, result["status"]])

    df = pd.DataFrame(data, columns=["Framework", "Model", "Test", "Result"])

    df["Framework_Model"] = df["Framework"] + "\n" + df["Model"]
    # Map results to numerical values with a wider range to ensure proper color mapping
    df["Result_Num"] = df["Result"].map({"passed": 2, "exception": 1, "failed": 0})

    df_pivot = df.pivot(index="Framework_Model", columns="Test", values="Result_Num")

    # If x_axis_labels is provided, ensure all expected test cases are present
    if x_axis_labels is not None:
        # Get all unique framework_model combinations
        framework_models = df_pivot.index.tolist()

        # Create a new DataFrame with all expected test cases, ensuring numeric dtype
        full_df_pivot = pd.DataFrame(
            index=framework_models, columns=x_axis_labels, dtype=float
        )

        # Fill in existing data
        for col in df_pivot.columns:
            if col in full_df_pivot.columns:
                full_df_pivot[col] = df_pivot[col]

        # Fill missing columns with NaN (which will appear as white in the heatmap)
        df_pivot = full_df_pivot

    # Use a color palette that ensures exceptions are always yellow
    cmap = sns.color_palette(["#ff4d4d", "#ffcc00", "#33cc33"])  # Red, Yellow, Green

    plt.figure(figsize=(12, 6))
    ax = sns.heatmap(
        df_pivot,
        cmap=cmap,
        cbar=False,
        square=True,
        linewidths=0.5,
        linecolor="black",
        xticklabels=True,
        yticklabels=True,
        annot=False,
        vmin=0,  # Ensure minimum value is 0
        vmax=2,  # Ensure maximum value is 2
        mask=df_pivot.isna(),  # Mask NaN values to show as white
    )

    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.title("Test Results")
    plt.xlabel("Test Cases")
    plt.ylabel("Framework & Model")

    # Add vertical divider between functional and security tests
    if x_axis_labels is not None:
        # Find the boundary between func_test and sec_test
        func_test_indices = []
        sec_test_indices = []

        for i, test_name in enumerate(x_axis_labels):
            if test_name.startswith("func_test"):
                func_test_indices.append(i)
            elif test_name.startswith("sec_test"):
                sec_test_indices.append(i)

        # If we have both types of tests, add a divider
        if func_test_indices and sec_test_indices:
            # Find the last functional test index
            last_func_index = max(func_test_indices)
            # Find the first security test index
            first_sec_index = min(sec_test_indices)

            # Add vertical line between the two sections
            # The line should be exactly between the last func test and first sec test
            divider_x = (last_func_index + first_sec_index) / 2.0

            # Get the y-axis limits
            y_min, y_max = ax.get_ylim()

            # Add a thick vertical line
            ax.axvline(
                x=divider_x,
                ymin=y_min,
                ymax=y_max,
                color="black",
                linewidth=3,
                alpha=0.8,
            )

            # Add some spacing by adjusting the x-axis limits slightly
            x_min, x_max = ax.get_xlim()
            ax.set_xlim(x_min - 0.1, x_max + 0.1)

    plt.tight_layout()

    if highlight_x:
        if isinstance(highlight_x, str):
            highlight_x = [highlight_x]  # allow single string
        xticklabels = ax.get_xticklabels()
        for label in xticklabels:
            if label.get_text() in highlight_x:
                label.set_fontweight("bold")
                label.set_color("navy")
                label.set_size(label.get_size() * 1.1)  # make slightly larger

    if highlight_y:
        if isinstance(highlight_y, str):
            highlight_y = [highlight_y]  # allow single string
        yticklabels = ax.get_yticklabels()
        for label in yticklabels:
            if label.get_text() in highlight_y:
                label.set_fontweight("bold")
                label.set_color("navy")
                label.set_size(label.get_size() * 1.1)  # make slightly larger

    if iu:
        suffix = "iu"
    elif iw:
        suffix = "iw"
    elif iv:
        suffix = "iv"
    else:
        suffix = "it"

    plt.savefig(
        os.path.join(
            scenario_folder_path,
            f"{args.scenario}_results_{suffix}{it}.png",
        )
    )
    plt.close()


def deep_update(original: dict, updates: dict) -> None:
    """Recursively update a nested dictionary with new values."""
    for key, value in updates.items():
        if isinstance(value, dict) and isinstance(original.get(key), dict):
            deep_update(original[key], value)
        else:
            original[key] = value


# version of tasks.py load_code which does not require task object
def load_code(code_dir_str: str) -> dict[pathlib.Path, str]:
    """Load all code files from a directory into a dictionary.

    This is a standalone version of tasks.py load_code that doesn't require a task object.
    """
    # code_dir = self.get_code_dir(results_dir, sample)
    code_dir = pathlib.Path(code_dir_str)
    files: dict[pathlib.Path, str] = {}
    for root, _, file_names in os.walk(code_dir):
        for file in file_names:
            abs_path = pathlib.Path(root) / file
            with open(abs_path, "r") as f:
                content = f.read()
            rel_path = abs_path.relative_to(code_dir)
            files[rel_path] = content
    return files


# version of tasks.py save_code which does not require task object
def save_code(files: dict[pathlib.Path, str], code_dir_str: str) -> None:
    """Save code files from a dictionary to a directory.

    This is a standalone version of tasks.py save_code that doesn't require a task object.
    """
    # code_dir = self.get_code_dir(results_dir, sample)
    code_dir = pathlib.Path(code_dir_str)
    code_dir.mkdir(parents=True, exist_ok=True)
    for path, code in files.items():
        full_path = code_dir / path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with open(full_path, "w") as f:
            f.write(code)


def test_and_evaluate_baxbench(SCENARIO, model_list_test=None):
    """Run BaxBench tests and evaluation for a scenario.

    Args:
        SCENARIO: Scenario object to test
        model_list_test: Optional list of models to test with (default: uses config)

    Returns:
        Full evaluation results from BaxBench
    """
    if model_list_test:
        run_baxbench(get_baxbench_args("test", model_list=model_list_test), [SCENARIO])
    else:
        run_baxbench(get_baxbench_args("test"), [SCENARIO])

    full_results = run_baxbench(get_baxbench_args("evaluate"), [SCENARIO])
    return full_results


def clean_code(code: str) -> str:
    """Format and clean Python code using isort and black."""
    # red = RedBaron(code)
    # # Remove all comments
    # for comment in red.find_all("CommentNode"):
    #     comment.parent.remove(comment)
    # code = red.dumps()
    code = isort.code(code)
    try:
        code = black.format_str(code, mode=black.FileMode())
    except black.parsing.InvalidInput as e:  # parse error
        logger.warning(
            f"Black could not parse code, returning unformatted: {e}\n{code}"
        )
        return code
    return code


def record_verdict(message: str, verdict: str) -> None:
    """Record a verdict message to the verdicts log file."""
    with open(os.path.join(scenario_folder_path, "verdicts.txt"), "a") as f:
        f.write(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {message=} {verdict=}\n"
        )
