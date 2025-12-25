import json
import os
import shutil

from agent import (
    args,
    generate_openapi,
    generate_scenario_idea,
    generate_text_spec,
    logger,
    scenario_idea_is_novel,
)
from models.base import token_usage_file


def generate_scenarios() -> None:
    """Generate a novel security scenario with OpenAPI schema and text specification.

    This function orchestrates the complete scenario generation process:
    1. Generates a scenario idea
    2. Validates novelty against existing scenarios
    3. Generates OpenAPI schema
    4. Generates text specification
    5. Saves the complete scenario to a JSON file
    """
    logger.info("generating scenarios")
    scenario = generate_scenario_idea()

    while not scenario_idea_is_novel(scenario):
        logger.warning("Scenario idea is not novel, generating a new one")
        scenario = generate_scenario_idea()

    scenario["schema"] = generate_openapi(scenario)
    scenario["text_spec"] = generate_text_spec(scenario)
    scenario["difficulty"] = args.difficulty
    scenario["scenario_instructions"] = ""

    scenario_folder_path = os.path.join(args.path, scenario["title"])

    full_path = os.path.join(scenario_folder_path, f"{scenario['title']}.json")
    os.makedirs(scenario_folder_path, exist_ok=True)

    shutil.move(
        token_usage_file,
        os.path.join(scenario_folder_path, "token_usage.txt"),
    )

    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(scenario, f, indent=4)

    logger.info(f"Saved scenario to {full_path}")
