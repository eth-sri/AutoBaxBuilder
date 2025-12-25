import keyword
import re
from pathlib import Path

import agent.templates as templates
from agent.config import args, logger, reasoning_model
from agent.utils import AgentException, agentic_loop
from models import Conversation, Response
from scenarios import all_scenarios


def scenario_idea_is_novel(scenario: dict) -> bool:
    """Checks if a scenario idea is novel compared to existing ones."""
    existing_scenarios = {
        f.name
        for f in Path(args.path).iterdir()
        if f.is_dir() and f.name != "fewshot_sec"
    } | {scenario.id for scenario in all_scenarios}

    prompt = templates.scenario_is_novel.format(
        title=scenario["title"],
        description=scenario["description"],
        existing_scenarios=", ".join(existing_scenarios),
    )
    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = reasoning_model.generate(
        conversation,
        temperature=0,
        purpose="generate_scenario_ideas: checking if scenario is novel",
    )
    if "yes" in response.text and "no" not in response.text:
        logger.info(f"scenario {scenario['title']} is a duplicate")
        return False
    elif "no" in response.text and "yes" not in response.text:
        logger.info(f"scenario {scenario['title']} is novel")
        return True
    else:
        logger.warning(
            f"inconclusive whether scenario {scenario['title']} is a duplicate"
        )
        return False


def make_identifier(s: str) -> str:
    s = re.sub(r"\W", "_", s)  # \W = anything not a letter, digit, underscore
    if re.match(r"^\d", s):
        s = "_" + s
    if keyword.iskeyword(s):  # python keywords
        s += "_"
    return s


def parse_scenario_idea(conversation: Conversation) -> dict:
    """Parses the scenario idea from the conversation."""
    match = re.search(
        r"<SCENARIO>\n- Scenario title: (.+?)\n- Scenario description: (.+?)\n- Persistent State: (.+?)\n- Needs Secret: (.+?)\n</SCENARIO>",
        conversation.responses[-1].text,
        re.DOTALL,
    )

    if match:
        parsed_scenario = {
            "title": make_identifier("".join(match.group(1).strip().split())),
            "description": match.group(2).strip(),
            "needs_db": match.group(3).strip().lower() == "true",
            "needs_secret": match.group(4).strip().lower() == "true",
        }
        return parsed_scenario
    else:
        raise AgentException("ParseError", "Could not parse scenario ideas")


def generate_scenario_idea() -> dict:
    """Generates a new scenario idea."""
    existing_scenarios = {
        f.name
        for f in Path(args.path).iterdir()
        if f.is_dir() and f.name != "fewshot_sec"
    } | {scenario.id for scenario in all_scenarios}

    prompt = templates.generate_scenario.format(
        scenario_template=templates.scenario_template,
        existing_scenarios=", ".join(existing_scenarios),
        endpoints=args.difficulty,
    )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = reasoning_model.generate(
        conversation,
        temperature=1,
        purpose="generate_scenario_ideas: generating scenario idea",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        parse_scenario_idea,
        args.N_RETRIES,
        "parsing scenario idea",
        templates.scenario_template,
    )
