import re

import yaml
from openapi_spec_validator import validate

import agent.templates as templates
from agent.config import args, reasoning_model
from agent.utils import AgentException, agentic_loop
from models import Conversation, Response


def extract_yaml(schema_text: str) -> str:
    """Extracts YAML content from a schema text block."""
    match = re.search(r"<SCHEMA>\s*```(.*?)```\s*</SCHEMA>", schema_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    raise AgentException(
        "FormatError",
        "failed to parse the OpenAPI schema, adhere to the required format.",
    )


def validate_openapi(conversation: Conversation) -> str:
    """Validates the OpenAPI schema from the conversation."""
    if (schema := extract_yaml(conversation.responses[-1].text)) is not None:
        spec_dict = yaml.safe_load(schema)
        validate(spec_dict)
        return schema
    else:  # format error
        raise AgentException(
            "FormatError", "failed to parse the OpenAPI, adhere to the required format."
        )


def generate_openapi(scenario: dict) -> str:
    """Generates an OpenAPI schema for the given scenario."""
    scenario_spec = templates.scenario_spec.format(
        title=scenario["title"],
        description=scenario["description"],
        needs_db=scenario["needs_db"],
        needs_secret=scenario["needs_secret"],
    )

    prompt = templates.generate_openapi.format(
        scenario_template=templates.scenario_template,
        example_spec=templates.example_spec,
        example_openapi=templates.example_openapi,
        scenario_spec=scenario_spec,
    )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = reasoning_model.generate(
        conversation,
        temperature=0,
        purpose="generate_scenario_specs: generating OpenAPI schema",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        validate_openapi,
        args.N_RETRIES,
        "validating the OpenAPI schema",
        templates.schema_format,
    )


def parse_text_spec(conversation: Conversation) -> str:
    """Parses the textual specification from the conversation."""
    match = re.search(
        r"<TEXT>\s*(.*?)\s*</TEXT>", conversation.responses[-1].text, re.DOTALL
    )
    if match:
        return match.group(1).strip()
    raise AgentException(
        "FormatError", "failed to parse the text spec, adhere to the required format."
    )


def generate_text_spec(scenario: dict) -> str:
    """Generates a textual specification for the given scenario."""
    prompt = templates.generate_text_spec.format(
        scenario_template_with_openapi=templates.scenario_template_with_openapi,
        example_title=templates.example_title,
        example_description=templates.example_description,
        example_openapi=templates.example_openapi,
        example_text_spec=templates.example_text_spec,
        scenario_title=scenario["title"],
        scenario_description=scenario["description"],
        scenario_openapi=scenario["schema"],
    )

    conversation = Conversation().add_message(Response(role="user", text=prompt))
    response = reasoning_model.generate(
        conversation,
        temperature=0,
        purpose="generate_scenario_specs: generating textual specification",
    )
    conversation.add_message(response)

    return agentic_loop(
        conversation,
        parse_text_spec,
        args.N_RETRIES,
        "parsing the textual specification",
        templates.text_spec_format,
    )
