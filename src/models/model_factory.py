from models.anthropic_model import AnthropicModel
from models.base import BaseModel
from models.openai_model import OpenAIModel
from models.openrouter_model import OpenRouterModel
from models.together_model import TogetherModel


def get_model(
    model_name: str,
    model_provider: str,
    reasoning: bool = False,
    reasoning_effort: int | str | None = None,
) -> BaseModel:
    if model_provider == "openai":
        if reasoning and isinstance(reasoning_effort, int):
            raise TypeError("OpenAI models do not support token numbers for reasoning.")
        return OpenAIModel(model_name, model_provider, reasoning, reasoning_effort)
    elif model_provider == "together":
        if reasoning and reasoning_effort is not None:
            raise TypeError("Together models do not support reasoning effort settings.")
        return TogetherModel(model_name, model_provider, reasoning, reasoning_effort)
    elif model_provider == "openrouter":
        if reasoning and reasoning_effort is not None:
            raise TypeError(
                "OpenRouter models do not support reasoning effort settings."
            )
        return OpenRouterModel(model_name, model_provider, reasoning, reasoning_effort)
    elif model_provider == "anthropic":
        if reasoning and isinstance(reasoning_effort, str):
            raise TypeError(
                "Anthropic models require reasoning settings as a number of reasoning tokens."
            )
        return AnthropicModel(model_name, model_provider, reasoning, reasoning_effort)
    else:
        raise NotImplementedError(
            f"Model {model_name} from {model_provider} with reasoning effort {reasoning_effort} is not supported."
        )
