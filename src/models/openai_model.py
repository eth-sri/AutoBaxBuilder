# mypy: ignore-errors
import os

from openai import NOT_GIVEN, OpenAI

from models.base import BaseModel, Conversation, Response, record_token_usage


class OpenAIModel(BaseModel):

    context_lengths = {
        "gpt-4o": 128000,
        "chatgpt-4o-latest": 128000,
        "o1": 200000,
        "o1-mini": 128000,
        "o3-mini": 200000,
        "o4-mini": 200000,
        "gpt-4.1": 200000,
        "gpt-5": 400000,
    }

    max_completion_tokens = {
        "gpt-4o": 16384,
        "chatgpt-4o-latest": 16384,
        "o1": 100000,
        "o1-mini": 65536,
        "o3-mini": 100000,
        "o4-mini": 100000,
        "gpt-4.1": 32768,
        "gpt-5": 128000,
    }

    def __init__(
        self,
        model_name: str,
        model_provider: str,
        reasoning: bool = False,
        reasoning_effort: int | str | None = None,
    ):
        super().__init__(model_name, model_provider, reasoning, reasoning_effort)
        self.client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    def _generate_chat(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        completion = self.client.chat.completions.create(
            model=self.model_name,
            max_completion_tokens=self.max_completion_tokens.get(self.model_name, 8192),
            n=1,
            temperature=temperature,
            messages=self._conv_to_messages(conversation, system="system"),
        )
        if completion.usage is not None:
            record_token_usage(
                completion.usage.prompt_tokens,
                completion.usage.completion_tokens,
                self.model_name,
                thinking=False,
                purpose=purpose,
            )
        text = completion.choices[0].message.content
        if text is None or len(text) == 0:
            raise Exception("Empty response")
        else:
            return Response(role="assistant", text=text)

    def _generate_reason(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        if self.model_name == "o1-mini":
            messages = self._conv_to_messages(conversation, system=None)
        else:
            messages = self._conv_to_messages(conversation, system="developer")
        completion = self.client.chat.completions.create(
            model=self.model_name,
            max_completion_tokens=self.max_completion_tokens.get(self.model_name, 8192),
            n=1,
            messages=messages,
            reasoning_effort=(
                NOT_GIVEN if self.model_name == "o1-mini" else self.reasoning_effort
            ),
        )
        if completion.usage is not None:
            record_token_usage(
                completion.usage.prompt_tokens,
                completion.usage.completion_tokens,
                self.model_name,
                thinking=self.reasoning_effort,
                purpose=purpose,
            )
        text = completion.choices[0].message.content
        if len(text) == 0:
            raise Exception("Empty response")
        else:
            return Response(role="assistant", text=text)
