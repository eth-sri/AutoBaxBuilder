# mypy: ignore-errors
import os
import re

from openai import OpenAI

from models.base import BaseModel, Conversation, Response, record_token_usage


class OpenRouterModel(BaseModel):

    max_tokens: dict[str, int] = {}

    def __init__(
        self,
        model_name: str,
        model_provider: str,
        reasoning: bool = False,
        reasoning_effort: int | str | None = None,
    ):
        super().__init__(model_name, model_provider, reasoning, reasoning_effort)
        self.client = OpenAI(
            api_key=os.environ["OPENROUTER_API_KEY"],
            base_url="https://openrouter.ai/api/v1",
        )

    def _generate_chat(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        max_tokens = self.max_tokens.get(self.model_name, 8192) - 2000
        completion = self.client.chat.completions.create(
            model=self.model_name,
            max_tokens=max_tokens,
            temperature=temperature,
            n=1,
            messages=self._conv_to_messages(conversation, system="system"),
        )
        if completion.choices is None:
            raise Exception("Empty response")
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

    def _parse_reasoning(self, text: str) -> tuple[str, str]:
        reasoning_pattern = r"<think>(.*?)</think>"
        match = re.search(reasoning_pattern, text, re.DOTALL)
        if match:
            reasoning = match.group(1).strip()
            rest_text = text[match.end() :]
            return reasoning, rest_text
        else:
            return "", text

    def _generate_reason(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        max_tokens = self.max_tokens.get(self.model_name, 8192) - 2000
        completion = self.client.chat.completions.create(
            model=self.model_name,
            max_tokens=max_tokens,
            temperature=temperature,
            n=1,
            messages=self._conv_to_messages(conversation, system="system"),
        )
        if completion.choices is None:
            raise Exception("Empty response")
        if completion.usage is not None:
            record_token_usage(
                completion.usage.prompt_tokens,
                completion.usage.completion_tokens,
                self.model_name,
                thinking=self.reasoning_effort,
                purpose=purpose,
            )

        text = completion.choices[0].message.content
        if text is not None:
            reasoning, text = self._parse_reasoning(text)
        if text is None or len(text) == 0:
            raise Exception("Empty response")
        else:
            return Response(role="assistant", text=text, reasoning=reasoning)
