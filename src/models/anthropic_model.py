# mypy: ignore-errors
import os
from typing import cast

from anthropic import Anthropic
from anthropic.types import TextBlock

from models.base import BaseModel, Conversation, Response, record_token_usage


class AnthropicModel(BaseModel):

    max_completion_tokens = {
        "claude-3-7-sonnet-20250219": 16384,
        "claude-3-5-sonnet-latest": 8192,
        "claude-3-5-sonnet-20241022": 8192,
        "claude-3-5-sonnet-20240620": 8192,
        "claude-3-5-haiku-20241022": 8192,
        "claude-3-opus-20240229": 4096,
        "claude-3-haiku-20240307": 4096,
        "claude-4-sonnet-20250514": 16384,
        "claude-sonnet-4-5-20250929": 20000,
    }

    max_reasoning_tokens = {
        "claude-3-7-sonnet-20250219": 64000,
        "claude-4-sonnet-20250514": 10000,
        "claude-sonnet-4-5-20250929": 10000,
    }

    def __init__(
        self,
        model_name: str,
        model_provider: str,
        reasoning: bool = False,
        reasoning_effort: int | str | None = None,
    ):
        super().__init__(model_name, model_provider, reasoning, reasoning_effort)
        self.client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        if self.reasoning and not isinstance(self.reasoning_effort, int):
            raise ValueError(
                "Anthropic models require reasoning settings as a number of reasoning tokens."
            )

    def _generate_chat(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        completion = self.client.messages.create(
            model=self.model_name,
            system=conversation.system_prompt,
            max_tokens=self.max_completion_tokens.get(self.model_name, 4096),
            temperature=temperature,
            messages=self._conv_to_messages(conversation, system=None),
        )
        if completion.usage is not None:
            record_token_usage(
                completion.usage.input_tokens,
                completion.usage.output_tokens,
                self.model_name,
                thinking=False,
                purpose=purpose,
            )

        if isinstance(completion.content[0], TextBlock):
            text = completion.content[0].text
            if not text or len(text.strip()) == 0:
                raise Exception("Empty response from Anthropic API")
            return Response(role="assistant", text=text)
        else:
            raise TypeError(
                "Completion content is not a TextBlock. This could be caused by API issues."
            )

    # NOTE: This method relies on the beta API of Claude. Needs to be updated when the API is stable.
    def _generate_reason(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        reasoning, text = "", ""

        response = self.client.messages.create(
            model=self.model_name,
            max_tokens=self.max_completion_tokens.get(self.model_name, 16384),
            thinking={
                "type": "enabled",
                "budget_tokens": min(
                    self.max_reasoning_tokens.get(self.model_name, 10000),
                    cast(int, self.reasoning_effort),
                ),
            },
            messages=self._conv_to_messages(conversation, system=None),
        )

        for block in response.content:
            if block.type == "text":
                text += block.text
            elif block.type == "thinking":
                reasoning += block.thinking
            else:
                assert False, f"Unhandled block type: {block.type}"

        record_token_usage(
            response.usage.input_tokens,
            response.usage.output_tokens,
            self.model_name,
            thinking=self.reasoning_effort,
            purpose=purpose,
        )

        # with self.client.beta.messages.create(
        #     model=self.model_name,
        #     max_tokens=self.max_completion_tokens.get(self.model_name, 16384),
        #     thinking={
        #         "type": "enabled",
        #         "budget_tokens": min(
        #             self.max_reasoning_tokens.get(self.model_name, 10000),
        #             cast(int, self.reasoning_effort),
        #         ),
        #     },
        #     messages=self._conv_to_messages(conversation, system=None),
        #     betas=["output-128k-2025-02-19"],
        #     stream=True,
        # ) as stream:
        #     for event in stream:
        #         if event.type == "content_block_delta":
        #             if event.delta.type == "thinking_delta":
        #                 reasoning += event.delta.thinking
        #             elif event.delta.type == "text_delta":
        #                 text += event.delta.text

        if not text or len(text.strip()) == 0:
            raise Exception("Empty response from Anthropic API")
        return Response(role="assistant", text=text, reasoning=reasoning)
