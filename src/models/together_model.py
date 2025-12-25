import os
import re

from together import Together

from models.base import BaseModel, Conversation, Response, record_token_usage


class TogetherModel(BaseModel):

    max_tokens = {
        "mistralai/Mixtral-8x22B-Instruct-v0.1": 65536,
        "meta-llama/Llama-3.3-70B-Instruct-Turbo": 131072,
        "deepseek-ai/DeepSeek-V3": 131072,
        "Qwen/Qwen2.5-Coder-32B-Instruct": 32768,
        "Qwen/Qwen2.5-72B-Instruct-Turbo": 32768,
        "Qwen/Qwen2.5-7B-Instruct-Turbo": 32768,
        "deepseek-ai/DeepSeek-R1": 164000,
        "google/gemma-2-27b-it": 8192,
        "deepseek-ai/DeepSeek-R1-Distill-Llama-70B": 131072,
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B": 131072,
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B": 131072,
        "qwen/qwen3-coder": 128000,
    }

    def __init__(
        self,
        model_name: str,
        model_provider: str,
        reasoning: bool = False,
        reasoning_effort: int | str | None = None,
    ):
        super().__init__(model_name, model_provider, reasoning, reasoning_effort)
        self.client = Together(api_key=os.environ["TOGETHER_API_KEY"])

    def _generate_chat(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        max_tokens = self.max_tokens.get(self.model_name, 8192) - 2000
        completion = self.client.chat.completions.create(
            model=self.model_name,
            max_tokens=max_tokens,
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
            n=1,
            temperature=temperature,
            messages=self._conv_to_messages(conversation, system="system"),
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
            reasoning, text = self._parse_reasoning(text)
            return Response(role="assistant", text=text, reasoning=reasoning)
