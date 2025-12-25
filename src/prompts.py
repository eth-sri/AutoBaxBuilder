import logging
import os
import pathlib
import random
import re
import time
from enum import Enum
from typing import Any, cast, no_type_check

from anthropic import Anthropic
from anthropic.types import TextBlock
from openai import NOT_GIVEN, OpenAI
from openai.types.chat import ChatCompletionMessageParam

from env.base import Env
from models.base import record_token_usage
from scenarios.base import Scenario

_SYSTEM_PROMPT = "You are an experienced full-stack developer"


class KeyLocs(Enum):
    openai_key = "OPENAI_API_KEY"
    anthropic_key = "ANTHROPIC_API_KEY"
    together_key = "TOGETHER_API_KEY"
    openrouter_key = "OPENROUTER_API_KEY"


class Prompter:

    # NOTE: unused because Together expects you to set
    # max_tokens=context_length-numTokens(prompt)
    # so we hardcode below for now
    openai_together_context_lengths = {
        "mistralai/Mixtral-8x22B-Instruct-v0.1": 65536,
        "meta-llama/Llama-3.3-70B-Instruct-Turbo": 131072,
        "meta-llama/Llama-3.3-70B-Instruct-Turbo-Free": 8100,
        "deepseek-ai/DeepSeek-V3": 131072,
        "Qwen/Qwen2.5-Coder-32B-Instruct": 32768,
        "Qwen/Qwen2.5-72B-Instruct-Turbo": 32768,
        "Qwen/Qwen2.5-7B-Instruct-Turbo": 32768,
        "gpt-4o": 128000,
        "chatgpt-4o-latest": 128000,
        "gpt-4.1-2025-04-14": 32000,
        "gpt-4.1-mini-2025-04-14": 32000,
        "gpt-4.1": 200000,
        "o1": 200000,
        "o1-mini": 128000,
        "o3-mini": 200000,
        "o4-mini": 200000,
        "deepseek-ai/DeepSeek-R1": 164000,
        "google/gemma-2-27b-it": 8192,
        "deepseek-ai/DeepSeek-R1-Distill-Llama-70B": 131072,
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B": 131072,
        "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B": 131072,
        "Qwen/QwQ-32B": 32768,
        "qwen/qwq-32b": 128000,
        "meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8": 524288,
        "meta-llama/Llama-4-Scout-17B-16E-Instruct": 327680,
        "google/gemini-2.5-pro-preview-03-25": 65000,
        "mistralai/mistral-small-3.1-24b-instruct": 33000,
        "google/gemma-3-27b-it": 32000,
        "meta-llama/llama-4-scout": 32000,
        "deepseek/deepseek-chat-v3-0324": 16000,
        "mistral/ministral-8b": 128000,
        "x-ai/grok-3-beta": 128000,
        "x-ai/grok-3-mini-beta": 128000,
        "Qwen/Qwen3-235B-A22B-fp8-tput": 40000,
        "qwen/qwen3-235b-a22b": 40000,
        "deepseek/deepseek-r1-0528": 32000,
        "x-ai/grok-4": 256000,
        "qwen/qwen3-coder": 32000,
        "Qwen/Qwen3-Coder-480B-A35B-Instruct-FP8": 50000,
    }

    anthropic_thinking_lengths = {
        "claude-opus-4-20250514": 32000,
        "claude-sonnet-4-20250514": 64000,
        "claude-3-7-sonnet-20250219": 64000,
        "claude-sonnet-4-5-20250929": 32000,
        "claude-opus-4-1-20250805": 32000,
    }

    openai_max_completion_tokens = {
        "gpt-4o": 16384,
        "chatgpt-4o-latest": 16384,
        "o1": 100000,
        "o1-mini": 65536,
        "o3-mini": 100000,
        "gpt-4.1": 32768,
        "o3-2025-04-16": 100000,
        "o4-mini": 100000,
        "o4-mini-2025-04-16": 100000,
        "gpt-5-2025-08-07": 128000,
    }

    openrouter_remap = {
        "meta-llama/Llama-3.3-70B-Instruct-Turbo": "meta-llama/llama-3.3-70b-instruct",
        "deepseek-ai/DeepSeek-V3": "deepseek/deepseek-chat",
        "Qwen/Qwen2.5-Coder-32B-Instruct": "qwen/qwen-2.5-coder-32b-instruct",
        "Qwen/Qwen2.5-7B-Instruct-Turbo": "qwen/qwen-2.5-7b-instruct",
        "Qwen/Qwen2.5-72B-Instruct-Turbo": "qwen/qwen-2.5-72b-instruct",
        "Qwen/Qwen3-235B-A22B-fp8-tput": "qwen/qwen3-235b-a22b",
    }

    def __init__(
        self,
        env: Env,
        scenario: Scenario,
        model: str,
        spec_type: str,
        safety_prompt: str,
        batch_size: int,
        temperature: float,
        reasoning_effort: str,
        openrouter: bool,
    ):
        self.env = env
        self.scenario = scenario
        self.spec_type = spec_type
        self.safety_prompt = safety_prompt
        self.model = model
        self.batch_size = batch_size
        self.temperature = temperature
        self.reasoning_effort = reasoning_effort

        self.system_prompt = _SYSTEM_PROMPT
        self.openai_reasoning = (
            model.startswith("o1")
            or model.startswith("o3")
            or model.startswith("o4")
            or model.startswith("gpt-5")
        )
        self.anthropic = "claude" in model
        self.openai = self.openai_reasoning or "gpt" in self.model
        self.openrouter = openrouter and not (self.anthropic or self.openai)
        self.anthropic_thinking = model in self.anthropic_thinking_lengths

        self.prompt = self.scenario.build_prompt(
            self.env, self.spec_type, self.safety_prompt
        )

    @no_type_check
    def prompt_anthropic(self, logger: logging.Logger) -> list[str]:
        client = Anthropic(api_key=os.environ[KeyLocs.anthropic_key.value])
        try:
            if self.anthropic_thinking:
                text, thinking = "", ""
                with client.messages.stream(
                    model=self.model,
                    thinking={
                        "type": "enabled",
                        "budget_tokens": self.anthropic_thinking_lengths[self.model]
                        - 1,
                    },
                    messages=[
                        {"role": "user", "content": self.prompt},
                    ],
                    max_tokens=self.anthropic_thinking_lengths[self.model],
                ) as stream:
                    for event in stream:
                        if event.type == "content_block_delta":
                            if event.delta.type == "thinking_delta":
                                thinking += event.delta.thinking
                            elif event.delta.type == "text_delta":
                                text += event.delta.text
                logger.info(f"Thinking traces:\n {thinking}")
                return [text]
            else:
                response = client.messages.create(
                    model=self.model,
                    system=self.system_prompt,
                    messages=[
                        {"role": "user", "content": self.prompt},
                    ],
                    temperature=self.temperature,
                    max_tokens=8192 if "claude-3-5-" in self.model else 4096,
                )
                assert isinstance(response.content[0], TextBlock)
            if response.usage is not None:
                logger.info(
                    f"Token stats: {response.usage}; around {response.usage.output_tokens} completion tokens per completion"
                )
                record_token_usage(
                    response.usage.input_tokens,
                    response.usage.output_tokens,
                    self.model,
                    thinking=self.reasoning_effort,
                    purpose="baxbench: initial implementation generation",
                )
            if response.stop_reason == "max_tokens":
                logger.warning("Completion was cut off due to length.")
            return [response.content[0].text]
        except Exception as e:
            raise e

    @no_type_check
    def prompt_openrouter(self, logger: logging.Logger) -> list[str]:
        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ[KeyLocs.openrouter_key.value],
        )
        if self.model in self.openrouter_remap:
            open_router_model = self.openrouter_remap[self.model]
        else:
            open_router_model = self.model
        try:
            extra_body: None | Any = None
            if self.model == "qwen/qwq-32b":
                extra_body = {
                    "provider": {"ignore": ["Groq"]},
                }
            elif self.model == "google/gemma-3-27b-it":
                extra_body = {
                    "provider": {"ignore": ["DeepInfra", "InferenceNet", "Kluster"]},
                }
            elif self.model == "meta-llama/llama-4-scout":
                extra_body = {
                    "provider": {"ignore": ["DeepInfra", "Groq"]},
                }
            elif self.model == "deepseek/deepseek-chat-v3-0324":
                extra_body = {
                    "provider": {"ignore": ["DeepSeek"]},
                }
            else:
                extra_body = None
            if self.model == "x-ai/grok-3-mini-beta":
                extra_kwargs = {"reasoning_effort": "high"}
            else:
                extra_kwargs = {}
            response = client.chat.completions.create(
                model=open_router_model,
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": self.prompt},
                ],
                n=1,
                temperature=self.temperature,
                max_tokens=(
                    8192
                    if self.model not in Prompter.openai_together_context_lengths
                    else Prompter.openai_together_context_lengths[self.model] - 3000
                ),
                extra_body=extra_body,
                **extra_kwargs,
            )
            if response.choices is None:
                logger.error(f"Response was None: {response}")
                raise Exception("No content")
            content = response.choices[0].message.content
            if content is not None and len(content) > 0:
                if response.usage is not None:
                    logger.info(
                        f"Token stats: {response.usage}; around {response.usage.completion_tokens} completion tokens per completion"
                    )
                    record_token_usage(
                        response.usage.prompt_tokens,
                        response.usage.completion_tokens,
                        open_router_model,
                        thinking=self.reasoning_effort,
                        purpose="baxbench: initial implementation generation",
                    )
                else:
                    logger.info("Token stats unavailable")
                if response.choices[0].finish_reason == "length":
                    logger.warning("Completion was cut off due to length.")
                try:
                    logger.info(f"Inference provided by: {response.provider}")
                    logger.info(f"Inference id: {response.id}")
                except Exception:
                    pass
                return [content]
            else:
                raise Exception("No content")
        except Exception as e:
            raise e

    def prompt_openai_together_batch(self, logger: logging.Logger) -> list[str]:
        if self.openai:
            client = OpenAI(api_key=os.environ[KeyLocs.openai_key.value])
        else:
            client = OpenAI(
                api_key=os.environ[KeyLocs.together_key.value],
                base_url="https://api.together.xyz/v1",
            )
        try:
            # Prepare extra kwargs
            extra_kwargs: dict[str, Any] = {}
            if (
                self.model == "o1"
                or self.model.startswith("o3")
                or self.model.startswith("o4")
                or self.model.startswith("gpt-5")
            ):  # NOTE: o1-mini does not have this
                extra_kwargs["reasoning_effort"] = self.reasoning_effort
            if self.openai:
                extra_kwargs["max_completion_tokens"] = (
                    Prompter.openai_max_completion_tokens[self.model]
                )
            else:
                extra_kwargs["max_tokens"] = (
                    8192
                    if self.model not in Prompter.openai_together_context_lengths
                    else Prompter.openai_together_context_lengths[self.model] - 3000
                )
            # Prepare the message
            messages: list[Any] = []
            if (
                self.model == "o1"
                or self.model.startswith("o3")
                or self.model.startswith("o4")
                or self.model.startswith("gpt-5")
            ):
                messages.append(
                    cast(
                        ChatCompletionMessageParam,
                        {"role": "developer", "content": self.system_prompt},
                    )
                )
            elif self.model == "o1-mini":
                # No sysprompt
                pass
            else:
                messages.append(
                    cast(
                        ChatCompletionMessageParam,
                        {"role": "system", "content": self.system_prompt},
                    )
                )
            messages.append({"role": "user", "content": self.prompt})

            # Query
            completions = client.chat.completions.create(
                model=self.model,
                messages=messages,
                n=self.batch_size,
                temperature=(
                    self.temperature if not self.openai_reasoning else NOT_GIVEN
                ),
                **extra_kwargs,
            )
            if completions.usage is not None:
                logger.info(
                    f"Batch token stats: {completions.usage}; around {completions.usage.completion_tokens / self.batch_size:.2f} completion tokens per completion"
                )
                record_token_usage(
                    completions.usage.prompt_tokens,
                    completions.usage.completion_tokens,
                    self.model,
                    thinking=self.reasoning_effort,
                    purpose="baxbench: initial implementation generation",
                )
            else:
                logger.info("Batch token stats unavailable")
            responses = []
            for idx, choice in enumerate(completions.choices):
                if choice.finish_reason == "length":
                    logger.warning(f"Completion {idx} was cut off due to length.")
                if choice.message.content:
                    responses.append(choice.message.content)
            return responses

        except Exception as e:
            raise e

    @no_type_check
    def prompt_model(self, logger: logging.Logger) -> list[str]:
        if self.anthropic:
            return self.prompt_anthropic(logger)
        elif self.openrouter:
            return self.prompt_openrouter(logger)
        else:
            return self.prompt_openai_together_batch(logger)

    def prompt_model_batch_with_exp_backoff(
        self,
        max_retries: int,
        base_delay: float,
        max_delay: float,
        logger: logging.Logger,
    ) -> list[str]:
        # Anthropic and OpenRouter don't support batching, so we have to sample a single completion multiple times
        n_times_to_sample = self.batch_size if self.openrouter or self.anthropic else 1
        completions = []
        for _ in range(n_times_to_sample):
            retries = 0
            while True:
                try:
                    if retries > 0:
                        logger.info(f"Retrying {retries} times")
                    completion = self.prompt_model(logger)
                    completions.extend(completion)
                    break
                except Exception as e:
                    retries += 1
                    if retries > max_retries:
                        logger.error(f"Max retries reached, raising exception: {e}")
                        raise e
                    delay = min(base_delay * 2**retries, max_delay)
                    delay = random.uniform(0, delay)
                    logger.exception(
                        f"{e}, backing off for {delay} seconds", exc_info=e
                    )
                    time.sleep(delay)
        return completions


class Parser:

    def __init__(self, env: Env, logger: logging.Logger):
        self.env = env
        self.logger = logger

        self.fp_pattern = re.compile(r"<FILEPATH>(.+?)</FILEPATH>", re.DOTALL)
        self.fp_ht_pattern = re.compile(r"^###\s*(.+?)$", re.DOTALL | re.MULTILINE)
        self.md_pattern = re.compile(r"```(?!bash)\w+\n(.*?)\n```", re.DOTALL)
        self.code_pattern = re.compile(r"<CODE>(.+?)</CODE>", re.DOTALL)

    def _invalid(self, response: str) -> dict[pathlib.Path, str]:
        self.logger.warning("Format not found")
        return {pathlib.Path("failed"): "Format not found. Full response:\n" + response}

    def _clean(self, s: str) -> str:
        s = s.strip()
        if s.startswith("**"):
            s = s[2:]
        if s.endswith("**"):
            s = s[:-2]
        s = s.strip()
        return s

    def _parse_md(self, response: str) -> list[str]:
        return [self._clean(s) for s in self.md_pattern.findall(response)]

    def _parse_code(self, response: str) -> list[str]:
        return [self._clean(s) for s in self.code_pattern.findall(response)]

    def _parse_multi_file_response(self, response: str) -> dict[pathlib.Path, str]:
        normal_file_paths = [
            pathlib.Path(self._clean(s)) for s in self.fp_pattern.findall(response)
        ]
        # NOTE: asserts that these patterns 1) are not mixed with normal filepaths 2) are not mixed with titles
        ht_file_paths = [
            pathlib.Path(self._clean(s)) for s in self.fp_ht_pattern.findall(response)
        ]
        for file_paths in (
            normal_file_paths,
            ht_file_paths,
        ):
            code_snippets_md = self._parse_md(response)
            code_snippets_code = self._parse_code(response)
            self.logger.info("Trying MD parsing")
            if len(file_paths) == len(code_snippets_md) and len(file_paths) > 0:
                return {fp: c for fp, c in zip(file_paths, code_snippets_md)}
            elif len(file_paths) == len(code_snippets_code) and len(file_paths) > 0:
                self.logger.warning("MD format not found, trying CODE format")
                # failsave code parsing in case some of them have md and some not
                codes = []
                for code in code_snippets_code:
                    md_parsed = self._parse_md(code)
                    if len(md_parsed) > 0:
                        codes.append(md_parsed[0])
                    else:
                        codes.append(code)
                assert len(codes) == len(code_snippets_code)
                return {fp: c for fp, c in zip(file_paths, codes)}
        self.logger.warning(
            f"Both formats failed, lengths are: files {len(file_paths)}, md {len(code_snippets_md)}, code {len(code_snippets_code)}"
        )
        return self._invalid(response)

    def _parse_single_file_response(self, response: str) -> dict[pathlib.Path, str]:
        assert self.env.code_filename is not None
        code_snippets_md = self._parse_md(response)
        code_snippets_code = self._parse_code(response)
        self.logger.info("Trying MD parsing")
        if len(code_snippets_md) > 0:
            return {pathlib.Path(self.env.code_filename): code_snippets_md[0]}
        elif len(code_snippets_code) > 0:
            self.logger.warning("MD format not found, trying CODE format")
            return {pathlib.Path(self.env.code_filename): code_snippets_code[0]}
        else:
            self.logger.warning("Both formats failed")
            return self._invalid(response)

    def parse_response(self, response: str) -> dict[pathlib.Path, str]:
        if self.env.is_multi_file:
            return self._parse_multi_file_response(response)
        else:
            return self._parse_single_file_response(response)
