import os
import uuid

# import random
# import time
from abc import ABC, abstractmethod
from argparse import ArgumentParser

# from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime

parser = ArgumentParser()
parser.add_argument("--path", default="./artifacts/")
parser.add_argument("--scenario")

known_args, _ = parser.parse_known_args()
if known_args.scenario:
    token_usage_file = os.path.join(
        known_args.path, known_args.scenario, "token_usage.txt"
    )
else:
    token_usage_file = os.path.join(
        known_args.path, f"token_usage_{uuid.uuid4().hex}.txt"
    )


def record_token_usage(
    prompt_tokens, completion_tokens, model, thinking=False, purpose="N/A"
):
    with open(token_usage_file, "a") as f:
        f.write(
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {model=} {thinking=} {prompt_tokens=} {completion_tokens=} {purpose=}\n"
        )


@dataclass
class Response:

    role: str
    text: str
    reasoning: str = ""

    def __str__(self):
        return self.text


@dataclass
class Conversation:

    system_prompt: str = (
        "Act as an experienced software developer and provide clear, concise, and technically accurate responses."
    )
    responses: list[Response] = field(default_factory=list)

    def __str__(self):
        s = "### System Prompt ###\n"
        s += self.system_prompt + "\n\n"
        for response in self.responses:
            s += f"### {response.role} ###\n"
            s += response.text + "\n\n"
        return s

    def __iter__(self):
        return iter(self.responses)

    def __item__(self, i: int) -> Response:
        return self.responses[i]

    def add_message(self, r: Response):
        self.responses.append(r)
        return self

    def remove_message(self, index: int = -1) -> Response:
        if not self.responses:
            raise IndexError("No messages to remove")
        return self.responses.pop(index)


class BaseModel(ABC):

    def __init__(
        self,
        model_name: str,
        model_provider: str,
        reasoning: bool = False,
        reasoning_effort: int | str | None = None,
    ):
        self.model_name = model_name
        self.model_provider = model_provider
        self.reasoning = reasoning
        self.reasoning_effort = reasoning_effort

    @abstractmethod
    def _generate_chat(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        pass

    @abstractmethod
    def _generate_reason(
        self, conversation: Conversation, temperature: float, purpose: str
    ) -> Response:
        pass

    def generate(
        self, conversation: Conversation, temperature: float, purpose: str = "N/A"
    ) -> Response:

        if self.reasoning:
            response = self._generate_reason(conversation, temperature, purpose)
        else:
            response = self._generate_chat(conversation, temperature, purpose)
        return response

    def _conv_to_messages(
        self, conversation: Conversation, system: str | None
    ) -> list[dict[str, str]]:
        messages = []
        if system is not None:
            messages.extend([{"role": system, "content": conversation.system_prompt}])
        messages.extend(
            [
                {"role": response.role, "content": response.text}
                for response in conversation.responses
            ]
        )
        return messages

    # def generate_erb(
    #     self,
    #     conversation: Conversation,
    #     temperature: float,
    #     max_retries: int,
    #     base_delay: float,
    #     max_delay: float,
    # ) -> Response:
    #     retries = 0
    #     completion = Response(role="assistant", text="")
    #     while True:
    #         try:
    #             completion = self.generate(
    #                 conversation=conversation, temperature=temperature
    #             )
    #             break
    #         except Exception as e:
    #             retries += 1
    #             if retries > max_retries:
    #                 raise e
    #             delay = min(base_delay**2, max_delay)
    #             delay = random.uniform(0, delay)
    #             time.sleep(delay)
    #     return completion

    # def generate_batch_erb(
    #     self,
    #     batch_size: int,
    #     conversation: Conversation,
    #     temperature: float,
    #     max_retries: int,
    #     base_delay: float,
    #     max_delay: float,
    #     max_workers: int | None,
    # ) -> list[Response]:

    #     with ThreadPoolExecutor(max_workers=max_workers) as executor:
    #         return list(
    #             executor.map(
    #                 self.generate_erb,
    #                 [conversation] * batch_size,
    #                 [temperature] * batch_size,
    #                 [max_retries] * batch_size,
    #                 [base_delay] * batch_size,
    #                 [max_delay] * batch_size,
    #             )
    #         )
