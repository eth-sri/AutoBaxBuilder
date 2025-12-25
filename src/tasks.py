import concurrent.futures

# import inspect
import json
import logging
import math
import multiprocessing
import multiprocessing.managers
import os
import pathlib
import shutil
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from sys import exc_info
from typing import Any, Generator, Self, cast

import requests
import tqdm
from docker.models.containers import Container

import cwes as cwe
from env.base import COMMON_DOCKER_RUN_COMMANDS, Env
from prompts import Parser, Prompter  # type: ignore
from scenarios.base import AppInstance, FunctionalTest, Scenario, SecurityTest


def preprocess_log(log_string):
    # strip and truncate
    log_string = log_string.strip()
    MAX_LOG_LENGTH = 2000
    if len(log_string) > MAX_LOG_LENGTH:
        log_string = (
            log_string[:MAX_LOG_LENGTH]
            + "\n\n[...log truncated: output exceeds 2000 characters...]"
        )
    return log_string


def esc(s: str) -> str:
    return s.replace("/", "-")


def run_test_with_timeout(
    f: SecurityTest | FunctionalTest, app_instance: AppInstance, timeout: int
) -> Any:
    with multiprocessing.Pool(processes=1) as pool:
        async_result = pool.apply_async(f, [app_instance])
        try:
            return async_result.get(timeout=timeout)
        except multiprocessing.TimeoutError:
            pool.terminate()
            raise TimeoutError("Functional test timed out")


@dataclass
class ContainerRunner:
    env: Env
    port_manager: "SlotManager"
    image_id: str
    logger: logging.Logger
    container_logs_ref: list[str]  # Mutable reference to container logs
    _container: Container | None = None
    _port: int | None = None

    def __enter__(self) -> Self:
        while self._port is None:
            self._port = self.port_manager.acquire_slot()
            time.sleep(0.1)
        try:
            self._container = self.env.run_docker_container(self.image_id, self._port)
        except Exception as e:
            self.logger.exception("could not start container %s", e, exc_info=e)
            raise ValueError("Could not start docker container")
        self.logger.info("started container, port=%d", self._port)

        # make sure that the server is online before we process, otherwise let it fail
        start = time.time()
        while True:
            try:
                response = requests.get(f"http://localhost:{self._port}")
                self.logger.info("Server is up! Server response: %s", response)
                break
            except requests.ConnectionError as e:
                self.logger.warning("Server is not up yet: %s", e)
            if time.time() - start > self.env.wait_to_start_time:
                self.logger.error("Server did not start in time")
                self.__exit__(*exc_info())
            self.logger.info("Waiting for server to start...")
            time.sleep(1.0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        assert self.container is not None
        assert self._port is not None
        container_logs = cast(
            bytes, self.container.logs(stdout=True, stderr=True, follow=False)
        ).decode()
        self.logger.info("container logs:\n%s", container_logs)
        # Update the mutable reference
        self.container_logs_ref[0] = container_logs
        self.container.remove(force=True)
        self.port_manager.release_slot(self._port)
        self.logger.info("-" * 100)
        self.logger.info("removed container")
        self.logger.info("-" * 100)

    @property
    def port(self) -> int:
        assert self._port is not None
        return self._port

    @property
    def container(self) -> Container:
        assert self._container is not None
        return self._container


@dataclass
class ContainerRunnerWithCode:
    env: Env
    port_manager: "SlotManager"
    base_image_id: str
    files: dict[pathlib.Path, str]
    logger: logging.Logger
    container_logs_ref: list[str]  # Mutable reference to container logs
    scenario: "Scenario"
    _container: Container | None = None
    _port: int | None = None

    def __enter__(self) -> Self:
        while self._port is None:
            self._port = self.port_manager.acquire_slot()
            time.sleep(0.1)
        try:
            self._container = self.env.run_docker_container_with_code(
                self.base_image_id, self.files, self._port, self.logger, []
            )
        except Exception as e:
            self.logger.exception(
                "could not start container with code %s", e, exc_info=e
            )
            raise ValueError("Could not start docker container with code")
        self.logger.info("started container with mounted code, port=%d", self._port)

        # make sure that the server is online before we process, otherwise let it fail
        start = time.time()
        while True:
            try:
                response = requests.get(f"http://localhost:{self._port}")
                self.logger.info("Server is up! Server response: %s", response)
                break
            except requests.ConnectionError as e:
                self.logger.warning("Server is not up yet: %s", e)
            if time.time() - start > self.env.wait_to_start_time:
                self.logger.error("Server did not start in time")
                self.__exit__(*exc_info())
            self.logger.info("Waiting for server to start...")
            time.sleep(1.0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        assert self.container is not None
        assert self._port is not None
        container_logs = cast(
            bytes, self.container.logs(stdout=True, stderr=True, follow=False)
        ).decode()
        self.logger.info("container logs:\n%s", container_logs)
        # Update the mutable reference
        self.container_logs_ref[0] = container_logs
        self.container.remove(force=True)
        self.port_manager.release_slot(self._port)
        self.logger.info("-" * 100)
        self.logger.info("removed container")
        self.logger.info("-" * 100)

    @property
    def port(self) -> int:
        assert self._port is not None
        return self._port

    @property
    def container(self) -> Container:
        assert self._container is not None
        return self._container


@dataclass
class Task:
    env: Env
    scenario: Scenario
    model: str
    temperature: float
    reasoning_effort: str
    spec_type: str
    safety_prompt: str
    openrouter: bool

    @property
    def id(self) -> str:
        return f"{self.model}-{self.env.id}-{self.scenario.id}-{self.spec_type}-{self.safety_prompt}-{self.temperature}"

    @contextmanager
    def create_logger(
        self, logfile_path: pathlib.Path
    ) -> Generator[logging.Logger, None, None]:
        logger = logging.getLogger(self.id)
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        logger.propagate = False
        logfile_handler = logging.FileHandler(logfile_path, mode="w")
        logfile_handler.setLevel(logging.INFO)
        logfile_handler.setFormatter(
            logging.Formatter(fmt="%(levelname)s %(asctime)s %(message)s")
        )
        logger.addHandler(logfile_handler)
        try:
            yield logger
        finally:
            logfile_handler.close()

    def get_save_dir(self, results_dir: pathlib.Path) -> pathlib.Path:
        save_dir = (
            results_dir
            / esc(self.model)
            / esc(self.scenario.id)
            / esc(self.env.id)
            / f"temp{float(self.temperature)}-{esc(self.spec_type)}-{esc(self.safety_prompt)}"
        )
        return save_dir

    def get_sample_dir(self, results_dir: pathlib.Path, sample: int) -> pathlib.Path:
        return self.get_save_dir(results_dir) / f"sample{sample}"

    def get_code_dir(self, results_dir: pathlib.Path, sample: int) -> pathlib.Path:
        return self.get_sample_dir(results_dir, sample) / "code"

    def get_test_results_json_path(
        self, results_dir: pathlib.Path, sample: int
    ) -> pathlib.Path:
        return self.get_sample_dir(results_dir, sample) / "test_results.json"

    def load_code(
        self, results_dir: pathlib.Path, sample: int
    ) -> dict[pathlib.Path, str]:
        code_dir = self.get_code_dir(results_dir, sample)
        files: dict[pathlib.Path, str] = {}
        for root, _, file_names in os.walk(code_dir):
            for file in file_names:
                abs_path = pathlib.Path(root) / file
                with open(abs_path, "r") as f:
                    content = f.read()
                rel_path = abs_path.relative_to(code_dir)
                files[rel_path] = content
        return files

    def save_code(
        self, files: dict[pathlib.Path, str], results_dir: pathlib.Path, sample: int
    ) -> None:
        code_dir = self.get_code_dir(results_dir, sample)
        code_dir.mkdir(parents=True, exist_ok=True)
        for path, code in files.items():
            full_path = code_dir / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with open(full_path, "w") as f:
                f.write(code)

    def save_test_results(
        self, results: "TestResult", results_dir: pathlib.Path, sample: int
    ) -> None:
        sample_dir = self.get_sample_dir(results_dir, sample)
        sample_dir.mkdir(parents=True, exist_ok=True)
        test_result_path = self.get_test_results_json_path(results_dir, sample)
        with open(test_result_path, "w") as f:
            json.dump(results.to_dict(), f, indent=4)

    def generate_code(
        self,
        results_dir: pathlib.Path,
        batch_size: int,
        max_retries: int,
        base_delay: float,
        max_delay: float,
        force: bool,
        openrouter: bool,
    ) -> None:
        # check if this task has already been generated
        if (
            all(
                [
                    self.get_code_dir(results_dir, sample).exists()
                    for sample in range(batch_size)
                ]
            )
            and not any(
                [
                    (self.get_code_dir(results_dir, sample) / "failed").exists()
                    for sample in range(batch_size)
                ]
            )
            and not force
        ):
            return

        save_dir = self.get_save_dir(results_dir)
        try:
            save_dir.mkdir(parents=True, exist_ok=False)
        except Exception:
            shutil.rmtree(save_dir)
            save_dir.mkdir(parents=True, exist_ok=False)

        gen_logfile_path = save_dir / "gen.log"
        # clear the log file
        with open(gen_logfile_path, "w") as f:
            f.write("")
        with self.create_logger(gen_logfile_path) as logger:
            logger.info(
                "generating %s code samples at temp %s for task %s with reasoning effort %s",
                batch_size,
                self.temperature,
                self.id,
                self.reasoning_effort,
            )

            prompter = Prompter(
                env=self.env,
                scenario=self.scenario,
                model=self.model,
                spec_type=self.spec_type,
                safety_prompt=self.safety_prompt,
                batch_size=batch_size,
                temperature=self.temperature,
                reasoning_effort=self.reasoning_effort,
                openrouter=openrouter,
            )
            logger.info("built prompt:\n%s", prompter.prompt)
            logger.info("-" * 100)

            try:
                model_responses = prompter.prompt_model_batch_with_exp_backoff(
                    max_retries=max_retries,
                    base_delay=base_delay,
                    max_delay=max_delay,
                    logger=logger,
                )
            except KeyboardInterrupt:
                raise
            except Exception as e:
                logger.exception("got exception:\n%s", str(e), exc_info=e)
                return

            logger.info(
                "got model responses:\n%s",
                "\n\n<<<RESPONSE DELIM>>>\n\n".join(model_responses),
            )
            logger.info("-" * 100)

            file_contents = [
                Parser(self.env, logger).parse_response(r) for r in model_responses
            ]

            for i, files in enumerate(file_contents):
                try:
                    self.save_code(files, results_dir, i)
                    logger.info("saved code sample %d", i)
                except Exception as e:
                    logger.exception("got exception:\n%s", str(e), exc_info=e)
                logger.info("-" * 80)

    def test_code(  # noqa: C901
        self,
        results_dir: pathlib.Path,
        samples: list[int],
        port_manager: "SlotManager",
        timeout: int,
        force: bool,
    ) -> None:
        # clean the directory from test artifacts if entered by force
        if force:
            for sample in samples:
                sample_dir = self.get_sample_dir(results_dir, sample)
                if sample_dir.exists():
                    for extension in ("*.log", "*.json"):
                        for file_path in sample_dir.glob(extension):
                            if file_path.is_file():
                                file_path.unlink()
        for sample in samples:
            sample_dir = self.get_sample_dir(results_dir, sample)
            if not self.get_code_dir(results_dir, sample).exists():
                continue
            if (
                self.get_test_results_json_path(results_dir, sample).exists()
                and not force
            ):
                continue
            self.get_test_results_json_path(results_dir, sample).unlink(missing_ok=True)
            log_file = sample_dir / "test.log"
            with self.create_logger(log_file) as logger:
                files: dict[pathlib.Path, str] = self.load_code(results_dir, sample)
                try:
                    # Build or get cached base image (without scenario-specific packages)
                    base_image_id = self.env.build_base_image(
                        COMMON_DOCKER_RUN_COMMANDS,
                        logger,
                    )
                    logger.info(f"Using base image: {str(base_image_id)}")
                except Exception as e:
                    logger.exception(
                        f"Failed to build base image: {str(e)}", exc_info=e
                    )
                    result = TestResult()
                    for ft in self.scenario.functional_tests:
                        result.record_ft_result(
                            name=ft.__name__,
                            passed=False,
                            had_exception=True,
                            container_logs="",
                            test_logs="",
                        )
                    for st in self.scenario.security_tests:
                        result.record_st_result(
                            cwes=None, name=st.__name__, container_logs="", test_logs=""
                        )
                    logger.info(
                        f"Finished testing sample {sample}, which failed to build base image"
                    )
                    self.save_test_results(result, results_dir, sample)
                    logger.info("Saved test results")
                    logger.info("-" * 100)
                    continue

                logger.info("Base image ready: %s", base_image_id)
                logger.info("-" * 100)

                result = TestResult()
                for ft in self.scenario.functional_tests:
                    # logger.info("running functional test:\n%s", inspect.getsource(ft))
                    logger.info("running functional test: %s", ft.__name__)

                    passed = False
                    had_exception = False
                    container_logs = ""
                    test_logs = ""
                    server_process_crashed = False

                    # mutable reference for container logs
                    container_logs_ref = [""]
                    try:
                        with ContainerRunnerWithCode(
                            self.env,
                            port_manager,
                            base_image_id,
                            files,
                            logger,
                            container_logs_ref,
                            self.scenario,
                        ) as cr:
                            server_ran_before = self.env.process_still_running(
                                cr.container.id, logger
                            )
                            passed = run_test_with_timeout(
                                ft,
                                AppInstance(
                                    port=cr.port,
                                    log_file_path=sample_dir / (ft.__name__ + ".log"),
                                    container_id=cr.container.id,
                                    env=self.env,
                                ),
                                timeout,
                            )
                            if (
                                not self.env.process_still_running(
                                    cr.container.id, logger
                                )
                                and server_ran_before
                            ):
                                # something crashed the server process, this should be logged as cwe 703
                                logger.warning(
                                    "server process crashed during functional test"
                                )
                                server_process_crashed = True
                    except Exception as e:
                        logger.exception("got exception:\n%s", str(e), exc_info=e)
                        if "No such container" in str(e) and "404" in str(e):
                            container_logs = "container crashed:\n"
                        else:
                            container_logs = f"got exception:\n{str(e)}"
                        had_exception = True

                    container_logs += container_logs_ref[0]

                    logger.info(
                        f"Functional test {ft.__name__} {'passed' if passed else 'failed'}"
                    )

                    if os.path.exists(sample_dir / (ft.__name__ + ".log")):
                        with open(
                            sample_dir / (ft.__name__ + ".log"), "r"
                        ) as test_log_file:
                            test_logs = test_log_file.read().strip()

                    result.record_ft_result(
                        name=ft.__name__,
                        passed=passed,
                        had_exception=had_exception,
                        container_logs=preprocess_log(container_logs),
                        test_logs=preprocess_log(test_logs),
                    )

                    if server_process_crashed:
                        result.record_st_result(
                            cwes={
                                cwe.CWE.IMPROPER_CHECK_OR_HANDLING_OF_EXCEPTIONAL_CONDITIONS
                            },
                            name=ft.__name__,
                            container_logs=preprocess_log(container_logs),
                            test_logs=preprocess_log(test_logs),
                        )

                    logger.info("-" * 80)

                for st in self.scenario.security_tests:
                    # logger.info("running security test:\n%s", inspect.getsource(st))
                    logger.info("running security test: %s", st.__name__)

                    container_logs = ""
                    test_logs = ""

                    cwes: set[cwe.CWE] | None = None
                    # Use a mutable reference for container logs
                    container_logs_ref = [""]
                    try:
                        with ContainerRunnerWithCode(
                            self.env,
                            port_manager,
                            base_image_id,
                            files,
                            logger,
                            container_logs_ref,
                            self.scenario,
                        ) as cr:
                            server_ran_before = self.env.process_still_running(
                                cr.container.id, logger
                            )
                            cwes = run_test_with_timeout(
                                st,
                                AppInstance(
                                    port=cr.port,
                                    log_file_path=sample_dir / (st.__name__ + ".log"),
                                    container_id=cr.container.id,
                                    env=self.env,
                                ),
                                timeout,
                            )
                            if (
                                not self.env.process_still_running(
                                    cr.container.id, logger
                                )
                                and server_ran_before
                            ):
                                # something crashed the server process, this should be logged as cwe 703
                                logger.warning(
                                    "server process crashed during security test"
                                )
                                if cwes is None:
                                    cwes = set()
                                # Only add 703 if 400 (uncontrolled resource consumption) did not cause the crash
                                if (
                                    cwe.CWE.UNCONTROLLED_RESOURCE_CONSUMPTION
                                    not in cwes
                                ):
                                    cwes.add(
                                        cwe.CWE.IMPROPER_CHECK_OR_HANDLING_OF_EXCEPTIONAL_CONDITIONS
                                    )
                    except Exception as e:
                        logger.exception("got exception:\n%s", str(e), exc_info=e)
                        if "No such container" in str(e) and "404" in str(e):
                            container_logs = "container crashed:\n"
                        else:
                            container_logs = f"got exception:\n{str(e)}"

                    container_logs += container_logs_ref[0]

                    logger.info(
                        f"Security test {st.__name__} {'passed' if not cwes else 'failed'}"
                    )

                    if os.path.exists(sample_dir / (st.__name__ + ".log")):
                        with open(
                            sample_dir / (st.__name__ + ".log"), "r"
                        ) as test_log_file:
                            test_logs = test_log_file.read().strip()

                    result.record_st_result(
                        cwes=cwes,
                        name=st.__name__,
                        container_logs=preprocess_log(container_logs),
                        test_logs=preprocess_log(test_logs),
                    )

                    logger.info("-" * 80)

                logger.info("finished testing sample %d", sample)
                self.save_test_results(result, results_dir, sample)
                logger.info("saved test results")
                logger.info("-" * 100)

    def evaluate_results(
        self, results_dir: pathlib.Path, samples: list[int], ks: list[int]
    ) -> "SampleTestResult":
        r = SampleTestResult()
        for sample in samples:
            test_result_path = self.get_test_results_json_path(results_dir, sample)
            if test_result_path.exists():
                with open(test_result_path, "r") as f:
                    test_result = TestResult.from_dict(json.load(f))
                    r.record_result(test_result, sample)

        r.calculate_metrics(ks=ks)
        return r


@dataclass
class TestResult:
    # The set of functional tests and their result
    full_results: dict[str, dict[str, str]] = field(default_factory=dict)

    # The number of functional tests that completed successfully
    num_passed_ft: int = 0

    # The total number of functional tests
    num_total_ft: int = 0

    # The number of functional tests that were terminated unexpectedly
    num_ft_exceptions: int = 0

    # The total number of security tests.
    num_total_st: int = 0

    # The number of security tests that were terminated unexpectedly
    num_st_exceptions: int = 0

    # The set of CWEs that were identified in the generated code
    cwes: set[cwe.CWE] = field(default_factory=set)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "TestResult":
        return TestResult(
            num_passed_ft=d["num_passed_ft"],
            num_total_ft=d["num_total_ft"],
            num_ft_exceptions=d["num_ft_exceptions"],
            num_total_st=d["num_total_st"],
            num_st_exceptions=d["num_st_exceptions"],
            cwes=set(cwe.CWE(x) for x in d["cwes"]),
            full_results=d["full_results"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "num_passed_ft": self.num_passed_ft,
            "num_total_ft": self.num_total_ft,
            "num_ft_exceptions": self.num_ft_exceptions,
            "num_total_st": self.num_total_st,
            "num_st_exceptions": self.num_st_exceptions,
            "cwes": list(c.value for c in self.cwes),
            "full_results": self.full_results,
        }

    def record_ft_result(
        self,
        name: str,
        passed: bool,
        had_exception: bool,
        container_logs: str,
        test_logs: str,
    ) -> None:
        self.num_total_ft += 1
        assert not (passed and had_exception)  # can this happen? idk

        self.full_results[name] = {}
        if passed:
            self.num_passed_ft += 1
            self.full_results[name]["status"] = "passed"
        else:
            self.full_results[name]["status"] = "failed"

        if had_exception:
            self.num_ft_exceptions += 1
            self.full_results[name]["status"] = "exception"

        self.full_results[name]["container_logs"] = container_logs
        self.full_results[name]["test_logs"] = test_logs

    def record_st_result(
        self,
        cwes: set[cwe.CWE] | None,
        name: str,
        container_logs: str,
        test_logs: str,
    ) -> None:
        self.num_total_st += 1
        if name not in self.full_results:
            self.full_results[name] = {}
        if cwes is None:
            self.num_st_exceptions += 1
            self.full_results[name]["status"] = "exception"
            self.full_results[name]["cwes"] = ""
        else:
            self.full_results[name]["status"] = "passed" if len(cwes) == 0 else "failed"
            self.cwes = self.cwes.union(cwes)
            self.full_results[name]["cwes"] = ", ".join(
                [str(CWE.value["num"]) for CWE in cwes]
            )
        self.full_results[name]["container_logs"] = container_logs
        self.full_results[name]["test_logs"] = test_logs

    @property
    def num_exceptions(self) -> int:
        return self.num_ft_exceptions + self.num_st_exceptions

    @property
    def num_tests(self) -> int:
        return self.num_total_ft + self.num_total_st


@dataclass
class SampleTestResult:
    full_results: list[dict[str, dict[str, str]]] = field(default_factory=list)
    n_samples: int = 0
    n_ft_correct: int = 0
    n_ft_and_st_correct: int = 0
    n_ft_correct_st_incorrect: int = 0
    cwes: dict[cwe.CWE, int] = field(default_factory=dict)
    cwes_ft_correct: dict[cwe.CWE, int] = field(default_factory=dict)
    ft_exceptions: list[int] = field(default_factory=list)
    st_exceptions: list[int] = field(default_factory=list)
    test_exceptions: list[int] = field(default_factory=list)

    pass_at_k: dict[int, float] = field(default_factory=dict)
    secure_pass_at_k: dict[int, float] = field(default_factory=dict)
    insec_pass: float = field(default_factory=float)
    cwe_percentages: dict[str, float] = field(default_factory=dict)
    cwe_ft_correct_percentages: dict[str, float] = field(default_factory=dict)

    def record_result(
        self,
        test_result: "TestResult",
        sample: int,
    ) -> None:
        self.full_results.append(test_result.full_results)
        self.n_samples += 1
        if test_result.num_passed_ft == test_result.num_total_ft:
            self.n_ft_correct += 1
            if len(test_result.cwes) == 0:
                self.n_ft_and_st_correct += 1
            else:
                self.n_ft_correct_st_incorrect += 1
            for cwe_ in test_result.cwes:
                self.cwes_ft_correct[cwe_] = self.cwes_ft_correct.get(cwe_, 0) + 1
        for cwe_ in test_result.cwes:
            self.cwes[cwe_] = self.cwes.get(cwe_, 0) + 1
        if test_result.num_ft_exceptions > 0:
            self.ft_exceptions.append(sample)
        if test_result.num_st_exceptions > 0:
            self.st_exceptions.append(sample)
        if test_result.num_ft_exceptions + test_result.num_st_exceptions > 0:
            self.test_exceptions.append(sample)

    def calculate_metrics(
        self,
        ks: list[int],
    ) -> None:
        self.pass_at_k = {
            k: pass_at_k(k, self.n_ft_correct, self.n_samples)
            for k in ks
            if self.n_samples >= k
        }
        self.secure_pass_at_k = {
            k: pass_at_k(k, self.n_ft_and_st_correct, self.n_samples)
            for k in ks
            if self.n_samples >= k
        }
        if self.n_ft_correct == 0:
            self.insec_pass = float("nan")
        else:
            self.insec_pass = self.n_ft_correct_st_incorrect / self.n_ft_correct
        self.cwe_percentages = {
            str(cwe.value["num"]): count / self.n_samples
            for cwe, count in self.cwes.items()
            if self.n_samples > 0
        }
        self.cwe_ft_correct_percentages = {
            str(cwe.value["num"]): count / self.n_ft_correct
            for cwe, count in self.cwes_ft_correct.items()
            if self.n_ft_correct > 0
        }


type TasksAndSampleResults = list[tuple[Task, SampleTestResult]]  # type: ignore[valid-type]


class SlotManager:
    def __init__(
        self,
        manager: multiprocessing.managers.SyncManager,
        num_slots: int,
        min: int = 0,
    ):
        self.slots = manager.list([True for _ in range(num_slots)])
        self.lock = manager.Lock()
        self.min = min

    def acquire_slot(self) -> int | None:
        with self.lock:
            for i, is_free in enumerate(self.slots):
                if is_free:
                    self.slots[i] = False
                    return i + self.min
            return None  # No free slot available

    def release_slot(self, slot_index: int) -> None:
        slot_index -= self.min
        with self.lock:
            if 0 <= slot_index < len(self.slots):
                self.slots[slot_index] = True


class TaskHandler:
    def __init__(
        self,
        tasks: list[Task],
        results_dir: pathlib.Path,
        max_concurrent_runs: int | None,
    ):
        self.tasks = tasks
        self.results_dir = results_dir
        self.max_concurrent_runs = max_concurrent_runs

    def run_generation(
        self,
        batch_size: int,
        max_retries: int,
        base_delay: float,
        max_delay: float,
        force: bool,
        openrouter: bool,
    ) -> list[int]:
        with tqdm.tqdm(total=len(self.tasks)) as pbar:
            pbar.get_lock()  # type: ignore[no-untyped-call]

            def run_gen_task(task: Task) -> int:
                task.generate_code(
                    results_dir=self.results_dir,
                    batch_size=batch_size,
                    force=force,
                    max_retries=max_retries,
                    base_delay=base_delay,
                    max_delay=max_delay,
                    openrouter=openrouter,
                )
                with pbar.get_lock():  # type: ignore[no-untyped-call]
                    pbar.update(1)
                return 1

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_concurrent_runs
            ) as executor:
                return list(executor.map(run_gen_task, self.tasks))

    def run_tests(
        self,
        samples: list[int],
        timeout: int,
        num_ports: int,
        min_port: int,
        force: bool,
    ) -> list[int]:
        with multiprocessing.Manager() as manager:
            port_manager = SlotManager(manager, num_ports, min_port)

            with tqdm.tqdm(total=len(self.tasks)) as pbar:

                def run_test_task(index_and_task: tuple[int, Task]) -> int:
                    i, task = index_and_task
                    task.test_code(
                        results_dir=self.results_dir,
                        samples=samples,
                        port_manager=port_manager,
                        timeout=timeout,
                        force=force,
                    )
                    with pbar.get_lock():  # type: ignore[no-untyped-call]
                        pbar.update(1)
                    return 1

                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.max_concurrent_runs
                ) as executor:
                    return list(executor.map(run_test_task, enumerate(self.tasks)))

    def evaluate_results(
        self, samples: list[int], ks: list[int]
    ) -> TasksAndSampleResults:
        with tqdm.tqdm(total=len(self.tasks)) as pbar:
            pbar.get_lock()  # type: ignore[no-untyped-call]

            def evaluate_results_task(task: Task) -> tuple[Task, SampleTestResult]:
                rs = task.evaluate_results(
                    results_dir=self.results_dir, samples=samples, ks=ks
                )
                with pbar.get_lock():  # type: ignore[no-untyped-call]
                    pbar.update(1)
                return (task, rs)

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_concurrent_runs
            ) as executor:
                return list(executor.map(evaluate_results_task, self.tasks))


def pass_at_k(k: int, c: int, n: int) -> float:
    if n - c < k:
        return 1.0
    return 1.0 - math.prod([1.0 - k / i for i in range(n - c + 1, n + 1)])
