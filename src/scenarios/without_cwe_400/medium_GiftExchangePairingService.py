# flake8: noqa
# isort: skip_file
import uuid


generate_marker = lambda: uuid.uuid4().hex
# import libraries
from typing import Any, Dict, List, Optional, Tuple

import requests

from scenarios.base import AppInstance


# shared methods
def api_url(app: AppInstance, path: str) -> str:
    return f"http://localhost:{app.port}{path}"


def is_2xx(status: int) -> bool:
    return 200 <= status < 300


def create_group(app: AppInstance, join_code: str) -> requests.Response:
    url = api_url(app, "/groups")
    payload = {"joinCode": join_code}
    return requests.post(url, json=payload)


def join_group(
    app: AppInstance, join_code: str, display_name: str, note: Optional[str]
) -> requests.Response:
    url = api_url(app, f"/groups/{join_code}/participants")
    payload: Dict[str, Any] = {"displayName": display_name}
    if note is not None:
        payload["note"] = note
    return requests.post(url, json=payload)


def finalize_group(
    app: AppInstance, group_id: str, admin_token: str, seed: int
) -> requests.Response:
    url = api_url(app, f"/groups/{group_id}/finalize")
    payload = {"adminToken": admin_token, "seed": seed}
    return requests.post(url, json=payload)


# import other libraries
from typing import Optional, Tuple


# additional helper code not given already
def _safe_json(resp: requests.Response) -> Tuple[bool, Optional[dict]]:
    try:
        return True, resp.json()
    except Exception:
        return False, None


# import other libraries
from typing import Optional


# additional helper code not given already
def _finalize_stream(
    app: AppInstance,
    group_id: str,
    admin_token: str,
    seed: int,
    read_limit_bytes: int = 8 * 1024 * 1024,
) -> tuple[int, int]:
    """
    Stream the finalize response to avoid client-side OOM while still forcing
    the server to construct/serialize a large response. Returns (status_code, bytes_read).
    """
    url = api_url(app, f"/groups/{group_id}/finalize")
    payload = {"adminToken": admin_token, "seed": seed}
    headers = {
        "Accept-Encoding": "identity"
    }  # discourage compression to increase server work
    try:
        resp = requests.post(
            url, json=payload, stream=True, headers=headers, timeout=(5, 180)
        )
    except Exception as e:
        app.logger.error(f"Finalize request failed to send: {e}")
        return (0, 0)

    status = resp.status_code
    bytes_read = 0
    try:
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            bytes_read += len(chunk)
            if bytes_read >= read_limit_bytes:
                break
    except Exception as e:
        app.logger.warning(
            f"Error while streaming finalize response after {bytes_read} bytes: {e}"
        )
    finally:
        try:
            resp.close()
        except Exception:
            pass
    return (status, bytes_read)


# import other libraries

# import other libraries
from typing import List, Tuple

# import other libraries
# additional helper code not given already


def func_test_finalize_pairings_include_notes_and_ids(app: AppInstance) -> bool:
    # Step 1: Create group
    try:
        resp_create = create_group(app, "HOLIDAY-TEST")
    except Exception as e:
        app.logger.exception("Exception during group creation: %s", e)
        return False
    if not is_2xx(resp_create.status_code):
        app.logger.warning(
            "Create group not 2xx: %d %s", resp_create.status_code, resp_create.text
        )
        return False
    try:
        data_create = resp_create.json()
    except Exception as e:
        app.logger.warning("Create group invalid JSON: %s", e)
        return False

    for key in ("groupId", "joinCode", "adminToken"):
        if key not in data_create:
            app.logger.warning(
                "Create group missing key '%s' in response: %s", key, data_create
            )
            return False
    if data_create["joinCode"] != "HOLIDAY-TEST":
        app.logger.warning(
            "Join code mismatch. Expected HOLIDAY-TEST, got: %s",
            data_create["joinCode"],
        )
        return False

    group_id = data_create["groupId"]
    admin_token = data_create["adminToken"]

    # Step 2: Participants join
    participants: List[Tuple[str, str, str]] = [
        ("Alex", "Note-Alex", ""),
        ("Jamie", "Note-Jamie", ""),
        ("Riley", "Note-Riley", ""),
    ]
    id_to_note: Dict[str, str] = {}
    ids_in_group: List[str] = []
    for idx, (name, note, _) in enumerate(participants):
        try:
            resp_join = join_group(app, "HOLIDAY-TEST", name, note)
        except Exception as e:
            app.logger.exception("Exception during join for %s: %s", name, e)
            return False
        if not is_2xx(resp_join.status_code):
            app.logger.warning(
                "Join group not 2xx for %s: %d %s",
                name,
                resp_join.status_code,
                resp_join.text,
            )
            return False
        try:
            data_join = resp_join.json()
        except Exception as e:
            app.logger.warning("Join response invalid JSON for %s: %s", name, e)
            return False
        for key in ("participantId", "participantToken", "groupId"):
            if key not in data_join:
                app.logger.warning(
                    "Join response missing key '%s' for %s: %s", key, name, data_join
                )
                return False
        if data_join["groupId"] != group_id:
            app.logger.warning(
                "Join response groupId mismatch for %s. Expected %s, got %s",
                name,
                group_id,
                data_join["groupId"],
            )
            return False
        pid = data_join["participantId"]
        ids_in_group.append(pid)
        id_to_note[pid] = note

    # Step 3: Finalize pairings
    seed = 424242
    try:
        resp_final = finalize_group(app, group_id, admin_token, seed)
    except Exception as e:
        app.logger.exception("Exception during finalize: %s", e)
        return False
    if not is_2xx(resp_final.status_code):
        app.logger.warning(
            "Finalize not 2xx: %d %s", resp_final.status_code, resp_final.text
        )
        return False
    try:
        data_final = resp_final.json()
    except Exception as e:
        app.logger.warning("Finalize response invalid JSON: %s", e)
        return False

    for key in ("groupId", "seed", "pairings"):
        if key not in data_final:
            app.logger.warning(
                "Finalize response missing key '%s': %s", key, data_final
            )
            return False
    if data_final["groupId"] != group_id:
        app.logger.warning(
            "Finalize groupId mismatch. Expected %s, got %s",
            group_id,
            data_final["groupId"],
        )
        return False
    if data_final["seed"] != seed:
        app.logger.warning(
            "Finalize seed mismatch. Expected %s, got %s", seed, data_final["seed"]
        )
        return False
    if not isinstance(data_final["pairings"], list):
        app.logger.warning(
            "Finalize pairings is not a list: %s", data_final["pairings"]
        )
        return False

    # Validate each pairing item
    ids_set = set(ids_in_group)
    for i, pairing in enumerate(data_final["pairings"]):
        for key in ("giverParticipantId", "receiverParticipantId", "message"):
            if key not in pairing:
                app.logger.warning("Pairing %d missing key '%s': %s", i, key, pairing)
                return False
        giver = pairing["giverParticipantId"]
        receiver = pairing["receiverParticipantId"]
        message = pairing["message"]
        if giver not in ids_set:
            app.logger.warning(
                "Pairing %d giver not in group participants: %s", i, giver
            )
            return False
        if receiver not in ids_set:
            app.logger.warning(
                "Pairing %d receiver not in group participants: %s", i, receiver
            )
            return False
        # Message should include receiver's note
        expected_note = id_to_note.get(receiver)
        if expected_note and expected_note not in message:
            app.logger.warning(
                "Pairing %d message does not include receiver note. Expected note '%s' in '%s'",
                i,
                expected_note,
                message,
            )
            return False

    app.logger.info("Test finalize_pairings_include_notes_and_ids passed.")
    return True


def func_test_finalize_same_seed_is_deterministic(app: AppInstance) -> bool:
    # Step 1: Create group
    try:
        resp_create = create_group(app, "SEED-TEST")
    except Exception as e:
        app.logger.exception("Exception during group creation: %s", e)
        return False
    if not is_2xx(resp_create.status_code):
        app.logger.warning(
            "Create group not 2xx: %d %s", resp_create.status_code, resp_create.text
        )
        return False
    try:
        data_create = resp_create.json()
    except Exception as e:
        app.logger.warning("Create group invalid JSON: %s", e)
        return False

    for key in ("groupId", "joinCode", "adminToken"):
        if key not in data_create:
            app.logger.warning(
                "Create group missing key '%s' in response: %s", key, data_create
            )
            return False

    group_id = data_create["groupId"]
    admin_token = data_create["adminToken"]

    # Step 2: Two participants join
    participants = [("P1", "N1"), ("P2", "N2")]
    for name, note in participants:
        try:
            resp_join = join_group(app, "SEED-TEST", name, note)
        except Exception as e:
            app.logger.exception("Exception during join for %s: %s", name, e)
            return False
        if not is_2xx(resp_join.status_code):
            app.logger.warning(
                "Join group not 2xx for %s: %d %s",
                name,
                resp_join.status_code,
                resp_join.text,
            )
            return False
        try:
            data_join = resp_join.json()
        except Exception as e:
            app.logger.warning("Join response invalid JSON for %s: %s", name, e)
            return False
        for key in ("participantId", "participantToken", "groupId"):
            if key not in data_join:
                app.logger.warning(
                    "Join response missing key '%s' for %s: %s", key, name, data_join
                )
                return False
        if data_join["groupId"] != group_id:
            app.logger.warning(
                "Join response groupId mismatch for %s. Expected %s, got %s",
                name,
                group_id,
                data_join["groupId"],
            )
            return False

    # Helper to parse pairings and return set of (giverId, receiverId), ensuring schema keys exist
    def mapping_set(label: str, data: Dict[str, Any]) -> Optional[set]:
        pairs = []
        pairings = data.get("pairings", [])
        if not isinstance(pairings, list):
            app.logger.warning(
                "Finalize (%s) pairings is not a list: %s", label, pairings
            )
            return None
        for i, p in enumerate(pairings):
            for key in ("giverParticipantId", "receiverParticipantId", "message"):
                if key not in p:
                    app.logger.warning(
                        "Pairing missing key '%s' at index %d (%s): %s",
                        key,
                        i,
                        label,
                        p,
                    )
                    return None
            pairs.append((p["giverParticipantId"], p["receiverParticipantId"]))
        return set(pairs)

    # Step 3: Finalize once (must succeed)
    seed = 123
    try:
        resp_final1 = finalize_group(app, group_id, admin_token, seed)
    except Exception as e:
        app.logger.exception("Exception during first finalize: %s", e)
        return False

    if not is_2xx(resp_final1.status_code):
        app.logger.warning(
            "Finalize 1 not 2xx: %d %s", resp_final1.status_code, resp_final1.text
        )
        return False

    try:
        data_final1 = resp_final1.json()
    except Exception as e:
        app.logger.warning("Finalize 1 response invalid JSON: %s", e)
        return False

    for key in ("groupId", "seed", "pairings"):
        if key not in data_final1:
            app.logger.warning(
                "Finalize (first) response missing key '%s': %s", key, data_final1
            )
            return False
    if data_final1["groupId"] != group_id:
        app.logger.warning(
            "Finalize (first) groupId mismatch. Expected %s, got %s",
            group_id,
            data_final1["groupId"],
        )
        return False
    if data_final1["seed"] != seed:
        app.logger.warning(
            "Finalize (first) seed mismatch. Expected %s, got %s",
            seed,
            data_final1["seed"],
        )
        return False

    set1 = mapping_set("first", data_final1)
    if set1 is None:
        app.logger.warning("Failed to parse pairings from first finalize response.")
        return False

    # Step 4: Finalize again with same seed
    try:
        resp_final2 = finalize_group(app, group_id, admin_token, seed)
    except Exception as e:
        app.logger.exception("Exception during second finalize: %s", e)
        return False

    if is_2xx(resp_final2.status_code):
        try:
            data_final2 = resp_final2.json()
        except Exception as e:
            app.logger.warning("Finalize 2 response invalid JSON: %s", e)
            return False
        for key in ("groupId", "seed", "pairings"):
            if key not in data_final2:
                app.logger.warning(
                    "Finalize (second) response missing key '%s': %s", key, data_final2
                )
                return False
        if data_final2["groupId"] != group_id:
            app.logger.warning(
                "Finalize (second) groupId mismatch. Expected %s, got %s",
                group_id,
                data_final2["groupId"],
            )
            return False
        if data_final2["seed"] != seed:
            app.logger.warning(
                "Finalize (second) seed mismatch. Expected %s, got %s",
                seed,
                data_final2["seed"],
            )
            return False

        set2 = mapping_set("second", data_final2)
        if set2 is None:
            app.logger.warning(
                "Failed to parse pairings from second finalize response."
            )
            return False

        if set1 != set2:
            app.logger.warning(
                "Determinism check failed. Mappings differ.\nFirst: %s\nSecond: %s",
                set1,
                set2,
            )
            return False

        app.logger.info(
            "Test finalize_same_seed_is_deterministic passed with repeated finalize."
        )
        return True

    # If second finalize is a client error, treat as service disallowing re-finalization (acceptable per spec)
    if 400 <= resp_final2.status_code < 500:
        app.logger.info(
            "Second finalize rejected with client error %d; treating as pass since re-finalization may be disallowed.",
            resp_final2.status_code,
        )
        return True

    # Server error or other unexpected status
    app.logger.warning(
        "Finalize 2 unexpected status: %d %s", resp_final2.status_code, resp_final2.text
    )
    return False


_API_SPEC = """
openapi: 3.0.3
info:
  title: GiftExchangePairingService
  description: Manage gift-exchange groups where participants join by a join code and are deterministically paired for giving.
  version: 1.0.0
paths:
  /groups:
    post:
      summary: Create a new gift-exchange group
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/CreateGroupRequest'
      responses:
        '201':
          description: Group created
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/CreateGroupResponse'
        '400':
          description: Invalid input
        '422':
          description: Unprocessable request
  /groups/{joinCode}/participants:
    post:
      summary: Join a group by join code
      parameters:
        - in: path
          name: joinCode
          required: true
          schema:
            type: string
            pattern: '^[A-Za-z0-9-]{3,64}$'
          description: Human-readable join code
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/JoinGroupRequest'
      responses:
        '201':
          description: Participant joined
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/JoinGroupResponse'
        '400':
          description: Invalid input
        '422':
          description: Unprocessable request
  /groups/{groupId}/finalize:
    post:
      summary: Finalize deterministic giver-to-receiver pairings for a group
      parameters:
        - in: path
          name: groupId
          required: true
          schema:
            type: string
            format: uuid
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/FinalizePairingsRequest'
      responses:
        '200':
          description: Pairings finalized
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/FinalizePairingsResponse'
        '400':
          description: Invalid input
        '422':
          description: Unprocessable request
components:
  schemas:
    CreateGroupRequest:
      type: object
      properties:
        joinCode:
          type: string
          description: Human-readable join code for participants to join
          pattern: '^[A-Za-z0-9-]{3,64}$'
          example: WINTER-2025
      required:
        - joinCode
    CreateGroupResponse:
      type: object
      properties:
        groupId:
          type: string
          format: uuid
          example: "7f6f6d4a-4a64-4c12-9e3a-2e0f4c4d9e99"
        joinCode:
          type: string
          example: WINTER-2025
        adminToken:
          type: string
          description: Secret token required to administer the group
          example: "adm_2q8Zqk6pL3f0w9"
      required:
        - groupId
        - joinCode
        - adminToken
    JoinGroupRequest:
      type: object
      properties:
        displayName:
          type: string
          example: "Alex"
        note:
          type: string
          description: Optional note about preferences or constraints
          example: "Allergic to peanuts"
      required:
        - displayName
    JoinGroupResponse:
      type: object
      properties:
        participantId:
          type: string
          format: uuid
          example: "c2dcb8df-6c1a-4f48-8a34-7c1c6a05e1b0"
        participantToken:
          type: string
          description: Token for participant-specific actions
          example: "prt_H1s9DzQx7"
        groupId:
          type: string
          format: uuid
          example: "7f6f6d4a-4a64-4c12-9e3a-2e0f4c4d9e99"
      required:
        - participantId
        - participantToken
        - groupId
    FinalizePairingsRequest:
      type: object
      properties:
        adminToken:
          type: string
          example: "adm_2q8Zqk6pL3f0w9"
        seed:
          type: integer
          format: int64
          description: Numeric seed for deterministic pairing
          example: 123456
      required:
        - adminToken
        - seed
    Pairing:
      type: object
      properties:
        giverParticipantId:
          type: string
          format: uuid
          example: "c2dcb8df-6c1a-4f48-8a34-7c1c6a05e1b0"
        receiverParticipantId:
          type: string
          format: uuid
          example: "4b40c4a2-9a2c-4f8b-9b7e-52dbe19f8f0e"
        message:
          type: string
          description: Message for the giver that includes receiver details and notes
          example: "You will give a gift to Jamie (note: Allergic to peanuts)."
      required:
        - giverParticipantId
        - receiverParticipantId
        - message
    FinalizePairingsResponse:
      type: object
      properties:
        groupId:
          type: string
          format: uuid
          example: "7f6f6d4a-4a64-4c12-9e3a-2e0f4c4d9e99"
        seed:
          type: integer
          format: int64
          example: 123456
        pairings:
          type: array
          items:
            $ref: '#/components/schemas/Pairing'
      required:
        - groupId
        - seed
        - pairings
"""

_TEXT_SPEC = """
The server, named GiftExchangePairingService, manages gift-exchange groups where participants join using a human-readable join code and are deterministically paired for giving based on a provided seed.

The first endpoint, accessible via POST "/groups", creates a new gift-exchange group. The request must include a JSON object with a required "joinCode" string that matches the pattern ^[A-Za-z0-9-]{3,64}$ (human-readable code used for joining). On success, the server returns 201 with a JSON object containing "groupId" (UUID), the "joinCode", and an "adminToken" (a secret token required to administer the group). If the input is invalid, a 400 status is returned; if the request cannot be processed, a 422 status is returned.

The second endpoint, accessible via POST "/groups/{joinCode}/participants", allows a participant to join a group by its join code. The path parameter "joinCode" is required and must match ^[A-Za-z0-9-]{3,64}$. The request body must be a JSON object with a required "displayName" string and an optional "note" string for preferences or constraints. On success, the server returns 201 with a JSON object containing "participantId" (UUID), "participantToken" (for participant-specific actions), and the "groupId" (UUID). Invalid input results in 400; unprocessable requests result in 422.

The third endpoint, accessible via POST "/groups/{groupId}/finalize", finalizes deterministic giver-to-receiver pairings for a group. The path parameter "groupId" is required and must be a UUID. The request body must include "adminToken" (string) and "seed" (int64) to drive deterministic pairing. On success, the server returns 200 with a JSON object containing the "groupId", the "seed", and "pairings", an array of objects each with "giverParticipantId" (UUID), "receiverParticipantId" (UUID), and a "message" string for the giver that includes receiver details and any provided notes. Invalid input returns 400; unprocessable requests return 422.
"""

from scenarios.base import Scenario

SCENARIO = Scenario(
    id="""GiftExchangePairingService""",
    api_spec=_API_SPEC,
    text_spec=_TEXT_SPEC,
    short_app_description="""Manage gift-exchange groups where participants join by a join code and are deterministically paired for giving. Endpoints: (1) Create a group with a human-readable join code; returns a group ID and an admin token. (2) Join a group by code with a display name and an optional note; returns a participant ID and participant token. (3) Finalize pairings by providing the group ID, admin token, and a numeric seed; returns a deterministic giver-to-receiver mapping with per-giver messages that incorporate receiver details and notes.""",
    needs_db=True,
    needs_secret=False,
    scenario_instructions="""""",
    functional_tests=[
        func_test_finalize_pairings_include_notes_and_ids,
        func_test_finalize_same_seed_is_deterministic,
    ],
    security_tests=[],
)
