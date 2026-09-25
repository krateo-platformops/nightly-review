"""Reach Autopilot over A2A, as an authenticated Krateo identity.

ADAPTED FROM alert-troubleshooter's handler, deliberately rather than reinvented: it already solved the
only genuinely hard part, which is getting past agentgateway. The service's Kubernetes ServiceAccount is
mapped to a Krateo identity by a serviceaccount.authn.krateo.io CR, authn exchanges that SA's projected
token for a Krateo JWT, and the JWT rides the A2A call so the agent can reach its gateway-gated tools.

THE AGENT IS NEVER GIVEN A WRITE TOOL AND IS NEVER ASKED TO ACT. It returns JSON. Everything that
touches a repository or the cluster is done afterwards, by code, from validated data.
"""
import json
import os
import re
import uuid

import requests

AUTOPILOT_A2A = os.environ.get("AUTOPILOT_A2A_URL", "http://krateo-autopilot.krateo-system.svc:8080/")
AUTHN_URL = os.environ.get("AUTHN_URL", "")
SA_TOKEN_PATH = os.environ.get("SA_TOKEN_PATH", "/var/run/secrets/krateo/authn/token")
A2A_TIMEOUT = int(os.environ.get("A2A_TIMEOUT", "900"))   # a nightly review reads a lot; be patient
_NS = uuid.UUID("6f1a1f4e-0b1a-4a2e-9f7c-2c1d5f0b9a31")   # stable namespace for this component


def service_jwt():
    """Exchange the projected SA token for a Krateo JWT. Returns None if intra-service auth is not
    configured — the caller then proceeds unauthenticated and the agent simply has fewer tools, which
    is a degraded run, NOT a failed one, and the run status must say which."""
    if not AUTHN_URL or not os.path.exists(SA_TOKEN_PATH):
        return None
    try:
        with open(SA_TOKEN_PATH) as fh:
            projected = fh.read().strip()
        r = requests.post(
            f"{AUTHN_URL.rstrip('/')}/serviceaccount/login",
            headers={"Authorization": f"Bearer {projected}"},
            timeout=30,
        )
        r.raise_for_status()
        return r.json().get("accessToken") or r.json().get("token")
    except Exception as exc:                                  # noqa: BLE001
        # Never fatal, and never silent: a degraded run that claims to be a clean one is the failure
        # this codebase keeps relearning.
        print(f"[authn] service-JWT exchange failed ({exc}); calling A2A unauthenticated", flush=True)
        return None


def context_id(run_name):
    """One A2A thread PER RUN, not one continuing thread across nights.

    A continuing thread would let the agent remember what it proposed before — tempting, and wrong to
    rely on: deduplication would then depend on the model recalling correctly, and would degrade
    silently as the context filled. Dedup is done deterministically by fingerprint in code, so the
    agent gets a clean context every night and correctness does not depend on its memory."""
    return str(uuid.uuid5(_NS, f"nightly-review:{run_name}"))


_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)


def extract_json(text):
    """The contract asks for bare JSON. Models sometimes fence it anyway, so accept a fenced object —
    but never try to repair malformed JSON. A response we had to guess at is a response we should
    refuse; see proposals.Refused."""
    text = (text or "").strip()
    if not text:
        raise ValueError("empty response")
    m = _FENCE.search(text)
    if m:
        return json.loads(m.group(1))
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object in response")
    return json.loads(text[start:end + 1])


def ask(system, user_message, run_name, token=None):
    """One JSON-RPC message/stream turn. Returns (parsed_json, raw_text, usage)."""
    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid.uuid4()),
        "method": "message/stream",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"kind": "text", "text": user_message}],
                "messageId": str(uuid.uuid4()),
                "contextId": context_id(run_name),
            },
            "metadata": {"systemPrompt": system},
        },
    }
    headers = {"content-type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    resp = requests.post(AUTOPILOT_A2A, json=payload, headers=headers, timeout=A2A_TIMEOUT, stream=True)
    resp.raise_for_status()

    # WHERE THE ANSWER ACTUALLY IS. kagent's A2A executor does not send `result.message.parts`; it sends
    # TaskStatusUpdateEvents carrying `result.status.message.parts`, artifact events carrying
    # `result.artifact.parts`, and a final task snapshot carrying `result.history[]`. Reading only
    # `result.message`/`result.parts` harvested nothing from a run that had worked perfectly, and the
    # empty string then surfaced as "empty response" — a failure message that named the wrong component.
    def texts(container):
        return [p["text"] for p in (container or {}).get("parts") or []
                if p.get("kind") == "text" and p.get("text")]

    candidates, usage, last_state, events = [], {}, None, 0
    for line in resp.iter_lines(decode_unicode=True):
        if not line or not line.startswith("data:"):
            continue
        try:
            event = json.loads(line[5:].strip())
        except json.JSONDecodeError:
            continue
        events += 1
        if event.get("error"):
            raise ValueError(f"A2A error: {str(event['error'])[:200]}")
        result = event.get("result") or {}
        status = result.get("status") or {}
        if status.get("state"):
            last_state = status["state"]
        for chunk in (texts(status.get("message")) + texts(result.get("artifact"))
                      + texts(result.get("message")) + texts(result)):
            candidates.append(chunk)
        for msg in result.get("history") or []:
            if msg.get("role") != "user":
                candidates.extend(texts(msg))
        if isinstance(result.get("usage"), dict):
            usage = result["usage"]

    # A REFUSAL OR A CRASH MUST NOT LOOK LIKE SILENCE. If the task ended in a terminal non-success state,
    # say so with the state name, even when some text did arrive.
    if last_state in ("failed", "canceled", "rejected", "unknown"):
        detail = (candidates[-1] if candidates else "")[:200]
        raise ValueError(f"agent task {last_state}"+(f": {detail}" if detail else ""))
    if not candidates:
        raise ValueError(f"no text in {events} A2A events (last state: {last_state or 'none'})")

    # Events repeat: the final snapshot echoes what the status updates already said. Concatenating would
    # splice two JSON objects into one unparseable blob, so try whole candidates — newest first, then the
    # longest — and return the first that parses.
    ordered, seen = [], set()
    for c in list(reversed(candidates)) + sorted(candidates, key=len, reverse=True):
        if c not in seen:
            seen.add(c)
            ordered.append(c)
    last_err = None
    for c in ordered:
        try:
            return extract_json(c), c, usage
        except (ValueError, json.JSONDecodeError) as exc:
            last_err = exc

    # LAST RESORT, for a long answer streamed as fragments. Events carry `metadata.adk_partial`, so a
    # reply larger than one chunk can arrive split across events, and then NO single candidate holds the
    # whole object. Joining in arrival order is what the original code did; it is wrong as a FIRST move
    # (the final snapshot repeats earlier text, and two spliced objects never parse) and right as a last
    # one, because a fragmented answer is otherwise unrecoverable.
    joined = "".join(candidates)
    try:
        return extract_json(joined), joined, usage
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"no JSON object in {len(ordered)} candidates nor in their concatenation "
                         f"({len(joined)} chars; last error: {exc or last_err})")
