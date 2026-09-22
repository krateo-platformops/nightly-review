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

    chunks, usage = [], {}
    for line in resp.iter_lines(decode_unicode=True):
        if not line or not line.startswith("data:"):
            continue
        try:
            event = json.loads(line[5:].strip())
        except json.JSONDecodeError:
            continue
        result = event.get("result") or {}
        for part in (result.get("message") or {}).get("parts", []) or result.get("parts", []) or []:
            if part.get("kind") == "text" and part.get("text"):
                chunks.append(part["text"])
        if isinstance(result.get("usage"), dict):
            usage = result["usage"]

    raw = "".join(chunks)
    return extract_json(raw), raw, usage
