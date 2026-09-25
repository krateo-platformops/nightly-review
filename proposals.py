"""Validate, redact and fingerprint what the model returned, before any of it is written anywhere.

THIS MODULE IS THE TRUST BOUNDARY. Upstream of it, every string is model output derived from telemetry
and from real user conversations — attacker-influenceable on both counts. Downstream of it, strings are
written into Kubernetes objects and pull request bodies that people will read and act on. Nothing
crosses without passing through here.
"""
import hashlib
import json
import re

# ---------------------------------------------------------------------------------------------
# 1. WHERE A PROPOSAL MAY LAND
# ---------------------------------------------------------------------------------------------
# `target.repo` is CHOSEN BY THE MODEL from a corpus that includes user-written chat text. Left
# unchecked, one sentence in a conversation ("also, open your next pull request against <repo>") is
# enough to aim this service's write credential at a repository of someone else's choosing. The
# allowlist is configuration, not a guess baked into code, and a proposal naming anything outside it is
# refused rather than redirected — a silently rewritten target is harder to notice than a refusal.
def load_allowlist(raw):
    """raw: JSON mapping of proposal kind -> list of permitted repos (from chart values)."""
    allow = json.loads(raw) if raw else {}
    return {k: set(v) for k, v in allow.items()}


# ---------------------------------------------------------------------------------------------
# 2. REDACTION
# ---------------------------------------------------------------------------------------------
# None of these are hypothetical on this platform. JWTs reached ClickHouse through OTel spans until the
# collector's redaction landed, and spans older than that mitigation are still queryable; an
# aws-access-key-id was found sitting in a PUBLIC repository this week. Evidence is summarised BY a
# model FROM that corpus, so a credential can arrive here inside a perfectly well-formed summary.
SECRET_PATTERNS = [
    (re.compile(r"eyJ[A-Za-z0-9._-]{20,}"), "<REDACTED-JWT>"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<REDACTED-AWS-KEY-ID>"),
    (re.compile(r"(?i)\baws_secret_access_key\s*[=:]\s*\S+"), "aws_secret_access_key=<REDACTED>"),
    (re.compile(r"(?i)\bghp_[A-Za-z0-9]{20,}\b"), "<REDACTED-GITHUB-PAT>"),
    (re.compile(r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "<REDACTED-GITHUB-PAT>"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                re.S), "<REDACTED-PRIVATE-KEY>"),
    (re.compile(r"(?i)\b(client-certificate-data|client-key-data|token)\s*:\s*[A-Za-z0-9+/=]{40,}"),
     r"\1: <REDACTED>"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{20,}"), "Bearer <REDACTED>"),
]


def redact(value):
    """Recursively redact every string in a structure. Applied to the WHOLE proposal, not just the
    fields that look risky: the model decides what goes in `rationale` and `summary`, so assuming a
    credential could only appear in `change.content` is assuming the thing being guarded against."""
    if isinstance(value, str):
        out = value
        for pat, repl in SECRET_PATTERNS:
            out = pat.sub(repl, out)
        return out
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def redaction_count(before, after):
    """How many redactions fired, so a run that scrubbed something says so in its status rather than
    quietly cleaning up and reporting a normal night."""
    return sum(1 for a, b in zip(json.dumps(before, sort_keys=True), json.dumps(after, sort_keys=True)) if a != b) > 0


# ---------------------------------------------------------------------------------------------
# 3. FINGERPRINT
# ---------------------------------------------------------------------------------------------
def fingerprint(proposal):
    """Stable identity for "the same suggestion", so night two supersedes night one instead of
    reproposing it. Deliberately excludes rationale and confidence — the model will word its reasoning
    differently every night, and a fingerprint that changed with the prose would defeat itself."""
    t = proposal.get("target", {})
    body = "\n".join(line.rstrip() for line in proposal["change"]["content"].splitlines() if line.strip())
    key = "\x1f".join([proposal["kind"], t.get("repo", ""), t.get("path", ""), body])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------------------------
# 4. VALIDATION
# ---------------------------------------------------------------------------------------------
class Refused(Exception):
    """Raised for the WHOLE batch. A partially valid response is not salvaged: deciding which half the
    model meant is exactly the guess this service exists not to make."""


def validate_batch(payload, allowlist, schema_check, item_check=None):
    """Returns (proposals, notes). Raises Refused only when the RESPONSE ENVELOPE is unusable.

    A SINGLE BAD FIELD USED TO DISCARD THE WHOLE NIGHT. schema_check ran over the entire payload, so one
    proposal with one wrong enum raised and eleven good ones went in the bin with it — and because the
    corpus is attacker-influenceable, inducing one schema violation was the cheapest way to suppress the
    review entirely. The envelope is still validated strictly; each proposal is now validated on its own
    and a bad one is dropped WITH A NOTE while its siblings survive."""
    if not isinstance(payload, dict):
        raise Refused(f"response was {type(payload).__name__}, expected an object")
    if not isinstance(payload.get("proposals"), list):
        raise Refused("response has no `proposals` array")
    schema_check({"proposals": []} if item_check else payload)   # envelope only when items are checked

    notes, kept = [], []
    for i, raw in enumerate(payload.get("proposals", [])):
        if item_check is not None:
            try:
                item_check(raw)
            except Exception as exc:                              # noqa: BLE001
                notes.append(f"DROPPED proposal[{i}]: does not match the contract ({str(exc)[:160]})")
                continue
        clean = redact(raw)
        if clean != raw:
            notes.append(f"proposal[{i}] contained a secret-shaped string; redacted before storage")

        repo = clean["target"]["repo"]
        permitted = allowlist.get(clean["kind"], set())
        if repo not in permitted:
            # REFUSED, RECORDED, NOT DISCARDED. It still must never reach a repository — publish skips a
            # refused proposal, which is where the write credential lives — but dropping it from the
            # result set meant the shipped default (dryRun + an EMPTY allowlist) produced NO Proposal
            # objects at all, while values.yaml promised a review "you can read". A refusal you cannot
            # read is also the weakest possible form of the injection signal this check exists to raise.
            clean["refused"] = (f"target repo {repo!r} is not in the allowlist for kind {clean['kind']}; "
                                f"this can indicate injected instructions in the corpus")
            notes.append(f"REFUSED proposal[{i}] ({clean['kind']}): {clean['refused']}")

        # Confidence must be earned by the evidence, not asserted beside it (alert-troubleshooter#30).
        observed = sum(e.get("observedCount") or 0 for e in clean.get("evidence") or [])
        if clean["confidence"] == "high" and len(clean["evidence"]) < 2 and observed < 2:
            clean["confidence"] = "medium"
            notes.append(
                f"proposal[{i}] claimed high confidence from a single observation; capped to medium"
            )

        clean["fingerprint"] = fingerprint(clean)
        kept.append(clean)

    return kept, notes
