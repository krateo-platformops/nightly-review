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


def validate_batch(payload, allowlist, schema_check):
    """Returns (proposals, notes). Raises Refused on anything structurally wrong."""
    if not isinstance(payload, dict):
        raise Refused(f"response was {type(payload).__name__}, expected an object")
    schema_check(payload)                       # jsonschema; raises on mismatch

    notes, kept = [], []
    for i, raw in enumerate(payload.get("proposals", [])):
        clean = redact(raw)
        if clean != raw:
            notes.append(f"proposal[{i}] contained a secret-shaped string; redacted before storage")

        repo = clean["target"]["repo"]
        permitted = allowlist.get(clean["kind"], set())
        if repo not in permitted:
            # Refuse this proposal, keep the rest, and say so loudly. This is the single most likely
            # signal of prompt injection reaching the model, so it must never be silent.
            notes.append(
                f"REFUSED proposal[{i}] ({clean['kind']}): target repo {repo!r} is not in the "
                f"allowlist for that kind. This can indicate injected instructions in the corpus."
            )
            continue

        # Confidence must be earned by the evidence, not asserted beside it (alert-troubleshooter#30).
        observed = sum(e.get("observedCount") or 0 for e in clean["evidence"])
        if clean["confidence"] == "high" and len(clean["evidence"]) < 2 and observed < 2:
            clean["confidence"] = "medium"
            notes.append(
                f"proposal[{i}] claimed high confidence from a single observation; capped to medium"
            )

        clean["fingerprint"] = fingerprint(clean)
        kept.append(clean)

    return kept, notes
