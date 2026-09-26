"""Validate, redact and fingerprint what the model returned, before any of it is written anywhere.

THIS MODULE IS THE TRUST BOUNDARY. Upstream of it, every string is model output derived from telemetry
and from real user conversations — attacker-influenceable on both counts. Downstream of it, strings are
written into Kubernetes objects and pull request bodies that people will read and act on. Nothing
crosses without passing through here.
"""
import hashlib
import json
import re

import yaml

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
    """How many redactions fired, so a run that scrubbed something says so rather than quietly
    cleaning up and reporting a normal night.

    IT USED TO ZIP TWO JSON STRINGS CHARACTER BY CHARACTER, which cannot answer the question it was
    named for. A redaction that SHORTENS the text shifts every later character, so the comparison
    degenerates into noise; a substitution of equal length at the same offset counts zero; and the
    whole thing was reduced to a bool by a trailing `> 0`, so one redaction and five were
    indistinguishable. It was also never called. Walk the two structures instead and count the string
    leaves that differ — which is exactly what "how many redactions fired" means."""
    if isinstance(before, str):
        return 1 if before != after else 0
    if isinstance(before, dict) and isinstance(after, dict):
        return sum(redaction_count(v, after.get(k)) for k, v in before.items())
    if isinstance(before, list) and isinstance(after, list):
        return sum(redaction_count(a, b) for a, b in zip(before, after))
    return 0


# ---------------------------------------------------------------------------------------------
# 3. FINGERPRINT
# ---------------------------------------------------------------------------------------------
def normalise_body(content, fmt=None):
    """What "the same change" means, independent of how the model happened to type it that night.

    The old normalisation dropped blank lines and trailing spaces and stopped there, so a reworded
    comment or two YAML keys in the other order produced a brand-new fingerprint — and therefore a
    second pull request for a suggestion already open. The docstring below feared exactly that
    outcome; this is what prevents it. YAML is compared as PARSED DATA with its mappings sorted, so
    key order and comments cannot affect identity. Anything that is not a YAML mapping or sequence
    falls through to the text path: comment lines and blank lines dropped, internal whitespace runs
    collapsed."""
    if fmt == "yaml":
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError:
            data = None
        if isinstance(data, (dict, list)):
            return yaml.safe_dump(data, sort_keys=True, default_flow_style=False).strip()
    lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lines.append(re.sub(r"\s+", " ", stripped))
    return "\n".join(lines)


def target_key(proposal):
    """What a proposal is ABOUT, with its body left out: one file, one kind of change. Two proposals
    sharing this but not their fingerprint are successive opinions on the same question, which is the
    distinction `superseded` was always meant to record."""
    t = proposal.get("target", {})
    return "\x1f".join([proposal["kind"], t.get("repo", ""), t.get("path", "")])


def fingerprint(proposal):
    """Stable identity for "the same suggestion", so night two supersedes night one instead of
    reproposing it. Deliberately excludes rationale and confidence — the model will word its reasoning
    differently every night, and a fingerprint that changed with the prose would defeat itself."""
    t = proposal.get("target", {})
    change = proposal.get("change", {})
    body = normalise_body(change.get("content", ""), change.get("format"))
    key = "\x1f".join([proposal["kind"], t.get("repo", ""), t.get("path", ""), body])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def classify(proposal, by_fingerprint, by_target):
    """(action, prior name). THREE OUTCOMES, WHERE THE CODE USED TO SEE TWO — and the missing third is
    why `superseded` was reported as a hardcoded 0 every night while its own docstring described a
    mechanism that did not exist. Identical to something already open is a duplicate and is dropped.
    Aimed at the same file with a DIFFERENT body is a replacement: the open one is stale and is marked
    Superseded, rather than left beside its own successor for a human to reconcile."""
    fp = fingerprint(proposal)
    if fp in by_fingerprint:
        return "dedup", by_fingerprint[fp]
    prior = by_target.get(target_key(proposal))
    if prior and prior.get("fingerprint") != fp:
        return "supersede", prior["name"]
    return "new", None


# ---------------------------------------------------------------------------------------------
# 4. VALIDATION
# ---------------------------------------------------------------------------------------------
def is_publishable(proposal):
    """THE CREDENTIAL GATE, as one named predicate instead of an inline `if` at the call site.

    A refused proposal is stored so it can be read, and must never be written anywhere. That rule was a
    `continue` inside validation, which meant the guarantee lived in whichever loop happened to iterate
    the results; now the publisher asks this, and a test can ask it too."""
    return not proposal.get("refused")


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
        fired = redaction_count(raw, clean)
        if fired:
            notes.append(f"proposal[{i}] contained {fired} secret-shaped string(s); redacted before storage")

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
