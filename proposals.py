"""Validate, redact and fingerprint what the model returned, before any of it is written anywhere.

THIS MODULE IS THE TRUST BOUNDARY. Upstream of it, every string is model output derived from telemetry
and from real user conversations — attacker-influenceable on both counts. Downstream of it, strings are
written into Kubernetes objects and pull request bodies that people will read and act on. Nothing
crosses without passing through here.
"""
import hashlib
import re

import yaml

from prompt import ALERT_API_VERSION

# ---------------------------------------------------------------------------------------------
# 1. WHERE A PROPOSAL MAY LAND
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
    # ADDED AFTER THE LIST WAS AUDITED AND FOUND THIN. A denylist is never complete — that is not a
    # reason to leave known families out of it, and each of these is a credential that would otherwise
    # survive a model's summary into a pull request body.
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "<REDACTED-GITLAB-PAT>"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), "<REDACTED-SLACK-TOKEN>"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "<REDACTED-GOOGLE-API-KEY>"),
    # user:pass@host in a URL — the password is the part that matters, so the host is left readable.
    (re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+):[^\s/@]+@"), r"\1:<REDACTED>@"),
    (re.compile(r"(?i)\b(api[_\-]?key|client[_\-]?secret|access[_\-]?token|password|passwd)"
                r"\s*[=:]\s*[\"\']?([A-Za-z0-9._\-]{8,})[\"\']?"), r"\1=<REDACTED>"),
    # THE SAME KEYS, JSON-QUOTED. The pattern above needs the colon right after the key, and in JSON a
    # quote sits between them — so `"password": "hunter2hunter2"` passed through untouched. That shape
    # was rare while only people's questions were read; tool ARGUMENTS are rendered as JSON, and the
    # agent-analysis stage reads every one of them. `token` is here bare as well, because tool arguments
    # carry it bare; `secret` is not, because in Kubernetes JSON it is far more often a Secret's NAME.
    (re.compile(r"(?i)\"(api[_\-]?key|client[_\-]?secret|access[_\-]?token|refresh[_\-]?token|token|password|passwd)\""
                r"\s*:\s*\"[^\"\\]{8,}\""), r'"\1": "<REDACTED>"'),
    # AND IN PROSE. People type "my password is X" to an agent, and agents answer "the password is X";
    # neither has a colon, so both passed. Found by the agent-analysis end-to-end run, where a planted
    # password in a question reached the fake reviewer — through #32's question read as well. The value
    # must carry a digit: prose has no other way to tell "the password is hunter2hunter2" from "the
    # password is required", and redacting English would make every transcript unreadable. A password of
    # letters only still passes; that is this pattern's stated limit, not an oversight.
    (re.compile(r"(?i)\b(password|passwd|api[_\- ]?key|token)(\s+(?:is|was|=)\s+)[\"\']?(?=[^\s\"\']*\d)[^\s\"\']{8,}[\"\']?"),
     r"\1\2<REDACTED>"),
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


# ---------------------------------------------------------------------------------------------
# 3b. SUBJECT — what a proposal is ABOUT, independent of where it would land
# ---------------------------------------------------------------------------------------------
# THE TARGET WAS NEVER A STABLE KEY FOR A FINDING, and the proposals on 057 are the measurement. One
# chart-inspector failure produced five Alert proposals across four repositories
# (installer-chart-inspector twice, sre-alerts, observability, monitoring), four of them still open on
# 2026-09-29 — each a different target_key, so each one looked new, and none superseded another. The model chooses the repository
# afresh every night; it is a weak signal of identity. What stays the same is the FINDING: which
# component, failing how.
#
# ONE NORMALISED STRING, `component/signal`, rather than a {service, signal} object. It is compared for
# equality and nothing else, so structure buys nothing the separator does not; one string is one CRD
# field, one printer column, one selector a portal can filter on, and one thing to eyeball in `kubectl
# get`. Both halves are lowercase kebab so the model's casing and punctuation cannot split one finding
# into two: `Snowplow/SubjectAccessReview Unauthorized` and `snowplow:subjectaccessreview-unauthorized`
# are the same subject.
_SLUG_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SLUG_NON = re.compile(r"[^a-z0-9]+")
SUBJECT_MAX = 160


def _slug(text):
    """CannotObserveExternalResource -> cannot-observe-external-resource; `HTTP 500!` -> http-500.
    CamelCase is split BEFORE lowercasing, because event reasons arrive CamelCase from Kubernetes and
    kebab from the model's paraphrase of them, and the two must meet."""
    return _SLUG_NON.sub("-", _SLUG_CAMEL.sub("-", text).lower()).strip("-")


def normalise_subject(value):
    """`component/signal`, normalised, or None when there is nothing usable to normalise.

    REWRITES, NEVER REFUSES. A colon where a slash was asked for, capitals, spaces — all folded. Only a
    value with no separator, or with an empty half after folding, comes back None, and None is a
    legitimate state: it is what every proposal written before this field existed carries, and
    subject_key guarantees it never groups."""
    if not isinstance(value, str):
        return None
    m = re.match(r"\s*([^/:]+)[/:](.+)", value)
    if not m:
        return None
    component, signal = _slug(m.group(1)), _slug(m.group(2))
    if not component or not signal:
        return None
    return f"{component}/{signal}"[:SUBJECT_MAX]


def subject_key(proposal):
    """(kind, subject), or None — AND None MUST NEVER BE A KEY. The twenty proposals on 057 that predate
    this field all carry no subject; if a missing subject compared equal to another missing subject,
    the first new proposal of each kind would supersede every legacy one of that kind in one night.

    KIND IS PART OF THE KEY on purpose. An Alert and a Documentation proposal about the same failure are
    two halves of one answer, not successive opinions on one question, and neither should retire the
    other."""
    subject = proposal.get("subject")
    if not subject:
        return None
    return "\x1f".join([proposal["kind"], subject])


def classify(proposal, by_fingerprint, by_target, by_subject=None, decided=None):
    """(action, priors). THREE OUTCOMES, WHERE THE CODE USED TO SEE TWO — and the missing third is why
    `superseded` was reported as a hardcoded 0 every night while its own docstring described a
    mechanism that did not exist.

    - Identical to something already open is a duplicate: ("dedup", name). The fingerprint wins over
      everything, because an exact repeat is not a new opinion however it is labelled.
    - The same FINDING (kind + subject) as a Proposed one from an earlier night, or the same FILE with a
      different body, is a replacement: ("supersede", [names]). The open ones are stale and are marked
      Superseded rather than left beside their own successor for a human to reconcile. A LIST, because
      the two keys can each name a different prior and both are stale.
    - Exactly what a PERSON has already answered (Rejected, Merged, or a PrOpen they opened) is
      ("decided", name) — neither a duplicate of an open question nor a new one. It is not written:
      the object is named by its fingerprint, so writing it would reset that person's answer to
      Proposed. `decided` is publish.open_index's fourth, optional index.
    - Otherwise ("new", None)."""
    fp = fingerprint(proposal)
    if decided and fp in decided:
        return "decided", decided[fp]
    if fp in by_fingerprint:
        return "dedup", by_fingerprint[fp]
    priors = []
    key = subject_key(proposal)
    if key is not None and by_subject:
        priors += [p["name"] for p in by_subject.get(key, ()) if p.get("fingerprint") != fp]
    prior = by_target.get(target_key(proposal))
    if prior and prior.get("fingerprint") != fp and prior["name"] not in priors:
        priors.append(prior["name"])
    if priors:
        return "supersede", priors
    return "new", None


# ---------------------------------------------------------------------------------------------
# 3c. THE ALERT KIND (#24)
# ---------------------------------------------------------------------------------------------
# Kinds and groups that are alert-shaped and dead here. Every one of the thirteen Alert proposals on 057
# on 2026-09-29 was one of these; see prompt.ALERT_KIND for why none of them can fire on this platform.
FORBIDDEN_ALERT_KINDS = frozenset({"PrometheusRule"})
FORBIDDEN_ALERT_GROUPS = frozenset({"monitoring.krateo.io", "monitoring.coreos.com"})
_FORBIDDEN_TEXT = re.compile(r"\bPrometheusRule\b|\bmonitoring\.krateo\.io\b|\bmonitoring\.coreos\.com\b")


def alert_kind_violation(proposal):
    """A sentence saying why change.content carries an alert this platform cannot evaluate, or None.

    TWO RULES, SCOPED DIFFERENTLY ON PURPOSE.
    - Any proposal whose YAML declares a PrometheusRule or an object in a forbidden group is refused,
      whatever its kind: a dead alert smuggled into a Policy proposal is as dead as one in an Alert.
    - An ALERT proposal must declare nothing but observability.krateo.io/v1alpha1 Alert. Not applied to
      other kinds, because `alerts.widgets.templates.krateo.io` is a real portal widget called Alert and
      a Widget proposal may legitimately carry one.
    A document with neither kind nor apiVersion is not an object declaration and is left alone. Content
    that is not parseable YAML — a diff, markdown — is scanned as text for the forbidden names, but only
    for Alert proposals: documentation may mention PrometheusRule in prose, an Alert may not ship one."""
    change = proposal.get("change") or {}
    content = change.get("content") or ""
    docs = None
    if change.get("format") == "yaml":
        try:
            docs = [d for d in yaml.safe_load_all(content) if isinstance(d, dict)]
        except yaml.YAMLError:
            docs = None
    if docs is None:
        if proposal.get("kind") == "Alert" and _FORBIDDEN_TEXT.search(content):
            return (f"an Alert proposal must carry an {ALERT_API_VERSION} Alert; its content names "
                    f"{_FORBIDDEN_TEXT.search(content).group(0)}, which nothing on this platform evaluates")
        return None
    for d in docs:
        kind, api = d.get("kind"), d.get("apiVersion")
        if kind is None and api is None:
            continue
        group = str(api or "").split("/")[0]
        if kind in FORBIDDEN_ALERT_KINDS or group in FORBIDDEN_ALERT_GROUPS:
            return (f"declares {api}/{kind}, which nothing on this platform evaluates — the only alert "
                    f"kind is {ALERT_API_VERSION} Alert")
        if proposal.get("kind") == "Alert" and (kind, api) != ("Alert", ALERT_API_VERSION):
            return (f"an Alert proposal must carry only {ALERT_API_VERSION} Alert objects; "
                    f"it declares {api}/{kind}")
    return None


# ---------------------------------------------------------------------------------------------
# 4. VALIDATION
# ---------------------------------------------------------------------------------------------
# THE ALLOWLIST IS GONE, DELIBERATELY, AND THIS COMMENT IS ITS EPITAPH so the next reader does not
# reintroduce it by accident. It bounded which repository a proposal could name, and it existed because
# this service used to hold a GitHub write credential: `target.repo` is chosen by the model from a
# corpus containing user-written chat, so an unbounded target aimed that credential wherever the corpus
# liked. Two things changed. Publishing moves to the platform's own chain, so the credential is
# git-provider's rather than the reviewer's; and every proposal now opens a pull request on a branch,
# which a human reads before anything merges. The review IS the control, and a proposal blocked before
# it becomes a pull request teaches nobody anything — not the reader, and not the next night's review.
#
# What that costs, stated plainly rather than left for someone to discover: the reviewer may now name
# any repository the install-level git credentials can write to.


class Refused(Exception):
    """Raised for the WHOLE batch. A partially valid response is not salvaged: deciding which half the
    model meant is exactly the guess this service exists not to make."""


def validate_batch(payload, schema_check, item_check=None):
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

        # NO CONFIDENCE CAP, DELIBERATELY (#14). There used to be one here: high was demoted to medium
        # unless the proposal carried two evidence items or a summed observedCount of two or more. It
        # read as evidence verification and was arithmetic on the model's own claims — observedCount is
        # model-authored and unbounded, so a single fabricated item claiming 900 satisfied it. Measured
        # on the nine real proposals from 057: four carried exactly one evidence item, so the length
        # clause caught all four, and all four kept high because the model's own counts (636, 612,
        # 8459, 4403) cleared the threshold. The cap never once changed an outcome, and a check that
        # cannot fail is worse than no check, because it is read as one.
        #
        # So `confidence` is the MODEL's self-report and the CRD now says so. The service cannot do
        # better here: it knows the corpus it gathered, not which rows support proposal 3, and a
        # confidence derived from corpus-level facts would be identical for every proposal in a run —
        # a run-level quality score wearing a per-proposal label, which is a subtler lie than this one.
        # Earning the field back needs the model to CITE rather than assert: evidence items naming one
        # of the service's own query names, validated against a per-run enum of the queries that
        # actually ran (see prompt.py — the same move that removed evidence[].query). The grounded
        # per-proposal prior is the merge/reject history, which is #21.

        # REFUSED WHOLE, WITH THE REASON, because a PrometheusRule is not a draft of an Alert that a
        # reviewer could fix in review — it is a different system, and merging it adds an alert that
        # never fires while looking like coverage. The note is what tells the next prompt change it is
        # still happening. Checked AFTER redaction so the note cannot quote a secret.
        dead = alert_kind_violation(clean)
        if dead:
            notes.append(f"DROPPED proposal[{i}] ({clean.get('kind')}): {dead}")
            continue

        # Normalised, not validated: see normalise_subject. A subject that folds to nothing is kept as
        # null WITH A NOTE, so the proposal survives and the run still says that one of its findings
        # can never be matched against tomorrow's.
        subject = normalise_subject(clean.get("subject"))
        if subject is None:
            clean.pop("subject", None)
            notes.append(f"proposal[{i}] carried no usable subject; it will not group with later nights")
        else:
            clean["subject"] = subject

        clean["fingerprint"] = fingerprint(clean)
        kept.append(clean)

    return kept, notes
