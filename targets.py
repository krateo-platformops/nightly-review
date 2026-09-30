"""Does the repository a proposal names actually exist? Recorded as a condition, never enforced.

WHY THIS IS A QUESTION AT ALL. `target.repo` is chosen by the model, and it invents repositories. Of
the twenty proposals on 057 on 2026-09-29, TWELVE named a repository that does not exist — nine
distinct names in krateo-platformops (`sre-alerts`, `monitoring`, `krateo-system`, `kagent`,
`clickstack` and others), each a plausible name for where such a file might live. Checked with an
authenticated client, so these are missing rather than private. A reviewer reading one of those has no way to
tell from the object that the pull request it proposes could never be opened.

A NORMAL STATE, NOT A REJECTION. A proposal aimed at a repository that does not exist still carries a
real finding; the evidence and the rationale are as good as they were. So it is written, with
TargetResolved=False, and a human (or the portal) re-aims it. Dropping it would throw away the finding
to punish the address.

AUTHENTICATED WHEN THE CHART SAYS SO, WITH A CREDENTIAL THIS SERVICE CANNOT GO AND FETCH. The check
was anonymous, and on 057 that made it useless exactly where it mattered: every Prompt proposal of
rr-20260930-0200 aimed at a krateo-agentiko repository, all of which are private, and all of them read
NotFoundOrPrivate — including krateo-agentiko/installer-agent and krateo-agentiko/autopilot, which exist.
So config.targetCheck.tokenSecret names a key of an EXISTING Secret (gh-token/token on 057) and the
CronJob injects it as TARGET_CHECK_TOKEN through `valueFrom.secretKeyRef`. The KUBELET reads that
Secret, not this service: the ServiceAccount still holds no `get` on Secrets, so what the anonymous
design protected — a component whose corpus goes to a model cannot read Secrets and put one in a
prompt — still holds for every Secret but this one value, and this value is used in exactly one place:
the Authorization header of the HEAD below. It is never logged, never in a condition, never in a
prompt; test_the_check_token_reaches_nothing_but_the_check runs a whole main.main() with a fake one to
hold that. What it does cost, stated: the process now holds a GitHub credential (gh-token is a PAT
that can write), where before it held none. It never writes with it — HEAD is the only verb here.

WHAT EACH ANSWER MEANS DEPENDS ON WHETHER A TOKEN WAS SENT.
- anonymous 404: NotFoundOrPrivate, as before. GitHub answers 404 for a PRIVATE repository to an
  anonymous caller, exactly as for a missing one, and the message says the check cannot tell them apart.
- authenticated 404: RepoNotFound. Definitive for every repository the credential can see — which, for
  the platform's own token, is the orgs it publishes to. The message still names that limit.
- authenticated 200 on a private repository: RepoFound. That is the point of sending it.
- 401: the credential was REJECTED (expired, revoked, mistyped). Unknown/CheckFailed, never
  RepoNotFound — a bad token says nothing about the repository.

Rate limit: 60 requests an hour anonymously, 5000 authenticated. A run writes at most twelve proposals
and each repository is asked once per run (the cache), so a night spends at most twelve either way.

WHERE A PROPOSAL LANDS IS CONFIGURATION, NEVER A MODEL CHOICE AND NEVER CODE (see aim() below).
rr-20260930-0200 aimed all three of its Alert proposals at `krateo-observability` — no owner, and not
the repository's name — so all three read InvalidRepo, for a destination nobody had to guess: the
platform's alerts live in krateo-platformops/observability. Its other proposals went to repositories the
model built as `krateo-platformops/<component>`: krateo-platformops/kagent, installer-chart-inspector and
github-provider do not exist. So the destination comes from the chart's values and only from there —
config.targets per kind, then config.destinations.components per component — and a proposal neither
names gets NO repository rather than the model's guess (TargetResolved False/NoDestination).
"""
import json
import os
import pathlib
import re

import requests

import proposals as P

# Empty disables the check: every proposal then records TargetResolved=Unknown/CheckDisabled, which
# is visibly different from a check that ran and found nothing.
API_URL = os.environ.get("TARGET_CHECK_API_URL", "https://api.github.com")
TIMEOUT = 10

# GitHub's own rules for owner and repository names. THIS IS A SECURITY CHECK AS WELL AS A SHAPE ONE:
# the string is model output from an attacker-influenceable corpus and is about to become part of a
# URL. `../`, `?`, `#` or a second slash could steer the request at a different endpoint; nothing
# outside this alphabet reaches requests.
_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

TYPE = "TargetResolved"

# The env var the CronJob fills from config.targetCheck.tokenSecret. Read at CALL time rather than at
# import, so nothing keeps a copy in a module global that a later refactor could print.
TOKEN_ENV = "TARGET_CHECK_TOKEN"

# kind -> {repo, pathPrefix}: config.targets, as JSON — the KIND OVERRIDE, which wins over everything.
# component -> {repo, pathPrefix, prompt?: {repo, path}}: config.destinations.components, as JSON.
# BOTH LIVE IN THE CHART'S values.yaml AND NOWHERE ELSE — not here, and not as a values.schema.json
# default, which core-provider would write into the live composition spec as a value nobody typed. Empty
# here, so a run without them aims nothing: every proposal then records NoDestination, which is the
# honest state for an install that has not said where anything goes.
DESTINATIONS = json.loads(os.environ.get("TARGET_DESTINATIONS") or "{}")
COMPONENTS = json.loads(os.environ.get("TARGET_COMPONENTS") or "{}")


def _cond(status, reason, message):
    return {"type": TYPE, "status": status, "reason": reason, "message": message[:500]}


def resolve(repo, cache=None):
    """The TargetResolved condition for `owner/name` (lastTransitionTime is the writer's to add).

    True/RepoFound, False/NotFoundOrPrivate (anonymous 404), False/RepoNotFound (authenticated 404),
    False/InvalidRepo, or Unknown with CheckFailed/CheckDisabled —
    Unknown is not a softer False: it means this run could not ask, and says why."""
    if cache is not None and repo in cache:
        return cache[repo]
    cond = _resolve(repo)
    if cache is not None:
        cache[repo] = cond
    return cond


def _resolve(repo):
    owner, _, name = (repo or "").partition("/")
    if not _NAME.match(owner) or not _REPO.match(name) or name in (".", ".."):
        return _cond("False", "InvalidRepo", f"{repo!r} is not a GitHub owner/name")
    if not API_URL:
        return _cond("Unknown", "CheckDisabled", "config.targetCheckApiUrl is empty; existence not checked")
    url = f"{API_URL.rstrip('/')}/repos/{owner}/{name}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "krateo-nightly-review"}
    token = os.environ.get(TOKEN_ENV, "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        # allow_redirects: a RENAMED repository answers 301 to its new name and still exists. requests
        # drops Authorization on a redirect to another host, so the token cannot follow one off GitHub.
        r = requests.head(url, timeout=TIMEOUT, allow_redirects=True, headers=headers)
    except Exception as exc:                                  # noqa: BLE001
        # The exception's TYPE only: its text can carry the request, and the request carries the token.
        return _cond("Unknown", "CheckFailed", f"HEAD {url}: {type(exc).__name__}")
    if r.status_code == 200:
        return _cond("True", "RepoFound", f"{owner}/{name} exists")
    if r.status_code == 401 and token:
        return _cond("Unknown", "CheckFailed",
                     f"HEAD {url} answered 401: the configured credential (config.targetCheck.tokenSecret) "
                     f"was rejected — expired, revoked or wrong. Says nothing about the repository.")
    if r.status_code == 404 and token:
        return _cond("False", "RepoNotFound",
                     f"No repository {owner}/{name} visible to the configured credential. Definitive for "
                     f"the organisations that credential can read; a private repository elsewhere would "
                     f"also answer 404.")
    if r.status_code == 404:
        # NOT "RepoNotFound": krateo-agentiko/krateo-autopilot and incident-agent are private and are
        # exactly where a Prompt proposal belongs. A reason that read "not found" would tell a reviewer the
        # model invented a repository it got right. The reason names both possibilities, so a UI can show
        # "unverified" rather than "wrong".
        return _cond("False", "NotFoundOrPrivate",
                     f"No public repository {owner}/{name}. It does not exist, or it is private — an anonymous "
                     f"check cannot tell those apart.")
    # 403 and 429 are the rate limit; anything else is GitHub having a bad night. Neither says anything
    # about the repository, so neither may be recorded as if it did.
    return _cond("Unknown", "CheckFailed", f"HEAD {url} answered {r.status_code}")


_FILE = re.compile(r"[^A-Za-z0-9._-]+")
_EXT = {"yaml": ".yaml", "markdown": ".md", "diff": ".diff"}

NO_DESTINATION = "NoDestination"


def component(proposal):
    """The subject's component half, normalised the way the subject itself is, or None. What a finding is
    ABOUT decides where it lands — never the repository the model proposed."""
    subject = P.normalise_subject(proposal.get("subject"))
    return subject.partition("/")[0] if subject else None


def _components(components):
    """The configured map with its keys normalised like a subject's component, so `Snowplow` in the
    values meets `snowplow` in a subject. A key that normalises to nothing is dropped, not guessed at."""
    out = {}
    for key, entry in (components or {}).items():
        norm = P.normalise_subject(f"{key}/x")
        if norm and isinstance(entry, dict):
            out[norm.partition("/")[0]] = entry
    return out


def _file_name(proposal):
    """The model's file name, reduced to a safe alphabet — it becomes a path in a pull request. With no
    usable basename the subject names the file, so one finding keeps one file across nights."""
    base = _FILE.sub("-", pathlib.PurePosixPath(proposal.get("target", {}).get("path") or "").name).lstrip(".-")
    if not base:
        fmt = (proposal.get("change") or {}).get("format")
        base = _FILE.sub("-", (proposal.get("subject") or "proposal").replace("/", "-")) + _EXT.get(fmt, ".txt")
    return base[:200]


def destination(proposal, destinations=None, components=None):
    """(repo, path, source) from the values, or (None, None, why) when they name none.

    PRECEDENCE, and why in this order:
      1. config.targets[kind] — a kind override. Every Alert is an observability.krateo.io Alert CR whatever
         it is about, so it lands in the observability chart whatever the component.
      2. config.destinations.components[component] — the component the subject names. For a Prompt proposal,
         only that entry's `prompt: {repo, path}`: a prompt is ONE file, so the path is taken exactly, and an
         entry without `prompt` is no destination for a Prompt — its chart repository is not its prompt.
      3. nothing: no destination. The model's own choice is never the fallback."""
    kinds = DESTINATIONS if destinations is None else destinations
    comps = _components(COMPONENTS if components is None else components)
    kind = proposal.get("kind")
    over = kinds.get(kind)
    if isinstance(over, dict) and over.get("repo"):
        return over["repo"], _join(over.get("pathPrefix"), _file_name(proposal)), f"config.targets.{kind}"
    comp = component(proposal)
    entry = comps.get(comp) if comp else None
    if not isinstance(entry, dict):
        return None, None, (f"no destination configured for component {comp}; add it to config.destinations"
                            if comp else "no subject component to look a destination up by; the subject "
                                         "could not be normalised")
    if kind == "Prompt":
        prompt = entry.get("prompt")
        if not (isinstance(prompt, dict) and prompt.get("repo") and prompt.get("path")):
            return None, None, (f"no prompt destination configured for component {comp}; add "
                                f"config.destinations.components.{comp}.prompt")
        return prompt["repo"], prompt["path"].strip("/"), f"config.destinations.components.{comp}.prompt"
    if not entry.get("repo"):
        return None, None, f"no destination configured for component {comp}; add it to config.destinations"
    return entry["repo"], _join(entry.get("pathPrefix"), _file_name(proposal)), \
        f"config.destinations.components.{comp}"


def _join(prefix, name):
    prefix = (prefix or "").strip("/")
    return f"{prefix}/{name}" if prefix else name


def aim(proposal, destinations=None, components=None):
    """Point a proposal at the destination the values give it, or at none. Returns a ValidationNotes line
    when it changed something, else None. THE CALLER RE-FINGERPRINTS: the target is part of the
    fingerprint, and a proposal named by its old target would neither dedup tomorrow nor supersede.

    WHY OVERRIDE AND NOT ASK. The prompt tells the model destinations are configured, but a prompt is a
    request; this is the guarantee. The model still chooses the FILE NAME (see _file_name) because that is
    a real per-finding choice; the repository and the directory are not.

    NO DESTINATION CLEARS target.repo. Keeping the model's guess would be keeping exactly what this
    replaces — rr-20260930-0200's `krateo-platformops/<component>` repositories that do not exist. The
    path keeps only the file name, because its directory belonged to the guessed repository. The proposal
    is still written — the finding is real — and no_destination() is its TargetResolved condition."""
    target = proposal.setdefault("target", {})
    old = f"{target.get('repo') or ''}/{target.get('path') or ''}".strip("/")
    repo, path, source = destination(proposal, destinations, components)
    if repo is None:
        target["repo"], target["path"] = "", _file_name(proposal)
        return f"{proposal.get('kind')} proposal {old or '(no target)'} cleared: {source}"
    target["repo"], target["path"] = repo, path
    new = f"{repo}/{path}"
    if new == old:
        return None
    return f"{proposal.get('kind')} proposal retargeted {old} -> {new} ({source})"


def no_destination(proposal, destinations=None, components=None):
    """The TargetResolved condition of a proposal the values give no destination: False, because it cannot
    become a pull request as it stands, with a reason a UI can tell apart from a repository GitHub denied.
    The message is recomputed from kind and subject — both untouched by aim() — rather than carried on the
    proposal, where an extra key would reach the Proposal spec and be pruned."""
    _, _, why = destination(proposal, destinations, components)
    return _cond("False", NO_DESTINATION, why)
