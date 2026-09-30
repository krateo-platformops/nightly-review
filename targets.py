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

WHERE A PROPOSAL OF A GIVEN KIND LANDS IS CONFIGURATION, NOT A MODEL CHOICE, when the chart says so
(config.targets; see aim() below). rr-20260930-0200 aimed all three of its Alert proposals at
`krateo-observability` — no owner, and not the repository's name — so all three read InvalidRepo and
none could ever have become a pull request, for a destination nobody had to guess: the platform's
alerts live in krateo-platformops/observability.
"""
import json
import os
import pathlib
import re

import requests

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

# kind -> {repo, pathPrefix}: config.targets, as JSON. The default is the chart's default, so a run
# without the env behaves like an install with it. A kind absent here stays the model's choice.
DESTINATIONS = json.loads(os.environ.get("TARGET_DESTINATIONS") or
                          '{"Alert": {"repo": "krateo-platformops/observability", '
                          '"pathPrefix": "charts/krateo-observability/templates"}}')


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


def aim(proposal, destinations=None):
    """Point a proposal of a configured kind at its configured repository and directory. Returns a
    ValidationNotes line when it moved something, else None. THE CALLER RE-FINGERPRINTS: the target is
    part of the fingerprint, and a proposal named by its old target would neither dedup tomorrow nor
    supersede correctly.

    WHY OVERRIDE AND NOT ASK. The prompt now tells the model where these kinds go, but a prompt is a
    request; this is the guarantee. The model still chooses the FILE NAME (the basename of its path,
    reduced to a safe alphabet — it becomes a path in a pull request) because that is a real per-finding
    choice; the directory is not. With no usable basename the subject names the file, so one finding keeps
    one file across nights."""
    dest = (destinations if destinations is not None else DESTINATIONS).get(proposal.get("kind"))
    if not isinstance(dest, dict) or not dest.get("repo"):
        return None
    target = proposal.setdefault("target", {})
    old = f"{target.get('repo')}/{target.get('path') or ''}".rstrip("/")
    target["repo"] = dest["repo"]
    prefix = (dest.get("pathPrefix") or "").strip("/")
    if prefix:
        base = _FILE.sub("-", pathlib.PurePosixPath(target.get("path") or "").name).lstrip(".-")
        if not base:
            fmt = (proposal.get("change") or {}).get("format")
            base = _FILE.sub("-", (proposal.get("subject") or "proposal").replace("/", "-")) + _EXT.get(fmt, ".txt")
        target["path"] = f"{prefix}/{base[:200]}"
    new = f"{target['repo']}/{target.get('path') or ''}".rstrip("/")
    if new == old:
        return None
    return f"{proposal['kind']} proposal retargeted {old} -> {new} (config.targets.{proposal['kind']})"
