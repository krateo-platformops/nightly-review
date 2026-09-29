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

UNAUTHENTICATED, DELIBERATELY. The only git credential on this platform is git-provider's, held in a
Secret that the publish chain reads. Using it here would mean granting this service Secret read, which
its RBAC withholds on purpose — the corpus it assembles goes to a model, and a component that can read
Secrets can put one in a prompt — and would put back the very credential #13 removed. An anonymous
`HEAD /repos/{owner}/{repo}` answers the question for every PUBLIC repository at no cost in trust.

What that costs, stated rather than discovered: GitHub answers 404 for a PRIVATE repository to an
anonymous caller, exactly as for a missing one. Eight krateo-platformops repositories are private
today. A proposal aimed at one reads NotFoundOrPrivate — named for exactly that — and the message says the check cannot
tell the two apart — so the False is honest about its own limit rather than a flat claim.

Rate limit: 60 unauthenticated requests an hour per egress IP. A run writes at most twelve proposals
and each repository is asked once per run, so a night spends at most twelve.
"""
import os
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


def _cond(status, reason, message):
    return {"type": TYPE, "status": status, "reason": reason, "message": message[:500]}


def resolve(repo, cache=None):
    """The TargetResolved condition for `owner/name` (lastTransitionTime is the writer's to add).

    True/RepoFound, False/NotFoundOrPrivate, False/InvalidRepo, or Unknown with CheckFailed/CheckDisabled —
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
    try:
        # allow_redirects: a RENAMED repository answers 301 to its new name and still exists.
        r = requests.head(url, timeout=TIMEOUT, allow_redirects=True,
                          headers={"Accept": "application/vnd.github+json",
                                   "User-Agent": "krateo-nightly-review"})
    except Exception as exc:                                  # noqa: BLE001
        return _cond("Unknown", "CheckFailed", f"HEAD {url}: {type(exc).__name__}")
    if r.status_code == 200:
        return _cond("True", "RepoFound", f"{owner}/{name} exists")
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
