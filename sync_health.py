"""Krateo-managed resources that have been out of sync for longer than anyone should have to notice.

WHY THIS EXISTS. On 2026-10-01 the GitHub token in krateo-system/git-provider-credentials expired. Every
github.krateo.io Repository and PullRequest and every git.krateo.io Repo and LocalResource went
Synced=False with a 401 and stayed that way for hours — 0 of 24 Repositories synced — and nothing on the
platform said so. It was found because a publish stalled and a person went looking. An expired token, a
revoked one, a narrowed scope and a deleted repository all present exactly like that: a controller that
keeps reconciling, a condition that keeps saying False, and a portal that keeps looking fine.

WHAT IT IS, AND WHAT IT IS NOT. A deterministic check, run by the nightly review: no model decides
whether a resource is failing, and none decides the count. It lists every kind the API serves in the
configured groups (config.syncStall.groups — DISCOVERED, so a provider that grows a kind is covered the
night it ships), keeps the objects whose Synced condition is False (or, with no Synced verdict, whose
Ready is False for a reconcile-error reason) for longer than config.syncStall.thresholdMinutes by the
condition's own lastTransitionTime, and groups them by provider component and by what the message says
went wrong: "401 Unauthorized x24 — credential rejected". Each group becomes ONE Proposal, written by the
service whether or not the model call succeeds that night. It is a NIGHTLY BACKSTOP: the outage above
would still have been found up to a day late. Catching it in minutes is an in-cluster alert's job.

THE CONDITION CLOCK HAS ONE BLIND SPOT, stated rather than discovered. provider-runtime's SetConditions
replaces a condition whenever its MESSAGE changes, and stamps a new lastTransitionTime when it does — so a
failure whose message carries something that changes every reconcile (a request id, a timestamp) looks
perpetually fresh and is never reported as sustained. Every failure under the threshold is therefore
counted on the run (`freshFailures`) and listed in the corpus, so a large number there is visible even when
no finding is.

SECRETS ARE NAMED, NEVER READ. A credential is found by its REFERENCE: a `{name, key}` mapping under a
`*Ref` key in the failing object's spec (git-provider's secretRef/usernameRef) or in the spec of the
Configuration its `configurationRef` names (KOG's authentication.bearer.tokenRef). The Configuration is a
custom resource in the same group, read with the same grant; no Secret is ever fetched, and this service's
ServiceAccount still has no verb on Secrets. That also rules out the obvious nicety — checking whether a
token has expired before it is rejected — because every way of doing it starts with reading the token.
It is skipped on purpose.
"""
import collections
import datetime as dt
import json
import os
import re

import proposals as P

# group -> {component, kinds}: config.syncStall.groups, as JSON. EMPTY HERE, like every destination: which
# groups are checked is the chart's values, never the code's. Empty disables the check, and says so.
GROUPS = json.loads(os.environ.get("SYNC_STALL_GROUPS") or "{}")
THRESHOLD_MINUTES = int(os.environ.get("SYNC_STALL_THRESHOLD_MINUTES") or "15")
# Ready=False counts as failing only for these reasons, and only when there is no Synced verdict: Ready is
# also False while an object is being created or deleted, which is progress, not a stall.
READY_ERROR_REASONS = [r.strip() for r in (os.environ.get("SYNC_STALL_READY_REASONS") or "ReconcileError").split(",")
                       if r.strip()]
# Synced=False that is somebody's intent rather than a failure: a paused reconcile.
IGNORE_REASONS = [r.strip() for r in (os.environ.get("SYNC_STALL_IGNORE_REASONS") or "ReconcilePaused").split(",")
                  if r.strip()]
PAGE = 500
MAX_PAGES = 20               # 10,000 objects of one kind; past that the kind is recorded as cut
MAX_FINDINGS = 10            # one Proposal per (component, pattern); a night that wants more is one incident
EXAMPLES = 3
MESSAGE_CHARS = 300

SOURCE = "sync-health"
AGENT = "nightly-review/sync-stall"

# WHAT A MESSAGE SAYS WENT WRONG, most specific first. Each pattern is a stable signal for the Proposal's
# subject, so the same outage tomorrow is the same finding, whatever the counts.
#
# A STATUS CODE COUNTS ONLY IN HTTP CONTEXT: beside its reason phrase ("401 Unauthorized") or after a word
# that introduces a status ("status 404", "returned 403"). A bare number is an object's particulars — "update
# pull request 401 in org/repo: 422 Unprocessable Entity" is a 422, and a repository named r-404-old is not
# a 404.
def _http(code, phrase):
    return (rf"\b(?:http(?:/[\d.]+)?|status(?:\s*code)?|code|returned|got|answered|response)\s*[:=]?\s*{code}\b"
            rf"|\b{code}\s+{phrase}")


PATTERNS = [
    # A Secret the object (or its Configuration) names does not exist IN THIS CLUSTER. Before every remote
    # pattern: the apiserver's `secrets "x" not found` would otherwise read as a deleted repository.
    ("local-secret-missing", "a Secret the resources reference does not exist in the cluster",
     re.compile(r"\bsecrets?\s+\"[^\"]*\"\s+not found|\bsecret\b[^:]{0,80}\bnot found\b", re.I)),
    # Before permission-denied: GitHub answers a primary or secondary rate limit with 403, not 429.
    ("rate-limited", "rate limited by the remote API",
     re.compile(_http(429, "Too Many Requests") + r"|rate.?limit|too many requests", re.I)),
    ("credential-rejected", "credential rejected — expired, revoked or wrong",
     re.compile(_http(401, "Unauthori[sz]ed")
                + r"|\bunauthori[sz]ed\b|bad credentials|authentication (?:failed|required)|invalid (?:token|credentials)",
                re.I)),
    ("permission-denied", "permission denied — token scope, SSO authorisation or an org policy",
     re.compile(_http(403, "Forbidden") + r"|\bforbidden\b|resource not accessible|permission denied", re.I)),
    ("remote-not-found", "remote object not found — deleted, renamed, or not visible to the credential",
     re.compile(_http(404, "Not Found") + r"|repository not found|\bnot found\b", re.I)),
    ("remote-rejected-request", "remote rejected the request as invalid",
     re.compile(_http(422, "Unprocessable") + r"|\bunprocessable\b", re.I)),
    ("remote-unreachable", "remote unreachable — timeout, DNS or connection",
     re.compile(r"deadline exceeded|timed? ?out|connection refused|connection reset|no such host|\bEOF\b", re.I)),
]
_URL = re.compile(r"https?://\S+")
_FALLBACK_STRIP = re.compile(r"\"[^\"]*\"|'[^']*'|/\S+|\b[0-9a-f]{7,}\b|\d+")


def classify(reason, message):
    """(signal, description) for a failing condition. A message no pattern knows is named by its first
    clause with every quoted string, URL, path and number taken out — Go wraps errors outermost-first, so
    the first clause is the operation that failed and the rest is this object's particulars."""
    text = message or ""
    for signal, description, pat in PATTERNS:
        if pat.search(text):
            return signal, description
    # URLs out BEFORE the split: "GET https://api.github.com/...: ..." split on its first colon is `GET https`.
    head = _FALLBACK_STRIP.sub(" ", _URL.sub(" ", text).split(": ", 1)[0])
    slug = P._slug(head)[:60].strip("-")
    if not slug:
        slug = P._slug(reason or "") or "unknown"
    return slug, f"{reason or 'failing'}: {' '.join(head.split())[:120] or 'no message'}"


def _parse(ts):
    if not isinstance(ts, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    # A time with no zone is UTC, as the apiserver writes it. Left naive, comparing it with the aware cutoff
    # raised TypeError and cost the night every sync finding.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def failing_condition(obj):
    """The condition that says this object is failing, or None.

    Synced is the reconcile's verdict and wins: Synced=True is a healthy object however old or odd its Ready
    condition looks, and a Synced=False carrying an ignored reason (a paused reconcile) is intent. Ready is
    consulted only when there is no Synced verdict at all, and only for a reconcile-error reason."""
    conds = {c.get("type"): c for c in ((obj.get("status") or {}).get("conditions") or []) if isinstance(c, dict)}
    synced, ready = conds.get("Synced"), conds.get("Ready")
    if synced and synced.get("status") == "True":
        return None
    if synced and synced.get("status") == "False":
        return None if synced.get("reason") in IGNORE_REASONS else synced
    if ready and ready.get("status") == "False" and ready.get("reason") in READY_ERROR_REASONS:
        return ready
    return None


def secret_refs(spec, namespace):
    """Every `{name, key}` mapping under a `*Ref` key — the Kubernetes shape of a pointer at one key of a
    Secret — as "namespace/name". NAMES ONLY: nothing here, or anywhere in this service, reads the Secret."""
    out = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if (isinstance(k, str) and k.endswith("Ref") and isinstance(v, dict)
                        and isinstance(v.get("name"), str) and "key" in v):
                    out.add(f"{v.get('namespace') or namespace}/{v['name']}")
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(spec)
    return out


def discoverer(api_client):
    """group -> [(version, plural, kind, namespaced)], read from the API's discovery documents.

    Every version the group serves, PREFERRED FIRST, because a group's kinds need not share one: on 057
    github.krateo.io serves its resources at v2022-11-28 and their Configurations at v1alpha1, so a scan of
    the preferred version alone would never see a Configuration. A kind is taken at the first version that
    serves it. Discovery needs no RBAC beyond being authenticated."""
    def discover(group):
        doc = api_client.call_api(f"/apis/{group}", "GET", response_type="object",
                                  auth_settings=["BearerToken"], _return_http_data_only=True)
        preferred = ((doc or {}).get("preferredVersion") or {}).get("version")
        versions = [v.get("version") for v in (doc or {}).get("versions") or []]
        versions = ([preferred] if preferred else []) + [v for v in versions if v and v != preferred]
        seen, out = set(), []
        for version in versions:
            res = api_client.call_api(f"/apis/{group}/{version}", "GET", response_type="object",
                                      auth_settings=["BearerToken"], _return_http_data_only=True)
            for r in (res or {}).get("resources") or []:
                if "/" in r.get("name", "") or "list" not in (r.get("verbs") or []) or r.get("kind") in seen:
                    continue
                seen.add(r["kind"])
                out.append((version, r["name"], r["kind"], bool(r.get("namespaced"))))
        return out
    return discover


def _list(api, group, version, plural, stats):
    items, token = [], None
    for _ in range(MAX_PAGES):
        kw = {"limit": PAGE}
        if token:
            kw["_continue"] = token
        got = api.list_cluster_custom_object(group, version, plural, **kw)
        items += got.get("items") or []
        token = (got.get("metadata") or {}).get("continue")
        if not token:
            return items
    stats["note"] = stats.get("note", "") + f"{plural}.{group}: stopped after {len(items)} objects; "
    stats["truncated"] = True
    return items


def gather(api, discover, now=None, groups=None, threshold_minutes=None):
    """(body, stats, proposals). body is the corpus block for the main review (None when nothing is out of
    sync); proposals are this check's own findings, in the shape the model's are validated in, one per
    (component, pattern) — and they are written by main.py whether or not the model answers.

    EACH GROUP AND EACH KIND FAILS ON ITS OWN, like every source: a kind that 403s is recorded, ok:false
    makes the run PartiallyCompleted, and the kinds that answered still produce their findings."""
    now = now or dt.datetime.now(dt.timezone.utc)
    groups = GROUPS if groups is None else groups
    threshold = THRESHOLD_MINUTES if threshold_minutes is None else threshold_minutes
    cutoff = now - dt.timedelta(minutes=threshold)
    stats = {"ok": True, "queried": 0, "returned": 0, "stalled": 0, "freshFailures": 0,
             "findings": 0, "thresholdMinutes": threshold}
    configured = {g: c for g, c in (groups or {}).items() if g and isinstance(c, dict)}
    if not configured:
        stats |= {"empty": True, "note": "config.syncStall.groups is empty; nothing was checked"}
        return None, stats, []

    def fail(what, exc):
        stats["ok"] = False
        stats["error"] = (stats.get("error", "") + P.redact(f"{what}: {str(exc)[:160]}; "))[:500]

    grouped = collections.OrderedDict()
    fresh = collections.Counter()
    config_cache = {}
    for group, cfg in sorted(configured.items()):
        component = cfg.get("component") or group.split(".")[0]
        only = set(cfg.get("kinds") or [])
        try:
            served = discover(group)
        except Exception as exc:                              # noqa: BLE001
            # A configured group this cluster does not serve (its provider is not installed) is nothing to
            # check, not a failure: degrading on it would make every run PartiallyCompleted.
            if getattr(exc, "status", None) == 404:
                stats["note"] = stats.get("note", "") + f"{group} is not served by this cluster; nothing to check; "
                continue
            fail(f"discovery of {group}", exc)
            continue
        by_kind = {kind: (version, plural) for version, plural, kind, _ in served}
        for version, plural, kind, _ in served:
            if only and kind not in only:
                continue
            try:
                items = _list(api, group, version, plural, stats)
            except Exception as exc:                          # noqa: BLE001
                fail(f"{plural}.{group}", exc)
                continue
            stats["queried"] += 1
            stats["returned"] += len(items)
            for obj in items:
                cond = failing_condition(obj)
                if cond is None:
                    continue
                since = _parse(cond.get("lastTransitionTime"))
                if since is None or since > cutoff:
                    fresh[f"{kind}.{group}"] += 1
                    continue
                signal, description = classify(cond.get("reason"), cond.get("message"))
                g = grouped.setdefault((component, signal), {
                    "component": component, "signal": signal, "description": description, "count": 0,
                    "kinds": collections.Counter(), "groups": set(), "examples": [], "since": since,
                    "reasons": collections.Counter(), "messages": collections.Counter(), "secrets": set(),
                    "configurations": set()})
                meta = obj.get("metadata") or {}
                ns = meta.get("namespace") or ""
                g["count"] += 1
                g["kinds"][kind] += 1
                g["groups"].add(group)
                g["reasons"][f"{cond.get('type')}={cond.get('status')}/{cond.get('reason') or '-'}"] += 1
                g["messages"][P.redact((cond.get("message") or "")[:MESSAGE_CHARS])] += 1
                g["since"] = min(g["since"], since)
                if len(g["examples"]) < EXAMPLES:
                    g["examples"].append(f"{kind} {ns + '/' if ns else ''}{meta.get('name')}")
                spec = obj.get("spec") or {}
                g["secrets"] |= secret_refs(spec, ns)
                ref = spec.get("configurationRef")
                if isinstance(ref, dict) and ref.get("name"):
                    cns = ref.get("namespace") or ns
                    g["configurations"].add(f"{kind}Configuration {cns}/{ref['name']}")
                    g["secrets"] |= _configuration_secrets(api, group, by_kind.get(f"{kind}Configuration"),
                                                           cns, ref["name"], config_cache)
    stats["stalled"] = sum(g["count"] for g in grouped.values())
    stats["freshFailures"] = sum(fresh.values())

    findings = sorted(grouped.values(), key=lambda g: (-g["count"], g["component"], g["signal"]))
    if len(findings) > MAX_FINDINGS:
        stats["note"] = stats.get("note", "") + (f"{len(findings) - MAX_FINDINGS} smaller group(s) not proposed "
                                                 f"(over {MAX_FINDINGS}); they are in the corpus; ")
    stats["findings"] = min(len(findings), MAX_FINDINGS)
    if stats.get("note"):
        stats["note"] = stats["note"].strip("; ")[:500]
    if not findings and not fresh:
        return None, stats, []
    props = [_proposal(g, threshold) for g in findings[:MAX_FINDINGS]]
    return P.redact(_render(findings, fresh, threshold, props)), stats, props


def _configuration_secrets(api, group, served, namespace, name, cache):
    """The Secret NAMES a Configuration's spec points at. The Configuration is a custom resource in the
    provider's own group; it is read, the Secret is not.

    BEST EFFORT, NEVER A FAILURE OF THE SOURCE. `<Kind>Configuration` is a naming convention, not a contract,
    and a reference may carry no namespace; when the lookup cannot be made or answers nothing, the Secret is
    simply left unnamed. The finding stands without it."""
    if not served or not namespace:
        return set()
    key = (group, served[1], namespace, name)
    if key not in cache:
        try:
            obj = api.get_namespaced_custom_object(group, served[0], namespace, served[1], name)
            cache[key] = secret_refs((obj or {}).get("spec") or {}, namespace)
        except Exception:                                     # noqa: BLE001
            cache[key] = set()
    return cache[key]


def _title(g, threshold):
    kinds = ", ".join(f"{k} x{n}" for k, n in g["kinds"].most_common())
    return (f"{g['component']}: {g['count']} resource(s) out of sync for over {threshold}m — "
            f"{g['description']} ({kinds})")[:200]


def _content(g, threshold):
    """THE PROPOSAL'S BODY HOLDS NOTHING THAT MOVES BY ITSELF. No "for 7 hours", no "as of": the fingerprint
    is computed over it, and the same outage on the next night must produce the same body, so it deduplicates
    instead of piling up. A real change — more objects, another kind, another Secret — is a new body under
    the same subject, and supersedes."""
    lines = [f"# {g['component']}: resources out of sync — {g['description']}", "",
             f"Measured by the nightly review's sync-stall check, not judged by a model: Krateo-managed "
             f"resources whose Synced condition is False (or whose Ready is False for a reconcile error) "
             f"for longer than {threshold} minutes, by the condition's own lastTransitionTime.", "",
             f"- **Objects:** {g['count']} — " + ", ".join(f"{k} x{n}" for k, n in g["kinds"].most_common()),
             f"- **API group(s):** {', '.join(sorted(g['groups']))}",
             f"- **Failing since (earliest):** {g['since'].strftime('%Y-%m-%dT%H:%M:%SZ')}",
             "- **Conditions:** " + ", ".join(f"{r} x{n}" for r, n in g["reasons"].most_common()),
             "- **Examples:** " + "; ".join(g["examples"])]
    if g["configurations"]:
        lines.append("- **Configurations referenced:** " + ", ".join(sorted(g["configurations"])[:10]))
    if g["secrets"]:
        lines.append("- **Secrets referenced (names only; never read):** " + ", ".join(sorted(g["secrets"])[:10]))
    lines += ["", "## What the controllers say", ""]
    lines += [f"- x{n}: `{m.replace('`', chr(39))}`" for m, n in g["messages"].most_common(3)]
    lines += ["", "## What to check", ""]
    if g["signal"] in ("credential-rejected", "permission-denied"):
        lines.append("The credential these resources use was refused. Expiry, revocation, a narrowed scope "
                     "and a missing SSO authorisation all look like this. Rotate or re-authorise the token in "
                     "the Secret(s) above; the controllers retry on their own, so the conditions clear without "
                     "touching the resources.")
    elif g["signal"] == "local-secret-missing":
        lines.append("A Secret these resources (or their Configuration) reference does not exist in the cluster: "
                     "deleted, renamed, or never created in that namespace. Nothing is wrong on the remote side. "
                     "Recreate the Secret named in the controllers' message; the controllers retry on their own.")
    elif g["signal"] == "remote-not-found":
        lines.append("The remote object is gone or invisible to the credential: a deleted or renamed "
                     "repository, or a token that lost access to it.")
    else:
        lines.append("Read the controller's message above against the provider's logs; the objects are "
                     "retried on every reconcile and clear by themselves once the cause is fixed.")
    lines += ["", "This is a nightly backstop: it finds a stall up to a day after it starts. An in-cluster "
                  "alert on these conditions would find it in minutes."]
    return "\n".join(lines) + "\n"


def _proposal(g, threshold):
    """A finding in the contract's own shape, so it crosses the same trust boundary as the model's:
    validate_batch redacts it, normalises the subject and fingerprints it; targets.aim gives it the
    component's configured destination."""
    kinds = ", ".join(f"{k} x{n}" for k, n in g["kinds"].most_common())
    secrets = sorted(g["secrets"])
    return {
        "kind": "Documentation",
        "subject": f"{g['component']}/{g['signal']}",
        "title": _title(g, threshold),
        "rationale": (f"{g['count']} {', '.join(sorted(g['groups']))} resource(s) ({kinds}) have been failing "
                      f"since {g['since'].strftime('%Y-%m-%dT%H:%M:%SZ')} — {g['description']}. Counted by the "
                      f"service from the objects' conditions; no model judged it, so confidence is the count's, "
                      f"not an opinion."
                      + (f" They use the credential(s) in {', '.join(secrets[:5])} (names only; Secrets are "
                         f"never read)." if secrets else ""))[:4000],
        "confidence": "high",
        "evidence": [{"source": "kubernetes", "observedCount": g["count"],
                      "summary": (f"{g['count']} object(s) with " + ", ".join(
                          f"{r} x{n}" for r, n in g["reasons"].most_common())
                                  + f" for over {threshold}m; e.g. " + "; ".join(g["examples"]))[:2000]}],
        # No repository of its own: targets.aim gives it the configured one. A placeholder here read as the
        # model's guess and made aim note a "retarget" every night.
        "target": {"repo": "", "path": f"{g['component']}-{g['signal']}.md"},
        "change": {"format": "markdown", "content": _content(g, threshold)},
    }


def _render(findings, fresh, threshold, props):
    lines = [f"- OUT OF SYNC for over {threshold}m, measured by this service (each group below is ALREADY "
             f"written as a Proposal by the service under the subject shown; do not propose it again):"]
    for g in findings:
        p = next((p for p in props if p["subject"] == f"{g['component']}/{g['signal']}"), None)
        lines.append(f"  - {g['count']}x {g['description']} [{', '.join(sorted(g['groups']))}: "
                     + ", ".join(f"{k} x{n}" for k, n in g["kinds"].most_common()) + "]"
                     + (f" — subject {p['subject']}" if p else " — not proposed (over the per-run cap)")
                     + f"; since {g['since'].strftime('%Y-%m-%dT%H:%M:%SZ')}"
                     + (f"; Secrets referenced: {', '.join(sorted(g['secrets'])[:5])}" if g["secrets"] else ""))
        for m, n in g["messages"].most_common(1):
            lines.append(f"    > x{n}: {m}")
    if fresh:
        lines.append(f"- failing for less than {threshold}m, or with no lastTransitionTime (not reported; a "
                     f"message that changes every reconcile resets the clock and stays here): "
                     + ", ".join(f"{k} x{n}" for k, n in fresh.most_common(10)))
    return "\n".join(lines)
