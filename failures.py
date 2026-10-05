"""The day's real failures: the Incidents the platform opened, and the Compositions that were not healthy.

WHY THESE COME FIRST. Every other source is a sample. ClickHouse's top error patterns are ranked by VOLUME,
so a chatty component's warnings push a real failure out of the top 25, and a composition that failed
validation once, was fixed by a person and never logged again does not rank at all. An Incident is a
failure the platform already noticed, investigated and (often) fixed; a Composition that went not-Ready
is a failure a person saw. Both are read straight from the apiserver, not ranked, and both reach the
prompt AHEAD of the log patterns — prompt.build_user_message orders them first.

READ-ONLY, THROUGH THE SERVICE'S OWN ServiceAccount. `list` on incidents.observability.krateo.io, on every
composition.krateo.io resource and on compositiondefinitions.core.krateo.io, cluster-wide
(templates/rbac.yaml). Nothing here gets a Secret, and nothing writes.

WHAT THE INCIDENT KIND DOES AND DOES NOT RECORD (incident-controller apis/incident/v1alpha1, and the 24 on
057 on 2026-10-05). There is no "affected object" field. What an Incident does carry: spec.alertRef and
spec.trigger (what opened it), status.rootCause {category, confidence, statement}, status.howToFix (bash
scripts, plus applyAction — the fix as ONE Kubernetes write, which names the object the fix changes), and
status.analyzedResources (what the analysis read). So the affected object is applyAction's target when
there is one, else the first analysed resource that is not the Alert itself — and it is labelled as such,
never presented as a field the Incident has. The owning composition is named only when one of those is a
composition.krateo.io object: an Incident records no composition of its own.

WHAT A COMPOSITION'S CONDITIONS CAN AND CANNOT SAY. Only the CURRENT conditions are visible; there is no
history to read. Two consequences, both measured on 057:
- Synced=True is re-stamped on every reconcile (all 51 compositions read lastTransitionTime within the same
  minute), so a Synced transition to True says nothing about a recovery and is never counted as one.
- Ready=True's lastTransitionTime does move only on a real transition, so Ready=True stamped inside the
  window, on a composition created before it, means it was NOT Ready earlier in the window and recovered.
  A chart upgrade's rollout produces exactly the same stamp, and the corpus says so beside every such line.
A composition that failed and recovered TWICE in the window shows only the last recovery. Stated, not fixed:
fixing it would need an event history this service does not keep.
"""
import datetime as dt
import json
import re

import evidence
import proposals as P
import sync_health

INCIDENTS_SOURCE = "incidents"
COMPOSITIONS_SOURCE = "compositions"

INCIDENT_GROUP, INCIDENT_VERSION, INCIDENT_PLURAL = "observability.krateo.io", "v1alpha1", "incidents"
COMPOSITION_GROUP = "composition.krateo.io"
CD_GROUP, CD_VERSION, CD_PLURAL = "core.krateo.io", "v1alpha1", "compositiondefinitions"

MAX_INCIDENTS = 25
MAX_FAILING = 40
MAX_RECOVERED = 25
MAX_REFUSED = 25
MAX_GONE = 10
MAX_EVENT_GROUPS = 300
EVENT_REASONS_PER_COMPOSITION = 3
EVENT_MESSAGE_CHARS = 300
TEXT_CHARS = 400

# The convention every Krateo chart release follows: the org-wide release-oci workflow publishes each
# Chart.yaml of github.com/<org>/<repo> as oci://ghcr.io/<org>/charts/<chart name>, and the Blueprint
# Builder's publish names the repository after the blueprint. So a blueprint's chart name IS its source
# repository's name — for a single-chart repository. A repository that carries several charts (one per
# blueprint under blueprints/<name>/chart) breaks it, and the TargetResolved check is what says so.
_OCI = re.compile(r"^oci://ghcr\.io/([A-Za-z0-9][A-Za-z0-9-]{0,38})/charts/([A-Za-z0-9._-]{1,100})/?$")


def _parse(ts):
    return sync_health._parse(ts)


def _in(ts, frm, to):
    t = _parse(ts)
    return t is not None and frm <= t <= to


def _short(text, n=TEXT_CHARS):
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[:n - 1] + "…"


def _ref(ns, kind, name):
    return f"{kind} {ns + '/' if ns else ''}{name}"


def blueprint_repo(chart_url):
    """(org, name) of the source repository a CompositionDefinition's chart URL implies, or None.

    Only the OCI shape is derivable. A classic Helm repository (https://<org>.github.io/charts/<index>)
    names an INDEX, not the repository that holds the chart's source, so nothing is guessed for it."""
    m = _OCI.match((chart_url or "").strip())
    return (m.group(1), m.group(2)) if m else None


# --- incidents -------------------------------------------------------------------------------------

def _affected(inc):
    """(what, ref, composition) — the object the incident is about, as far as the Incident records one."""
    st = inc.get("status") or {}
    action = (st.get("howToFix") or {}).get("applyAction") or {}
    composition = None
    refs = []
    if action.get("resource") and action.get("name"):
        group = (action.get("apiVersion") or "").rpartition("/")[0]
        refs.append(("fix target", group, action.get("namespace") or "", action["resource"], action["name"]))
    alert = (inc.get("spec") or {}).get("alertRef") or {}
    for r in st.get("analyzedResources") or []:
        gvr = (r.get("gvr") or "").split("/")
        group, resource = (gvr[0] if len(gvr) == 3 else ""), gvr[-1]
        # The Alert that opened it and the Incident itself are what was investigated FROM, not the failure.
        if (resource == "alerts" and r.get("name") == alert.get("name")) or \
                (resource == INCIDENT_PLURAL and r.get("name") == (inc.get("metadata") or {}).get("name")):
            continue
        refs.append(("examined", group, r.get("namespace") or "", resource, r.get("name") or ""))
    for _, group, ns, resource, name in refs:
        if group == COMPOSITION_GROUP and composition is None:
            composition = _ref(ns, resource, name)
    if not refs:
        return None, None, composition
    what, group, ns, resource, name = refs[0]
    return what, _ref(ns, f"{resource}{'.' + group if group else ''}", name), composition


def _fix_summary(inc):
    """The fix in one line: the apply script's first comment (the analysis writes the intent there) and,
    when the fix is one API write, that write."""
    fix = (inc.get("status") or {}).get("howToFix") or {}
    intent = next((ln.lstrip("# ").strip() for ln in (fix.get("apply") or "").splitlines()
                   if ln.startswith("#") and not ln.startswith("#!") and ln.strip("# ")), "")
    action = fix.get("applyAction") or {}
    write = ""
    if action.get("verb") and action.get("resource"):
        write = (f"one API write: {action['verb']} {action['resource']} "
                 f"{(action.get('namespace') + '/') if action.get('namespace') else ''}{action.get('name', '')}")
    return "; ".join(x for x in (_short(intent, 240), write) if x)


def _lifecycle(inc):
    spec, st = inc.get("spec") or {}, inc.get("status") or {}
    state = st.get("state") or "unknown"
    res = st.get("resolution") or {}
    out = state
    if res.get("by"):
        out += f" (ended by {'a person' if res['by'] == 'user' else 'its verify check'} at {res.get('at', '?')})"
    if spec.get("applied"):
        out += "; a person applied the fix"
    return out


def incidents(api, window):
    """(body, stats): every Incident opened, fired, analysed or ended inside the window, newest first,
    ended ones ahead of open ones — an incident that ended is a failure somebody had to fix."""
    frm, to = _parse(window["from"]), _parse(window["to"])
    stats = {"ok": True, "queried": 1, "returned": 0, "findings": 0}
    try:
        items = sync_health._list(api, INCIDENT_GROUP, INCIDENT_VERSION, INCIDENT_PLURAL, stats)
    except Exception as exc:                                  # noqa: BLE001
        # A cluster without the incident controller has no such kind: nothing to read, not a failure.
        if getattr(exc, "status", None) == 404:
            return None, {"ok": True, "queried": 0, "returned": 0, "empty": True,
                          "note": "incidents.observability.krateo.io is not served by this cluster"}
        return None, {"ok": False, "queried": 1, "returned": 0,
                      "error": P.redact(f"{type(exc).__name__}: {str(exc)[:200]}")[:300]}
    stats["returned"] = len(items)

    def touched(i):
        st, meta = i.get("status") or {}, i.get("metadata") or {}
        return [t for t in ((i.get("spec") or {}).get("triggeredAt"), st.get("lastFiredAt"), st.get("completedAt"),
                            (st.get("resolution") or {}).get("at"), meta.get("creationTimestamp"))
                if _in(t, frm, to)]

    hits = [(i, max(_parse(t) for t in ts)) for i in items if (ts := touched(i))]
    ended = ("Resolved", "Closed")
    hits.sort(key=lambda h: ((h[0].get("status") or {}).get("state") not in ended, -h[1].timestamp()))
    stats["findings"] = len(hits)
    if not hits:
        stats |= {"empty": True, "note": f"{len(items)} Incident(s) in the cluster; none opened, fired or ended "
                                          f"in the window"}
        return None, stats
    lines = [f"- {len(hits)} Incident(s) opened, fired, analysed or ended in the window "
             f"(of {len(items)} in the cluster). Ended ones first: those are failures the platform or a "
             f"person had to fix."]
    for inc, _ in hits[:MAX_INCIDENTS]:
        meta, spec, st = inc.get("metadata") or {}, inc.get("spec") or {}, inc.get("status") or {}
        alert = spec.get("alertRef") or {}
        lines.append(f"- Incident {meta.get('namespace')}/{meta.get('name')}: {_lifecycle(inc)}; trigger "
                     f"{spec.get('trigger') or 'alert'} {alert.get('name', '')}; opened {spec.get('triggeredAt', '?')}, "
                     f"last fired {st.get('lastFiredAt', '?')}, firings {st.get('firings', '?')}")
        what, ref, composition = _affected(inc)
        if ref:
            lines.append(f"    affected ({what}): {ref}"
                         + (f"; composition {composition}" if composition and composition != ref else ""))
        rc = st.get("rootCause") or {}
        if rc.get("statement"):
            lines.append(f"    root cause [{rc.get('category', '?')}, confidence {rc.get('confidence', '?')}]: "
                         f"{_short(rc['statement'])}")
        fix = _fix_summary(inc)
        if fix:
            lines.append(f"    remediation: {fix}")
        if st.get("error"):
            lines.append(f"    analysis failed: {_short(st['error'], 200)}")
    if len(hits) > MAX_INCIDENTS:
        lines.append(f"- ... and {len(hits) - MAX_INCIDENTS} more Incident(s) in the window, not listed")
        stats["note"] = f"listed {MAX_INCIDENTS} of {len(hits)} Incidents in the window"
    return evidence._cap(P.redact("\n".join(lines)), stats), stats


# --- compositions ----------------------------------------------------------------------------------

def _conds(obj):
    return {c.get("type"): c for c in ((obj.get("status") or {}).get("conditions") or []) if isinstance(c, dict)}


def _definitions(api):
    """(by_name, by_kind): CompositionDefinitions keyed by (namespace, name) and by the Kind they serve."""
    by_name, by_kind = {}, {}
    for cd in sync_health._list(api, CD_GROUP, CD_VERSION, CD_PLURAL, {}):
        meta, spec, st = cd.get("metadata") or {}, cd.get("spec") or {}, cd.get("status") or {}
        chart = spec.get("chart") or {}
        info = {"name": meta.get("name"), "namespace": meta.get("namespace"), "url": chart.get("url"),
                "version": chart.get("version"), "repoName": chart.get("repo")}
        by_name[(meta.get("namespace"), meta.get("name"))] = info
        if st.get("kind"):
            by_kind.setdefault(st["kind"], info)
    return by_name, by_kind


def _blueprint(obj, by_name, by_kind):
    labels = (obj.get("metadata") or {}).get("labels") or {}
    key = (labels.get("krateo.io/composition-definition-namespace"),
           labels.get("krateo.io/composition-definition-name"))
    return by_name.get(key) or by_kind.get(obj.get("kind"))


def _blueprint_text(bp, obj, blueprints):
    """The blueprint and, when its org is one config.destinations.blueprints allows, the source repository a
    proposal about it lands in. Other orgs' charts are named without a repository: their components are
    mapped explicitly in config.destinations.components, and a derived name there would only mislead."""
    st = obj.get("status") or {}
    if not bp:
        url, ver = st.get("helmChartUrl"), st.get("helmChartVersion")
        return f"no CompositionDefinition found for it; chart {url}@{ver}" if url else "no CompositionDefinition found"
    repo = blueprints.get(bp["name"])
    return (f"blueprint {bp['name']} (CompositionDefinition {bp['namespace']}/{bp['name']}, chart {bp['url']}"
            + (f" {bp['repoName']}" if bp.get("repoName") else "") + f" @ {bp.get('version')}"
            + (f"; source repository {repo}" if repo else "") + ")")


def compositions(api, discover, window, orgs=(), read_events=None):
    """(body, stats, blueprints). body lists every composition NOT Ready or NOT Synced now, and every one
    that RECOVERED inside the window, each with its blueprint; blueprints maps every CompositionDefinition
    whose OCI chart is published by one of `orgs` (config.destinations.blueprints.orgs) to the "org/repo" its
    chart URL implies, so targets can aim a proposal about that blueprint at its source."""
    frm, to = _parse(window["from"]), _parse(window["to"])
    stats = {"ok": True, "queried": 0, "returned": 0, "findings": 0}
    read_events = read_events or warning_events

    def fail(what, exc):
        stats["ok"] = False
        stats["error"] = (stats.get("error", "") + P.redact(f"{what}: {str(exc)[:160]}; "))[:500]

    try:
        served = discover(COMPOSITION_GROUP)
    except Exception as exc:                                  # noqa: BLE001
        if getattr(exc, "status", None) == 404:
            return None, {"ok": True, "queried": 0, "returned": 0, "empty": True,
                          "note": f"{COMPOSITION_GROUP} is not served by this cluster"}, {}
        fail(f"discovery of {COMPOSITION_GROUP}", exc)
        return None, stats, {}
    try:
        by_name, by_kind = _definitions(api)
    except Exception as exc:                                  # noqa: BLE001
        # Degraded, not blank: the compositions still answer, they only lose their blueprint.
        by_name, by_kind = {}, {}
        fail(CD_PLURAL, exc)

    # EVERY blueprint with a derivable source in an allowed org, not only the failing ones': an Incident can
    # be about a composition that is healthy again, and its proposal belongs in that blueprint's repository too.
    allowed = {o.lower() for o in orgs or ()}
    blueprints = {bp["name"]: f"{repo[0]}/{repo[1]}" for bp in by_name.values()
                  if bp.get("name") and (repo := blueprint_repo(bp["url"])) and repo[0].lower() in allowed}
    try:
        groups, note = read_events(window)
    except Exception as exc:                                  # noqa: BLE001
        # Degraded, not blank: conditions still answer; a failure fixed in the window is what is lost.
        groups, note = [], None
        fail("warning events (ClickHouse)", exc)
    if note:
        stats["note"] = note
    stats["warningEvents"] = sum(g["count"] for g in groups)
    by_uid, by_ref = {}, {}
    for g in groups:
        if g["uid"]:
            by_uid.setdefault(g["uid"], []).append(g)
        by_ref.setdefault((g["namespace"], g["kind"], g["name"]), []).append(g)
    matched = set()

    failing, refused, recovered = [], [], []
    for version, plural, kind, _ in served:
        try:
            items = sync_health._list(api, COMPOSITION_GROUP, version, plural, stats)
        except Exception as exc:                              # noqa: BLE001
            fail(f"{plural}.{COMPOSITION_GROUP}", exc)
            continue
        stats["queried"] += 1
        stats["returned"] += len(items)
        for obj in items:
            obj.setdefault("kind", kind)
            meta = obj.get("metadata") or {}
            # BY UID OR BY name+namespace+kind: an event recorded before a composition was deleted and recreated
            # under the same name is still about the composition a person sees under that name.
            ev = by_uid.get(meta.get("uid")) or by_ref.get((meta.get("namespace") or "", obj["kind"], meta.get("name")))
            if ev:
                matched.update(id(g) for g in ev)
            conds = _conds(obj)
            bad = [c for t in ("Ready", "Synced") if (c := conds.get(t)) and c.get("status") != "True"]
            ready = conds.get("Ready") or {}
            synced = conds.get("Synced") or {}
            created = _parse(meta.get("creationTimestamp"))
            if bad:
                failing.append((obj, bad, ev or []))
            elif ev and synced.get("status") == "True":
                refused.append((obj, ev))
            elif (ready.get("status") == "True" and _in(ready.get("lastTransitionTime"), frm, to)
                  and created is not None and created < frm):
                recovered.append((obj, ready))
    gone = {}
    for g in groups:
        if id(g) not in matched:
            gone.setdefault((g["namespace"], g["kind"], g["name"]), []).append(g)

    stats["failing"], stats["recovered"] = len(failing), len(refused) + len(recovered)
    stats["findings"] = len(failing) + len(refused) + len(recovered) + len(gone)
    if not stats["findings"]:
        if stats["ok"]:
            stats |= {"empty": True, "note": f"{stats['returned']} composition(s): all Ready and Synced, none "
                                              f"recovered and no Warning events in the window"}
        return None, stats, blueprints

    def since(c):
        t = c.get("lastTransitionTime")
        return f"since {t}" + (" (in the window)" if _in(t, frm, to) else " (before the window)") if t else "no time"

    def bp_text(obj):
        return _blueprint_text(_blueprint(obj, by_name, by_kind), obj, blueprints)

    failing.sort(key=lambda f: (f[0]["kind"], f[0]["metadata"].get("namespace", ""), f[0]["metadata"]["name"]))
    refused.sort(key=lambda r: max(g["lastSeen"] for g in r[1]), reverse=True)
    recovered.sort(key=lambda r: r[1].get("lastTransitionTime") or "", reverse=True)
    lines = []
    if failing:
        lines.append(f"- {len(failing)} composition(s) NOT healthy now:")
        for obj, bad, ev in failing[:MAX_FAILING]:
            m = obj["metadata"]
            lines.append(f"  - {_ref(m.get('namespace'), obj['kind'], m['name'])}: "
                         + "; ".join(f"{c.get('type')}={c.get('status')}/{c.get('reason') or '-'} {since(c)}: "
                                     f"{_short(c.get('message'), 300) or 'no message'}" for c in bad))
            lines.append(f"    {bp_text(obj)}")
            lines += _event_lines(ev)
        if len(failing) > MAX_FAILING:
            lines.append(f"  - ... and {len(failing) - MAX_FAILING} more not listed")
    if refused:
        lines.append(f"- {len(refused)} composition(s) RECOVERED after being REFUSED — Warning events on the "
                     f"composition inside the window, Synced=True now. Each was refused by the apiserver or its controller "
                     f"and is not any more — fixed by a person, or transient; the message says which:")
        for obj, ev in refused[:MAX_REFUSED]:
            m = obj["metadata"]
            reasons = ", ".join(dict.fromkeys(g["reason"] for g in ev))
            lines.append(f"  - {_ref(m.get('namespace'), obj['kind'], m['name'])}: recovered (was refused: "
                         f"{reasons}); {bp_text(obj)}")
            lines += _event_lines(ev)
        if len(refused) > MAX_REFUSED:
            lines.append(f"  - ... and {len(refused) - MAX_REFUSED} more not listed")
    if recovered:
        lines.append(f"- {len(recovered)} composition(s) RECOVERED in the window — Ready=True stamped inside it on "
                     f"a composition created before it, so it was not Ready earlier in the window (a chart "
                     f"upgrade's rollout stamps the same; weigh these beside the incidents and log patterns):")
        for obj, ready in recovered[:MAX_RECOVERED]:
            m = obj["metadata"]
            lines.append(f"  - {_ref(m.get('namespace'), obj['kind'], m['name'])}: Ready=True/"
                         f"{ready.get('reason') or '-'} since {ready.get('lastTransitionTime')}; {bp_text(obj)}")
        if len(recovered) > MAX_RECOVERED:
            lines.append(f"  - ... and {len(recovered) - MAX_RECOVERED} more not listed")
    if gone:
        lines.append(f"- {len(gone)} composition(s) with Warning events in the window that NO LONGER EXIST "
                     f"(deleted since):")
        for (ns, kind, name), ev in sorted(gone.items(), key=lambda kv: max(g["lastSeen"] for g in kv[1]), reverse=True)[:MAX_GONE]:
            lines.append(f"  - {_ref(ns, kind, name)}:")
            lines += _event_lines(ev)
        if len(gone) > MAX_GONE:
            lines.append(f"  - ... and {len(gone) - MAX_GONE} more not listed")
    cut = [f"{min(n, cap)} of {n} {what}" for what, n, cap in (
        ("failing", len(failing), MAX_FAILING), ("refused-then-recovered", len(refused), MAX_REFUSED),
        ("recovered", len(recovered), MAX_RECOVERED), ("deleted", len(gone), MAX_GONE)) if n > cap]
    if cut:
        stats["note"] = "; ".join(filter(None, [stats.get("note"), "listed " + ", ".join(cut)]))
    return evidence._cap(P.redact("\n".join(lines)), stats), stats, blueprints


def _event_lines(groups):
    """One line per (reason) for one composition: how many, first and last seen, and the latest message."""
    out = []
    for g in sorted(groups, key=lambda g: g["lastSeen"], reverse=True)[:EVENT_REASONS_PER_COMPOSITION]:
        out.append(f"    warning event {g['reason']} x{g['count']}, first {g['firstSeen']}, last {g['lastSeen']}: "
                   f"{_short(g['message'], EVENT_MESSAGE_CHARS) or 'no message'}")
    return out


# WARNING EVENTS ON COMPOSITIONS, FROM CLICKHOUSE — NOT THE EVENTS API, which keeps an Event for about an
# hour: a refusal fixed in the morning is gone from it by the nightly run. The collector's k8sobjects
# receiver watches Events and writes each watch notification as one otel_logs row, telemetry.source
# 'k8s-events', with the notification as JSON in Body: {"type": ADDED|MODIFIED|DELETED, "object": <Event>}.
# Shapes verified on 057 (2026-10-05):
#   - DELETED rows are the apiserver EXPIRING an Event, a copy of one already recorded: excluded, or every
#     occurrence counts twice (on 057, 278,733 DELETED against 284,249 ADDED in seven days).
#   - composition-dynamic-controller writes events.k8s.io-style Events: firstTimestamp/lastTimestamp null,
#     `count` 0, a new Event (new metadata.uid) per occurrence, eventTime set. So occurrences are counted per
#     Event uid, taking count or series.count when an Event carries one, and the row Timestamp is the clock.
# The window bound is the same {from}/{to} text substitution, in the same index-friendly format, as every
# configured query (evidence._ch_time).
WARNING_EVENTS_SQL = """
SELECT kind, namespace, name, uid, reason, sum(n) AS count,
       toString(min(first)) AS firstSeen, toString(max(last)) AS lastSeen, argMax(msg, last) AS message
FROM (
  SELECT JSONExtractString(Body, 'object', 'involvedObject', 'kind')      AS kind,
         JSONExtractString(Body, 'object', 'involvedObject', 'namespace') AS namespace,
         JSONExtractString(Body, 'object', 'involvedObject', 'name')      AS name,
         JSONExtractString(Body, 'object', 'involvedObject', 'uid')       AS uid,
         JSONExtractString(Body, 'object', 'reason')                      AS reason,
         JSONExtractString(Body, 'object', 'metadata', 'uid')             AS event,
         greatest(max(JSONExtractInt(Body, 'object', 'count')),
                  max(JSONExtractInt(Body, 'object', 'series', 'count')), 1) AS n,
         min(Timestamp) AS first, max(Timestamp) AS last,
         substring(argMax(JSONExtractString(Body, 'object', 'message'), Timestamp), 1, 600) AS msg
  FROM otel_logs
  WHERE Timestamp BETWEEN '{from}' AND '{to}'
    AND ResourceAttributes['telemetry.source'] = 'k8s-events'
    AND JSONExtractString(Body, 'type') != 'DELETED'
    AND JSONExtractString(Body, 'object', 'type') = 'Warning'
    AND startsWith(JSONExtractString(Body, 'object', 'involvedObject', 'apiVersion'), 'composition.krateo.io/')
  GROUP BY kind, namespace, name, uid, reason, event
)
GROUP BY kind, namespace, name, uid, reason
ORDER BY lastSeen DESC
LIMIT {limit}
"""


def warning_events(window):
    """([group], note): Warning events on composition.krateo.io objects in the window, one group per
    (composition, reason). Through the same ClickHouse endpoint and credentials as the configured queries.
    Not configured is a note, not a failure — the conditions still answer. A failed query raises."""
    if not evidence.CLICKHOUSE_URL:
        return [], "warning events not read: CLICKHOUSE_URL is not configured"
    sql = (WARNING_EVENTS_SQL.replace("{from}", evidence._ch_time(window["from"]))
           .replace("{to}", evidence._ch_time(window["to"])).replace("{limit}", str(MAX_EVENT_GROUPS)))
    r = evidence.requests.post(
        evidence.CLICKHOUSE_URL, data=f"{sql}\nFORMAT JSONEachRow",
        params={"max_result_rows": MAX_EVENT_GROUPS, "result_overflow_mode": "break"},
        auth=(evidence.CLICKHOUSE_USER, evidence.CLICKHOUSE_PASSWORD) if evidence.CLICKHOUSE_USER else None,
        timeout=120)
    r.raise_for_status()
    groups = []
    for ln in r.text.splitlines():
        try:
            row = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(row, dict) or not row.get("kind") or not row.get("name"):
            continue
        try:
            count = int(row.get("count") or 1)
        except (TypeError, ValueError):
            count = 1
        groups.append({"kind": str(row["kind"]), "namespace": str(row.get("namespace") or ""),
                       "name": str(row["name"]), "uid": str(row.get("uid") or ""),
                       "reason": str(row.get("reason") or "-"), "count": count,
                       "firstSeen": str(row.get("firstSeen") or "?")[:19], "lastSeen": str(row.get("lastSeen") or "?")[:19],
                       "message": str(row.get("message") or "")})
    note = (f"warning events: the first {MAX_EVENT_GROUPS} (composition, reason) groups only"
            if len(groups) >= MAX_EVENT_GROUPS else None)
    return groups, note
