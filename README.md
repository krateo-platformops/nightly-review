# nightly-review

Once a night, reads the platform's own telemetry and its agents' activity, and **proposes** changes:
new alerts, portal widgets, agent-prompt corrections, gateway policy tuning, missing documentation.
Every proposal becomes a `Proposal` object. Nothing is applied, and this service opens no pull
requests. **The portal opens one per proposal**, when a person decides to.

## The shape, and why

```
CronJob ─▶ gather ─▶ ask ─▶ validate ─▶ publish ─▶ record
           evidence   the     schema, redact,   skipped:   Proposals +
           (fixed     reviewer alert kind,      dryRun     ReviewRun
           queries)   agent    dedup/supersede,
                      (no      target exists?
                      tools)
```

Each stage is recorded on the run as `status.steps[]`, with its own start, finish and outcome, so a
failed run says *where* it stopped, and in particular whether the model was ever called.

**The agent proposes; the service writes.** The reviewer is a dedicated kagent Agent holding **no
tools** (`templates/agent.yaml`). It cannot delegate, fetch or write; it reads the evidence it is given
and returns JSON. That JSON is schema-checked, redacted and validated before any of it is written.
A prompt injection can therefore produce a bad `Proposal`, never a commit.

**The corpus is untrusted.** It contains telemetry and data derived from real people's use of agents,
so anyone who can write a log line or talk to an agent can put text in tomorrow's prompt. It is fenced
with a per-run nonce as data, and the model is told to *report* rather than obey anything that tries
to steer it.

## It stays in dry run, permanently

`dryRun: true` is the shipped default and the intended mode. The run writes `Proposal` objects; the
`publish` step is recorded as `Skipped`. Pull requests are opened from the portal, per proposal, by
the person acting on it, so the decision and the pull request share a name.

The non-dry-run path still exists: it renders each proposal as a `BuilderPublish` claim to the
platform's own publish chain (Repository → Repo → LocalResource → PullRequest), the same chain
portal-builder and blueprint-builder use. **This service holds no GitHub token** and never did since
#13. The only git credential on the platform is git-provider's, configured once at install level.

**There is no repository allowlist any more.** It existed to bound a GitHub write credential this
service no longer holds, and it blocked proposals before a human could read them. The reviewer may name
any repository; what bounds that is the human reading the pull request. See the epitaph in
`proposals.py`.

## Two objects, and why they are two

| kind | is | lifecycle |
|---|---|---|
| `ReviewRun` | one nightly execution | an **event**, pruned after `retention.runDays` |
| `Proposal` | one suggested change | a **decision record**: `Proposed → PrOpen → Merged \| Rejected \| Superseded` |

A `Proposal` carries **no `ownerReference`** to its run. That wiring looks obvious and would let the
run's expiry garbage-collect the decision. An open proposal is never collected at all: it is an
undecided question, and deleting those is how a review loop quietly stops mattering.

Portal admins act on proposals through the `<release>-portal-admin` ClusterRole (read both kinds,
get/patch a Proposal, get/patch/update `proposals/status`). It is **bound** to the groups in
`portalAdminAccess.groups` (default `admins`), not aggregated, because Krateo's admins hold
cluster-admin through their group rather than the built-in `admin` ClusterRole that `aggregate-to-admin`
feeds.

## A person's decision: `spec.decision`

The portal records a decision in the **spec**, because snowplow's `/call` builds only the
main-resource path and cannot reach `proposals/status`. It is the same pattern as `spec.lifecycle` on a
TroubleshootingReport. The portal sends a merge-patch with the user's own token:

```json
{"spec": {"decision": {"phase": "Rejected", "reason": "why, in the person's words"}}}
{"spec": {"decision": {"phase": "PrOpen", "claim": "<BuilderPublish claim name>"}}}
```

- **Admission keeps it honest** (`templates/decision-policy.yaml`, `decisionPolicy.enabled`, on by
  default). For anyone but this service's ServiceAccount, a ValidatingAdmissionPolicy refuses any
  other spec change, refuses removing a decision, and refuses changing one, with one exception:
  `PrOpen → Rejected`, because a change request closed unmerged is a rejection. An identical resend is
  allowed and changes nothing. A MutatingAdmissionPolicy stamps `decidedBy` from
  `request.userInfo.username` and `decidedAt` from the apiserver's clock, so the portal neither sends
  nor can forge them. It is rendered only where `admissionregistration.k8s.io/v1`
  MutatingAdmissionPolicy is served (Kubernetes 1.36+). Elsewhere the validating policy still requires
  `decidedBy` to equal the requesting user, and the client must send both fields.
- **The run mirrors it onto status** at the start of every run (phase, decidedBy, decidedAt, reason),
  and the claim onto the `review.krateo.io/publish-claim` label. It writes only what differs, so it is
  idempotent. Status stays the service's record; the decision is the person's input.
- **The decision is authoritative before the mirror runs.** Dedup and supersession read
  `spec.decision` first. A decided proposal (and one whose status is already `Rejected` or `Merged`) is
  never superseded and never deduplicated into. The same fingerprint coming back is counted as
  *already decided* in the validate step and is not written, because the object is named after its
  fingerprint and writing it would reset the answer to `Proposed`.

## What a finding is, and how night two relates to night one

- **`spec.subject`** is what a proposal is *about*: `component/signal` in lowercase kebab, e.g.
  `installer-chart-inspector/rbac-generation-http-500`. The model chooses the target repository afresh
  every night, so the target is a weak identity. One failure used to arrive as several unrelated
  proposals in several repositories. The subject is normalised in code, never trusted as typed.
- **A fingerprint** over (kind + target + normalised content) catches exact repeats. They are dropped,
  and counted as `deduplicated`.
- **Supersession.** A new proposal with the same kind and subject as a `Proposed` one from an earlier
  run, or the same kind and target file with a different body, **supersedes** it. The old one gets
  `phase: Superseded` and `status.supersededBy`. `PrOpen` proposals are not superseded by subject,
  because a person's pull request hangs off them. Proposals with no subject (everything written before
  the field existed) **never** match each other.
- **`TargetResolved`** records whether `target.repo` exists, checked with an *anonymous* GitHub API
  request, because this service holds no credential. `False/NotFoundOrPrivate` (no public repo by that name — missing, or private) is a normal state, not a
  rejection: the finding stands and wants re-aiming. A private repository answers 404 like a missing
  one, and the condition message says so.

## What keeps it honest

- **Evidence is required**, `minItems: 1`. The **queries** a reviewer should re-run are the ones this
  service issued, recorded on the run under `status.evidence.clickhouse.queries`. They are not a
  paraphrase from the model. (That field was pruned by the CRD from 0.1.14 until it was declared; a
  test now drives a whole run and fails on any written field the CRDs would prune.)
- **Confidence is the model's own estimate**, and the CRD says so. The old cap was arithmetic on
  model-authored counts and never fired once (#14).
- **One alert kind.** `observability.krateo.io/v1alpha1` `Alert` is the only alert this platform
  evaluates, and its live spec is in the prompt. A PrometheusRule or a `monitoring.krateo.io` object is
  refused with a note. All thirteen Alert proposals on 057 before this change were one of those two.
- **Proposing nothing is a valid night**, and no evidence at all is a `Failed` run. "No proposals" from
  a healthy night and from a blind one look identical and mean opposite things.
  **`PartiallyCompleted` is its own phase** for a run where some source failed.
- **Token usage is recorded only when the agent reports it** (`kagent_usage_metadata` on the A2A
  stream). It is absent otherwise, never zeros. There is no model name: the response does not carry
  one.

## Reading the platform

| source | how | why that way |
|---|---|---|
| ClickHouse | fixed SQL from chart values, `{from}`/`{to}` bound to the window | a model is never asked to author SQL against a store that has held live credentials; an unwindowed query is refused |
| kagent sessions | session **metadata**, and the text of **user-authored** messages in the window, from kagent's Postgres, with a role granted SELECT on `session` and `event` (revoked on `task`) | reports which deployed agents are idle or never used, and what people asked, so a question asked again and again with no written answer becomes a Documentation proposal. All users; the run records `scope` saying so. Questions only, never agent replies or tool output; redacted before the prompt; capped per conversation and in total, with every cut recorded (`truncated`, `droppedMessages`, `droppedSessions`); no user ids. `shapes` counts how the stored events parsed, so an unreadable corpus fails the source instead of reading as a quiet night |
| existing Alerts and pages | Kubernetes API: Alerts, and page roots (Flex widgets named `page-*`; there is no Page kind), each read failing on its own | so it proposes gaps rather than duplicates |

The review window is bounded, and that is a safety control rather than a cost one: spans ingested
before the collector's JWT redaction landed can still carry live credentials.

## Configuration

See `helm/nightly-review/values.yaml`, and `values.schema.json`, whose defaults are what the installer
applies. The values that matter: `clickhouseQueries` (the reviewable surface; adapt them to your
schema), `secrets.kagentDb` (the narrow Postgres role), `reviewer.modelConfig`,
`config.targetCheckApiUrl` (empty disables the existence check), `portalAdminAccess`, and
`decisionPolicy`.

Releases are cut by tag: `Chart.yaml` ships `CHART_VERSION`, and a `X.Y.Z` tag builds the image and
publishes both charts at that version.

## Related

- `alert-troubleshooter`: the same service→A2A→CR pattern this is modelled on
- `krateo-autopilot`: the orchestrator this used to ask; the dedicated reviewer replaced it
