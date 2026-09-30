# nightly-review

Once a night, reads the platform's own telemetry and its agents' activity, and **proposes** changes:
new alerts, portal widgets, agent-prompt corrections, gateway policy tuning, missing documentation.
Every proposal becomes a `Proposal` object. Nothing is applied, and this service opens no pull
requests. **The portal opens one per proposal**, when a person decides to.

## The shape, and why

```
CronJob ─▶ gather ─▶ analyse ─▶ ask ─▶ validate ─▶ publish ─▶ record
           evidence   one call   the     schema, redact,   skipped:   Proposals +
           (fixed     per agent, reviewer alert kind,      dryRun     ReviewRun
           queries)   whole      agent    dedup/supersede,
                      conver-    (no      target exists?
                      sations    tools)
```

Each stage is recorded on the run as `status.steps[]`, with its own start, finish and outcome, so a
failed run says *where* it stopped, and in particular whether the model was ever called.

**The agent proposes; the service writes.** The reviewer is a dedicated kagent Agent holding **no
tools** (`templates/agent.yaml`). It cannot delegate, fetch or write; it reads the evidence it is given
and returns JSON. That JSON is schema-checked, redacted and validated before any of it is written.
A prompt injection can therefore produce a bad `Proposal`, never a commit.

**Conversations are read in full, but not by the main review.** The `analyse` stage makes one call
per agent, to the same tool-less reviewer, over that agent's conversations in the window: what people
asked, what the agent answered, which tools it called and what they returned, against the prompt the
agent runs with today. What reaches the main review is each call's bounded **assessment**, never a
transcript. See [What the agents did](#what-the-agents-did).

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
- **`TargetResolved`** records whether `target.repo` exists, with one `HEAD` per repository per run.
  With `config.targetCheck.tokenSecret` (values.yaml: `gh-token`/`token`; no schema default) the check is authenticated: the
  kubelet injects that one Secret key as an env var (`secretKeyRef`, `optional: true`), so the
  ServiceAccount still has no Secret read, and the token is used only as the check's `Authorization`
  header — never logged, never in a prompt or a status (a test drives a whole run with a fake token to
  hold that). Authenticated, a private repository the token can see is `True/RepoFound` and a 404 is
  `False/RepoNotFound`; a rejected token (401) is `Unknown/CheckFailed`, never "not found". Without a
  token, `False/NotFoundOrPrivate` (missing, or private — an anonymous check cannot tell). False is a
  normal state, not a rejection: the finding stands and wants re-aiming.
- **Fixed destinations.** For a kind in `config.targets` (values.yaml: `Alert` ->
  `krateo-platformops/observability`, under `charts/krateo-observability/templates`) the service
  replaces `target.repo` and the path's directory before fingerprinting, notes the move in
  `ValidationNotes`, and tells the model up front; the model keeps choosing the file name.

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
| kagent sessions | session **metadata**, and the text of **user-authored** messages in the window, from kagent's Postgres, with a role granted SELECT on `session` and `event` (revoked on `task`) | reports which deployed agents are idle or never used, and what people asked, so a question asked again and again with no written answer becomes a Documentation proposal. All users; the run records `scope` saying so. Questions only, never agent replies or tool output; redacted before the prompt; capped per conversation and in total, with every cut recorded (`truncated`, `droppedMessages`, `droppedSessions`); no user ids. `shapes` counts how the stored events parsed, so an unreadable corpus fails the source instead of reading as a quiet night. The questions of agents the analysis read in full are folded to a pointer (`questionsFolded`) |
| agent analysis | whole conversations of every agent with sessions in the window (same Postgres role; `event` already holds replies and tool output), and each agent's prompt from its `Agent` object | the only source that can say whether people were **served**, and why the prompt made it so. Read by a separate call per agent; the main review gets the assessment. See below |
| existing Alerts and pages | Kubernetes API: Alerts, and page roots (Flex widgets named `page-*`; there is no Page kind), each read failing on its own | so it proposes gaps rather than duplicates |

The review window is bounded, and that is a safety control rather than a cost one: spans ingested
before the collector's JWT redaction landed can still carry live credentials.

## What the agents did

The `analyse` stage, between `gather` and `ask`. It exists because #32's question-only read was the
wrong shape twice over: on 057 (rr-20260929-2033) it saw 26 questions and was barred from the 323 events
that say whether they were answered, and it still overran its cap by 167,941 characters. Whole
conversations are far bigger, so they are read one agent at a time and **never** go to the main call,
where they would evict the ClickHouse and Kubernetes evidence that produced every proposal that night.

- **What one call sees.** The agent's conversations in the window, in order, per conversation (Python
  `author`/`function_call` and Go `Author`/`functionCall` spellings both), with delegated sessions
  labelled as another agent's; and the agent's **current prompt**, from its `Agent` (v1alpha2): the
  `systemMessage`, with kagent's `promptTemplate` `include("alias/key")` resolved from the ConfigMaps
  its `dataSources` name. On 057 every production agent's `systemMessage` is a single include, so the
  1–49k characters that matter are in a ConfigMap. A `systemMessageFrom` Secret is **never** read; it is
  recorded as such.
- **What comes back.** `failurePatterns[]` (category: misroute, refusal, wrong-or-invented,
  tool-failure, loop, ignored-instruction, other), `promptFindings[]` (what the prompt says or lacks, the
  evidence, the change), `recurringNeeds[]`, `servedWell`, `summary`.
- **Counted by the service, not the model.** A pattern's `count` is the number of distinct cited
  conversations that exist; the model is never asked for a number. Every excerpt is searched for in the
  transcript it cites (and a `promptExcerpt` in the prompt); one that cannot be found is dropped and
  counted in `unverifiedExamples`. Tool errors, unanswered conversations and repeated identical calls are
  **measured** from the events and given to the model as fact.
- **Redacted before anything leaves the process**, per message and before any cut — replies, tool
  arguments, tool results and the prompt included. The per-agent call is a new egress point (whole
  conversations leave the process there), and a test stands a fake reviewer at it. The redactor now
  matches any identifier CONTAINING a key word — `DB_PASSWORD=`, `PGPASSWORD=`, `MY_API_KEY=`,
  `"dbPassword": "…"`, `db_password: …` all passed before, because `\b` never matched after `_` or
  inside a word — plus JSON-quoted keys and prose (`my password is …`, when the value carries a digit).
  The key must be followed by `=` or `:`, so "how do I reset my password?" is left alone.
- **Budgets** (`config.agentAnalysis`, all declared in `values.schema.json`): agents per run (8), sessions
  per agent (20), events per conversation (40: first half and last half), characters per agent (80k),
  per message (2k), per tool result (800, the hard one), per tool call's arguments (400), prompt (60k), a
  per-event fetch limit (256 KiB), a per-call timeout (300s) and a stage total (1500s), and what the
  assessments may add to the main corpus (16k). This budget is **separate** from `evidenceMaxChars`.
  Every cut is recorded on the run.
- **Failure is per agent.** A call that times out or answers unusable JSON is recorded on that agent
  (`status.evidence.agent-analysis.agents[].error`) and the others go on. The source is `ok: false`, and
  the run `PartiallyCompleted`, only when no agent could be analysed.
- **Not paid for twice.** #32's question read stays — its census and `shapes` are what tell "nobody
  asked" from "the shape changed", and it still carries the questions of agents the analysis did not
  cover — but the questions of every agent the analysis **did** read are folded to one pointer line
  (`questionsFolded`).
- **Excluded:** the reviewer itself, always, and `excludeAgents` (default `*-bench`: a benchmark's
  traffic is a harness's, and product prompts must not be tuned from it). Agents with sessions but no
  longer deployed are skipped: their rows are history.
- **Where a Prompt proposal lands.** If the `Agent` or its prompt ConfigMap carries
  `krateo.io/prompt-repo` (or `krateo.io/source-repo`, `org.opencontainers.image.source`), a Prompt
  proposal about that agent is aimed there, whatever the model chose, with a validation note. Otherwise
  the model proposes a repository and `TargetResolved` records what GitHub said — for agent prompts,
  which live in private `krateo-agentiko` repositories, that is `RepoFound` with the token and
  `NotFoundOrPrivate` without it.
- **Coverage, in words.** `status.coverage` counts what the review actually saw — conversations and
  characters read of the total, agents skipped and why, sources cut or silent — and, whenever anything
  was cut, its sentence opens `status.summary` (e.g. "Coverage: Based on 21 of 65 agent conversations;
  3 agent(s) skipped: …"). The same sentence goes to the main model, so its proposals do not overclaim.
  Computed by the service, never the model.
- **On the ReviewRun:** `status.evidence.agent-analysis` (scope, counts, cuts, and one entry per agent:
  sessions, messages, droppedChars, tokens, patterns, error), `status.agentAnalysis.assessments` (bounded,
  for the portal; the one place a run keeps quoted content: at most three redacted 300-character
  excerpts per pattern), `status.usage` (every model call with the tokens it reported, and a total that
  says how many calls it covers), and an `analyse` entry in `status.steps`.
- **RBAC:** `get` on ConfigMaps in the release namespace (never `list`, never Secrets; narrowed to
  `config.agentAnalysis.promptConfigMaps` when set), and `get` on Agents beside the cluster-wide `list`
  granted since 0.1.19.

**The instructions now reach the model.** Both calls send their instructions as the first part of the
A2A message. They used to travel in `params.metadata.systemPrompt`, which kagent 0.10.1 never reads (its
request converter uses `message.parts` only), so until this release the main review never saw a line of
`prompt.SYSTEM` — only the reviewer Agent's own `systemMessage` and the schema rendered into the message.

## Configuration

See `helm/nightly-review/values.yaml`, and `values.schema.json`, whose defaults are what the installer
applies. The values that matter: `clickhouseQueries` (the reviewable surface; adapt them to your
schema), `secrets.kagentDb` (the narrow Postgres role), `reviewer.modelConfig`,
`config.targetCheckApiUrl` (empty disables the existence check), `config.targetCheck.tokenSecret`
(the credential for it; empty name = anonymous), `config.targets` (fixed destinations per kind), `config.agentAnalysis` (the per-agent
conversation budget; `maxAgents: 0` turns the stage off), `portalAdminAccess`, and `decisionPolicy`.

Releases are cut by tag: `Chart.yaml` ships `CHART_VERSION`, and a `X.Y.Z` tag builds the image and
publishes both charts at that version.

## Related

- `alert-troubleshooter`: the same service→A2A→CR pattern this is modelled on
- `krateo-autopilot`: the orchestrator this used to ask; the dedicated reviewer replaced it
