"""How much of the night the review actually saw, counted by the service and said in words.

WHY THIS EXISTS. rr-20260930-0200, the first analysis run on 057, cut 2,469,686 characters out of the
agent-analysis stage, left two agents unanalysed for the agent cap and one for a failed call, and folded
all forty of kagent-sessions' questions into that analysis. The model saw a small fraction of the
conversations, and its summary read like a full review: "Nightly review identified three significant
unalerted platform error patterns…". Every number needed to say otherwise was already on the run, spread
over status.evidence where no reader of the summary would add it up.

SO THE SERVICE ADDS IT UP. status.coverage carries the counts; its `sentence` is prepended to
status.summary whenever anything was cut, and the same sentence goes into the main model's corpus note so
its proposals stop claiming more than it read. It is computed from the sources' own stats, never asked
of a model: a model that saw a fraction cannot be the one to say how large a fraction.

WHAT THE NUMBERS MEAN, precisely, because "X of Y" invites rounding in the reader's head.
- conversations: the agent-analysis stage's. Read = conversations shown to an agent's call THAT
  RETURNED an assessment (a failed call read nothing the review can use). Total = every conversation in
  the window of the agents chosen for analysis plus those skipped for the agent cap. Agents excluded by
  configuration (the reviewer itself, *-bench) and agents no longer deployed are outside the total: they
  are out of scope, not missed.
- characters: in the stage's rendered units. Read = what analysed agents' calls were shown. Total = what
  was shown plus what the caps measurably cut, for every chosen agent. It is a LOWER BOUND whenever
  events or conversations were dropped without being fetched (the head/tail message cap, the session
  cap, an agent not reached), and the sentence then says "at least".
- sourcesCut: every main-corpus source that was truncated before the main call, and the agent-analysis
  block itself when the assessments overran corpusMaxChars.
- sourcesFailed: every source that did not answer (ok: false). Not a cut, but a summary silent about it
  would read as a whole night just the same.
"""

SKIP_REASONS = ("over maxAgents",)


def _n(value):
    return f"{value:,}"


def compute(evidence_stats):
    """status.coverage from status.evidence. Always returns a dict; `complete` says whether anything was
    cut, and `sentence` is always set so the corpus note can carry it either way."""
    aa = evidence_stats.get("agent-analysis") or {}
    records = aa.get("agents") or []
    over_cap = [s for s in aa.get("skipped") or [] if s.get("reason") in SKIP_REASONS]

    analysed = [r for r in records if not r.get("error")]
    conv_read = sum(r.get("conversations", 0) for r in analysed)
    conv_total = sum(r.get("sessions", 0) for r in records) + sum(s.get("sessions", 0) for s in over_cap)
    measured = any("chars" in r for r in records)
    chars_read = sum(r.get("chars", 0) for r in analysed)
    chars_total = sum(r.get("chars", 0) + r.get("droppedChars", 0) for r in records)
    lower_bound = bool(over_cap) or any(
        r.get("droppedMessages") or r.get("droppedSessions") or r.get("error") for r in records)

    skipped = [{"agent": s["agent"], "reason": s["reason"]} for s in over_cap]
    skipped += [{"agent": r["agent"],
                 "reason": "analysis failed" if r.get("conversations") else "nothing readable"}
                for r in records if r.get("error")]

    cut = []
    for name, st in sorted(evidence_stats.items()):
        if name == "agent-analysis":
            if st.get("corpusDroppedChars"):
                cut.append({"source": name, "droppedChars": st["corpusDroppedChars"]})
        elif st.get("truncated"):
            cut.append({"source": name, "droppedChars": st.get("droppedChars", 0)})

    # A source that did not answer at all is not "cut", but a summary that stayed silent about it would
    # read as a whole night all the same. The phase says PartiallyCompleted; the sentence says which.
    failed = sorted(n for n, st in evidence_stats.items() if st.get("ok") is False)

    complete = not (skipped or cut or failed or aa.get("truncated") or conv_read < conv_total
                    or (measured and chars_read < chars_total))

    parts = []
    if records or over_cap:
        head = (f"Based on {'all ' if conv_read == conv_total else ''}{_n(conv_read)}"
                + ("" if conv_read == conv_total else f" of {_n(conv_total)}") + " agent conversations")
        if measured:
            head += (f" ({_n(chars_read)} of {'at least ' if lower_bound else ''}{_n(chars_total)} characters)"
                     if chars_read < chars_total else f" ({_n(chars_read)} characters)")
        parts.append(head)
    elif aa:
        parts.append("No agent conversation was analysed"
                     + (f" ({aa.get('error') or aa.get('note')})" if aa.get("error") or aa.get("note") else ""))
    if skipped:
        parts.append(f"{len(skipped)} agent(s) skipped: "
                     + ", ".join(f"{s['agent']} ({s['reason']})" for s in skipped))
    if cut:
        parts.append("evidence cut before the review: "
                     + ", ".join(f"{c['source']} ({_n(c['droppedChars'])} characters not shown)" for c in cut))
    if failed:
        parts.append("did not answer: " + ", ".join(failed))
    sentence = "Coverage: " + ("; ".join(parts) if parts else "nothing was measured") + "."

    out = {"complete": complete, "sentence": sentence[:600], "agentsSkipped": skipped[:30],
           "sourcesCut": cut[:10], "sourcesFailed": failed}
    if records or over_cap:
        out |= {"conversationsRead": conv_read, "conversationsTotal": conv_total}
    if measured:
        out |= {"charsRead": chars_read, "charsTotal": chars_total, "charsTotalIsLowerBound": lower_bound}
    return out


def summary(coverage, model_summary, limit=2000):
    """status.summary: the coverage sentence FIRST when anything was cut, then the model's words. The
    sentence goes first because a summary is read from the top and truncated from the bottom."""
    model_summary = (model_summary or "").strip()
    if coverage.get("complete"):
        return model_summary[:limit] or None
    return (coverage["sentence"] + (" " + model_summary if model_summary else ""))[:limit]
