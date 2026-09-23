"""Pull human-readable text out of one stored kagent event.

WHY THIS IS ITS OWN MODULE AND NOT PART OF evidence.py. It is pure parsing — stdlib only, no HTTP, no
cluster — and the unit suite is hermetic and dependency-free by design (pytest + jsonschema, nothing
else). Importing it from evidence.py would drag `requests` into the test environment to exercise a
function that never makes a request. CI caught exactly that; this keeps the boundary honest rather
than widening the test dependencies to match a misplacement.
"""
import json


def _event_text(data):
    """Pull human-readable text out of one stored event.

    Event.Data is an opaque JSON string (kagent persists the ADK event verbatim), and the shape is
    not pinned anywhere we can read from outside. So try the plausible paths and REPORT which one
    matched rather than assuming: a silent empty result here is indistinguishable from a quiet night,
    which is the failure this whole service is built not to have. The first real run tells us the
    truth; until then the stats say "shape=unmatched" instead of nothing.

    Returns (role, text, shape) — text is "" when nothing matched.
    """
    if data is None or data == "":
        # No payload at all. Distinct from "I could not read it" — lumping the two together would
        # hide a decoding problem behind events that legitimately carry nothing.
        return "", "", "empty"
    try:
        ev = json.loads(data) if isinstance(data, str) else data
    except (json.JSONDecodeError, TypeError):
        return "", "", "unparseable"
    if not isinstance(ev, dict):
        return "", "", "unparseable"

    for shape, container in (("content", ev.get("content")),
                             ("message", ev.get("message")),
                             ("root", ev)):
        if not isinstance(container, dict):
            continue
        parts = container.get("parts")
        if isinstance(parts, list):
            texts = [p["text"] for p in parts
                     if isinstance(p, dict) and isinstance(p.get("text"), str) and p["text"].strip()]
            if texts:
                role = container.get("role") or ev.get("author") or ""
                return str(role), "\n".join(texts), shape
    if isinstance(ev.get("text"), str) and ev["text"].strip():
        return str(ev.get("author") or ""), ev["text"], "text"
    return "", "", "unmatched"
