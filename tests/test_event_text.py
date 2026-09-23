"""The session-content extractor (sessiontext.py — stdlib only, so these stay hermetic), and specifically its behaviour when it does NOT recognise a shape.

Event.Data is an opaque JSON string: kagent persists the ADK event verbatim and the stored shape is
not pinned anywhere readable from outside the cluster. So the extractor tries several plausible
paths, and the thing these tests actually protect is that an UNRECOGNISED shape is REPORTED rather
than silently yielding nothing — because "no questions were asked last night" and "I could not read
any of the questions" produce an identical empty corpus and mean opposite things.
"""
import json
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from sessiontext import _event_text  # noqa: E402


def test_content_parts_shape():
    role, text, shape = _event_text(json.dumps(
        {"content": {"role": "user", "parts": [{"text": "why is my composition not ready?"}]}}))
    assert (role, text, shape) == ("user", "why is my composition not ready?", "content")


def test_message_parts_shape():
    role, text, shape = _event_text(json.dumps(
        {"message": {"role": "assistant", "parts": [{"text": "because its child is unhealthy"}]}}))
    assert shape == "message" and text == "because its child is unhealthy"


def test_root_parts_shape_and_author_fallback():
    role, text, shape = _event_text(json.dumps(
        {"author": "autopilot", "parts": [{"text": "hello"}]}))
    assert (role, shape) == ("autopilot", "root")


def test_multiple_parts_are_joined():
    _, text, _ = _event_text(json.dumps(
        {"content": {"parts": [{"text": "one"}, {"text": "two"}]}}))
    assert text == "one\ntwo"


def test_non_text_parts_are_ignored_not_crashed():
    """Tool-call parts carry structured data, not text. They must not raise and must not be quoted."""
    _, text, shape = _event_text(json.dumps(
        {"content": {"parts": [{"functionCall": {"name": "k8s_get"}}, {"text": "real question"}]}}))
    assert text == "real question" and shape == "content"


def test_unrecognised_shape_is_reported_not_silent():
    """THE POINT OF THIS FILE. A shape we cannot read must say so."""
    role, text, shape = _event_text(json.dumps({"somethingElse": {"nested": "value"}}))
    assert text == "" and shape == "unmatched"


def test_unparseable_data_is_reported_not_silent():
    assert _event_text("not json at all")[2] == "unparseable"
    assert _event_text("[1,2,3]")[2] == "unparseable"        # valid JSON, wrong type


def test_absent_payload_is_distinct_from_unreadable():
    """An event carrying nothing is not a decoding failure, and must not be filed as one —
    otherwise a real decoding problem hides behind legitimately empty events."""
    assert _event_text(None)[2] == "empty"
    assert _event_text("")[2] == "empty"


def test_empty_text_parts_do_not_count_as_a_match():
    """A part with whitespace-only text is not evidence, and must not mask an unmatched shape."""
    _, text, shape = _event_text(json.dumps({"content": {"parts": [{"text": "   "}]}}))
    assert text == "" and shape == "unmatched"
