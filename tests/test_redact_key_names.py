"""A secret's KEY may be part of a longer name: DB_PASSWORD, PGPASSWORD, MY_API_KEY.

The key pattern opened with `\\b(password|...)`, and `\\b` does not fire between `_` and a letter or
inside PGPASSWORD, so every env-var-shaped secret passed untouched. On 057 KAGENT_DB_PASSWORD holds
admin's password, and the agent-analysis stage reads tool output, which is exactly where an `env` dump
lands. Values are assembled at runtime so the repo's secret scanner sees no literal credential.
"""
import pytest

import proposals as P

V = "s3" + "cret" + "Val" + "ue9"          # 12 chars, has a digit, no literal in the source
PUNCT = "s3" + "cret!" + "va" + "lue"      # punctuation must not stop the redaction halfway


@pytest.mark.parametrize("line", [
    f"DB_PASSWORD={V}",
    f"PGPASSWORD={V}",
    f"MY_API_KEY={V}",
    f"CLICKHOUSE_PASSWORD={V}",
    f"export KAGENT_DB_PASSWORD='{V}'",
    f"db_password: {V}",
    f'{{"PGPASSWORD": "{V}"}}',
    f'{{"db_access_token": "{V}"}}',
    f"KAGENT_DB_PASSWORD={PUNCT}",
])
def test_an_env_style_key_is_redacted(line):
    out = P.redact(line)
    assert V not in out and PUNCT not in out and "cret" not in out, out
    assert "<REDACTED>" in out


def test_an_env_dump_redacts_every_secret_and_keeps_the_rest():
    dump = "\n".join([
        "HOME=/root",
        f"KAGENT_DB_PASSWORD={V}",
        "KAGENT_DB_HOST=kagent-postgresql",
        f"CLICKHOUSE_PASSWORD={PUNCT}",
        f"OPENAI_API_KEY={V}",
    ])
    out = P.redact(dump)
    assert "cret" not in out
    assert "HOME=/root" in out and "KAGENT_DB_HOST=kagent-postgresql" in out
    assert out.count("<REDACTED>") == 3


@pytest.mark.parametrize("prose", [
    "How do I reset my password?",
    "set the password: see docs",
    "tokens used: 14518",
])
def test_prose_about_passwords_survives(prose):
    assert P.redact(prose) == prose
