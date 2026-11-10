"""pg8000.native.to_statement over the service's queries, for pg_test.go.

REGENERATE from a checkout of the last Python commit (9a11299), with pg8000==1.31.2:
    python -I internal/pg/testdata/gen_to_statement.py /path/to/python-checkout > internal/pg/testdata/to_statement.json
"""
import json
import re
import sys

sys.path.insert(0, sys.argv[1])
from pg8000.native import to_statement  # noqa: E402

import analysis  # noqa: E402
import evidence  # noqa: E402

queries = [evidence.SESSION_SQL, evidence.QUESTIONS_SQL, evidence.QUESTIONS_CENSUS_SQL, analysis.CENSUS_SQL,
           analysis.CONVERSATIONS_SQL, "SELECT :a, ':b', $$ :c $$, \"x:d\", E'it\\'s :e', :a::int -- :f\n, :g"]
out = []
for q in queries:
    stmt, make_args = to_statement(q)
    # make_args maps a dict of named values to the positional list; probe it with the names themselves
    keys = sorted(set(re.findall(r":([A-Za-z_][A-Za-z0-9_]*)", q)))
    probe = {k: k for k in keys}
    try:
        order = make_args(probe)
    except KeyError:
        order = None
    out.append({"sql": q, "statement": stmt, "order": order})
print(json.dumps(out, indent=0))
