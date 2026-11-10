"""Find the nesting depths (internal/pyyaml/api.go: composeMaxDepthLoad, composeMaxDepthLoadAll,
representMaxDepth) at which PyYAML raises RecursionError when called where the
service calls it.

    /tmp/nr-venv/bin/python -I internal/pyyaml/testdata/measure_depth.py <path-to-python-checkout>
"""
import sys
sys.path.insert(0, sys.argv[1])
import yaml
import proposals as P

def at_service_depth(fn, base):
    # base = frames the service has on the stack below fn (e.g. [<module>, main, validate_batch, fingerprint])
    def stack_depth():
        n, f = 0, sys._getframe(1)
        while f is not None:
            n, f = n + 1, f.f_back
        return n
    extra = stack_depth() - base
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(1000 + extra)
    try:
        return fn()
    finally:
        sys.setrecursionlimit(old)

def ok(fn, base):
    try:
        at_service_depth(fn, base)
        return True
    except RecursionError:
        return False

def threshold(make, fn, base):
    lo, hi = 1, 2000
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if ok(lambda: fn(make(mid)), base):
            lo = mid
        else:
            hi = mid - 1
    return lo

seq = lambda n: "[" * n + "1" + "]" * n
seqe = lambda n: "[" * n + "]" * n
mp = lambda n: "{a: " * n + "1" + "}" * n
# normalise_body at [<module>, main, validate_batch, fingerprint] -> base 4 frames below normalise_body's caller frame
for name, make in (("seq", seq), ("seq-empty", seqe), ("map", mp)):
    print(name, "normalise_body max ok depth:", threshold(make, lambda c: P.normalise_body(c, "yaml"), 4))
    print(name, "safe_load only:", threshold(make, lambda c: yaml.safe_load(c), 5))
    print(name, "alert_kind_violation:", threshold(make, lambda c: P.alert_kind_violation({"kind": "Alert", "change": {"format": "yaml", "content": c}}), 3))
    print(name, "safe_load_all only (alert path):", threshold(make, lambda c: list(yaml.safe_load_all(c)), 4))
