"""check.py FILE RC EXPR... -- assert on one reachable -json run.

Each EXPR is Python, evaluated with:
  rc          exit status of the run
  d           the parsed JSON
  st(i, n)    status of check n in direction i (0 = A->B, 1 = B->A), "" if absent
  code(i, n)  its code
  det(i, n)   its detail text
  chk(i, n)   the whole check, as a dict ({} if absent)
  verdict(i)  the direction's verdict
"""
import json
import sys

path, rc, exprs = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
with open(path) as f:
    d = json.load(f)


def find(i, n):
    for c in d["directions"][i]["checks"]:
        if c["name"] == n:
            return c
    return {}


env = {
    "rc": rc,
    "d": d,
    "st": lambda i, n: find(i, n).get("status", ""),
    "code": lambda i, n: find(i, n).get("code", ""),
    "det": lambda i, n: find(i, n).get("detail", ""),
    "chk": find,
    "verdict": lambda i: d["directions"][i]["verdict"],
}
failed = [e for e in exprs if not eval(e, env)]
for e in failed:
    print("    FAILED: " + e)
sys.exit(1 if failed else 0)
