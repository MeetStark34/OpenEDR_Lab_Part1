"""Proves the validator can fail: each mutation must change the outcome."""
import copy, validate as v
from lab_data import EVENTS, QUERIES
checks = []
def hit(q, e=None):
    ast = v.parse(q); return [x["_id"] for x in (e or EVENTS) if v.evaluate(ast, x)]
# 1 the assignment's "net view" value can never match a process.name
checks.append(("'net view' as process.name returns 0", hit('process.name : "net view"') == []))
# 2 case sensitivity
checks.append(("wrong-case keyword value returns 0", hit('process.name : "PowerShell.exe"') == []))
# 3 multi-word wildcard parsed as one literal
ev = [{"_id": "x", "process.command_line": "powershell -w hidden -c x"}]
checks.append(("'*-w hidden*' matches as one literal", hit("process.command_line : (*-enc* or *-w hidden*)", ev) == ["x"]))
# 4 removing the parent from S1-02 must drop the S1 hit
m = copy.deepcopy(EVENTS)
for e in m:
    if e["_id"] == "S1-02": e["process.parent.name"] = "wmiprvse.exe"
checks.append(("S1 misses when parent is wmiprvse.exe", hit(QUERIES["S1"], m) == []))
# 5 assignment's literal S3 simulation does not match the S3 query
s301 = [e for e in EVENTS if e["_id"] == "S3-01"]
checks.append(("assignment S3 literal command misses S3 query", hit(QUERIES["S3"], s301) == []))
# 6 malformed query raises
try:
    v.parse('process.name : ("a" or'); checks.append(("malformed query rejected", False))
except SyntaxError:
    checks.append(("malformed query rejected", True))
for n, ok in checks: print("PASS" if ok else "FAIL", n)
raise SystemExit(0 if all(o for _, o in checks) else 1)
