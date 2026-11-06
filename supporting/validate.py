"""Tiny KQL-subset evaluator plus threshold and correlation checks for the synthetic dataset.

Models keyword/wildcard field behaviour: case-sensitive, whole-value matching.
This is a consistency check on the report's own data. It is NOT Kibana.
Run: python validate.py   (exit code 1 if any query disagrees with its expected hits)
"""
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta

from lab_data import EVENTS, EXPECTED, QUERIES

TOK = re.compile(r'''\s*(?:
    (?P<lp>\() | (?P<rp>\)) | (?P<colon>:) |
    "(?P<q>(?:[^"\\]|\\.)*)" |
    (?P<kw>(?:and|or|not)(?=[\s(]|$)) |
    (?P<lit>(?:[^\s():"\\]|\\.|:(?=\*))+(?:[ ](?!and\b|or\b)(?:[^\s():"\\]|\\.)+)*)
)''', re.I | re.X)


def tokenize(s):
    pos, out = 0, []
    s = s.strip()
    while pos < len(s):
        m = TOK.match(s, pos)
        if not m or m.end() == pos:
            raise SyntaxError(f"bad token at {pos}: {s[pos:pos + 30]!r}")
        pos = m.end()
        out.append((m.lastgroup, m.group(m.lastgroup)))
    return out


class Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def kw(self, w):
        k, v = self.peek()
        if k == "kw" and v.lower() == w:
            self.i += 1
            return True
        return False

    def eat(self, kind):
        k, v = self.peek()
        if k != kind:
            raise SyntaxError(f"expected {kind}, got {k} {v}")
        self.i += 1
        return v

    def expr(self):
        n = self.andx()
        while self.kw("or"):
            n = ("or", n, self.andx())
        return n

    def andx(self):
        n = self.notx()
        while self.kw("and"):
            n = ("and", n, self.notx())
        return n

    def notx(self):
        return ("not", self.notx()) if self.kw("not") else self.prim()

    def prim(self):
        if self.peek()[0] == "lp":
            self.i += 1
            n = self.expr()
            self.eat("rp")
            return n
        f = self.eat("lit")
        self.eat("colon")
        return ("field", f, self.vals())

    def vals(self):
        if self.peek()[0] == "lp":
            self.i += 1
            vs = [self.val()]
            while self.kw("or"):
                vs.append(self.val())
            self.eat("rp")
            return vs
        return [self.val()]

    def val(self):
        k, v = self.peek()
        if k == "q":
            self.i += 1
            return ("exact", v)
        if k == "lit":
            self.i += 1
            return ("wild", v)
        raise SyntaxError(f"expected value, got {k} {v}")


def parse(q):
    p = Parser(tokenize(" ".join(q.split())))
    n = p.expr()
    if p.i != len(p.t):
        raise SyntaxError(f"trailing tokens: {p.t[p.i:]}")
    return n


def value_match(kind, pat, val):
    val = str(val)
    if kind == "exact" or "*" not in pat:
        return val == pat
    return re.fullmatch(".*".join(re.escape(x) for x in pat.split("*")), val, re.S) is not None


def evaluate(n, e):
    if n[0] == "and":
        return evaluate(n[1], e) and evaluate(n[2], e)
    if n[0] == "or":
        return evaluate(n[1], e) or evaluate(n[2], e)
    if n[0] == "not":
        return not evaluate(n[1], e)
    v = e.get(n[1])
    return v is not None and any(value_match(k, p, v) for k, p in n[2])


def T(e):
    return datetime.strptime(e["@timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")


def hits(name):
    ast = parse(QUERIES[name])
    return [e for e in EVENTS if evaluate(ast, e)]


def sliding(rows, key, field, win):
    """Maximum distinct `field` values per key inside any sliding window."""
    groups = defaultdict(list)
    for e in rows:
        groups[key(e)].append(e)
    res = {}
    for k, rs in groups.items():
        rs.sort(key=T)
        res[k] = max(len({b[field] for b in rs[i:] if T(b) - T(a) <= win}) for i, a in enumerate(rs))
    return res


def correlate(window=timedelta(seconds=30)):
    """exec -> outbound connection -> file create; same host and pid; ordered; within window."""
    out = []
    for x in hits("S2-PS"):
        rel = [e for e in EVENTS if e["host.name"] == x["host.name"] and e.get("process.pid") == x["process.pid"]
               and timedelta(0) <= T(e) - T(x) <= window]
        n = next((e for e in rel if e["event.category"] == "network"), None)
        f = next((e for e in rel if e["event.category"] == "file" and n and T(e) >= T(n)), None)
        out.append({"exec": x["_id"], "net": n and n["_id"], "file": f and f["_id"], "confirmed": bool(n and f)})
    return out


def results():
    R = {"queries": {}, "fail": []}
    for name in QUERIES:
        got = {e["_id"] for e in hits(name)}
        ok = got == EXPECTED[name]
        R["queries"][name] = {"hits": len(got), "expected": len(EXPECTED[name]), "ok": ok,
                              "unexpected": sorted(got - EXPECTED[name]),
                              "missing": sorted(EXPECTED[name] - got)}
        if not ok:
            R["fail"].append(name)

    def user(e):
        return e["user.name"]

    def pk(e):
        return f'{e["process.name"]}/{e["process.pid"]}'

    R["th_r1"] = sliding(hits("R1"), user, "process.name", timedelta(minutes=5))
    R["th_r1_tuned"] = sliding(hits("R1-TUNED"), user, "process.name", timedelta(minutes=5))
    out = [e for e in EVENTS if e.get("network.direction") == "outbound"]
    R["th_r2_ip"] = sliding(out, pk, "destination.ip", timedelta(minutes=1))
    R["th_r2_port"] = sliding(out, pk, "destination.port", timedelta(minutes=1))
    inb = [e for e in EVENTS if e.get("network.direction") == "inbound"]
    R["th_r2_in"] = sliding(inb, lambda e: e["source.ip"], "destination.port", timedelta(minutes=1))
    R["corr"] = correlate()
    R["total"] = len(EVENTS)
    return R


if __name__ == "__main__":
    r = results()
    print(json.dumps(r, indent=1))
    assert len({e["_id"] for e in EVENTS}) == len(EVENTS)
    sys.exit(1 if r["fail"] else 0)
