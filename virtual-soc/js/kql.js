/* KQL-subset parser and evaluator for the Virtual SOC Lab.
   Models keyword/wildcard field behaviour: case-sensitive, whole-value matching.
   It is a teaching tool. It is not Kibana. */
(function (root) {
  'use strict';

  class KqlError extends Error {
    constructor(message, pos) { super(message); this.pos = pos; }
  }

  const isSpace = c => c === ' ' || c === '\t' || c === '\n' || c === '\r';
  const STOP = new Set(['(', ')', '"', '<', '>']);

  function wordAt(s, i) {
    let j = i;
    while (j < s.length) {
      const c = s[j];
      if (c === '\\' && j + 1 < s.length) { j += 2; continue; }
      if (isSpace(c) || STOP.has(c)) break;
      if (c === ':' && s[j + 1] !== '*') break;
      j++;
    }
    return j;
  }
  const keywordAt = (s, i) => {
    const m = /^(and|or|not)(?=[\s(]|$)/i.exec(s.slice(i));
    return m ? m[1].toLowerCase() : null;
  };

  function tokenize(src) {
    const s = src, out = [];
    let i = 0;
    while (i < s.length) {
      const c = s[i];
      if (isSpace(c)) { i++; continue; }
      if (c === '(') { out.push({ t: 'lp', pos: i }); i++; continue; }
      if (c === ')') { out.push({ t: 'rp', pos: i }); i++; continue; }
      if (c === ':') { out.push({ t: 'colon', pos: i }); i++; continue; }
      if (c === '<' || c === '>') {
        const op = s[i + 1] === '=' ? c + '=' : c;
        out.push({ t: 'cmp', v: op, pos: i }); i += op.length; continue;
      }
      if (c === '"') {
        let j = i + 1, v = '';
        while (j < s.length && s[j] !== '"') {
          if (s[j] === '\\' && j + 1 < s.length) { v += s[j + 1]; j += 2; } else { v += s[j]; j++; }
        }
        if (j >= s.length) throw new KqlError('Unterminated quoted string', i);
        out.push({ t: 'q', v, pos: i }); i = j + 1; continue;
      }
      const kw = keywordAt(s, i);
      if (kw) { out.push({ t: 'kw', v: kw, pos: i }); i += kw.length; continue; }
      let j = wordAt(s, i);
      if (j === i) throw new KqlError(`Unexpected character "${c}"`, i);
      // Unquoted values may contain single spaces, for example *-w hidden*
      for (;;) {
        let k = j;
        while (k < s.length && s[k] === ' ') k++;
        if (k === j || k >= s.length || keywordAt(s, k)) break;
        const e = wordAt(s, k);
        if (e === k) break;
        j = e;
      }
      out.push({ t: 'lit', v: s.slice(i, j), pos: i }); i = j;
    }
    return out;
  }

  class Parser {
    constructor(toks, len) { this.t = toks; this.i = 0; this.len = len; }
    peek() { return this.t[this.i] || { t: 'end', pos: this.len }; }
    kw(w) { const p = this.peek(); if (p.t === 'kw' && p.v === w) { this.i++; return true; } return false; }
    eat(kind, label) {
      const p = this.peek();
      if (p.t !== kind) throw new KqlError(`Expected ${label}`, p.pos);
      this.i++; return p;
    }
    expr() { let n = this.andx(); while (this.kw('or')) n = { op: 'or', a: n, b: this.andx() }; return n; }
    andx() { let n = this.notx(); while (this.kw('and')) n = { op: 'and', a: n, b: this.notx() }; return n; }
    notx() { return this.kw('not') ? { op: 'not', a: this.notx() } : this.prim(); }
    prim() {
      const p = this.peek();
      if (p.t === 'lp') { this.i++; const n = this.expr(); this.eat('rp', 'a closing parenthesis'); return n; }
      if (p.t === 'q') { this.i++; return { op: 'text', v: p.v }; }
      if (p.t !== 'lit') throw new KqlError(p.t === 'end' ? 'Query ended unexpectedly' : 'Expected a field name or search term', p.pos);
      this.i++;
      const nx = this.peek();
      if (nx.t === 'colon') { this.i++; return { op: 'field', f: p.v, v: this.vals() }; }
      if (nx.t === 'cmp') {
        this.i++;
        const val = this.peek();
        if (val.t !== 'lit' && val.t !== 'q') throw new KqlError('Expected a value after the comparison', val.pos);
        this.i++;
        return { op: 'cmp', f: p.v, c: nx.v, v: val.v };
      }
      return { op: 'text', v: p.v };
    }
    vals() {
      if (this.peek().t === 'lp') { this.i++; const n = this.vor(); this.eat('rp', 'a closing parenthesis'); return n; }
      return this.val();
    }
    vor() { let n = this.vand(); while (this.kw('or')) n = { op: 'or', a: n, b: this.vand() }; return n; }
    vand() { let n = this.vnot(); while (this.kw('and')) n = { op: 'and', a: n, b: this.vnot() }; return n; }
    vnot() { return this.kw('not') ? { op: 'not', a: this.vnot() } : this.vprim(); }
    vprim() {
      if (this.peek().t === 'lp') { this.i++; const n = this.vor(); this.eat('rp', 'a closing parenthesis'); return n; }
      return this.val();
    }
    val() {
      const p = this.peek();
      if (p.t === 'q') { this.i++; return { op: 'exact', p: p.v }; }
      if (p.t === 'lit') { this.i++; return { op: 'wild', p: p.v }; }
      throw new KqlError('Expected a value', p.pos);
    }
  }

  function parse(q) {
    const src = String(q || '');
    if (!src.trim()) return null;
    const p = new Parser(tokenize(src), src.length);
    const n = p.expr();
    if (p.i !== p.t.length) throw new KqlError('Unexpected text after the end of the query', p.peek().pos);
    return n;
  }

  const reCache = new Map();
  function wildRe(pat) {
    if (reCache.has(pat)) return reCache.get(pat);
    let r = '';
    for (let i = 0; i < pat.length; i++) {
      const c = pat[i];
      if (c === '\\' && i + 1 < pat.length) { i++; r += pat[i].replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); } else if (c === '*') r += '[\\s\\S]*';
      else r += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    const re = new RegExp('^' + r + '$');
    reCache.set(pat, re);
    return re;
  }
  const ipNum = ip => ip.split('.').reduce((a, b) => a * 256 + Number(b), 0);
  function inCidr(ip, cidr) {
    const [net, bits] = cidr.split('/');
    const n = Number(bits);
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || !/^\d+\.\d+\.\d+\.\d+$/.test(net) || !(n >= 0 && n <= 32)) return false;
    const size = 2 ** (32 - n);
    return Math.floor(ipNum(ip) / size) === Math.floor(ipNum(net) / size);
  }
  function matchValue(node, val, field) {
    if (node.op === 'or') return matchValue(node.a, val, field) || matchValue(node.b, val, field);
    if (node.op === 'and') return matchValue(node.a, val, field) && matchValue(node.b, val, field);
    if (node.op === 'not') return !matchValue(node.a, val, field);
    const s = String(val);
    if (field.endsWith('.ip') && node.p.includes('/')) return inCidr(s, node.p);
    if (node.op === 'exact') return s === node.p;
    return wildRe(node.p).test(s);
  }
  function evaluate(n, doc) {
    if (!n) return true;
    switch (n.op) {
      case 'and': return evaluate(n.a, doc) && evaluate(n.b, doc);
      case 'or': return evaluate(n.a, doc) || evaluate(n.b, doc);
      case 'not': return !evaluate(n.a, doc);
      case 'field': {
        const v = doc[n.f];
        return v !== undefined && v !== null && matchValue(n.v, v, n.f);
      }
      case 'cmp': {
        const v = doc[n.f];
        if (v === undefined || v === null) return false;
        const num = Number(n.v), a = typeof v === 'number' ? v : (n.f === '@timestamp' ? Date.parse(v) : v);
        const b = n.f === '@timestamp' ? Date.parse(n.v) : (Number.isNaN(num) ? n.v : num);
        return n.c === '<' ? a < b : n.c === '<=' ? a <= b : n.c === '>' ? a > b : a >= b;
      }
      case 'text': {
        const needle = n.v.replace(/\*/g, '').toLowerCase();
        return Object.keys(doc).some(k => k[0] !== '_' && String(doc[k]).toLowerCase().includes(needle));
      }
      default: return false;
    }
  }
  function walk(n, fn) {
    if (!n) return;
    fn(n);
    if (n.a) walk(n.a, fn);
    if (n.b) walk(n.b, fn);
    if (n.op === 'field') walk(n.v, m => m);
  }
  function fieldsUsed(ast) { const s = new Set(); walk(ast, n => { if (n.f) s.add(n.f); }); return [...s]; }
  /** Literal fragments the query looks for in one field, used to highlight matches. */
  function termsFor(ast, field) {
    const out = [];
    const vals = n => {
      if (!n) return;
      if (n.a) vals(n.a);
      if (n.b) vals(n.b);
      if (n.p) n.p.split('*').filter(x => x.length > 1).forEach(x => out.push(x));
    };
    walk(ast, n => { if (n.op === 'field' && n.f === field) vals(n.v); });
    return out;
  }

  root.KQL = { parse, evaluate, fieldsUsed, termsFor, KqlError };
  if (typeof module !== 'undefined') module.exports = root.KQL;
})(typeof window !== 'undefined' ? window : globalThis);
