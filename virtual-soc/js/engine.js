/* Simulated detection engine: query, threshold and sequence rules over the synthetic events.
   Threshold rules use a true sliding window. Real Kibana rules run on a schedule, so a burst
   that straddles a run boundary can behave differently. */
(function (root) {
  'use strict';
  const KQL = root.KQL || (typeof require !== 'undefined' ? require('./kql.js') : null);

  const severityRank = { high: 3, medium: 2, low: 1 };
  const groupKey = (e, fields) => fields.map(f => e[f]).join(' / ');
  const truthOf = evs => (evs.some(e => e._role === 'false-positive') ? 'false-positive' : 'true-positive');

  function mkAlert(rule, evs, t, entity, reason, extra) {
    return Object.assign({
      id: `${rule.id}|${entity}|${evs[0]._id}`, ruleId: rule.id, ruleName: rule.name, severity: rule.severity,
      t, entity, reason, eventIds: evs.map(e => e._id), mitre: rule.mitre || [], truth: truthOf(evs),
    }, extra || {});
  }

  function runQuery(rule, events) {
    const ast = KQL.parse(rule.kql);
    return events.filter(e => KQL.evaluate(ast, e)).map(e => {
      const parent = e['process.parent.name'] ? `${e['process.parent.name']} → ` : '';
      return mkAlert(rule, [e], e._t, `${e['user.name']} on ${e['host.name']}`, `${parent}${e['process.name']} matched the rule query`);
    });
  }

  /** Groups with the largest distinct count seen in any sliding window, for previews. */
  function thresholdGroups(rule, events) {
    const th = rule.threshold;
    const ast = KQL.parse(rule.kql);
    const groups = new Map();
    events.filter(e => KQL.evaluate(ast, e)).forEach(e => {
      const k = groupKey(e, th.groupBy);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(e);
    });
    const win = th.windowSec * 1000;
    return [...groups.entries()].map(([key, rows]) => {
      rows.sort((a, b) => a._t - b._t);
      let best = 0;
      rows.forEach((a, i) => {
        const s = new Set();
        for (let j = i; j < rows.length && rows[j]._t - a._t <= win; j++) s.add(rows[j][th.countField]);
        best = Math.max(best, s.size);
      });
      return { key, rows, distinct: best, fires: best >= th.value };
    }).sort((a, b) => b.distinct - a.distinct);
  }

  function runThreshold(rule, events) {
    const th = rule.threshold, win = th.windowSec * 1000, alerts = [];
    thresholdGroups(rule, events).forEach(g => {
      const rows = g.rows;
      let i = 0;
      while (i < rows.length) {
        const seen = new Set();
        let cross = -1;
        for (let j = i; j < rows.length && rows[j]._t - rows[i]._t <= win; j++) {
          seen.add(rows[j][th.countField]);
          if (seen.size >= th.value) { cross = j; break; }
        }
        if (cross < 0) { i++; continue; }
        let end = cross;   // keep the rest of the burst inside the same alert
        while (end + 1 < rows.length && rows[end + 1]._t - rows[end]._t <= win) end++;
        const evs = rows.slice(i, end + 1);
        const distinct = new Set(evs.map(e => e[th.countField])).size;
        alerts.push(mkAlert(rule, evs, rows[cross]._t, g.key,
          `${distinct} distinct ${th.countField} in ${th.windowSec}s (threshold ${th.value})`,
          { distinct, crossedBy: rows[cross]._id }));
        i = end + 1;
      }
    });
    return alerts;
  }

  function runSequence(rule, events) {
    const sq = rule.sequence, span = sq.maxspanSec * 1000;
    const asts = sq.steps.map(s => KQL.parse(s));
    const alerts = [];
    events.filter(e => KQL.evaluate(asts[0], e)).forEach(first => {
      const chain = [first];
      let last = first;
      for (let s = 1; s < asts.length; s++) {
        const next = events.find(e => e._t >= last._t && e._t - first._t <= span && e !== last
          && sq.by.every(f => e[f] === first[f]) && KQL.evaluate(asts[s], e));
        if (!next) return;
        chain.push(next);
        last = next;
      }
      alerts.push(mkAlert(rule, chain, last._t, groupKey(first, sq.by), `${chain.length}-step sequence completed in ${((last._t - first._t) / 1000).toFixed(2)}s`));
    });
    return alerts;
  }

  function runRule(rule, events) {
    if (rule.type === 'threshold') return runThreshold(rule, events);
    if (rule.type === 'sequence') return runSequence(rule, events);
    return runQuery(rule, events);
  }

  function evaluateAll(rules, events) {
    const out = [];
    rules.filter(r => r.enabled).forEach(r => {
      try { out.push(...runRule(r, events)); } catch (e) { /* invalid custom rule: surfaced on the rule page */ }
    });
    return out.sort((a, b) => a.t - b.t);
  }

  const api = { runRule, evaluateAll, thresholdGroups, severityRank };
  root.SOCEngine = api;
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
