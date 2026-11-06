/* Detection rule list, detail, edit and live preview. */
(function () {
  'use strict';
  const { S, D, EV, esc, go, act, chg, inp, toast, render, recompute, saveRules, MITRE } = App;
  const typeLabel = { query: 'Query', threshold: 'Threshold', sequence: 'Sequence' };
  const rule = id => S.rules.find(r => r.id === id);
  const original = id => JSON.parse(JSON.stringify(D.rules.find(r => r.id === id) || null));
  const firing = id => S.alerts.filter(a => a.ruleId === id).length;

  function listView() {
    const rows = S.rules.map(r => `<tr><td><button class="switch ${r.enabled ? 'on' : ''}" role="switch" aria-checked="${r.enabled}" aria-label="Enable ${esc(r.name)}" data-act="ruleToggle" data-id="${esc(r.id)}"><i></i></button></td>
      <td><button class="link" data-act="ruleOpen" data-id="${esc(r.id)}">${esc(r.name)}</button></td><td>${esc(typeLabel[r.type])}</td><td class="sev ${r.severity}">${esc(r.severity)}</td><td class="small">${esc(r.fidelity || 'Custom')}</td>
      <td class="small">${(r.mitre || []).map(esc).join(', ') || '–'}</td><td class="num" data-rule-alerts="${esc(r.id)}">${r.enabled ? firing(r.id) : '–'}</td></tr>`).join('');
    return `<div class="grid"><div class="note">The KQL in each rule only selects candidate events. Threshold and sequence rules add counting, time windows and ordering on top, which KQL cannot do alone. This engine evaluates all ${EV.length} synthetic events each time a rule changes.</div>
      <div class="card"><div class="row" style="margin-bottom:8px"><h2>Detection rules</h2><span class="sp"></span><span class="small muted"><span id="rules-enabled">${S.rules.filter(r => r.enabled).length}</span> of ${S.rules.length} enabled, <span id="rules-alerts">${S.alerts.length}</span> alerts</span><button class="btn pri sm" data-act="ruleNew">New KQL rule</button></div>
      <div style="overflow:auto"><table class="t"><thead><tr><th>On</th><th>Name</th><th>Type</th><th>Severity</th><th>Fidelity</th><th>ATT&amp;CK</th><th class="num">Alerts</th></tr></thead><tbody>${rows}</tbody></table></div></div></div>`;
  }

  function preview(r) {
    let html;
    try {
      const ast = KQL.parse(r.kql);
      const n = EV.filter(e => KQL.evaluate(ast, e)).length;
      if (r.type === 'threshold') {
        const g = SOCEngine.thresholdGroups(r, EV), v = r.threshold.value;
        const mx = Math.max(v * 1.25, ...g.map(x => x.distinct), 1);
        html = `<p class="small" style="margin:0 0 6px"><b id="rule-candidates">${n}</b> candidate events, grouped by <code>${r.threshold.groupBy.map(esc).join(' + ')}</code></p>${g.map(x => `<div class="small mono" style="margin-top:7px">${esc(x.key)}<span class="sp"></span> <b>${x.distinct}</b> ${x.fires ? '<span class="vm">fires</span>' : '<span class="muted">below threshold</span>'}</div><div class="tg"><i style="width:${100 * x.distinct / mx}%"></i><u style="left:${100 * v / mx}%"></u></div>`).join('') || '<div class="empty">No groups.</div>'}<p class="tiny muted" style="margin:8px 0 0">Bars show the most distinct <code>${esc(r.threshold.countField)}</code> values in any ${r.threshold.windowSec}s window. The dashed line is the threshold of ${v}.</p>`;
      } else {
        const a = SOCEngine.runRule(r, EV);
        html = `<p class="small" style="margin:0"><b id="rule-candidates">${n}</b> candidate events, <b>${a.length}</b> ${a.length === 1 ? 'alert' : 'alerts'} if enabled.</p>${a.slice(0, 8).map(x => `<div class="small mono" style="margin-top:4px">${App.hms(x.t)} ${esc(x.entity)}</div>`).join('')}`;
      }
    } catch (e) { html = `<p class="qerr" id="rule-err">KQL syntax error at position ${e.pos}: ${esc(e.message)}</p>`; }
    return html;
  }

  function detailView(r) {
    const th = r.threshold;
    const orig = original(r.id);
    const changed = orig && ['kql', 'threshold', 'severity'].some(k => JSON.stringify(r[k]) !== JSON.stringify(orig[k]));
    return `<div class="row" style="margin-bottom:10px"><button class="btn sm" data-act="ruleBack">All rules</button><h2 style="font-size:16px">${esc(r.name)}</h2><span class="pill">${esc(typeLabel[r.type])}</span>${changed ? '<span class="pill" style="color:var(--amber)">edited</span>' : ''}<span class="sp"></span>
      Enabled <button class="switch ${r.enabled ? 'on' : ''}" role="switch" aria-checked="${r.enabled}" aria-label="Enable rule" data-act="ruleToggle" data-id="${esc(r.id)}"><i></i></button></div>
    <div class="grid rd"><div class="card form"><h2>Definition</h2><p class="small muted" style="margin:0 0 8px">${esc(r.description || 'Custom KQL rule.')}</p>
      <label>${r.type === 'sequence' ? 'First step (KQL, read-only for sequences)' : 'KQL query'}<textarea id="rule-kql" spellcheck="false" data-inp="ruleKql" ${r.type === 'sequence' ? 'readonly' : ''}>${esc(r.kql)}</textarea></label>
      ${th ? `<div class="row" style="align-items:flex-end"><label style="flex:1">Group by<input type="text" readonly value="${esc(th.groupBy.join(', '))}"></label><label style="flex:1">Count unique<input type="text" readonly value="${esc(th.countField)}"></label>
        <label style="width:96px">Threshold<input type="number" id="rule-th" min="1" max="100" value="${th.value}" data-inp="ruleTh"></label><label style="width:110px">Window (s)<input type="number" id="rule-win" min="1" max="3600" value="${th.windowSec}" data-inp="ruleWin"></label></div>` : ''}
      ${r.sequence ? `<ol class="small mono" style="padding-left:18px;margin:0 0 8px">${r.sequence.steps.map(s => `<li style="margin-bottom:4px">${esc(s.replace(/\s+/g, ' '))}</li>`).join('')}</ol><p class="small muted">Joined on <code>${r.sequence.by.map(esc).join(', ')}</code>, maximum span ${r.sequence.maxspanSec}s.</p>` : ''}
      <label style="max-width:180px">Severity<select data-chg="ruleSev" data-id="${esc(r.id)}">${['high', 'medium', 'low'].map(s => `<option ${s === r.severity ? 'selected' : ''}>${s}</option>`).join('')}</select></label>
      <div class="row"><button class="btn pri" data-act="ruleSave" data-id="${esc(r.id)}">Save rule</button>${orig ? `<button class="btn" data-act="ruleRevert" data-id="${esc(r.id)}">Revert to default</button>` : `<button class="btn" data-act="ruleDel" data-id="${esc(r.id)}">Delete rule</button>`}<button class="btn" data-act="ruleDiscover" data-id="${esc(r.id)}">Run in Discover</button><button class="btn" data-act="ovRule" data-id="${esc(r.id)}">View alerts</button></div></div>
    <div class="grid"><div class="card"><h2>Live preview</h2><div id="rule-preview">${preview(r)}</div></div>
      <div class="card"><h2>Context</h2><dl class="kv"><dt>Fidelity</dt><dd>${esc(r.fidelity || 'Not rated')}</dd><dt>ATT&amp;CK</dt><dd>${(r.mitre || []).map(m => `<span class="pill" title="${esc(MITRE[m] || '')}">${esc(m)}</span>`).join(' ') || '–'}</dd><dt>False positives</dt><dd class="small">${esc(r.falsePositives || '–')}</dd>
      ${r.type === 'threshold' ? '<dt>Engine note</dt><dd class="small">This lab uses a true sliding window. A scheduled rule in real Kibana looks back over fixed runs, so a burst across a boundary can be split.</dd>' : ''}</dl></div></div></div>`;
  }

  function draft() {
    const r = rule(S.sub);
    const d = JSON.parse(JSON.stringify(r));
    const k = document.getElementById('rule-kql'), t = document.getElementById('rule-th'), w = document.getElementById('rule-win');
    if (k) d.kql = k.value;
    if (t && d.threshold) d.threshold.value = Math.max(1, +t.value || 1);
    if (w && d.threshold) d.threshold.windowSec = Math.max(1, +w.value || 1);
    return d;
  }
  const livePreview = () => { document.getElementById('rule-preview').innerHTML = preview(draft()); };
  inp.ruleKql = livePreview; inp.ruleTh = livePreview; inp.ruleWin = livePreview;
  const commit = () => { saveRules(); recompute(); };

  S.views.rules = {
    render() {
      if (S.sub === 'new') return `<div class="row" style="margin-bottom:10px"><button class="btn sm" data-act="ruleBack">All rules</button><h2 style="font-size:16px">New KQL rule</h2></div><div class="card form" style="max-width:720px"><label>Name<input type="text" id="new-name" maxlength="70"></label><label>KQL query<textarea id="new-kql" spellcheck="false" placeholder='event.category : "process" and process.name : "mshta.exe"'></textarea></label><label style="max-width:180px">Severity<select id="new-sev"><option>high</option><option selected>medium</option><option>low</option></select></label><div id="new-err" class="qerr"></div><button class="btn pri" data-act="ruleCreate">Create and enable</button></div>`;
      const r = S.sub && rule(S.sub);
      return r ? detailView(r) : listView();
    },
  };
  chg.ruleSev = el => { const r = rule(el.dataset.id); r.severity = el.value; commit(); toast(`Severity set to ${esc(el.value)}.`); render(); };
  Object.assign(act, {
    ruleOpen: el => go('rules/' + encodeURIComponent(el.dataset.id)),
    ruleBack: () => go('rules'),
    ruleNew: () => go('rules/new'),
    ruleToggle(el) { const r = rule(el.dataset.id); r.enabled = !r.enabled; commit(); toast(`${esc(r.name)} ${r.enabled ? 'enabled' : 'disabled'}. ${S.alerts.length} alerts now.`); render(); },
    ruleSave(el) {
      const r = rule(el.dataset.id), d = draft();
      try { KQL.parse(d.kql); } catch (e) { return toast(`Not saved. KQL error: ${esc(e.message)}`); }
      r.kql = d.kql; if (d.threshold) r.threshold = d.threshold;
      commit(); toast(`Saved. ${S.alerts.filter(a => a.ruleId === r.id).length} alerts from this rule.`); render();
    },
    ruleRevert(el) { const r = rule(el.dataset.id), o = original(r.id); const on = r.enabled; Object.assign(r, o); r.enabled = on; commit(); toast('Rule restored to its default definition.'); render(); },
    ruleDel(el) { S.rules = S.rules.filter(r => r.id !== el.dataset.id); commit(); go('rules'); },
    ruleDiscover(el) { const r = rule(el.dataset.id); S.views.discover.open(r.kql.replace(/\s+/g, ' ')); },
    ruleCreate() {
      const name = document.getElementById('new-name').value.trim(), kql = document.getElementById('new-kql').value.trim(), err = document.getElementById('new-err');
      if (!name || !kql) { err.textContent = 'Enter a name and a query.'; return; }
      try { if (!KQL.parse(kql)) throw new Error('Empty'); } catch (e) { err.textContent = `KQL error: ${e.message}`; return; }
      const id = 'CUSTOM-' + Date.now().toString(36);
      S.rules.push({ id, name, type: 'query', severity: document.getElementById('new-sev').value, enabled: true, kql, custom: true, mitre: [], description: 'Custom KQL rule.' });
      commit(); toast(`Rule created. ${S.alerts.filter(a => a.ruleId === id).length} alerts.`); go('rules/' + encodeURIComponent(id));
    },
  });
})();
