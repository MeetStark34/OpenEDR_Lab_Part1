/* Virtual SOC Lab shell: state, routing, shared helpers, event detail panel. All data is synthetic. */
(function () {
  'use strict';
  const D = window.SOC_DATA;
  const EV = D.events.map(e => Object.assign({}, e, { _t: Date.parse(e['@timestamp']) })).sort((a, b) => a._t - b._t);
  const BY = Object.fromEntries(EV.map(e => [e._id, e]));
  const T0 = Date.UTC(2026, 10, 5, 9, 30), T1 = Date.UTC(2026, 10, 5, 12, 30);
  const DAY0 = Date.UTC(2026, 10, 5);

  // Browser storage can be unavailable; the lab must still work without it.
  const store = {
    get(k, d) { try { const v = localStorage.getItem('vsoc.' + k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem('vsoc.' + k, JSON.stringify(v)); } catch (e) { /* ignored */ } },
    clear() { try { Object.keys(localStorage).filter(k => k.startsWith('vsoc.')).forEach(k => localStorage.removeItem(k)); } catch (e) { /* ignored */ } },
  };

  const esc = s => String(s === undefined || s === null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const pad = (n, w = 2) => String(n).padStart(w, '0');
  const hms = t => { const d = new Date(t); return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`; };
  const hm = t => hms(t).slice(0, 5);
  const full = t => `Nov 5, 2026 @ ${hms(t)}.${pad(new Date(t).getUTCMilliseconds(), 3)}`;
  const parseT = s => {
    const m = /^(\d\d):(\d\d)(?::(\d\d))?$/.exec((s || '').trim());
    if (!m || +m[1] > 23 || +m[2] > 59 || +(m[3] || 0) > 59) return null;
    return DAY0 + ((+m[1] * 60 + +m[2]) * 60 + +(m[3] || 0)) * 1000;
  };

  const MITRE = {
    T1033: 'System Owner/User Discovery', T1087: 'Account Discovery', T1016: 'System Network Configuration Discovery',
    T1018: 'Remote System Discovery', T1082: 'System Information Discovery', T1057: 'Process Discovery', T1046: 'Network Service Discovery',
    T1595: 'Active Scanning', 'T1566.001': 'Spearphishing Attachment', 'T1204.002': 'Malicious File', 'T1059.001': 'PowerShell',
    'T1566.002': 'Spearphishing Link', 'T1204.001': 'Malicious Link', T1105: 'Ingress Tool Transfer', T1218: 'System Binary Proxy Execution',
    T1204: 'User Execution', 'T1204.004': 'Malicious Copy and Paste',
  };
  const WINDOWS = [['Full lab run', '09:30', '12:30'], ['R1 sweep', '10:13', '10:16'], ['R2 outbound', '10:30', '10:33'], ['R2 inbound', '10:37', '10:40'],
    ['S1 macro', '10:51', '10:54'], ['S2 cradle', '11:06', '11:09'], ['S2 LOLBin', '11:18', '11:21'], ['S3 pastes', '11:31', '11:40'], ['Admin session', '12:09', '12:15']];

  const NAV = [
    ['overview', 'SOC Overview', '<path d="M3 13h6V3H3zM11 21h10v-8H11zM3 21h6v-5H3zM11 10h10V3H11z"/>'],
    ['discover', 'Discover', '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>'],
    ['alerts', 'Alerts', '<path d="M12 3l9 16H3zM12 10v4M12 17v.5"/>'],
    ['rules', 'Detection Rules', '<path d="M4 6h16M4 12h16M4 18h10"/>'],
    ['tree', 'Process Trees', '<path d="M6 4v13a2 2 0 0 0 2 2h5M6 10h7"/><rect x="13" y="7.5" width="7" height="5" rx="1"/><rect x="13" y="16.5" width="7" height="5" rx="1"/>'],
    ['timeline', 'Event Timeline', '<path d="M3 12h18M7 8v8M13 6v12M18 9v6"/>'],
    ['scenarios', 'Scenarios', '<path d="M6 4l14 8-14 8z"/>'],
    ['fields', 'Field Reference', '<path d="M5 4h11l3 3v13H5zM9 10h6M9 14h6"/>'],
  ];

  const S = {
    route: 'overview', sub: null, params: {}, from: T0, to: T1, answers: store.get('answers', false), rules: [], alerts: [], alertState: store.get('alertState', {}),
    views: {},
  };

  const defaults = JSON.stringify(D.rules);
  function loadRules() {
    const edits = store.get('ruleEdits', {}), custom = store.get('customRules', []);
    S.rules = JSON.parse(defaults).map(r => Object.assign(r, edits[r.id] || {})).concat(custom);
  }
  function saveRules() {
    const base = Object.fromEntries(JSON.parse(defaults).map(r => [r.id, r])), edits = {};
    S.rules.filter(r => !r.custom).forEach(r => {
      const b = base[r.id], d = {};
      ['enabled', 'kql', 'threshold', 'severity'].forEach(k => { if (JSON.stringify(r[k]) !== JSON.stringify(b[k])) d[k] = r[k]; });
      if (Object.keys(d).length) edits[r.id] = d;
    });
    store.set('ruleEdits', edits);
    store.set('customRules', S.rules.filter(r => r.custom));
  }
  function recompute() { S.alerts = SOCEngine.evaluateAll(S.rules, EV); }
  const alertState = id => S.alertState[id] || { status: 'open', assignee: '', classification: '', notes: [] };
  function setAlertState(id, patch) { S.alertState[id] = Object.assign({}, alertState(id), patch); store.set('alertState', S.alertState); }
  const inRange = t => t >= S.from && t <= S.to;
  const rangedEvents = () => EV.filter(e => inRange(e._t));
  const rangedAlerts = () => S.alerts.filter(a => inRange(a.t));

  // ---- routing ----
  function hashFor(route, params) {
    const p = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => { if (v !== undefined && v !== null && v !== '') p.set(k, v); });
    if (S.from !== T0 || S.to !== T1) { if (!p.has('from')) p.set('from', hms(S.from)); if (!p.has('to')) p.set('to', hms(S.to)); }
    const q = p.toString();
    return '#/' + route + (q ? '?' + q : '');
  }
  function go(route, params) {
    const h = hashFor(route, params);
    if (location.hash === h) render(); else location.hash = h;
  }
  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, '');
    const i = raw.indexOf('?');
    const path = i < 0 ? raw : raw.slice(0, i), qs = i < 0 ? '' : raw.slice(i + 1);
    const parts = path.split('/');
    S.route = parts[0] || 'overview';
    S.sub = parts[1] ? decodeURIComponent(parts[1]) : null;
    S.params = Object.fromEntries(new URLSearchParams(qs));
    const a = parseT(S.params.from), b = parseT(S.params.to);
    S.from = a !== null ? a : T0;
    S.to = b !== null ? b : T1;
  }
  function setTime(a, b, keepHash) {
    S.from = Math.max(DAY0, Math.min(a, b));
    S.to = Math.max(a, b);
    if (keepHash) { render(); return; }
    const sub = S.sub ? '/' + encodeURIComponent(S.sub) : '';
    const params = Object.assign({}, S.params);
    delete params.from; delete params.to;
    go(S.route + sub, params);
  }

  // ---- rendering ----
  function renderNav() {
    const open = S.alerts.filter(a => alertState(a.id).status === 'open').length;
    const item = ([id, label, svg]) => `<button class="navi ${S.route === id ? 'on' : ''}" data-act="nav" data-to="${id}" ${S.route === id ? 'aria-current="page"' : ''} title="${esc(label)}">
      <svg viewBox="0 0 24 24" aria-hidden="true">${svg}</svg><span class="lbl">${esc(label)}</span>${id === 'alerts' && open ? `<span class="cnt">${open}</span>` : ''}</button>`;
    document.getElementById('nav').innerHTML = `<div class="brand"><b>Virtual SOC Lab</b><span>SIMULATED · OpenEDR Part 1</span></div>
      ${NAV.slice(0, 2).map(item).join('')}<div class="navsep">DETECT</div>${NAV.slice(2, 4).map(item).join('')}
      <div class="navsep">INVESTIGATE</div>${NAV.slice(4, 6).map(item).join('')}<div class="navsep">LEARN</div>${NAV.slice(6).map(item).join('')}`;
  }
  function renderTop() {
    const title = (NAV.find(n => n[0] === S.route) || [0, 'Virtual SOC Lab'])[1];
    const cur = WINDOWS.find(w => parseT(w[1]) === S.from && parseT(w[2]) === S.to);
    document.getElementById('topbar').innerHTML = `<h1>${esc(title)}</h1>
      <div class="tp"><label>Window <select data-chg="timePreset" aria-label="Time window">
        ${cur ? '' : '<option value="">Custom</option>'}${WINDOWS.map(w => `<option value="${w[1]}|${w[2]}" ${w === cur ? 'selected' : ''}>${esc(w[0])}</option>`).join('')}</select></label>
        <input type="text" class="tbox" id="t-from" value="${hms(S.from)}" maxlength="8" aria-label="From, 24-hour UTC, HH:MM:SS"> to <input type="text" class="tbox" id="t-to" value="${hms(S.to)}" maxlength="8" aria-label="To, 24-hour UTC, HH:MM:SS">
        <button class="btn" data-act="timeApply">Apply</button><span class="tiny">UTC, 5 Nov 2026</span></div>
      <button class="btn ${S.answers ? 'on' : ''}" data-act="answers" aria-pressed="${S.answers}" title="Show ground-truth labels and report event IDs">Lab answers: ${S.answers ? 'on' : 'off'}</button>
      <button class="btn warn" data-act="resetLab" title="Clear rule edits, triage and saved searches">Reset lab</button>`;
  }
  function render() {
    (S.views[S.leaving] || {}).leave && S.views[S.leaving].leave();
    S.leaving = S.route;
    const v = S.views[S.route] || S.views.overview;
    renderNav(); renderTop();
    const el = document.getElementById('view');
    el.innerHTML = v.render();
    if (v.after) v.after();
    document.title = `${(NAV.find(n => n[0] === S.route) || [0, 'Lab'])[1]} · Virtual SOC Lab (SIMULATED)`;
  }

  // ---- shared widgets ----
  function toast(html, ms = 4200) {
    const box = document.getElementById('toasts'), d = document.createElement('div');
    d.className = 'toast'; d.innerHTML = html; box.appendChild(d);
    setTimeout(() => d.remove(), ms);
  }
  function flyout(html) {
    const f = document.getElementById('flyout');
    f.innerHTML = html; f.hidden = false; f.scrollTop = 0;
  }
  function closeFlyout() { const f = document.getElementById('flyout'); f.hidden = true; f.innerHTML = ''; S.flyEvent = null; S.flyAlert = null; }

  function nested(e) {
    const out = {};
    Object.keys(e).forEach(k => {
      if (k[0] === '_') return;
      if (k === '@timestamp') { out[k] = e[k]; return; }
      const ps = k.split('.'); let c = out;
      ps.slice(0, -1).forEach(p => { c = c[p] = c[p] || {}; });
      c[ps[ps.length - 1]] = e[k];
    });
    return out;
  }
  const docId = e => (S.answers ? e._id : e._doc);
  const fieldsOf = e => Object.keys(e).filter(k => k[0] !== '_').sort();

  function docPanel(e, tab) {
    const rows = fieldsOf(e).map(k => `<tr><td>${esc(k)}</td><td class="ac2">
      <button class="ib" title="Filter for this value" aria-label="Filter for ${esc(k)}" data-act="dvFilter" data-f="${esc(k)}" data-v="${esc(e[k])}">+</button><button class="ib" title="Filter out this value" aria-label="Filter out ${esc(k)}" data-act="dvFilter" data-neg="1" data-f="${esc(k)}" data-v="${esc(e[k])}">−</button><button class="ib" title="Toggle column" aria-label="Toggle column ${esc(k)}" data-act="dvCol" data-f="${esc(k)}">▦</button>
      </td><td>${esc(e[k])}</td></tr>`).join('');
    const head = `<span class="simtag">${esc(D.label)}</span>`;
    const tabs = `<div class="tabs"><button class="tab ${tab !== 'json' ? 'on' : ''}" data-act="docTab" data-tab="table" data-id="${e._id}">Table</button><button class="tab ${tab === 'json' ? 'on' : ''}" data-act="docTab" data-tab="json" data-id="${e._id}">JSON</button></div>`;
    const body = tab === 'json' ? `<pre class="json">${esc(JSON.stringify(nested(e), null, 2))}</pre>` : `<table><tbody>${rows}</tbody></table>`;
    const pid = e['process.pid'];
    const acts = `<div class="row" style="margin-top:8px">
      ${pid ? `<button class="btn sm" data-act="toTree" data-pid="${pid}">Process tree</button>` : ''}
      <button class="btn sm" data-act="toTimeline" data-id="${e._id}">Show on timeline</button>
      <button class="btn sm" data-act="surround" data-id="${e._id}">Surrounding events (±60s)</button>
      ${pid ? `<button class="btn sm" data-act="pivotPid" data-pid="${pid}">Pivot on PID ${pid}</button>` : ''}
      <span class="tiny muted">_id ${esc(docId(e))}</span></div>`;
    return `<div class="doc" data-doc="${e._id}">${head}${tabs}${body}${acts}</div>`;
  }
  function showEvent(id, tab) {
    const e = BY[id]; if (!e) return;
    S.flyEvent = id; S.flyAlert = null;
    const name = e['process.name'] || e['event.category'];
    flyout(`<div class="fhead"><h2>${esc(e['event.action'])} · <span class="mono">${esc(name)}</span></h2><button class="btn sm" data-act="closeFly">Close</button></div>
      <p class="muted small" style="margin:0 0 8px">${esc(full(e._t))} UTC</p>${docPanel(e, tab)}`);
  }
  function refreshDoc(id, tab) {
    const el = document.querySelector(`[data-doc="${CSS.escape(id)}"]`);
    if (!el) return;
    if (S.dv) S.dv.tabs[id] = tab;
    const t = document.createElement('div'); t.innerHTML = docPanel(BY[id], tab);
    el.replaceWith(t.firstElementChild);
  }

  // ---- event delegation ----
  const act = {
    nav: el => { closeFlyout(); go(el.dataset.to); },
    closeFly: closeFlyout,
    timeApply() {
      const a = parseT(document.getElementById('t-from').value), b = parseT(document.getElementById('t-to').value);
      if (a === null || b === null) return toast('Enter times as 24-hour HH:MM:SS, for example 10:14:00.');
      if (a >= b) return toast('The start time must be before the end time.');
      setTime(a, b);
    },
    answers() { S.answers = !S.answers; store.set('answers', S.answers); render(); if (S.flyEvent) showEvent(S.flyEvent); else if (S.flyAlert) act.showAlertById(S.flyAlert); },
    resetLab(el) {
      if (el.dataset.armed !== '1') { el.dataset.armed = '1'; el.textContent = 'Click again to reset'; setTimeout(() => { if (el.isConnected) { el.dataset.armed = ''; el.textContent = 'Reset lab'; } }, 3000); return; }
      store.clear(); S.alertState = {}; S.answers = false; loadRules(); recompute();
      if (S.views.discover.reset) S.views.discover.reset();
      closeFlyout(); toast('Lab reset. Rules, triage and saved searches are back to defaults.'); location.hash = '#/overview'; render();
    },
    docTab: el => refreshDoc(el.dataset.id, el.dataset.tab),
    toTree: el => { closeFlyout(); go('tree', { pid: el.dataset.pid }); },
    toTimeline: el => { closeFlyout(); const e = BY[el.dataset.id]; S.from = e._t - 90000; S.to = e._t + 90000; go('timeline', { sel: e._id }); },
    surround: el => { closeFlyout(); const e = BY[el.dataset.id]; S.from = e._t - 60000; S.to = e._t + 60000; S.views.discover.open(''); },
    pivotPid: el => { closeFlyout(); S.from = T0; S.to = T1; S.views.discover.open(`process.pid : ${el.dataset.pid}`); },
    openEvent: el => showEvent(el.dataset.id),
  };
  document.addEventListener('click', e => {
    const el = e.target.closest('[data-act]');
    if (el && act[el.dataset.act]) act[el.dataset.act](el, e);
  });
  const chg = { timePreset(el) { if (!el.value) return; const [a, b] = el.value.split('|'); setTime(parseT(a), parseT(b)); } };
  document.addEventListener('change', e => { const el = e.target.closest('[data-chg]'); if (el && chg[el.dataset.chg]) chg[el.dataset.chg](el, e); });
  const inp = {};
  document.addEventListener('input', e => { const el = e.target.closest('[data-inp]'); if (el && inp[el.dataset.inp]) inp[el.dataset.inp](el, e); });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && !document.getElementById('flyout').hidden) closeFlyout();
    if (e.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && S.route === 'discover') { e.preventDefault(); const q = document.getElementById('kql'); if (q) q.focus(); }
  });
  const tip = document.getElementById('tip');
  document.addEventListener('mousemove', e => {
    const el = e.target.closest && e.target.closest('[data-tip]');
    if (!el) { tip.hidden = true; return; }
    tip.textContent = el.getAttribute('data-tip'); tip.hidden = false;
    const r = tip.getBoundingClientRect();
    tip.style.left = Math.min(e.clientX + 12, innerWidth - r.width - 6) + 'px';
    tip.style.top = Math.min(e.clientY + 14, innerHeight - r.height - 6) + 'px';
  });

  function download(name, text, type) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type }));
    a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }

  // ---- field reference page ----
  S.views.fields = {
    render() {
      const rows = D.fields.map(f => `<tr><td>${esc(f.role)}</td><td class="mono">${esc(f.field)}</td><td class="mono">${esc(f.source)}</td><td><span class="pill">${esc(f.tag)}</span></td><td>${esc(f.note)}</td></tr>`).join('');
      return `<div class="grid"><div class="note warn">OpenEDR does not publish a JSON schema. Most field names here are assumed ECS-style names, so check them against one real event before relying on any query.</div>
      <div class="card"><h2>Field provenance</h2><table class="t"><thead><tr><th>Role</th><th>Query field</th><th>Assumed raw source</th><th>Tag</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>
      <p class="small muted"><b>D</b> documented · <b>L</b> name seen in a real log listing · <b>S</b> found in OpenEDR source, not confirmed as JSON output · <b>A</b> assumed for this simulation</p></div>
      <div class="card"><h2>How matching works in this lab</h2><ul class="small" style="margin:0;padding-left:18px">
        <li>Field queries behave like <code>keyword</code> and <code>wildcard</code> fields: case-sensitive and matched against the whole value.</li>
        <li>Supported KQL: <code>field : value</code>, <code>field : "exact"</code>, <code>*</code> wildcards, <code>and</code>, <code>or</code>, <code>not</code>, parentheses, value lists, <code>field : *</code>, <code>&lt; &lt;= &gt; &gt;=</code> and CIDR on <code>.ip</code> fields.</li>
        <li>Free text with no field is a lab convenience: case-insensitive, across all fields. Real Kibana behaviour depends on the mappings.</li>
        <li>KQL filters one document at a time. Distinct counts, windows and sequences come from the rule engine, as they would from a real alert rule.</li>
        <li>This engine is a teaching model, so a query that works here still has to be tested in a real Kibana.</li></ul></div></div>`;
    },
  };

  window.App = {
    D, EV, BY, T0, T1, DAY0, S, MITRE, WINDOWS, store, esc, hms, hm, full, parseT, go, render, setTime, toast, flyout, closeFlyout, showEvent, docPanel, docId, fieldsOf,
    nested, act, chg, inp, download, recompute, saveRules, alertState, setAlertState, inRange, rangedEvents, rangedAlerts, hashFor,
    start() {
      loadRules(); recompute();
      window.addEventListener('hashchange', () => { parseHash(); render(); });
      parseHash(); render();
    },
  };
})();
