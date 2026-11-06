/* Interactive process trees built from process-create, network and file events. */
(function () {
  'use strict';
  const { S, EV, BY, esc, hms, full, go, act, inp, chg, render, showEvent, docId } = App;

  // Nodes are keyed by PID. PIDs are unique in this dataset; real telemetry reuses them.
  function build() {
    const nodes = new Map();
    const node = (pid, name, exe) => {
      if (!nodes.has(pid)) nodes.set(pid, { pid, name, exe, parent: null, kids: [], ev: null, net: [], file: [], inferred: true });
      return nodes.get(pid);
    };
    EV.forEach(e => {
      if (e['event.category'] === 'process') {
        const n = node(e['process.pid'], e['process.name'], e['process.executable']);
        Object.assign(n, { ev: e, inferred: false, name: e['process.name'] });
        const p = node(e['process.parent.pid'], e['process.parent.name'], e['process.parent.executable']);
        n.parent = p.pid;
      } else if (e['process.pid'] !== undefined) {
        const n = node(e['process.pid'], e['process.name'], e['process.executable']);
        (e['event.category'] === 'network' ? n.net : n.file).push(e);
      }
    });
    nodes.forEach(n => { if (n.parent !== null) nodes.get(n.parent).kids.push(n.pid); });
    nodes.forEach(n => n.kids.sort((a, b) => nodes.get(a).ev._t - nodes.get(b).ev._t));
    return nodes;
  }
  const N = build();
  const roots = () => [...N.values()].filter(n => n.parent === null).sort((a, b) => count(b) - count(a));
  const count = n => 1 + n.kids.reduce((s, k) => s + count(N.get(k)), 0);
  const eventsOf = n => (n.ev ? [n.ev] : []).concat(n.net, n.file);
  const alertsOf = n => {
    const ids = new Set(eventsOf(n).map(e => e._id));
    return S.alerts.filter(a => a.eventIds.some(i => ids.has(i)));
  };
  const hasAlert = n => alertsOf(n).length > 0 || n.kids.some(k => hasAlert(N.get(k)));
  const rootOf = pid => { let n = N.get(pid); while (n && n.parent !== null) n = N.get(n.parent); return n; };

  S.tr = { open: new Set(), sel: null, root: null, search: '', onlyAlerts: false, groups: new Set() };
  function focus(pid) {
    const t = S.tr; let n = N.get(pid);
    if (!n) return;
    t.sel = pid; t.root = rootOf(pid).pid;
    for (n = N.get(n.parent); n; n = n.parent === null ? null : N.get(n.parent)) t.open.add(n.pid);
  }

  function matches(n, q) { return !!q && `${n.name} ${n.pid} ${n.ev ? n.ev['process.command_line'] : ''}`.toLowerCase().includes(q); }
  const subtreeHit = (n, q) => matches(n, q) || n.kids.some(k => subtreeHit(N.get(k), q));

  function li(n, q) {
    const t = S.tr;
    if (t.onlyAlerts && !hasAlert(n)) return '';
    const al = alertsOf(n), kids = n.kids.map(k => N.get(k));
    const forced = q && kids.some(k => subtreeHit(k, q));
    const hasKids = kids.length || n.net.length || n.file.length;
    const open = t.open.has(n.pid) || forced;
    const cmd = n.ev ? n.ev['process.command_line'] : '';
    const cls = ['tn', t.sel === n.pid ? 'sel' : '', al.length ? 'alert' : '', matches(n, q) ? 'hitq' : '', q && !subtreeHit(n, q) ? 'dim' : ''].join(' ');
    const grp = (list, label) => {
      if (!list.length) return '';
      const key = `${n.pid}:${label}`, on = t.groups.has(key);
      const rows = on ? `<ul>${list.map(e => `<li><button class="tn" data-act="openEvent" data-id="${esc(e._id)}"><span class="pd">${hms(e._t)}</span><span class="cm">${esc(e['file.path'] || `${e['source.ip']}:${e['source.port']} → ${e['destination.ip']}:${e['destination.port']}`)}</span></button></li>`).join('')}</ul>` : '';
      return `<li><div class="tn"><button class="tw" data-act="trGroup" data-k="${esc(key)}" aria-label="Toggle ${esc(label)}" aria-expanded="${on}">${on ? '−' : '+'}</button><span class="muted small">${list.length} ${esc(label)}</span></div>${rows}</li>`;
    };
    return `<li><div class="${cls}" data-act="trSel" data-pid="${n.pid}" role="button" tabindex="0" aria-pressed="${t.sel === n.pid}">
        <button class="tw ${hasKids ? '' : 'none'}" data-act="trToggle" data-pid="${n.pid}" aria-label="Expand ${esc(n.name)}" aria-expanded="${!!open}">${open ? '−' : '+'}</button>
        <span class="nm">${esc(n.name)}</span><span class="pd">PID ${n.pid}</span>${n.inferred ? '<span class="bdg inf" title="No process-create event; known only from other events">inferred</span>' : ''}${al.length ? `<span class="bdg">${al.length} ${al.length === 1 ? 'alert' : 'alerts'}</span>` : ''}<span class="cm" title="${esc(cmd)}">${esc(cmd)}</span></div>
      ${open && hasKids ? `<ul>${kids.map(k => li(k, q)).join('')}${grp(n.net, n.net.length === 1 ? 'network connection' : 'network connections')}${grp(n.file, n.file.length === 1 ? 'file event' : 'file events')}</ul>` : ''}</li>`;
  }

  function detail(n) {
    if (!n) return '<div class="card"><h2>Process details</h2><div class="empty">Select a process.</div></div>';
    const al = alertsOf(n);
    const anc = [];
    for (let p = n; p; p = p.parent === null ? null : N.get(p.parent)) anc.unshift(p);
    return `<div class="card" id="tree-detail"><h2 class="mono">${esc(n.name)}</h2><span class="simtag">${esc(App.D.label)}</span>
      <dl class="kv small"><dt>PID</dt><dd>${n.pid}</dd><dt>Path</dt><dd class="mono">${esc(n.exe || '–')}</dd>
      ${n.ev ? `<dt>Started</dt><dd>${esc(full(n.ev._t))}</dd><dt>User</dt><dd>${esc(n.ev['user.domain'])}\\${esc(n.ev['user.name'])}</dd><dt>Command</dt><dd class="mono">${esc(n.ev['process.command_line'])}</dd>` : '<dt>Status</dt><dd>Inferred from other events. No process-create record exists in this dataset.</dd>'}
      <dt>Lineage</dt><dd class="mono">${anc.map(a => esc(a.name)).join(' → ')}</dd><dt>Activity</dt><dd>${n.kids.length} child, ${n.net.length} network, ${n.file.length} file</dd></dl>
      ${al.length ? `<div class="sec"><h3>Alerts</h3>${al.map(a => `<div><button class="link small" data-act="showAlert" data-id="${esc(a.id)}">${esc(a.ruleName)}</button> <span class="sev ${a.severity} small">${esc(a.severity)}</span></div>`).join('')}</div>` : ''}
      <div class="sec row">${n.ev ? `<button class="btn sm" data-act="openEvent" data-id="${esc(n.ev._id)}">Open event</button>` : ''}<button class="btn sm" data-act="pivotPid" data-pid="${n.pid}">Pivot in Discover</button>${eventsOf(n)[0] ? `<button class="btn sm" data-act="toTimeline" data-id="${esc(eventsOf(n)[0]._id)}">Timeline</button>` : ''}</div></div>`;
  }

  S.views.tree = {
    render() {
      const t = S.tr;
      if (S.params.pid && +S.params.pid !== t.lastPid) { t.lastPid = +S.params.pid; focus(+S.params.pid); }
      if (t.root === null) { t.root = roots()[0].pid; t.open.add(t.root); }
      const root = N.get(t.root), q = t.search.toLowerCase();
      const quick = [['S1 macro', 7588], ['S2 cradle', 5512], ['R1 sweep', 6120], ['S3 paste', 6044], ['Admin session', 8102], ['Updater', 5902]];
      return `<div class="grid"><div class="card"><div class="row"><label class="small muted">Root process <select data-chg="trRoot" aria-label="Root process">${roots().map(r => `<option value="${r.pid}" ${r.pid === t.root ? 'selected' : ''}>${esc(r.name)} (PID ${r.pid}), ${count(r)} processes</option>`).join('')}</select></label>
        <input type="search" data-inp="trSearch" value="${esc(t.search)}" placeholder="Find name, PID or command" aria-label="Find process">
        <button class="btn sm" data-act="trAll" data-v="1">Expand all</button><button class="btn sm" data-act="trAll" data-v="0">Collapse all</button>
        <button class="btn sm ${t.onlyAlerts ? 'on' : ''}" data-act="trOnly" aria-pressed="${t.onlyAlerts}">Only alert paths</button><span class="sp"></span>
        <span class="small muted">Jump to</span>${quick.map(([l, p]) => `<button class="btn sm" data-act="trJump" data-pid="${p}">${esc(l)}</button>`).join('')}</div></div>
      <div class="grid tv"><div class="card" style="overflow:auto"><ul class="tree" id="tree-root">${li(root, q) || '<li class="empty">No alert paths under this root.</li>'}</ul></div>${detail(N.get(t.sel) || null)}</div></div>`;
    },
  };
  function descend(n, fn) { fn(n); n.kids.forEach(k => descend(N.get(k), fn)); }
  chg.trRoot = el => { S.tr.root = +el.value; S.tr.open.add(S.tr.root); S.tr.sel = S.tr.root; render(); };
  inp.trSearch = el => {
    S.tr.search = el.value;
    const pos = el.selectionStart; render();
    const n = document.querySelector('[data-inp="trSearch"]'); n.focus(); n.setSelectionRange(pos, pos);
  };
  Object.assign(act, {
    trSel(el, e) { if (e.target.closest('.tw')) return; S.tr.sel = +el.dataset.pid; render(); },
    trToggle(el, e) { e.stopPropagation(); const p = +el.dataset.pid, o = S.tr.open; if (o.has(p)) o.delete(p); else o.add(p); render(); },
    trGroup(el, e) { e.stopPropagation(); const g = S.tr.groups, k = el.dataset.k; if (g.has(k)) g.delete(k); else g.add(k); render(); },
    trAll(el) { descend(N.get(S.tr.root), n => { if (el.dataset.v === '1') S.tr.open.add(n.pid); else S.tr.open.delete(n.pid); }); render(); },
    trOnly() { S.tr.onlyAlerts = !S.tr.onlyAlerts; render(); },
    trJump(el) { S.tr.lastPid = null; go('tree', { pid: el.dataset.pid }); },
  });
  document.addEventListener('keydown', e => {
    const el = e.target.closest && e.target.closest('.tn[data-act="trSel"]');
    if (el && (e.key === 'Enter' || e.key === ' ') && e.target === el) { e.preventDefault(); S.tr.sel = +el.dataset.pid; render(); }
  });
  App.treeNodes = N;
})();
