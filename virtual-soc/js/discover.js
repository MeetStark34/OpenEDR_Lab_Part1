/* Discover: live KQL over the synthetic events. */
(function () {
  'use strict';
  const { S, D, EV, BY, esc, hms, full, go, act, chg, inp, store, toast, setTime, docPanel, flyout, closeFlyout, download, nested } = App;
  const DEFAULT_COLS = ['user.name', 'process.parent.name', 'process.name', 'process.command_line'];
  const PAGE = 25;
  const FIELDS = [...new Set(EV.flatMap(e => Object.keys(e).filter(k => k[0] !== '_')))].sort();

  function fresh() {
    return { q: '', filters: [], cols: store.get('cols', DEFAULT_COLS.slice()), sort: ['@timestamp', 'asc'], page: 0, open: new Set(), tabs: {}, fopen: null, err: null, ac: [], acI: 0 };
  }
  S.dv = fresh();
  const saved = () => store.get('saved', []);
  const presets = () => [
    { name: 'All process events', q: 'event.category : "process"' },
    { name: 'All network events', q: 'event.category : "network"' },
    { name: 'All file events', q: 'event.category : "file"' },
    { name: 'Checkpoint 2: Notepad test', q: 'process.name : "notepad.exe"' },
    { name: 'S2 pivot: PID 5512', q: 'host.name : "WIN11-LAB01" and process.pid : 5512' },
  ].concat(S.rules.filter(r => !r.custom).map(r => ({ name: 'Rule: ' + r.name, q: r.kql.replace(/\s+/g, ' ') })));

  function compute() {
    const d = S.dv;
    let ast = null;
    d.err = null;
    try { ast = KQL.parse(d.q); } catch (e) { d.err = { msg: e.message, pos: e.pos }; }
    let rows = App.rangedEvents();
    if (!d.err && ast) rows = rows.filter(e => KQL.evaluate(ast, e));
    if (d.err) rows = [];
    d.filters.filter(f => !f.off).forEach(f => { rows = rows.filter(e => (String(e[f.f]) === f.v) !== !!f.neg); });
    const [c, dir] = d.sort, m = dir === 'asc' ? 1 : -1;
    rows = rows.slice().sort((a, b) => {
      const x = c === '@timestamp' ? a._t : a[c], y = c === '@timestamp' ? b._t : b[c];
      if (x === undefined && y === undefined) return a._t - b._t;
      if (x === undefined) return 1;
      if (y === undefined) return -1;
      return (x < y ? -1 : x > y ? 1 : a._t - b._t) * m;
    });
    return { rows, ast };
  }

  function histogram(rows) {
    const span = S.to - S.from;
    const step = [1, 2, 5, 10, 30, 60, 120, 300, 600, 900].map(s => s * 1000).find(s => span / s <= 60) || 1800000;
    const n = Math.max(1, Math.ceil(span / step)), c = new Array(n).fill(0);
    rows.forEach(e => { c[Math.min(n - 1, Math.floor((e._t - S.from) / step))]++; });
    const mx = Math.max(1, ...c), w = 1000 / n;
    const bars = c.map((v, i) => {
      const h = v ? Math.max(4, 72 * v / mx) : 0, t = S.from + i * step;
      return `<rect x="${i * w + 1}" y="${78 - h - 1}" width="${Math.max(1, w - 2)}" height="${h}" fill="var(--c1)"/><rect x="${i * w}" y="0" width="${w}" height="78" fill="transparent" data-tip="${hms(t)}: ${v} ${v === 1 ? 'event' : 'events'}"/>`;
    }).join('');
    return `<div class="hist" id="hist"><svg viewBox="0 0 1000 78" preserveAspectRatio="none" aria-label="Events over time"><line x1="0" x2="1000" y1="77.5" y2="77.5" stroke="var(--line2)"/>${bars}</svg><div class="axis"><span>${hms(S.from)}</span><span class="tiny">Drag to zoom into a time range</span><span>${hms(S.to)}</span></div></div>`;
  }

  function highlight(text, terms) {
    let s = esc(text);
    terms.map(esc).sort((a, b) => b.length - a.length).forEach(t => { s = s.split(t).join(`\u0001${t}\u0002`); });
    return s.replace(/\u0001/g, '<mark>').replace(/\u0002/g, '</mark>');
  }

  function sidebar(rows) {
    const d = S.dv;
    const counts = Object.fromEntries(FIELDS.map(f => [f, rows.filter(e => e[f] !== undefined).length]));
    const item = f => {
      const on = d.cols.includes(f);
      let vals = '';
      if (d.fopen === f) {
        const c = {};
        rows.forEach(e => { if (e[f] !== undefined) c[e[f]] = (c[e[f]] || 0) + 1; });
        const top = Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 6);
        vals = `<div class="fv">${top.length ? top.map(([v, n]) => `<div class="fvr"><span title="${esc(v)}">${esc(v)}</span><span class="num muted">${Math.round(100 * n / counts[f])}%</span><button class="ib" aria-label="Filter for ${esc(v)}" data-act="dvFilter" data-f="${esc(f)}" data-v="${esc(v)}">+</button><button class="ib" aria-label="Filter out ${esc(v)}" data-act="dvFilter" data-neg="1" data-f="${esc(f)}" data-v="${esc(v)}">−</button></div>`).join('') : '<span class="muted">No values in these results.</span>'}
          <span class="tiny muted">${Object.keys(c).length} distinct in ${counts[f]} records</span></div>`;
      }
      return `<div class="fld" data-fname="${esc(f)}"><div><button class="fn" data-act="dvField" data-f="${esc(f)}" title="${esc(f)}" aria-expanded="${d.fopen === f}">${esc(f)}</button><span class="fc">${counts[f]}</span><button class="ib" data-act="dvCol" data-f="${esc(f)}" title="${on ? 'Remove column' : 'Add column'}" aria-label="${on ? 'Remove' : 'Add'} column ${esc(f)}">${on ? '×' : '+'}</button></div>${vals}</div>`;
    };
    return `<aside class="side" aria-label="Fields"><input type="search" data-inp="dvFieldSearch" placeholder="Search field names" aria-label="Search field names" style="width:100%">
      <h3>SELECTED FIELDS</h3>${d.cols.map(item).join('')}<h3>AVAILABLE FIELDS</h3>${FIELDS.filter(f => !d.cols.includes(f)).map(item).join('')}</aside>`;
  }

  function table(rows, ast) {
    const d = S.dv, terms = ast ? KQL.termsFor(ast, 'process.command_line') : [];
    const pages = Math.max(1, Math.ceil(rows.length / PAGE));
    d.page = Math.min(d.page, pages - 1);
    const slice = rows.slice(d.page * PAGE, d.page * PAGE + PAGE);
    const arrow = c => (d.sort[0] === c ? (d.sort[1] === 'asc' ? ' ▲' : ' ▼') : '');
    const cols = d.cols, nCols = cols.length + 2 + (S.answers ? 1 : 0);
    const head = `<th aria-label="Expand"></th><th><button class="link" data-act="dvSort" data-f="@timestamp">@timestamp${arrow('@timestamp')}</button></th>${cols.map(c => `<th><button class="link" data-act="dvSort" data-f="${esc(c)}">${esc(c)}${arrow(c)}</button><button class="ib x" data-act="dvCol" data-f="${esc(c)}" aria-label="Remove column ${esc(c)}">×</button></th>`).join('')}${S.answers ? '<th>Lab answer</th>' : ''}`;
    const body = slice.map(e => {
      const open = d.open.has(e._id);
      const tds = cols.map(c => {
        const v = e[c];
        if (v === undefined) return '<td class="muted">–</td>';
        return `<td>${c === 'process.command_line' ? highlight(v, terms) : esc(v)}</td>`;
      }).join('');
      return `<tr data-row="${esc(e._id)}"><td><button class="ib" data-act="dvOpen" data-id="${esc(e._id)}" aria-expanded="${open}" aria-label="Toggle details">${open ? '▾' : '▸'}</button></td><td class="tm">${esc(full(e._t))}</td>${tds}${S.answers ? `<td>${esc(e._id)} <span class="muted">${esc(e._role)}</span></td>` : ''}</tr>${open ? `<tr><td colspan="${nCols}" style="padding:0">${docPanel(e, d.tabs[e._id])}</td></tr>` : ''}`;
    }).join('');
    return `<div class="dtable"><table class="t"><thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="${nCols}"><div class="empty">No results match this query and time window.</div></td></tr>`}</tbody></table></div>
    <div class="pager"><button class="btn sm" data-act="dvPage" data-d="-1" ${d.page === 0 ? 'disabled' : ''}>Previous</button><span>Page ${d.page + 1} of ${pages}</span><button class="btn sm" data-act="dvPage" data-d="1" ${d.page >= pages - 1 ? 'disabled' : ''}>Next</button></div>`;
  }

  S.views.discover = {
    reset() { S.dv = fresh(); },
    open(q) { const d = S.dv; d.q = q; d.filters = []; d.page = 0; d.open.clear(); go('discover', { q }); },
    render() {
      const d = S.dv;
      if ('q' in S.params && S.params.q !== d.lastHashQ) { d.q = S.params.q; d.lastHashQ = S.params.q; }
      const { rows, ast } = compute();
      const unknown = ast ? KQL.fieldsUsed(ast).filter(f => !FIELDS.includes(f)) : [];
      const list = presets(), mine = saved();
      const fbar = d.filters.map((f, i) => `<span class="fpill ${f.neg ? 'neg' : ''} ${f.off ? 'off' : ''}"><button class="link" style="color:inherit;font-family:inherit" data-act="dvFToggle" data-i="${i}" title="Enable or disable">${f.neg ? 'NOT ' : ''}${esc(f.f)}: ${esc(f.v)}</button><button class="ib" data-act="dvFNeg" data-i="${i}" title="Invert" aria-label="Invert filter">⇄</button><button class="ib" data-act="dvFDel" data-i="${i}" aria-label="Remove filter">×</button></span>`).join('');
      return `<div class="dv">${sidebar(rows)}<section style="min-width:0">
        <div class="qbar"><span class="kq">KQL</span><div class="qwrap"><textarea id="kql" class="${d.err ? 'err' : ''}" spellcheck="false" aria-label="KQL query" placeholder='Try: process.parent.name : "winword.exe"  (press / to focus, Enter to run)' data-inp="dvType">${esc(d.q)}</textarea><div class="ac" id="ac" hidden></div>
          ${d.err ? `<div class="qerr" id="kql-err">KQL syntax error at position ${d.err.pos}: ${esc(d.err.msg)}</div>` : ''}
          ${unknown.length ? `<div class="qerr">Field not in this dataset: ${unknown.map(esc).join(', ')}</div>` : ''}</div>
          <div class="row" style="flex-direction:column;align-items:stretch;gap:4px"><button class="btn pri" data-act="dvRun">Update</button><button class="btn sm" data-act="dvClear">Clear</button></div></div>
        <div class="row" style="margin-top:7px"><label class="small muted">Saved search <select data-chg="dvSaved" id="dv-saved" aria-label="Saved search"><option value="">Choose…</option><optgroup label="Lab searches">${list.map((p, i) => `<option value="p${i}">${esc(p.name)}</option>`).join('')}</optgroup>${mine.length ? `<optgroup label="My searches">${mine.map((p, i) => `<option value="m${i}">${esc(p.name)}</option>`).join('')}</optgroup>` : ''}</select></label>
          <button class="btn sm" data-act="dvSave">Save search</button><span class="sp"></span><button class="btn sm" data-act="dvExport" data-t="csv">Export CSV</button><button class="btn sm" data-act="dvExport" data-t="ndjson">Export NDJSON</button></div>
        <div class="fbar">${fbar}</div>
        <div class="row" style="margin-bottom:4px"><span><b id="hit-count" style="font-size:18px">${rows.length}</b> ${rows.length === 1 ? 'hit' : 'hits'}</span><span class="muted small">of ${EV.length} synthetic events · ${esc(full(S.from).slice(0, -4))} to ${esc(hms(S.to))} UTC</span></div>
        ${histogram(rows)}${table(rows, ast)}</section></div>`;
    },
    after() {
      const d = S.dv, h = document.getElementById('hist'), ta = document.getElementById('kql');
      let x0 = null, sel = null;
      fit(ta);
      const frac = ev => { const r = h.getBoundingClientRect(); return Math.max(0, Math.min(1, (ev.clientX - r.left) / r.width)); };
      h.addEventListener('pointerdown', ev => { x0 = frac(ev); h.setPointerCapture(ev.pointerId); sel = document.createElement('div'); sel.className = 'sel'; h.appendChild(sel); });
      h.addEventListener('pointermove', ev => { if (x0 === null) return; const x = frac(ev); sel.style.left = Math.min(x, x0) * 100 + '%'; sel.style.width = Math.abs(x - x0) * 100 + '%'; });
      h.addEventListener('pointerup', ev => {
        if (x0 === null) return;
        const x = frac(ev), a = Math.min(x, x0), b = Math.max(x, x0); x0 = null;
        if (sel) sel.remove();
        if (b - a < 0.008) return;
        const span = S.to - S.from;
        setTime(Math.floor((S.from + a * span) / 1000) * 1000, Math.ceil((S.from + b * span) / 1000) * 1000);
      });
      ta.addEventListener('keydown', ev => {
        const box = document.getElementById('ac');
        if (!box.hidden && d.ac.length) {
          if (ev.key === 'ArrowDown' || ev.key === 'ArrowUp') { ev.preventDefault(); d.acI = (d.acI + (ev.key === 'ArrowDown' ? 1 : d.ac.length - 1)) % d.ac.length; drawAc(); return; }
          if (ev.key === 'Tab' || (ev.key === 'Enter' && d.acNav !== false)) { ev.preventDefault(); applyAc(d.acI); return; }
          if (ev.key === 'Escape') { box.hidden = true; ev.stopPropagation(); return; }
        }
        if (ev.key === 'Enter' && !ev.shiftKey) { ev.preventDefault(); run(); }
      });
      ta.addEventListener('blur', () => setTimeout(() => { const b = document.getElementById('ac'); if (b) b.hidden = true; }, 160));
    },
  };

  function context(ta) {
    const pos = ta.selectionStart, before = ta.value.slice(0, pos);
    const val = /([\w.@]+)\s*:\s*\(?(?:[^():]*\bor\s+)?"?([^"\s()]*)$/.exec(before);
    if (val && FIELDS.includes(val[1])) return { kind: 'value', field: val[1], part: val[2], start: pos - val[2].length - (before[pos - val[2].length - 1] === '"' ? 1 : 0), pos };
    const fld = /(?:^|[\s(])([\w.@]*)$/.exec(before);
    return fld ? { kind: 'field', part: fld[1], start: pos - fld[1].length, pos } : null;
  }
  function suggest(ta) {
    const d = S.dv, c = context(ta), box = document.getElementById('ac');
    d.ac = []; d.acI = 0; d.ctx = c;
    if (c && c.kind === 'field' && c.part.length >= 1) d.ac = FIELDS.filter(f => f.startsWith(c.part) && f !== c.part).slice(0, 8).map(f => ({ label: f, text: f + ' : ' }));
    if (c && c.kind === 'value') {
      const vals = [...new Set(EV.map(e => e[c.field]).filter(v => v !== undefined))].map(String);
      d.ac = vals.filter(v => v.startsWith(c.part)).sort().slice(0, 8).map(v => ({ label: v, text: `"${v.replace(/"/g, '\\"')}"` }));
    }
    box.hidden = !d.ac.length;
    drawAc();
  }
  function drawAc() {
    const d = S.dv, box = document.getElementById('ac');
    box.innerHTML = d.ac.map((a, i) => `<button class="${i === d.acI ? 'on' : ''}" data-act="dvAc" data-i="${i}" tabindex="-1">${esc(a.label)}</button>`).join('');
  }
  function applyAc(i) {
    const d = S.dv, ta = document.getElementById('kql'), a = d.ac[i], c = d.ctx;
    ta.value = ta.value.slice(0, c.start) + a.text + ta.value.slice(c.pos);
    const p = c.start + a.text.length;
    ta.focus(); ta.setSelectionRange(p, p);
    document.getElementById('ac').hidden = true;
    d.q = ta.value;
  }
  function run() {
    const d = S.dv, ta = document.getElementById('kql');
    d.q = ta.value.trim(); d.page = 0; d.open.clear(); d.lastHashQ = d.q;
    go('discover', { q: d.q });
    const n = document.getElementById('kql'); if (n) n.focus();
  }

  const fit = ta => { ta.style.height = 'auto'; ta.style.height = Math.min(130, Math.max(42, ta.scrollHeight + 2)) + 'px'; };
  inp.dvType = el => { S.dv.q = el.value; fit(el); suggest(el); };
  inp.dvFieldSearch = el => {
    const t = el.value.toLowerCase();
    document.querySelectorAll('.fld').forEach(f => { f.hidden = !f.dataset.fname.toLowerCase().includes(t); });
  };
  chg.dvSaved = el => {
    const v = el.value; if (!v) return;
    const item = v[0] === 'p' ? presets()[+v.slice(1)] : saved()[+v.slice(1)];
    S.views.discover.open(item.q);
  };
  const rerender = () => App.render();
  Object.assign(act, {
    dvRun: run,
    dvClear() { S.dv.q = ''; S.dv.filters = []; S.dv.lastHashQ = ''; go('discover'); },
    dvAc: el => applyAc(+el.dataset.i),
    dvField(el) { S.dv.fopen = S.dv.fopen === el.dataset.f ? null : el.dataset.f; rerender(); },
    dvCol(el) {
      const d = S.dv, f = el.dataset.f;
      d.cols = d.cols.includes(f) ? d.cols.filter(c => c !== f) : d.cols.concat(f);
      store.set('cols', d.cols);
      if (S.route === 'discover') rerender(); else toast(`Column ${esc(f)} ${d.cols.includes(f) ? 'added to' : 'removed from'} Discover.`);
    },
    dvFilter(el) {
      const d = S.dv, f = { f: el.dataset.f, v: el.dataset.v, neg: !!el.dataset.neg };
      if (!d.filters.some(x => x.f === f.f && x.v === f.v && !!x.neg === f.neg)) d.filters.push(f);
      d.page = 0; closeFlyout();
      if (S.route === 'discover') rerender(); else go('discover');
    },
    dvFToggle(el) { const f = S.dv.filters[+el.dataset.i]; f.off = !f.off; rerender(); },
    dvFNeg(el) { const f = S.dv.filters[+el.dataset.i]; f.neg = !f.neg; rerender(); },
    dvFDel(el) { S.dv.filters.splice(+el.dataset.i, 1); rerender(); },
    dvSort(el) {
      const d = S.dv, f = el.dataset.f;
      d.sort = d.sort[0] === f ? [f, d.sort[1] === 'asc' ? 'desc' : 'asc'] : [f, 'asc'];
      d.page = 0; rerender();
    },
    dvPage(el) { S.dv.page += +el.dataset.d; rerender(); },
    dvOpen(el) { const d = S.dv, id = el.dataset.id; if (d.open.has(id)) d.open.delete(id); else d.open.add(id); rerender(); },
    dvSave() {
      const q = S.dv.q.trim();
      if (!q) return toast('Enter a query to save first.');
      flyout(`<div class="fhead"><h2>Save search</h2><button class="btn sm" data-act="closeFly">Close</button></div><div class="form"><label>Name<input type="text" id="save-name" maxlength="60"></label><label>Query<textarea readonly>${esc(q)}</textarea></label><button class="btn pri" data-act="dvSaveGo">Save</button></div>`);
      document.getElementById('save-name').focus();
    },
    dvSaveGo() {
      const name = document.getElementById('save-name').value.trim();
      if (!name) return toast('Give the search a name.');
      store.set('saved', saved().concat({ name, q: S.dv.q.trim() }));
      closeFlyout(); toast(`Saved "${esc(name)}".`); rerender();
    },
    dvExport(el) {
      const { rows } = compute(), d = S.dv;
      if (el.dataset.t === 'ndjson') {
        download('simulated_discover_export.ndjson', rows.map(e => JSON.stringify(Object.assign({ _simulated: true }, nested(e)))).join('\n') + '\n', 'application/x-ndjson');
      } else {
        const cols = ['@timestamp'].concat(d.cols), q = v => `"${String(v === undefined ? '' : v).replace(/"/g, '""')}"`;
        download('simulated_discover_export.csv', [`# ${D.label}`, cols.map(q).join(',')].concat(rows.map(e => cols.map(c => q(e[c])).join(','))).join('\r\n'), 'text/csv');
      }
      toast(`Exported ${rows.length} simulated records.`);
    },
  });
})();
