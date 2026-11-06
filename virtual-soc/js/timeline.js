/* Event timeline: swimlanes with zoom, brush, alert markers and PID following. */
(function () {
  'use strict';
  const { S, EV, BY, esc, hms, full, hm, act, chg, setTime, showEvent, WINDOWS, parseT, T0, T1, go } = App;
  S.tl = { lane: 'category', sel: null, follow: false };
  const COLOR = { process: 'var(--c1)', network: 'var(--c2)', file: 'var(--c3)' };
  const SEV = { high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)' };
  const laneKey = {
    category: e => e['event.category'], user: e => e['user.name'], process: e => e['process.name'] || 'other',
    scenario: e => ({ CK: 'Checkpoint' }[e._scenario] || e._scenario),
  };
  function lanes(rows) {
    const k = laneKey[S.tl.lane], c = {};
    rows.forEach(e => { c[k(e)] = (c[k(e)] || 0) + 1; });
    if (S.tl.lane === 'category') return ['process', 'network', 'file'];
    return Object.keys(c).sort((a, b) => (S.tl.lane === 'scenario' ? a.localeCompare(b) : c[b] - c[a])).slice(0, 10);
  }
  function shape(e, x, y, cls) {
    const cat = e['event.category'], tip = `${hms(e._t)} ${e['event.action']}\n${e['process.name'] || ''} ${e['process.command_line'] || e['destination.ip'] || e['file.path'] || ''}`.slice(0, 180);
    const a = `class="tldot ${cls}" fill="${COLOR[cat]}" data-act="tlSel" data-id="${esc(e._id)}" data-tip="${esc(tip)}"`;
    if (cat === 'network') return `<rect x="${x - 4.5}" y="${y - 4.5}" width="9" height="9" rx="1.5" ${a}/>`;
    if (cat === 'file') return `<path d="M${x} ${y - 6} L${x + 6} ${y + 4.5} L${x - 6} ${y + 4.5} Z" ${a}/>`;
    return `<circle cx="${x}" cy="${y}" r="5" ${a}/>`;
  }
  function ticks(a, b) {
    const step = [1, 5, 10, 30, 60, 120, 300, 600, 900, 1800, 3600].map(s => s * 1000).find(s => (b - a) / s <= 10) || 3600000;
    const out = [];
    for (let t = Math.ceil(a / step) * step; t <= b; t += step) out.push(t);
    return { out, sec: step < 60000 };
  }
  function draw() {
    const box = document.getElementById('tlbox');
    if (!box) return;
    const rows = App.rangedEvents(), ls = lanes(rows), W = Math.max(600, box.clientWidth), L = 112, R = 12, AX = 24, LH = 46, AL = 40;
    const H = AX + AL + ls.length * LH + 8, X = t => L + (W - L - R) * (t - S.from) / (S.to - S.from);
    const sel = S.tl.sel && BY[S.tl.sel], pid = sel && S.tl.follow ? sel['process.pid'] : null;
    const { out, sec } = ticks(S.from, S.to);
    let g = out.map(t => `<line class="gl" x1="${X(t)}" x2="${X(t)}" y1="${AX}" y2="${H - 6}"/><text class="ax" x="${X(t)}" y="15" text-anchor="middle">${sec ? hms(t) : hm(t)}</text>`).join('');
    g += `<text class="ax" x="6" y="${AX + AL / 2 + 4}">alerts</text>`;
    App.rangedAlerts().forEach(a => {
      const x = X(a.t), y = AX + AL / 2;
      g += `<path d="M${x} ${y - 8} L${x + 7} ${y} L${x} ${y + 8} L${x - 7} ${y} Z" fill="${SEV[a.severity]}" class="tldot" data-act="showAlert" data-id="${esc(a.id)}" data-tip="${esc(`${hms(a.t)} ${a.ruleName}\n${a.severity}: ${a.reason}`)}"/>`;
    });
    const k = laneKey[S.tl.lane], y0 = AX + AL;
    ls.forEach((l, i) => {
      const y = y0 + i * LH + LH / 2;
      g += `<line class="gl" x1="0" x2="${W}" y1="${y0 + i * LH}" y2="${y0 + i * LH}"/><text class="ax" x="6" y="${y + 4}" style="fill:var(--t2)">${esc(String(l).slice(0, 15))}</text>`;
    });
    const placed = rows.filter(e => ls.includes(k(e)));
    if (pid) {
      const pts = placed.filter(e => e['process.pid'] === pid).map(e => `${X(e._t)},${y0 + ls.indexOf(k(e)) * LH + LH / 2}`);
      if (pts.length > 1) g += `<polyline points="${pts.join(' ')}" fill="none" stroke="var(--amber)" stroke-width="1.5" stroke-dasharray="4 3"/>`;
    }
    placed.forEach(e => {
      const cls = [e._id === S.tl.sel ? 'tl-sel' : '', pid && e['process.pid'] !== pid ? 'tl-dim' : ''].join(' ');
      g += shape(e, X(e._t), y0 + ls.indexOf(k(e)) * LH + LH / 2, cls);
    });
    box.innerHTML = `<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img" aria-label="Event timeline" id="tlsvg">${g}<rect id="tlbrush" y="${AX}" height="${H - AX - 6}" width="0" fill="rgba(90,162,240,.22)" stroke="var(--accent)" pointer-events="none"/></svg>`;
    const list = document.getElementById('tl-count');
    if (list) list.textContent = rows.length;
    bind(box, L, R);
  }
  function bind(box, L, R) {
    const svg = document.getElementById('tlsvg'), brush = document.getElementById('tlbrush');
    let x0 = null;
    const px = ev => { const r = svg.getBoundingClientRect(); return (ev.clientX - r.left) * (svg.viewBox.baseVal.width / r.width); };
    const toT = x => { const w = svg.viewBox.baseVal.width; return S.from + (S.to - S.from) * Math.max(0, Math.min(1, (x - L) / (w - L - R))); };
    svg.addEventListener('pointerdown', ev => { if (ev.target.closest('.tldot')) return; x0 = px(ev); svg.setPointerCapture(ev.pointerId); });
    svg.addEventListener('pointermove', ev => { if (x0 === null) return; const x = px(ev); brush.setAttribute('x', Math.min(x, x0)); brush.setAttribute('width', Math.abs(x - x0)); });
    svg.addEventListener('pointerup', ev => {
      if (x0 === null) return;
      const x = px(ev), a = Math.min(x, x0), b = Math.max(x, x0); x0 = null; brush.setAttribute('width', 0);
      if (b - a < 8) return;
      setTime(Math.floor(toT(a) / 1000) * 1000, Math.ceil(toT(b) / 1000) * 1000);
    });
    svg.addEventListener('wheel', ev => {
      ev.preventDefault();
      zoom(ev.deltaY < 0 ? 0.7 : 1.4, toT(px(ev)));
    }, { passive: false });
  }
  function zoom(f, c) {
    const span = Math.max(4000, Math.min(T1 - T0, (S.to - S.from) * f));
    const mid = c === undefined ? (S.from + S.to) / 2 : c, r = (mid - S.from) / (S.to - S.from);
    let a = mid - span * r, b = a + span;
    if (a < T0) { a = T0; b = a + span; }
    if (b > T1) { b = T1; a = b - span; }
    setTime(Math.floor(a / 1000) * 1000, Math.ceil(b / 1000) * 1000);
  }
  function table() {
    const rows = App.rangedEvents(), sel = S.tl.sel && BY[S.tl.sel];
    const related = e => sel && e['process.pid'] === sel['process.pid'];
    return rows.map(e => `<tr class="click ${e._id === S.tl.sel ? 'on' : ''}" data-act="tlSel" data-id="${esc(e._id)}"><td class="mono">${hms(e._t)}</td><td>${esc(e['event.action'])}</td><td class="mono">${esc(e['process.name'] || '')}</td><td class="mono">${e['process.pid'] || ''}</td><td class="mono" style="overflow-wrap:anywhere">${esc(e['process.command_line'] || e['file.path'] || `${e['source.ip']} → ${e['destination.ip']}:${e['destination.port']}`)}</td><td>${related(e) && e._id !== S.tl.sel ? '<span class="pill">same PID</span>' : ''}</td></tr>`).join('');
  }
  S.views.timeline = {
    render() {
      if (S.params.sel && BY[S.params.sel] && S.tl.lastSel !== S.params.sel) { S.tl.sel = S.params.sel; S.tl.lastSel = S.params.sel; }
      const t = S.tl, sel = t.sel && BY[t.sel];
      const lane = (v, l) => `<button class="btn sm ${t.lane === v ? 'on' : ''}" data-act="tlLane" data-v="${v}" aria-pressed="${t.lane === v}">${l}</button>`;
      return `<div class="grid"><div class="card"><div class="row" style="margin-bottom:8px"><span class="small muted">Lanes</span>${lane('category', 'Category')}${lane('process', 'Process')}${lane('user', 'User')}${lane('scenario', 'Scenario')}
        <span class="small muted" style="margin-left:10px">Zoom</span><button class="btn sm" data-act="tlZoom" data-f="0.5" aria-label="Zoom in">+</button><button class="btn sm" data-act="tlZoom" data-f="2" aria-label="Zoom out">−</button>
        ${WINDOWS.map(w => `<button class="btn sm" data-act="tlWin" data-a="${w[1]}" data-b="${w[2]}">${esc(w[0])}</button>`).join('')}</div>
        <div class="lg"><span><i style="background:var(--c1);border-radius:50%"></i>process</span><span><i style="background:var(--c2)"></i>network</span><span><i style="background:var(--c3);clip-path:polygon(50% 0,100% 100%,0 100%)"></i>file</span><span>◆ alert, coloured by severity</span><span class="sp"></span><span class="tiny">Scroll to zoom. Drag an empty area to select a range.</span></div>
        <div id="tlbox"></div></div>
      <div class="card"><div class="row" style="margin-bottom:6px"><h2><span id="tl-count">0</span> events in this window</h2><span class="sp"></span>
        ${sel ? `<span class="small muted">Selected: ${hms(sel._t)} ${esc(sel['process.name'] || '')}</span>${sel['process.pid'] ? `<button class="btn sm ${t.follow ? 'on' : ''}" data-act="tlFollow" aria-pressed="${t.follow}">Follow PID ${sel['process.pid']}</button>` : ''}<button class="btn sm" data-act="openEvent" data-id="${esc(sel._id)}">Open event</button>` : '<span class="small muted">Select an event to follow its process.</span>'}</div>
        <div class="tlist"><table class="t"><thead><tr><th>Time</th><th>Action</th><th>Process</th><th>PID</th><th>Detail</th><th></th></tr></thead><tbody>${table()}</tbody></table></div></div></div>`;
    },
    after() { draw(); },
  };
  window.addEventListener('resize', () => { if (S.route === 'timeline') draw(); });
  Object.assign(act, {
    tlLane(el) { S.tl.lane = el.dataset.v; App.render(); },
    tlSel(el) { S.tl.sel = el.dataset.id; App.render(); },
    tlFollow() { S.tl.follow = !S.tl.follow; App.render(); },
    tlZoom: el => zoom(+el.dataset.f),
    tlWin: el => setTime(parseT(el.dataset.a), parseT(el.dataset.b)),
  });
})();
