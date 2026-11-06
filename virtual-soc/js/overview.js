/* SOC overview dashboard. Every tile, bar and row drills into another view. */
(function () {
  'use strict';
  const { S, esc, hm, hms, full, go, act, setTime, MITRE, alertState } = App;
  const CAT = [['process', 'var(--c1)'], ['network', 'var(--c2)'], ['file', 'var(--c3)']];

  function pickStep(ms) {
    const steps = [10, 30, 60, 120, 300, 600, 900, 1800].map(s => s * 1000);
    return steps.find(s => ms / s <= 16) || 3600000;
  }
  function stacked(rows) {
    const step = pickStep(S.to - S.from), start = Math.floor(S.from / step) * step;
    const n = Math.max(1, Math.ceil((S.to - start) / step));
    const b = Array.from({ length: n }, () => ({ process: 0, network: 0, file: 0 }));
    rows.forEach(e => { const i = Math.min(n - 1, Math.floor((e._t - start) / step)); b[i][e['event.category']]++; });
    const W = 760, H = 210, L = 34, B = 24, top = 16;
    const mx = Math.max(1, ...b.map(x => x.process + x.network + x.file));
    const nice = mx <= 5 ? 1 : mx <= 10 ? 2 : mx <= 25 ? 5 : mx <= 60 ? 10 : 20;
    const ch = H - B - top, bw = (W - L) / n, y = v => H - B - ch * v / mx;
    let g = '';
    for (let v = 0; v <= mx; v += nice) g += `<line class="gl" x1="${L}" x2="${W}" y1="${y(v)}" y2="${y(v)}"/><text class="ax" x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${v}</text>`;
    let bars = '';
    const peak = Math.max(...b.map(x => x.process + x.network + x.file));
    b.forEach((x, i) => {
      const t = start + i * step, tot = x.process + x.network + x.file;
      const label = `${hms(t)} to ${hms(t + step)}\nprocess ${x.process}, network ${x.network}, file ${x.file}`;
      let yy = H - B;
      const w = Math.max(3, bw - 10), xx = L + i * bw + (bw - w) / 2;
      CAT.forEach(([c, col]) => {
        if (!x[c]) return;
        const h = Math.max(3, ch * x[c] / mx);
        yy -= h;
        bars += `<rect x="${xx}" y="${yy}" width="${w}" height="${Math.max(1, h - 2)}" rx="2" fill="${col}"/>`;
      });
      if (tot && tot === peak) bars += `<text x="${xx + w / 2}" y="${yy - 4}" text-anchor="middle" style="fill:var(--t1);font-size:11.5px">${tot}</text>`;
      bars += `<rect class="barhit" data-tip="${esc(label)}" data-act="ovZoom" data-a="${t}" data-b="${t + step}" x="${L + i * bw}" y="${top}" width="${bw}" height="${ch}" fill="transparent"/>`;
      if (i % Math.ceil(n / 8) === 0) bars += `<text class="ax" x="${L + i * bw + bw / 2}" y="${H - 7}" text-anchor="middle">${hm(t)}</text>`;
    });
    return `<svg viewBox="0 0 ${W} ${H}" style="width:100%;display:block" role="img" aria-label="Events by category over time">${g}${bars}</svg>`;
  }
  function hbars(list, field) {
    const mx = Math.max(1, ...list.map(x => x[1]));
    return list.map(([k, v]) => `<button class="hb" data-act="ovField" data-f="${esc(field)}" data-v="${esc(k)}" data-tip="${esc(k)}: ${v} events"><span>${esc(k)}</span><span class="bar"><i style="width:${100 * v / mx}%"></i></span><span class="num">${v}</span></button>`).join('');
  }
  const top = (rows, f, n) => {
    const c = {}; rows.forEach(e => { if (e[f] !== undefined) c[e[f]] = (c[e[f]] || 0) + 1; });
    return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, n);
  };

  S.views.overview = {
    render() {
      const rows = App.rangedEvents(), alerts = App.rangedAlerts();
      const count = c => rows.filter(e => e['event.category'] === c).length;
      const open = alerts.filter(a => alertState(a.id).status === 'open').length;
      const high = alerts.filter(a => a.severity === 'high').length;
      const kpi = (v, l, a, extra = '') => `<button class="kpi" data-act="${a}" ${extra}><b>${v}</b><span>${esc(l)}</span></button>`;
      const byRule = {};
      alerts.forEach(a => { (byRule[a.ruleId] = byRule[a.ruleId] || []).push(a); });
      const ruleRows = S.rules.filter(r => byRule[r.id]).map(r => {
        const l = byRule[r.id], cls = l.filter(a => alertState(a.id).classification === 'false-positive').length;
        return `<tr class="click" data-act="ovRule" data-id="${esc(r.id)}"><td>${esc(r.name)}</td><td class="sev ${r.severity}">${esc(r.severity)}</td><td class="num">${l.length}</td><td class="num">${l.filter(a => alertState(a.id).status === 'open').length}</td><td class="num">${cls || '–'}</td></tr>`;
      }).join('');
      const tech = {};
      alerts.forEach(a => a.mitre.forEach(m => { tech[m] = (tech[m] || 0) + 1; }));
      const techs = Object.keys(MITRE).filter(k => S.rules.some(r => (r.mitre || []).includes(k)));
      const recent = alerts.slice().sort((a, b) => b.t - a.t).slice(0, 6).map(a => `<tr class="click" data-act="showAlert" data-id="${esc(a.id)}"><td class="mono small">${hms(a.t)}</td><td class="sev ${a.severity}">${esc(a.severity)}</td><td>${esc(a.ruleName)}</td><td class="small muted">${esc(a.entity)}</td></tr>`).join('');
      return `<div class="grid">
      <div class="kpis">${kpi(rows.length, 'Events', 'ovAll')}${kpi(count('process'), 'Process', 'ovField', 'data-f="event.category" data-v="process"')}${kpi(count('network'), 'Network', 'ovField', 'data-f="event.category" data-v="network"')}${kpi(count('file'), 'File', 'ovField', 'data-f="event.category" data-v="file"')}${kpi(open, 'Open alerts', 'ovAlerts')}${kpi(high, 'High severity', 'ovHigh')}</div>
      <div class="grid ov">
        <div class="card"><h2>Events over time, by category</h2><div class="lg">${CAT.map(([c, col]) => `<span><i style="background:${col}"></i>${c}</span>`).join('')}<span class="sp"></span><span class="tiny">Click a bar to zoom in</span></div>${rows.length ? stacked(rows) : '<div class="empty">No events in this window.</div>'}</div>
        <div class="card"><h2>Rule firings</h2>${ruleRows ? `<table class="t"><thead><tr><th>Rule</th><th>Severity</th><th class="num">Fired</th><th class="num">Open</th><th class="num">Marked FP</th></tr></thead><tbody>${ruleRows}</tbody></table>` : '<div class="empty">No alerts in this window.</div>'}</div>
      </div>
      <div class="grid ov">
        <div class="card"><h2>Latest alerts</h2>${recent ? `<table class="t"><tbody>${recent}</tbody></table>` : '<div class="empty">No alerts in this window.</div>'}</div>
        <div class="card"><h2>Top processes</h2>${hbars(top(rows, 'process.name', 6), 'process.name')}<h2 style="margin-top:10px">Top users</h2>${hbars(top(rows, 'user.name', 3), 'user.name')}</div>
      </div>
      <div class="card"><h2>ATT&amp;CK coverage</h2><div class="chips">${techs.map(k => `<button class="chip ${tech[k] ? '' : 'dim'}" data-act="ovTech" data-t="${esc(k)}" data-tip="${esc(MITRE[k])}">${esc(k)}${tech[k] ? `<b>${tech[k]}</b>` : ''}</button>`).join('')}</div><p class="tiny muted" style="margin:6px 0 0">The number is the alert count in this window, with enabled rules only. Dim techniques have no alerts here.</p></div>
      </div>`;
    },
  };
  Object.assign(act, {
    ovZoom: el => setTime(+el.dataset.a, +el.dataset.b),
    ovAll: () => S.views.discover.open(''),
    ovField: el => { const v = el.dataset.v; S.views.discover.open(`${el.dataset.f} : "${v.replace(/"/g, '\\"')}"`); },
    ovAlerts: () => go('alerts', { status: 'open' }),
    ovHigh: () => go('alerts', { sev: 'high' }),
    ovRule: el => go('alerts', { rule: el.dataset.id }),
    ovTech: el => go('alerts', { tech: el.dataset.t }),
  });
})();
