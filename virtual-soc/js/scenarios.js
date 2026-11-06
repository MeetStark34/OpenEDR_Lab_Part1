/* Five guided scenario demonstrations with event replay. Nothing is executed: replay plays back synthetic records. */
(function () {
  'use strict';
  const { S, EV, BY, esc, hms, go, act, chg, inp, toast, parseT, MITRE, D } = App;
  const ids = (p, n) => Array.from({ length: n }, (_, i) => `${p}${String(i + 1).padStart(2, '0')}`);

  const SC = {
    R1: {
      title: 'R1 Host reconnaissance', fidelity: 'Medium', mitre: ['T1033', 'T1087', 'T1016', 'T1018', 'T1082', 'T1057'], rules: ['R1', 'R1-TUNED'], win: ['10:13', '10:16'],
      objective: 'See how a cluster of ordinary built-in commands, run close together, reveals an attacker orienting after landing.',
      observes: 'Each command is a process-create event with a known binary, command line and parent. Any one is normal. The signal is many different tools from one user in a short window.',
      cmd: 'whoami /all; net user; net group "Domain Admins" /domain 2>$null\nnltest /dclist: 2>$null; systeminfo; ipconfig /all; arp -a; net view 2>$null; tasklist',
      events: ['CTL-02'].concat(ids('R1-', 11)),
      steps: [['Run the base rule query in Discover and read the parent column.', 'scQuery', 'R1'], ['Open the process tree. Which binary is not a child of PowerShell?', 'scTree', 6120], ['Compare with the administrator session, which also trips the base rule.', 'scTree', 8102], ['Lower the threshold on the rule page and watch the alert count change.', 'scRule', 'R1']],
    },
    R2: {
      title: 'R2 Network scanning', fidelity: 'High for host-touching scans; blind beyond the host', mitre: ['T1046', 'T1018', 'T1595'], rules: ['R2-OUT', 'R2-IN'], win: ['10:30', '10:40'],
      objective: 'Detect scanning at the two points a host sensor can see it: launched from the host, and arriving at the host.',
      observes: 'Outbound, one process fans out to many addresses. Inbound, one source touches many local ports. A scan between two other machines is invisible to this sensor.',
      cmd: '1..25 | ForEach-Object { Test-NetConnection -ComputerName 192.168.56.$_ -Port 445 `\n    -WarningAction SilentlyContinue } | Out-Null\n\n# Inbound, from the monitoring host against the VM only\nnmap 192.168.56.101',
      events: ids('R2O-', 25).concat(ids('R2I-', 24)),
      steps: [['Run the outbound query. Why does it also return the S2 download connections?', 'scQuery', 'R2-OUT'], ['Open the rule. Distinct destination.port is 1 for this sweep, so the rule counts destination.ip.', 'scRule', 'R2-OUT'], ['Open the inbound rule and raise the threshold above 24.', 'scRule', 'R2-IN'], ['See the sweep on the timeline, then follow the PID.', 'scTime', 'R2O-01']],
    },
    S1: {
      title: 'S1 Weaponised document', fidelity: 'High', mitre: ['T1566.001', 'T1204.002', 'T1059.001'], rules: ['S1'], win: ['10:51', '10:54'],
      objective: 'Catch the most reliable phishing-execution signal: a macro launching a child process from an Office application.',
      observes: 'A process-create event whose parent is an Office binary and whose child is an interpreter or LOLBin. The relationship is the detection. The command line only confirms intent.',
      cmd: 'powershell -NoProfile -Command "Write-Host lab-macro-fired"',
      events: ['S1-01', 'S1-02', 'CTL-05'],
      steps: [['Run the rule query. How many records match?', 'scQuery', 'S1'], ['Open the tree and read the lineage of the PowerShell process.', 'scTree', 7588], ['Find the other Word child. Why is printing not an alert?', 'scTree', 7420]],
    },
    S2: {
      title: 'S2 Phishing link and download cradle', fidelity: 'Medium-High', mitre: ['T1566.002', 'T1204.001', 'T1105', 'T1218'], rules: ['S2-PS', 'S2-PS-TUNED', 'S2-LOLBIN', 'S2-CORR'], win: ['11:06', '11:28'],
      objective: 'Catch a clicked link leading to a PowerShell cradle or signed binary fetching a remote payload, then confirm it by correlation.',
      observes: 'A process with a remote-fetch argument, an outbound connection from that same process, and a file written to disk. Each is weak alone, and together they show a download.',
      cmd: 'powershell -NoProfile -Command "Invoke-WebRequest https://example.com -OutFile $env:TEMP\\lab_fetch.txt"\n\n# LOLBin shape, represented in the synthetic data by:\nmshta.exe https://example.com/lab_probe.hta',
      events: ['S2-01', 'S2-02', 'S2-03', 'S2-04', 'S2-05', 'FP-01', 'FP-01b', 'FP-01c'],
      steps: [['Run the base PowerShell rule query and compare both parents.', 'scQuery', 'S2-PS'], ['Pivot on PID 5512 to see all three correlated events.', 'scPivot', 5512], ['Turn on the sequence rule. Notice that the updater also confirms.', 'scRule', 'S2-CORR'], ['Try the parent-tuned rule, which removes the updater.', 'scRule', 'S2-PS-TUNED']],
    },
    S3: {
      title: 'S3 Fake IT / ClickFix', fidelity: 'Low-Medium', mitre: ['T1204', 'T1204.004', 'T1059.001'], rules: ['S3'], win: ['11:31', '11:40'],
      objective: 'Detect a user being talked into pasting a command into the Run dialog, and see how little there is to detect.',
      observes: 'An interpreter whose parent is explorer.exe, with no document and no clicked link in the tree. Explorer starts programs all day, so the command line carries almost all of the signal.',
      cmd: '# From the assignment: right tree, but does NOT match the query\npowershell -NoProfile -Command "Write-Host clickfix-lab"\n\n# Variant carrying the iex marker\npowershell -NoProfile -Command "iex \'Write-Host clickfix-lab\'"',
      events: ['S3-01', 'S3-02', 'S3-03', 'S3-04', 'S3-05', 'FP-02'],
      steps: [['Run the rule query. Which records are not paste variants?', 'scQuery', 'S3'], ['Compare the trees of a hit and a miss.', 'scTree', 6010], ['Try your own text in the paste tester below.', null, null]],
    },
  };
  S.rp = { sc: 'R1', i: 0, timer: null, speed: 4, feed: [], seen: new Set(), alerts: [] };

  function stop() { if (S.rp.timer) { clearTimeout(S.rp.timer); S.rp.timer = null; } }
  function reset(sc) { stop(); Object.assign(S.rp, { sc, i: 0, feed: [], seen: new Set(), alerts: [] }); }
  const played = () => SC[S.rp.sc].events.slice(0, S.rp.i).map(i => BY[i]).sort((a, b) => a._t - b._t);

  function step() {
    const r = S.rp, c = SC[r.sc];
    if (r.i >= c.events.length) { stop(); draw(); return false; }
    const e = BY[c.events[r.i]];
    r.i++;
    const what = e['process.command_line'] || e['file.path'] || `${e['source.ip']} → ${e['destination.ip']}:${e['destination.port']}`;
    r.feed.push(`<div><span class="tmv">${hms(e._t)}</span> ${esc(e['process.name'] || '')} ${esc(what)}</div>`);
    const seen = played();
    c.rules.forEach(id => {
      const rule = S.rules.find(x => x.id === id);
      if (!rule) return;
      SOCEngine.runRule(rule, seen).forEach(a => {
        const key = a.ruleId + '|' + a.entity + '|' + a.eventIds[0];
        if (r.seen.has(key)) return;
        r.seen.add(key); r.alerts.push(a);
        r.feed.push(`<div class="al">ALERT ${esc(a.ruleName)}: ${esc(a.reason)}</div>`);
        toast(`<b>${esc(a.ruleName)}</b><br><span class="small">${esc(a.reason)}</span>`, 3200);
      });
    });
    draw();
    return true;
  }
  function loop() {
    const r = S.rp, c = SC[r.sc];
    if (!step() || r.i >= c.events.length) { stop(); draw(); return; }
    const a = BY[c.events[r.i - 1]], b = BY[c.events[r.i]];
    const gap = Math.abs(b._t - a._t) / r.speed;
    r.timer = setTimeout(loop, Math.max(90, Math.min(1300, gap)));
  }
  const meter = (label, v, max, th, cls = '') => `<div class="small row"><span>${esc(label)}</span><span class="sp"></span><b>${v}</b></div><div class="meter"><i class="${cls}" style="width:${Math.min(100, 100 * v / max)}%"></i><u style="left:${100 * th / max}%"></u></div>`;

  function stage() {
    const r = S.rp, ev = played();
    if (r.sc === 'R1') {
      const names = ['whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe', 'systeminfo.exe', 'ipconfig.exe', 'arp.exe', 'tasklist.exe'];
      const set = new Set(ev.map(e => e['process.name']));
      const base = names.filter(n => set.has(n)).length;
      const tuned = new Set(ev.filter(e => names.includes(e['process.name']) && e['process.parent.name'] === 'powershell.exe').map(e => e['process.name'])).size;
      return `${meter('Base rule: distinct binaries', base, 10, 5)}${meter('Tuned rule: distinct binaries', tuned, 10, 5, 'o')}<div class="cells" style="margin-top:8px">${names.map(n => `<div class="cell ${set.has(n) ? 'on' : ''}">${esc(n.replace('.exe', ''))}</div>`).join('')}</div>`;
    }
    if (r.sc === 'R2') {
      const out = new Set(ev.filter(e => e['network.direction'] === 'outbound').map(e => e['destination.ip']));
      const inn = new Set(ev.filter(e => e['network.direction'] === 'inbound').map(e => e['destination.port']));
      const ports = ids('R2I-', 24).map(i => BY[i]['destination.port']);
      return `${meter('Outbound: distinct destination.ip', out.size, 30, 20)}<div class="cells">${Array.from({ length: 25 }, (_, i) => `<div class="cell ${out.has('192.168.56.' + (i + 1)) ? 'on' : ''}">.${i + 1}</div>`).join('')}</div>
        <div style="margin-top:8px">${meter('Inbound: distinct destination.port', inn.size, 30, 20, 'o')}</div><div class="cells">${ports.map(p => `<div class="cell ${inn.has(p) ? 'on' : ''}">${p}</div>`).join('')}</div>`;
    }
    const on = id => ev.some(e => e._id === id);
    const lnk = (id, h, s) => `<div class="lnk ${on(id) ? 'on' : ''}"><b>${esc(h)}</b><span>${esc(s)}</span></div>`;
    if (r.sc === 'S1') {
      return `<div class="chain"><div class="lnk on"><b>explorer.exe</b><span>user shell</span></div>${lnk('S1-01', 'winword.exe', 'opens lab_invoice.docm')}${lnk('S1-02', 'powershell.exe', 'child of Word: the detection')}</div><div class="chain" style="margin-top:6px">${lnk('CTL-05', 'splwow64.exe', 'also a child of Word, excluded')}</div>`;
    }
    if (r.sc === 'S2') {
      return `<p class="small muted" style="margin:0 0 4px">PowerShell cradle, PID 5512</p><div class="chain">${lnk('S2-01', '1 Execution', 'Invoke-WebRequest')}${lnk('S2-02', '2 Connection', '→ 203.0.113.10:443')}${lnk('S2-03', '3 File write', 'lab_fetch.txt')}</div>
        <p class="small muted" style="margin:8px 0 4px">LOLBin shape, PID 5736</p><div class="chain">${lnk('S2-04', 'mshta.exe', 'remote .hta argument')}${lnk('S2-05', 'Connection', '→ 203.0.113.10:443')}</div>
        <p class="small muted" style="margin:8px 0 4px">Benign updater, PID 5902</p><div class="chain">${lnk('FP-01', 'Execution', 'parent svchost.exe')}${lnk('FP-01b', 'Connection', '→ 198.51.100.40:443')}${lnk('FP-01c', 'File write', 'agent.msi')}</div>`;
    }
    const ast = KQL.parse(S.rules.find(x => x.id === 'S3').kql);
    return `<table class="t"><thead><tr><th>Pasted arguments</th><th>Result</th></tr></thead><tbody>${SC.S3.events.filter(i => i !== 'FP-02').map(i => {
      const e = BY[i], seen = on(i), hit = KQL.evaluate(ast, e), cmd = e['process.command_line'].replace(/^powershell /, '').replace(/([A-Za-z0-9+/=]{12})[A-Za-z0-9+/=]+/, '$1…');
      return `<tr style="${seen ? '' : 'opacity:.4'}"><td class="mono small">${esc(cmd)}</td><td class="${seen ? (hit ? 'vh' : 'vm') : 'muted'}">${seen ? (hit ? 'HIT' : 'MISS') : 'waiting'}</td></tr>`;
    }).join('')}</tbody></table>`;
  }
  function draw() {
    const r = S.rp, c = SC[r.sc];
    const st = document.getElementById('rp-stage');
    if (!st) return;
    st.innerHTML = stage();
    const f = document.getElementById('rp-feed');
    f.innerHTML = r.feed.join('') || '<div class="muted">Press Play to replay the synthetic events.</div>';
    f.scrollTop = f.scrollHeight;
    document.getElementById('rp-pos').textContent = `${r.i} of ${c.events.length} events · ${r.alerts.length} ${r.alerts.length === 1 ? 'alert' : 'alerts'}`;
    document.getElementById('rp-play').textContent = r.timer ? 'Pause' : (r.i >= c.events.length ? 'Replay' : 'Play');
  }
  function tester(text) {
    const m = /^\s*"?([^\s"]+)/.exec(text || '');
    const base = m ? m[1].split(/[\\/]/).pop().toLowerCase() : '';
    const name = !base ? '' : base.endsWith('.exe') ? base : base + '.exe';
    const doc = { 'event.category': 'process', 'process.parent.name': 'explorer.exe', 'process.name': name, 'process.command_line': text };
    const rule = S.rules.find(x => x.id === 'S3');
    const hit = KQL.evaluate(KQL.parse(rule.kql), doc);
    const interp = ['powershell.exe', 'cmd.exe', 'mshta.exe'].includes(name);
    const markers = ['-enc', '-w hidden', 'http', 'DownloadString', 'iex', 'Invoke-Expression'].filter(k => text.includes(k));
    return `<span class="${hit ? 'vh' : 'vm'}" id="s3-result">${hit ? 'HIT' : 'MISS'}</span> <span class="small muted">${interp ? `interpreter ${esc(name)}` : `process "${esc(name || 'none')}" is not in the interpreter list`}; ${markers.length ? `markers found: ${markers.map(esc).join(', ')}` : 'no markers found (matching is case-sensitive)'}</span>`;
  }

  S.views.scenarios = {
    leave() { stop(); },
    render() {
      const id = SC[S.sub] ? S.sub : 'R1';
      if (S.rp.sc !== id) reset(id);
      const c = SC[id];
      const tabs = Object.keys(SC).map(k => `<button class="tab ${k === id ? 'on' : ''}" data-act="scTab" data-id="${k}">${esc(SC[k].title)}</button>`).join('');
      const steps = c.steps.map(([t, a, v], i) => `<div class="step"><b>${i + 1}</b><div>${esc(t)} ${a ? `<button class="link small" data-act="${a}" data-v="${esc(v)}">Open</button>` : ''}</div></div>`).join('');
      return `<div class="tabs" role="tablist">${tabs}</div><div class="grid sc"><div class="grid">
        <div class="card"><h2>${esc(c.title)}</h2><p style="margin:6px 0">${esc(c.objective)}</p><dl class="kv small"><dt>ATT&amp;CK</dt><dd>${c.mitre.map(m => `<span class="pill" title="${esc(MITRE[m] || '')}">${esc(m)}</span>`).join(' ')}</dd><dt>Fidelity</dt><dd>${esc(c.fidelity)}</dd><dt>Sensor sees</dt><dd>${esc(c.observes)}</dd></dl></div>
        <div class="card"><h2>Benign simulation command</h2><p class="tiny muted" style="margin:2px 0">Shown for reference only. Not executed. Replay plays back synthetic records.</p><pre class="cmd">${esc(c.cmd)}</pre></div>
        <div class="card"><h2>Investigation steps</h2>${steps}</div>
        ${id === 'S3' ? `<div class="card"><h2>Paste tester</h2><p class="tiny muted" style="margin:2px 0 6px">Your text is only compared with the S3 query in this page. Nothing runs.</p><input type="text" id="s3-input" style="width:100%" class="mono" data-inp="s3Test" value="powershell -NoProfile -Command &quot;Write-Host clickfix-lab&quot;" aria-label="Paste test text"><div style="margin-top:6px" id="s3-out">${tester('powershell -NoProfile -Command "Write-Host clickfix-lab"')}</div></div>` : ''}
      </div>
      <div class="grid"><div class="card"><div class="row" style="margin-bottom:8px"><h2>Replay</h2><span class="sp"></span><span class="small muted" id="rp-pos"></span></div>
        <div class="row" style="margin-bottom:8px"><button class="btn pri" id="rp-play" data-act="rpPlay">Play</button><button class="btn" data-act="rpStep">Step</button><button class="btn" data-act="rpEnd">Skip to end</button><button class="btn" data-act="rpReset">Reset</button>
          <label class="small muted">Speed <select data-chg="rpSpeed" aria-label="Replay speed">${[1, 4, 16].map(s => `<option value="${s}" ${s === S.rp.speed ? 'selected' : ''}>${s}×</option>`).join('')}</select></label><span class="sp"></span><button class="btn sm" data-act="scWin">Open window in Discover</button></div>
        <span class="simtag">${esc(D.label)}</span><div id="rp-stage"></div></div>
        <div class="card"><h2>Event feed</h2><div class="feed" id="rp-feed" aria-live="off"></div></div></div></div>`;
    },
    after() { draw(); },
  };
  inp.s3Test = el => { document.getElementById('s3-out').innerHTML = tester(el.value); };
  chg.rpSpeed = el => { S.rp.speed = +el.value; };
  Object.assign(act, {
    scTab: el => go('scenarios/' + el.dataset.id),
    rpPlay() {
      const r = S.rp;
      if (r.timer) { stop(); draw(); return; }
      if (r.i >= SC[r.sc].events.length) reset(r.sc);
      r.timer = 1; loop();
    },
    rpStep() { stop(); step(); },
    rpEnd() { stop(); while (step()); },
    rpReset() { reset(S.rp.sc); draw(); },
    scWin() { const c = SC[S.rp.sc]; S.from = parseT(c.win[0]); S.to = parseT(c.win[1]); S.views.discover.open(''); },
    scQuery(el) { const r = S.rules.find(x => x.id === el.dataset.v); S.from = App.T0; S.to = App.T1; S.views.discover.open(r.kql.replace(/\s+/g, ' ')); },
    scTree(el) { S.tr.lastPid = null; S.from = App.T0; S.to = App.T1; go('tree', { pid: el.dataset.v }); },
    scRule: el => { S.from = App.T0; S.to = App.T1; go('rules/' + encodeURIComponent(el.dataset.v)); },
    scTime(el) { const e = BY[el.dataset.v]; S.from = e._t - 30000; S.to = e._t + 90000; go('timeline', { sel: e._id }); },
    scPivot(el) { S.from = App.T0; S.to = App.T1; S.views.discover.open(`process.pid : ${el.dataset.v}`); },
  });
  App.SC = SC;
})();
