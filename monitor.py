#!/usr/bin/env python3
"""Agent Monitor - live view of local AI agents on this Mac.

Read-only: it only observes (ps, lsof, ioreg, lms, local HTTP APIs, log files).
It never kills, unloads or edits anything. Run:  python3 monitor.py  ->  http://127.0.0.1:8790
"""
import glob
import json
import os
import re
import statistics
import subprocess
import threading
import time
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = 8790
POLL = 2.0
HOME = Path.home()
LMS = HOME / ".lmstudio/bin/lms"
LMS_LOGS = HOME / ".lmstudio/server-logs"
EAD = HOME / "Documents/EAD"
NCPU = os.cpu_count() or 1
MEM_TOTAL = int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True).stdout or 0)

# Which processes belong to which agent. First match wins.
GROUPS = [
    ("ead", "EAD pipeline", "Your multi-agent safety pipeline (Python, uses Qwen)", r"ead_pipeline\.py"),
    ("lms_mcp", "LM Studio MCP plugins", "Tools the Qwen chat can call (files, web fetch)", r"server-filesystem|mcp-server-fetch|\.lmstudio/extensions"),
    ("lmstudio", "LM Studio + Qwen", "Local model server on :1234", r"LM Studio\.app|\.lmstudio/"),
    ("ollama", "Ollama", "Second local model server on :11434", r"Ollama\.app|ollama serve|ollama runner"),
    ("desktop_cmd", "Desktop Commander MCP", "Shell/file access for Claude Desktop", r"desktop-commander"),
    ("claude_desktop", "Claude Desktop", "Desktop app and its helpers", r"/Claude\.app/"),
    ("claude_code", "Claude Code", "CLI agent sessions", r"(?-i:(^|/)claude( |$)|claude-code)"),
    ("copilot", "GitHub Copilot", "VS Code agent runtime", r"copilot-runtime|copilot-language-server|copilot-sdk"),
    ("other", "Other agent-like", "Unclassified python/node agent or MCP processes",
     r"(python|node|uv |uvx|npx).*(agent|mcp|crew|autogen|langgraph|langchain|openai|anthropic|llm)"),
]
GROUP_RE = [(k, n, d, re.compile(p, re.I)) for k, n, d, p in GROUPS]

LOCK = threading.Lock()
STATE = {"snapshot": {}, "history": deque(maxlen=150), "feed": deque(maxlen=200)}
_prev_cpu = {}
_prev_t = None
_slow = {"t": 0, "listen": [], "conns": {}}
_log = {"path": None, "pos": 0}
_gpu_busy_idle = 0


def sh(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def http_json(url, timeout=1.5):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


def cpu_secs(s):
    # ps "time": [[dd-]hh:]mm:ss.ss
    days = 0
    if "-" in s:
        d, s = s.split("-", 1)
        days = int(d)
    parts = [float(p) for p in s.split(":")]
    secs = 0.0
    for p in parts:
        secs = secs * 60 + p
    return secs + days * 86400


def etime_secs(s):
    days = 0
    if "-" in s:
        d, s = s.split("-", 1)
        days = int(d)
    secs = 0
    for p in s.split(":"):
        secs = secs * 60 + int(p)
    return secs + days * 86400


def processes():
    global _prev_t
    out = sh(["ps", "-Ao", "pid=,ppid=,rss=,time=,etime=,command="])
    now = time.time()
    dt = (now - _prev_t) if _prev_t else None
    procs, seen = [], {}
    for line in out.splitlines():
        p = line.split(None, 5)
        if len(p) < 6:
            continue
        pid, ppid, rss, t, et, cmd = int(p[0]), int(p[1]), int(p[2]), p[3], p[4], p[5]
        c = cpu_secs(t)
        seen[pid] = c
        cpu = 0.0
        if dt and pid in _prev_cpu:
            cpu = max(0.0, (c - _prev_cpu[pid]) / dt * 100)
        procs.append({"pid": pid, "ppid": ppid, "rss": rss * 1024, "cpu": cpu, "age": etime_secs(et), "cmd": cmd})
    _prev_cpu.clear()
    _prev_cpu.update(seen)
    _prev_t = now
    return procs


def classify(cmd):
    if "AgentMonitor/monitor.py" in cmd:
        return None
    for k, _, _, rx in GROUP_RE:
        if rx.search(cmd):
            return k
    return None


def short_cmd(cmd):
    cmd = cmd.replace(str(HOME), "~")
    cmd = re.sub(r"-e \\012function.*", "-e <LM Studio worker script>", cmd)
    cmd = re.sub(r"\s--(type|user-data-dir|lang|service-sandbox-type|utility-sub-type|field-trial|enable|disable|metrics|shared-files|seatbelt|message-loop|variations|crashpad|monitor)\S*", "", cmd)
    return cmd[:180]


def slow_scan():
    """lsof is comparatively slow, so refresh ports/connections every 10 s."""
    if time.time() - _slow["t"] < 10:
        return
    _slow["t"] = time.time()
    listen = []
    for line in sh(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]).splitlines()[1:]:
        f = line.split()
        if len(f) >= 9:
            listen.append({"pid": int(f[1]), "addr": f[8]})
    conns = {}
    for line in sh(["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED"]).splitlines()[1:]:
        f = line.split()
        if len(f) < 9 or "->" not in f[8]:
            continue
        remote = f[8].split("->", 1)[1]
        if remote.startswith(("127.", "[::1]", "localhost", "[fe80")):
            continue
        host = remote.rsplit(":", 1)[0]
        conns.setdefault(int(f[1]), set()).add(host)
    _slow["listen"] = listen
    _slow["conns"] = {k: sorted(v) for k, v in conns.items()}


def gpu():
    out = sh(["ioreg", "-r", "-d", "1", "-c", "IOAccelerator"])
    g = {}
    for key, name in (("Device Utilization %", "util"), ("In use system memory", "mem")):
        m = re.search(r'"%s"=(\d+)' % re.escape(key), out)
        if m:
            g[name] = int(m.group(1))
    return g


def memory():
    level = sh(["sysctl", "-n", "kern.memorystatus_level"]).strip()
    swap = sh(["sysctl", "-n", "vm.swapusage"])
    m = re.search(r"used = ([\d.]+)M", swap)
    free_pct = int(level) if level.isdigit() else None
    return {"free_pct": free_pct, "used_pct": (100 - free_pct) if free_pct is not None else None,
            "swap_mb": float(m.group(1)) if m else 0.0}


def lmstudio():
    info = {"up": False, "models": []}
    raw = sh([str(LMS), "ps", "--json"], timeout=4) if LMS.exists() else ""
    try:
        for m in json.loads(raw or "[]"):
            info["up"] = True
            last = m.get("lastUsedTime")
            info["models"].append({
                "id": m.get("identifier"), "name": m.get("displayName"), "size": m.get("sizeBytes"),
                "status": m.get("status"), "queued": m.get("queued", 0), "parallel": m.get("parallel"),
                "ctx": m.get("contextLength"), "ttl": m.get("ttlMs"),
                "idle_s": (time.time() - last / 1000) if last else None,
                "quant": (m.get("quantization") or {}).get("name"),
            })
    except Exception:
        pass
    if not info["up"]:
        info["up"] = http_json("http://127.0.0.1:1234/v1/models") is not None
    return info


NOISE = re.compile(r"LMSAuthenticator|\]\[DEBUG\]|Listing loaded|Prompt processing progress|^\s|^[{}\[\]]")
LOGLINE = re.compile(r"^\[(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)\]\[(\w+)\](?:\[([^\]]+)\])?\s*(.*)")


def tail_lms_log():
    files = sorted(glob.glob(str(LMS_LOGS / "*/*.log")), key=os.path.getmtime)
    if not files:
        return
    path = files[-1]
    if path != _log["path"]:
        _log["path"], _log["pos"] = path, max(0, os.path.getsize(path) - 20000)
    try:
        with open(path, "r", errors="ignore") as f:
            f.seek(_log["pos"])
            chunk = f.read()
            _log["pos"] = f.tell()
    except Exception:
        return
    for line in chunk.splitlines():
        if NOISE.search(line):
            continue
        m = LOGLINE.match(line)
        if not m:
            continue
        _, hhmm, lvl, src, msg = m.groups()
        if src and src.startswith("Plugin(") and lvl == "ERROR" and "stderr" in msg:
            lvl = "INFO"  # MCP plugins write normal output to stderr; LM Studio labels it ERROR
        msg = re.sub(r"Generated prediction:.*", "Finished a reply", msg)
        STATE["feed"].append({"t": hhmm, "src": "LM Studio" + (f" · {src}" if src else ""), "lvl": lvl, "msg": msg[:200]})


_ead_seen = set()


def ead():
    st = http_json("http://127.0.0.1:8765/status")
    res = {"up": st is not None, "status": st, "audit": None}
    if st:
        for e in st.get("events", [])[-80:]:
            if e not in _ead_seen:
                _ead_seen.add(e)
                m = re.match(r"\[(\d\d:\d\d:\d\d)\]\s*(.*)", e)
                if m:
                    lvl = "WARN" if re.search(r"major|STOP|Kill|error|fail", m.group(2), re.I) else "INFO"
                    STATE["feed"].append({"t": m.group(1), "src": "EAD pipeline", "lvl": lvl, "msg": m.group(2)[:200]})
    logs = sorted(glob.glob(str(EAD / "work/*/*/audit_log.jsonl")), key=os.path.getmtime)
    if logs:
        calls, starts, gates = [], 0, []
        for line in open(logs[-1], errors="ignore"):
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event") == "llm_call":
                calls.append({"stage": e.get("stage"), "call": e.get("call"), "s": e.get("seconds", 0),
                              "finish": e.get("finish_reason")})
            elif e.get("event") == "start":
                starts += 1
            elif e.get("event") == "gate":
                gates.append({"stage": e.get("stage"), "decision": e.get("decision")})
        res["audit"] = {"run": "/".join(Path(logs[-1]).parts[-3:-1]), "calls": calls, "starts": starts, "gates": gates}
    return res


def analyse(snap, procs):
    """Rules that turn raw observations into irregularities and suggestions."""
    global _gpu_busy_idle
    issues, tips = [], []

    def issue(sev, title, detail, fix=None, cmd=None):
        issues.append({"sev": sev, "title": title, "detail": detail, "fix": fix, "cmd": cmd})

    lm = snap["lmstudio"]
    generating = any(m["status"] not in (None, "idle") for m in lm["models"])
    for m in lm["models"]:
        gb = (m["size"] or 0) / 1e9
        if m["status"] == "idle" and m["idle_s"] and m["idle_s"] > 900 and not m["ttl"]:
            issue("warn", f"{m['name']} idle {int(m['idle_s'] // 60)} min, holding {gb:.0f} GB",
                  "The model has no idle timeout (TTL), so it keeps its memory and GPU allocation until you unload it.",
                  "Unload it when not in use, or reload it with an auto-unload TTL.",
                  f"~/.lmstudio/bin/lms unload {m['id']}   # or: lms load {m['id']} --ttl 1800")
        if m["queued"]:
            issue("warn", f"{m['queued']} request(s) queued on {m['name']}",
                  "Several agents are calling the model at once; they wait their turn.", None, None)

    olla = snap["ollama"]
    if olla["up"] and not olla["loaded"]:
        issue("info", "Ollama is running with nothing to serve",
              f"Ollama is listening on :11434 with {olla['n_models']} model(s) downloaded and none loaded. It duplicates LM Studio.",
              "Quit Ollama and remove it from Login Items if you only use LM Studio.",
              "osascript -e 'quit app \"Ollama\"'")

    e = snap["ead"]
    st = e["status"] or {}
    g = snap["groups"].get("ead")
    if st.get("state") == "finished" and g:
        issue("warn", "EAD pipeline finished but its process is still running",
              "The run is done, but the Python process still holds port 8765 for the dashboard. A new run can't use the same port.",
              "Stop it with Ctrl+C in its Terminal window, or:",
              f"kill {' '.join(str(p['pid']) for p in g['procs'])}")
    if st.get("stop_file"):
        issue("info", "EAD kill switch file STOP exists", "Agents will halt at the next step until it is removed.",
              None, f"rm {EAD}/STOP")
    fnd = st.get("findings") or {}
    first = next((int(m.group(1)) for ev in st.get("events", []) for m in [re.search(r"Reviewer found (\d+) major", ev)] if m), None)
    if first is not None and fnd.get("major", 0) >= first and st.get("loops"):
        approved = any("approved" in ev for ev in st.get("events", []) if "GATE (reviewer)" in ev)
        issue("crit" if approved else "warn",
              f"Review loop did not converge: {first} → {fnd.get('major')} major findings",
              "After the revision loop there are as many or more major findings than before."
              + (" The reviewer gate was still approved." if approved else ""),
              "Read 05_Review_log.xlsx before using the documents. Consider max_review_loops: 2 or thinking on (disable_thinking: false).",
              None)
    a = e["audit"]
    if a:
        by = {}
        for c in a["calls"]:
            by.setdefault(c["stage"], []).append(c["s"])
        allmed = statistics.median([c["s"] for c in a["calls"]]) if a["calls"] else 0
        for c in a["calls"]:
            if c["s"] > max(1200, 3 * allmed):
                issue("warn", f"Stalled model call: {c['stage']} #{c['call']} took {c['s'] / 60:.0f} min",
                      f"Typical call in this run: {allmed / 60:.1f} min. Usually the Mac slept, LM Studio was blocked, or several runs hit the model at once.",
                      "Keep the Mac awake during long runs.", "caffeinate -dims  # run in a terminal while the pipeline works")
            if c["finish"] not in ("stop", None):
                issue("warn", f"Truncated output: {c['stage']} #{c['call']} ended with '{c['finish']}'",
                      "The model hit max_tokens; the document may be cut off.", "Raise llm.max_tokens in autonomy.yaml.", None)
        if a["starts"] > 2:
            issue("info", f"Run {a['run']} was started {a['starts']} times",
                  "It was resumed repeatedly, so its audit trail spans several sessions.", None, None)

    for gk, grp in snap["groups"].items():
        for p in grp["procs"]:
            if re.search(r"@latest|npx -y (@[\w.-]+/)?[\w.-]+(\s|$)", p["cmd"]):
                issue("info", f"Unpinned package auto-runs: {grp['name']}",
                      "It starts through 'npx -y …@latest', so every launch downloads and runs whatever version is newest, without review.",
                      "Pin a version in the app's MCP config (e.g. @wonderwhy-er/desktop-commander@0.x.y).", None)
                break
        for p in grp["procs"]:
            if p["ppid"] == 1 and gk in ("desktop_cmd", "lms_mcp", "other") :
                issue("warn", f"Orphaned process: {grp['name']} (pid {p['pid']})",
                      "Its parent exited, but it is still running.", None, f"kill {p['pid']}")
        ext = sorted({h for p in grp["procs"] for h in _slow["conns"].get(p["pid"], [])})
        grp["external"] = ext
        if ext and gk in ("ead", "ollama"):
            issue("warn", f"{grp['name']} has internet connections",
                  f"Expected offline, but it is connected to: {', '.join(ext[:4])}", None, None)
        for l in grp["listen"]:
            if l.startswith(("*:", "0.0.0.0", "[::]:")):
                issue("warn", f"{grp['name']} listens on all interfaces ({l})",
                      "Other devices on your network can reach this port.", "Bind it to 127.0.0.1.", None)

    gu = snap["gpu"].get("util")
    _gpu_busy_idle = _gpu_busy_idle + 1 if (gu is not None and gu > 60 and not generating) else 0
    if _gpu_busy_idle >= 5:
        issue("warn", f"GPU {gu}% busy while no model is generating",
              "Something other than your local model is using the GPU (often a browser tab, video, or another app).",
              "Check Activity Monitor → Window → GPU History, and the GPU % column.", None)
    mem = snap["mem"]
    if mem["free_pct"] is not None and mem["free_pct"] < 15:
        issue("crit", f"Memory pressure: only {mem['free_pct']}% free", "Loading or running models will be slow or fail.",
              "Unload unused models.", None)
    if mem["swap_mb"] > 1024:
        issue("warn", f"Swapping {mem['swap_mb'] / 1024:.1f} GB", "Disk swap slows model inference heavily.", None, None)

    tips += [
        {"title": "Set an idle TTL for Qwen", "detail": "LM Studio → Developer → model settings → 'Auto unload if idle'. 30 min frees 16 GB automatically."},
        {"title": "One model server is enough", "detail": "Ollama and LM Studio both run in the background. Keep the one your agents use (LM Studio)."},
        {"title": "Parallel 4 on a 27B model", "detail": "With parallel_agents: true, agents share 4 slots on one model. Each slot is slower, so a single run doesn't finish faster. Set parallel 1–2 for steadier latency."},
        {"title": "Keep the Mac awake during runs", "detail": "Add 'caffeinate -i' to 'Run EAD Pipeline.command' so a 25-min run doesn't stall when the Mac sleeps."},
        {"title": "Pin MCP server versions", "detail": "Replace '@latest' and 'npx -y' with fixed versions in Claude Desktop and LM Studio mcp.json."},
    ]
    sev_rank = {"crit": 0, "warn": 1, "info": 2}
    issues.sort(key=lambda i: sev_rank[i["sev"]])
    return issues, tips


def collect():
    slow_scan()
    procs = processes()
    groups = {}
    meta = {k: (n, d) for k, n, d, _ in GROUPS}
    for p in procs:
        k = classify(p["cmd"])
        if not k:
            continue
        g = groups.setdefault(k, {"key": k, "name": meta[k][0], "desc": meta[k][1], "procs": [], "cpu": 0.0, "rss": 0,
                                  "age": 0, "listen": []})
        g["procs"].append({"pid": p["pid"], "ppid": p["ppid"], "cpu": round(p["cpu"], 1), "rss": p["rss"],
                           "age": p["age"], "cmd": short_cmd(p["cmd"])})
        g["cpu"] += p["cpu"]
        g["rss"] += p["rss"]
        g["age"] = max(g["age"], p["age"])
    pid2g = {p["pid"]: k for k, g in groups.items() for p in g["procs"]}
    for l in _slow["listen"]:
        k = pid2g.get(l["pid"])
        if k and l["addr"] not in groups[k]["listen"]:
            groups[k]["listen"].append(l["addr"])
    for g in groups.values():
        g["procs"].sort(key=lambda p: -p["rss"])
        g["cpu"] = round(g["cpu"], 1)

    total_cpu = sum(p["cpu"] for p in procs) / NCPU
    olla_ps = http_json("http://127.0.0.1:11434/api/ps")
    olla_tags = http_json("http://127.0.0.1:11434/api/tags")
    tail_lms_log()
    snap = {
        "time": time.strftime("%H:%M:%S"),
        "host": {"ncpu": NCPU, "mem_total": MEM_TOTAL},
        "cpu": round(min(total_cpu, 100), 1),
        "mem": memory(),
        "gpu": gpu(),
        "lmstudio": lmstudio(),
        "ollama": {"up": olla_ps is not None, "loaded": [m.get("name") for m in (olla_ps or {}).get("models", [])],
                   "n_models": len((olla_tags or {}).get("models", []))},
        "ead": ead(),
        "groups": groups,
    }
    snap["issues"], snap["tips"] = analyse(snap, procs)
    with LOCK:
        STATE["history"].append({"t": snap["time"], "cpu": snap["cpu"], "mem": snap["mem"]["used_pct"],
                                 "gpu": snap["gpu"].get("util"),
                                 "groups": {k: g["cpu"] for k, g in groups.items()}})
        snap["history"] = list(STATE["history"])
        snap["feed"] = sorted(list(STATE["feed"])[-80:], key=lambda f: f["t"])
        STATE["snapshot"] = snap


def loop():
    while True:
        try:
            collect()
        except Exception as ex:  # keep the monitor alive whatever happens
            STATE["feed"].append({"t": time.strftime("%H:%M:%S"), "src": "monitor", "lvl": "ERROR", "msg": repr(ex)[:200]})
        time.sleep(POLL)


PAGE = (Path(__file__).parent / "dashboard.html")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/api/snapshot"):
            with LOCK:
                body = json.dumps(STATE["snapshot"], default=list).encode()
            ctype = "application/json"
        else:
            body, ctype = PAGE.read_bytes(), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    threading.Thread(target=loop, daemon=True).start()
    print(f"Agent Monitor running at http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
