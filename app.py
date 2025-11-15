"""
app.py — EMI SUPER BOT (Premium Top, single-file, in-memory)
Features:
- Register / Login / Logout
- Passwords hashed with bcrypt (initial users + generated passwords)
- Admin panel (create users, generate/revoke premium codes)
- Premium codes in-memory, webhook skeleton for Gumroad
- Free vs Premium behaviour: free daily limit, premium unlimited
- History stored in memory (per-user)
- Frontend: modern chat UI, typing indicator, admin pages
- Uses Groq client for model calls (read GROQ_API_KEY from env)
"""

import os
import time
import secrets
import json
from datetime import datetime
from functools import wraps
from hashlib import sha1
from hmac import new as hmac_new

from flask import (
    Flask, request, jsonify, session, render_template_string,
    redirect, url_for
)
import bcrypt
from groq import Groq  # expected to be installed and usable

# ---------------------------
# Configuration / ENV
# ---------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "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")
FLASK_SECRET = os.getenv("FLASK_SECRET", "n9F4n3l0X8vA71K2sP0dF82LwqM1zR6Q")
ADMIN_PASSWORD_ENV = os.getenv("ADMIN_PASSWORD", None)  # optional quick admin pass
BUY_LINK = os.getenv("BUY_LINK", "https://your-gumroad-or-pay-link.example")
GUMROAD_SECRET = os.getenv("GUMROAD_SECRET", None)
PORT = int(os.getenv("PORT", "10000"))
DEBUG = os.getenv("DEBUG", "0") == "1"

if not FLASK_SECRET:
    # generate a stable secret for the process lifetime
    FLASK_SECRET = secrets.token_urlsafe(32)

if not GROQ_API_KEY:
    print("WARNING: GROQ_API_KEY is empty. Set it in environment before production.")

app = Flask(__name__)
app.secret_key = FLASK_SECRET

client = Groq(api_key=GROQ_API_KEY)

# ---------------------------
# In-memory stores
# ---------------------------
# NOTE: These are created at startup. For persistent production, replace with DB.
USERS = {}
VALID_PREMIUM_CODES = set()
USED_PREMIUM_CODES = set()

FREE_DAILY_LIMIT = 20            # free messages per day
HISTORY_FREE = 8                 # last pairs (user+bot) used for context for free
HISTORY_PREMIUM = 40             # for premium users

# ---------------------------
# INITIAL USERS (hashed passwords inserted)
# Passwords were generated and hashed below; see assistant message for plaintext.
# ---------------------------
# Generated plaintext passwords (for your reference):
# admin:  sB5Zj_@=ymQ!QGmd
# utente1: efKgOaM^H0Uiq*
# premiumtester: CtBVZ2)i!j4AosyT

USERS["admin"] = {
    # bcrypt hash of "sB5Zj_@=ymQ!QGmd"
    "password_hash": bcrypt.hashpw(b"sB5Zj_@=ymQ!QGmd", bcrypt.gensalt()),
    "premium": True,
    "is_admin": True,
    "created_at": datetime.utcnow().isoformat(),
    "history": [],
    "daily_count": {"date": datetime.utcnow().strftime("%Y-%m-%d"), "count": 0}
}

USERS["utente1"] = {
    # bcrypt hash of "efKgOaM^H0Uiq*"
    "password_hash": bcrypt.hashpw(b"efKgOaM^H0Uiq*", bcrypt.gensalt()),
    "premium": False,
    "is_admin": False,
    "created_at": datetime.utcnow().isoformat(),
    "history": [],
    "daily_count": {"date": datetime.utcnow().strftime("%Y-%m-%d"), "count": 0}
}

USERS["premiumtester"] = {
    # bcrypt hash of "CtBVZ2)i!j4AosyT"
    "password_hash": bcrypt.hashpw(b"CtBVZ2)i!j4AosyT", bcrypt.gensalt()),
    "premium": True,
    "is_admin": False,
    "created_at": datetime.utcnow().isoformat(),
    "history": [],
    "daily_count": {"date": datetime.utcnow().strftime("%Y-%m-%d"), "count": 0}
}

# ---------------------------
# Helpers
# ---------------------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        uname = session.get("username")
        if not uname:
            return redirect(url_for("login", next=request.path))
        u = USERS.get(uname)
        if u and u.get("is_admin"):
            return f(*args, **kwargs)
        # fallback to ADMIN_PASSWORD_ENV via query/header/form for convenience
        supplied = request.args.get("admin_pw") or request.form.get("admin_pw") or request.headers.get("X-Admin-Pw")
        if ADMIN_PASSWORD_ENV and supplied == ADMIN_PASSWORD_ENV:
            return f(*args, **kwargs)
        return "Admin access required", 403
    return wrapped

def now_ymd():
    return datetime.utcnow().strftime("%Y-%m-%d")

def reset_daily_if_needed(u):
    today = now_ymd()
    dc = u.setdefault("daily_count", {"date": today, "count": 0})
    if dc.get("date") != today:
        dc["date"] = today
        dc["count"] = 0

def increment_daily(u):
    reset_daily_if_needed(u)
    u["daily_count"]["count"] += 1
    return u["daily_count"]["count"]

def user_message_count(u):
    reset_daily_if_needed(u)
    return u["daily_count"]["count"]

def verify_gumroad_signature(payload_bytes, sig_header):
    # skeleton: adapt if Gumroad uses different scheme
    if not GUMROAD_SECRET:
        return True
    if not sig_header:
        return False
    computed = hmac_new(GUMROAD_SECRET.encode(), payload_bytes, sha1).hexdigest()
    return computed == sig_header

# ---------------------------
# HTML templates (single-file UI)
# ---------------------------
BASE_HTML = """
<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>EMI SUPER BOT — Premium</title>
  <style>
    body{font-family:Inter, system-ui, Arial; margin:0; background:#0b1220; color:#e6eef8}
    header{display:flex;justify-content:space-between;padding:12px 20px;background:rgba(255,255,255,0.02)}
    .container{max-width:1100px;margin:20px auto;padding:16px}
    .panel{background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01)); border-radius:12px;padding:16px;}
    .row{display:flex;gap:16px}
    .col-3{width:320px}
    .col-flex{flex:1}
    .chat-window{height:520px; display:flex; flex-direction:column}
    .messages{flex:1; overflow:auto; padding:12px; display:flex; flex-direction:column; gap:8px}
    .bubble{max-width:72%; padding:10px 12px; border-radius:12px}
    .bubble.bot{align-self:flex-start; background:rgba(255,255,255,0.04)}
    .bubble.user{align-self:flex-end; background:linear-gradient(90deg,#0ea5a4,#06b6d4)}
    .controls{display:flex;gap:8px;padding:12px;border-top:1px solid rgba(255,255,255,0.02)}
    textarea{flex:1; min-height:56px; border-radius:8px; background:transparent; color:inherit; border:1px solid rgba(255,255,255,0.04); padding:8px}
    button{background:#10b981;border:none;color:#012018;padding:10px 14px;border-radius:8px;font-weight:700}
    .small{font-size:12px;color:#94a3b8}
    form.inline{display:flex;gap:8px;align-items:center}
    a.link{color:#9be7d6}
    @media(max-width:900px){.row{flex-direction:column}.col-3{width:100%}}
  </style>
</head>
<body>
<header>
  <div class="brand">EMI SUPER BOT — Premium Top</div>
  <div>
    {% if username %}
      <span class="small">Ciao, <strong>{{ username }}</strong></span>
      &nbsp;&nbsp;
      <a class="link" href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a class="link" href="{{ url_for('login') }}">Login</a> &nbsp;
      <a class="link" href="{{ url_for('register') }}">Register</a>
    {% endif %}
  </div>
</header>
<div class="container">
  {% block content %}{% endblock %}
</div>
</body>
</html>
"""

HOME_HTML = """
{% extends base %}
{% block content %}
<div class="row">
  <div class="col-flex panel">
    <div class="chat-window">
      <div style="display:flex;justify-content:space-between;align-items:center;padding-bottom:8px">
        <div><strong>EMI SUPER BOT</strong><div class="small">Assistente intelligente</div></div>
        <div><span class="small">Plan: <strong>{{ plan|upper }}</strong></span></div>
      </div>

      <div class="messages" id="messages">
        {% for m in history %}
          <div class="bubble {{ 'user' if m.role=='user' else 'bot' }}">{{ m.content }}</div>
        {% endfor %}
      </div>

      <div class="controls">
        <textarea id="prompt" placeholder="Scrivi qualcosa..."></textarea>
        <button id="sendBtn">Invia</button>
      </div>
      <div class="small" style="padding:8px 12px">Limite giornaliero free: {{ free_limit }} — Usati oggi: {{ used_today }}</div>
    </div>
  </div>

  <div class="col-3 panel">
    <div style="margin-bottom:12px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div><strong>{{ username or 'Ospite' }}</strong><div class="small">Account</div></div>
        <div style="width:44px;height:44px;border-radius:999px;background:#0284c7;display:flex;align-items:center;justify-content:center">U</div>
      </div>
    </div>

    <div style="margin-bottom:12px"><strong>Account</strong>
      <div class="small">Tipo: <strong>{{ plan }}</strong></div>
      <div class="small">Creato: {{ created_at }}</div>
      <div style="margin-top:8px">
        {% if not premium %}
        <form action="{{ url_for('upgrade') }}" method="post" class="inline">
          <input name="code" placeholder="Codice premium">
          <button type="submit">Usa codice</button>
        </form>
        <div style="margin-top:8px">
          <button onclick="window.open('{{ buy_link }}','_blank')">Compra Premium</button>
        </div>
        {% else %}
        <div class="small">Sei Premium — grazie! 💎</div>
        {% endif %}
      </div>
    </div>

    <div><strong>Azioni</strong>
      <div style="margin-top:8px">
        <form action="{{ url_for('clear_history') }}" method="post"><button type="submit">Pulisci cronologia</button></form>
      </div>
    </div>

    <div style="margin-top:12px"><strong>Admin</strong>
      <div class="small">Vai a <a href="{{ url_for('admin') }}">Admin Panel</a> (protetto)</div>
    </div>
  </div>
</div>

<script>
const sendBtn = document.getElementById('sendBtn');
const prompt = document.getElementById('prompt');
const messagesEl = document.getElementById('messages');

function appendMessage(text, who){
  const d = document.createElement('div');
  d.className = 'bubble ' + (who==='user'?'user':'bot');
  d.textContent = text;
  messagesEl.appendChild(d);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

sendBtn.addEventListener('click', async ()=>{
  const txt = prompt.value.trim();
  if(!txt) return;
  appendMessage(txt,'user');
  prompt.value = '';
  const typing = document.createElement('div');
  typing.className = 'bubble bot';
  typing.textContent = 'EMI sta scrivendo…';
  messagesEl.appendChild(typing);
  messagesEl.scrollTop = messagesEl.scrollHeight;

  const res = await fetch('/chat', {
    method:'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({message: txt})
  });
  const data = await res.json();
  messagesEl.removeChild(typing);
  if(data.error){
    appendMessage("Errore: "+data.error,'bot');
  } else {
    appendMessage(data.reply,'bot');
  }
});
</script>
{% endblock %}
"""

AUTH_HTML = """
{% extends base %}
{% block content %}
<div class="panel" style="max-width:520px;margin:0 auto">
  <h2>{{ title }}</h2>
  <form method="post">
    <div style="margin-bottom:8px"><label>Username<br><input name="username" required style="width:100%;padding:8px;border-radius:6px"></label></div>
    <div style="margin-bottom:8px"><label>Password<br><input name="password" type="password" required style="width:100%;padding:8px;border-radius:6px"></label></div>
    {% if extra %}<div style="margin-bottom:8px">{{ extra }}</div>{% endif %}
    <div><button type="submit">{{ button }}</button></div>
  </form>
  <div class="small" style="margin-top:8px">Nota: demo in-memory. Cambia password e usa DB per produzione.</div>
</div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends base %}
{% block content %}
<div class="panel">
  <h2>Admin Panel</h2>

  <div style="margin-top:12px">
    <h3>Utenti</h3>
    <table style="width:100%;border-collapse:collapse">
      <tr><th>Name</th><th>Premium</th><th>Admin</th><th>Created</th><th>Actions</th></tr>
      {% for uname,u in users.items() %}
      <tr>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ uname }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ 'YES' if u.premium else 'NO' }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ 'YES' if u.is_admin else 'NO' }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ u.created_at }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">
          <form style="display:inline" action="{{ url_for('admin_toggle_premium', username=uname) }}" method="post"><button type="submit">Toggle Premium</button></form>
          <form style="display:inline" action="{{ url_for('admin_delete_user', username=uname) }}" method="post"><button type="submit">Delete</button></form>
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div style="margin-top:12px">
    <h3>Generate Premium Codes</h3>
    <form method="post" action="{{ url_for('admin_generate_codes') }}">
      <input name="n" type="number" value="3" min="1" max="200">
      <button type="submit">Generate</button>
    </form>
    <div style="margin-top:8px"><strong>Valid codes</strong>
      <div style="background:#061220;padding:8px;border-radius:6px;max-height:160px;overflow:auto">
        {% for c in codes %}
          <div>{{ c }} {% if c in used %}<span class="small"> (USED)</span>{% endif %}</div>
        {% endfor %}
      </div>
    </div>
  </div>

  <div style="margin-top:12px">
    <h3>Create user</h3>
    <form method="post" action="{{ url_for('admin_create_user') }}">
      <input name="username" placeholder="username" required>
      <input name="password" placeholder="password" required>
      <label><input type="checkbox" name="is_admin"> is admin</label>
      <button type="submit">Create</button>
    </form>
  </div>
</div>
{% endblock %}
"""

# ---------------------------
# Routes: Register / Login / Logout
# ---------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uname = (request.form.get("username") or "").strip()
        pw = (request.form.get("password") or "")
        if not uname or not pw:
            return "Username and password required", 400
        if uname in USERS:
            return "Username already exists", 400
        USERS[uname] = {
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
            "premium": False,
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        session["username"] = uname
        return redirect(url_for("home"))
    return render_template_string(AUTH_HTML, base=BASE_HTML, title="Register", button="Create account", extra=None, username=None)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        uname = (request.form.get("username") or "").strip()
        pw = (request.form.get("password") or "")
        if not uname or not pw:
            return "Username and password required", 400
        u = USERS.get(uname)
        if not u:
            return "Invalid credentials", 400
        if bcrypt.checkpw(pw.encode(), u["password_hash"]):
            session["username"] = uname
            return redirect(url_for("home"))
        return "Invalid credentials", 400
    return render_template_string(AUTH_HTML, base=BASE_HTML, title="Login", button="Login", extra=None, username=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------
# Home & Chat
# ---------------------------
@app.route("/")
@login_required
def home():
    uname = session.get("username")
    u = USERS.get(uname)
    plan = "premium" if u.get("premium") else "free"
    used = user_message_count(u)
    history = [{"role": m["role"], "content": m["content"]} for m in u.get("history", [])[-(HISTORY_PREMIUM*2):]]
    return render_template_string(
        HOME_HTML, base=BASE_HTML, username=uname, plan=plan, premium=u.get("premium"),
        created_at=u.get("created_at"), buy_link=BUY_LINK, history=history,
        free_limit=FREE_DAILY_LIMIT, used_today=used
    )

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    uname = session.get("username")
    u = USERS.get(uname)
    if not u:
        return jsonify({"error": "User not found"}), 400

    data = request.get_json() or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Empty message"}), 400

    # daily free limit
    if not u.get("premium"):
        count = increment_daily(u)
        if count > FREE_DAILY_LIMIT:
            return jsonify({"error": "Free daily limit reached. Upgrade to premium."}), 429

    # prepare history (last N messages)
    max_pairs = HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE
    recent = u.get("history", [])[-(max_pairs*2):]
    ctx = [{"role":"system", "content":"Sei EMI SUPER BOT. Rispondi nella stessa lingua dell'utente."}]
    for m in recent:
        ctx.append({"role": m["role"], "content": m["content"]})
    ctx.append({"role": "user", "content": message})

    # select model
    model = "llama-3.1-70b" if u.get("premium") else "llama-3.1-8b-instant"

    try:
        resp = client.chat.completions.create(
            model=model,
            messages=ctx
        )
        ai_text = resp.choices[0].message.content
    except Exception as exc:
        return jsonify({"error": f"Model API error: {str(exc)}"}), 500

    # store history
    u.setdefault("history", []).append({"role":"user","content": message, "ts": time.time()})
    u.setdefault("history", []).append({"role":"bot","content": ai_text, "ts": time.time()})
    # trim
    max_items = (HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE) * 2
    if len(u["history"]) > max_items:
        u["history"] = u["history"][-max_items:]

    return jsonify({"reply": ai_text})

# ---------------------------
# Account actions
# ---------------------------
@app.route("/upgrade", methods=["POST"])
@login_required
def upgrade():
    uname = session.get("username")
    code = (request.form.get("code") or "").strip()
    if not code:
        return "No code provided", 400
    if code in USED_PREMIUM_CODES:
        return "Code already used", 400
    if code not in VALID_PREMIUM_CODES:
        return "Invalid code", 400
    USED_PREMIUM_CODES.add(code)
    USERS[uname]["premium"] = True
    return redirect(url_for("home"))

@app.route("/clear_history", methods=["POST"])
@login_required
def clear_history():
    uname = session.get("username")
    USERS[uname]["history"] = []
    return redirect(url_for("home"))

# ---------------------------
# Admin routes
# ---------------------------
@app.route("/admin")
@admin_required
def admin():
    uv = {}
    for k,v in USERS.items():
        uv[k] = type("U", (), {"premium": v.get("premium"), "is_admin": v.get("is_admin"), "created_at": v.get("created_at")})
    return render_template_string(ADMIN_HTML, base=BASE_HTML, users=uv, codes=sorted(list(VALID_PREMIUM_CODES)), used=USED_PREMIUM_CODES, username=session.get("username"))

@app.route("/admin/generate_codes", methods=["POST"])
@admin_required
def admin_generate_codes():
    n = int(request.form.get("n", "3"))
    n = max(1, min(n, 200))
    created = []
    for _ in range(n):
        code = secrets.token_hex(6)
        VALID_PREMIUM_CODES.add(code)
        created.append(code)
    return jsonify({"created": created})

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    uname = (request.form.get("username") or "").strip()
    pw = (request.form.get("password") or "").strip()
    is_admin = bool(request.form.get("is_admin"))
    if not uname or not pw:
        return "username and password required", 400
    if uname in USERS:
        return "exists", 400
    USERS[uname] = {
        "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
        "premium": False,
        "is_admin": is_admin,
        "created_at": datetime.utcnow().isoformat(),
        "history": [],
        "daily_count": {"date": now_ymd(), "count": 0}
    }
    return redirect(url_for("admin"))

@app.route("/admin/toggle_premium/<username>", methods=["POST"])
@admin_required
def admin_toggle_premium(username):
    if username not in USERS:
        return "no user", 400
    USERS[username]["premium"] = not USERS[username].get("premium", False)
    return redirect(url_for("admin"))

@app.route("/admin/delete_user/<username>", methods=["POST"])
@admin_required
def admin_delete_user(username):
    if username in USERS:
        del USERS[username]
    return redirect(url_for("admin"))

# ---------------------------
# Admin API: codes
# ---------------------------
@app.route("/admin/codes", methods=["GET"])
@admin_required
def admin_codes():
    return jsonify({"valid": list(VALID_PREMIUM_CODES), "used": list(USED_PREMIUM_CODES)})

@app.route("/admin/revoke_code", methods=["POST"])
@admin_required
def admin_revoke_code():
    code = request.form.get("code")
    if code in VALID_PREMIUM_CODES:
        VALID_PREMIUM_CODES.remove(code)
    return redirect(url_for("admin"))

# ---------------------------
# Webhook: Gumroad skeleton
# ---------------------------
@app.route("/webhook/gumroad", methods=["POST"])
def gumroad_webhook():
    payload = request.get_data()
    sig = request.headers.get("X-Gumroad-Signature") or request.headers.get("x-gumroad-signature")
    if GUMROAD_SECRET:
        if not verify_gumroad_signature(payload, sig):
            return "invalid signature", 403
    data = request.form.to_dict() or request.get_json(silent=True) or {}
    # create code per purchase (demo). In production, email the buyer
    code = secrets.token_hex(6)
    VALID_PREMIUM_CODES.add(code)
    return jsonify({"ok": True, "code": code})

# ---------------------------
# Health
# ---------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": time.time()})

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    print("EMI SUPER BOT starting. Set GROQ_API_KEY in env before production.")
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
