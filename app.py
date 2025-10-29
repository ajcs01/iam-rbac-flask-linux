import os, json, base64
from functools import wraps
from flask import Flask, redirect, session, url_for, abort, render_template_string
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

# --- config ---
load_dotenv()
FLASK_SECRET = os.getenv("FLASK_SECRET_KEY", "dev")
ISSUER       = os.getenv("KC_ISSUER", "http://127.0.0.1:8080/realms/CyberRealm").rstrip("/")
CLIENT_ID    = os.getenv("KC_CLIENT_ID", "risk-app")
CLIENT_SECRET= os.getenv("KC_CLIENT_SECRET") or None  # public client => blank
REDIRECT_URI = os.getenv("KC_REDIRECT_URI", "http://127.0.0.1:5050/callback/keycloak")
PORT         = int(os.getenv("PORT", "5050"))  # default to 5050 on macOS

app = Flask(__name__)
app.secret_key = FLASK_SECRET

oauth = OAuth(app)
keycloak = oauth.register(
    name="keycloak",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid profile email",
        "token_endpoint_auth_method": "none" if CLIENT_SECRET is None else "client_secret_basic",
    },
)

# ---------- minimal UI ----------
BASE = """
<!doctype html><html><head><meta charset="utf-8"><title>CyberRisk App</title>
<style>
 body{font-family:system-ui;margin:2rem} nav a{margin-right:1rem}
 .btn{border:1px solid #333;border-radius:8px;padding:.35rem .7rem;text-decoration:none}
 .badge{display:inline-block;border:1px solid #888;border-radius:999px;padding:2px 8px;margin-left:6px}
 pre{background:#f6f8fa;padding:1rem;border-radius:8px;overflow:auto}
</style></head><body>
<nav>
 <a href="{{ url_for('index') }}">Home</a>
 <a href="{{ url_for('profile') }}">Profile</a>
 <a href="{{ url_for('reports') }}">Reports</a>
 <a href="{{ url_for('admin') }}">Admin</a>
 {% if session.get('user') %}<a class="btn" href="{{ url_for('logout') }}">Logout</a>{% else %}
 <a class="btn" href="{{ url_for('login') }}">Login with Keycloak</a>{% endif %}
</nav><hr>{{ content|safe }}</body></html>
"""

def page(html): return render_template_string(BASE, content=html)

# ---------- helpers ----------
def parse_id_token(id_token: str):
    try:
        body = id_token.split('.')[1]
        body += '=' * (-len(body) % 4)
        return json.loads(base64.urlsafe_b64decode(body.encode()))
    except Exception:
        return {"_warning":"could not parse id_token"}

def extract_roles(claims: dict):
    roles = set()
    realm_access = claims.get("realm_access") or {}
    roles.update(realm_access.get("roles", []) or [])
    # (optional) also include client roles if you choose to use them:
    for _, rec in (claims.get("resource_access") or {}).items():
        roles.update(rec.get("roles", []) or [])
    return roles

def require_roles(required: set[str]):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            user = session.get("user")
            if not user:
                return redirect(url_for("login"))
            have = set(user.get("claims", {}).get("_effective_roles", []))
            if have.intersection(required):
                return fn(*a, **kw)
            return page("<h3>403 – Access denied</h3><p>You lack the required role.</p>"), 403
        return wrapper
    return deco

# ---------- routes ----------
@app.get("/")
def index():
    if not session.get("user"):
        return page("<h2>CyberRisk Reports App</h2><p>Use Keycloak to sign in.</p>")
    u = session["user"]["claims"].get("preferred_username") or "user"
    return page(f"<h2>Welcome, <code>{u}</code></h2><p>Try /profile, /reports, /admin.</p>")

@app.get("/login")
def login():
    return keycloak.authorize_redirect(REDIRECT_URI)

@app.get("/callback/keycloak")
def callback():
    token = keycloak.authorize_access_token()
    id_token = token.get("id_token")
    claims = parse_id_token(id_token) if id_token else {}
    roles = sorted(list(extract_roles(claims)))
    claims["_effective_roles"] = roles
    session["user"] = {"claims": claims, "id_token": id_token}
    return redirect(url_for("profile"))

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.get("/profile")
def profile():
    u = session.get("user")
    if not u:
        return redirect(url_for("login"))
    claims = u.get("claims", {})
    badges = " ".join([f"<span class='badge'>{r}</span>" for r in claims.get("_effective_roles", [])]) or "<em>none</em>"
    html = f"<h3>Profile & Token Claims</h3><p>Roles: {badges}</p><pre>{json.dumps(claims, indent=2)}</pre>"
    return page(html)

@app.get("/reports")
@require_roles({"admin","analyst"})
def reports():
    return page("<h3>Reports</h3><p>Access granted (admin or analyst).</p>")

@app.get("/admin")
@require_roles({"admin"})
def admin():
    return page("<h3>Admin</h3><p>Access granted (admin only).</p>")

@app.errorhandler(403)
def forbidden(_):
    return page("<h3>403 – Access denied</h3>"), 403

if __name__ == "__main__":
    app.run(debug=True, port=PORT)