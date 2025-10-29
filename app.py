import os, json, base64
from functools import wraps
from flask import Flask, redirect, session, url_for, render_template
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
            return render_template(
                "unauthorized.html",
                title="Access denied",
                message="You lack the required role.",
                required_roles=sorted(required),
            ), 403
        return wrapper
    return deco

# ---------- routes ----------
@app.get("/")
def index():
    user = session.get("user")
    claims = user.get("claims", {}) if user else {}
    username = claims.get("preferred_username")
    roles = claims.get("_effective_roles", [])
    return render_template(
        "index.html",
        logged_in=bool(user),
        username=username or "Cyber analyst",
        roles=roles or [],
    )

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
    roles = claims.get("_effective_roles", [])
    return render_template(
        "profile.html",
        claims=json.dumps(claims, indent=2),
        roles=roles,
        username=claims.get("preferred_username") or "Cyber analyst",
        email=claims.get("email"),
        full_name=claims.get("name"),
    )

@app.get("/reports")
@require_roles({"admin","analyst"})
def reports():
    user = session.get("user", {})
    claims = user.get("claims", {})
    return render_template(
        "reports.html",
        username=claims.get("preferred_username") or "Cyber analyst",
        roles=claims.get("_effective_roles", []),
    )

@app.get("/admin")
@require_roles({"admin"})
def admin():
    user = session.get("user", {})
    claims = user.get("claims", {})
    return render_template(
        "admin.html",
        username=claims.get("preferred_username") or "Cyber analyst",
        roles=claims.get("_effective_roles", []),
    )

@app.errorhandler(403)
def forbidden(_):
    return render_template(
        "unauthorized.html",
        title="403 – Access denied",
        message="It looks like you do not have permissions for that action.",
        required_roles=[],
    ), 403

if __name__ == "__main__":
    app.run(debug=True, port=PORT)
