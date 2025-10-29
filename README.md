# CyberRisk Flask + Keycloak Lab (Linux)

Demonstration of integrating Flask with Keycloak (CyberRealm) for RBAC.

## Quick Start (Linux)

### 1. Start Keycloak
```bash
docker run -p 127.0.0.1:8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.4.2 start-dev
```

### 2. Setup Flask APP
```bash
cd iam-rbac-flask-linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
flask --app app run --debug --port 5000
```
Access the app at http://127.0.0.1:5000
