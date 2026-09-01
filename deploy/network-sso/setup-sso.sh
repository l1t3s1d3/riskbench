#!/usr/bin/env bash
set -euo pipefail

echo "=== RiskDesk SSO Deployment Setup ==="
echo ""

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DEPLOY_DIR"

# Generate cookie secret if not set
if grep -q "^OAUTH_COOKIE_SECRET=$" .env 2>/dev/null || [ ! -f .env ]; then
    echo "Generating .env from example..."
    cp -n .env.example .env
    COOKIE_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    sed -i "s|^OAUTH_COOKIE_SECRET=.*|OAUTH_COOKIE_SECRET=${COOKIE_SECRET}|" .env
    echo "  Cookie secret generated."
fi

# Create self-signed certs if none exist
if [ ! -d certs ]; then
    echo "Creating self-signed TLS certificate (replace with real certs for production)..."
    mkdir -p certs
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout certs/key.pem -out certs/cert.pem \
        -subj "/CN=riskdesk.local/O=RiskDesk" 2>/dev/null
    echo "  Self-signed cert created at certs/"
fi

echo ""
echo "Before starting, edit .env and set:"
echo "  1. OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET from your IdP"
echo "  2. OAUTH_ISSUER_URL for your OIDC provider"
echo "     Azure AD:  https://login.microsoftonline.com/<tenant-id>/v2.0"
echo "     Okta:      https://<domain>.okta.com"
echo "     Keycloak:  https://<host>/realms/<realm>"
echo "  3. TLS_CERT_PATH and TLS_KEY_PATH for production certs"
echo ""
echo "Then run:"
echo "  docker compose -f docker-compose.sso.yml up -d"
echo ""
echo "First run will also need:"
echo "  docker compose -f docker-compose.sso.yml run --rm riskdesk init"
