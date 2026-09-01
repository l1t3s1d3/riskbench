#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
[ -f .env ] || { cp .env.example .env; echo "Created .env from the template. Add credentials when you have them."; }
python3 -m app.cli init
echo "RiskDesk on http://127.0.0.1:8080"
python3 -m app.cli serve "$@"
