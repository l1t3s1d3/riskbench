#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found. Install Python 3.10+ first."
    echo "  Ubuntu/Debian: sudo apt install python3 python3-venv python3-pip"
    echo "  macOS:         brew install python3"
    echo "  RHEL/Fedora:   sudo dnf install python3"
    exit 1
fi

if [ ! -d .venv ]; then
    echo "Creating virtual environment..."
    if ! python3 -m venv .venv 2>/dev/null; then
        PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        echo ""
        echo "Error: Failed to create virtual environment."
        echo "On Ubuntu/Debian, the venv module is a separate package."
        echo "Install it with:"
        echo ""
        echo "  sudo apt install python3-venv python3-pip"
        echo ""
        echo "Or for your specific Python version:"
        echo ""
        echo "  sudo apt install python${PY_VER}-venv"
        echo ""
        exit 1
    fi
fi

source .venv/bin/activate
python3 -m pip install -q -r requirements.txt
[ -f .env ] || { cp .env.example .env; echo "Created .env from the template. Add credentials when you have them."; }
python3 -m app.cli init
echo "RiskDesk on http://127.0.0.1:8080"
python3 -m app.cli serve "$@"
