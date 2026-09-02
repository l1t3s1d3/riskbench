#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

MIN_PY_MAJOR=3
MIN_PY_MINOR=10

# --- Detect OS family ---------------------------------------------------------

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|pop|linuxmint|elementary|zorin) echo "debian" ;;
            fedora|rhel|centos|rocky|alma|ol)             echo "rhel"   ;;
            arch|manjaro|endeavouros)                      echo "arch"   ;;
            opensuse*|sles)                                echo "suse"   ;;
            *)                                             echo "linux"  ;;
        esac
    elif [ "$(uname)" = "Darwin" ]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

OS_FAMILY=$(detect_os)

# --- Install system packages if needed ----------------------------------------

install_packages() {
    local missing=("$@")
    echo ""
    echo "  Installing missing system packages: ${missing[*]}"
    echo ""
    case "$OS_FAMILY" in
        debian)
            sudo apt-get update -qq
            sudo apt-get install -y -qq "${missing[@]}"
            ;;
        rhel)
            sudo dnf install -y "${missing[@]}"
            ;;
        arch)
            sudo pacman -S --noconfirm "${missing[@]}"
            ;;
        suse)
            sudo zypper install -y "${missing[@]}"
            ;;
        macos)
            if command -v brew &>/dev/null; then
                brew install "${missing[@]}"
            else
                echo "Error: Homebrew not found. Install from https://brew.sh then re-run."
                exit 1
            fi
            ;;
        *)
            echo "Error: Cannot auto-install on this OS. Please install manually:"
            printf '  %s\n' "${missing[@]}"
            exit 1
            ;;
    esac
}

# --- Check Python 3 -----------------------------------------------------------

check_python() {
    if command -v python3 &>/dev/null; then
        return 0
    fi

    echo "  python3 not found — installing..."
    case "$OS_FAMILY" in
        debian) install_packages python3 ;;
        rhel)   install_packages python3 ;;
        arch)   install_packages python  ;;
        suse)   install_packages python3 ;;
        macos)  install_packages python3 ;;
        *)
            echo "Error: python3 not found. Install Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ manually."
            exit 1
            ;;
    esac

    if ! command -v python3 &>/dev/null; then
        echo "Error: python3 still not found after install attempt."
        exit 1
    fi
}

# --- Check Python version -----------------------------------------------------

check_python_version() {
    local ver
    ver=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local major minor
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)

    if [ "$major" -lt "$MIN_PY_MAJOR" ] || { [ "$major" -eq "$MIN_PY_MAJOR" ] && [ "$minor" -lt "$MIN_PY_MINOR" ]; }; then
        echo "Error: Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ required, found ${ver}."
        echo "Upgrade Python and try again."
        exit 1
    fi
    echo "  Python ${ver} — OK"
}

# --- Check pip and venv modules -----------------------------------------------

check_venv_and_pip() {
    local missing_pkgs=()
    local py_ver
    py_ver=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")

    if ! python3 -c "import venv" &>/dev/null; then
        case "$OS_FAMILY" in
            debian) missing_pkgs+=("python${py_ver}-venv") ;;
            rhel)   missing_pkgs+=("python3-libs") ;;
            *)      missing_pkgs+=("python3-venv") ;;
        esac
    fi

    if ! python3 -c "import pip" &>/dev/null; then
        case "$OS_FAMILY" in
            debian) missing_pkgs+=("python3-pip") ;;
            rhel)   missing_pkgs+=("python3-pip") ;;
            arch)   missing_pkgs+=("python-pip") ;;
            suse)   missing_pkgs+=("python3-pip") ;;
            macos)  ;; # pip ships with Homebrew python3
            *)      missing_pkgs+=("python3-pip") ;;
        esac
    fi

    if [ ${#missing_pkgs[@]} -gt 0 ]; then
        echo "  Missing Python modules: ${missing_pkgs[*]}"
        install_packages "${missing_pkgs[@]}"
    fi

    if ! python3 -c "import venv" &>/dev/null; then
        echo "Error: venv module still unavailable after install. Check your Python installation."
        exit 1
    fi
    echo "  pip and venv — OK"
}

# --- Main setup ---------------------------------------------------------------

echo "=== RiskDesk Setup ==="
echo ""

check_python
check_python_version
check_venv_and_pip

echo ""

# Create virtual environment
if [ ! -d .venv ]; then
    echo "  Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

echo "  Installing Python dependencies..."
python3 -m pip install -q -r requirements.txt

# Create .env from template on first run
if [ ! -f .env ]; then
    cp .env.example .env
    echo "  Created .env from template. Add source credentials when you have them."
fi

# Initialize database
python3 -m app.cli init

echo ""
echo "=== RiskDesk on http://127.0.0.1:8080 ==="
echo ""
python3 -m app.cli serve "$@"
