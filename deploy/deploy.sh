#!/usr/bin/env bash
# RiskDesk deploy pipeline. Called from the git post-receive hook with
# oldrev and newrev. Streams its output back over the SSH session, so what
# you see on `git push` is exactly what's happening on the VM.
#
# Stages, each must pass or the deploy aborts and the previous version keeps
# serving:
#   1. Export the new revision to a staging worktree
#   2. Install Python deps into a fresh venv subdirectory
#   3. Run the test suite
#   4. Run the security pipeline (ruff / bandit / pip-audit / gitleaks)
#   5. Rotate: current -> previous, staging -> current
#   6. Restart the service, verify /api/meta responds
#
# On failure after stage 5, rollback.sh is invoked automatically.

set -euo pipefail

OLDREV="${1:-0000000000000000000000000000000000000000}"
NEWREV="${2:?NEWREV required}"

APP_DIR=/opt/riskdesk
GIT_DIR=/srv/git/riskbench.git
DATA_DIR=/var/lib/riskdesk
LOG_DIR=/var/log/riskdesk
TS=$(date +%Y%m%d-%H%M%S)
LOG=$LOG_DIR/deploy-$TS.log

# Everything goes to both the SSH session and the on-disk log.
mkdir -p "$LOG_DIR"
exec > >(tee -a "$LOG") 2>&1

trap 'echo; echo "deploy failed. log: $LOG"' ERR

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m%s\033[0m\n' "$*"; }

echo "deploy $NEWREV at $TS"
echo "actor: ${USER:-unknown} via ${SSH_CONNECTION:-local}"

STAGING=$APP_DIR/staging
CURRENT=$APP_DIR/current
PREVIOUS=$APP_DIR/previous

# ----- 1. export working tree ---------------------------------------------

step "Exporting $NEWREV to $STAGING"
rm -rf "$STAGING"
mkdir -p "$STAGING"
git --git-dir="$GIT_DIR" archive "$NEWREV" | tar -x -C "$STAGING"
echo "$NEWREV" > "$STAGING/.deployed-rev"

# ----- 2. python deps -----------------------------------------------------

step "Installing Python dependencies"
VENV=$STAGING/.venv
PY_BIN=$(cat /etc/riskdesk/python-binary 2>/dev/null || echo python3.11)
"$PY_BIN" -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip wheel
"$VENV/bin/pip" install --quiet -r "$STAGING/riskdesk/requirements.txt"
# Scanners run inside the staging venv so they see the exact deps that will
# ship. Keep them pinned to known-good majors.
"$VENV/bin/pip" install --quiet 'ruff==0.6.*' 'bandit==1.7.*' 'pip-audit==2.7.*'

# ----- 3. tests -----------------------------------------------------------

step "Running tests"
( cd "$STAGING/riskdesk" && \
    RISKDESK_DB_URL="sqlite:///:memory:" \
    RISKDESK_AUTH_MODE=none \
    RISKDESK_SCHEDULER_ENABLED=0 \
    "$VENV/bin/python" -m pytest -q -p no:warnings )
ok "tests pass"

# ----- 4. security pipeline -----------------------------------------------

if [[ "${BYPASS_SCANS:-0}" == "1" ]]; then
    echo
    echo ":: BYPASS_SCANS=1 -- skipping security pipeline"
    echo ":: actor=${USER:-unknown} rev=$NEWREV connection=${SSH_CONNECTION:-local}" \
        >> "$LOG_DIR/bypass.log"
else
    step "Security pipeline"
    OLDREV="$OLDREV" NEWREV="$NEWREV" GIT_DIR="$GIT_DIR" \
        "$APP_DIR/security-scan.sh" "$STAGING"
    ok "security pipeline clean"
fi

# ----- 5. rotate ----------------------------------------------------------

step "Rotating release"
rm -rf "$PREVIOUS"
if [[ -d "$CURRENT" ]]; then
    mv "$CURRENT" "$PREVIOUS"
fi
mv "$STAGING" "$CURRENT"
chown -R riskdesk:riskdesk "$CURRENT"

# ----- 6. restart & smoke test --------------------------------------------

step "Restarting service"
sudo /bin/systemctl restart riskdesk
# First-time deploys: make sure the service is enabled for next boot. No-op
# if it is already enabled, so safe to run every time.
sudo /bin/systemctl enable riskdesk 2>/dev/null || true

# Service runs the additive migration at startup; wait for it to come up.
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if curl -fsS -o /dev/null http://127.0.0.1:8080/api/meta; then
        ok "service healthy on attempt $i"
        break
    fi
    if [[ $i == 10 ]]; then
        echo "service did not come up; rolling back"
        /opt/riskdesk/rollback.sh
        exit 1
    fi
done

step "Deployed $(cd "$CURRENT" && git describe --always --dirty 2>/dev/null || echo "$NEWREV")"
echo "log: $LOG"
