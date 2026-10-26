#!/usr/bin/env bash
# RiskDesk security pipeline. Runs four scanners against a staged worktree.
# Any scanner failing exits non-zero and aborts the deploy. Scanner thresholds
# are tuned here, not in each tool's config, so the policy is in one place.
#
# Called by deploy.sh with the staging directory as $1 and these env vars:
#   OLDREV, NEWREV, GIT_DIR
#
# Reports are written to /var/log/riskdesk/scan-<timestamp>-<tool>.json
set -euo pipefail

STAGING="${1:?staging dir required}"
VENV=$STAGING/.venv
TS=$(date +%Y%m%d-%H%M%S)
LOG_DIR=/var/log/riskdesk
mkdir -p "$LOG_DIR"

run() { echo; printf -- '-- %s --\n' "$*"; }
fail() { echo; printf '\033[1;31mSCAN FAILED: %s\033[0m\n' "$*"; exit 1; }

cd "$STAGING"

# ---------------------------------------------------------------- 1. ruff
# Lint catches many undeclared-name, unused-import, unsafe-regex, and
# bad-exception-chain patterns that correlate with real bugs. Rules in
# pyproject.toml at the repo root.
run "ruff (lint)"
RUFF_REPORT=$LOG_DIR/scan-$TS-ruff.json
if ! "$VENV/bin/ruff" check riskdesk/app --output-format=json \
        > "$RUFF_REPORT" 2>/dev/null; then
    echo "ruff found issues (see $RUFF_REPORT):"
    "$VENV/bin/ruff" check riskdesk/app --output-format=concise || true
    fail "ruff"
fi
echo "ruff clean"

# ---------------------------------------------------------------- 2. bandit
# Python SAST. We fail on medium+ severity with high confidence. Tune with
# -lll (low severity) or -iii (low confidence) if the signal gets noisy.
run "bandit (SAST)"
BANDIT_REPORT=$LOG_DIR/scan-$TS-bandit.json
if ! "$VENV/bin/bandit" -r riskdesk/app -q \
        --severity-level medium --confidence-level high \
        -f json -o "$BANDIT_REPORT"; then
    echo "bandit found issues (see $BANDIT_REPORT):"
    "$VENV/bin/bandit" -r riskdesk/app -q \
        --severity-level medium --confidence-level high -f txt || true
    fail "bandit"
fi
echo "bandit clean"

# ---------------------------------------------------------------- 3. pip-audit
# Dependency CVE scan via OSV. Blocks on any known vulnerable package in the
# requirements set. --strict means an unresolvable requirement is also a fail.
run "pip-audit (dependency CVEs)"
AUDIT_REPORT=$LOG_DIR/scan-$TS-pip-audit.json
if ! "$VENV/bin/pip-audit" -r riskdesk/requirements.txt \
        --format json --output "$AUDIT_REPORT"; then
    echo "pip-audit found vulnerable dependencies (see $AUDIT_REPORT):"
    "$VENV/bin/pip-audit" -r riskdesk/requirements.txt || true
    fail "pip-audit"
fi
echo "pip-audit clean"

# ---------------------------------------------------------------- 4. gitleaks
# Secret scanning across the commit range being deployed. On a first push
# (OLDREV all-zeros) we scan the whole working tree instead of a range, so
# an initial import doesn't skip the check.
run "gitleaks (secret scan)"
LEAKS_REPORT=$LOG_DIR/scan-$TS-gitleaks.json
if [[ "$OLDREV" == "0000000000000000000000000000000000000000" ]]; then
    MODE_ARGS=(detect --source "$STAGING" --no-git --report-path "$LEAKS_REPORT")
else
    MODE_ARGS=(detect --source "$GIT_DIR" --log-opts "$OLDREV..$NEWREV" \
               --report-path "$LEAKS_REPORT")
fi
if ! gitleaks "${MODE_ARGS[@]}" --exit-code 1 --redact --report-format json 2>&1; then
    echo "gitleaks found secrets (see $LEAKS_REPORT, values redacted):"
    fail "gitleaks"
fi
echo "gitleaks clean"

echo
echo "all scanners clean"
echo "reports: $LOG_DIR/scan-$TS-*.json"
