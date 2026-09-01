#!/bin/bash
# One-shot Trivy scan for use in CI pipeline steps.
# Usage: scan.sh <type> <target> [severity-gate]
#   type: image | fs | config
#   target: image name or path
#   severity-gate: CRITICAL | HIGH | MEDIUM (fails if findings at or above this level)

set -euo pipefail

TYPE="${1:?Usage: scan.sh <image|fs|config> <target> [severity-gate]}"
TARGET="${2:?Provide a target (image name or path)}"
GATE="${3:-CRITICAL}"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUTFILE="/results/trivy-${TYPE}-${TIMESTAMP}.json"

echo "=== Trivy scan: ${TYPE} ${TARGET} ==="
echo "Severity gate: ${GATE}"

trivy "${TYPE}" \
  --format json \
  --output "${OUTFILE}" \
  --severity "CRITICAL,HIGH,MEDIUM,LOW" \
  --scanners vuln,secret,misconfig \
  --exit-code 0 \
  "${TARGET}"

echo "Results written to ${OUTFILE}"

# Report to RiskDesk if configured
if [ -n "${RISKDESK_URL:-}" ] && [ -n "${RISKDESK_API_TOKEN:-}" ]; then
  echo "Reporting to RiskDesk..."
  curl -s -X POST "${RISKDESK_URL}/api/pipeline/import" \
    -H "Authorization: Bearer ${RISKDESK_API_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"source\":\"trivy\",\"scan_type\":\"${TYPE}\",\"target\":\"${TARGET}\",\"report\":$(cat ${OUTFILE}),\"timestamp\":\"${TIMESTAMP}\"}" \
    || echo "RiskDesk report failed (non-fatal)"
fi

# Report to DefectDojo if configured
if [ -n "${DOJO_URL:-}" ] && [ -n "${DOJO_API_TOKEN:-}" ]; then
  echo "Reporting to DefectDojo..."
  curl -s -X POST "${DOJO_URL}/api/v2/reimport-scan/" \
    -H "Authorization: Token ${DOJO_API_TOKEN}" \
    -F "scan_type=Trivy Scan" \
    -F "product_name=${TARGET}" \
    -F "engagement_name=Pipeline-${TYPE}" \
    -F "auto_create_context=true" \
    -F "active=true" \
    -F "verified=false" \
    -F "file=@${OUTFILE}" \
    || echo "DefectDojo report failed (non-fatal)"
fi

# Gate check: fail the build if findings meet the severity threshold
GATE_EXIT=0
case "${GATE}" in
  CRITICAL) trivy "${TYPE}" --severity CRITICAL --exit-code 1 "${TARGET}" 2>/dev/null || GATE_EXIT=$? ;;
  HIGH)     trivy "${TYPE}" --severity CRITICAL,HIGH --exit-code 1 "${TARGET}" 2>/dev/null || GATE_EXIT=$? ;;
  MEDIUM)   trivy "${TYPE}" --severity CRITICAL,HIGH,MEDIUM --exit-code 1 "${TARGET}" 2>/dev/null || GATE_EXIT=$? ;;
esac

if [ "${GATE_EXIT}" -ne 0 ]; then
  echo "!!! GATE FAILED: findings at ${GATE} severity or above detected."
  exit 1
fi

echo "Gate passed: no findings at ${GATE} or above."
