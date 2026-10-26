#!/usr/bin/env bash
# Swap previous release back into place. Does not touch the database --
# migrations are additive, so last-version code reads newer schema fine.
set -euo pipefail

APP_DIR=/opt/riskdesk
CURRENT=$APP_DIR/current
PREVIOUS=$APP_DIR/previous
ROLLBACK_HOLD=$APP_DIR/rolled-back

if [[ ! -d "$PREVIOUS" ]]; then
    echo "no previous release to roll back to"
    exit 1
fi

echo "rolling back"
echo "  current  -> $ROLLBACK_HOLD (held for inspection)"
echo "  previous -> current"

rm -rf "$ROLLBACK_HOLD"
mv "$CURRENT" "$ROLLBACK_HOLD"
mv "$PREVIOUS" "$CURRENT"

sudo /bin/systemctl restart riskdesk

for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if curl -fsS -o /dev/null http://127.0.0.1:8080/api/meta; then
        echo "rolled back successfully (attempt $i)"
        exit 0
    fi
done
echo "service did not come up after rollback"
exit 1
