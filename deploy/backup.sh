#!/bin/sh
# Daily SQLite snapshot. Installed by bootstrap-vm.sh at
# /etc/cron.daily/riskdesk-backup. .backup uses the online-backup API, so it
# runs while the service is live without blocking writers.
set -eu

DB=/var/lib/riskdesk/riskdesk.db
BACKUP_DIR=/var/lib/riskdesk/backups
STAMP=$(date +%Y-%m-%d)
KEEP_DAYS=30

install -d -o riskdesk -g riskdesk -m 0700 "$BACKUP_DIR"
sudo -u riskdesk sqlite3 "$DB" ".backup $BACKUP_DIR/riskdesk-$STAMP.db"
# Rotate: delete backups older than KEEP_DAYS.
find "$BACKUP_DIR" -name 'riskdesk-*.db' -mtime +$KEEP_DAYS -delete

# If you have offsite storage, ship the latest snapshot here, e.g.:
#   rclone copy "$BACKUP_DIR/riskdesk-$STAMP.db" b2:riskdesk-backups/
#   restic -r /mnt/backups backup "$BACKUP_DIR/riskdesk-$STAMP.db"
