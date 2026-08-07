#!/usr/bin/env bash
set -euo pipefail

# This script is a manual SQLite backup reference. It is not the scheduled
# production backup, which currently targets a different PostgreSQL database.
DB_PATH=${DB_PATH:-/opt/stocki/data/data.db}
BACKUP_DIR=${BACKUP_DIR:-/opt/stocki/backups}
KEEP_DAYS=${KEEP_DAYS:-14}

mkdir -p "$BACKUP_DIR"

timestamp=$(date -u +"%Y%m%dT%H%M%SZ")
backup_file="$BACKUP_DIR/stocki_${timestamp}.sqlite"

sqlite3 "$DB_PATH" "VACUUM INTO '$backup_file';"

find "$BACKUP_DIR" -type f -name 'stocki_*.sqlite' -mtime "+$KEEP_DAYS" -print -delete
