#!/usr/bin/env bash
set -euo pipefail

DB_PATH=${DB_PATH:-/srv/granempresa/data/data.db}
BACKUP_DIR=${BACKUP_DIR:-/srv/granempresa/backups}
KEEP_DAYS=${KEEP_DAYS:-14}

mkdir -p "$BACKUP_DIR"

timestamp=$(date -u +"%Y%m%dT%H%M%SZ")
backup_file="$BACKUP_DIR/granempresa_${timestamp}.sqlite"

sqlite3 "$DB_PATH" "VACUUM INTO '$backup_file';"

find "$BACKUP_DIR" -type f -name 'granempresa_*.sqlite' -mtime "+$KEEP_DAYS" -print -delete
