#!/bin/sh
# Backup all MTD partitions from an OpenWrt router over SSH.
# Usage: ./scripts/backup-mtd.sh <router-ip>

set -e

ROUTER="${1:?Usage: $0 <router-ip>}"
BACKUP_DIR="./backup"
mkdir -p "$BACKUP_DIR"

echo "Reading MTD layout from $ROUTER ..."

ssh "root@$ROUTER" 'tail -n +2 /proc/mtd' | while IFS=': ' read -r dev size erase name; do
	name=$(echo "$name" | tr -d '"')
	dst="$BACKUP_DIR/${dev}_${name}.bin"
	echo "  /dev/$dev ($name, 0x$size) -> $dst"
	ssh "root@$ROUTER" "dd if=/dev/$dev bs=65536 2>/dev/null" > "$dst"
done

echo "Done:"
ls -lh "$BACKUP_DIR"
