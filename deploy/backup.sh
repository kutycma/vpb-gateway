#!/bin/sh
set -eu
umask 077
base=/var/lib/vpb-gateway
mkdir -p "$base/backups"
# Stop CLI/service writers briefly at the operational level for restore snapshots.
work=$(mktemp -d "$base/backups/.archive-XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
sqlite3 "$base/gateway.db" ".backup '$work/gateway.db'"
cp "$base/state.json" "$work/state.json"
cp /etc/vpb-gateway/config.toml "$work/config.toml"
archive="$base/backups/$(date -u +%Y%m%dT%H%M%S).cms"
tar -C "$work" -czf "$work/snapshot.tar.gz" gateway.db state.json config.toml
openssl cms -encrypt -binary -aes-256-cbc -in "$work/snapshot.tar.gz" -outform DER -out "$archive" /etc/vpb-gateway/backup-cert.pem
for old in "$base"/backup-*.db; do
    [ ! -f "$old" ] || mv "$old" "$base/backups/"
done
find "$base/backups" -type f \( -name '*.db' -o -name '*.cms' -o -name '*.state.json' \) -mtime +13 -delete
