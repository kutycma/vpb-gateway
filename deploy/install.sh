#!/bin/sh
set -eu
test "$(id -u)" = 0 || { echo 'Chạy bằng sudo'; exit 1; }
apt-get update
apt-get install -y python3 python3-venv sqlite3
python3 -c 'import sys; assert sys.version_info >= (3,11), "Cần Python 3.11+; xem README cho Ubuntu 22.04"'
id vpbgw >/dev/null 2>&1 || useradd --system --home /var/lib/vpb-gateway --shell /usr/sbin/nologin vpbgw
install -d /opt/vpb-gateway /etc/vpb-gateway
install -d -m 0700 -o vpbgw -g vpbgw /var/lib/vpb-gateway
python3 -m venv /opt/vpb-gateway/.venv
/opt/vpb-gateway/.venv/bin/pip install --require-hashes -r requirements-build.lock
/opt/vpb-gateway/.venv/bin/pip install --no-build-isolation --require-hashes -r requirements.lock
/opt/vpb-gateway/.venv/bin/pip install --no-deps --no-build-isolation .
test -e /etc/vpb-gateway/config.toml || install -m 0640 -o root -g vpbgw deploy/config.example.toml /etc/vpb-gateway/config.toml
install -m 0644 deploy/vpb-gateway.service deploy/vpb-gateway-backup.service deploy/vpb-gateway-backup.timer deploy/vpb-gateway-prune.service deploy/vpb-gateway-prune.timer /etc/systemd/system/
install -m 0755 deploy/backup.sh /opt/vpb-gateway/backup.sh
systemctl daemon-reload
systemctl enable --now vpb-gateway-backup.timer vpb-gateway-prune.timer
echo 'Tiếp theo: doctor, register, rồi systemctl enable --now vpb-gateway'
