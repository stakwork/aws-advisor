#!/bin/bash
# Starts the Steampipe service as the advisor user, then the app. Root only long enough to fix the volume's
# ownership; Steampipe refuses to run as root and the app has no reason to.
set -euo pipefail
mkdir -p /data/advisor /data/steampipe/config /data/aws
chown -R advisor:advisor /data
# the AWS files the app and Steampipe share; the Steampipe config dir the app writes the connection into
ln -sfn /data/aws /home/advisor/.aws
mkdir -p /home/advisor/.steampipe && rm -rf /home/advisor/.steampipe/config && ln -sfn /data/steampipe/config /home/advisor/.steampipe/config
chown -h advisor:advisor /home/advisor/.aws /home/advisor/.steampipe/config
# Steampipe needs at least one connection file to serve the aws schema; the app writes `advisor.spc` on setup
export STEAMPIPE_UPDATE_CHECK=false
gosu advisor steampipe service start --database-listen local --database-port 9193 >/dev/null 2>&1 || {
  echo "steampipe service failed to start" >&2; gosu advisor steampipe service status || true; }
trap 'gosu advisor steampipe service stop >/dev/null 2>&1 || true' EXIT
# Watchdog: the service (its Postgres and the AWS plugin) can die on a plugin panic or under memory pressure,
# and nothing else would bring it back. Every 30 s, when the port stops answering, start it again and say so.
(
  while sleep 30; do
    if ! (exec 3<>/dev/tcp/127.0.0.1/9193) 2>/dev/null; then
      echo "[steampipe] service not answering on 9193, restarting" >&2
      gosu advisor steampipe service stop >/dev/null 2>&1 || true
      gosu advisor steampipe service start --database-listen local --database-port 9193 >/dev/null 2>&1 \
        && echo "[steampipe] service restarted" >&2 || echo "[steampipe] restart failed" >&2
    fi
  done
) &
cd /usr/src/app
exec gosu advisor "$@"
