#!/usr/bin/env bash
# Launch the full testbed: all server bridges + ONE combined HTTP proxy.
#   proxy -> :8790  (serves targets.json: benign routes + attack-variant routes)
# Benign and attack tasks share this port; the proxy's combined log labels each
# exchange successful / failed / benign (see Proxy/classifier.py).
set -euo pipefail
cd "$(dirname "$0")/Proxy"
set -a; . ./.env; set +a
PY=.venv/bin/python

echo "== one-time data setup =="
bash ../servers/git/init_repos.sh
python3 ../servers/database/seed.py --db-path ../servers/database/benign.db

echo "== bridges =="
"$PY" start_bridges.py targets.json &  B1=$!
sleep 6   # npx may fetch server-everything / server-memory on first run

echo "== proxy =="
PROXY_PORT=8790 TARGETS_FILE=targets.json LOCAL_LOG_PATH=logs/proxy_traffic.jsonl \
  "$PY" proxy_server.py &  P1=$!

echo "proxy :8790  (combined; Ctrl-C to stop)"
trap 'kill $B1 $P1 2>/dev/null || true' INT TERM
wait
