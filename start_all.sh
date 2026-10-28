#!/usr/bin/env bash
# Launch the full testbed: bridges + two role-separated HTTP proxies.
#   benign proxy -> :8790  (serves targets.benign.json)
#   attack proxy -> :8795  (serves targets.attack.json)
set -euo pipefail
cd "$(dirname "$0")/Proxy"
set -a; . ./.env; set +a
PY=.venv/bin/python

echo "== one-time data setup =="
bash ../servers/git/init_repos.sh
python3 ../servers/database/seed.py --db-path ../servers/database/benign.db

echo "== bridges =="
"$PY" start_bridges.py targets.benign.json &  B1=$!
"$PY" start_bridges.py targets.attack.json &  B2=$!
sleep 6   # npx may fetch server-everything / server-memory on first run

echo "== proxies =="
PROXY_PORT=8790 PROXY_ROLE=benign TARGETS_FILE=targets.benign.json \
  LOCAL_LOG_PATH=logs/proxy.benign.jsonl "$PY" proxy_server.py &  P1=$!
PROXY_PORT=8795 PROXY_ROLE=attack TARGETS_FILE=targets.attack.json \
  LOCAL_LOG_PATH=logs/proxy.attack.jsonl "$PY" proxy_server.py &  P2=$!

echo "benign :8790  attack :8795  (Ctrl-C to stop)"
trap 'kill $B1 $B2 $P1 $P2 2>/dev/null || true' INT TERM
wait
