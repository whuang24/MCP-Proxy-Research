import json
import os

# Single combined proxy now: one port serves BOTH benign and attack tasks.
# The attack/benign distinction lives in the log's `label` field (set by
# classifier.py), not in a per-role port or file.
AUTH_TOKEN = os.environ.get("PROXY_AUTH_TOKEN", "")
PORT = int(os.environ.get("PROXY_PORT", "8790"))
LOCAL_LOG_PATH = os.environ.get("LOCAL_LOG_PATH", "./logs/proxy_traffic.jsonl")
TARGETS_FILE = os.environ.get("TARGETS_FILE", "./targets.json")

with open(TARGETS_FILE) as f:
    TARGETS: dict = json.load(f)
