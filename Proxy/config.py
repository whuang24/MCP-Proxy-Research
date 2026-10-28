import json
import os

AUTH_TOKEN = os.environ.get("PROXY_AUTH_TOKEN", "")
PORT = int(os.environ.get("PROXY_PORT", "8790"))
ROLE = os.environ.get("PROXY_ROLE", "benign")          # benign | attack  (path separation)
LOCAL_LOG_PATH = os.environ.get("LOCAL_LOG_PATH", "./logs/proxy.benign.jsonl")
TARGETS_FILE = os.environ.get("TARGETS_FILE", "./targets.benign.json")

with open(TARGETS_FILE) as f:
    TARGETS: dict = json.load(f)
