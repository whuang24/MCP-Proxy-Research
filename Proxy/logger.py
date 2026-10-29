import json
import time
from config import LOCAL_LOG_PATH

# Single combined traffic log. Each exchange carries a `label` with one of
# three values -- "successful", "failed", "benign" -- computed per round-trip by
# classifier.py and stamped on both the client_to_server and server_to_client
# lines (same trace_id). The AUTHORITATIVE strict-schema telemetry is still
# assembled by the harness (harness/run_experiment.py) from these logs + sink
# receipts + the host plugin's prompt records.


def log_event(server: str, direction: str, payload: dict, keywords: dict | None = None,
              trace_id: str | None = None, duration_ms: float | None = None,
              outcome: str | None = None, label: str | None = None,
              category: str | None = None):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "label": label,
        "category": category,
        "server": server,
        "direction": direction,
        "trace_id": trace_id,
        "raw_payload": payload,
        "keywords": keywords or {},
        "duration_ms": duration_ms,
        "outcome": outcome,
    }
    with open(LOCAL_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
