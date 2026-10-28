import json
import time
from config import LOCAL_LOG_PATH, ROLE

# Raw per-direction proxy log. This is supporting evidence that proves the
# physical benign/attack path separation (each proxy writes its own file and
# stamps its role). The AUTHORITATIVE strict-schema telemetry is assembled by
# the harness (harness/run_experiment.py) from these logs + sink receipts +
# the host plugin's prompt records.


def log_event(server: str, direction: str, payload: dict, keywords: dict | None = None,
              trace_id: str | None = None, duration_ms: float | None = None,
              outcome: str | None = None):
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "role": ROLE,
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
