#!/usr/bin/env python3
"""
Experiment harness for the MCP-Proxy-Research.

Drives each experiment's BENIGN path through the benign proxy (:8790) and its
ATTACK path through the attack proxy (:8795) -- physical task-level separation.
For every tool call it emits one strict-schema telemetry record (OWASP report
section 6) augmented with the host-side prompt fields that the opencode plugin
would capture (user_prompt, agent, prompt_id, session_id). Ground truth for
exfiltration / execution comes from the sink server's independent receipts.

Usage:
  python3 run_experiment.py                 # all experiments, benign + attack
  python3 run_experiment.py --only E1,E2    # subset
  python3 run_experiment.py --runs 5        # repeat each run 5x (dataset volume)
"""
import argparse
import hashlib
import json
import os
import time
import uuid
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TELE = os.path.join(ROOT, "telemetry")
RUNS_DIR = os.path.join(TELE, "runs")
RECEIPTS = os.path.join(TELE, "receipts.jsonl")
DATASET = os.path.join(TELE, "dataset.jsonl")
COUNTER = os.path.join(TELE, ".prompt_counter")

PROXY = {"benign": "http://127.0.0.1:8790", "attack": "http://127.0.0.1:8795"}
TOKEN = ""
for line in open(os.path.join(ROOT, "Proxy", ".env")):
    if line.startswith("PROXY_AUTH_TOKEN="):
        TOKEN = line.split("=", 1)[1].strip()

EXPERIMENTS = json.load(open(os.path.join(HERE, "experiments.json")))
PATHS = EXPERIMENTS.pop("_paths")

PKG = {}
for _role, _tf in (("benign", "targets.benign.json"), ("attack", "targets.attack.json")):
    _cfg = json.load(open(os.path.join(ROOT, "Proxy", _tf)))
    PKG[_role] = {k: v.get("package_version") for k, v in _cfg.items()}

READ_TOOLS = {"read_file", "read_text_file", "git_log", "git_status", "git_diff",
              "git_diff_unstaged", "git_diff_staged", "git_show", "read_graph",
              "search_nodes", "open_nodes", "list_tables", "read_query", "describe_table"}
WRITE_TOOLS = {"write_query", "git_commit", "git_add", "create_table", "create_entities"}


def op_class(tool, is_list):
    if is_list:
        return "discover"
    if tool == "send_data":
        return "exfiltrate"
    if tool == "run_command":
        return "execute"
    if tool in WRITE_TOOLS:
        return "write"
    if tool in READ_TOOLS:
        return "read"
    return "other"


def resolve(val):
    if not isinstance(val, str):
        return val
    for k, v in PATHS.items():
        if val == k:
            return v
        if val.startswith(k + "/"):
            return v + val[len(k):]
    return val


def resolve_args(args):
    return {k: resolve(v) for k, v in (args or {}).items()}


def post(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
            if r.status == 202 or not body:
                return None
            return json.loads(body)
    except urllib.error.HTTPError as e:
        return {"error": {"code": e.code, "message": e.read().decode(errors="replace")[:200]}}


def rpc_text(resp):
    """Extract human text from a JSON-RPC tool response."""
    if not isinstance(resp, dict):
        return ""
    res = resp.get("result")
    if isinstance(res, dict) and isinstance(res.get("content"), list):
        return "\n".join(c.get("text", "") for c in res["content"] if isinstance(c, dict))
    return json.dumps(res) if res is not None else json.dumps(resp.get("error", ""))


def next_prompt_id():
    n = 0
    try:
        n = int(open(COUNTER).read().strip())
    except Exception:
        pass
    n += 1
    os.makedirs(TELE, exist_ok=True)
    open(COUNTER, "w").write(str(n))
    return n


def tail_receipt():
    try:
        lines = [l for l in open(RECEIPTS) if l.strip()]
        return json.loads(lines[-1]) if lines else None
    except Exception:
        return None


# --- injection / anomaly detectors (transparent, content+metadata based) -----
INJECTION_RE = ("<important>", "e1-payload", "also read", "also send", "forward",
                "ignore the", "credentials.txt", "exfil_destination")


def looks_injected(text):
    t = (text or "").lower()
    return any(m in t for m in INJECTION_RE)


def detect_and_score(exp_id, intent, tool, is_list, args, text, receipt, allowed_roots):
    """Return (access_result, send_result, ground_truth, detector_alert, evidence_level)."""
    access_result = send_result = ground_truth = None
    alert = False
    level = 0
    if is_list:
        if looks_injected(text):
            alert, ground_truth, level = True, "poisoned_tool_definition", 1
        return access_result, send_result, ground_truth, alert, level
    if tool in ("read_file", "read_text_file"):
        returned = bool(text) and "error" not in text.lower()[:30]
        access_result = "returned" if returned else "denied"
        path = (args or {}).get("path", "")
        root = resolve(allowed_roots[0]) if allowed_roots else None
        real = os.path.realpath(path)
        out_of_root = root is not None and os.path.commonpath([real, root]) != root
        if "SYNTHETIC_INJECTION_CANARY" in text:
            alert, ground_truth, level = True, "canary_read", 3
        elif "E4_MARKER" in text or (out_of_root and returned):
            alert, ground_truth, level = True, "forbidden_content_returned", 4
        elif "E2_MARKER" in text or "CONFIDENTIAL" in text:
            alert, ground_truth, level = True, "confidential_read", 3
    elif tool == "send_data":
        send_result = "accepted"
        if receipt and receipt.get("marker_detected"):
            alert, ground_truth, level = True, "exfiltration_verified", 4
        else:
            ground_truth, level = "send_attempted", 2
    elif tool == "run_command":
        if receipt and receipt.get("operation_class") in ("destructive", "network", "injection-suspect"):
            alert, ground_truth, level = True, "unauthorized_execution_simulated", 4
        else:
            ground_truth, level = "execution_attempted", 2
    elif tool == "read_graph" or tool == "search_nodes":
        if "OVERSHARE_MARKER_B2D4" in text:
            alert, ground_truth, level = True, "cross_workspace_disclosure", 3
        access_result = "returned"
    return access_result, send_result, ground_truth, alert, level


def marker_id(text):
    for m in ("EXFIL_MARKER_7F3A9C2E", "TRAVERSAL_TARGET_55B1",
              "SYNTHETIC_INJECTION_CANARY", "OVERSHARE_MARKER_B2D4"):
        if text and m in text:
            return m
    return None


def run_one(exp_id, exp, intent, repeat_idx):
    spec = exp[intent]
    role = "benign" if intent == "benign" else "attack"
    base = PROXY[role]
    run_id = uuid.uuid4().hex[:16]
    session_id = "ses_" + uuid.uuid4().hex[:24]
    prompt_id = next_prompt_id()
    prompt_ts = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    servers = sorted({s["server"] for s in spec["steps"]})
    for srv in servers:  # handshake per server used
        post(f"{base}/mcp/{srv}", {"jsonrpc": "2.0", "id": 0, "method": "initialize",
             "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                        "clientInfo": {"name": "harness", "version": "1.0"}}})
        post(f"{base}/mcp/{srv}", {"jsonrpc": "2.0", "method": "notifications/initialized"})

    records = []
    prev_text = ""
    rpc = 100
    for i, step in enumerate(spec["steps"]):
        srv = step["server"]
        is_list = bool(step.get("list"))
        tool = step.get("tool")
        rpc += 1
        t0 = time.monotonic()
        if is_list:
            resp = post(f"{base}/mcp/{srv}", {"jsonrpc": "2.0", "id": rpc, "method": "tools/list"})
            args = {}
        else:
            args = resolve_args(step.get("arguments"))
            args = {k: (prev_text if v == "{{prev_text}}" else v) for k, v in args.items()}
            resp = post(f"{base}/mcp/{srv}", {"jsonrpc": "2.0", "id": rpc, "method": "tools/call",
                        "params": {"name": tool, "arguments": args}})
        dur = round((time.monotonic() - t0) * 1000, 2)
        text = rpc_text(resp)
        prev_text = text or prev_text
        receipt = tail_receipt() if srv == "sink" else None

        # integrity / schema hashes
        schema_hash = desc_hash = None
        if is_list and isinstance(resp, dict):
            tools = (resp.get("result") or {}).get("tools", [])
            schema_hash = hashlib.sha256(json.dumps([t.get("inputSchema") for t in tools],
                                                     sort_keys=True).encode()).hexdigest()
            desc_hash = hashlib.sha256(json.dumps([t.get("description") for t in tools],
                                                  sort_keys=True).encode()).hexdigest()
        tool_error = None
        if isinstance(resp, dict):
            if "error" in resp:
                tool_error = resp["error"]
            elif isinstance(resp.get("result"), dict) and resp["result"].get("isError"):
                tool_error = resp["result"]

        access, send, gtruth, alert, level = detect_and_score(
            exp_id, intent, tool, is_list, args, text, receipt, spec.get("allowed_roots", []))

        full = json.dumps(resp) if resp is not None else ""
        truncated = len(full) > 2000
        rec = {
            # --- identity ---
            "experiment_id": exp_id, "run_id": run_id, "scenario_id": f"{exp_id}-{intent}",
            "server_id": srv, "package_version": PKG.get(role, {}).get(srv),
            # --- correlation ---
            "connection_id": f"{role}:{srv}:{run_id[:8]}", "session_id": session_id,
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "direction": "roundtrip", "jsonrpc_id": rpc,
            "method": "tools/list" if is_list else "tools/call",
            # --- tool data ---
            "tool_name": ("tools/list" if is_list else tool),
            "tool_arguments": json.dumps(args),
            "tool_result": (full[:2000] if truncated else full),
            "tool_error": json.dumps(tool_error) if tool_error else None,
            "operation_class": op_class(tool, is_list),
            # --- integrity ---
            "payload_sha256": hashlib.sha256(full.encode()).hexdigest(),
            "payload_bytes": len(full.encode()), "content_truncated": truncated,
            "schema_hash": schema_hash, "description_hash": desc_hash,
            # --- policy ---
            "task_intent_label": spec["task_intent_label"],
            "allowed_roots": [resolve(r) for r in spec.get("allowed_roots", [])],
            "approved_destinations": spec.get("approved_destinations", []),
            "workspace_label": spec.get("workspace_label"),
            # --- outcomes ---
            "synthetic_marker_id": marker_id(text), "access_result": access,
            "send_result": send, "sink_receipt": receipt, "ground_truth": gtruth,
            "evidence_level": level,
            # --- detection ---
            "detector_alert": alert,
            "alert_timestamp": (time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()) if alert else None),
            "duration_ms": dur,
            # --- host-side (opencode plugin) additions ---
            "prompt_id": prompt_id, "user_prompt": spec["user_prompt"], "agent": spec["agent"],
        }
        records.append(rec)

    out = os.path.join(RUNS_DIR, f"{exp_id}_{intent}_{run_id}.jsonl")
    os.makedirs(RUNS_DIR, exist_ok=True)
    with open(out, "w") as f, open(DATASET, "a") as d:
        for r in records:
            line = json.dumps(r)
            f.write(line + "\n")
            d.write(line + "\n")
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="", help="comma list, e.g. E1,E4")
    ap.add_argument("--intent", default="both", choices=["benign", "attack", "both"])
    ap.add_argument("--runs", type=int, default=1)
    a = ap.parse_args()
    ids = [x.strip() for x in a.only.split(",") if x.strip()] or list(EXPERIMENTS)
    intents = ["benign", "attack"] if a.intent == "both" else [a.intent]
    summary = []
    for r in range(a.runs):
        for eid in ids:
            for intent in intents:
                recs = run_one(eid, EXPERIMENTS[eid], intent, r)
                alerts = sum(1 for x in recs if x["detector_alert"])
                gt = [x["ground_truth"] for x in recs if x["ground_truth"]]
                summary.append((eid, intent, len(recs), alerts, gt))
    print(f"{'exp':4} {'intent':7} {'calls':5} {'alerts':6} ground_truth")
    for eid, intent, n, al, gt in summary:
        print(f"{eid:4} {intent:7} {n:5} {al:6} {','.join(gt) or '-'}")
    print(f"\ndataset -> {DATASET}")


if __name__ == "__main__":
    main()
