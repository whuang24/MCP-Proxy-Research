# MCP-Proxy-Research

A local, reproducible MCP security testbed that generates **labeled attack vs.
benign traffic over streamable HTTP** and records it in the strict telemetry
schema from the SFU report *MCP Server Selection and Experimental Testbed
Design* (§6), extended with the opencode host-side prompt fields.

Transport is **streamable HTTP end to end** (opencode → proxy → stdio→HTTP
bridge → server) — this project's role is to produce attack data through HTTP,
so the report's stdio-only recommendation is intentionally overridden.

## Task-level attack/benign separation

The two traffic paths are **physically separate**, split at the proxy:

```
                         benign task  ─► benign proxy  :8790 ─► benign servers
opencode (build agent) ─┤
                         attack task  ─► attack proxy  :8795 ─► attack servers
   │
   └─ host plugin mcp-trace.js records user_prompt / agent / prompt_id
```

A benign run can only reach benign server instances; an attack run only reaches
attack instances. You read the path from the port, never from log pattern-
matching. Every record still also carries `task_intent_label`.

## Server roster

| Path | Server (`/mcp/<id>`) | Backend | Bridge | Used by |
|---|---|---|---|---|
| benign :8790 | filesystem | `@modelcontextprotocol/server-filesystem` (clean workspace) | :9501 | E1,E2,E4 |
| | git | `mcp-server-git` (clean repo) | :9502 | E1,E5 |
| | database | `safe_sqlite_server.py` | :9503 | baseline |
| | everything | `@modelcontextprotocol/server-everything` | :9504 | protocol baseline (E3) |
| | memory | `@modelcontextprotocol/server-memory` (Workspace A only) | :9505 | E6 |
| | catalog | `poisoned_server.py` **baseline** mode | :9506 | E3 baseline |
| attack :8795 | filesystem | `vuln_fs_server.py` (prefix-match bypass) + payloads/canary | :9601 | E1,E2,E4 |
| | git | `mcp-server-git` (repo w/ injected commit+issue) | :9602 | E1,E5 |
| | memory | `server-memory` (Workspace A **+ B** marker) | :9603 | E6 |
| | catalog | `poisoned_server.py` **poisoned** mode | :9604 | E3 |
| | sink | `sink_server.py` (exfil sink + mock exec; writes receipts) | :9605 | E2,E5 ground truth |

The **sink** never transmits or executes anything; it appends receipts to
`telemetry/receipts.jsonl`, the independent ground truth for E2/E5.

## Experiment → evidence mapping (E1–E6)

| Exp | OWASP | Benign path | Attack path | Verified ground truth |
|---|---|---|---|---|
| E1 tool-output injection | MCP06 | read clean repo+README | injected commit/issue → reads `.config/credentials.txt` canary | `canary_read` (L3) |
| E2 data exfiltration | MCP01/10 | read allowed notes | read `CONFIDENTIAL.txt` → `send_data` to sink | `exfiltration_verified` (L4, sink receipt) |
| E3 tool poisoning | MCP03 | `catalog` baseline `tools/list` | `catalog` poisoned `tools/list` | `poisoned_tool_definition` (hash+instruction delta) |
| E4 path traversal | MCP07/02 | in-root read | sibling-dir read via prefix bypass | `forbidden_content_returned` (L4, marker) |
| E5 command injection | MCP05/02 | `git_status` read-only | status → `run_command` on sink | `unauthorized_execution_simulated` (L4, receipt) |
| E6 context over-sharing | MCP10 | `read_graph` Workspace A only | `read_graph` leaks Workspace B marker | `cross_workspace_disclosure` (L3) |

Evidence levels follow the report §8: 1 suspicious content, 2 requested,
3 accepted/returned, 4 independently verified.

## Telemetry schema

`telemetry/dataset.jsonl` (and per-run files in `telemetry/runs/`) use the
strict §6 fields — identity (`experiment_id`, `run_id`, `scenario_id`,
`server_id`, `package_version`), correlation (`connection_id`, `session_id`,
`timestamp_utc`, `direction`, `jsonrpc_id`, `method`), tool data (`tool_name`,
`tool_arguments`, `tool_result`, `tool_error`, `operation_class`), integrity
(`payload_sha256`, `payload_bytes`, `content_truncated`, `schema_hash`,
`description_hash`), policy (`task_intent_label`, `allowed_roots`,
`approved_destinations`, `workspace_label`), outcomes (`synthetic_marker_id`,
`access_result`, `send_result`, `sink_receipt`, `ground_truth`,
`evidence_level`), detection (`detector_alert`, `alert_timestamp`,
`duration_ms`) — **plus** the host-plugin additions `prompt_id`, `user_prompt`,
`agent`. `direction` is `roundtrip` because each record is one merged
request+response tool call (the unit of analysis). The raw per-message proxy
logs (`Proxy/logs/proxy.<role>.jsonl`) are kept as supporting evidence.

## Run

```bash
./start_all.sh                       # bridges + both proxies (first run fetches npx servers)
# in another shell:
python3 harness/run_experiment.py            # all E1-E6, benign + attack
python3 harness/run_experiment.py --only E2,E5 --runs 20   # volume for a family
```

`--runs N` repeats each run for dataset volume; `--intent benign|attack` filters.

## Layout
- `Proxy/` — proxy (role-aware), bridge, launchers, `targets.{benign,attack}.json`
- `servers/` — filesystem (safe + vuln), git, database, everything, memory, poisoned, sink
- `harness/` — `experiments.json` (E1–E6 benign/attack) + `run_experiment.py`
- `telemetry/` — `dataset.jsonl`, `runs/`, `receipts.jsonl`
- `archive/` — the original **MCP-Path-Traversal** and **MCP-Prompt-Injection** labs (frozen)

## Live-agent mode (optional)
The harness drives the HTTP proxies directly (deterministic data generation). To
instead capture a real opencode agent, point an opencode `mcp` config at the
benign or attack proxy and run from a folder the host plugin routes; the plugin
supplies `user_prompt`/`agent`/`prompt_id`, correlated to proxy traffic by run
window. The harness remains the authoritative strict-telemetry writer.

## Safety
Local sandbox only. All "secret"/confidential values are synthetic markers; the
sink neither transmits nor executes. Paths in the configs are absolute to this
machine. Change the placeholder `PROXY_AUTH_TOKEN` before any non-local use.
