# Log Interpretation Guide

How to read the data this testbed produces, what every field means, and where
each value actually comes from. Written for anyone analyzing the logs who did
not build the testbed.

## The log sources

A single tool call leaves a trail in up to three places, correlated by ids:

| File | What it holds | Written by |
|---|---|---|
| `Proxy/logs/proxy_traffic.jsonl` | **The primary log.** Every MCP message in and out of the proxy, two lines per exchange, each tagged using `label` + `category`.  | Proxy (`proxy_server.py` → `logger.py`) |
| `telemetry/receipts.jsonl` | **The logging for E2/E5.** Independent receipts for every exfil/exec attempt sent to the sink.  | Sink MCP server (`sink_server.py`) |
| `~/.config/opencode/.../host_trace.json` | **Prompt Log.** The user prompt and agent used, captured host-side. Only present in live opencode runs. | MCP Host plugin (`mcp-trace.js`) |

`telemetry/dataset.jsonl` is a fourth, separate artifact: the strict §6
analysis schema assembled by `harness/run_experiment.py`, not a raw log. Its
fields are documented in [README.md](README.md#telemetry-schema).

### How the three join

- `proxy_traffic.jsonl` pairs its own two lines by **`trace_id`** (request + response, both carrying the same `label`/`category`).
- The sink receipt corresponds to the `send_data`/`run_command` exchange on the
  `sink` server; match by time order and payload. (May be flawed, not guaranteed match)
- The host plugin's prompt record links to proxy traffic by **`session_id`** +
  run window (`prompt_id` groups the tool calls a single prompt caused).

### "Sourced from" — the origins used in the table

- **Host** — the opencode MCP Host plugin (`mcp-trace.js`), off-MCP context.
- **Client** — the author of the request (the harness driver `run_experiment.py`
  / `random_traffic.py`, or opencode + the LLM). Request-side `raw_payload`
  content originates here; the proxy only records it.
- **Proxy** — values the proxy computes or stamps itself.
- **Server** — the target MCP backend's reply. Response-side `raw_payload`
  content originates here.
- **Sink** — the sink MCP server, which also writes `receipts.jsonl`.

## Field reference

`raw_payload` is the verbatim JSON-RPC message. Its meaning depends on
`direction`: on a `client_to_server` line it is the **request** (from Client);
on a `server_to_client` line it is the **response** (from Server, or a
Proxy-generated error). That is why request fields and response fields below are
sourced differently even though they share the `raw_payload` prefix.

| Parameter | Represents | Sourced from |
|---|---|---|
| `timestamp` | UTC time the proxy logged the line | Proxy |
| `trace_id` | UUID tying the request line and response line of one exchange together | Proxy |
| `direction` | `client_to_server` (request) or `server_to_client` (response) | Proxy |
| `server` | Which route/backend was addressed (`/mcp/<id>`); safe vs attack-variant route | Proxy (from URL) |
| `outcome` | Disposition of the exchange: `response_received`, `tool_error`, `error_response`, `blocked_invalid_identifier`, `rejected_unauthorized`, `rejected_unknown_server`, `acknowledged`, `timeout`, `connection_error` | Proxy |
| `label` | Verdict: `successful` / `failed` / `benign` | Proxy (`classifier.py`) |
| `category` | Attack family: `E1`–`E6` or `none` | Proxy (`classifier.py`) |
| `duration_ms` | Round-trip latency for the exchange (on the response line) | Proxy (measured) |
| `raw_payload` | The full JSON-RPC message (request or response per `direction`) | Client (request) / Server (response) |
| `raw_payload.jsonrpc` | Protocol version, `"2.0"` | Client / Server |
| `raw_payload.id` | JSON-RPC call id; same value on request and matching response | Client (set), Server (echoed) |
| `raw_payload.method` | JSON-RPC method: `tools/call`, `tools/list`, `initialize`, `notifications/initialized` | Client |
| `raw_payload.params.name` | The tool invoked (e.g. `read_file`, `git_log`, `send_data`) — the LLM/driver's chosen action | Client |
| `raw_payload.params.arguments` | The tool's arguments object | Client |
| `raw_payload.params.arguments.path` / `repo_path` | File/repo target; a `..` here is a traversal attempt | Client |
| `raw_payload.params.arguments.destination` / `payload` | Exfil target URL and forwarded data (sink `send_data`) | Client |
| `raw_payload.params.arguments.command` | Shell command text (sink `run_command`) | Client |
| `raw_payload.params.arguments.query` | SQL text (database `read_query`) | Client |
| `raw_payload.result` | The tool result object (response line only) | Server |
| `raw_payload.result.content[].text` | The tool's output text — **where synthetic markers appear if forbidden content was returned** | Server |
| `raw_payload.result.isError` | Tool-level failure flag (`true` = the server refused/failed the call) | Server |
| `raw_payload.error` | JSON-RPC error object; backend errors come from Server, auth/route/SQL-guard errors come from Proxy | Server / Proxy |
| `keywords.method` | The method, re-extracted for convenience | Proxy (`keywords.py`) |
| `keywords.tool_name` | The tool name, re-extracted | Proxy (`keywords.py`) |
| `keywords.arg_keys` | Just the argument key names (not values) | Proxy (`keywords.py`) |
| `keywords.matched_watchlist` | Suspicious terms seen in the message (`delete`, `token`, `exec`, `ignore`, …); supporting signal, not a verdict | Proxy (`keywords.py`) |
| `keywords.extracted_keywords` | Content words pulled from free-text argument values | Proxy (`keywords.py`) |

### Host-plugin fields (`host_trace.json`, live runs only)

| Parameter | Represents | Sourced from |
|---|---|---|
| `prompt_id` | Sequential id grouping all tool calls caused by one prompt | Host |
| `user_prompt` | The user's natural-language request (never visible to the proxy) | Host |
| `agent` | The opencode agent that acted (e.g. `build`) | Host |
| `session_id` | opencode session; links a prompt to its proxy traffic | Host |
| `prompt_timestamp` / `request_timestamp` / `response_timestamp` | Timing of the prompt and each call | Host |
| `call_id` | opencode's per-call id | Host |
| `mcp_request` / `mcp_response` | Arguments sent and content returned, as the host saw them | Host |
| `response_available` | `1` if content came back, else `0` | Host |

### Sink receipt fields (`telemetry/receipts.jsonl`)

| Parameter | Represents | Sourced from |
|---|---|---|
| `tool` | `send_data` or `run_command` | Sink |
| `destination` | Where exfil was aimed (recorded, never sent) | Sink |
| `payload_sha256` / `payload_bytes` | Hash and size of the forwarded data | Sink |
| `marker_detected` | The synthetic marker found in the payload, or `null` — **confirms a real secret was exfiltrated** | Sink |
| `operation_class` | Command risk: `destructive` / `network` / `injection-suspect` / `benign` | Sink |
| `command` | The command text (recorded, never executed) | Sink |
| `ts` | UTC time the receipt was written | Sink |

## Reading the verdict off the fields

`label` is derived, but these are the parameters that prove it:

- **benign** — no attempt signal and nothing realized: a safe `server`, no `..`
  in `path`, not `send_data`/`run_command`, no marker in
  `result.content[].text`, `outcome: response_received`, `isError` absent.
- **successful** — an attempt **plus** realization: a synthetic marker in
  `result.content[].text`, or the sink receipt's `marker_detected` non-null /
  `operation_class` risky, with a clean `outcome`.
- **failed** — an attempt that was blocked or did not realize: `outcome` is an
  error, or `result.isError` is `true`, or `raw_payload.error` is set, or the
  returned content held no marker and the sink `marker_detected` was `null`.

`category` is independent of `label`: a blocked traversal is `(failed, E4)`, a
leaked one is `(successful, E4)`.

## Building a benign-traffic baseline

Primary focus is on the user prompt provided to the MCP Host and collected by the
Opencode plugin.

- **`user_prompt` + `agent` (declared intent).** The host-side prompt is the only
  record of what the user actually asked for.

The following are other potentially useful parameters that could contribute to the
development of a baseline complimentary of user prompt, which is the primary benign 
baseline building factor.

These are the parameters most worth profiling from the `benign`subset, and why each matters:

- **`server` + `raw_payload.params.name` (the tool mix).** The joint
  distribution of which backends are called and which tools accessed on them is
  the foundation of the baseline. Benign work concentrates in a predictable manner of
  tool reads and accesses per server; a call to a server or tool that never appeared in the
  baseline, or a sudden shift in the proportions, is a first-order anomaly. This
  pair is crucial because almost every attack family first shows up as an unusual
  server/tool choice (`send_data`, `run_command`, a `read_file` on a route that
  normally only lists). 

- **`outcome` and the error rate it implies.** Benign traffic is overwhelmingly
  `response_received` with a small, stable fraction of ordinary errors. Baselining
  the error-rate and the specific `outcome` values that occur normally lets you
  treat spikes in `tool_error`, `blocked_invalid_identifier`, or
  `rejected_unauthorized` as signal.

- **Argument shape: `arg_keys` + values in `params.arguments`** Benign calls use a
  narrow, well-formed set of argument keys and stay inside allowed roots. Profiling
  the normal key sets and path/query patterns provides guideline on regular traffic paths,
  , and outcasts any command injection (`command`), and exfil (`destination`)
  arguments falling outside of this guideline. This is crucial because the attack intent
  often lives entirely in the argument values while the tool name still looks ordinary.

- **`duration_ms` (latency profile).** Each tool on each server has a
  characteristic benign latency band. A baseline of these bands turns prolonged timing
  into a cheap sidelining anomalous signal. It matters
  because some abuse patterns and resource-exhaustion behaviors are visible in
  timing before they are visible in content due to extra requirement to search for
  sensitive or exfiltration worthy data.

- **Call sequences per `session_id` / `prompt_id` (shape of a task).** Benign
  tasks produce recognizable ordered sequences of calls (for example, list a
  repo, read its README, check status). Modeling these sequences, not just
  individual calls, allows the flagging of out-of-place step such as a read
  immediately followed by a `send_data`. It is crucial because several families
  (E1 injection, E2 exfil, the E3 rug-pull chain) are defined by the *transition*
  between calls rather than any single call. (Potential **tool chaining**)

A practical baseline is therefore not one field but a small joint profile:
per-`server`/`tool` frequencies, the normal `outcome` and `duration_ms`
distributions, the allowed argument envelope, and the typical call sequence per
prompt.
