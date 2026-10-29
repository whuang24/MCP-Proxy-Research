import asyncio
import json
import time
import uuid
import httpx
from fastapi import FastAPI, Request, Response
import uvicorn
from config import AUTH_TOKEN, PORT, TARGETS
from logger import log_event
from keywords import extract_keywords
from sql_identifier_guard import check as check_sql_identifier
from classifier import classify, categorize

app = FastAPI()
_http_client = httpx.AsyncClient(timeout=30.0)

_stdio_procs: dict[str, asyncio.subprocess.Process] = {}
_stdio_pending: dict[str, dict[str, asyncio.Future]] = {}
_stdio_meta: dict[str, dict[str, dict]] = {}


def _outcome_for(payload: dict) -> str:
    if "error" in payload:
        return "error_response"
    result = payload.get("result")
    if isinstance(result, dict) and result.get("isError"):
        return "tool_error"
    return "response_received"


def _default_reply_for_server_request(method: str, req_id) -> dict:
    if method == "roots/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"roots": []}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"proxy: no client bridge for '{method}'"}}


async def _stdio_reader(server_name: str):
    proc = _stdio_procs[server_name]
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "method" in payload:
            log_event(server_name, "server_to_client", payload, extract_keywords(payload),
                      label="benign")
            if payload.get("id") is not None:
                reply = _default_reply_for_server_request(payload["method"], payload["id"])
                proc.stdin.write((json.dumps(reply) + "\n").encode())
                await proc.stdin.drain()
            continue
        req_id = str(payload.get("id"))
        meta = _stdio_meta[server_name].pop(req_id, None)
        trace_id = meta["trace_id"] if meta else None
        duration_ms = round((time.monotonic() - meta["t0"]) * 1000, 2) if meta else None
        _req = meta.get("request") if meta else None
        _lbl = classify(server_name, _req, payload, _outcome_for(payload))
        log_event(server_name, "server_to_client", payload, extract_keywords(payload),
                   trace_id=trace_id, duration_ms=duration_ms, outcome=_outcome_for(payload),
                   label=_lbl, category=categorize(server_name, _req, payload, _lbl))
        pending = _stdio_pending[server_name]
        if req_id in pending:
            pending.pop(req_id).set_result(payload)


@app.on_event("startup")
async def start_stdio_targets():
    for name, cfg in TARGETS.items():
        if cfg["transport"] == "stdio":
            proc = await asyncio.create_subprocess_exec(
                cfg["command"], *cfg["args"],
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
            _stdio_procs[name] = proc
            _stdio_pending[name] = {}
            _stdio_meta[name] = {}
            asyncio.create_task(_stdio_reader(name))


_http_sessions: dict[str, str] = {}


def _parse_sse(text: str, req_id) -> dict | None:
    for event in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(l[5:].lstrip() for l in event.split("\n") if l.startswith("data:"))
        if not data:
            continue
        try:
            msg = json.loads(data)
        except json.JSONDecodeError:
            continue
        if "method" not in msg and msg.get("id") == req_id:
            return msg
    return None


async def _post_mcp(server_name: str, url: str, payload: dict) -> dict | None:
    headers = {"Accept": "application/json, text/event-stream"}
    sid = _http_sessions.get(server_name)
    if sid:
        headers["Mcp-Session-Id"] = sid
    resp = await _http_client.post(url, json=payload, headers=headers)
    if resp.headers.get("Mcp-Session-Id"):
        _http_sessions[server_name] = resp.headers["Mcp-Session-Id"]
    if resp.status_code == 202 or not resp.content:
        return None
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        return _parse_sse(resp.text, payload.get("id"))
    return resp.json()


async def _forward_http(server_name: str, url: str, payload: dict) -> dict:
    reply = await _post_mcp(server_name, url, payload)
    if reply is None:
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": -32003, "message": f"{server_name} returned no response"}}
    return reply


async def _forward_stdio(server_name: str, payload: dict, trace_id: str, t0: float) -> dict:
    proc = _stdio_procs[server_name]
    req_id = str(payload.get("id"))
    future = asyncio.get_event_loop().create_future()
    _stdio_pending[server_name][req_id] = future
    _stdio_meta[server_name][req_id] = {"trace_id": trace_id, "t0": t0, "request": payload}
    proc.stdin.write((json.dumps(payload) + "\n").encode())
    await proc.stdin.drain()
    try:
        return await asyncio.wait_for(future, timeout=30)
    except asyncio.TimeoutError:
        _stdio_pending[server_name].pop(req_id, None)
        _stdio_meta[server_name].pop(req_id, None)
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": -32002, "message": f"{server_name} target timeout"}}


@app.post("/mcp/{server_name}")
async def mcp_endpoint(server_name: str, request: Request):
    trace_id = str(uuid.uuid4())
    t0 = time.monotonic()

    def elapsed_ms() -> float:
        return round((time.monotonic() - t0) * 1000, 2)

    # Buffer the exchange's log lines; flush them together with a single label
    # computed once the response + outcome are known (classifier.py).
    staged: list[dict] = []

    def stage(direction, payload, keywords=None, duration_ms=None, outcome=None):
        staged.append(dict(server=server_name, direction=direction, payload=payload,
                           keywords=keywords or {}, trace_id=trace_id,
                           duration_ms=duration_ms, outcome=outcome))

    def flush(request_payload, response_payload, final_outcome):
        label = classify(server_name, request_payload, response_payload, final_outcome)
        category = categorize(server_name, request_payload, response_payload, label)
        for e in staged:
            log_event(**e, label=label, category=category)

    if not AUTH_TOKEN or request.headers.get("Authorization") != f"Bearer {AUTH_TOKEN}":
        rp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32001, "message": "Unauthorized"}}
        stage("server_to_client", rp, {}, elapsed_ms(), "rejected_unauthorized")
        flush(None, rp, "rejected_unauthorized")
        return rp

    if server_name not in TARGETS:
        rp = {"jsonrpc": "2.0", "id": None,
              "error": {"code": -32004, "message": f"Unknown server '{server_name}'"}}
        stage("server_to_client", rp, {}, elapsed_ms(), "rejected_unknown_server")
        flush(None, rp, "rejected_unknown_server")
        return rp

    payload = await request.json()
    kw = extract_keywords(payload)
    cfg = TARGETS[server_name]
    stage("client_to_server", payload, kw)

    if server_name == "database":
        block = check_sql_identifier(payload)
        if block:
            rp = {"jsonrpc": "2.0", "id": payload.get("id"),
                  "error": {"code": -32006, "message": block}}
            stage("server_to_client", rp, {}, elapsed_ms(), "blocked_invalid_identifier")
            flush(payload, rp, "blocked_invalid_identifier")
            return rp

    if "id" not in payload:
        if cfg["transport"] == "http":
            await _post_mcp(server_name, cfg["url"], payload)
        else:
            proc = _stdio_procs[server_name]
            proc.stdin.write((json.dumps(payload) + "\n").encode())
            await proc.stdin.drain()
        ack = {"jsonrpc": "2.0", "id": None, "result": None}
        stage("server_to_client", ack, {}, elapsed_ms(), "acknowledged")
        flush(payload, ack, "acknowledged")
        return Response(status_code=202)

    if cfg["transport"] == "http":
        try:
            rp = await _forward_http(server_name, cfg["url"], payload)
        except httpx.HTTPError as e:
            rp = {"jsonrpc": "2.0", "id": payload.get("id"),
                  "error": {"code": -32003, "message": f"{server_name} unreachable: {e}"}}
            stage("server_to_client", rp, {}, elapsed_ms(), "connection_error")
            flush(payload, rp, "connection_error")
            return rp
        outcome = _outcome_for(rp)
        stage("server_to_client", rp, extract_keywords(rp), elapsed_ms(), outcome)
        flush(payload, rp, outcome)
    else:
        # Dormant in this all-HTTP testbed. The async reader logs + labels the
        # server_to_client line, so flush the staged client line now with a
        # request-only label.
        cl_label = classify(server_name, payload, None, None)
        cl_cat = categorize(server_name, payload, None, cl_label)
        for e in staged:
            log_event(**e, label=cl_label, category=cl_cat)
        staged.clear()
        rp = await _forward_stdio(server_name, payload, trace_id, t0)
        if "error" in rp and rp["error"].get("code") == -32002:
            to_lbl = classify(server_name, payload, rp, "timeout")
            log_event(server=server_name, direction="server_to_client", payload=rp,
                      keywords={}, trace_id=trace_id, duration_ms=elapsed_ms(),
                      outcome="timeout", label=to_lbl,
                      category=categorize(server_name, payload, rp, to_lbl))
    return rp


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT)
