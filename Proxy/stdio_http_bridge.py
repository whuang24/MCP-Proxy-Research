"""
Expose one stdio MCP server as a Streamable HTTP endpoint (MCP spec 2025-03-26+).

    python stdio_http_bridge.py --port 9101 -- <command> [args...]

POST /mcp   JSON-RPC request       -> 200 application/json (the matching reply)
            JSON-RPC notification  -> 202, no body
            initialize             -> also sets an Mcp-Session-Id response header
GET  /mcp   -> 405 (no server-initiated SSE stream)
DELETE /mcp -> 200 (session end)

One persistent child process serves all sessions. Server-initiated requests
(roots/list, ping, ...) can't be relayed over a plain-JSON response, so they get
a safe default reply, as the proxy did before.
"""
import argparse
import asyncio
import json
import sys
import uuid

import uvicorn
from fastapi import FastAPI, Request, Response

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--host", default="127.0.0.1")
ap.add_argument("--timeout", type=float, default=30)
ap.add_argument("cmd", nargs=argparse.REMAINDER)
args = ap.parse_args()
CMD = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
if not CMD:
    ap.error("missing stdio command after --")

app = FastAPI()
proc: asyncio.subprocess.Process
pending: dict[str, asyncio.Future] = {}


def _default_reply(method: str, req_id) -> dict:
    if method == "roots/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"roots": []}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    return {"jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"bridge: no client for '{method}'"}}


async def _send(msg: dict):
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    await proc.stdin.drain()


async def _reader():
    while True:
        line = await proc.stdout.readline()
        if not line:
            break
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "method" in msg:
            if msg.get("id") is not None:
                await _send(_default_reply(msg["method"], msg["id"]))
            continue
        fut = pending.pop(str(msg.get("id")), None)
        if fut and not fut.done():
            fut.set_result(msg)


@app.on_event("startup")
async def _start():
    global proc
    proc = await asyncio.create_subprocess_exec(
        *CMD, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=sys.stderr)
    asyncio.create_task(_reader())


@app.on_event("shutdown")
async def _stop():
    if proc.returncode is None:
        proc.terminate()


@app.post("/mcp")
async def post_mcp(request: Request):
    try:
        msg = await request.json()
    except json.JSONDecodeError:
        return Response(json.dumps({"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "Parse error"}}),
                        status_code=400, media_type="application/json")
    if isinstance(msg, list):
        return Response(json.dumps({"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32600, "message": "Batches not supported"}}),
                        status_code=400, media_type="application/json")
    if "id" not in msg:  # notification or client response
        await _send(msg)
        return Response(status_code=202)

    rid = str(msg["id"])
    fut = asyncio.get_running_loop().create_future()
    pending[rid] = fut
    await _send(msg)
    headers = {}
    if msg.get("method") == "initialize":
        headers["Mcp-Session-Id"] = request.headers.get("Mcp-Session-Id") or uuid.uuid4().hex
    try:
        reply = await asyncio.wait_for(fut, timeout=args.timeout)
    except asyncio.TimeoutError:
        pending.pop(rid, None)
        reply = {"jsonrpc": "2.0", "id": msg["id"],
                 "error": {"code": -32002, "message": "stdio backend timeout"}}
    return Response(json.dumps(reply), media_type="application/json", headers=headers)


@app.get("/mcp")
async def get_mcp():
    return Response(status_code=405, headers={"Allow": "POST, DELETE"})


@app.delete("/mcp")
async def delete_mcp():
    return Response(status_code=200)


if __name__ == "__main__":
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
