#!/usr/bin/env python3
"""
Minimal stdio MCP server that reproduces the flawed access check behind
CVE-2025-53110 (Anthropic Filesystem MCP Server, path-prefix validation bypass).

FOR LOCAL, ISOLATED TESTING ONLY. This process only ever looks at files under
--sandbox-root (fs-mcp-sandbox/ by default) and is never exposed outside the
proxy on this machine. Do not point --allowed-dir at anything outside the
sandbox and do not expose this process to untrusted callers.

The bug: the real (patched) server upgraded to a true containment check.
Pre-patch, it validated a requested path by testing whether the resolved
path STRING STARTS WITH the allowed directory string:

    def is_allowed(path, allowed_dir):
        return os.path.realpath(path).startswith(os.path.realpath(allowed_dir))

That passes for "/sandbox/allowed_dir_sensitive/credentials.txt" when
allowed_dir is "/sandbox/allowed_dir", because the STRING "allowed_dir" is a
prefix of the STRING "allowed_dir_sensitive" -- even though the sensitive
directory is a sibling, not a child, of the allowed one.

This server implements exactly that buggy check for one tool, read_file, so
the proxy has something real to send both benign and exploit traffic to.
"""
import argparse
import json
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--allowed-dir", required=True)
args = parser.parse_args()

ALLOWED_DIR = os.path.realpath(args.allowed_dir)

TOOLS = [{
    "name": "read_file",
    "description": "Read a file inside the allowed directory.",
    "inputSchema": {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
}]


def is_allowed_vulnerable(path: str) -> bool:
    """The CVE-2025-53110 check: prefix string match, not real containment."""
    resolved = os.path.realpath(path)
    return resolved.startswith(ALLOWED_DIR)


def handle(req: dict) -> dict | None:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "vuln-fs-server", "version": "pre-0.6.3"},
        }}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params", {})
        if params.get("name") != "read_file":
            return {"jsonrpc": "2.0", "id": req_id,
                     "error": {"code": -32601, "message": "unknown tool"}}
        path = params.get("arguments", {}).get("path", "")
        if not is_allowed_vulnerable(path):
            return {"jsonrpc": "2.0", "id": req_id, "result": {
                "isError": True,
                "content": [{"type": "text", "text": f"Access denied: {path} is outside the allowed directory"}],
            }}
        resolved = os.path.realpath(path)
        try:
            with open(resolved) as f:
                text = f.read()
        except OSError as e:
            return {"jsonrpc": "2.0", "id": req_id, "result": {
                "isError": True,
                "content": [{"type": "text", "text": f"Error reading {path}: {e}"}],
            }}
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "isError": False,
            "content": [{"type": "text", "text": text}],
        }}
    return {"jsonrpc": "2.0", "id": req_id,
             "error": {"code": -32601, "message": f"unknown method {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
