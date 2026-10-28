#!/usr/bin/env python3
"""
A small, dependency-free stdio MCP server for SQLite, written to avoid the
common attack classes in this kind of server:

  - SQL injection via string-built queries: identifiers (table names) are
    validated against a strict allowlist regex AND checked against the
    database's actual schema before being interpolated into a PRAGMA
    statement (PRAGMA doesn't support bound parameters in sqlite3). Query
    bodies for read/write/create are never built by concatenating untrusted
    fragments -- the caller's full statement is executed as-is, which is the
    intended "run SQL" surface of this class of tool, scoped down by:
  - Multi-statement / stacked-query injection: python's sqlite3 refuses to
    execute more than one statement per call (confirmed on this host), so
    "SELECT 1; DROP TABLE x;" raises instead of running.
  - Privilege separation between reads and writes: read_query opens the
    database with SQLite's native read-only URI mode (mode=ro), so even a
    cleverly-crafted "SELECT" cannot write, regardless of query content.
  - Path confusion: the database file path is fixed at startup via
    --db-path and never taken from request arguments.

This server speaks newline-delimited JSON-RPC on stdin/stdout, matching the
framing the proxy already expects (see proxy_server.py's _stdio_reader).
"""
import argparse
import json
import re
import sqlite3
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--db-path", required=True)
args = parser.parse_args()
DB_PATH = args.db_path

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

TOOLS = [
    {
        "name": "list_tables",
        "description": "List all tables in the database.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "describe_table",
        "description": "Show column info for a table.",
        "inputSchema": {
            "type": "object",
            "properties": {"table_name": {"type": "string"}},
            "required": ["table_name"],
        },
    },
    {
        "name": "read_query",
        "description": "Execute a single read-only SELECT query.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "write_query",
        "description": "Execute a single INSERT, UPDATE, or DELETE statement.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "create_table",
        "description": "Execute a single CREATE TABLE statement.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
]


def _existing_tables(conn) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows}


def _tool_error(req_id, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "result": {"isError": True, "content": [{"type": "text", "text": message}]}}


def _tool_ok(req_id, text: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id,
            "result": {"isError": False, "content": [{"type": "text", "text": text}]}}


def call_tool(req_id, name: str, tool_args: dict) -> dict:
    tool_args = tool_args or {}

    if name == "list_tables":
        conn = sqlite3.connect(DB_PATH)
        try:
            return _tool_ok(req_id, json.dumps(sorted(_existing_tables(conn))))
        finally:
            conn.close()

    if name == "describe_table":
        table_name = tool_args.get("table_name", "")
        if not _SAFE_IDENTIFIER.match(table_name):
            return _tool_error(req_id, f"'{table_name}' is not a valid table identifier")
        conn = sqlite3.connect(DB_PATH)
        try:
            # Belt-and-suspenders: only interpolate a name we've confirmed
            # already exists in the schema, never an arbitrary caller string.
            if table_name not in _existing_tables(conn):
                return _tool_error(req_id, f"No such table: {table_name}")
            rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
            cols = [{"name": r[1], "type": r[2], "notnull": bool(r[3]), "pk": bool(r[5])} for r in rows]
            return _tool_ok(req_id, json.dumps(cols))
        finally:
            conn.close()

    if name == "read_query":
        query = tool_args.get("query", "")
        if not query.strip().upper().startswith("SELECT"):
            return _tool_error(req_id, "Only SELECT queries are allowed for read_query")
        # Native read-only connection: a write can't happen here even if the
        # query text were somehow crafted to attempt one.
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        try:
            cur = conn.execute(query)
            cols = [d[0] for d in cur.description or []]
            rows = [dict(zip(cols, row)) for row in cur.fetchall()]
            return _tool_ok(req_id, json.dumps(rows))
        except sqlite3.Error as e:
            return _tool_error(req_id, f"Database error: {e}")
        finally:
            conn.close()

    if name == "write_query":
        query = tool_args.get("query", "")
        if query.strip().upper().startswith("SELECT"):
            return _tool_error(req_id, "SELECT queries are not allowed for write_query")
        conn = sqlite3.connect(DB_PATH)
        try:
            cur = conn.execute(query)
            conn.commit()
            return _tool_ok(req_id, json.dumps({"affected_rows": cur.rowcount}))
        except sqlite3.Error as e:
            return _tool_error(req_id, f"Database error: {e}")
        finally:
            conn.close()

    if name == "create_table":
        query = tool_args.get("query", "")
        if not query.strip().upper().startswith("CREATE TABLE"):
            return _tool_error(req_id, "Only CREATE TABLE statements are allowed")
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(query)
            conn.commit()
            return _tool_ok(req_id, "Table created successfully")
        except sqlite3.Error as e:
            return _tool_error(req_id, f"Database error: {e}")
        finally:
            conn.close()

    return {"jsonrpc": "2.0", "id": req_id,
             "error": {"code": -32601, "message": f"unknown tool: {name}"}}


def handle(req: dict) -> dict | None:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "safe-sqlite-server", "version": "1.0.0"},
        }}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params", {})
        return call_tool(req_id, params.get("name"), params.get("arguments"))
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
