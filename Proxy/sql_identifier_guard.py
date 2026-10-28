"""
Defense-in-depth input validation for the sqlite MCP target.

mcp-server-sqlite's describe_table tool builds its query as
    f"PRAGMA table_info({arguments['table_name']})"
without validating table_name first (see modelcontextprotocol/servers-archived,
src/sqlite/src/mcp_server_sqlite/server.py). sqlite3.Cursor.execute() only runs
a single statement, which blocks classic ";-stacked" injection, but an
unvalidated identifier is still bad practice and could matter against a
different sqlite3 build or a future server rewrite. We enforce a strict
identifier allowlist at the proxy so a malformed table_name never reaches the
backend at all, regardless of how well-behaved that backend turns out to be.
"""
import re

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def check(payload: dict) -> str | None:
    """
    Returns an error message if this request should be blocked, else None.
    Only inspects describe_table calls; everything else passes through.
    """
    if payload.get("method") != "tools/call":
        return None
    params = payload.get("params", {})
    if params.get("name") != "describe_table":
        return None
    table_name = params.get("arguments", {}).get("table_name")
    if not isinstance(table_name, str) or not _SAFE_IDENTIFIER.match(table_name):
        return f"Blocked by proxy: '{table_name}' is not a valid table identifier"
    return None
