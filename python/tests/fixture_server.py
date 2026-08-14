"""A minimal classic-flow stdio MCP fixture server, entirely offline.

Speaks initialize / notifications/initialized / tools/list, line-delimited
JSON-RPC on stdio. The surface is controlled by environment variables so a
verifier run with different --env sees a different (drifted or inadmissible)
surface than the one locked:

    FIXTURE_TOOLS  JSON array of tool objects (default: one greet tool)
    FIXTURE_INSTR  server instructions string (default: "Be helpful.")
"""

import json
import os
import sys

DEFAULT_TOOLS = '[{"name":"greet","description":"Say hello.","inputSchema":{"type":"object"}}]'


def main() -> None:
    tools = json.loads(os.environ.get("FIXTURE_TOOLS", DEFAULT_TOOLS))
    instr = os.environ.get("FIXTURE_INSTR", "Be helpful.")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        rid = req.get("id")
        if rid is None:
            continue  # notification
        method = req.get("method")
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "serverInfo": {"name": "fixture", "version": "1"},
                "capabilities": {"tools": {}},
                "instructions": instr,
            }
        elif method == "tools/list":
            result = {"tools": tools}
        else:
            reply = {"jsonrpc": "2.0", "id": rid,
                     "error": {"code": -32601, "message": f"no method {method}"}}
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()
            continue
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
