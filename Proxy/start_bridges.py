"""Launch a stdio_http_bridge.py for every target that has a "backend".

Usage: python start_bridges.py <targets.json>

Each backend may carry an optional "env" dict (e.g. MEMORY_FILE_PATH for the
memory server); it is merged into the bridge subprocess environment and
inherited by the stdio backend the bridge spawns.
"""
import json
import os
import signal
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
targets_file = sys.argv[1] if len(sys.argv) > 1 else "targets.benign.json"
targets = json.load(open(targets_file))

procs = []
for name, cfg in targets.items():
    b = cfg.get("backend")
    if not b:
        continue
    port = cfg["url"].rsplit(":", 1)[1].split("/")[0]
    env = dict(os.environ)
    env.update(b.get("env", {}))
    print(f"bridge {name}: {cfg['url']}", flush=True)
    procs.append(subprocess.Popen(
        [sys.executable, os.path.join(HERE, "stdio_http_bridge.py"),
         "--port", port, "--", b["command"], *b["args"]],
        env=env))

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
try:
    for p in procs:
        p.wait()
except (KeyboardInterrupt, SystemExit):
    pass
finally:
    for p in procs:
        p.terminate()
