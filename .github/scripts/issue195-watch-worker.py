#!/usr/bin/env python3
"""Observe worker exit with pidfd; deliberately cannot hold VM destruction."""
import os
from pathlib import Path
import select
import subprocess
import sys

pid = int(sys.argv[1])
expected_start = sys.argv[2]
fd = os.pidfd_open(pid)
start = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
if start != expected_start:
    raise SystemExit("Worker PID was reused")
print("worker_watch_ready", flush=True)
select.select([fd], [], [])
subprocess.run(["/usr/bin/bash", "/usr/local/bin/issue195-finalize", "worker-exit"], check=True)
