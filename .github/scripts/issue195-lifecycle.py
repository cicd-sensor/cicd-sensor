#!/usr/bin/env python3
"""Read lifecycle evidence; never execute or change provider scripts.

Print only lifecycle-related lines from shell scripts. Avoid environment dumps,
runner configuration/credential files, and full process command lines.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess


def emit(kind, **values):
    print(json.dumps({"kind": kind, **values}, ensure_ascii=False), flush=True)


def redact(line):
    if re.search(r"token|password|passwd|secret|credential|authorization|private.key|api.key|access.key", line, re.I):
        return "<credential-related line omitted>"
    line = re.sub(r"https?://[^\s\"'<>]+", "<url>", line)
    line = re.sub(r"(?i)((?:[A-Z_]*(?:TOKEN|PASSWORD|SECRET|API_KEY)[A-Z_]*)\s*=).*", r"\1<redacted>", line)
    line = re.sub(r"(?i)(authorization\s*[:=]).*", r"\1<redacted>", line)
    line = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|sk_cs_[A-Za-z0-9_]+)\b", "<redacted>", line)
    return line[:800]


emit("environment", kernel=platform.release(), arch=platform.machine(), btf=Path("/sys/kernel/btf/vmlinux").exists())
cmdline = Path("/proc/cmdline").read_text()
emit("kernel_reboot", arguments=[v for v in cmdline.split() if v.startswith(("reboot=", "panic="))])

paths = {Path(p) for p in ("/setup.sh", "/job_completed.sh", "/run.sh", "/start.sh", "/entrypoint.sh", "/reboot.sh")}
paths.update(path for path in Path("/").glob("*.sh") if path.is_file())
provider_binaries = set()
processes = []
for proc in Path("/proc").iterdir():
    if not proc.name.isdigit():
        continue
    try:
        comm = (proc / "comm").read_text().strip()
        argv = (proc / "cmdline").read_bytes().split(b"\0")
        executable = os.readlink(proc / "exe")
        if "blacksmith" in comm.lower():
            provider_binaries.add(Path(executable))
        if any(word in comm.lower() for word in ("runner", "blacksmith")) or comm in ("bash", "sh", "dash"):
            status = (proc / "status").read_text()
            parent = re.search(r"^PPid:\s+(\d+)", status, re.M)
            processes.append({"pid": int(proc.name), "ppid": int(parent[1]) if parent else None,
                              "comm": comm, "exe": executable,
                              "cgroup": (proc / "cgroup").read_text().strip()})
            for raw in argv[:3]:
                candidate = Path(raw.decode(errors="replace"))
                if not candidate.is_absolute() and candidate.suffix == ".sh":
                    candidate = (proc / "cwd").resolve() / candidate
                if candidate.is_absolute() and candidate.suffix == ".sh" and candidate.is_file():
                    paths.add(candidate)
        # Only read the two hook names from Runner process environments.
        if comm.startswith("Runner."):
            for entry in (proc / "environ").read_bytes().split(b"\0"):
                name, _, value = entry.partition(b"=")
                if name in (b"ACTIONS_RUNNER_HOOK_JOB_STARTED", b"ACTIONS_RUNNER_HOOK_JOB_COMPLETED"):
                    hook = value.decode(errors="replace")
                    emit("hook", pid=int(proc.name), name=name.decode(), path=hook)
                    if Path(hook).is_absolute():
                        paths.add(Path(hook))
    except (OSError, ValueError):
        continue
emit("processes", entries=processes)

interesting = re.compile(r"performReboot|vmshutdown|sysrq|reboot|shutdown|trap |job_completed|ACTIONS_RUNNER_HOOK|blacksmithd|Runner\.Listener|run\.sh|runsvc\.sh|docker.*stop|umount", re.I)
for path in sorted(paths):
    try:
        data = path.read_bytes()
        if len(data) > 256 * 1024 or b"\0" in data:
            continue
        text = data.decode("utf-8")
        if not (text.startswith("#!") or path.suffix == ".sh"):
            continue
        source_lines = text.splitlines()
        selected = set()
        for i, line in enumerate(source_lines):
            if interesting.search(line):
                selected.update(range(max(0, i - 3), min(len(source_lines), i + 4)))
        lines = [{"line": i + 1, "text": redact(source_lines[i])} for i in sorted(selected)]
        emit("script", path=str(path), sha256=hashlib.sha256(data).hexdigest(),
             mode=oct(path.stat().st_mode & 0o777), lifecycle_lines=lines)
    except (OSError, UnicodeError):
        continue

for path in sorted(provider_binaries):
    try:
        if path.stat().st_size > 100 * 1024 * 1024:
            continue
        data = path.read_bytes()
        # Presence is static evidence only, not proof a reboot path executed.
        markers = ["forcing reboot via sysrq", "falling back to reboot syscall",
                   "vmshutdown", "/proc/sysrq-trigger", "syscall.Reboot"]
        emit("provider_binary", path=str(path), sha256=hashlib.sha256(data).hexdigest(),
             markers={marker: marker.encode() in data for marker in markers})
    except OSError:
        continue

result = subprocess.run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"], capture_output=True, text=True, timeout=10)
units = [line.split()[0] for line in result.stdout.splitlines() if re.search(r"blacksmith|actions\.runner", line, re.I)]
for unit in units:
    result = subprocess.run(["systemctl", "show", unit, "--property=Id,MainPID,ControlGroup,ActiveState,After,Before"], capture_output=True, text=True, timeout=10)
    emit("unit", name=unit, properties=result.stdout.strip())
