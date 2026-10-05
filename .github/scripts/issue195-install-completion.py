#!/usr/bin/env python3
"""Experimental, hash-gated wrapper for one disposable Blacksmith VM."""
import hashlib
import os
from pathlib import Path
import shlex
import subprocess

hook = Path("/job_completed.sh")
expected = "42b819fe601e6125639174386b90f216e875f7960b30896f58fb2ed3aa412ff4"
data = hook.read_bytes()
actual = hashlib.sha256(data).hexdigest()
print("completed_hook_sha256=" + actual, flush=True)
if actual != expected:
    raise SystemExit("Provider hook changed; refusing to wrap an unreviewed script")
root = Path("/run/issue195")
root.mkdir(mode=0o755, exist_ok=True)
unit = "cicd-sensor-agent.service"
def prop(name):
    return subprocess.check_output(["systemctl", "show", unit, "--value", "--property=" + name], text=True).strip()
if prop("ActiveState") != "active" or prop("Transient") != "yes" or prop("Restart") != "no":
    raise SystemExit("Expected the fresh Action-owned transient agent without restart")
keys = ["GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "PROBE_RUNNER",
        "PROBE_REP", "PROBE_ORDER", "PROBE_ENDPOINT"]
context = {k: os.environ[k] for k in keys}
context["PROBE_TRACKING_ID"] = os.environ["RUNNER_TRACKING_ID"]
context["EXPECTED_INVOCATION_ID"] = prop("InvocationID")
if not context["EXPECTED_INVOCATION_ID"]:
    raise SystemExit("Missing agent invocation ID")
target = root / "context.env"
target.write_text("".join(f"export {k}={shlex.quote(v)}\n" for k, v in context.items()))
target.chmod(0o644)  # Only run identity and non-secret diagnostic endpoint.
if os.environ["ISSUE195_MODE"] == "baseline":
    raise SystemExit(0)
backup = root / "provider-completed.sh"
if backup.exists():
    raise SystemExit("Already installed")
backup.write_bytes(data)
backup.chmod(0o755)
wrapper = root / "wrapper.sh"
wrapper.write_text('''#!/usr/bin/env bash
# Preserve the provider's shell options, arguments, environment and failure.
provider_rc=0
/usr/bin/bash --noprofile --norc -e -o pipefail /run/issue195/provider-completed.sh "$@" || provider_rc=$?
sensor_rc=0
sudo /usr/bin/bash /usr/local/bin/issue195-finalize "$provider_rc" || sensor_rc=$?
if [ "$provider_rc" -ne 0 ]; then exit "$provider_rc"; fi
exit "$sensor_rc"
''')
wrapper.chmod(0o755)
# Atomic replacement; original bytes remain in the root-owned backup.
staged = hook.with_name("job_completed.issue195.new.sh")
staged.write_bytes(wrapper.read_bytes())
staged.chmod(0o755)
staged.replace(hook)
print("completion_wrapper_installed", flush=True)
