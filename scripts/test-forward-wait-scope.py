"""Run with python3 scripts/test-forward-wait-scope.py; no cluster required."""
from pathlib import Path
import subprocess

for name in (
    "e2e-dcr-backchannel-kind.sh",
    "e2e-password-grant-kind.sh",
    "e2e-forward-auth-ha-kind.sh",
):
    path = Path(__file__).parent / name
    source = path.read_text()
    start = source.index("wait_forward()")
    end = source.index("\n)", start) + 2
    function = source[start:end]
    # Stub only external readiness probes; exercise the actual shell function.
    check = """
grep() { return 0; }
nc() { return 0; }
port=59401
wait_forward "$$" unused "$((port + 1))"
test "$port" = 59401
"""
    subprocess.run(["sh", "-n", str(path)], check=True)
    subprocess.run(["sh", "-eu", "-c", function + check], check=True)
    broken = function.replace("wait_forward() (", "wait_forward() {", 1)
    broken = broken[:-1] + "}"
    assert subprocess.run(["sh", "-eu", "-c", broken + check]).returncode != 0
print("forward-wait scope checks passed")
