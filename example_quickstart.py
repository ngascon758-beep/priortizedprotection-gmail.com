"""
Quickstart Demo: Intercepting unsafe agent actions with PPM
"""
from ppm_core import AutonomicGate, InvariantViolationError

gate = AutonomicGate()

@gate.intercept("shell_exec")
def run_agent_command(command: str):
    return f"Executing safely: {command}"

# 1. Safe execution
print(run_agent_command("ls -la"))

# 2. Blocked malicious attempt
try:
    run_agent_command("rm -rf / --no-preserve-root")
except InvariantViolationError as e:
    print(f"\n[BLOCKED BY PPM]: {e}")
