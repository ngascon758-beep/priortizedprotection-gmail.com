import pytest
from ppm_core import AutonomicGate, Tier1Invariant, InvariantViolationError

def test_safe_action_passes():
    gate = AutonomicGate([Tier1Invariant.NO_DESTRUCTIVE_FS])
    assert gate.evaluate("file_read", {"path": "config.json"}) is True

def test_destructive_file_blocked():
    gate = AutonomicGate([Tier1Invariant.NO_DESTRUCTIVE_FS])
    with pytest.raises(InvariantViolationError):
        gate.evaluate("file_delete", {"path": "database.db"})

def test_unauthorized_shell_blocked():
    gate = AutonomicGate([Tier1Invariant.NO_DESTRUCTIVE_FS])
    with pytest.raises(InvariantViolationError):
        gate.evaluate("shell_exec", {"command": "rm -rf /"})
