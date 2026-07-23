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
    gate = AutonomicGate([Tier1Invariant.NO_UNAUTHORIZED_SHELL])
    with pytest.raises(InvariantViolationError):
        gate.evaluate("shell_exec", {"command": "rm -rf /"})


def test_piped_and_chained_commands_blocked():
    """Verifies that evasion attempts like 'ls | rm -rf /' are caught."""
    gate = AutonomicGate([Tier1Invariant.NO_UNAUTHORIZED_SHELL])
    with pytest.raises(InvariantViolationError):
        gate.evaluate("shell_exec", {"command": "echo hello && rm -rf /"})


def test_outbound_socket_restriction():
    """Verifies socket and SSRF metadata blocking."""
    gate = AutonomicGate([Tier1Invariant.RESTRICT_OUTBOUND_SOCKETS])
    with pytest.raises(InvariantViolationError):
        gate.evaluate("http_request", {"host": "http://169.254.169.254/latest/meta-data"})


def test_null_or_empty_parameters_handled_safely():
    """Verifies gate doesn't crash on None or empty parameters."""
    gate = AutonomicGate()
    assert gate.evaluate("file_read", None) is True
    assert gate.evaluate("file_read", {}) is True
