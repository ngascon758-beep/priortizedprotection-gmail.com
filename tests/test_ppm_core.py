"""Test suite for PPM Core autonomic execution gate."""

import pytest
from Ppm_core import (
    AutonomicGate,
    Tier1Invariant,
    InvariantViolationError,
)


class TestTier1Invariants:
    """Test Tier-1 invariant enforcement."""

    def test_no_destructive_fs_blocks_delete(self):
        """Test that NO_DESTRUCTIVE_FS blocks file delete operations."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_DESTRUCTIVE_FS]
        )

        with pytest.raises(InvariantViolationError) as exc_info:
            gate.evaluate("file_delete", {"path": "/tmp/test.txt"})

        assert "Blocked destructive filesystem action" in str(exc_info.value)

    def test_no_destructive_fs_blocks_remove(self):
        """Test that NO_DESTRUCTIVE_FS blocks remove operations."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_DESTRUCTIVE_FS]
        )

        with pytest.raises(InvariantViolationError):
            gate.evaluate("remove", {"path": "/data/file.txt"})

    def test_no_destructive_fs_blocks_delete_action(self):
        """Test that NO_DESTRUCTIVE_FS blocks 'delete' action type."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_DESTRUCTIVE_FS]
        )

        with pytest.raises(InvariantViolationError):
            gate.evaluate("delete", {"path": "/important/data.db"})

    def test_no_unauthorized_shell_blocks_rm(self):
        """Test that NO_UNAUTHORIZED_SHELL blocks rm commands."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_UNAUTHORIZED_SHELL]
        )

        with pytest.raises(InvariantViolationError) as exc_info:
            gate.evaluate("shell_exec", {"command": "rm -rf /home/user/data"})

        assert "Blocked unauthorized/dangerous shell execution" in str(
            exc_info.value
        )

    def test_no_unauthorized_shell_blocks_mkfs(self):
        """Test that NO_UNAUTHORIZED_SHELL blocks mkfs commands."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_UNAUTHORIZED_SHELL]
        )

        with pytest.raises(InvariantViolationError):
            gate.evaluate("shell_exec", {"command": "mkfs.ext4 /dev/sda1"})

    def test_no_unauthorized_shell_blocks_dd(self):
        """Test that NO_UNAUTHORIZED_SHELL blocks dd commands."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_UNAUTHORIZED_SHELL]
        )

        with pytest.raises(InvariantViolationError):
            gate.evaluate("shell_exec", {"command": "dd if=/dev/zero of=/dev/sda"})

    def test_no_unauthorized_shell_blocks_dev_redirect(self):
        """Test that NO_UNAUTHORIZED_SHELL blocks /dev/sd writes."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_UNAUTHORIZED_SHELL]
        )

        with pytest.raises(InvariantViolationError):
            gate.evaluate("bash", {"command": "echo malicious > /dev/sda"})


class TestAutonomicGateConfiguration:
    """Test AutonomicGate configuration and initialization."""

    def test_default_invariants(self):
        """Test that default invariants are set correctly."""
        gate = AutonomicGate()
        assert Tier1Invariant.NO_DESTRUCTIVE_FS in gate.active_invariants
        assert Tier1Invariant.NO_UNAUTHORIZED_SHELL in gate.active_invariants

    def test_custom_invariants(self):
        """Test that custom invariants can be configured."""
        custom_invariants = [Tier1Invariant.RESTRICT_OUTBOUND_SOCKETS]
        gate = AutonomicGate(active_invariants=custom_invariants)
        assert gate.active_invariants == custom_invariants

    def test_empty_invariants_allows_all(self):
        """Test that empty invariants list allows all actions."""
        gate = AutonomicGate(active_invariants=[])
        # Should not raise any exception
        assert gate.evaluate("file_delete", {"path": "/tmp/test"}) is True
        assert gate.evaluate("shell_exec", {"command": "rm -rf /"}) is True


class TestInterceptDecorator:
    """Test the intercept decorator functionality."""

    def test_intercept_decorator_blocks_violation(self):
        """Test that intercept decorator blocks violating function calls."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_DESTRUCTIVE_FS]
        )

        @gate.intercept("file_delete")
        def delete_file(path):
            return f"Deleted {path}"

        with pytest.raises(InvariantViolationError):
            delete_file("/tmp/important.txt")

    def test_intercept_decorator_allows_safe_operations(self):
        """Test that intercept decorator allows safe operations."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_UNAUTHORIZED_SHELL]
        )

        @gate.intercept("shell_exec")
        def safe_command(cmd):
            return f"Executed: {cmd}"

        result = safe_command("echo 'hello world'")
        assert result == "Executed: echo 'hello world'"

    def test_intercept_with_kwargs(self):
        """Test intercept decorator with keyword arguments."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_DESTRUCTIVE_FS]
        )

        @gate.intercept("file_delete")
        def delete_with_kwargs(path=None):
            return f"Deleted {path}"

        with pytest.raises(InvariantViolationError):
            delete_with_kwargs(path="/tmp/test.txt")


class TestEvaluateMethod:
    """Test the evaluate method directly."""

    def test_evaluate_returns_true_on_success(self):
        """Test that evaluate returns True on successful validation."""
        gate = AutonomicGate(active_invariants=[])
        result = gate.evaluate("safe_operation", {})
        assert result is True

    def test_evaluate_with_multiple_invariants(self):
        """Test evaluate with multiple active invariants."""
        gate = AutonomicGate(
            active_invariants=[
                Tier1Invariant.NO_DESTRUCTIVE_FS,
                Tier1Invariant.NO_UNAUTHORIZED_SHELL,
            ]
        )

        # Safe operation should pass
        assert gate.evaluate("read_file", {"path": "/tmp/test.txt"}) is True

        # Destructive FS should fail
        with pytest.raises(InvariantViolationError):
            gate.evaluate("file_delete", {"path": "/tmp/test.txt"})

        # Shell exec with safe command should pass
        assert gate.evaluate("shell_exec", {"command": "ls -la"}) is True

        # Shell exec with dangerous command should fail
        with pytest.raises(InvariantViolationError):
            gate.evaluate("bash", {"command": "rm -rf /home"})


class TestErrorMessages:
    """Test that error messages are informative."""

    def test_fs_error_includes_path(self):
        """Test that filesystem error messages include the blocked path."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_DESTRUCTIVE_FS]
        )
        test_path = "/var/sensitive/data.db"

        with pytest.raises(InvariantViolationError) as exc_info:
            gate.evaluate("delete", {"path": test_path})

        assert test_path in str(exc_info.value)

    def test_shell_error_includes_command(self):
        """Test that shell error messages include the blocked command."""
        gate = AutonomicGate(
            active_invariants=[Tier1Invariant.NO_UNAUTHORIZED_SHELL]
        )
        dangerous_cmd = "rm -rf /root"

        with pytest.raises(InvariantViolationError) as exc_info:
            gate.evaluate("shell_exec", {"command": dangerous_cmd})

        assert dangerous_cmd in str(exc_info.value)
