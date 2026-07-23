"""
PPM (Prioritized Protection Model) Core
Sub-millisecond autonomic execution gate for AI agent tool interception.
"""

from enum import Enum
from functools import wraps
import re


class InvariantViolationError(Exception):
    """Raised when an agent action violates a hard Tier-1 invariant."""
    pass


class Tier1Invariant(Enum):
    NO_DESTRUCTIVE_FS = "NO_DESTRUCTIVE_FS"
    NO_UNAUTHORIZED_SHELL = "NO_UNAUTHORIZED_SHELL"
    RESTRICT_OUTBOUND_SOCKETS = "RESTRICT_OUTBOUND_SOCKETS"


class AutonomicGate:
    """
    Autonomic reflex arc positioned between an AI model's reasoning loop 
    and tool execution layer.
    """
    def __init__(self, active_invariants=None):
        self.active_invariants = active_invariants or [
            Tier1Invariant.NO_DESTRUCTIVE_FS,
            Tier1Invariant.NO_UNAUTHORIZED_SHELL
        ]

    def evaluate(self, action_type: str, params: dict) -> bool:
        """
        Evaluates state safety against active invariants in < 1ms.
        """
        # 1. File System Invariants
        if Tier1Invariant.NO_DESTRUCTIVE_FS in self.active_invariants:
            if action_type in ["file_delete", "delete", "remove"]:
                path = params.get("path", "")
                raise InvariantViolationError(
                    f"Blocked destructive filesystem action on path: '{path}'"
                )

        # 2. Shell Execution Invariants
        if Tier1Invariant.NO_UNAUTHORIZED_SHELL in self.active_invariants:
            if action_type in ["shell_exec", "exec", "bash", "system"]:
                cmd = params.get("command", "")
                dangerous_patterns = [r"\brm\s+", r"mkfs", r"dd\s+", r">\s*/dev/sd"]
                for pattern in dangerous_patterns:
                    if re.search(pattern, cmd):
                        raise InvariantViolationError(
                            f"Blocked unauthorized/dangerous shell execution: '{cmd}'"
                        )

        return True

    def intercept(self, action_type: str):
        """
        Decorator to wrap agent tool functions with deterministic invariant checks.
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Map standard keyword args or positionals for checking
                params = kwargs.copy()
                if args and "path" not in params and "command" not in params:
                    params["path"] = args[0] if isinstance(args[0], str) else ""
                    params["command"] = args[0] if isinstance(args[0], str) else ""

                self.evaluate(action_type, params)
                return func(*args, **kwargs)
            return wrapper
        return decorator
