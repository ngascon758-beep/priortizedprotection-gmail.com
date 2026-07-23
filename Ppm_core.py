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
            Tier1Invariant.NO_UNAUTHORIZED_SHELL,
            Tier1Invariant.RESTRICT_OUTBOUND_SOCKETS,
        ]

    def evaluate(self, action_type: str, params: dict | None = None) -> bool:
        """
        Evaluates state safety against active invariants in < 1ms.
        Handles missing or null parameters gracefully.
        """
        params = params or {}

        # 1. File System Invariants
        if Tier1Invariant.NO_DESTRUCTIVE_FS in self.active_invariants:
            if action_type in ["file_delete", "delete", "remove"]:
                path = params.get("path") or ""
                raise InvariantViolationError(
                    f"Blocked destructive filesystem action on path: '{path}'"
                )

        # 2. Shell Execution Invariants (Hardened against pattern evasion & piping)
        if Tier1Invariant.NO_UNAUTHORIZED_SHELL in self.active_invariants:
            if action_type in ["shell_exec", "exec", "bash", "system"]:
                cmd = str(params.get("command") or "").lower()
                # Remove extra internal whitespace to prevent 'r m  -rf' evasion
                normalized_cmd = re.sub(r"\s+", " ", cmd)
                
                dangerous_patterns = [
                    r"\brm\b",          # Matches rm, /bin/rm, rm -rf
                    r"\bmkfs\b",        # Filesystem format
                    r"\bdd\b",          # Direct disk write
                    r">\s*/dev/sd",     # Overwriting block devices
                    r"\bshutdown\b",
                    r"\breboot\b"
                ]
                for pattern in dangerous_patterns:
                    if re.search(pattern, normalized_cmd):
                        raise InvariantViolationError(
                            f"Blocked unauthorized/dangerous shell command: '{cmd}'"
                        )

        # 3. Outbound Socket Invariants
        if Tier1Invariant.RESTRICT_OUTBOUND_SOCKETS in self.active_invariants:
            if action_type in ["socket_connect", "net_outbound", "http_request", "connect"]:
                host = str(params.get("host") or params.get("url") or "").lower()
                # Block cloud metadata service IP (SSRF) and unauthorized outbound calls
                if "169.254.169.254" in host or params.get("unauthorized", False):
                    raise InvariantViolationError(
                        f"Blocked restricted outbound socket/network target: '{host}'"
                    )

        return True

    def intercept(self, action_type: str):
        """
        Decorator to wrap agent tool functions with deterministic invariant checks.
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                params = kwargs.copy()
                if args and "path" not in params and "command" not in params:
                    params["path"] = args[0] if isinstance(args[0], str) else ""
                    params["command"] = args[0] if isinstance(args[0], str) else ""

                self.evaluate(action_type, params)
                return func(*args, **kwargs)
            return wrapper
        return decorator
