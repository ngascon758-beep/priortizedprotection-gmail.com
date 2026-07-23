"""
PPM (Prioritized Protection Model) Core
Sub-millisecond autonomic execution gate for AI agent tool interception.
"""

from enum import Enum
from functools import wraps
import re
from typing import Any, Dict, List, Union


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

    def _extract_all_strings(self, obj: Any) -> List[str]:
        """Recursively extract all string values from nested dicts, lists, or tuples."""
        strings = []
        if isinstance(obj, str):
            strings.append(obj)
        elif isinstance(obj, dict):
            for k, v in obj.items():
                strings.extend(self._extract_all_strings(k))
                strings.extend(self._extract_all_strings(v))
        elif isinstance(obj, (list, tuple, set)):
            for item in obj:
                strings.extend(self._extract_all_strings(item))
        return strings

    def evaluate(self, action_type: str, params: Union[Dict, Any] = None) -> bool:
        """
        Evaluates state safety against active invariants in < 1ms.
        Scans parameter keys, values, and positional structures.
        """
        params = params if isinstance(params, dict) else {"raw": params}
        all_str_values = self._extract_all_strings(params)
        combined_text = " ".join(all_str_values).lower()

        # 1. File System Invariants (Destructive actions & Path Traversal)
        if Tier1Invariant.NO_DESTRUCTIVE_FS in self.active_invariants:
            # Path Traversal & Sensitive System Directories
            path_traversal_patterns = [
                r"\.\./", r"\.\.\\",              # Path traversal
                r"/etc/", r"/proc/", r"/sys/",    # Linux system dirs
                r"c:\\windows", r"c:\\system32"    # Windows system dirs
            ]
            for pattern in path_traversal_patterns:
                if re.search(pattern, combined_text):
                    raise InvariantViolationError(
                        f"Blocked path traversal or sensitive directory access in: '{combined_text}'"
                    )

            if action_type in ["file_delete", "delete", "remove"]:
                path = str(params.get("path") or combined_text)
                raise InvariantViolationError(
                    f"Blocked destructive filesystem action on path: '{path}'"
                )

        # 2. Shell Execution Invariants (Hardened against injection, exfil, & escalation)
        if Tier1Invariant.NO_UNAUTHORIZED_SHELL in self.active_invariants:
            if action_type in ["shell_exec", "exec", "bash", "system"]:
                cmd = str(params.get("command") or combined_text).lower()
                normalized_cmd = re.sub(r"\s+", " ", cmd)

                dangerous_patterns = [
                    r"\brm\b",                # File removal
                    r"\bmkfs\b",              # Disk format
                    r"\bdd\b",                # Direct block writes
                    r">\s*/dev/sd",           # Partition overwrite
                    r"\bsudo\b", r"\bsu\b",   # Privilege escalation
                    r"\bwget\b", r"\bcurl\b", r"\bnc\b", r"\bnetcat\b",  # Network exfil
                    r"`.*`",                  # Backtick command injection
                    r"\$\(.*\)",              # Subshell command substitution
                    r"\|", r";", r"&&"        # Command chaining
                ]
                for pattern in dangerous_patterns:
                    if re.search(pattern, normalized_cmd):
                        raise InvariantViolationError(
                            f"Blocked unauthorized shell execution pattern '{pattern}' in: '{cmd}'"
                        )

        # 3. Outbound Socket/Network Invariants
        if Tier1Invariant.RESTRICT_OUTBOUND_SOCKETS in self.active_invariants:
            if action_type in ["socket_connect", "net_outbound", "http_request", "connect", "fetch"]:
                target = str(params.get("host") or params.get("url") or combined_text).lower()
                
                restricted_patterns = [
                    r"169\.254\.169\.254",   # Cloud metadata endpoint (SSRF)
                    r"127\.0\.0\.1",          # Localhost loopback
                    r"localhost",
                    r"0\.0\.0\.0"
                ]
                for pattern in restricted_patterns:
                    if re.search(pattern, target):
                        raise InvariantViolationError(
                            f"Blocked restricted outbound socket target: '{target}'"
                        )

        return True

    def intercept(self, action_type: str):
        """
        Decorator to wrap agent tool functions with deterministic invariant checks.
        Intelligently assigns positional arguments based on action type.
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                params = kwargs.copy()
                
                # Context-aware positional argument mapping
                if args:
                    if action_type in ["shell_exec", "exec", "bash", "system"] and "command" not in params:
                        params["command"] = args[0]
                    elif action_type in ["file_delete", "delete", "remove", "file_read", "file_write"] and "path" not in params:
                        params["path"] = args[0]
                    elif action_type in ["socket_connect", "net_outbound", "http_request", "connect"] and "host" not in params:
                        params["host"] = args[0]
                    else:
                        params["positional_args"] = list(args)

                self.evaluate(action_type, params)
                return func(*args, **kwargs)
            return wrapper
        return decorator
