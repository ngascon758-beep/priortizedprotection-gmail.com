"""
PPM (Prioritized Protection Model) Core
Sub-millisecond autonomic execution gate for AI agent tool interception.
"""

from enum import Enum
from functools import wraps
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional, Union

# Configure logger
logger = logging.getLogger("ppm_core")


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
    def __init__(self, active_invariants: Optional[List[Tier1Invariant]] = None) -> None:
        self.active_invariants: List[Tier1Invariant] = active_invariants or [
            Tier1Invariant.NO_DESTRUCTIVE_FS,
            Tier1Invariant.NO_UNAUTHORIZED_SHELL,
            Tier1Invariant.RESTRICT_OUTBOUND_SOCKETS,
        ]

    def _extract_all_strings(self, obj: Any) -> List[str]:
        """Recursively extract all string values from nested dicts, lists, or tuples."""
        strings: List[str] = []
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

    def evaluate(self, action_type: str, params: Optional[Union[Dict[str, Any], Any]] = None) -> bool:
        """
        Evaluates state safety against active invariants with sub-millisecond latency.
        """
        start_time = time.perf_counter()

        params_dict = params if isinstance(params, dict) else {"raw": params}
        all_str_values = self._extract_all_strings(params_dict)
        combined_text = " ".join(all_str_values)

        # Whitespace & tab normalization across newlines and tabs
        normalized_text = re.sub(r"[\s\t\n\r]+", " ", combined_text).lower()

        # 1. File System Invariants (Destructive actions & Path Traversal)
        if Tier1Invariant.NO_DESTRUCTIVE_FS in self.active_invariants:
            path_traversal_patterns = [
                r"\.\./", r"\.\.\\",              # Path traversal
                r"/etc/", r"/proc/", r"/sys/",    # Linux system dirs
                r"/dev/sd", r"/dev/hd",           # Raw block devices
                r"c:\\windows", r"c:\\system32"    # Windows system dirs
            ]
            for pattern in path_traversal_patterns:
                if re.search(pattern, normalized_text):
                    msg = f"Blocked path traversal/sensitive access in: '{combined_text}'"
                    logger.warning(f"PPM Invariant Violation: {Tier1Invariant.NO_DESTRUCTIVE_FS.value} - {msg}")
                    raise InvariantViolationError(msg)

            if action_type in ["file_delete", "delete", "remove"]:
                path = str(params_dict.get("path") or combined_text)
                msg = f"Blocked destructive filesystem action on path: '{path}'"
                logger.warning(f"PPM Invariant Violation: {Tier1Invariant.NO_DESTRUCTIVE_FS.value} - {msg}")
                raise InvariantViolationError(msg)

        # 2. Shell Execution Invariants (Piped commands & Evasion hardened)
        if Tier1Invariant.NO_UNAUTHORIZED_SHELL in self.active_invariants:
            if action_type in ["shell_exec", "exec", "bash", "system"]:
                cmd = str(params_dict.get("command") or normalized_text).lower()
                
                # Split chained/piped command segments (| ; &&)
                segments = re.split(r"[|;&]", cmd)

                dangerous_patterns = [
                    r"\brm\b",                # File removal
                    r"\bmkfs\b",              # Disk format
                    r"\bdd\b",                # Direct block writes
                    r">\s*/dev/sd",           # Partition overwrite
                    r"\bsudo\b", r"\bsu\b",   # Privilege escalation
                    r"\bwget\b", r"\bcurl\b", r"\bnc\b", r"\bnetcat\b",  # Network exfil
                    r"`.*`",                  # Backtick command injection
                    r"\$\(.*\)"               # Subshell command substitution
                ]

                for segment in segments:
                    clean_segment = segment.strip()
                    for pattern in dangerous_patterns:
                        if re.search(pattern, clean_segment):
                            msg = f"Blocked dangerous shell pattern '{pattern}' in segment: '{clean_segment}'"
                            logger.warning(f"PPM Invariant Violation: {Tier1Invariant.NO_UNAUTHORIZED_SHELL.value} - {msg}")
                            raise InvariantViolationError(msg)

        # 3. Outbound Socket/Network Invariants
        if Tier1Invariant.RESTRICT_OUTBOUND_SOCKETS in self.active_invariants:
            if action_type in ["socket_connect", "net_outbound", "http_request", "connect", "fetch"]:
                target = str(params_dict.get("host") or params_dict.get("url") or normalized_text).lower()
                
                restricted_patterns = [
                    r"169\.254\.169\.254",   # Cloud metadata endpoint (SSRF)
                    r"127\.0\.0\.1",          # Localhost loopback
                    r"localhost",
                    r"0\.0\.0\.0"
                ]
                for pattern in restricted_patterns:
                    if re.search(pattern, target):
                        msg = f"Blocked restricted outbound socket target: '{target}'"
                        logger.warning(f"PPM Invariant Violation: {Tier1Invariant.RESTRICT_OUTBOUND_SOCKETS.value} - {msg}")
                        raise InvariantViolationError(msg)

        # Performance metric check: Verify evaluation latency < 1 ms
        elapsed = time.perf_counter() - start_time
        if elapsed > 0.001:
            logger.warning(f"PPM evaluate exceeded sub-millisecond target: {elapsed * 1000:.3f}ms")

        return True

    def intercept(self, action_type: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """
        Decorator to wrap agent tool functions with deterministic invariant checks.
        """
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                params: Dict[str, Any] = kwargs.copy()
                
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
