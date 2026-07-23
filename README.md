# PPM Core - Prioritized Protection Model

**Runtime safety gate and autonomic threat intercept for AI agents and LLM execution pipelines.**

A sub-millisecond deterministic execution gate that enforces Tier-1 safety invariants between AI model reasoning loops and tool execution layers. Blocks unauthorized state transitions, dangerous commands, and policy violations before they execute.

## Features

- **Autonomic Reflex Arc**: Positioned between AI model reasoning and tool execution
- **Sub-millisecond Evaluation**: Deterministic safety checks in <1ms latency
- **Tier-1 Invariants**: Hard safety guarantees that cannot be bypassed
- **Pattern Evasion Hardened**: Defends against whitespace injection, piped commands, and encoding tricks

## Tier-1 Invariants

### 1. NO_DESTRUCTIVE_FS
Blocks destructive filesystem operations and path traversal attacks:
- File deletion/removal operations
- System directory access (`/etc/`, `/proc/`, `/sys/`, Windows system paths)
- Path traversal attempts (`../`, block device access)

### 2. NO_UNAUTHORIZED_SHELL
Prevents dangerous shell execution patterns:
- File removal tools (`rm`, `mkfs`, `dd`)
- Privilege escalation (`sudo`, `su`)
- Data exfiltration (`wget`, `curl`, `nc`, `netcat`)
- Command injection (backticks, subshell substitution)
- Piped/chained command segments

### 3. RESTRICT_OUTBOUND_SOCKETS
Restricts network communication to prevent SSRF and unauthorized outbound calls:
- Cloud metadata endpoints (`169.254.169.254`)
- Localhost loopback (`127.0.0.1`, `localhost`, `0.0.0.0`)

## Installation

```bash
pip install ppm-core
```

Or from source:
```bash
git clone https://github.com/ngascon758-beep/priortizedprotection-gmail.com.git
cd priortizedprotection-gmail.com
pip install -e .
```

## Usage

### Basic Example

```python
from ppm_core import AutonomicGate, Tier1Invariant

# Initialize the gate with default invariants
gate = AutonomicGate()

# Use as a decorator
@gate.intercept("shell_exec")
def execute_command(command: str):
    """Execute a shell command (protected by the gate)."""
    # This will be blocked if command violates invariants
    return subprocess.run(command, shell=True)

# Or evaluate directly
try:
    gate.evaluate("file_delete", {"path": "/etc/passwd"})
except InvariantViolationError as e:
    print(f"Access denied: {e}")
```

### Custom Invariants

```python
# Create a gate with only specific invariants
custom_gate = AutonomicGate(
    active_invariants=[
        Tier1Invariant.NO_DESTRUCTIVE_FS,
        Tier1Invariant.NO_UNAUTHORIZED_SHELL,
    ]
)
```

## Architecture

The AutonomicGate operates as a deterministic reflex arc:

1. **Intercept**: Decorator or direct evaluation captures action intent
2. **Extract**: Recursively extracts all string values from parameters
3. **Normalize**: Whitespace/tab normalization and pattern hardening
4. **Evaluate**: Tests against active Tier-1 invariants
5. **Block/Allow**: Raises InvariantViolationError or proceeds

All operations complete in sub-millisecond time with deterministic behavior.

## Development

### Testing

```bash
pip install -e ".[dev]"
pytest
```

### Security Notes

- Invariants are **not configurable per-action** — they enforce deterministic policy
- Blocking is **fail-safe**: when in doubt, the gate denies
- Pattern matching includes evasion hardening (whitespace injection, encoding tricks)
- Latency monitoring: warnings logged if evaluation exceeds 1ms target

## License

MIT License - See [LICENSE](LICENSE) file for details

## Author

Alex Gascon

---

**For security issues**, see [Security.md](Security.md)
