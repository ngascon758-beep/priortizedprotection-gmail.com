# Prioritized Protection Model (PPM) Core

Runtime safety gate and autonomic threat intercept for AI agents and LLM execution pipelines. Enforces deterministic, tier-1 invariants to block unauthorized state transitions and tool-call violations before execution.

## Features

- **Sub-millisecond Execution Gate**: Autonomic reflex arc positioned between AI model reasoning and tool execution
- **Tier-1 Invariants**: Deterministic safety checks including:
  - `NO_DESTRUCTIVE_FS`: Blocks destructive filesystem operations (delete, remove)
  - `NO_UNAUTHORIZED_SHELL`: Prevents dangerous shell commands (rm, mkfs, dd, dev writes)
  - `RESTRICT_OUTBOUND_SOCKETS`: Control outbound network access
- **Decorator-based Integration**: Simple `@gate.intercept()` decorator for tool functions
- **Exception-driven Safety**: Raises `InvariantViolationError` on constraint violations

## Installation

```bash
pip install ppm-core
```

## Usage

```python
from Ppm_core import AutonomicGate, Tier1Invariant, InvariantViolationError

# Initialize the autonomic gate with active invariants
gate = AutonomicGate(active_invariants=[
    Tier1Invariant.NO_DESTRUCTIVE_FS,
    Tier1Invariant.NO_UNAUTHORIZED_SHELL
])

# Protect tool execution with the intercept decorator
@gate.intercept("shell_exec")
def execute_shell(command):
    # This will raise InvariantViolationError for dangerous commands
    return subprocess.run(command, shell=True)

# Attempt safe operation
result = execute_shell("echo 'hello'")

# This will raise InvariantViolationError
try:
    execute_shell("rm -rf /")
except InvariantViolationError as e:
    print(f"Blocked: {e}")
```

## Testing

Run the test suite:

```bash
pip install -e ".[dev]"
pytest
```

## Development

Install development dependencies:

```bash
pip install -e ".[dev]"
```

## License

MIT License - See LICENSE file for details

## Security

For security concerns and responsible disclosure, see [Security.md](Security.md).
