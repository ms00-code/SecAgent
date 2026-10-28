# Contributing to SecAgent

## Getting started

```bash
git clone https://github.com/yourname/secagent
cd secagent
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/
```

## Adding a new check

1. Create a new module in `secagent/checks/`
2. Return a `list[Finding]` from your check function
3. Call it from `secagent/scanner.py`
4. Add tests in `tests/`

## Code style

- Keep it simple and readable
- No unnecessary abstractions
- Passive/non-destructive checks only
- Document any non-obvious logic

## Scope

This tool is for passive reconnaissance only. Pull requests that add:
- Brute force capabilities
- Exploitation features
- DoS capabilities

will be rejected.
