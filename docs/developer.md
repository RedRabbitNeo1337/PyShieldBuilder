# Developer Guide

## Local checks

```bash
python -m pip install -e .[dev]
pytest -q
ruff check .
mypy src/pyshieldbuilder
python -m pip wheel . -w /tmp/psb-wheels
```

## Conventions

- Keep public APIs documented in `docs/api.md`.
- Preserve backward compatibility for older package envelopes.
- Add tests for new runtime and packaging behavior.
