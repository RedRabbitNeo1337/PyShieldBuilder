# PyShieldBuilder

PyShieldBuilder is a production-focused Python project for protecting Python source code through encrypted packaging, integrity verification, and in-memory execution.

## Features

- Python 3.12+
- AES-256-GCM payload encryption
- PBKDF2 key derivation with strong defaults
- SHA-256 payload integrity verification
- Memory-only module import and execution
- CLI for build/inspect/run workflows
- Unit-tested public APIs

## Installation

```bash
pip install pyshieldbuilder
```

For development:

```bash
pip install -e .[dev]
```

## Quick Start

```bash
pyshieldbuilder build \
  --source ./example_app \
  --entrypoint app.main:run \
  --output ./dist/example.psb \
  --password "strong-password"

pyshieldbuilder inspect --package ./dist/example.psb --password "strong-password"

pyshieldbuilder run --package ./dist/example.psb --password "strong-password"
```

## Project Structure

```text
PyShieldBuilder/
├── src/pyshieldbuilder/
├── tests/
├── docs/
├── examples/
├── pyproject.toml
├── README.md
├── LICENSE
└── .gitignore
```

## Security Notes

- Keep package passwords out of shell history; prefer `PYSHIELDBUILDER_PASSWORD`.
- Use dedicated CI secrets management for automation.
- Rotate passwords and regenerate packages regularly.

## License

MIT
