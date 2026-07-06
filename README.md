# PyShieldBuilder

PyShieldBuilder is a Python source protection tool for encrypted packaging, manifest verification, and in-memory execution.

## Features

- Python 3.12+
- Source transformation pipeline
- AES-256-GCM payload encryption
- Manifest signing and integrity checks
- Memory-only module execution
- CLI for build, verify, inspect, extract, run, benchmark, version, doctor, and clean
- Wheel, editable, and pip installation support

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

pyshieldbuilder verify --package ./dist/example.psb --password "strong-password"
pyshieldbuilder inspect --package ./dist/example.psb --password "strong-password"

pyshieldbuilder extract --package ./dist/example.psb --output ./out --password "strong-password"
pyshieldbuilder run --package ./dist/example.psb --password "strong-password"
```

## CLI Commands

- `build`
- `verify`
- `inspect`
- `extract`
- `run`
- `benchmark`
- `version`
- `doctor`
- `clean`

## Documentation

- [API](docs/api.md)
- [Architecture](docs/architecture.md)
- [Migration guide](docs/migration.md)
- [Developer guide](docs/developer.md)
- [Examples](examples/basic_build_and_run.py)

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
