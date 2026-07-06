# Migration Guide

## From 0.x to 1.0.0

- Package format version changed to 2.
- Packages now include a signed manifest.
- Source transformation flags are configurable.
- Use `inspect_package`, `verify_package`, and `extract_package` for runtime workflows.

Existing 0.x packages remain loadable through backward-compatible manifest handling.
