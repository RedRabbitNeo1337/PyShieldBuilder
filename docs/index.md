# PyShieldBuilder Documentation

## Overview

PyShieldBuilder builds encrypted package envelopes containing Python source archives and allows secure in-memory execution.

## Modules

- `pyshieldbuilder.crypto`: AES-256-GCM encryption/decryption
- `pyshieldbuilder.integrity`: SHA-256 integrity functions
- `pyshieldbuilder.package`: source archive creation/extraction
- `pyshieldbuilder.builder`: package construction/decryption loader
- `pyshieldbuilder.runtime`: metadata inspection and in-memory execution
- `pyshieldbuilder.config`: optional tool configuration loader
- `pyshieldbuilder.cli`: command-line interface

## CLI Commands

- `pyshieldbuilder build`
- `pyshieldbuilder inspect`
- `pyshieldbuilder run`

See `docs/api.md` and `examples/` for usage details.
