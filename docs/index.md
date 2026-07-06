# PyShieldBuilder Documentation

## Overview

PyShieldBuilder builds signed encrypted package envelopes containing transformed Python source archives and supports secure in-memory execution.

## Modules

- `pyshieldbuilder.crypto`: AES-256-GCM encryption/decryption
- `pyshieldbuilder.integrity`: SHA-256 integrity functions
- `pyshieldbuilder.package`: source archive creation/extraction
- `pyshieldbuilder.builder`: package construction/decryption loader
- `pyshieldbuilder.runtime`: metadata inspection, verification, extraction, and in-memory execution
- `pyshieldbuilder.config`: optional tool configuration loader
- `pyshieldbuilder.transform`: source transformation pipeline
- `pyshieldbuilder.cli`: command-line interface

## Guides

- [API documentation](api.md)
- [Architecture documentation](architecture.md)
- [Migration guide](migration.md)
- [Developer guide](developer.md)

See `examples/` for a runnable end-to-end example.
