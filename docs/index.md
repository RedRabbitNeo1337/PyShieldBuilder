# PyShieldBuilder Documentation

## Overview

PyShieldBuilder builds encrypted package envelopes containing Python source archives and allows secure in-memory execution.

## Protection pipeline (Stage 1)

All packages built with Stage 1 protection active have their source archive processed through:

```
source files  →  tar.gz archive  →  zlib(9)  →  base85  →  split into chunks  →  shuffle
```

The chunk-order map is stored inside the encrypted envelope.  At runtime the
process is reversed:

```
decrypt  →  verify payload hash  →  reassemble chunks  →  base85-decode  →  zlib-decompress  →  tar.gz  →  in-memory modules
```

Every step includes integrity verification (SHA-256 + AES-256-GCM authentication
tag).

## Modules

- `pyshieldbuilder.crypto`: AES-256-GCM encryption/decryption
- `pyshieldbuilder.integrity`: SHA-256 integrity functions
- `pyshieldbuilder.package`: source archive creation/extraction
- `pyshieldbuilder.stage1`: Stage 1 obfuscation pipeline (protect/unprotect)
- `pyshieldbuilder.builder`: package construction/decryption loader
- `pyshieldbuilder.runtime`: metadata inspection and in-memory execution
- `pyshieldbuilder.config`: optional tool configuration loader
- `pyshieldbuilder.cli`: command-line interface

## CLI Commands

- `pyshieldbuilder build`
- `pyshieldbuilder inspect`
- `pyshieldbuilder run`
- `pyshieldbuilder verify`

See `docs/api.md` and `examples/` for usage details.
