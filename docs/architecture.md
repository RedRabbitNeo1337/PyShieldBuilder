# Architecture

## Build flow

1. Collect Python source files.
2. Apply optional AST-based source transformations.
3. Create a deterministic source archive.
4. Encrypt the archive with AES-256-GCM.
5. Sign the manifest and write a single package file.

## Runtime flow

1. Load and decrypt the package.
2. Verify manifest, signature, and payload integrity.
3. Verify source hashes.
4. Import modules from memory only.
5. Execute the requested entrypoint.

## Package format

- `manifest`: build metadata, source hashes, and transform flags
- `manifest_sha256`: canonical manifest digest
- `signature`: HMAC signature of the canonical manifest
- `salt`, `nonce`, `ciphertext`: encrypted payload material
