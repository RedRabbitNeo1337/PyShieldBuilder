# Public API

## Builder

- `PyShieldBuilder(source_dir, entrypoint).build(output_path, password)`
- `build_package(source_dir, output_path, password, entrypoint)`

## Runtime

- `inspect_package(package_path, password)`
- `execute_package(package_path, password, entrypoint=None)`

## Crypto

- `encrypt_bytes(plaintext, password, aad=b"")`
- `decrypt_bytes(ciphertext, password, salt, nonce, aad=b"")`

## Config

- `BuilderConfig.from_file(path)`

## Exceptions

- `PyShieldBuilderError`
- `PackageBuildError`
- `InvalidPackageError`
- `DecryptionError`
- `RuntimeExecutionError`
