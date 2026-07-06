# Public API

## Builder

- `PyShieldBuilder(source_dir, entrypoint).build(output_path, password)`
- `build_package(source_dir, output_path, password, entrypoint, *, transformation=None, reproducible=False, sign_package=True, package_version='1.0.0', metadata_version=1)`

## Runtime

- `inspect_package(package_path, password)`
- `verify_package(package_path, password)`
- `extract_package(package_path, password, destination)`
- `execute_package(package_path, password, entrypoint=None)`

## Crypto

- `encrypt_bytes(plaintext, password, aad=b"")`
- `decrypt_bytes(ciphertext, password, salt, nonce, aad=b"")`
- `derive_signing_key(password, salt)`
- `sign_bytes(data, key)`

## Config

- `BuilderConfig.from_file(path)`
- `TransformationConfig(...)`

## Exceptions

- `PyShieldBuilderError`
- `PackageBuildError`
- `InvalidPackageError`
- `DecryptionError`
- `RuntimeExecutionError`
