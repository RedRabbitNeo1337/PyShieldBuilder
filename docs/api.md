# Public API

## Builder

- `PyShieldBuilder(source_dir, entrypoint).build(output_path, password)`
- `build_package(source_dir, output_path, password, entrypoint)`

## Runtime

- `inspect_package(package_path, password)` → `PackageMetadata`
- `execute_package(package_path, password, entrypoint=None)`

## Stage 1 Protection

- `protect_archive(data, *, _seed=None)` → `dict` – apply zlib+base85+chunk+shuffle pipeline
- `unprotect_archive(protected)` → `bytes` – reverse Stage 1 and verify integrity

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

## Metadata fields (`PackageMetadata`)

| Field | Type | Description | Default |
|---|---|---|---|
| `format_version` | `int` | Envelope format version | – |
| `created_at` | `str` | ISO-8601 creation timestamp | – |
| `entrypoint` | `str` | Module:attr entrypoint | – |
| `file_count` | `int` | Number of bundled `.py` files | – |
| `payload_sha256` | `str` | SHA-256 of the encrypted payload | – |
| `stage1_enabled` | `bool` | Stage 1 obfuscation applied | `False` |
| `source_protection` | `bool` | Any source protection active | `False` |
| `protection_version` | `str` | Protection layer version string | `""` |
| `protection_pipeline` | `str` | Pipeline descriptor | `""` |
| `runtime_version` | `str` | Runtime format version | `""` |

## CLI Commands

- `pyshieldbuilder build --source DIR --entrypoint MOD:FN --output FILE --password PW`
- `pyshieldbuilder inspect --package FILE --password PW`
- `pyshieldbuilder run --package FILE --password PW [--entrypoint MOD:FN]`
- `pyshieldbuilder verify --package FILE --password PW`

`verify` exits **0** when the package passes all integrity checks, **1** on failure.
Output is JSON with `status`, `stage1_verified`, `protection_version`, `protection_pipeline`, `runtime_version`, and `message` keys.
