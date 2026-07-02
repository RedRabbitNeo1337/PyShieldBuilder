# PyShieldBuilder

PyShieldBuilder melindungi source code Python melalui pipeline build berlapis:

1. AST obfuscation
2. compile + marshal
3. compression
4. AES-GCM encryption
5. RSA/Ed25519 signing
6. anti-tamper runtime verification

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
pyshieldbuilder build examples/hello_app -e app:main -o dist/hello.psb
pyshieldbuilder run dist/hello.psb
```

## Development

```bash
pytest
python -m pip wheel . -w /tmp/psb-wheels
```
