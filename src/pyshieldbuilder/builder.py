import ast
import base64
import json
import marshal
import tarfile
import tempfile
import zlib
from pathlib import Path

from .config import BuilderConfig
from .crypto import derive_key, encrypt_bytes, generate_signing_keypair, sign_data
from .exceptions import BuildError
from .integrity import sha256_hex
from .models import SecurePackage
from .package import dumps_package
from .utils import b64e, secure_bytes
from .utils.audit import write_audit_event


class _StringObfuscator(ast.NodeTransformer):
    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str) and node.value:
            char_codes = [ord(ch) for ch in node.value]
            return ast.Call(
                func=ast.Attribute(
                    value=ast.Constant(value=""),
                    attr="join",
                    ctx=ast.Load(),
                ),
                args=[
                    ast.Call(
                        func=ast.Name(id="map", ctx=ast.Load()),
                        args=[
                            ast.Name(id="chr", ctx=ast.Load()),
                            ast.List(elts=[ast.Constant(value=n) for n in char_codes], ctx=ast.Load()),
                        ],
                        keywords=[],
                    )
                ],
                keywords=[],
            )
        return node


def _obfuscate_source(source: str) -> str:
    tree = ast.parse(source)
    tree = _StringObfuscator().visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def _build_aad(entry_module: str) -> bytes:
    return json.dumps({"entry": entry_module}, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _bootstrap_source(bundle_bytes: bytes) -> str:
    encoded = base64.b64encode(bundle_bytes).decode("ascii")
    return f"""
import base64
import io
import tarfile

_bundle = base64.b64decode("{encoded}")
_ns = {{}}
with tarfile.open(fileobj=io.BytesIO(_bundle), mode="r:gz") as _archive:
    for _member in _archive.getmembers():
        if _member.name.endswith(".py"):
            _source = _archive.extractfile(_member).read().decode("utf-8")
            exec(compile(_source, _member.name, "exec"), _ns, _ns)
globals().update(_ns)
"""


class ShieldBuilder:
    def __init__(self, master_secret: bytes) -> None:
        self.master_secret = master_secret

    def _bundle_sources(self, source_dir: Path) -> bytes:
        with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            with tarfile.open(tmp_path, "w:gz") as archive:
                for file in source_dir.rglob("*.py"):
                    source = file.read_text(encoding="utf-8")
                    obfuscated = _obfuscate_source(source)
                    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8") as obf:
                        obf.write(obfuscated)
                        obf_path = Path(obf.name)
                    archive.add(obf_path, arcname=file.relative_to(source_dir))
                    obf_path.unlink(missing_ok=True)
            return tmp_path.read_bytes()
        finally:
            tmp_path.unlink(missing_ok=True)

    def build(self, config: BuilderConfig) -> Path:
        source_dir = config.source_dir
        if not source_dir.exists():
            raise BuildError(f"source dir does not exist: {source_dir}")

        bundled = self._bundle_sources(source_dir)
        bootstrap = _bootstrap_source(bundled)
        marshaled = marshal.dumps(compile(bootstrap, "<pyshieldbuilder>", "exec"))
        compressed = zlib.compress(marshaled, level=config.compression_level)

        salt = secure_bytes(16)
        nonce = secure_bytes(12)
        key = derive_key(self.master_secret, salt)
        aad = _build_aad(config.entry_module)
        encrypted = encrypt_bytes(key, nonce, compressed, aad=aad)

        priv, pub = generate_signing_keypair(config.signing_alg)
        signature = sign_data(priv, config.signing_alg, encrypted)

        package = SecurePackage(
            version=2,
            alg="aesgcm+scrypt",
            nonce=b64e(nonce),
            ciphertext=b64e(encrypted),
            key_salt=b64e(salt),
            integrity_hash=sha256_hex(encrypted),
            signature_alg=config.signing_alg,
            signature=b64e(signature),
            public_key=b64e(pub),
            metadata={"entry": config.entry_module},
        )

        config.output_file.parent.mkdir(parents=True, exist_ok=True)
        config.output_file.write_bytes(dumps_package(package))
        audit_file = (config.key_dir or config.output_file.parent) / "audit.log"
        write_audit_event(audit_file, "build", {"output": str(config.output_file), "alg": config.signing_alg})
        return config.output_file
