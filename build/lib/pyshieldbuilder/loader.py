import zlib

from .crypto import decrypt_bytes, derive_key, verify_signature
from .builder import _build_aad
from .exceptions import VerificationError
from .integrity import verify_hash
from .package import loads_package
from .runtime import enforce_runtime_protections, execute_marshaled_payload
from .utils import b64d


class ShieldLoader:
    def __init__(self, master_secret: bytes) -> None:
        self.master_secret = master_secret

    def _decode_and_verify(self, package_bytes: bytes):
        package = loads_package(package_bytes)
        ciphertext = b64d(package.ciphertext)
        if not verify_hash(ciphertext, package.integrity_hash):
            raise VerificationError("integrity hash mismatch")

        if not verify_signature(b64d(package.public_key), package.signature_alg, ciphertext, b64d(package.signature)):
            raise VerificationError("signature verification failed")
        return package, ciphertext

    def run(self, package_bytes: bytes) -> dict:
        enforce_runtime_protections()
        package, ciphertext = self._decode_and_verify(package_bytes)

        salt = b64d(package.key_salt)
        nonce = b64d(package.nonce)
        key = derive_key(self.master_secret, salt)
        aad = _build_aad(package.metadata["entry"])
        compressed = decrypt_bytes(key, nonce, ciphertext, aad=aad)
        marshaled = zlib.decompress(compressed)
        return execute_marshaled_payload(marshaled)
