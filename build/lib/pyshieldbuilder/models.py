from dataclasses import dataclass


@dataclass(slots=True)
class SecurePackage:
    version: int
    alg: str
    nonce: str
    ciphertext: str
    key_salt: str
    integrity_hash: str
    signature_alg: str
    signature: str
    public_key: str
    metadata: dict
