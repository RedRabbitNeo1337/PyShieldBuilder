from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa


def generate_signing_keypair(alg: str) -> tuple[bytes, bytes]:
    if alg == "ed25519":
        private = ed25519.Ed25519PrivateKey.generate()
    elif alg == "rsa":
        private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    else:
        raise ValueError(f"unsupported signing algorithm: {alg}")

    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_data(private_pem: bytes, alg: str, payload: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(private_pem, None)
    if alg == "ed25519":
        return private_key.sign(payload)
    if alg == "rsa":
        return private_key.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    raise ValueError(f"unsupported signing algorithm: {alg}")


def verify_signature(public_pem: bytes, alg: str, payload: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(public_pem)
    try:
        if alg == "ed25519":
            public_key.verify(signature, payload)
        elif alg == "rsa":
            public_key.verify(signature, payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        else:
            raise ValueError(f"unsupported signing algorithm: {alg}")
    except InvalidSignature:
        return False
    return True
