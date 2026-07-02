from pyshieldbuilder.crypto import generate_signing_keypair, sign_data, verify_signature


def test_ed25519_signature_roundtrip():
    private, public = generate_signing_keypair("ed25519")
    payload = b"signed"
    signature = sign_data(private, "ed25519", payload)
    assert verify_signature(public, "ed25519", payload, signature)


def test_rsa_signature_roundtrip():
    private, public = generate_signing_keypair("rsa")
    payload = b"signed-rsa"
    signature = sign_data(private, "rsa", payload)
    assert verify_signature(public, "rsa", payload, signature)
