from pathlib import Path

from pyshieldbuilder.integrity import hash_bytes, hash_file, verify_digest


def test_integrity_helpers(tmp_path: Path) -> None:
    sample = b"abc123"
    file_path = tmp_path / "payload.bin"
    file_path.write_bytes(sample)

    digest = hash_bytes(sample)
    assert digest == hash_file(file_path)
    assert verify_digest(sample, digest)
    assert not verify_digest(sample + b"x", digest)
