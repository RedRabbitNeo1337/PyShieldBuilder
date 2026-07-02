import json
from dataclasses import asdict

from .models import SecurePackage


def dumps_package(package: SecurePackage) -> bytes:
    return json.dumps(asdict(package), separators=(",", ":"), sort_keys=True).encode("utf-8")


def loads_package(raw: bytes) -> SecurePackage:
    data = json.loads(raw.decode("utf-8"))
    return SecurePackage(**data)
