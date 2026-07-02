from typing import Protocol


class BuildPlugin(Protocol):
    def before_encrypt(self, payload: bytes) -> bytes: ...

    def after_decrypt(self, payload: bytes) -> bytes: ...
