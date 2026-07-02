"""Stage 1 source protection helpers."""

from __future__ import annotations

import base64
import marshal
import zlib

STAGE1_METHOD = "marshal+zlib+base85"


def protect_source(source: str, filename: str) -> str:
    """Return a Stage 1 protected source wrapper for *source*."""
    code = compile(source, filename, "exec")
    encoded = base64.b85encode(zlib.compress(marshal.dumps(code), level=9)).decode("ascii")
    return (
        "import base64 as _b64\n"
        "import marshal as _m\n"
        "import zlib as _z\n"
        f"exec(_m.loads(_z.decompress(_b64.b85decode({encoded!r}))), globals(), globals())\n"
    )
