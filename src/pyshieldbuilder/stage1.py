"""Stage 1 source-protection pipeline.

Pipeline: archive bytes -> zlib(9) -> base85 -> split -> shuffle -> store map.

Public constants are intentionally short to minimise recognisable strings when
the module is inspected at the bytecode level.
"""

from __future__ import annotations

import base64
import hmac
import random
import zlib

from .exceptions import InvalidPackageError

# Short constants to avoid leaving obvious strings in bytecode.
_PV: str = "1.0"          # protection version
_PPLN: str = "zlib+b85+chunks"   # pipeline descriptor
_RV: str = "1.0"          # runtime version

_MIN_N: int = 8     # minimum number of chunks
_MAX_N: int = 24    # maximum number of chunks
_MIN_CS: int = 4    # minimum chunk size (characters)


def protect_archive(data: bytes, *, _seed: int | None = None) -> dict:
    """Apply Stage 1 obfuscation to *data* and return a protection envelope.

    Keys are intentionally terse:
      ``c`` – shuffled chunks list
      ``m`` – chunk map (shuffled_pos -> original_pos)
      ``h`` – hex digest of the original *data*
    """
    import hashlib  # inline import reduces top-level symbol exposure

    _h = hashlib.sha256(data).hexdigest()
    _z = zlib.compress(data, 9)
    _e = base64.b85encode(_z).decode("ascii")

    _rng = random.Random(_seed)

    _n = _rng.randint(_MIN_N, _MAX_N) if len(_e) >= _MIN_N * _MIN_CS else 1
    _cs = max(_MIN_CS, len(_e) // _n)
    _cks: list[str] = [_e[_i : _i + _cs] for _i in range(0, len(_e), _cs)]
    _n = len(_cks)

    # Build a shuffled index list: _idx[shuffled_pos] = original_pos.
    _idx = list(range(_n))
    _rng.shuffle(_idx)

    _shuf = [_cks[_idx[_i]] for _i in range(_n)]

    return {"c": _shuf, "m": _idx, "h": _h}


def unprotect_archive(protected: dict) -> bytes:
    """Reverse Stage 1 obfuscation and verify archive integrity.

    Raises :class:`~pyshieldbuilder.exceptions.InvalidPackageError` if the
    envelope is malformed or the payload hash does not match.
    """
    import hashlib  # inline import – mirrors protect_archive

    try:
        _cks: list[str] = protected["c"]
        _mp: list[int] = protected["m"]
        _exp_h: str = protected["h"]
    except (KeyError, TypeError) as _exc:
        raise InvalidPackageError("malformed stage1 payload") from _exc

    if len(_cks) != len(_mp):
        raise InvalidPackageError("stage1 chunk/map length mismatch")

    _n = len(_cks)
    _ord: list[str] = [""] * _n
    for _si, _oi in enumerate(_mp):
        if _oi < 0 or _oi >= _n:
            raise InvalidPackageError("stage1 map index out of range")
        _ord[_oi] = _cks[_si]

    _enc = "".join(_ord)

    try:
        _z = base64.b85decode(_enc)
        _data = zlib.decompress(_z)
    except Exception as _exc:
        raise InvalidPackageError("stage1 decode/decompress failed") from _exc

    _act_h = hashlib.sha256(_data).hexdigest()
    if not hmac.compare_digest(_act_h, _exp_h):
        raise InvalidPackageError("stage1 payload integrity check failed – payload may have been modified")

    return _data
