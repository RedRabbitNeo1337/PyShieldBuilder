import marshal
from types import CodeType


def execute_marshaled_payload(payload: bytes, module_globals: dict | None = None) -> dict:
    code = marshal.loads(payload)
    if not isinstance(code, CodeType):
        raise TypeError("marshaled payload is not a code object")
    namespace = {} if module_globals is None else module_globals
    exec(code, namespace, namespace)
    return namespace
