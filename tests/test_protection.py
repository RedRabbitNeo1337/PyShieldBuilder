from pyshieldbuilder.protection import STAGE1_METHOD, protect_source


def test_protect_source_executes_original_behavior() -> None:
    protected = protect_source("VALUE = 7\n\ndef run():\n    return VALUE * 2\n", "x.py")
    namespace: dict[str, object] = {}
    exec(protected, namespace)
    assert namespace["run"]() == 14


def test_stage1_method_name_is_stable() -> None:
    assert STAGE1_METHOD == "marshal+zlib+base85"
