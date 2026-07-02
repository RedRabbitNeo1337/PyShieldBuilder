from pyshieldbuilder.builder import _obfuscate_source


def test_string_obfuscation_changes_literal_shape():
    source = 'message = "hello"\n'
    out = _obfuscate_source(source)
    assert "hello" not in out
    assert "map(chr" in out
