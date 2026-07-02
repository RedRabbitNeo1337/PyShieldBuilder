from pyshieldbuilder.cli import main


def test_cli_requires_command():
    try:
        main([])
    except SystemExit as exc:
        assert exc.code != 0
