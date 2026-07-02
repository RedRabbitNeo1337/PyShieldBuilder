import argparse
from pathlib import Path

from .builder import ShieldBuilder
from .config import BuilderConfig
from .loader import ShieldLoader


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pyshieldbuilder")
    sub = parser.add_subparsers(dest="command", required=True)

    build_cmd = sub.add_parser("build")
    build_cmd.add_argument("source_dir")
    build_cmd.add_argument("-e", "--entry", required=True)
    build_cmd.add_argument("-o", "--output", required=True)
    build_cmd.add_argument("--alg", default="ed25519", choices=["ed25519", "rsa"])
    build_cmd.add_argument("--secret", default="pyshieldbuilder")

    run_cmd = sub.add_parser("run")
    run_cmd.add_argument("package")
    run_cmd.add_argument("--secret", default="pyshieldbuilder")

    args = parser.parse_args(argv)

    if args.command == "build":
        builder = ShieldBuilder(args.secret.encode("utf-8"))
        config = BuilderConfig(
            source_dir=Path(args.source_dir),
            entry_module=args.entry,
            output_file=Path(args.output),
            signing_alg=args.alg,
        )
        builder.build(config)
        return 0

    loader = ShieldLoader(args.secret.encode("utf-8"))
    loader.run(Path(args.package).read_bytes())
    return 0
