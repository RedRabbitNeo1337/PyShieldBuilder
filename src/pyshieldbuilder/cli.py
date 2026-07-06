"""CLI for building, inspecting, and executing encrypted packages."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .builder import PyShieldBuilder
from .config import BuilderConfig
from .models import TransformationConfig
from .runtime import execute_package, extract_package, inspect_package, verify_package


def _resolve_password(password: str | None) -> str:
    resolved = password or os.getenv("PYSHIELDBUILDER_PASSWORD", "")
    if not resolved:
        raise SystemExit("Password required via --password or PYSHIELDBUILDER_PASSWORD")
    return resolved


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pyshieldbuilder")
    sub = parser.add_subparsers(dest="command", required=True)

    build_cmd = sub.add_parser("build", help="Build encrypted package")
    build_cmd.add_argument("--source", required=True)
    build_cmd.add_argument("--entrypoint", required=True)
    build_cmd.add_argument("--output", required=True)
    build_cmd.add_argument("--password")
    build_cmd.add_argument("--config")
    build_cmd.add_argument("--reproducible", action=argparse.BooleanOptionalAction, default=False)
    build_cmd.add_argument("--sign-package", action=argparse.BooleanOptionalAction, default=True)
    build_cmd.add_argument("--package-version", default="1.0.0")
    build_cmd.add_argument("--metadata-version", type=int, default=1)
    _add_transform_flags(build_cmd)

    verify_cmd = sub.add_parser("verify", help="Verify package integrity")
    verify_cmd.add_argument("--package", required=True)
    verify_cmd.add_argument("--password")

    inspect_cmd = sub.add_parser("inspect", help="Inspect package metadata")
    inspect_cmd.add_argument("--package", required=True)
    inspect_cmd.add_argument("--password")

    extract_cmd = sub.add_parser("extract", help="Extract package source files")
    extract_cmd.add_argument("--package", required=True)
    extract_cmd.add_argument("--output", required=True)
    extract_cmd.add_argument("--password")

    run_cmd = sub.add_parser("run", help="Run encrypted package")
    run_cmd.add_argument("--package", required=True)
    run_cmd.add_argument("--password")
    run_cmd.add_argument("--entrypoint")

    benchmark_cmd = sub.add_parser("benchmark", help="Benchmark package execution")
    benchmark_cmd.add_argument("--package", required=True)
    benchmark_cmd.add_argument("--password")
    benchmark_cmd.add_argument("--entrypoint")
    benchmark_cmd.add_argument("--iterations", type=int, default=10)

    sub.add_parser("version", help="Print version")
    sub.add_parser("doctor", help="Check local environment")

    clean_cmd = sub.add_parser("clean", help="Remove build artifacts")
    clean_cmd.add_argument("paths", nargs="*", default=["dist", "build"])

    return parser


def _add_transform_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rename-identifiers", action=argparse.BooleanOptionalAction, default=False
    )
    parser.add_argument("--encrypt-strings", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--hide-constants", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--insert-dead-code", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument(
        "--flatten-control-flow", action=argparse.BooleanOptionalAction, default=False
    )
    parser.add_argument("--rewrite-imports", action=argparse.BooleanOptionalAction, default=False)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "version":
        print(__version__)
        return 0

    if args.command == "doctor":
        print(json.dumps(_doctor_report(), indent=2, sort_keys=True))
        return 0

    if args.command == "clean":
        removed = _clean_paths(args.paths)
        print(json.dumps({"removed": [str(path) for path in removed]}, indent=2, sort_keys=True))
        return 0

    if args.command == "build":
        password = _resolve_password(getattr(args, "password", None))
        config = _build_config(args)
        target = PyShieldBuilder(args.source, args.entrypoint, config=config).build(
            args.output, password
        )
        print(str(Path(target).resolve()))
        return 0

    password = _resolve_password(getattr(args, "password", None))

    if args.command == "verify":
        metadata = verify_package(args.package, password)
        print(json.dumps(asdict(metadata), indent=2, sort_keys=True))
        return 0

    if args.command == "inspect":
        metadata = inspect_package(args.package, password)
        print(json.dumps(asdict(metadata), indent=2, sort_keys=True))
        return 0

    if args.command == "extract":
        written = extract_package(args.package, password, args.output)
        print(json.dumps([str(path) for path in written], indent=2))
        return 0

    if args.command == "run":
        result = execute_package(args.package, password, entrypoint=args.entrypoint)
        if result is not None:
            print(result)
        return 0

    if args.command == "benchmark":
        timings: list[float] = []
        result = None
        for _ in range(max(1, args.iterations)):
            start = time.perf_counter()
            result = execute_package(args.package, password, entrypoint=args.entrypoint)
            timings.append(time.perf_counter() - start)
        print(
            json.dumps(
                {
                    "iterations": len(timings),
                    "min_seconds": min(timings),
                    "max_seconds": max(timings),
                    "average_seconds": sum(timings) / len(timings),
                    "result": result,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    raise SystemExit(f"unknown command: {args.command}")  # pragma: no cover


def _build_config(args: argparse.Namespace) -> BuilderConfig:
    base = BuilderConfig(
        source_dir=args.source,
        entrypoint=args.entrypoint,
        output_path=args.output,
        package_version=args.package_version,
        metadata_version=args.metadata_version,
        reproducible=bool(args.reproducible),
        sign_package=bool(args.sign_package),
        transformation=TransformationConfig(
            rename_identifiers=bool(args.rename_identifiers),
            encrypt_strings=bool(args.encrypt_strings),
            hide_constants=bool(args.hide_constants),
            insert_dead_code=bool(args.insert_dead_code),
            flatten_control_flow=bool(args.flatten_control_flow),
            rewrite_imports=bool(args.rewrite_imports),
        ),
    )
    if args.config:
        loaded = BuilderConfig.from_file(args.config)
        return loaded.with_overrides(
            source_dir=base.source_dir,
            entrypoint=base.entrypoint,
            output_path=base.output_path,
            package_version=base.package_version,
            metadata_version=base.metadata_version,
            reproducible=base.reproducible,
            sign_package=base.sign_package,
            transformation=base.transformation,
        )
    return base


def _doctor_report() -> dict[str, object]:
    return {
        "status": "ok",
        "python": tuple(sys.version_info[:3]),
        "version": __version__,
        "tempdir": tempfile.gettempdir(),
    }


def _clean_paths(paths: list[str]) -> list[Path]:
    removed: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            shutil.rmtree(path)
            removed.append(path)
        elif path.exists():
            path.unlink()
            removed.append(path)
    return removed


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
