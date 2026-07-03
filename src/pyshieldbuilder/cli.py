"""CLI for building, inspecting, and executing encrypted packages."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path

from .builder import PyShieldBuilder
from .exceptions import InvalidPackageError, DecryptionError
from .runtime import execute_package, inspect_package


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

    inspect_cmd = sub.add_parser("inspect", help="Inspect package metadata")
    inspect_cmd.add_argument("--package", required=True)
    inspect_cmd.add_argument("--password")

    run_cmd = sub.add_parser("run", help="Run encrypted package")
    run_cmd.add_argument("--package", required=True)
    run_cmd.add_argument("--password")
    run_cmd.add_argument("--entrypoint")

    verify_cmd = sub.add_parser("verify", help="Verify package integrity")
    verify_cmd.add_argument("--package", required=True)
    verify_cmd.add_argument("--password")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    password = _resolve_password(getattr(args, "password", None))

    if args.command == "build":
        target = PyShieldBuilder(args.source, args.entrypoint).build(args.output, password)
        print(str(Path(target).resolve()))
        return 0

    if args.command == "inspect":
        metadata = inspect_package(args.package, password)
        print(json.dumps(asdict(metadata), indent=2))
        return 0

    if args.command == "verify":
        pkg_path = args.package
        try:
            metadata = inspect_package(pkg_path, password)
            report = {
                "package": str(Path(pkg_path).resolve()),
                "status": "valid",
                "stage1_verified": metadata.stage1_enabled,
                "protection_version": metadata.protection_version,
                "protection_pipeline": metadata.protection_pipeline,
                "runtime_version": metadata.runtime_version,
                "message": "Package integrity verified successfully.",
            }
            print(json.dumps(report, indent=2))
            return 0
        except (InvalidPackageError, DecryptionError) as exc:
            report = {
                "package": str(Path(pkg_path).resolve()),
                "status": "invalid",
                "message": str(exc),
            }
            print(json.dumps(report, indent=2))
            return 1

    result = execute_package(args.package, password, entrypoint=args.entrypoint)
    if result is not None:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
