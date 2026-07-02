import time
from pathlib import Path

from pyshieldbuilder.builder import ShieldBuilder
from pyshieldbuilder.config import BuilderConfig


def main() -> None:
    source = Path("examples/hello_app")
    output = Path("dist/bench.psb")
    builder = ShieldBuilder(b"benchmark-secret")
    start = time.perf_counter()
    builder.build(BuilderConfig(source_dir=source, entry_module="app:main", output_file=output))
    elapsed = time.perf_counter() - start
    print(f"build_time_seconds={elapsed:.6f}")


if __name__ == "__main__":
    main()
