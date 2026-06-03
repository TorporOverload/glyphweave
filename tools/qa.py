"""Static-analysis runner: ruff, mypy, bandit, vulture, lizard.

    uv run python tools/qa.py            # run everything
    uv run python tools/qa.py ruff mypy  # run a subset

Exit code is non-zero if any of the requested checks fail.

Environment overrides:
    QA_TARGET                - space-separated paths to analyse (default: app)
    BANDIT_EXCLUDES          - comma-separated paths to exclude
    VULTURE_MIN_CONFIDENCE   - vulture minimum confidence (default: 80)
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGETS = ["app"]
EXISTING_TARGETS = [p for p in DEFAULT_TARGETS if (REPO_ROOT / p).exists()] or ["."]
TARGET = os.environ.get("QA_TARGET", " ".join(EXISTING_TARGETS))
BANDIT_EXCLUDES = os.environ.get(
    "BANDIT_EXCLUDES", ".venv,venv,.git,__pycache__,.mypy_cache,.pytest_cache"
)
LIZARD_MAX_CCN = "120"
VULTURE_MIN_CONFIDENCE = os.environ.get("VULTURE_MIN_CONFIDENCE", "80")


def _split_targets(value: str) -> list[str]:
    return [item for item in value.split() if item]


def _run(*args: str) -> int:
    completed = subprocess.run(  # noqa: S603 - argv list, not shell
        [sys.executable, "-m", *args], cwd=REPO_ROOT
    )
    return completed.returncode


def run_ruff() -> int:
    return _run("ruff", "check", *EXISTING_TARGETS)


def run_mypy() -> int:
    import mypy.api

    stdout, stderr, exit_code = mypy.api.run(_split_targets(TARGET))
    sys.stdout.write(stdout)
    sys.stderr.write(stderr)
    return exit_code


def run_bandit() -> int:
    return _run("bandit", "-r", *EXISTING_TARGETS, "-ll", "-ii", "-x", BANDIT_EXCLUDES)


def run_vulture() -> int:
    return _run("vulture", *EXISTING_TARGETS, "--min-confidence", VULTURE_MIN_CONFIDENCE)


def run_lizard() -> int:
    args = ["lizard"]
    if LIZARD_MAX_CCN:
        args.extend(["-C", str(LIZARD_MAX_CCN)])
    args.extend(EXISTING_TARGETS)
    return _run(*args)


CHECKS = {
    "ruff": run_ruff,
    "mypy": run_mypy,
    "bandit": run_bandit,
    "vulture": run_vulture,
    "lizard": run_lizard,
}


def main(argv: list[str]) -> int:
    selected = argv[1:] or list(CHECKS.keys())
    unknown = [c for c in selected if c not in CHECKS]
    if unknown:
        sys.stderr.write(
            f"unknown check(s): {', '.join(unknown)}; "
            f"valid: {', '.join(CHECKS)}\n"
        )
        return 2

    failures: list[str] = []
    for name in selected:
        print(f"\n=== {name} ===")
        rc = CHECKS[name]()
        if rc != 0:
            failures.append(name)

    if failures:
        sys.stderr.write(f"\nQA failures: {', '.join(failures)}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
