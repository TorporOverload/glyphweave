# GlyphWeave

Privacy-focused, local-first document management with zero-knowledge cloud storage.

## Installing

**Requirements:** Windows 10/11 (x64)

1. Download the latest `glyphweave-setup` executable from the [Releases](https://github.com/TorporOverload/glyphweave/releases) page.
2. Run the installer. If [WinFsp](https://github.com/winfsp/winfsp/releases) is not already installed on your machine, the installer will request administrator rights and install it automatically (WinFsp is a kernel-mode file-system driver required for vault mounting).
3. Launch **Glyphweave** from the Start Menu or the optional desktop shortcut.

To uninstall, use **Add or Remove Programs** in Windows Settings. WinFsp is left in place as it may be used by other applications. You can clean up remaining files manually if desired.

Vault metadata is stored locally in the user's AppData directory:

```
%USERPROFILE%\.glyphweave
```

## Development Setup

### Prerequisites

- Windows 10/11 (x64) — the only supported platform
- Python 3.13+
- [uv](https://docs.astral.sh/uv/) — fast Python package and project manager
- [WinFsp](https://github.com/winfsp/winfsp/releases) — required for FUSE-based vault mounting (needed by integration tests and the app itself)

### Install uv

```powershell
# Using the official installer (recommended)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Or via pip
pip install uv
```

### Clone and install dependencies

```powershell
git clone https://github.com/TorporOverload/glyphweave.git
cd glyphweave

# Install all dependencies including dev tools (pytest, ruff, mypy, pyinstaller, etc.)
uv sync --all-groups
```

`uv sync` creates a `.venv` automatically and installs everything declared in `pyproject.toml`. You do not need to create a virtual environment manually.

### Dependency groups

| Group | What it adds | When you need it |
|-------|-------------|-----------------|
| *(default)* | Runtime dependencies | Always |
| `dev` | pytest, ruff, mypy, bandit, pyinstaller, … | Development and testing |
| `bench` | matplotlib, numpy, scikit-learn, scienceplots | Running benchmarks |

```powershell
uv sync                    # default + dev
uv sync --all-groups       # default + dev + bench
uv sync --group bench      # default + bench only
```

### Running the app

```powershell
# CLI mode (recommended for development)
just run
# equivalent: $env:GLYPHWEAVE_DEBUG="3"; $env:GLYPHWEAVE_EVENT_ENCRYPTION="0"; uv run glyphweave cli

# GUI mode
just run-gui

# Dev mode (uses isolated test_data/app_data directory)
just run-dev
```

Or without `just`:

```powershell
uv run glyphweave          # GUI
uv run glyphweave cli      # CLI
```

---

## Testing

### Quick start

```powershell
just test
```

This sets the required environment variables (`GLYPHWEAVE_DEBUG`, log file paths) and runs the full test suite quietly via pytest.

### Test layout

```
tests/
├── unit/
│   ├── app/          # UI action handlers, config, layout
│   ├── common/       # Atomic writes, device ID, file extensions, logging
│   └── core/
│       ├── crypto/   # AES-GCM, key derivation, key wrapping, secure memory
│       ├── database/ # Encryption, file/folder/search/sync services, sessions
│       ├── fuse/     # Chunk store, file handles, meta store, mount runner
│       ├── service/  # Vault bootstrap, indexing, search, import, integrity
│       │   └── vault_files/  # File lifecycle, sessions, mounts, edge cases
│       └── sync/     # Event emitter/processor/store, HLC, replay, runtime
├── integration/
│   └── core/
│       ├── fuse/     # Mount lifecycle, chunk store, WAL, recovery, stress
│       ├── service/  # File lifecycle, search corpus, concurrency
│       └── sync/     # Cross-device conflicts, event replay, DB dumps
├── benchmarks/       # Test harness, corpus, metrics, plotting, smoke
└── support/          # Shared fixtures: fuse builders, temp paths
```

### Test commands

```powershell
# Run the full suite (quiet output)
just test

# Run with full output
just test output=1

# Run a specific file
just test target=tests/unit/core/crypto/primitives/test_key_derivation.py

# Run a specific test
just test target=tests/unit/core/database/test_search_service.py::TestSearchService::test_basic_query

# Run with full output and a specific target
just test target=tests/integration/core/fuse output=1

# Run directly with pytest for full control
uv run pytest tests/unit
uv run pytest tests/integration
uv run pytest tests/unit/core/sync -v
uv run pytest -k "test_hlc"          # filter by name pattern
uv run pytest --no-cov               # skip coverage report
```

### Coverage

Coverage is enabled by default (configured in `pyproject.toml`). The report is printed to the terminal after each run showing missing lines. To skip it:

```powershell
uv run pytest --no-cov
```

### Linting and type checking

```powershell
# Lint (ruff — checks E, F, S rules across app/)
uv run ruff check app/

# Auto-fix lint issues
uv run ruff check --fix app/

# Type check (mypy)
uv run mypy app/

# Security scan (bandit)
uv run bandit -r app/

# Dead code detection (vulture)
uv run vulture app/
```

---

## Benchmarks

The benchmark suite measures six performance dimensions and writes raw results to `benchmarks/results/raw/` (CSV + text) and rendered figures to `benchmarks/results/figures/` (PDF + PNG).

### Setup

```powershell
# Install bench dependencies if not already installed
uv sync --all-groups

# WinFsp must be installed (required for mount benchmarks)
```

### Running benchmarks

```powershell
# Run the full suite
just bench

# Smoke run — shrinks sizes and repeat counts for a fast sanity check
just bench-quick

# Pass arbitrary flags
just bench --only fuse,unlock
just bench --only search --latency-corpus "path/to/large-corpus"
```

Or without `just`:

```powershell
uv run python -m benchmarks.run_all
uv run python -m benchmarks.run_all --quick
uv run python -m benchmarks.run_all --only fuse,unlock
```

### Running a single benchmark module

```powershell
uv run python -m benchmarks.bench_vault_unlock
uv run python -m benchmarks.bench_fuse_throughput
uv run python -m benchmarks.bench_search_latency
uv run python -m benchmarks.bench_concurrent_access
uv run python -m benchmarks.bench_search_accuracy
uv run python -m benchmarks.bench_db_size
```

### Benchmark descriptions

| Benchmark | What it measures |
|-----------|-----------------|
| `bench_fuse_throughput` | MB/s vs file size — in-process and real mount, escalates to failure |
| `bench_search_latency` | Query latency vs corpus size (persisted, resumable vault); hit + zero-result miss queries |
| `bench_vault_unlock` | KDF/bootstrap breakdown, KDF parameter sweep, first-mount time |
| `bench_concurrent_access` | Maximum concurrency at 100% correctness, escalates to failure |
| `bench_search_accuracy` | Precision, recall, MAP, specificity by scope and script; PR curve via scikit-learn |
| `bench_db_size` | On-disk footprint vs corpus size: blobs, DB snapshot, events, metadata, storage overhead ratios |

---

## Building

Requires [GitHub CLI](https://cli.github.com/) (`gh`) and [Inno Setup 6](https://jrsoftware.org/isinfo.php) installed.

```powershell
just build
```

This mirrors the CI pipeline locally:

1. Downloads the latest WinFsp MSI into `redist/` via `gh`
2. Syncs all dependency groups
3. Builds the executable with PyInstaller (`glyphweave.spec`)
4. Packages the installer with Inno Setup (`installer.iss`) — outputs to `Output\`

The version number used for local builds is defined in `installer.iss` (`MyAppVersion`). CI overrides it from the git tag.

---

## Runtime Notes

- On first startup, GlyphWeave creates `device.json` in the app data directory and assigns a persistent UUIDv4 `device_id` if one is missing.
- SQLCipher DB dumps are created with SQLite's online backup API and stored under `vault/db_dumps/`.

## License

GlyphWeave is free software, licensed under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.

This project links against [SQLCipher](https://www.zetetic.net/sqlcipher/) (BSD-style + OpenSSL), [PySide6](https://www.qt.io/qt-for-python) (LGPL-3.0), and [WinFsp](https://winfsp.dev/) (GPL-3.0 with FLOSS exception). Third-party license texts are kept under `app/ui/gui/assets/oss_liscence/`.
