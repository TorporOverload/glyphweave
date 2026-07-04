set shell := ["powershell", "-NoLogo", "-Command"]

run:
    $env:GLYPHWEAVE_DEBUG = "3"; \
    $env:GLYPHWEAVE_EVENT_ENCRYPTION = "0"; \
    uv run glyphweave cli
    
run-gui:
    $env:GLYPHWEAVE_DEBUG = "3"; \
    $env:GLYPHWEAVE_EVENT_ENCRYPTION = "0"; \
    uv run glyphweave

run-dev:
    $env:GLYPHWEAVE_APP_DATA_DIR = "test_data/app_data"; \
    $env:GLYPHWEAVE_DEBUG = "3"; \
    $env:GLYPHWEAVE_EVENT_ENCRYPTION = "0"; \
    uv run glyphweave

test target='' output='0':
    $env:GLYPHWEAVE_DEBUG = "3"; \
    $env:GLYPHWEAVE_LOG_FILE = Join-Path $PWD ".test_tmp\\debug.log"; \
    $env:GLYPHWEAVE_ERROR_LOG_FILE = Join-Path $PWD ".test_tmp\\error.log"; \
    if ("{{output}}" -eq "1" -and "{{target}}" -eq "") { \
    uv run -m pytest $pytest_tmp \
    } elseif ("{{output}}" -eq "1") { \
    uv run -m pytest $pytest_tmp {{target}} \
    } elseif ("{{target}}" -eq "") { \
    uv run -m pytest -q $pytest_tmp \
    } else { \
    uv run -m pytest -q $pytest_tmp {{target}} \
    }

build:
    New-Item -ItemType Directory -Force -Path redist | Out-Null; \
    gh release download --repo winfsp/winfsp --pattern "winfsp-*.msi" --dir redist; \
    Get-ChildItem redist\*.msi | Select-Object -First 1 | Rename-Item -NewName "winfsp.msi" -Force; \
    uv sync --all-groups; \
    uv run pyinstaller glyphweave.spec; \
    & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss; \
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

bench *args:
    uv run python -m benchmarks.run_all {{args}}

bench-quick:
    uv run python -m benchmarks.run_all --quick
