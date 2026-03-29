set shell := ["powershell", "-NoLogo", "-Command"]

run:
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
