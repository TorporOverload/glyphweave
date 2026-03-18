set shell := ["powershell", "-NoLogo", "-Command"]

run:
    uv run glyphweave

test target='' output='0':
    New-Item -ItemType Directory -Force .test_tmp | Out-Null
    $env:UV_CACHE_DIR = Join-Path $PWD ".uv-cache"
    $env:GLYPHWEAVE_LOG_FILE = Join-Path $PWD ".test_tmp\\debug.log"
    $env:GLYPHWEAVE_ERROR_LOG_FILE = Join-Path $PWD ".test_tmp\\error.log"
    if ("{{output}}" -eq "1" -and "{{target}}" -eq "") { uv run pytest } elseif ("{{output}}" -eq "1") { uv run pytest {{target}} } elseif ("{{target}}" -eq "") { uv run pytest -q } else { uv run pytest -q {{target}} }
