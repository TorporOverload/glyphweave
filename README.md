# GlyphWeave

Privacy-focused, local-first document management with zero-knowledge cloud storage.

## Development

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
# Create virtual environment and install dependencies
uv sync

# Run the application
uv run glyphweave

# Run with debug logging
$env:GLYPHWEAVE_DEBUG="1"; uv run glyphweave

# Run tests
uv run pytest
```


