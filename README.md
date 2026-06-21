# GlyphWeave

Privacy-focused, local-first document management with zero-knowledge cloud storage.

## Installing

**Requirements:** Windows 10/11 (x64)

1. Download the latest `glyphweave-setup` executable from the [Releases](https://github.com/TorporOverload/glyphweave/releases) page.
2. Run the installer. If [WinFsp](https://github.com/winfsp/winfsp/releases) is not already installed on your machine, the installer will request administrator rights and install it automatically (WinFsp is a kernel-mode file-system driver required for vault mounting).
3. Launch **Glyphweave** from the Start Menu or the optional desktop shortcut.

To uninstall, use **Add or Remove Programs** in Windows Settings. WinFsp is left in place as it may be used by other applications.

you can clean up the remaining files manually if desired.

vault metadata is stored locally in the user's AppData directory:

```
%USERPROFILE%\.glyphweave
```

## License

GlyphWeave is free software, licensed under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See [LICENSE](LICENSE) for the full text.

This project links against [SQLCipher](https://www.zetetic.net/sqlcipher/) (BSD-style + OpenSSL), [PySide6](https://www.qt.io/qt-for-python) (LGPL-3.0), and [WinFsp](https://winfsp.dev/) (GPL-3.0 with FLOSS exception). Third-party license texts are kept under `app/ui/gui/assets/oss_liscence/`.

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

## Runtime Notes

- On first startup, GlyphWeave creates `device.json` in the app data directory and assigns a persistent UUIDv4 `device_id` if one is missing.
- SQLCipher DB dumps are created with SQLite's online backup API and stored under `vault/db_dumps/`.

