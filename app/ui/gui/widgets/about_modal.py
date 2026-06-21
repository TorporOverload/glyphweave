"""About modal for GlyphWeave - app info + OSS licenses."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata as importlib_metadata

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from app.ui.gui.setup.resources import RESOURCES_DIR, get_liscence_text

APP_VERSION = "0.1.001"
RELEASES_URL = "https://github.com/TorporOverload/glyphweave/releases"


@dataclass(frozen=True)
class _Dep:
    name: str
    version: str
    license: str
    url: str
    license_file: str | tuple[str, ...] | None = (
        None  # filename(s) inside assets/oss_liscence/
    )


_BUNDLED_DEPS: tuple[_Dep, ...] = (
    _Dep(
        "Qt for Python (PySide6)",
        "6.11.0",
        "LGPL-3.0",
        "https://www.qt.io/",
        "plain_LGPL.txt",
    ),
    _Dep(
        "cryptography",
        "47.0.0",
        "Apache-2.0 OR BSD-3-Clause",
        "https://cryptography.io",
        ("Apache-2.0_cryptography.txt", "BSD-3-Clause_cryptography.txt"),
    ),
    _Dep(
        "kreuzberg",
        "4.9.4",
        "MIT",
        "https://github.com/Goldziher/kreuzberg",
        "kreuzberg.txt",
    ),
    _Dep(
        "mfusepy", 
        ">=3.1.0", 
        "ISC", 
        "https://github.com/mxmlnkn/mfusepy", 
        "mfusepy.txt"
    ),
    _Dep(
        "mnemonic",
        ">=0.21",
        "MIT",
        "https://github.com/trezor/python-mnemonic",
        "mnemonic.txt",
    ),
    _Dep(
        "SQLAlchemy",
        ">=2.0.46",
        "MIT",
        "https://www.sqlalchemy.org",
        "sqlalchemy.txt",
    ),
    _Dep(
        "sqlcipher3-wheels",
        ">=0.5.7",
        "Zlib",
        "https://github.com/laggykiller/sqlcipher3",
        "sqlcipher3.txt",
    ),
    _Dep(
        "SQLCipher",
        "bundled",
        "BSD-3-Clause",
        "https://www.zetetic.net/sqlcipher/",
        "sqlcipher.txt",
    ),
    _Dep(
        "watchdog",
        ">=6.0.0",
        "Apache-2.0",
        "https://github.com/gorakhargosh/watchdog",
        "watchdog.txt",
    ),
    _Dep(
        "WinFsp",
        "system",
        "GPL-3.0 with FLOSS exception",
        "https://winfsp.dev/",
        "winfsp.txt",
    ),
    _Dep(
        "IBM Plex Sans / Mono",
        "bundled",
        "SIL OFL 1.1",
        "https://github.com/IBM/plex",
        "OFL_ibmPlex.txt",
    ),
    _Dep(
        "AK Rasmee",
        "bundled",
        "SIL OFL 1.1",
        "https://www.akurutype.com/fonts/rasmee",
        "OFL_akrasmee.txt",
    ),
    _Dep(
        "Source Serif Pro",
        "bundled",
        "SIL OFL 1.1",
        "https://github.com/adobe-fonts/source-serif-pro",
        "OFL_source.txt",
    ),
    _Dep(
        "Phosphor Icons",
        "2.1.1",
        "MIT",
        "https://phosphoricons.com",
        "phosphor.txt",
    ),
)


def _resolve_runtime_version(name: str, fallback: str) -> str:
    """Read the actually-installed version from pkg metadata; fall back to the
    declared pin if the package isn't importable (e.g. font-only entries)."""
    try:
        return importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        return fallback


class AboutModal(QDialog):
    """Two-tab About modal: 'About' and 'OSS Licenses'."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("aboutModal")
        self.setWindowTitle("About Glyphweave")
        self.setModal(True)
        self.resize(720, 520)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        tabs = QTabWidget(self)
        tabs.setObjectName("aboutTabs")
        tabs.addTab(self._build_about_tab(), "About")
        tabs.addTab(self._build_licenses_tab(), "OSS Licenses")
        root.addWidget(tabs, 1)

        footer = QWidget(self)
        footer.setObjectName("aboutFooter")
        footer_layout = QHBoxLayout(footer)
        footer_layout.setContentsMargins(16, 10, 16, 10)
        footer_layout.addStretch(1)
        close_btn = QPushButton("Close", footer)
        close_btn.setDefault(True)
        close_btn.clicked.connect(self.accept)
        footer_layout.addWidget(close_btn)
        root.addWidget(footer)

    # About tab

    def _build_about_tab(self) -> QWidget:
        page = QWidget(self)
        page.setObjectName("aboutPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(28, 24, 28, 16)
        layout.setSpacing(14)

        # Header row: logo + wordmark/tagline
        header = QWidget(page)
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(16)

        logo = QLabel(header)
        logo.setObjectName("aboutLogo")
        logo_path = RESOURCES_DIR[0] / "icons" / "glyphweave-icon.png"
        if logo_path.exists():
            pix = QPixmap(str(logo_path))
            if not pix.isNull():
                logo.setPixmap(
                    pix.scaled(
                        64,
                        64,
                        Qt.AspectRatioMode.KeepAspectRatio,
                        Qt.TransformationMode.SmoothTransformation,
                    )
                )
        logo.setFixedSize(64, 64)
        h_layout.addWidget(logo)

        from app.ui.gui.setup import TOKENS

        accent_hex = TOKENS.colors.focus_ring.name()
        wordmark_box = QWidget(header)
        wordmark_layout = QVBoxLayout(wordmark_box)
        wordmark_layout.setContentsMargins(0, 4, 0, 0)
        wordmark_layout.setSpacing(2)
        wordmark = QLabel(
            f"""<span style=\"font-family:'IBM Plex Sans';
        font-weight:140; color:#2e3440;\">"""
            f'glyph<span style="color:{accent_hex};">weave</span>'
            f"</span>",
            wordmark_box,
        )
        wordmark.setObjectName("aboutWordmark")
        wordmark.setTextFormat(Qt.TextFormat.RichText)
        wordmark_layout.addWidget(wordmark)
        tagline = QLabel("where your files stay yours", wordmark_box)
        tagline.setObjectName("aboutTagline")
        wordmark_layout.addWidget(tagline)
        version = QLabel(f"Version {APP_VERSION}", wordmark_box)
        version.setObjectName("aboutVersion")
        wordmark_layout.addWidget(version)
        wordmark_layout.addStretch(1)
        h_layout.addWidget(wordmark_box, 1)

        layout.addWidget(header)

        # Key/value grid
        grid = QWidget(page)
        grid.setObjectName("aboutGrid")
        grid_layout = QVBoxLayout(grid)
        grid_layout.setContentsMargins(0, 4, 0, 0)
        grid_layout.setSpacing(4)
        for key, value in (
            ("Edition", "Desktop"),
            ("Channel", "Development"),
            ("Vault format", "v1"),
            ("Cipher", "AES-256-GCM · SQLCipher (metadata)"),
            ("Runtime", "Python 3.13+"),
            ("Platform", "Windows / WinFsp"),
            ("License", "GPL-3.0-or-later - see LICENSE"),
        ):
            row = QWidget(grid)
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(12)
            k = QLabel(key, row)
            k.setObjectName("aboutGridKey")
            k.setFixedWidth(110)
            v = QLabel(value, row)
            v.setObjectName("aboutGridValue")
            v.setWordWrap(True)
            row_layout.addWidget(k)
            row_layout.addWidget(v, 1)
            grid_layout.addWidget(row)
        layout.addWidget(grid)

        # Blurb
        blurb = QLabel(
            "Glyphweave is a privacy-focused, local-first document management "
            "application. Files live in encrypted, content-addressed vaults on "
            "your device. Cloud sync is zero-knowledge, with providers only seeing "
            "opaque ciphertext blobs and never your keys.",
            page,
        )
        blurb.setObjectName("aboutBlurb")
        blurb.setWordWrap(True)
        layout.addWidget(blurb)

        layout.addStretch(1)

        # Links row
        links = QWidget(page)
        links_layout = QHBoxLayout(links)
        links_layout.setContentsMargins(0, 8, 0, 0)
        links_layout.setSpacing(16)
        copyright_label = QLabel(
            "© 2026 torporoverload · Free software under GPL-3.0-or-later", links
        )
        copyright_label.setObjectName("aboutCopyright")
        links_layout.addWidget(copyright_label)
        links_layout.addStretch(1)
        for label_text in ("Release notes", "Check for updates"):
            link = QPushButton(label_text, links)
            link.setObjectName("aboutLink")
            link.setFlat(True)
            link.setCursor(Qt.CursorShape.PointingHandCursor)
            link.clicked.connect(
                lambda _checked=False: QDesktopServices.openUrl(QUrl(RELEASES_URL))
            )
            links_layout.addWidget(link)
        layout.addWidget(links)

        return page

    # OSS Licenses tab

    def _build_licenses_tab(self) -> QWidget:
        page = QWidget(self)
        page.setObjectName("aboutLicensesPage")
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal, page)
        splitter.setObjectName("aboutLicensesSplitter")

        self._license_list = QListWidget(splitter)
        self._license_list.setObjectName("aboutLicenseList")
        for dep in _BUNDLED_DEPS:
            display_version = _resolve_runtime_version(dep.name.split()[0], dep.version)
            item = QListWidgetItem(f"{dep.name}\n{display_version}  ·  {dep.license}")
            item.setData(Qt.ItemDataRole.UserRole, dep)
            self._license_list.addItem(item)

        self._license_detail = QTextBrowser(splitter)
        self._license_detail.setObjectName("aboutLicenseDetail")
        self._license_detail.setOpenExternalLinks(True)

        splitter.addWidget(self._license_list)
        splitter.addWidget(self._license_detail)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([260, 460])

        self._license_list.currentItemChanged.connect(self._on_license_selected)
        if self._license_list.count() > 0:
            self._license_list.setCurrentRow(0)

        layout.addWidget(splitter, 1)
        return page

    def _on_license_selected(
        self, current: QListWidgetItem | None, _previous: QListWidgetItem | None
    ) -> None:
        if current is None:
            self._license_detail.clear()
            return
        dep: _Dep = current.data(Qt.ItemDataRole.UserRole)
        if isinstance(dep.license_file, tuple):
            parts = []
            spdx_ids = [s.strip() for s in dep.license.split(" OR ")]
            for i, fname in enumerate(dep.license_file):
                label = spdx_ids[i] if i < len(spdx_ids) else fname
                text = get_liscence_text(fname) or ""
                parts.append(
                    f'<div style=\'font-family:"IBM Plex Mono",monospace;'
                    f" font-size:10px; color:#858c9b; text-align:center; "
                    f"margin:{'0 0 6px 0' if i == 0 else '14px 0 6px 0'};'>"
                    f"── {label} ──</div>"
                    f'<pre style=\'font-family:"IBM Plex Mono",monospace;'
                    f" font-size:11px; white-space:pre-wrap;"
                    f" margin:0;'>{_escape_html(text)}</pre>"
                )
            license_text = "".join(parts)
        else:
            raw = get_liscence_text(dep.license_file) or ""
            license_text = (
                '<pre style=\'font-family:"IBM Plex Mono",monospace; font-size:11px; '
                f"white-space:pre-wrap; margin:0;'>{_escape_html(raw)}</pre>"
            )
        header = (
            f"<h3 style='margin:0 0 4px 0;'>{dep.name}</h3>"
            f"<div style='color:#858c9b; font-family:monospace; font-size:11px;'>"
            f"version: {dep.version}</div>"
            f"<div style='margin:6px 0 4px 0;'><b>License:</b> {dep.license}</div>"
            f"<div style='margin-bottom:12px;'>"
            f"<a href='{dep.url}' style='color:#1a4a8a;'>{dep.url}</a></div>"
        )
        self._license_detail.setHtml(header + license_text)
        self._license_detail.verticalScrollBar().setValue(0)


def _escape_html(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
