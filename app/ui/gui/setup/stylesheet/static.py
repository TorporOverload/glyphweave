"""Static QSS blocks that don't depend on theme tokens - the Windows-only
menubar polish and the About-modal styling."""


WINDOWS_MENUBAR_QSS = """
/* ------ Windows 10/11 menubar (windows-only) ------ */

QMenuBar {
    background-color: #f3f3f3;
    color: #1f1f1f;
    border-bottom: 1px solid #d1d1d1;
    font-family: "Segoe UI", system-ui, sans-serif;
    font-size: 12px;
    padding: 0;
    spacing: 0;
}

QMenuBar::item {
    background: transparent;
    color: #1f1f1f;
    padding: 4px 10px;
    margin: 0;
    border: 1px solid transparent;
}

QMenuBar::item:selected {
    background-color: #e5e5e5;
}

QMenuBar::item:pressed,
QMenuBar::item:open {
    background-color: #ffffff;
    border: 1px solid #d1d1d1;
}

QMenu {
    background-color: #ffffff;
    color: #1f1f1f;
    border: 1px solid #d1d1d1;
    border-radius: 4px;
    padding: 4px;
    font-family: "Segoe UI", system-ui, sans-serif;
    font-size: 12px;
}

QMenu::item {
    background: transparent;
    color: #1f1f1f;
    padding: 6px 24px 6px 12px;
    border-radius: 3px;
    min-height: 18px;
}

QMenu::item:selected {
    background-color: #e5f1fb;
    color: #1f1f1f;
}

QMenu::item:disabled {
    color: #a0a0a0;
}

QMenu::separator {
    height: 1px;
    background-color: #e5e5e5;
    margin: 4px 2px;
}

#menubarStatus {
    background: transparent;
}

#menubarStatusText {
    font-family: "Segoe UI", system-ui, sans-serif;
    font-size: 11px;
    color: #5a5a5a;
    background: transparent;
}

"""


ABOUT_MODAL_QSS = """
/* ------ About modal ------ */

#aboutModal {
    background-color: #ffffff;
}

#aboutTabs::pane {
    border: 0;
    border-top: 1px solid #d1d1d1;
    background-color: #ffffff;
}

#aboutTabs QTabBar {
    background-color: #f6f7f9;
}

#aboutTabs QTabBar::tab {
    background-color: transparent;
    color: #4c566a;
    padding: 10px 22px;
    border: 0;
    font-size: 12px;
    font-weight: 600;
}

#aboutTabs QTabBar::tab:selected {
    color: #2e3440;
    border-bottom: 2px solid #5a5f9e;
}

#aboutTabs QTabBar::tab:hover:!selected {
    color: #2e3440;
}

#aboutPage {
    background-color: #ffffff;
}

#aboutModal QWidget {
    background-color: #ffffff;
}

#aboutWordmark {
    font-family: "IBM Plex Sans";
    font-size: 24px;
    font-weight: 600;
    color: #2e3440;
}

#aboutTagline {
    font-family: "IBM Plex Mono";
    font-size: 11px;
    color: #858c9b;
}

#aboutVersion {
    font-family: "IBM Plex Mono";
    font-size: 11px;
    color: #4c566a;
}

#aboutGridKey {
    font-family: "IBM Plex Mono";
    font-size: 10px;
    text-transform: uppercase;
    color: #858c9b;
}

#aboutGridValue {
    font-size: 12px;
    color: #2e3440;
}

#aboutBlurb {
    font-size: 12px;
    color: #3b4252;
    line-height: 1.5;
    background-color: #f6f7f9;
    border: 1px solid #e5e9f0;
    border-radius: 4px;
    padding: 12px 14px;
}

#aboutCopyright {
    font-family: "IBM Plex Mono";
    font-size: 10px;
    color: #858c9b;
}

#aboutLink {
    color: #5a5f9e;
    background: transparent;
    border: 0;
    text-decoration: underline;
    font-size: 11px;
    padding: 2px 4px;
}

#aboutLink:hover {
    color: #2e3440;
}

#aboutFooter {
    background-color: #f6f7f9;
    border-top: 1px solid #e5e9f0;
}

#aboutLicensesPage {
    background-color: #ffffff;
}

#aboutLicenseList {
    background-color: #f6f7f9;
    border: 0;
    border-right: 1px solid #e5e9f0;
    padding: 4px;
    font-size: 11px;
}

#aboutLicenseList::item {
    padding: 8px 10px;
    border-radius: 4px;
    color: #2e3440;
}

#aboutLicenseList::item:selected {
    background-color: #d6d7ec;
    color: #2e3440;
}

#aboutLicenseList::item:hover:!selected {
    background-color: #e5e9f0;
}

#aboutLicenseDetail {
    background-color: #ffffff;
    border: 0;
    padding: 16px 20px;
    color: #2e3440;
    font-size: 12px;
}
"""
