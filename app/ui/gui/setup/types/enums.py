from __future__ import annotations

from enum import StrEnum


class ButtonVariant(StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    GHOST = "ghost"
    DANGER = "danger"
    ICON = "icon"


class FieldVariant(StrEnum):
    TEXT = "text"
    SEARCH = "search"
    PASSWORD = "pass" + "word"
    SELECT = "select"
    MULTILINE = "multiline"


class SelectionVariant(StrEnum):
    CHECKBOX = "checkbox"
    RADIO = "radio"
    SWITCH = "switch"


class BadgeVariant(StrEnum):
    NEUTRAL = "neutral"
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    WARNING_STRONG = "warning-strong"
    ERROR = "error"
    CONFLICT = "conflict"
    METADATA = "metadata"


class AlertVariant(StrEnum):
    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    WARNING_STRONG = "warning-strong"
    ERROR = "error"
    CONFLICT = "conflict"


class StatusKey(StrEnum):
    LOCKED = "locked"
    UNLOCK_ERROR = "unlock-error"
    READY = "ready"
    SYNCED = "synced"
    SYNCING = "syncing"
    CONFLICT = "conflict"



class Role(StrEnum):
    # Generic
    CARD = "card"
    SEPARATOR = "separator"
    BADGE = "badge"
    ALERT = "alert"
    SIDEBAR_ITEM = "sidebar-item"
    # Screens
    EMPTY_VAULT = "empty-vault"
    RECOVERY_PHRASE = "recovery-phrase"
    VAULT_LIST = "vault-list"
    UNLOCK_VAULT = "unlock-vault"
    FILE_VIEW = "file-view"
    # Modals
    CREATE_VAULT_MODAL = "create-vault-modal"
    RECOVERY_MODAL = "recovery-modal"
    VAULT_LIST_MODAL = "vault-list-modal"
    UNLOCK_MODAL = "unlock-modal"
    # Create vault
    CREATE_VAULT = "create-vault"
    CREATE_VAULT_FIELD = "create-vault-field"
    CREATE_VAULT_DIVIDER = "create-vault-divider"
    CREATE_VAULT_CAPTION = "create-vault-caption"
    SPLASH_COPY = "splash-copy"
    # Create folder
    CREATE_FOLDER = "create-folder"
    CREATE_FOLDER_TITLE = "create-folder-title"
    CREATE_FOLDER_FIELD = "create-folder-field"
    # Recovery
    RECOVERY = "recovery"
    RECOVERY_PILL = "recovery-pill"
    RECOVERY_NUMBER = "recovery-number"
    RECOVERY_MONO = "recovery-mono"
    RECOVERY_WARNING = "recovery-warning"
    RECOVERY_HINT = "recovery-hint"
    RECOVERY_CHECK = "recovery-check"
    RECOVERY_DIVIDER = "recovery-divider"
    RECOVERY_SHORT_DIVIDER = "recovery-short-divider"
    RECOVERY_INPUT = "recovery-input"
    # Vault list
    VAULT_ITEM = "vault-item"
    VAULT_LINK = "vault-link"
    VAULT_PATH = "vault-path"
    VAULT_INDICATOR = "vault-indicator"
    VAULT_INTRO = "vault-intro"
    VAULT_SUBTITLE = "vault-subtitle"
    VAULT_FOOTER = "vault-footer"
    VAULT_TIMESTAMP = "vault-timestamp"
    # Unlock
    UNLOCK = "unlock"
    UNLOCK_BACK = "unlock-back"
    UNLOCK_FORGOT = "unlock-forgot"
    PASSWORD = "password"  # noqa: S105
    UNLOCK_PATH = "unlock-path"
    UNLOCK_INTRO = "unlock-intro"
    ERROR_TEXT = "error-text"
    # File view
    FILE_HEADER = "file-header"
    SEARCH_SHELL = "search-shell"
    SEARCH = "search"
    BREADCRUMBS = "breadcrumbs"
    FILE_TOOLBAR = "file-toolbar"
    FILE_TREE = "file-tree"
    FILE_TABLE = "file-table"
    FILE_TABS = "file-tabs"
    FILE_TAB = "file-tab"
    FILE_CARD = "file-card"
    FILE_PILL = "file-pill"
    FILE_PROPS_ACTIONS = "file-props-actions"
    FILE_PREVIEW = "file-preview"
    FILE_FOOTER = "file-footer"
    UNLOCKED_CARD = "unlocked-card"


class State(StrEnum):
    ACTIVE = "active"
    SELECTED = "selected"
    ERROR = "error"


class Size(StrEnum):
    SM = "sm"
    MD = "md"
    LG = "lg"


class Tone(StrEnum):
    MUTED = "muted"
    SUCCESS = "success"
    WARNING = "warning"
    WARNING_STRONG = "warning-strong"
    ERROR = "error"
    INFO = "info"
    NEUTRAL = "neutral"
    CONFLICT = "conflict"
    METADATA = "metadata"
