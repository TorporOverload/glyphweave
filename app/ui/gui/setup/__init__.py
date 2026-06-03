"""GlyphWeave GUI setup package.

Provides design tokens, theming, icon loading, and stylesheet building.
All public symbols are re-exported here for convenience.
"""

from .icons import IconLabel, ph_icon_path, tinted_icon
from .resources import (
    FONT_SUFFIXES,
    RESOURCES_DIR,
    load_app_icon,
    load_application_fonts,
    load_icon,
)
from .stylesheet import build_stylesheet
from .theme import (
    ThemeContext,
    apply_alert_variant,
    apply_badge_variant,
    apply_button,
    apply_card_style,
    apply_field,
    apply_selection_variant,
    apply_sidebar_item_style,
    apply_text_style,
    apply_theme,
    build_palette,
    refresh_widget_style,
    set_field_error,
    set_properties,
    set_state,
    set_tone,
)
from .tokens import (
    TOKENS,
    AlertVariant,
    BadgeSpec,
    BadgeVariant,
    ButtonSpec,
    ButtonVariant,
    FieldVariant,
    InputSpec,
    Motion,
    Palette,
    Radius,
    SelectionControlSpec,
    SelectionVariant,
    Sizes,
    Spacing,
    StatusKey,
    StatusSpec,
    SurfaceColors,
    TabNavSpec,
    ThemeTokens,
    Typography,
)
from .types import (
    FILE_ICON_MAP,
    PH_ICON_MAP,
    Role,
    Size,
    State,
    Tone,
)

__all__ = [
    # tokens
    "TOKENS",
    "AlertVariant",
    "BadgeVariant",
    "BadgeSpec",
    "ButtonSpec",
    "ButtonVariant",
    "FieldVariant",
    "InputSpec",
    "Motion",
    "Palette",
    "Radius",
    "Role",
    "SelectionControlSpec",
    "SelectionVariant",
    "Sizes",
    "Spacing",
    "StatusKey",
    "StatusSpec",
    "SurfaceColors",
    "TabNavSpec",
    "ThemeTokens",
    "Tone",
    "Typography",
    # theme
    "ThemeContext",
    "apply_alert_variant",
    "apply_badge_variant",
    "apply_button",
    "apply_card_style",
    "apply_field",
    "apply_selection_variant",
    "apply_sidebar_item_style",
    "apply_text_style",
    "apply_theme",
    "build_palette",
    "refresh_widget_style",
    "set_field_error",
    "set_properties",
    "set_state",
    "set_tone",
    # types
    "FILE_ICON_MAP",
    "PH_ICON_MAP",
    "Size",
    "State",
    # icons
    "IconLabel",
    "ph_icon_path",
    "tinted_icon",
    # resources
    "FONT_SUFFIXES",
    "RESOURCES_DIR",
    "load_app_icon",
    "load_application_fonts",
    "load_icon",
    # stylesheet
    "build_stylesheet",
]
