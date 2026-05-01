def escape_like_pattern(value: str) -> str:
    """Escape special LIKE pattern characters (%, _, \\)."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
