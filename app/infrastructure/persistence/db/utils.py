def escape_like_pattern(value: str) -> str:
    """Escape special LIKE pattern characters (%, _, \\) for safe use in SQL LIKE clauses."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
