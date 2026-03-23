from pathlib import Path


def safe_cache_path(cache_dir: Path, file_name: str) -> Path:
    """Resolve a safe, path-traversal-proof cache path for the given filename."""
    safe_name = Path(str(file_name)).name
    if safe_name in {"", ".", ".."}:
        raise ValueError("Invalid vault filename")

    cache_root = cache_dir.resolve()
    temp_path = (cache_root / safe_name).resolve()
    if not temp_path.is_relative_to(cache_root):
        raise ValueError("Invalid vault filename")
    return temp_path
