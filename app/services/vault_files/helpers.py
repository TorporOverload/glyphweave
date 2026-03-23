from __future__ import annotations


def normalize_vault_path(path: str | None) -> str:
    if path is None:
        return "/"

    normalized = path.strip().replace("\\", "/")
    if not normalized:
        return "/"

    parts = [segment for segment in normalized.split("/") if segment not in {"", "."}]
    if any(segment == ".." for segment in parts):
        raise ValueError("Parent traversal ('..') is not allowed")

    if not parts:
        return "/"
    return "/" + "/".join(parts)


def is_descendant_path(candidate_path: str, parent_path: str) -> bool:
    normalized_candidate = normalize_vault_path(candidate_path)
    normalized_parent = normalize_vault_path(parent_path)
    return normalized_candidate == normalized_parent or normalized_candidate.startswith(
        normalized_parent + "/"
    )


def ensure_no_nested_selection(entries) -> None:
    ordered_paths = sorted(entry.virtual_path for entry in entries)
    for index, path in enumerate(ordered_paths):
        for later in ordered_paths[index + 1 :]:
            if later.startswith(path + "/"):
                raise ValueError("Nested selections are not allowed for this operation")


def collapse_descendant_entries(entries):
    kept = []
    for entry in sorted(entries, key=lambda item: len(item.virtual_path)):
        if any(
            entry.virtual_path.startswith(parent.virtual_path + "/") for parent in kept
        ):
            continue
        kept.append(entry)
    return kept
