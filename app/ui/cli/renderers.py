from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any


def render_setup_vault_lines(known_vaults: list[dict]) -> list[str]:
    lines = render_known_vault_lines(known_vaults)
    lines.extend(
        [
            "  96. Delete local vault record",
            "  97. Import existing vault",
            "  98. Recover vault with recovery phrase",
            "  99. Create new vault",
        ]
    )
    return lines


def render_known_vault_lines(known_vaults: list[dict]) -> list[str]:
    if not known_vaults:
        return ["No known vaults yet."]

    lines = ["Known vaults:"]
    for index, vault in enumerate(known_vaults, 1):
        lines.append(f"  {index}. {vault['vault_alias']}  ({vault['path']})")
    return lines


def render_vault_contents_lines(
    root_entries: Sequence[Any],
    get_children: Callable[[int], Sequence[Any]],
) -> list[str]:
    lines: list[str] = []
    for index, ref in enumerate(root_entries, 1):
        if ref.is_folder:
            lines.append(f"  {index}. [DIR]  {ref.name}")
            lines.extend(
                _render_child_lines(get_children(ref.id), get_children, "         ")
            )
        else:
            lines.append(f"  {index}. {ref.name}{_size_suffix(ref)}")
    return lines


def _render_child_lines(
    entries: Sequence[Any],
    get_children: Callable[[int], Sequence[Any]],
    prefix: str,
) -> list[str]:
    lines: list[str] = []
    for ref in entries:
        if ref.is_folder:
            lines.append(f"{prefix}[DIR] {ref.name}")
            lines.extend(
                _render_child_lines(get_children(ref.id), get_children, prefix + "  ")
            )
        else:
            lines.append(f"{prefix}{ref.name}{_size_suffix(ref)}")
    return lines


def render_available_file_lines(file_refs: Sequence[Any]) -> list[str]:
    return [
        f"  {index}. {ref.name}{_size_suffix(ref)}"
        for index, ref in enumerate(file_refs, 1)
    ]


def render_directory_entry_lines(entries: Sequence[Any]) -> list[str]:
    lines: list[str] = []
    for index, ref in enumerate(entries, 1):
        if ref.is_folder:
            lines.append(f"  {index}. [DIR] {ref.name}")
        else:
            lines.append(f"  {index}. {ref.name}{_size_suffix(ref)}")
    return lines


def render_unlocked_file_lines(unlocked_items: Sequence[Any]) -> list[str]:
    lines: list[str] = []
    for index, item in enumerate(unlocked_items, 1):
        source_label = "FUSE" if item.source == "mount" else "CACHE"
        lines.append(
            f"  {index}. [{source_label}] {item.file_name}  ({item.file_path})"
        )
    return lines


def render_vault_menu_lines(vault_name: str | None) -> list[str]:
    return [
        "=" * 40,
        f"GlyphWeave - {vault_name}",
        "=" * 40,
        "1. List files",
        "2. Open file",
        "3. List unlocked files",
        "4. Add file",
        "5. Search",
        "6. Manage files/folders",
        "7. Show recovery phrase",
        "8. Show DB key (debug)",
        "9. Manage sync conflicts",
        "10. Manage device aliases",
        "11. Check vault integrity",
        "12. Repair local state from events",
        "13. Exit",
        "=" * 40,
    ]


def render_search_result_lines(results: Sequence[Any]) -> list[str]:
    if not results:
        return ["  No results found."]

    lines: list[str] = []
    for index, result in enumerate(results, 1):
        snippet_clean = result.snippet.replace("<b>", "*").replace("</b>", "*")
        lines.append(f"  {index}. {result.file_name}  ({result.virtual_path})")
        if snippet_clean:
            lines.append(f"     {snippet_clean}")
    return lines


def render_search_options_lines(has_more: bool) -> list[str]:
    lines = ["", "Options:"]
    if has_more:
        lines.append("  n. Next page")
    lines.append("  [number]. Open file")
    lines.append("  [blank]. Go back")
    return lines


def select_file_by_choice(choice: str, file_refs: Sequence[Any]) -> Any | None:
    if choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(file_refs):
            return file_refs[index]
        return None

    for ref in file_refs:
        if ref.name == choice:
            return ref
    return None


def parse_path_list(text: str) -> list[str]:
    return [part.strip().strip('"') for part in text.split(",") if part.strip()]


def _size_suffix(ref: Any) -> str:
    if getattr(ref, "file_entry", None):
        return f"  ({ref.file_entry.original_size_bytes} bytes)"
    return ""
