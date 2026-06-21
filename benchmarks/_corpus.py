from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path

from app.services.content.extraction_service import ExtractionService

ARTIFACT_NAMES = {"fulltext_search_corpus.txt"}
VALID_SCOPES = {"content", "filename", "both"}


@dataclass(frozen=True)
class LabeledQuery:
    query: str
    relevant: frozenset[str]
    scope: str = "both"

    @property
    def api_scope(self) -> str:
        """Map the label scope to the search_page() scope vocabulary."""
        return "all" if self.scope == "both" else self.scope

    @property
    def is_negative(self) -> bool:
        return not self.relevant


def is_dhivehi(text: str) -> bool:
    """True if any character falls in the Thaana (Dhivehi) Unicode block."""
    return any(0x0780 <= ord(c) <= 0x07B1 for c in text)


def load_corpus(corpus_dir: Path) -> list[Path]:
    """Recursively collect supported document files (ignoring known artifacts)."""
    return [
        p
        for p in sorted(corpus_dir.rglob("*"))
        if p.is_file()
        and p.name not in ARTIFACT_NAMES
        and ExtractionService.is_supported(p.name)
    ]


def import_documents(
    svc, files: list[Path], start: int, stop: int, *, label: str, total: int
) -> int:
    """Import ``files[start:stop]`` into the vault under ordinal dest names.

    Each file is stored as ``{index:06d}_{name}`` so import order is stable and
    resumable. Prints a progress line every 250 files. Returns ``stop`` (the new
    imported-file count), so callers can keep a running tally across batches.
    """
    for i in range(start, stop):
        path = files[i]
        svc.add_file(path, dest_name=f"{i:06d}_{path.name}")
        if (i + 1) % 250 == 0:
            print(f"[{label} build] imported {i + 1}/{total}")
    return stop


def seeded_order(files: list[Path], seed: int = 1234) -> list[Path]:
    """Deterministic shuffle so nested prefixes are a reproducible random sample."""
    ordered = list(files)
    random.Random(seed).shuffle(ordered)  # noqa
    return ordered


def size_batches(files: list, sizes: list[int]) -> list[tuple[int, list]]:
    """Nested cumulative subsets: 
            batch[k] == files[:sizes[k]] (superset of batch[k-1])."""
    capped = sorted({min(s, len(files)) for s in sizes if s > 0})
    return [(s, files[:s]) for s in capped]


def default_sizes(corpus_len: int) -> list[int]:
    ladder = [50, 100, 250, 500, 1000, 2500, 5000, 10000, 20000]
    sizes = [s for s in ladder if s < corpus_len]
    if not sizes or sizes[-1] != corpus_len:
        sizes.append(corpus_len)
    return sizes


def load_labels(labels_path: Path) -> list[LabeledQuery]:
    raw = json.loads(labels_path.read_text(encoding="utf-8"))
    out: list[LabeledQuery] = []
    for item in raw:
        scope = item.get("scope", "both")
        if scope not in VALID_SCOPES:
            raise ValueError(f"Invalid scope {scope!r} for query {item.get('query')!r}")
        out.append(
            LabeledQuery(
                query=item["query"],
                relevant=frozenset(item.get("relevant", [])),
                scope=scope,
            )
        )
    return out
