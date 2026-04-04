from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.common.exceptions.crypto import InvalidPasswordError
from app.common.paths.vault_layout import EVENTS_DIR, vault_key_path
from app.core.domain.sync.hlc import hlc_to_tuple
from app.infrastructure.crypto.service.key_service import KeyService
from app.infrastructure.crypto.service.utils import load_vault_key
from app.infrastructure.persistence.event_store import EventIntegrityError, EventStore
from app.infrastructure.persistence.event_store_config import EventStoreConfig

DECRYPTED_OBJECTS_DIR = "decrypted-objects"
DEFAULT_LIMIT = 100


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Decrypt the most recent vault event objects and export them as JSON files."
        ),
    )
    parser.add_argument(
        "--path",
        dest="vault_path",
        required=True,
        type=Path,
        help="Path to the vault directory.",
    )
    parser.add_argument(
        "--password",
        required=True,
        help="Vault password.",
    )
    parser.add_argument(
        "--limit",
        type=_positive_int,
        default=DEFAULT_LIMIT,
        help=f"Number of most recent events to export. Default: {DEFAULT_LIMIT}.",
    )
    return parser


def decrypt_recent_events(
    vault_path: Path,
    password: str,
    *,
    limit: int,
) -> list[dict[str, object]]:
    store = _build_event_store(vault_path, password)
    return collect_recent_events(store, limit=limit)


def collect_recent_events(
    store: EventStore,
    *,
    limit: int,
) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for path in store.objects_dir.glob("*.json"):
        event = store.load_event(path.stem, verify=True)
        payload = event.to_dict()
        payload["source_path"] = str(path)
        payload["event_hash"] = event.event_hash or path.stem
        events.append(payload)
    return sorted(events, key=_recent_event_sort_key, reverse=True)[:limit]


def export_decrypted_events(
    events: list[dict[str, object]],
    *,
    output_dir: Path,
) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    for existing in output_dir.glob("*.json"):
        existing.unlink()

    width = max(3, len(str(max(len(events), 1))))
    written_paths: list[Path] = []
    for index, event in enumerate(events, start=1):
        event_hash = str(event.get("event_hash") or f"event-{index}")
        target_path = output_dir / f"{index:0{width}d}-{event_hash}.json"
        target_path.write_text(
            json.dumps(event, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        written_paths.append(target_path)
    return written_paths


def decrypted_objects_dir(vault_path: Path) -> Path:
    return Path(vault_path) / EVENTS_DIR / DECRYPTED_OBJECTS_DIR


def main() -> int:
    args = build_parser().parse_args()
    vault_path = args.vault_path.expanduser().resolve()

    try:
        events = decrypt_recent_events(
            vault_path,
            args.password,
            limit=args.limit,
        )
        output_dir = decrypted_objects_dir(vault_path)
        written_paths = export_decrypted_events(events, output_dir=output_dir)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except InvalidPasswordError:
        print("Failed to unlock vault: incorrect password.", file=sys.stderr)
        return 2
    except EventIntegrityError as exc:
        print(f"Event integrity check failed: {exc}", file=sys.stderr)
        return 3
    except Exception as exc:
        print(f"Failed to decrypt vault events: {exc}", file=sys.stderr)
        return 4

    print(
        f"Exported {len(written_paths)} decrypted event object(s) to {output_dir}",
    )
    return 0


def _build_event_store(vault_path: Path, password: str) -> EventStore:
    key_path = vault_key_path(vault_path)
    if not key_path.exists():
        raise FileNotFoundError(f"vault.key not found at {key_path}")

    key_service = KeyService()
    key_service.vault_key_file = load_vault_key(key_path)
    key_service.unwrap_master_key(password)

    if not key_service.master_key:
        exit()

    return EventStore(
        EventStoreConfig(
            vault_path=vault_path,
            vault_id=key_service.vault_key_file.vault_id,
            master_key=key_service.master_key,
            encryption_enabled=True,
        )
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("limit must be a positive integer")
    return parsed


def _recent_event_sort_key(event: dict[str, object]) -> tuple[int, int, str, str]:
    hlc = event.get("hlc")
    if not isinstance(hlc, dict):
        raise ValueError("Decrypted event is missing a valid HLC payload")
    wall_time, logical, device_id = hlc_to_tuple(hlc)
    return (wall_time, logical, device_id, str(event.get("event_id") or ""))


if __name__ == "__main__":
    raise SystemExit(main())
