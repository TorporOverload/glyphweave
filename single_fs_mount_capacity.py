from __future__ import annotations

import argparse
import getpass
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from app.core.service.vault_service import VaultService


@dataclass
class Attempt:
    ref_id: int
    virtual_path: str
    ok: bool
    detail: str
    elapsed_seconds: float


@dataclass
class ImportResult:
    attempted: int
    imported: int
    failed: int
    first_failure: str | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure how many vault files can be mounted simultaneously "
            "via SingleFileFS."
        )
    )
    parser.add_argument(
        "--vault-path",
        type=Path,
        required=True,
        help="Path to the vault directory.",
    )
    parser.add_argument(
        "--password",
        help="Vault password. If omitted, prompt securely.",
    )
    parser.add_argument(
        "--password-env",
        default="GLYPHWEAVE_VAULT_PASSWORD",
        help=(
            "Environment variable to read password from when --password is not used "
            "(default: GLYPHWEAVE_VAULT_PASSWORD)."
        ),
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Only test the first N files (default: all files in vault).",
    )
    parser.add_argument(
        "--verify",
        choices=("none", "path", "read", "office"),
        default="read",
        help=(
            "Mount verification level: none=skip checks, path=wait for path, "
            "read=probe open/read, office=full Office-style probe."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait for each verification probe (default: 10).",
    )
    parser.add_argument(
        "--continue-on-failure",
        action="store_true",
        help="Keep testing remaining files after a failure.",
    )
    parser.add_argument(
        "--keep-mounted",
        action="store_true",
        help="Leave successful mounts active when the script exits.",
    )
    parser.add_argument(
        "--import-dir",
        type=Path,
        default=None,
        help=(
            "Import all files under this directory (recursive) before running "
            "mount-capacity checks."
        ),
    )
    parser.add_argument(
        "--import-prefix",
        default="",
        help=("Optional prefix for imported file names (for example: imported_)."),
    )
    parser.add_argument(
        "--import-target-dir",
        default="/",
        help=(
            "Vault directory path where the import tree should be placed (default: /)."
        ),
    )
    parser.add_argument(
        "--import-only",
        action="store_true",
        help="Only perform recursive import and exit.",
    )

    args = parser.parse_args()
    if args.max_files is not None and args.max_files <= 0:
        parser.error("--max-files must be greater than 0")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.import_only and args.import_dir is None:
        parser.error("--import-only requires --import-dir")
    return args


def resolve_password(args: argparse.Namespace) -> str:
    if args.password:
        return args.password

    env_value = os.getenv(args.password_env)
    if env_value:
        return env_value

    return getpass.getpass("Vault password: ")


def list_file_refs(service: VaultService) -> list:
    folder_service = service.context.folder_service
    if folder_service is None:
        raise RuntimeError("Folder service is not initialized")

    refs = [ref for ref in folder_service.get_vault_tree() if not ref.is_folder]
    refs.sort(key=lambda ref: ref.id)
    return refs


def _normalize_vault_dir_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    if not normalized:
        return "/"

    parts = [segment for segment in normalized.split("/") if segment not in {"", "."}]
    if any(segment == ".." for segment in parts):
        raise ValueError("Parent traversal ('..') is not allowed in import target dir")

    if not parts:
        return "/"
    return "/" + "/".join(parts)


def _join_vault_dir(base_dir: str, relative_parent: Path) -> str:
    if not relative_parent.parts:
        return base_dir

    suffix = "/".join(relative_parent.parts)
    if base_dir == "/":
        return f"/{suffix}"
    return f"{base_dir}/{suffix}"


def _format_vault_file_path(parent_dir: str, file_name: str) -> str:
    if parent_dir == "/":
        return f"/{file_name}"
    return f"{parent_dir}/{file_name}"


def _existing_names_for_directory(
    service: VaultService,
    directory_path: str,
    cache: dict[str, set[str]],
) -> set[str]:
    existing = cache.get(directory_path)
    if existing is not None:
        return existing

    if directory_path == "/":
        entries = service.list_root_entries()
        names = {entry.name for entry in entries}
        cache[directory_path] = names
        return names

    folder_service = service.context.folder_service
    if folder_service is None:
        raise RuntimeError("Folder service is not initialized")

    folder_ref = folder_service.get_by_virtual_path(directory_path)
    if folder_ref is None:
        names: set[str] = set()
        cache[directory_path] = names
        return names

    if not folder_ref.is_folder:
        raise NotADirectoryError(
            f"Import target is not a folder in vault: {directory_path}"
        )

    entries = service.list_children(folder_ref.id)
    names = {entry.name for entry in entries}
    cache[directory_path] = names
    return names


def _make_unique_name(desired: str, used_names: set[str]) -> str:
    if desired not in used_names:
        return desired

    base_path = Path(desired)
    stem = base_path.stem or "file"
    suffix = base_path.suffix

    counter = 2
    while True:
        candidate = f"{stem}_{counter}{suffix}"
        if candidate not in used_names:
            return candidate
        counter += 1


def import_directory_recursive(
    service: VaultService,
    source_dir: Path,
    *,
    prefix: str,
    target_dir: str,
) -> ImportResult:
    if not source_dir.exists() or not source_dir.is_dir():
        raise FileNotFoundError(f"Import directory not found: {source_dir}")

    files = sorted(
        (path for path in source_dir.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(source_dir).as_posix(),
    )
    if not files:
        return ImportResult(attempted=0, imported=0, failed=0, first_failure=None)

    target_base_dir = _normalize_vault_dir_path(target_dir)
    names_cache: dict[str, set[str]] = {}

    imported = 0
    failed = 0
    first_failure: str | None = None
    total = len(files)

    for idx, source_path in enumerate(files, start=1):
        relative_path = source_path.relative_to(source_dir)
        relative_parent = (
            Path(*relative_path.parts[:-1]) if relative_path.parts[:-1] else Path()
        )
        vault_parent_dir = _join_vault_dir(target_base_dir, relative_parent)
        used_names = _existing_names_for_directory(
            service, vault_parent_dir, names_cache
        )

        base_name = f"{prefix}{relative_path.name}" if prefix else relative_path.name
        dest_name = _make_unique_name(base_name, used_names)

        try:
            service.add_file(
                source_path,
                dest_name=dest_name,
                dest_parent_virtual_path=vault_parent_dir,
            )
            used_names.add(dest_name)
            imported += 1
            vault_dest_path = _format_vault_file_path(vault_parent_dir, dest_name)
            print(
                f"[IMPORT OK] {idx}/{total} src={relative_path.as_posix()} "
                f"dest={vault_dest_path}"
            )
        except Exception as exc:
            failed += 1
            reason = f"{type(exc).__name__}: {exc}"
            vault_dest_path = _format_vault_file_path(vault_parent_dir, dest_name)
            if first_failure is None:
                first_failure = (
                    f"src={relative_path.as_posix()} dest={vault_dest_path} "
                    f"reason={reason}"
                )
            print(
                f"[IMPORT FAIL] {idx}/{total} src={relative_path.as_posix()} "
                f"dest={vault_dest_path} reason={reason}"
            )

    return ImportResult(
        attempted=total,
        imported=imported,
        failed=failed,
        first_failure=first_failure,
    )


def verify_mount(mounts, info, verify_level: str, timeout: float) -> tuple[bool, str]:
    if verify_level == "none":
        return True, "mounted"

    if not mounts._wait_for_mount_path(info.file_path, timeout):
        return False, "mount path did not become visible"

    if verify_level == "path":
        return True, "path visible"

    if not mounts._wait_for_mount_responsive(info.file_path, timeout):
        return False, "file open/read probe failed"

    if verify_level == "read":
        return True, "read probe passed"

    if not mounts._wait_for_mount_office_ready(info.mount_dir, info.file_path, timeout):
        return False, "Office compatibility probe failed"

    return True, "Office probe passed"


def main() -> int:
    args = parse_args()
    service = VaultService()
    runtime_ready = False

    attempts: list[Attempt] = []
    opened = 0

    try:
        service.prepare_existing_vault(args.vault_path)
        service.open_existing_vault(resolve_password(args))
        runtime_ready = True

        if args.import_dir is not None:
            print(f"Importing files recursively from: {args.import_dir}")
            import_result = import_directory_recursive(
                service,
                args.import_dir,
                prefix=args.import_prefix,
                target_dir=args.import_target_dir,
            )

            print("\nImport result")
            print(f"- Attempted: {import_result.attempted}")
            print(f"- Imported: {import_result.imported}")
            print(f"- Failed: {import_result.failed}")
            if import_result.first_failure:
                print(f"- First failure: {import_result.first_failure}")

            if args.import_only:
                if import_result.failed > 0:
                    return 1
                return 0

        mounts = service.context.mounts
        if mounts is None:
            raise RuntimeError("Mount orchestrator is not initialized")

        file_refs = list_file_refs(service)
        if not file_refs:
            print("No files found in this vault.")
            return 1

        if args.max_files is not None:
            file_refs = file_refs[: args.max_files]

        total = len(file_refs)
        print(f"Testing SingleFileFS concurrent mounts for {total} file(s)...")

        for idx, file_ref in enumerate(file_refs, start=1):
            start = perf_counter()
            ok = False
            detail = ""
            info = None

            try:
                info = mounts.mount_and_open(file_ref.id, open_in_app=False)
                if info is None:
                    detail = "mount_and_open returned None"
                else:
                    ok, detail = verify_mount(mounts, info, args.verify, args.timeout)
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"

            elapsed = perf_counter() - start

            if ok:
                opened += 1
                print(
                    f"[OK] {idx}/{total} ref={
                        file_ref.id} path={file_ref.virtual_path} "
                    f"active={mounts.active_mount_count} ({elapsed:.2f}s)"
                )
            else:
                print(
                    f"[FAIL] {idx}/{total} ref={
                        file_ref.id} path={file_ref.virtual_path} "
                    f"reason={detail} ({elapsed:.2f}s)"
                )
                if mounts.is_mounted(file_ref.id):
                    mounts.unmount(file_ref.id)

            attempts.append(
                Attempt(
                    ref_id=file_ref.id,
                    virtual_path=file_ref.virtual_path,
                    ok=ok,
                    detail=detail,
                    elapsed_seconds=elapsed,
                )
            )

            if not ok and not args.continue_on_failure:
                break

        failures = [attempt for attempt in attempts if not attempt.ok]
        print("\nResult")
        print(f"- Mounted simultaneously: {opened}")
        print(f"- Attempts run: {len(attempts)}")
        print(f"- Active mounts now: {mounts.active_mount_count}")

        if failures:
            first = failures[0]
            print(
                f"- First failure: ref={first.ref_id} path={first.virtual_path} "
                f"reason={first.detail}"
            )
        else:
            print("- Failures: none")

        if args.keep_mounted:
            print("- Cleanup: skipped (--keep-mounted)")

        return 0

    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    finally:
        if runtime_ready and not args.keep_mounted:
            try:
                service.cleanup()
            except Exception as cleanup_error:
                print(
                    f"Cleanup warning: {type(cleanup_error).__name__}: {cleanup_error}",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    raise SystemExit(main())
