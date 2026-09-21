"""
Forensic Metadata Extractor Module.

Handles the extraction of MAC (Modified, Accessed, Created/Changed) timestamps,
file sizes, and cryptographic hashes from all files within a target directory.
Implements robust error handling for permission-denied and broken-symlink
scenarios commonly encountered during live Linux forensic scans.
"""

import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from chronosight.ui import console, print_error, print_warning

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Buffer size for incremental hashing — 64 KiB balances memory and I/O speed.
_HASH_BUF_SIZE = 65_536

# Maximum file size (in bytes) that we will hash.  Files larger than this
# threshold are skipped to avoid stalling on multi-gigabyte disk images.
MAX_HASHABLE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GiB


# ---------------------------------------------------------------------------
# Helper: Compute Cryptographic Hashes
# ---------------------------------------------------------------------------

def compute_hashes(filepath: Path) -> dict[str, str]:
    """
    Compute MD5 and SHA-256 digests for *filepath*.

    Reads the file in 64 KiB chunks so that even large files do not require
    loading the entire content into memory.  Files exceeding
    ``MAX_HASHABLE_SIZE`` are skipped and return ``"SKIPPED_TOO_LARGE"``.

    Args:
        filepath: Absolute or relative path to the target file.

    Returns:
        A dict with keys ``"md5"`` and ``"sha256"`` containing hex-digest
        strings, or placeholder values on error.

    Forensic Note:
        MD5 is included for backward-compatibility with legacy evidence
        databases.  SHA-256 is the primary integrity digest.
    """
    try:
        file_size = filepath.stat().st_size
        if file_size > MAX_HASHABLE_SIZE:
            return {"md5": "SKIPPED_TOO_LARGE", "sha256": "SKIPPED_TOO_LARGE"}

        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        with open(filepath, "rb") as fh:
            while chunk := fh.read(_HASH_BUF_SIZE):
                md5.update(chunk)
                sha256.update(chunk)

        return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}

    except PermissionError:
        return {"md5": "PERMISSION_DENIED", "sha256": "PERMISSION_DENIED"}
    except OSError as exc:
        return {"md5": f"ERROR: {exc}", "sha256": f"ERROR: {exc}"}


# ---------------------------------------------------------------------------
# Helper: Extract MAC Timestamps
# ---------------------------------------------------------------------------

def _epoch_to_iso(epoch: float) -> str:
    """Convert a Unix epoch timestamp to an ISO-8601 UTC string."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def extract_mac_times(filepath: Path) -> dict[str, str]:
    """
    Extract Modified, Accessed, and Created/Changed timestamps for a file.

    On Linux, ``st_ctime`` represents the *inode change time* (metadata
    change), not the true creation time.  True birth time (``st_birthtime``)
    is only available on certain filesystems (ext4 with kernel ≥ 4.11,
    Btrfs, XFS).  We attempt ``st_birthtime`` first and fall back to
    ``st_ctime``.

    Args:
        filepath: Path to the target file.

    Returns:
        Dictionary with keys ``modified``, ``accessed``, ``created`` (ISO-8601).
    """
    st = filepath.stat()
    modified = _epoch_to_iso(st.st_mtime)
    accessed = _epoch_to_iso(st.st_atime)

    # Attempt true birth time; fall back to ctime (inode change time).
    birth = getattr(st, "st_birthtime", None)
    created = _epoch_to_iso(birth) if birth else _epoch_to_iso(st.st_ctime)

    return {"modified": modified, "accessed": accessed, "created": created}


# ---------------------------------------------------------------------------
# Helper: Determine File Type Category
# ---------------------------------------------------------------------------

def _file_type(filepath: Path) -> str:
    """Return a human-readable file-type label based on the stat mode bits."""
    try:
        mode = filepath.lstat().st_mode
    except OSError:
        return "unknown"

    if stat.S_ISREG(mode):
        return "regular"
    elif stat.S_ISDIR(mode):
        return "directory"
    elif stat.S_ISLNK(mode):
        return "symlink"
    elif stat.S_ISFIFO(mode):
        return "fifo"
    elif stat.S_ISSOCK(mode):
        return "socket"
    elif stat.S_ISBLK(mode):
        return "block_device"
    elif stat.S_ISCHR(mode):
        return "char_device"
    return "unknown"


# ---------------------------------------------------------------------------
# Core: Scan a Directory Tree
# ---------------------------------------------------------------------------

def scan_directory(target: Path) -> list[dict[str, Any]]:
    """
    Recursively walk *target* and extract forensic metadata for every file.

    For each regular file the function records:
      - Absolute path
      - File size in bytes
      - File type (regular, symlink, …)
      - MAC timestamps (Modified / Accessed / Created)
      - MD5 and SHA-256 hashes

    Symbolic links are recorded but **not** followed to prevent infinite
    loops and to preserve evidence of potential symlink-based attacks.

    Args:
        target: Root directory to scan.

    Returns:
        A list of artifact dictionaries, one per file.

    Raises:
        SystemExit: If *target* does not exist or is not a directory.
    """
    if not target.exists():
        print_error(f"Target path does not exist: {target}")
        raise SystemExit(1)
    if not target.is_dir():
        print_error(f"Target path is not a directory: {target}")
        raise SystemExit(1)

    # First pass: count files for the progress bar.
    file_list: list[Path] = []
    for root, _dirs, files in os.walk(target, followlinks=False):
        for fname in files:
            file_list.append(Path(root) / fname)

    artifacts: list[dict[str, Any]] = []
    skipped = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]Extracting"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("scan", total=len(file_list))

        for filepath in file_list:
            progress.advance(task)

            # Skip broken symlinks — their metadata is inaccessible.
            if filepath.is_symlink() and not filepath.exists():
                skipped += 1
                continue

            try:
                st = filepath.stat()
            except PermissionError:
                print_warning(f"Permission denied: {filepath}")
                skipped += 1
                continue
            except OSError as exc:
                print_warning(f"OS error on {filepath}: {exc}")
                skipped += 1
                continue

            artifact: dict[str, Any] = {
                "path": str(filepath.resolve()),
                "size_bytes": st.st_size,
                "type": _file_type(filepath),
                "timestamps": extract_mac_times(filepath),
                "hashes": compute_hashes(filepath),
            }
            artifacts.append(artifact)

    if skipped:
        print_warning(f"Skipped {skipped} file(s) due to errors or broken symlinks.")

    return artifacts
