"""Hashing helpers used for evidence acquisition and re-verification."""
from __future__ import annotations

import hashlib
from pathlib import Path


def compute_hashes(data: bytes) -> dict:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),  # noqa: S324 - forensic reference value only
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - forensic reference value only
    }


def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(chunk):
            h.update(block)
    return h.hexdigest()


def verify_file(path: Path, expected_sha256: str) -> tuple[bool, str]:
    """Return (matches, actual_sha256 or reason)."""
    path = Path(path)
    if not path.exists():
        return False, "MISSING"
    actual = sha256_file(path)
    return actual == expected_sha256, actual
