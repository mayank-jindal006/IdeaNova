from __future__ import annotations

import os
from pathlib import Path

from app.core.config import settings


class ScanRootError(RuntimeError):
    """The trusted scan root is missing or unusable."""


class ScanPathError(ValueError):
    """A checkout is not a valid path within the trusted scan root."""


def require_scan_root() -> Path:
    if settings.scan_root is None:
        raise ScanRootError("Trusted scan root is not configured")
    try:
        root = settings.scan_root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ScanRootError("Trusted scan root is unavailable") from None
    if not root.is_dir():
        raise ScanRootError("Trusted scan root is unavailable")
    return root


def validate_scan_path(repo_path: str | Path) -> Path:
    root = require_scan_root()
    try:
        checkout = Path(repo_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError):
        raise ScanPathError("Repository checkout is unavailable") from None
    if not checkout.is_dir():
        raise ScanPathError("Repository checkout is unavailable")
    if checkout == root or not checkout.is_relative_to(root):
        raise ScanPathError("Repository checkout is outside the trusted scan root")

    def raise_walk_error(_: OSError) -> None:
        raise ScanPathError("Repository checkout could not be validated") from None

    try:
        for current, directories, filenames in os.walk(checkout, followlinks=False, onerror=raise_walk_error):
            current_path = Path(current)
            for name in (*directories, *filenames):
                entry = current_path / name
                if (entry.is_symlink() or entry.is_junction()) and not entry.resolve(strict=False).is_relative_to(checkout):
                    raise ScanPathError("Repository checkout contains an unsafe symbolic link")
    except (OSError, RuntimeError):
        raise ScanPathError("Repository checkout could not be validated") from None
    return checkout
