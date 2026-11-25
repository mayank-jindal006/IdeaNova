from dataclasses import replace

import pytest

import app.core.scan_paths as scan_paths
from app.core.config import settings
from app.core.scan_paths import ScanPathError, ScanRootError, require_scan_root, validate_scan_path


def _set_root(monkeypatch, root):
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(scan_paths, "settings", replace(settings, scan_root=root))


def test_valid_checkout_is_canonicalized_inside_trusted_root(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    checkout = root / "owner" / "repo"
    checkout.mkdir(parents=True)
    subdir = checkout / "subdir"
    subdir.mkdir()
    _set_root(monkeypatch, root)

    assert validate_scan_path(subdir / "..") == checkout.resolve()


def test_checkout_outside_trusted_root_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    checkout = tmp_path / "outside" / "repo"
    checkout.mkdir(parents=True)
    _set_root(monkeypatch, root)

    with pytest.raises(ScanPathError):
        validate_scan_path(checkout)


def test_path_traversal_outside_trusted_root_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    checkout = root / "owner" / "repo"
    checkout.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    _set_root(monkeypatch, root)

    with pytest.raises(ScanPathError):
        validate_scan_path(checkout / ".." / ".." / ".." / "outside")


def test_symlink_escape_in_checkout_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    checkout = root / "owner" / "repo"
    checkout.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    _set_root(monkeypatch, root)
    try:
        (checkout / "external").symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Directory symlinks are unavailable: {exc}")

    with pytest.raises(ScanPathError):
        validate_scan_path(checkout)


def test_symlinked_checkout_cannot_resolve_outside_root(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _set_root(monkeypatch, root)
    try:
        (root / "repo-link").symlink_to(outside, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Directory symlinks are unavailable: {exc}")

    with pytest.raises(ScanPathError):
        validate_scan_path(root / "repo-link")


def test_missing_scan_root_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_paths, "settings", replace(settings, scan_root=None))

    with pytest.raises(ScanRootError):
        require_scan_root()


def test_unavailable_scan_root_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(scan_paths, "settings", replace(settings, scan_root=tmp_path / "missing"))

    with pytest.raises(ScanRootError):
        require_scan_root()
