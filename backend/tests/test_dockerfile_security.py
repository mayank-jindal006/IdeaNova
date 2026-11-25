from pathlib import Path
import re


def test_dockerfile_uses_a_versioned_checksum_verified_gitleaks_release():
    dockerfile = Path(__file__).parents[1].joinpath("Dockerfile").read_text(encoding="utf-8")

    assert "ARG GITLEAKS_VERSION=8.30.1" in dockerfile
    assert "releases/download/v${GITLEAKS_VERSION}/${archive}" in dockerfile
    assert "sha256sum --check --status" in dockerfile
    assert "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb" in dockerfile
    assert "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080" in dockerfile
    assert not re.search(r"raw\.githubusercontent\.com/.+/(?:main|master)/", dockerfile)
    assert not re.search(r"curl[^\n]*\|\s*(?:sh|bash)", dockerfile)
