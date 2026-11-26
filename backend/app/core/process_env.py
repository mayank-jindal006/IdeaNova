from __future__ import annotations

import os
import re

_SENSITIVE_NAME = re.compile(
    r"TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|CREDENTIAL|"
    r"DATABASE_(?:URL|URI)|CONNECTION_(?:STRING|URI)|_DSN|"
    r"PRIVATE_KEY|AUTHORIZATION|COOKIE|SESSION",
    re.IGNORECASE,
)
_PROXY_NAMES = {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}


def subprocess_environment(*, include_proxy: bool = False) -> dict[str, str]:
    """Return a child environment without application credentials or Git overrides."""
    environment: dict[str, str] = {}
    for name, value in os.environ.items():
        normalized = name.upper()
        if normalized.startswith("GIT_") or _SENSITIVE_NAME.search(normalized):
            continue
        if not include_proxy and normalized in _PROXY_NAMES:
            continue
        environment[name] = value
    return environment
