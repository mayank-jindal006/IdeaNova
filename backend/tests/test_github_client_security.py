from dataclasses import replace
from pathlib import Path
import subprocess

import pytest

from app.core import scan_paths
from app.core.config import settings as scan_settings
from app.github_client import client
from app.settings import settings as runtime_settings
from app.services import gitleaks


def test_clone_uses_process_scoped_credentials_without_persisting_them(tmp_path, monkeypatch, caplog):
    root = tmp_path / "trusted"
    root.mkdir()
    token = "github-token-used-only-by-test-child-process"
    monkeypatch.setattr(scan_paths, "settings", replace(scan_settings, scan_root=root))
    monkeypatch.setattr(client, "settings", replace(runtime_settings, github_token=token))
    monkeypatch.setenv("GIT_TRACE", "1")
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://user:db-password@localhost/test")
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-inherited-github-token")
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "synthetic-webhook-secret")
    monkeypatch.setenv("LLM_API_KEY", "synthetic-llm-api-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy-user:proxy-password@proxy.test:8080")
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []

    def fake_run(command, **kwargs):
        commands.append(list(command))
        environments.append(kwargs.get("env"))
        if command[1] == "clone":
            checkout = Path(command[-1])
            (checkout / ".git").mkdir()
            (checkout / ".git" / "config").write_text(
                '[remote "origin"]\n\turl = https://github.com/owner/repo.git\n',
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(client.subprocess, "run", fake_run)

    checkout = Path(client.clone_repo("owner/repo", "a" * 40, "refs/heads/feature/security"))

    assert checkout.is_relative_to(root.resolve())
    assert len(commands) == 4
    assert all(token not in " ".join(command) for command in commands)
    assert all(environment["REPOGUARD_GIT_TOKEN"] == token for environment in environments[:2])
    assert all("GIT_TRACE" not in environment for environment in environments[:2])
    assert all("HTTPS_PROXY" in environment for environment in environments[:2])
    assert all("HTTPS_PROXY" not in environment for environment in environments[2:])
    assert all(
        not {"DATABASE_URL", "GITHUB_TOKEN", "GITHUB_WEBHOOK_SECRET", "LLM_API_KEY"}.intersection(environment)
        for environment in environments
    )
    assert all("GIT_TRACE" not in environment for environment in environments[2:])
    assert all("REPOGUARD_GIT_TOKEN" not in environment for environment in environments[2:])
    assert all(token not in value for value in environments[0].values() if value != token)
    assert all(token not in record.getMessage() for record in caplog.records)
    git_config = (checkout / ".git" / "config").read_text(encoding="utf-8")
    assert token not in git_config
    assert "credential.helper" not in git_config
    assert "https://github.com/owner/repo.git" in git_config
    assert list(root.iterdir()) == [checkout]


def test_gitleaks_subprocess_does_not_inherit_application_secrets(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    checkout = root / "empty-repository"
    checkout.mkdir(parents=True)
    monkeypatch.setattr(scan_paths, "settings", replace(scan_settings, scan_root=root))
    injected_values = {
        name: f"synthetic-{name.lower()}"
        for name in ("DATABASE_URL", "GITHUB_TOKEN", "GITHUB_WEBHOOK_SECRET", "LLM_API_KEY")
    }
    for name, value in injected_values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy-user:proxy-password@proxy.test:8080")
    monkeypatch.setattr(gitleaks, "_discover_gitleaks_binary", lambda: ("gitleaks", None))
    captured: dict[str, str] = {}

    def fake_run(command, **kwargs):
        captured.update(kwargs["env"])
        report_path = Path(command[command.index("--report-path") + 1])
        report_path.write_text("[]", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(gitleaks.subprocess, "run", fake_run)

    result = gitleaks.scan_repository_secrets(checkout)

    assert result.status == "empty"
    assert result.source == "gitleaks"
    assert not {
        "DATABASE_URL",
        "GITHUB_TOKEN",
        "GITHUB_WEBHOOK_SECRET",
        "LLM_API_KEY",
        "HTTPS_PROXY",
    }.intersection(captured)
    assert not any(
        secret in value
        for secret in injected_values.values()
        for value in captured.values()
    )
    assert not any("proxy-password" in value for value in captured.values())


def test_git_credential_helper_supplies_token_only_to_git_credential_lookup():
    token = "github-token-used-only-by-test-child-process"
    environment = client._git_auth_environment(token)

    result = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True,
        check=True,
        text=True,
        env=environment,
    )

    credentials = dict(line.split("=", 1) for line in result.stdout.splitlines())
    assert credentials == {"protocol": "https", "host": "github.com", "username": "x-access-token", "password": token}


def test_clone_failure_removes_checkout_and_does_not_expose_token(tmp_path, monkeypatch, caplog):
    root = tmp_path / "trusted"
    root.mkdir()
    token = "github-token-used-only-by-test-child-process"
    monkeypatch.setattr(scan_paths, "settings", replace(scan_settings, scan_root=root))
    monkeypatch.setattr(client, "settings", replace(runtime_settings, github_token=token))

    def fail_clone(command, **kwargs):
        if command[1] == "clone":
            raise subprocess.CalledProcessError(
                128,
                command,
                output=f"clone failed: {token}",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(client.subprocess, "run", fail_clone)

    with pytest.raises(RuntimeError, match="Repository checkout failed") as error:
        client.clone_repo("owner/repo")

    assert token not in str(error.value)
    assert all(token not in record.getMessage() for record in caplog.records)
    assert list(root.iterdir()) == []


def test_clone_rejects_invalid_commit_or_ref_before_creating_checkout(tmp_path, monkeypatch):
    root = tmp_path / "trusted"
    root.mkdir()
    monkeypatch.setattr(scan_paths, "settings", replace(scan_settings, scan_root=root))
    monkeypatch.setattr(client, "settings", replace(runtime_settings, github_token="test-token"))

    for commit_sha, ref in (
        ("not-a-sha", "refs/heads/main"),
        ("a" * 40, "refs/tags/v1"),
        ("a" * 40, "refs/heads/../outside"),
    ):
        try:
            client.clone_repo("owner/repo", commit_sha, ref)
        except ValueError:
            pass
        else:
            raise AssertionError("Invalid commit or ref was accepted")

    assert list(root.iterdir()) == []
