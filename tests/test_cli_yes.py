"""The --yes flag makes destructive commands non-interactive (scriptable)."""
from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from ssh_manager.cli import app

runner = CliRunner()


def _cfg(env: dict[str, Path], monkeypatch) -> None:
    monkeypatch.setenv("SSH_MANAGER_CONFIG_DIR", str(env["config_dir"]))


def test_host_delete_yes_is_noninteractive(env, monkeypatch) -> None:
    _cfg(env, monkeypatch)
    assert runner.invoke(app, ["profile", "add", "tp"]).exit_code == 0
    assert runner.invoke(
        app, ["host", "add", "tp", "web1", "--hostname", "1.2.3.4", "--user", "d"]
    ).exit_code == 0
    # no stdin supplied -> would hit EOF on a prompt; --yes must skip both prompts
    r = runner.invoke(app, ["host", "delete", "tp", "web1", "--yes"], input="")
    assert r.exit_code == 0
    assert "web1" not in runner.invoke(app, ["list"]).stdout


def test_profile_delete_yes_is_noninteractive(env, monkeypatch) -> None:
    _cfg(env, monkeypatch)
    runner.invoke(app, ["profile", "add", "tp2"])
    r = runner.invoke(app, ["profile", "delete", "tp2", "--yes"], input="")
    assert r.exit_code == 0
    assert "tp2" not in runner.invoke(app, ["list"]).stdout


def test_delete_without_yes_still_prompts(env, monkeypatch) -> None:
    _cfg(env, monkeypatch)
    runner.invoke(app, ["profile", "add", "tp3"])
    # answering 'n' to the first prompt aborts (non-zero), profile stays
    r = runner.invoke(app, ["profile", "delete", "tp3"], input="n\n")
    assert r.exit_code != 0
    assert "tp3" in runner.invoke(app, ["list"]).stdout
