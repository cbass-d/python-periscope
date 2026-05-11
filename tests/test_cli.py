from pathlib import Path

from typer.testing import CliRunner

from periscope.cli import app

runner = CliRunner()


def test_profile_rejects_strict_without_policy() -> None:
    result = runner.invoke(app, ["profile", "img", "wlan0", "--strict"])
    assert result.exit_code == 1
    assert "--strict requires --policy" in result.output


def test_profile_rejects_malformed_policy(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("[dns\nallowed = []\n")
    result = runner.invoke(app, ["profile", "img", "wlan0", "--policy", str(bad)])
    assert result.exit_code == 1
    assert "invalid TOML" in result.output
