from typer.testing import CliRunner

from periscope.cli import app

runner = CliRunner()


def test_profile():
    result = runner.invoke(app, ["profile", "nginx"])
    assert result.exit_code == 0
    assert "Would profile image=nginx for 60s" in result.output


def test_profile_with_duration():
    result = runner.invoke(app, ["profile", "nginx", "-d", "30"])
    assert result.exit_code == 0
    assert "Would profile image=nginx for 30s" in result.output
