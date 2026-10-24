"""Tests for MergeReady command-line interface, formatting, and exit codes."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from merge_ready.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_cli_help(capsys):
    """Verify --help exits cleanly and displays usage."""
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "merge-ready" in captured.out
    assert "check" in captured.out


def test_cli_version(capsys):
    """Verify --version displays version."""
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "merge-ready 0.1.0" in captured.out


def test_cli_good_tool_terminal(capsys):
    """Verify clean fixture exits 0 with terminal output."""
    good_dir = str(FIXTURES_DIR / "good-tool")
    code = main(["check", good_dir])
    assert code == 0
    captured = capsys.readouterr()
    assert "MergeReady Contribution Validator" in captured.out
    assert "PASSED" in captured.out
    assert "0 fail" in captured.out


def test_cli_good_tool_json(capsys):
    """Verify JSON format outputs strictly valid parseable JSON."""
    good_dir = str(FIXTURES_DIR / "good-tool")
    code = main(["check", good_dir, "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["slug"] == "good-tool"
    assert data["summary"]["fail"] == 0
    assert "results" in data


def test_cli_good_tool_markdown(capsys):
    """Verify Markdown format produces GitHub-compatible report."""
    good_dir = str(FIXTURES_DIR / "good-tool")
    code = main(["check", good_dir, "--format", "markdown"])
    assert code == 0
    captured = capsys.readouterr()
    assert "# MergeReady Validation Report" in captured.out
    assert "### Verdict:" in captured.out


def test_cli_bad_agent_exit_code(capsys):
    """Verify defective fixture returns exit code 1."""
    bad_dir = str(FIXTURES_DIR / "bad-agent")
    code = main(["check", bad_dir])
    assert code == 1
    captured = capsys.readouterr()
    assert "FAILED" in captured.out


def test_cli_strict_mode():
    """Verify --strict fails when warnings exist."""
    bad_dir = str(FIXTURES_DIR / "bad-agent")
    code = main(["check", bad_dir, "--strict"])
    assert code == 1


def test_cli_output_file(tmp_path: Path):
    """Verify --output writes report to destination file."""
    good_dir = str(FIXTURES_DIR / "good-tool")
    out_file = tmp_path / "report.json"
    code = main(["check", good_dir, "--format", "json", "--output", str(out_file)])
    assert code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["summary"]["fail"] == 0


def test_cli_invalid_path():
    """Verify non-existent project directory returns exit code 2."""
    code = main(["check", "non_existent_folder_xyz_123"])
    assert code == 2
