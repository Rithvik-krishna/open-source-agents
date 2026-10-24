"""Comprehensive unit tests for MergeReady checks and rules."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import pytest

from merge_ready.checks import run_all_checks
from merge_ready.checks.agent_safety import decode_tag_chars, scan_unicode
from merge_ready.checks.deps import IMPORT_ALIAS_MAP, normalize_package_name
from merge_ready.checks.layout import check_l02
from merge_ready.checks.secrets import is_placeholder, redact_secret, shannon_entropy
from merge_ready.model import Severity, Verdict
from merge_ready.project import ProjectContext

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_good_tool_passes_all_checks():
    """Verify that the golden good-tool fixture produces zero failures and passes."""
    ctx = ProjectContext(project_path=FIXTURES_DIR / "good-tool")
    report = run_all_checks(ctx)

    assert not report.has_failures, f"Good tool failed unexpectedly: {report.to_dict()}"
    assert report.summary["fail"] == 0
    assert report.summary["errors"] == 0
    # Must pass core layout, files, template, and safety rules
    assert report.results["L01"].verdict == Verdict.PASS
    assert report.results["L02"].verdict == Verdict.PASS
    assert report.results["F01"].verdict == Verdict.PASS
    assert report.results["D01"].verdict == Verdict.PASS
    assert report.results["S01"].verdict == Verdict.PASS
    assert report.results["S02"].verdict == Verdict.PASS
    assert report.results["A02"].verdict == Verdict.PASS


def test_bad_agent_triggers_expected_rules():
    """Verify that defective fixture triggers expected failures and warnings."""
    ctx = ProjectContext(project_path=FIXTURES_DIR / "bad-agent")
    report = run_all_checks(ctx)

    assert report.has_failures, "Bad agent should have failed validation"
    # D01: Template residue
    assert report.results["D01"].verdict == Verdict.FAIL
    assert any("[Project Name]" in f.evidence for f in report.results["D01"].findings)

    # S01: Secret exposure
    assert report.results["S01"].verdict == Verdict.FAIL
    bad_key = "AIza" + "SyD9a8b7c6d5e4f3g2h1j0k9l8m7n6b5v4c"
    for f in report.results["S01"].findings:
        assert bad_key not in (f.evidence or "")
    assert any("[REDACTED]" in (f.evidence or "") for f in report.results["S01"].findings)

    # S02: Local database tracked/present
    assert report.results["S02"].verdict == Verdict.FAIL
    assert any(".sqlite" in f.path for f in report.results["S02"].findings)

    # E01: Undocumented env var
    assert report.results["E01"].verdict == Verdict.FAIL
    assert any("SECRET_BACKDOOR_KEY" in f.message for f in report.results["E01"].findings)

    # R01: Missing manifest dependency (yaml)
    assert report.results["R01"].verdict == Verdict.WARN
    assert any("yaml" in f.message or "pyyaml" in f.message for f in report.results["R01"].findings)

    # A01: Unbounded execution loop
    assert report.results["A01"].verdict == Verdict.WARN
    assert any("unbounded" in f.message.lower() for f in report.results["A01"].findings)

    # A02: Hidden Unicode
    assert report.results["A02"].verdict == Verdict.FAIL
    assert any("Bidirectional override" in f.message or "tag character" in f.message for f in report.results["A02"].findings)

    # A03: High-impact subprocess execution
    assert report.results["A03"].verdict == Verdict.WARN
    assert any("subprocess" in f.message for f in report.results["A03"].findings)


def test_invalid_project_name_l02(tmp_path: Path):
    """L02: Test kebab-case and generic name blocklist."""
    # 1. Uppercase / spaces
    bad_dir = tmp_path / "My Agent"
    bad_dir.mkdir()
    ctx1 = ProjectContext(project_path=bad_dir)
    res1 = check_l02(ctx1, {})
    assert res1.verdict == Verdict.FAIL
    assert any("kebab-case" in f.message for f in res1.findings)

    # 2. Generic name
    generic_dir = tmp_path / "my-agent"
    generic_dir.mkdir()
    ctx2 = ProjectContext(project_path=generic_dir)
    res2 = check_l02(ctx2, {})
    assert res2.verdict == Verdict.FAIL
    assert any("generic" in f.message for f in res2.findings)


def test_missing_required_files_f01(tmp_path: Path):
    """F01: Missing required files produce explicit errors."""
    empty_proj = tmp_path / "empty-tool"
    empty_proj.mkdir()
    ctx = ProjectContext(project_path=empty_proj)
    report = run_all_checks(ctx)

    assert report.results["F01"].verdict == Verdict.FAIL
    missing_msgs = [f.message for f in report.results["F01"].findings]
    assert any("README.md" in m for m in missing_msgs)
    assert any(".env.example" in m for m in missing_msgs)
    assert any(".gitignore" in m for m in missing_msgs)
    assert any("manifest" in m for m in missing_msgs)


def test_secrets_redaction_and_entropy_negative_controls():
    """S01: Test negative controls (UUID, Git SHA, placeholders) and redaction."""
    # Redaction
    raw_secret = "AIza" + "SyD12345678901234567890123456789"
    redacted = redact_secret(raw_secret)
    assert raw_secret not in redacted
    assert "[REDACTED]" in redacted

    # Placeholders
    assert is_placeholder("your_api_key_here")
    assert is_placeholder("<your-token>")
    assert is_placeholder("DUMMY_KEY_VALUE")
    assert not is_placeholder("ghp_" + "123456789012345678901234567890123456")

    # Shannon entropy computation
    low_ent = shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    high_ent = shannon_entropy("w9Xz+7bM/Q2eR4tY1uI8")
    assert low_ent < 1.0
    assert high_ent > 4.0


def test_hidden_unicode_and_tag_decoding():
    """A02: Test bidi characters, hidden tags, and tag payload decoding."""
    # Legitimate emoji with ZWJ (U+200D) should not trigger ERROR
    emoji_text = "Hello 👩‍💻 world!"
    findings = scan_unicode(emoji_text)
    error_findings = [f for f in findings if f[0] == Severity.ERROR]
    assert len(error_findings) == 0

    # Tag characters for 'P', 'W', 'N'
    tag_pwn = "\U000E0050\U000E0057\U000E004E"
    decoded = decode_tag_chars(tag_pwn)
    assert decoded == "PWN"

    # Scan detects tag chars as ERROR
    findings_tag = scan_unicode(tag_pwn)
    assert any(f[0] == Severity.ERROR and "tag" in f[4].lower() for f in findings_tag)

    # Bidi override detected
    bidi_str = "Code with \u202E override"
    findings_bidi = scan_unicode(bidi_str)
    assert any(f[0] == Severity.ERROR and "bidirectional" in f[4].lower() for f in findings_bidi)


def test_dependency_manifest_alias_normalization():
    """R01: Verify normalization and package alias mapping."""
    assert normalize_package_name("PyYAML") == "pyyaml"
    assert normalize_package_name("google_genai") == "google-genai"
    assert normalize_package_name("google.adk") == "google-adk"
    assert IMPORT_ALIAS_MAP["google.genai"] == "google-genai"
    assert IMPORT_ALIAS_MAP["yaml"] == "pyyaml"
    assert IMPORT_ALIAS_MAP["PIL"] == "pillow"


def test_scope_diff_validation_with_git(tmp_path: Path):
    """P01 & I01: Verify diff scope using a temporary Git repository."""
    repo = tmp_path / "test-repo"
    repo.mkdir()

    # 1. Initialize git repo
    subprocess.run(["git", "init"], cwd=str(repo), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=str(repo), check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=str(repo), check=True)

    # Create root files & base branch
    (repo / "tools").mkdir()
    (repo / "tools" / "README.md").write_text("# Tools\n| Tool | Description |\n| :--- | :--- |\n| *(None yet)* | — |\n")
    (repo / "CONTRIBUTING.md").write_text("Contributing guidelines")
    (repo / "template").mkdir()
    (repo / "template" / "README.md").write_text("# [Project Name]\n## Overview\n## License\n")
    (repo / "template" / ".env.example").write_text("# API_KEY=xxx\n")
    (repo / "template" / ".gitignore").write_text(".venv/\n")

    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "Initial upstream commit"], cwd=str(repo), check=True)
    subprocess.run(["git", "branch", "-M", "main"], cwd=str(repo), check=True)

    # 2. Create feature branch and add valid tool
    subprocess.run(["git", "checkout", "-b", "feat/my-clean-tool"], cwd=str(repo), check=True)
    my_tool = repo / "tools" / "my-clean-tool"
    my_tool.mkdir()
    (my_tool / "README.md").write_text("# My Clean Tool\n## Overview\nClean tool.\n## License\nMIT\n")
    (my_tool / ".env.example").write_text("# API_KEY=xxx\n")
    (my_tool / ".gitignore").write_text(".venv/\n")
    (my_tool / "requirements.txt").write_text("pytest\n")

    # Update index table by replacing None yet row
    (repo / "tools" / "README.md").write_text("# Tools\n| Tool | Description |\n| :--- | :--- |\n| [my-clean-tool](my-clean-tool/) | Clean utility |\n")

    subprocess.run(["git", "add", "."], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "feat: add my-clean-tool"], cwd=str(repo), check=True)

    # Validate with base=main
    ctx = ProjectContext(project_path=my_tool, base_ref="main")
    report = run_all_checks(ctx)
    assert report.results["P01"].verdict == Verdict.PASS
    assert report.results["I01"].verdict == Verdict.PASS

    # 3. Corrupt scope: modify root CONTRIBUTING.md
    (repo / "CONTRIBUTING.md").write_text("Modified root guidelines out of scope")
    subprocess.run(["git", "add", "CONTRIBUTING.md"], cwd=str(repo), check=True)
    subprocess.run(["git", "commit", "-m", "corrupt scope"], cwd=str(repo), check=True)

    ctx_bad = ProjectContext(project_path=my_tool, base_ref="main")
    report_bad = run_all_checks(ctx_bad)
    assert report_bad.results["P01"].verdict == Verdict.FAIL
    assert any("CONTRIBUTING.md" in f.path for f in report_bad.results["P01"].findings)
