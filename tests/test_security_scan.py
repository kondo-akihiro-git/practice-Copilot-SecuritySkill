import subprocess
from pathlib import Path

from scripts import security_scan
from scripts.security_scan import (
    Finding,
    advisory_link_candidates,
    django_check,
    render_report,
    scan_pip_audit,
    scan_secrets,
    severity_counts,
    translated_severity,
)


def test_translated_severity_uses_japanese_labels() -> None:
    assert translated_severity("critical") == "緊急"
    assert translated_severity("moderate") == "中"
    assert translated_severity("unknown") == "警告"


def test_severity_counts_includes_empty_categories() -> None:
    counts = severity_counts([Finding(severity="高", title="test", tool="test")])
    assert counts["高"] == 1
    assert counts["緊急"] == 0


def test_scannable_excludes_dependency_directories(tmp_path: Path) -> None:
    from scripts.security_scan import is_scannable

    assert is_scannable(Path("app/views.py"))
    assert not is_scannable(Path("node_modules/library/index.js"))


def test_advisory_link_candidates_only_allow_known_identifier_schemes() -> None:
    links = advisory_link_candidates(["CVE-2025-13473", "GHSA-2mcm-79hx-8fxw", "PYSEC-2026-42", "unknown"])
    assert links == (
        ("CVE-2025-13473", "https://osv.dev/vulnerability/CVE-2025-13473"),
        ("GHSA-2mcm-79hx-8fxw", "https://github.com/advisories/GHSA-2mcm-79hx-8fxw"),
        ("PYSEC-2026-42", "https://osv.dev/vulnerability/PYSEC-2026-42"),
    )


def test_secret_scan_includes_text_configuration_files(tmp_path: Path) -> None:
    config = tmp_path / "settings.yaml"
    config.write_text(f"access_key: {'AKIA' + '1234567890ABCDEF'}\n", encoding="utf-8")

    findings, check = scan_secrets(tmp_path, [config])

    assert check.status == "完了"
    assert findings[0].path == "settings.yaml"


def test_unmapped_pyproject_is_reported_as_unexecuted(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'example'\ndependencies = ['Django==5.2.10']\n",
        encoding="utf-8",
    )

    _, checks = scan_pip_audit(tmp_path, enabled=True)

    assert any(check.status == "未実施" for check in checks)


def test_django_check_error_is_not_treated_as_warning(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "manage.py").touch()
    monkeypatch.setattr(
        security_scan,
        "run_command",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Traceback: settings import failed"
        ),
    )

    _, check = django_check(tmp_path, enabled=True)

    assert check.status == "失敗"


def test_report_escapes_untrusted_markdown() -> None:
    report = render_report(
        Path("."),
        [],
        [Finding(
            severity="高",
            title="# 偽の見出し",
            tool="test",
            evidence="```\n[危険](https://example.invalid)",
        )],
        [],
        "full",
    )

    assert "### 1. [高] \\# 偽の見出し" in report
    assert "``\\`" in report
