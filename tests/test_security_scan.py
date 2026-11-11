from pathlib import Path

from scripts.security_scan import Finding, severity_counts, translated_severity


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
