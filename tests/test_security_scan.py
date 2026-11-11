from pathlib import Path

from scripts.security_scan import Finding, advisory_links, severity_counts, translated_severity


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


def test_advisory_links_only_known_verified_identifier_schemes() -> None:
    links = advisory_links(["CVE-2025-13473", "GHSA-2mcm-79hx-8fxw", "PYSEC-2026-42", "unknown"])
    assert links == (
        ("CVE-2025-13473", "https://osv.dev/vulnerability/CVE-2025-13473"),
        ("GHSA-2mcm-79hx-8fxw", "https://github.com/advisories/GHSA-2mcm-79hx-8fxw"),
        ("PYSEC-2026-42", "https://osv.dev/vulnerability/PYSEC-2026-42"),
    )
