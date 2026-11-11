#!/usr/bin/env python3
"""Run layered, fail-closed security checks and render a Japanese Markdown report."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import re
import shutil
import subprocess  # nosec B404 - this scanner deliberately invokes fixed security tools without a shell.
import sys
from pathlib import Path
from typing import Iterable

SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".css"}
EXCLUDED_PARTS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    "coverage",
    "htmlcov",
    "tests",
}
DEPENDENCY_FILES = {
    "requirements.txt",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
}
SEVERITY_MAP = {
    "critical": "緊急",
    "high": "高",
    "error": "高",
    "warning": "中",
    "medium": "中",
    "moderate": "中",
    "low": "低",
    "info": "情報",
    "information": "情報",
}
SEVERITY_ORDER = {"情報": 0, "低": 1, "中": 2, "高": 3, "重大": 4, "緊急": 5}
SECRET_PATTERNS = (
    (re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "緊急", "秘密鍵らしき値"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "高", "AWS アクセスキーらしき値"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "高", "GitHub トークンらしき値"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "高", "GitHub fine-grained token らしき値"),
)


@dataclasses.dataclass
class Finding:
    severity: str
    title: str
    tool: str
    path: str = ""
    line: int | None = None
    evidence: str = ""
    recommendation: str = ""
    identifier: str = ""
    links: tuple[tuple[str, str], ...] = ()
    blocking: bool = False


@dataclasses.dataclass
class Check:
    name: str
    status: str
    detail: str


def tool_command(command: str) -> list[str] | None:
    """Prefer a tool installed beside the interpreter running this script."""
    local_tool = Path(sys.executable).parent / command
    if local_tool.is_file():
        return [str(local_tool)]
    if shutil.which(command):
        return [command]
    return None


def run_command(command: list[str], cwd: Path, timeout: int = 180) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(  # nosec B603 - commands are fixed tool names and argument lists; shell is never used.
            command, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def is_scannable(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_SUFFIXES and not any(part in EXCLUDED_PARTS for part in path.parts)


def all_source_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file() and is_scannable(path.relative_to(root)))


def staged_files(root: Path) -> list[Path]:
    result = run_command(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"], root, 30)
    if result is None or result.returncode != 0:
        return []
    return [root / line for line in result.stdout.splitlines() if line and (root / line).is_file()]


def parse_json(text: str) -> object | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def translated_severity(value: object, default: str = "警告") -> str:
    return SEVERITY_MAP.get(str(value).lower(), default)


def advisory_links(identifiers: Iterable[object]) -> tuple[tuple[str, str], ...]:
    """Create links only for advisory URL schemes verified by this project."""
    links: list[tuple[str, str]] = []
    seen: set[str] = set()
    for value in identifiers:
        identifier = str(value).strip()
        if identifier in seen:
            continue
        if re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier, flags=re.IGNORECASE):
            links.append((identifier, f"https://osv.dev/vulnerability/{identifier.upper()}"))
        elif re.fullmatch(r"GHSA-[\w-]+", identifier, flags=re.IGNORECASE):
            links.append((identifier, f"https://github.com/advisories/{identifier}"))
        elif re.fullmatch(r"PYSEC-\d{4}-\d+", identifier, flags=re.IGNORECASE):
            links.append((identifier, f"https://osv.dev/vulnerability/{identifier.upper()}"))
        else:
            continue
        seen.add(identifier)
    return tuple(links)


def rel(root: Path, path: Path | str) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def line_text(path: Path, line: int | None) -> str:
    if line is None:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()[line - 1].strip()
    except (OSError, IndexError):
        return ""


def scan_secrets(root: Path, files: Iterable[Path]) -> tuple[list[Finding], Check]:
    findings: list[Finding] = []
    for path in files:
        try:
            for number, content in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for pattern, severity, title in SECRET_PATTERNS:
                    if pattern.search(content):
                        findings.append(
                            Finding(
                                severity=severity,
                                title=title,
                                tool="組み込み秘密情報検査",
                                path=rel(root, path),
                                line=number,
                                evidence=content.strip()[:200],
                                recommendation="値を直ちに無効化・ローテーションし、環境変数または秘密情報管理へ移してください。",
                                blocking=True,
                            )
                        )
        except OSError:
            return findings, Check("組み込み秘密情報検査", "失敗", f"{rel(root, path)} を読み取れません。")
    return findings, Check("組み込み秘密情報検査", "完了", f"{len(list(files))} ファイルを確認しました。")


def scan_bandit(root: Path, files: list[Path]) -> tuple[list[Finding], Check]:
    python_files = [path for path in files if path.suffix == ".py"]
    if not python_files:
        return [], Check("Bandit", "対象外", "Python ファイルがありません。")
    command = tool_command("bandit")
    if command is None:
        return [], Check("Bandit", "未実施", "bandit が見つかりません。`pip install -e '.[scanner]'` を実行してください。")
    result = run_command([*command, "--format", "json", "--quiet", *map(str, python_files)], root)
    if result is None:
        return [], Check("Bandit", "失敗", "Bandit の起動または実行が失敗しました。")
    data = parse_json(result.stdout)
    if not isinstance(data, dict):
        return [], Check("Bandit", "失敗", "Bandit の JSON 結果を解釈できません。")
    findings = [
        Finding(
            severity=translated_severity(item.get("issue_severity"), "中"),
            title=str(item.get("issue_text", "Bandit が問題を検出しました。")),
            tool="Bandit",
            path=str(item.get("filename", "")),
            line=item.get("line_number"),
            evidence=str(item.get("code", "")).strip(),
            recommendation="Bandit のテスト ID と該当処理の入力経路を確認し、安全な API または検証を適用してください。",
            identifier=str(item.get("test_id", "")),
        )
        for item in data.get("results", [])
    ]
    return findings, Check("Bandit", "完了", f"{len(python_files)} Python ファイル、{len(findings)} 件。")


def scan_semgrep(root: Path, files: list[Path]) -> tuple[list[Finding], Check]:
    candidates = [path for path in files if is_scannable(path.relative_to(root))]
    if not candidates:
        return [], Check("Semgrep", "対象外", "対象言語のファイルがありません。")
    command = tool_command("semgrep")
    if command is None:
        return [], Check("Semgrep", "未実施", "semgrep が見つかりません。`pip install -e '.[scanner]'` を実行してください。")
    rules = root / ".github/skills/security-review/rules/security.yml"
    if not rules.is_file():
        return [], Check("Semgrep", "失敗", f"ルールがありません: {rel(root, rules)}")
    result = run_command([*command, "scan", "--config", str(rules), "--json", "--quiet", *map(str, candidates)], root)
    if result is None:
        return [], Check("Semgrep", "失敗", "Semgrep の起動または実行が失敗しました。")
    data = parse_json(result.stdout)
    if not isinstance(data, dict):
        return [], Check("Semgrep", "失敗", "Semgrep の JSON 結果を解釈できません。")
    errors = data.get("errors", [])
    if errors:
        return [], Check("Semgrep", "失敗", f"Semgrep が {len(errors)} 件の解析エラーを返しました。")
    findings = []
    for item in data.get("results", []):
        start = item.get("start", {})
        path = str(item.get("path", ""))
        findings.append(
            Finding(
                severity=translated_severity(item.get("extra", {}).get("severity"), "中"),
                title=str(item.get("extra", {}).get("message", "Semgrep が問題を検出しました。")),
                tool="Semgrep",
                path=path,
                line=start.get("line"),
                evidence=line_text(root / path, start.get("line")),
                recommendation="値の出所、到達可能性、エンコード・検証・権限確認を確認してください。",
                identifier=str(item.get("check_id", "")),
            )
        )
    return findings, Check("Semgrep", "完了", f"{len(candidates)} ファイル、{len(findings)} 件。")


def scan_pip_audit(root: Path, enabled: bool) -> tuple[list[Finding], list[Check]]:
    requirements = sorted(root.glob("requirements*.txt"))
    if not enabled:
        return [], [Check("pip-audit", "対象外", "依存関係ファイルは今回の変更に含まれません。")]
    if not requirements:
        return [], [Check("pip-audit", "対象外", "requirements*.txt がありません。")]
    command = tool_command("pip-audit")
    if command is None:
        return [], [Check("pip-audit", "未実施", "pip-audit が見つかりません。`pip install -e '.[scanner]'` を実行してください。")]
    findings: list[Finding] = []
    checks: list[Check] = []
    for requirement in requirements:
        result = run_command([*command, "--requirement", str(requirement), "--format", "json"], root, 300)
        data = parse_json(result.stdout if result else "")
        packages = data.get("dependencies") if isinstance(data, dict) else data
        if result is None or not isinstance(packages, list):
            checks.append(Check("pip-audit", "失敗", f"{rel(root, requirement)} の脆弱性 DB 照会または結果解析に失敗しました。"))
            continue
        count = 0
        for package in packages:
            for vulnerability in package.get("vulns", []):
                count += 1
                findings.append(
                    Finding(
                        severity="警告",
                        title=f"{package.get('name')} {package.get('version')} の既知脆弱性",
                        tool="pip-audit",
                        path=rel(root, requirement),
                        evidence=str(vulnerability.get("description", "")).replace("\n", " ")[:300],
                        recommendation="修正済みバージョンへ更新し、到達可能性と互換性を確認してください。",
                        identifier=str(vulnerability.get("id", "")),
                        links=advisory_links(
                            [vulnerability.get("id", ""), *vulnerability.get("aliases", [])]
                        ),
                        blocking=True,
                    )
                )
        checks.append(Check("pip-audit", "完了", f"{rel(root, requirement)}: {count} 件。"))
    return findings, checks


def scan_npm_audit(root: Path, enabled: bool) -> tuple[list[Finding], list[Check]]:
    lockfiles = sorted([*root.rglob("package-lock.json"), *root.rglob("npm-shrinkwrap.json")])
    lockfiles = [path for path in lockfiles if not any(part in EXCLUDED_PARTS for part in path.relative_to(root).parts)]
    if not enabled:
        return [], [Check("npm audit", "対象外", "JavaScript 依存関係ファイルは今回の変更に含まれません。")]
    if not lockfiles:
        return [], [Check("npm audit", "対象外", "package-lock.json または npm-shrinkwrap.json がありません。")]
    command = tool_command("npm")
    if command is None:
        return [], [Check("npm audit", "未実施", "npm が見つかりません。Node.js/npm を導入してください。")]
    findings: list[Finding] = []
    checks: list[Check] = []
    for lockfile in lockfiles:
        result = run_command([*command, "audit", "--json", "--package-lock-only"], lockfile.parent, 300)
        data = parse_json(result.stdout if result else "")
        if result is None or not isinstance(data, dict) or data.get("error"):
            checks.append(Check("npm audit", "失敗", f"{rel(root, lockfile)} の脆弱性 DB 照会または結果解析に失敗しました。"))
            continue
        vulnerabilities = data.get("vulnerabilities", {})
        for name, vulnerability in vulnerabilities.items():
            findings.append(
                Finding(
                    severity=translated_severity(vulnerability.get("severity"), "警告"),
                    title=f"{name} の既知脆弱性",
                    tool="npm audit",
                    path=rel(root, lockfile),
                    evidence=str(vulnerability.get("via", ""))[:300],
                    recommendation="`npm audit` の修正提案を確認し、互換性を検証して更新してください。",
                    blocking=True,
                )
            )
        checks.append(Check("npm audit", "完了", f"{rel(root, lockfile)}: {len(vulnerabilities)} 件。"))
    return findings, checks


def django_check(root: Path, enabled: bool) -> tuple[list[Finding], Check]:
    manage = root / "manage.py"
    if not manage.is_file():
        return [], Check("Django deploy check", "対象外", "manage.py がありません。")
    if not enabled:
        return [], Check("Django deploy check", "未実施", "`--django-check` が指定されていません。設定を実行できる安全な環境で実行してください。")
    result = run_command([sys.executable, "manage.py", "check", "--deploy", "--fail-level", "WARNING"], root, 180)
    if result is None:
        return [], Check("Django deploy check", "失敗", "Django deploy check を実行できません。")
    if result.returncode == 0:
        return [], Check("Django deploy check", "完了", "警告は検出されませんでした。")
    if result.returncode == 1:
        return [Finding(
            severity="中",
            title="Django デプロイ設定の警告",
            tool="Django deploy check",
            path="manage.py",
            evidence="詳細は `python manage.py check --deploy` の出力を確認してください。",
            recommendation="Django の deployment checklist に従い、設定警告を解消してください。",
        )], Check("Django deploy check", "完了", "設定警告を検出しました。")
    return [], Check("Django deploy check", "失敗", "Django の初期化またはチェック実行に失敗しました。")


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {name: 0 for name in ("緊急", "重大", "高", "中", "低", "情報", "警告")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def render_report(root: Path, files: list[Path], findings: list[Finding], checks: list[Check], mode: str) -> str:
    counts = severity_counts(findings)
    now = dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")
    lines = [
        "# セキュリティ検査結果",
        "",
        "## 検査概要",
        "",
        f"- 検査日時: {now}",
        f"- モード: {'コミット前（ステージ済みファイル）' if mode == 'pre-commit' else '全体検査'}",
        f"- 検査対象ファイル数: {len(files)}",
        "- 使用した検査: 組み込み秘密情報検査、Bandit、Semgrep、pip-audit、npm audit、Django deploy check",
        "",
        "## 検出結果",
        "",
        "| 重大度 | 件数 |",
        "|---|---:|",
        *[f"| {severity} | {counts[severity]} |" for severity in ("緊急", "重大", "高", "中", "低", "情報", "警告")],
        "",
        "## 検出された問題",
        "",
    ]
    if not findings:
        lines.append("検出された問題はありません。未実施・失敗した検査がないか、次の一覧を確認してください。")
    for index, finding in enumerate(findings, 1):
        location = finding.path or "該当なし"
        if finding.line is not None:
            location += f":{finding.line}"
        references = ", ".join(
            f"[{label}]({url})" for label, url in finding.links
        ) or "なし"
        lines.extend([
            f"### {index}. [{finding.severity}] {finding.title}",
            "",
            f"- ファイル: `{location}`",
            f"- 検出方法: {finding.tool}",
            f"- 識別子: {finding.identifier or 'なし'}",
            f"- 参照: {references}",
            f"- 根拠: {finding.evidence or 'ツールの検出結果'}",
            f"- 推奨対応: {finding.recommendation or 'コードの文脈を確認して修正してください。'}",
            "",
        ])
    lines.extend(["## 検査できなかった項目・実行状況", ""])
    for check in checks:
        lines.append(f"- **{check.name}** — {check.status}: {check.detail}")
    incomplete = [check for check in checks if check.status in {"未実施", "失敗"}]
    blocked = any(finding.blocking or SEVERITY_ORDER.get(finding.severity, 0) >= SEVERITY_ORDER["高"] for finding in findings)
    lines.extend([
        "",
        "## 総合評価",
        "",
        f"- 総合的なセキュリティ評価: {'要対応' if findings else '自動検査上は問題未検出'}",
        f"- コミット可否: {'不可' if blocked or incomplete else '可'}",
        f"- 検査未実施・失敗: {len(incomplete)} 件",
        "- 注意: AI の文脈レビューはこの CLI では自動実行しません。Copilot Chat で認証・認可・到達可能性を確認してください。",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Japanese security scanner for supported web projects")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="検査対象のリポジトリルート")
    parser.add_argument("--mode", choices=("full", "pre-commit"), default="full")
    parser.add_argument("--staged", action="store_true", help="ステージ済みファイルだけを静的解析する")
    parser.add_argument("--django-check", action="store_true", help="manage.py check --deploy を実行する")
    parser.add_argument("--output", type=Path, help="Markdown の出力先（未指定時は標準出力）")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    if not root.is_dir():
        print(f"エラー: 検査ルートがありません: {root}", file=sys.stderr)
        return 2
    selected = staged_files(root) if args.staged else all_source_files(root)
    files = [path for path in selected if is_scannable(path.relative_to(root))]
    dependency_changed = args.mode == "full" or any(path.name in DEPENDENCY_FILES for path in selected)
    all_findings, secret_check = scan_secrets(root, files)
    checks = [secret_check]
    findings, check = scan_bandit(root, files)
    all_findings.extend(findings); checks.append(check)
    findings, check = scan_semgrep(root, files)
    all_findings.extend(findings); checks.append(check)
    findings, more_checks = scan_pip_audit(root, dependency_changed)
    all_findings.extend(findings); checks.extend(more_checks)
    findings, more_checks = scan_npm_audit(root, dependency_changed)
    all_findings.extend(findings); checks.extend(more_checks)
    findings, check = django_check(root, args.django_check)
    all_findings.extend(findings); checks.append(check)
    report = render_report(root, files, all_findings, checks, args.mode)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    print(report, end="")
    incomplete = any(check.status in {"未実施", "失敗"} for check in checks)
    blocking = any(
        finding.blocking or SEVERITY_ORDER.get(finding.severity, 0) >= SEVERITY_ORDER["高"]
        for finding in all_findings
    )
    return 1 if incomplete or blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
