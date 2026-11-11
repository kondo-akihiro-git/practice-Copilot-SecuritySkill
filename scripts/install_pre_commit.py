#!/usr/bin/env python3
"""Install this repository's native Git pre-commit hook without copying files."""

from __future__ import annotations

import subprocess  # nosec B404 - invokes the fixed Git executable without a shell.
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    hook = root / ".githooks" / "pre-commit"
    if not hook.is_file():
        print(f"フックが見つかりません: {hook}", file=sys.stderr)
        return 1
    result = subprocess.run(  # nosec B603 B607 - fixed Git command, no user-controlled executable or shell.
        ["git", "config", "core.hooksPath", ".githooks"], cwd=root, text=True, check=False
    )
    if result.returncode:
        print("Git フックの設定に失敗しました。Git リポジトリ内で実行してください。", file=sys.stderr)
        return result.returncode
    print("pre-commit フックを .githooks/pre-commit に設定しました。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
