# Copilot Security Review Plugin

Python/Django を中心に、JavaScript、TypeScript、HTML、CSS と依存関係を検査する、
再利用可能な GitHub Copilot Agent Plugin、Skill、ローカルスキャナーです。既知の依存関係
脆弱性、危険な実装パターン、秘密情報、Django のデプロイ設定を別々に検査し、
日本語 Markdown で結果を出力します。

> 自動検査で「問題なし」となっても安全性は保証されません。認証・認可、IDOR、
> 到達可能性、業務上の権限は Copilot Chat と人間のレビューで確認してください。

## Plugin としての導入

このリポジトリは Agent Plugins 1.0 形式で、無料の Plugin Marketplace も含みます。
Copilot CLI 利用者は、次のコマンドでMarketplaceを登録してからPluginを導入できます。

```bash
copilot plugin marketplace add kondo-akihiro-git/practice-Copilot-SecuritySkill
copilot plugin install copilot-security-review@kondo-security-tools
```

導入後は `copilot plugin list` で `copilot-security-review` が有効であることを確認し、
Copilot Chat でセキュリティレビューを依頼します。更新は `copilot plugin marketplace update
kondo-security-tools` の後に `copilot plugin update copilot-security-review`、削除は
`copilot plugin uninstall copilot-security-review` です。

Plugin は Skill と同梱する検査ルール・スクリプトを一緒に配布する単位です。対象プロジェクトの
依存関係や検査ツールは別途導入が必要であり、Plugin の導入だけで Git hook は自動設定されません。

## 対象と検査内容

| 対象 | 検査 |
|---|---|
| Python/Django | Bandit、Semgrep、Django deploy check、秘密情報パターン |
| JavaScript/TypeScript | Semgrep による動的実行・危険な HTML 挿入 |
| HTML/CSS | Django テンプレートの `safe` フィルターを含む Semgrep 対象。CSS は実装上のセキュリティ問題が限定的なため、外部リソースや表示による情報漏えいを文脈レビューする。 |
| `requirements*.txt` | pip-audit による既知脆弱性照合 |
| `package-lock.json` / `npm-shrinkwrap.json` | npm audit による既知脆弱性照合 |
| 設定・ソース全体 | 秘密鍵、AWS アクセスキー、GitHub トークンらしき値の検出 |

`pyproject.toml`、`Pipfile`、`yarn.lock`、`pnpm-lock.yaml` も依存関係変更として認識します。
この版で自動監査する Python 依存関係形式は `requirements*.txt`、JavaScript 依存関係形式は
npm の lockfile です。`pyproject.toml` は同じディレクトリの `requirements*.txt` で監査し、
Pipenv/Yarn/pnpm の lockfile は **未実施** としてコミットをブロックします。対応する
requirements または npm lockfile を用意するか、プロジェクトに適した監査コマンドを追加してください。

## 使用する検査技術と確認内容

各検査は異なる種類の問題を対象とします。たとえば、**CVE の確認**と
**Bandit によるコード検査**は別の検査です。両方を実行することで、利用中ライブラリの
既知の問題と、自作コードに含まれる危険な実装を分けて確認します。

| 技術・ツール | 主な確認対象 | 確認方法と出力 |
|---|---|---|
| pip-audit | Python ライブラリの既知脆弱性 | `requirements*.txt` のパッケージ名・固定バージョンを脆弱性情報と照合します。CVE、GHSA、PYSEC などの識別子が返った場合は、識別子と OSV/GitHub Advisory へのリンクを出力します。 |
| npm audit | npm ライブラリの既知脆弱性 | `package-lock.json` または `npm-shrinkwrap.json` の依存関係ツリーを npm レジストリのアドバイザリと照合します。 |
| Bandit | Python の危険な実装 | Python の構文木（AST）を解析し、危険な関数、弱い暗号設定、コマンド実行、SQL 組み立てなどの一般的な危険パターンを検出します。Django のビュー、モデル、設定などの Python コードも対象です。 |
| Semgrep | Python/Django/JavaScript/TypeScript/HTML の危険なパターン | 同梱ルールで `eval`/`exec`、`shell=True`、生 SQL、JavaScript の `innerHTML`・`document.write`、Django テンプレートの `safe` フィルターなどを検出します。 |
| Django deploy check | Django のデプロイ設定 | `--django-check` 指定時に `manage.py check --deploy` を実行し、`DEBUG`、HTTPS、Cookie、セキュリティヘッダーなど Django が検出可能な設定警告を確認します。 |
| 組み込み秘密情報検査 | 誤って含めた認証情報 | テキスト形式のソース・設定ファイルから、秘密鍵ヘッダー、AWS アクセスキー、GitHub トークンらしき文字列を検出します。バイナリ、仮想環境、ビルド成果物は除外します。 |
| Copilot Chat の文脈レビュー | 設計・認可・処理の組合せ | 自動検査で確定できない IDOR、権限確認漏れ、入力から出力までのデータフローなどを、Skill の手順に従ってコード根拠付きで確認します。 |

### CVE・OSV・NVD の扱い

CVE は脆弱性を識別する番号であり、脆弱性の有無をコードだけから判定する仕組みでは
ありません。この Skill では pip-audit と npm audit がパッケージ名・バージョンを既知の
アドバイザリ情報と照合します。CVE が付与されたアドバイザリなら、その CVE を結果に表示
します。OSV は複数の脆弱性情報源を横断して参照できるデータベースとしてリンク先に使い、
NVD は CVE の詳細調査・影響評価を補完する情報源として利用します。

依存関係に CVE がない、または脆弱性データベースに接続できないことは、安全の保証では
ありません。後者は **未実施・失敗** と表示し、コミット前検査ではブロックします。

## 構成

```text
SecuritySkill/
├── .github/plugin/marketplace.json # 第三者導入用のMarketplaceカタログ
├── plugin.json                  # Agent Plugins 1.0 マニフェスト
├── skills/security-review/
│   ├── SKILL.md                 # Copilot が読む Skill 定義
│   └── rules/security.yml       # ローカル Semgrep ルール
├── .githooks/pre-commit         # ネイティブ Git フック
├── scripts/
│   ├── security_scan.py         # 検査・集約・日本語レポート
│   └── install_pre_commit.py    # フック有効化
├── references/tooling-and-severity.md
├── tests/
├── pyproject.toml
└── .pre-commit-config.yaml      # pre-commit 利用者向けの代替設定
```

別プロジェクトで使うには、このディレクトリをコピーするか Skill と `scripts/` を取り込み、
対象プロジェクトのリポジトリルートでスクリプトを実行します。Plugin として利用する場合は、
Copilot CLI が `skills/security-review/SKILL.md` を検出します。

## 導入

必要環境は Python 3.10 以上、Git、インターネット接続（依存関係監査時）です。npm の
lockfile を監査する場合は Node.js/npm も必要です。

```bash
git clone https://github.com/kondo-akihiro-git/practice-Copilot-SecuritySkill.git
cd SecuritySkill
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install 'bandit[toml]>=1.7.10' 'pip-audit>=2.7.3' 'semgrep>=1.100.0' 'pytest>=8.0'
python -m pip install -e .
python scripts/install_pre_commit.py
```

Bandit、pip-audit、Semgrep、pytest はスキャナーを動かす開発ツールであり、検査対象
プロジェクトの依存関係ではありません。外部データベースの照会に失敗した場合、スキャナーは
成功扱いにしません。パッケージ名、バージョン、脆弱性 ID は依存関係監査の根拠として出力されます。
NVD は手動の詳細調査で補完し、ローカル実行時に API キーを要求しません。

## 実行方法

全体検査（Django プロジェクトは安全に初期化できる環境で実行）:

```bash
python scripts/security_scan.py --root /path/to/target --mode full --django-check --output reports/security-report.md
```

Django プロジェクト以外、または Django 設定を実行したくない場合:

```bash
python scripts/security_scan.py --root /path/to/target --mode full
```

コミット前は、フックがステージ済みソースを Bandit/Semgrep/秘密情報検査にかけます。
`requirements*.txt` や npm lockfile の変更時には依存関係全体も監査します。高以上の
静的検出、既知の依存関係脆弱性、ツール未導入、実行失敗、DB 照会失敗があると、
終了コード 1 でコミットを止めます。

```bash
python scripts/install_pre_commit.py
git commit -m "Describe change"
```

`--no-verify` は Git フックを回避できます。保護ブランチや CI でも同じ全体検査を実行して
ください。`.pre-commit-config.yaml` は既存の pre-commit 運用に統合するための代替です。

## 検査結果

レポートは日本語 Markdown で、検査日時、対象数、重大度別件数、ファイル/行、根拠、
推奨対応、検査の実行状況、コミット可否を出力します。pip-audit が返した CVE、GHSA、
PYSEC の識別子には、出力前に到達確認した OSV または GitHub Advisory へのリンクも付けます。

| 表記 | 意味 |
|---|---|
| 緊急 / 重大 | 人間のレビューで直ちに悪用可能または極めて重大と確認した場合に使用 |
| 高 / 中 / 低 | 静的解析・依存関係監査の重大度を日本語化 |
| 警告 | 重大度不明の既知脆弱性、または追加確認が必要な状態 |
| 未実施 / 失敗 | 問題なしではない。コミット前検査では失敗として扱う |

依存関係脆弱性の外部評価と、Copilot による設計・文脈レビューは区別します。AI レビューは
CLI から自動起動しません。認証、料金、データ送信先、実行時間をこの汎用スクリプトが
保証できないためです。Copilot Chat で `security-review` Skill を使い、レポートと
該当コードを根拠に、認可漏れ、IDOR、入力から出力までのデータフロー、アップロード、
リダイレクト、Cookie/セッションをレビューしてください。

## 除外と注意事項

`node_modules`、仮想環境、キャッシュ、ビルド成果物、バイナリ、ベンダー生成物はコード
走査から除外します。ノイズと検査時間を抑えるためですが、依存関係は lockfile/manifest
の監査で別途確認します。生成物に自作コードが含まれる場合は、元ソースを検査対象にして
ください。

実行対象の Django アプリケーションは、`manage.py check --deploy` で初期化されます。
信頼できないコードを検査する場合は、隔離環境で実行し、必要なダミー環境変数だけを与えて
ください。レポート、`.env`、鍵、トークン、ローカル設定はコミットしません。

## 拡張

言語やフレームワークを追加する際は、専用の検査器を `scripts/security_scan.py` に追加し、
その失敗状態を必ずレポートへ記録してください。新規 Semgrep ルールは
`skills/security-review/rules/` に追加し、誤検知・検出例をテストします。
採用理由、重大度の扱い、公式資料は
[`references/tooling-and-severity.md`](references/tooling-and-severity.md) に記録します。
