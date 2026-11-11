# 検査方式と判定基準

## 採用した方式

| 方式 | 採用理由 | 限界 |
|---|---|---|
| pip-audit | Python パッケージと既知脆弱性をパッケージ名・バージョンで照合できる。 | 未固定依存、非公開パッケージ、到達可能性は判定しない。 |
| npm audit | lockfile を使い npm の依存グラフとアドバイザリを照合できる。 | npm 以外のレジストリや lockfile のない構成は対象外。 |
| Bandit | Python AST で一般的な危険 API を検出する。 | 認可設計や入力値の出所は理解しない。 |
| Semgrep | 言語横断のカスタムルールを、ネットワーク不要で再現性高く実行できる。 | パターン一致であり、脆弱性の確定ではない。 |
| Django deploy check | Django の公式システムチェックを利用できる。 | 実行には安全な設定・依存関係・環境変数が必要。 |

NVD は CVE の補完情報源として有用だが、API キー、レート制限、CPE の曖昧さを避けるため、
このローカルスキャナーでは直接照会しない。pip-audit/npm audit の機械可読な結果を一次根拠とし、
詳細調査時に OSV、GitHub Advisory、NVD、ベンダーの修正情報を照合する。

## 重大度の日本語表示

| 外部値・状態 | 表示 |
|---|---|
| critical | 緊急 |
| high | 高 |
| moderate / medium | 中 |
| low | 低 |
| info | 情報 |
| 重大度不明の既知依存脆弱性 | 警告 |
| ツール未導入・実行失敗・DB 照会失敗 | 警告（未実施） |

「重大」は、人間のレビューで、外部公開かつ認証不要で機密性・完全性・可用性に重大な影響が
あると確認できたときに使う。「緊急」は同条件で直ちに悪用可能、または能動的な悪用が確認
された場合に限定する。自動ツールはこの二つを自動付与しない。

## 公式資料

- [Django security](https://docs.djangoproject.com/en/stable/topics/security/)
- [Django deployment checklist](https://docs.djangoproject.com/en/stable/howto/deployment/checklist/)
- [pip-audit](https://github.com/pypa/pip-audit)
- [Bandit](https://bandit.readthedocs.io/)
- [Semgrep](https://semgrep.dev/docs/)
- [npm audit](https://docs.npmjs.com/cli/commands/npm-audit)
- [OSV](https://osv.dev/)
- [NVD](https://nvd.nist.gov/developers)
