# CredShim

開発用クレデンシャル注入プロキシ。計画と進捗は `docs/plan.md`（各フェーズの完了条件チェックボックスが進捗の正）、脅威モデルは `docs/threat-model.md`。

## ルール

- 秘密は必ず `secrecy` の型で持つ。`expose_secret()` を呼べるのは core の差し替え関数（`crates/core/src/inject.rs`）、`crates/secrets/`、oauth の保管庫とトークン交換だけ。`scripts/check-secret-exposure.sh` がCIで検査する。許可先を増やすときはスクリプトの allowlist を変える。
- リクエスト／レスポンスのボディを丸ごと読み込まない。例外は oauth のトークンエンドポイント処理だけで、必ずサイズ上限を付ける。
- ログ、エラー、パニックに秘密やトークンの値を出さない。テストでは `credshim_testkit::fake_secret` で偽秘密を作り、`capture_logs().assert_absent(..)` でログに出ていないことを検査する。
- 新しい挙動には統合テストを付ける。完了の条件は `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`、`scripts/check-secret-exposure.sh` がすべて通ること。
- 実運用の設定ディレクトリや秘密ストア（`~/.config/credshim`、`/var/lib/credshim`、キーチェーンの credshim 項目）を読まない・編集しない。開発中も本物の鍵は使わない。
- `testing` フィーチャー（上流の追加信頼アンカーとDNS上書き）はテスト専用。リリースビルドでは `compile_error!` で止まり、`scripts/check-release-excludes-testing.sh` が検査する。

## 構成

- `crates/core` ルール照合・差し替え・ダミー生成・スクラブ（I/Oなし）
- `crates/mitm` CA、証明書キャッシュ、CONNECT、TLS終端、h1/h2中継、上流接続
- `crates/secrets` 秘密ストアのバックエンド
- `crates/oauth` トークン保管庫、トークンエンドポイント処理
- `crates/testkit` テスト用CA、モック上流（echo・SSE・大容量・WebSocket、h1/h2）、ログキャプチャ
- `crates/cli` `credshim` バイナリ

## 環境メモ

- Rust は rustup で `~/.cargo` に入っている。非対話シェルでは `. ~/.cargo/env` が要る。
- Node は mise 管理（`mise.toml`）。`mise exec -- node` で使う。Python の SDK E2E は `uv run --python 3.13` を使う（システムの python3 は 3.9）。
