# CredShim

開発用クレデンシャル注入プロキシ。脅威モデルは `docs/threat-model.md`。

## ルール

- 秘密は必ず `secrecy` の型で持つ。`expose_secret()` を呼べるのは core の差し替え関数（`crates/core/src/inject.rs`）とスクラブ（`crates/core/src/scrub.rs`）、`crates/secrets/`、oauth の保管庫とトークン交換、SSH の鍵（`crates/ssh/src/key.rs`）、AWS の再署名（`crates/aws/src/resign.rs`）だけ。`scripts/check-secret-exposure.sh` がCIで検査する。許可先を増やすときはスクリプトの allowlist を変える。
- リクエスト／レスポンスのボディを丸ごと読み込まない。例外は oauth のトークンエンドポイント処理と、AWS の S3 以外への要求（署名にボディのハッシュが要る）だけで、必ずサイズ上限を付ける。
- ログ、エラー、パニックに秘密やトークンの値を出さない。テストでは `credshim_testkit::fake_secret` で偽秘密を作り、`capture_logs().assert_absent(..)` でログに出ていないことを検査する。
- 新しい挙動には統合テストを付ける。完了の条件は `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`、`scripts/check-secret-exposure.sh` がすべて通ること。
- 実運用の設定ディレクトリや秘密ストア（`~/.config/credshim`、`/var/lib/credshim`、キーチェーンの credshim 項目）を読まない・編集しない。開発中も本物の鍵は使わない。
- `docs/install.md` のインストールの1行は `scripts/install.sh` をコミットの SHA で指す。スクリプトを変えたら、CI の `stage-b` が通ったあとで `docs/install.md` の SHA をそのコミットに書き換える。README のお試し構成のバージョン（`v=`）は、リリースのたびに上げる。
- `testing` フィーチャー（上流の追加信頼アンカーとDNS上書き）はテスト専用。リリースビルドでは `compile_error!` で止まり、`scripts/check-release-excludes-testing.sh` が検査する。

## 構成

- `crates/core` ルール照合・差し替え・ダミー生成・スクラブ（I/Oなし）
- `crates/mitm` CA、証明書キャッシュ、CONNECT、TLS終端、h1/h2中継、上流接続
- `crates/secrets` 秘密ストアのバックエンド
- `crates/oauth` トークン保管庫、トークンエンドポイント処理
- `crates/ssh` ssh-agent（session-bind の検証と署名の判定、鍵の生成）
- `crates/aws` SigV4 の解析と再署名、認証情報を発行する操作の拒否と操作の許可リスト（操作の表は `scripts/aws/credential-operations.py` で botocore から生成）
- `crates/testkit` テスト用CA、モック上流（echo・SSE・大容量・WebSocket、h1/h2）、モック AWS（SigV4 検証）、テスト用 sshd、ログキャプチャ
- `crates/cli` `credshim` バイナリ（設定ファイル、`secret set/list`、`preset`、監査ログ）
- `crates/e2e` 実SDK（Python、Node）と `aws` CLI v2 の E2E。`#[ignore]` なので `mise exec -- cargo test -p credshim-e2e -- --ignored`（Node は先に `crates/e2e/sdk/node` で `npm ci`）

## 環境メモ

- Rust は rustup で `~/.cargo` に入っている。非対話シェルでは `. ~/.cargo/env` が要る。
- Node と `aws` CLI は mise 管理（`mise.toml`）。`mise exec -- node` で使い、SDK E2E は `mise exec -- cargo test -p credshim-e2e -- --ignored` で PATH に node と aws を載せる。Python の SDK E2E は `uv run --python 3.13` を使う（システムの python3 は 3.9）。
