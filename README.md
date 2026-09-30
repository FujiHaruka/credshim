# CredShim

ローカル開発用のクレデンシャル注入プロキシ。アプリやコーディングエージェントにはダミーのAPIキーだけを持たせ、登録済みホストへ出ていく直前にプロキシが本物へ差し替える。本物のキーは .env にも、アプリのメモリにも、ログにも、エージェントのコンテキストにも現れない。

- `HTTPS_PROXY` で挟まる MITM プロキシ（HTTP/1.1、HTTP/2、SSE、WebSocket）。SDK は無改造で動く。
- CA を扱えないランタイム向けに、LiteLLM Proxy と同じ使い方の base URL モードもある。
- ダミーは束縛したホスト（とポート、任意でパス）宛てのときだけ差し替え、それ以外は403で止める。レスポンスに本物が現れればダミーに戻す。

設計と脅威モデルは [docs/plan.md](docs/plan.md) と [docs/threat-model.md](docs/threat-model.md)。

## インストール

Rust（rustup）が要る。

```sh
cargo install --locked --path crates/cli
```

## 最初のストリーミング応答まで

OpenAI を例にする。設定ファイルは `~/.config/credshim/config.toml`（`$XDG_CONFIG_HOME` に従う）、秘密は macOS ではキーチェーン、それ以外では `~/.config/credshim/secrets.age` に入る。

```sh
# 1. 開発用CAを作る（OS の信頼ストアには入れない）
credshim ca init

# 2. ルールを追加する（ダミーは毎回ランダムに生成される）
mkdir -p ~/.config/credshim
credshim preset openai >> ~/.config/credshim/config.toml

# 3. 本物のキーを登録する（端末から入力。argv や環境変数は経由しない）
credshim secret set openai

# 4. プロキシを起動する
credshim run
```

別のシェルで:

```sh
# 5. プロキシ、CA、ダミーキーの変数を読み込む
eval "$(credshim env)"

# 6. このシェルのランタイムがプロキシと CA を本当に使っているか確かめる
credshim doctor

# 7. ストリーミングで叩く（$OPENAI_API_KEY はダミー）
curl -N https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4o-mini", "stream": true, "messages": [{"role": "user", "content": "hi"}]}'
```

SDK もそのまま動く。

```sh
uv run --with openai python -c '
import openai
for chunk in openai.OpenAI().chat.completions.create(
    model="gpt-4o-mini", stream=True, messages=[{"role": "user", "content": "hi"}]):
    print(chunk.choices[0].delta.content or "", end="", flush=True)
'
```

`credshim env` が出すのは `HTTPS_PROXY`・`HTTP_PROXY`（小文字も）、`NO_PROXY`、結合バンドルを指す `SSL_CERT_FILE`・`REQUESTS_CA_BUNDLE`・`CURL_CA_BUNDLE`、開発CAを指す `NODE_EXTRA_CA_CERTS`、`NODE_USE_ENV_PROXY=1`、ルールに `env` がある場合はそのダミーキー（`OPENAI_API_KEY` など）。ダミーなので .env にそのまま書いてよい。

## credshim doctor

`credshim.test` はプロキシ自身が答える予約ホスト名で、DNS には存在しない。そこへ届けば「プロキシ経由」、TLS が通れば「CA を信頼している」、ALPN で h2 か http/1.1 かも分かる。

```text
[ok  ] proxy    credshim.test answered through 127.0.0.1:8787 over h2; its certificate chains to ~/.config/credshim/ca/ca.pem
[ok  ] env      HTTPS_PROXY=http://127.0.0.1:8787
[ok  ] env      SSL_CERT_FILE=~/.config/credshim/ca/bundle.pem includes the CA
[ok  ] curl     via the proxy, CA trusted, h2
[ok  ] python   via the proxy, CA trusted, http/1.1
[ok  ] node     via the proxy, CA trusted, http/1.1
[ok  ] go       via the proxy, CA trusted, h2
```

PATH にある curl、python3、node、go をこのシェルの環境のまま実行して確かめる。各言語から叩くワンライナー（requests、httpx、Node の fetch、Go）は `credshim doctor --snippets` で出る。

- **Node。** 組み込みの fetch は `NODE_USE_ENV_PROXY=1`（Node 24 以降）がないと `HTTPS_PROXY` を見ない。古い Node では undici の `EnvHttpProxyAgent` を dispatcher に渡す。doctor はプロキシを素通りした失敗（`ENOTFOUND credshim.test`）を見分けて案内する。
- **Python。** Apple 同梱の `/usr/bin/python3` の ssl モジュールは `SSL_CERT_FILE` を読まない。requests と httpx は `REQUESTS_CA_BUNDLE`・`SSL_CERT_FILE` を自分で読むので動く。

## base URL モード

CA を設定できないランタイムや、プロキシ変数を見ないクライアント向け。`http://127.0.0.1:8788/openai/...` を `https://api.openai.com/...` に固定で対応させるリバースプロキシで、同じルール（束縛、許可リスト、上限、スクラブ）がそのまま掛かる。

```toml
[listen]
addr = "127.0.0.1:8787"
base_url_addr = "127.0.0.1:8788"
```

プリセットのルールには `base_url_prefix = "/openai"` が入っている。

```sh
OPENAI_BASE_URL=http://127.0.0.1:8788/openai/v1 OPENAI_API_KEY=sk-credshim-openai-... python app.py
```

`credshim env` は base URL を `# base URL for openai: http://127.0.0.1:8788/openai` のようにコメントで出す。対応表に無いパス、`..` や `%2f` を含むパス、ループバック以外を名乗る Host は拒否する。ダミーを含まない要求はそのまま上流へ転送する（本物は使わない）。

## SSH エージェント

CredShim は ssh-agent としても動く。鍵はプロキシの中で生成して秘密ストアにだけ置き、外へは公開鍵しか出さない。署名するのは、OpenSSH 8.9 以降の `ssh` が送る session-bind で検証できたサーバーのホスト鍵が設定の指紋に含まれ、許可したユーザー名でのログイン要求のときだけ。`ssh -A` の先からの要求、`ssh-keygen -Y sign`（コミット署名）、鍵の追加・削除は拒否する。

```sh
credshim preset github-ssh >> ~/.config/credshim/config.toml   # GitHub のホスト鍵3種、ユーザー git
credshim ssh keygen ssh-github                                  # 公開鍵を GitHub に登録する
credshim run                                                    # 既定のソケットは ~/.config/credshim/ssh-agent.sock
export SSH_AUTH_SOCK=~/.config/credshim/ssh-agent.sock
ssh -T git@github.com
```

```toml
[ssh]
socket = "/path/to/ssh-agent.sock"

[[ssh_key]]
name = "github"
secret = "ssh-github"
users = ["git"]
host_keys = ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"]
```

ProxyJump で踏み台にも同じ鍵で入るなら、踏み台のホスト鍵の指紋も `host_keys` に入れる。既存の `~/.ssh` の鍵は取り込まず、新しい鍵に入れ替えて古い鍵は無効化する。

## AWS（静的アクセスキー）

`~/.aws/credentials` にはダミーのアクセスキーだけを置く。`aws` コマンドはダミーで SigV4 署名した要求をプロキシへ送り、CredShim はアクセスキー ID でルールを引いて本物の認証情報で署名し直す。ダミーのシークレットは送信されないので、何を書いてもよい。

```sh
credshim preset aws >> ~/.config/credshim/config.toml   # ダミーのアクセスキー ID は毎回ランダム
credshim secret set aws-access-key-id                   # 本物のアクセスキー ID
credshim secret set aws-secret-access-key               # 本物のシークレット
credshim run

# ~/.aws/credentials
# [default]
# aws_access_key_id = <preset が出した dummy_access_key_id>
# aws_secret_access_key = dummy
export HTTPS_PROXY=http://127.0.0.1:8787
export AWS_CA_BUNDLE=~/.config/credshim/ca/bundle.pem   # 開発CA＋システムのルート（置き換えなので CA 単体は不可）
aws sts get-caller-identity
```

```toml
[aws]
max_body_bytes = 16777216   # S3 以外で署名のために読むボディの上限（既定 16MiB）

[[aws_key]]
name = "aws"
dummy_access_key_id = "CREDSHIMAWS..."
access_key_id = "aws-access-key-id"          # 秘密ストアの名前
secret_access_key = "aws-secret-access-key"  # 秘密ストアの名前
services = ["sts", "s3", "dynamodb"]         # 省略すると全サービス。資格スコープのサービス名で照合
regions = ["ap-northeast-1"]                 # 省略すると全リージョン
```

認証情報を発行する操作（`sts:AssumeRole`・`GetSessionToken`、`iam:CreateAccessKey`、`s3:CreateSession` など37操作）は拒否する。SSO OIDC、SSO ポータル、`aws login` の signin のホストへの CONNECT は、AWS の設定が無くても常に拒否する。`aws sso login`、AssumeRole するプロファイル、`aws s3 presign` などクライアント側で署名するもの、S3 Express One Zone は動かない。

## 監査ログと状態

```toml
[audit]
path = "/path/to/audit.jsonl"

[status]
socket = "/path/to/status.sock"
```

`credshim tail` が監査ログをライブ表示し、エージェントが今どこを叩いているかが見える。`credshim status` はルールごとのカウンタを出す。どちらにも秘密やダミーの値は出ない。

```text
2026-09-30T03:31:37.5Z inject      200 POST https://api.openai.com:443/v1/chat/completions [openai] via connect
2026-09-30T03:31:40.1Z deny        403 POST https://attacker.example:443/collect [openai] via connect
```

## 別ユーザーでの常駐（段階B）

同じOSユーザーでエージェントとプロキシが動く限り、エージェントは秘密ストアや設定に手が届く。実運用ではプロキシを専用ユーザーで常駐させ、開発ユーザーには sudo を与えない。

```sh
sudo credshim service install          # Linux は systemd（ユーザー credshim）、macOS は launchd（ユーザー _credshim）
credshim service install --print       # 実行前に中身を確認する
```

状態は `/var/lib/credshim`（専用ユーザーだけが読める）、公開用の CA 証明書・結合バンドル・シェル用の変数は `/etc/credshim` に置かれる。ルールと秘密の登録は専用ユーザーとして行い、ルールを変えたらインストール済みのバイナリで `service install` をもう一度実行して `/etc/credshim/env` を更新する（開発ユーザーが書き換えられるバイナリを sudo で動かさない）。別のバイナリで置き換えるときは `--upgrade` を付ける。

```sh
credshim preset openai | sudo -u credshim tee -a /var/lib/credshim/config.toml
sudo -u credshim /usr/local/libexec/credshim/credshim secret set openai --config /var/lib/credshim/config.toml
sudo /usr/local/libexec/credshim/credshim service install   # macOS は /Library/CredShim/bin/credshim

# 開発ユーザーのシェルで
. /etc/credshim/env && credshim doctor
```

`scripts/stage-b/verify.sh` を開発ユーザーとして実行すると、設定・秘密・CA鍵を読めず書けないことを確かめる。

## 開発

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/check-secret-exposure.sh

# 実SDK（Python、Node）、aws CLI v2 と doctor（Python、Node、Go）の E2E
(cd crates/e2e/sdk/node && npm ci)
mise exec -- cargo test -p credshim-e2e -- --ignored
cargo test -p credshim --test dev_tools -- --ignored
```
