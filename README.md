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

`credshim env` が出すのは `HTTPS_PROXY`・`HTTP_PROXY`（小文字も）、`NO_PROXY`、結合バンドルを指す `SSL_CERT_FILE`・`REQUESTS_CA_BUNDLE`・`CURL_CA_BUNDLE`、開発CAを指す `NODE_EXTRA_CA_CERTS`、`NODE_USE_ENV_PROXY=1`、`aws` コマンド向けに結合バンドルを指す `AWS_CA_BUNDLE`、ルールに `env` がある場合はそのダミーキー（`OPENAI_API_KEY` など）。`[[ssh_key]]` があれば agent のソケットを指す `SSH_AUTH_SOCK`、AWS のルールがちょうど1つならそのダミーの `AWS_ACCESS_KEY_ID` と `AWS_SECRET_ACCESS_KEY`（2つ以上なら `~/.aws/credentials` に書くプロファイルをコメントで出す）。ダミーなので .env にそのまま書いてよい。

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
[ok  ] ssh      SSH_AUTH_SOCK=~/.config/credshim/ssh-agent.sock is the credshim agent (rules: github)
[ok  ] openssh  /usr/bin/ssh is OpenSSH 9.9, which sends session-bind
[ok  ] aws      the aws CLI reached credshim.test through the proxy and trusted the CA
[ok  ] files    no private keys in ~/.ssh and no real AWS credentials in ~/.aws or the environment
```

PATH にある curl、python3、node、go をこのシェルの環境のまま実行して確かめる。各言語から叩くワンライナー（requests、httpx、Node の fetch、Go）は `credshim doctor --snippets` で出る。

- **Node。** 組み込みの fetch は `NODE_USE_ENV_PROXY=1`（Node 24 以降）がないと `HTTPS_PROXY` を見ない。古い Node では undici の `EnvHttpProxyAgent` を dispatcher に渡す。doctor はプロキシを素通りした失敗（`ENOTFOUND credshim.test`）を見分けて案内する。
- **Python。** Apple 同梱の `/usr/bin/python3` の ssl モジュールは `SSL_CERT_FILE` を読まない。requests と httpx は `REQUESTS_CA_BUNDLE`・`SSL_CERT_FILE` を自分で読むので動く。
- **SSH。** `SSH_AUTH_SOCK` の agent に鍵の一覧を求め、CredShim の鍵（コメント `credshim:<ルール>`）が無ければ別の agent を指していると警告する。PATH の `ssh` が session-bind を送らない OpenSSH 8.9 より前なら報告する。
- **AWS。** PATH の `aws` で `credshim.test` にダミーのキーの要求を送り、プロキシを通って CA を信頼しているかを見る（`AWS_CA_BUNDLE` は信頼ストアを置き換えるので結合バンドルを指す）。
- **残った本物。** `~/.ssh` の秘密鍵、`~/.aws/credentials`・`~/.aws/config` の本物のアクセスキーと `credential_process`・SSO のプロファイル、`~/.aws/sso/cache`・`~/.aws/cli/cache`、環境変数の本物のキーとセッショントークンを、パスとプロファイル名だけで報告する（値は出さない）。移行の手順は下の「既存の認証情報からの移行」。

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
eval "$(credshim env)"                                          # SSH_AUTH_SOCK も出る
ssh -T git@github.com
```

```toml
[ssh]
socket = "/path/to/ssh-agent.sock"
client_uids = [501]          # 接続を受け付ける uid。省略するとプロキシ自身の uid だけ

[[ssh_key]]
name = "github"
secret = "ssh-github"
users = ["git"]
host_keys = ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"]
limits = { per_minute = 30, per_day = 500 }   # 署名の回数の上限（省略すると無制限）
```

上限を超えた署名要求は拒否し、監査ログに `reason="limited"` を残す。agent は接続元の uid を確かめ、`client_uids` に無い接続はすぐに閉じる。

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
services = ["sts", "s3", "dynamodb"]         # 省略すると全サービス（execute-api は明示したときだけ）。資格スコープのサービス名で照合
regions = ["ap-northeast-1"]                 # 省略すると全リージョン
operations = ["sts:GetCallerIdentity", "s3:GetObject", "s3:ListObjects*", "dynamodb:Describe*"]
limits = { per_minute = 120, per_day = 5000, concurrent = 8 }
```

`operations` は `<署名名>:<操作名>` の許可リストで、末尾の `*` は前方一致（`s3:*` はそのサービスの全操作）。操作は要求から特定する：Query と EC2 は `Action`、JSON は `X-Amz-Target`、rpc-v2-cbor はパス、REST（S3、Lambda など）はメソッド、パス、必須のクエリとヘッダーで、botocore のモデルから生成した表のうち最も具体的なもの。特定した操作のどれかが許可リストに無いか、操作を特定できなければ `CredShimOperationNotAllowed` の403で、上流へは送らない（同じ形の操作が複数あるとき、たとえば `GetBucketLifecycle` と `GetBucketLifecycleConfiguration` は両方を許可する）。監査ログと `credshim tail` の `operation` に特定した操作名が出るので、そこから許可リストを作れる。`limits` を超えると `CredShimLimitExceeded` の429。`services`・`regions`・`operations`・`limits` は SSO のロールにも書ける。

認証情報を発行する操作（`sts:AssumeRole`・`GetSessionToken`、`iam:CreateAccessKey`、`s3:CreateSession` など37操作）は拒否する。SSO OIDC、SSO ポータル、`aws login` の signin のホストへの CONNECT は、AWS の設定が無くても常に拒否する。`aws sso login`（代わりに `credshim aws sso login`）、AssumeRole するプロファイル、`aws s3 presign` などクライアント側で署名するもの、S3 Express One Zone は動かない。

## AWS（IAM Identity Center／SSO）

SSO のロールも、`~/.aws` にはダミーの静的アクセスキーだけを置いて使う。ログインは `aws sso login` ではなく `credshim aws sso login` で人間が行い、SSO トークンは秘密ストアに、ロール認証情報はプロキシのメモリにだけ置く。プロキシは期限の10分前にロール認証情報と SSO トークンを取り直す（リフレッシュトークンがあれば）。

```sh
credshim preset aws-sso >> ~/.config/credshim/config.toml   # start_url、region、アカウント、ロールを書き換える
credshim run
credshim aws sso login sso       # 表示された URL をブラウザで開いてコードを確かめ、承認する
aws sts get-caller-identity      # ~/.aws/credentials はダミー（静的キーと同じ）
credshim aws sso logout sso      # IAM Identity Center のセッションを終わらせ、保存したトークンを消す
```

```toml
[[aws_sso_session]]
name = "sso"
start_url = "https://your-portal.awsapps.com/start"
region = "us-east-1"                 # IAM Identity Center のリージョン

[[aws_sso_role]]
name = "aws-sso"
dummy_access_key_id = "CREDSHIMAWS..."
session = "sso"
account_id = "123456789012"
role_name = "Developer"
services = ["sts", "s3"]             # 省略すると全サービス（静的キーと同じ）
regions = ["ap-northeast-1"]
```

ログインしていない、または SSO トークンが切れて更新できないときは、要求を上流へ送らずに `CredShimSsoLoginRequired` のエラー（`credshim aws sso login <session>` を促すメッセージ付き）を返し、監査ログに `sso_login_required` を残す。実行中のプロキシは次の AWS の要求で新しいログインを読み込むので、再起動は要らない。`logout` のあとも、プロキシがすでに持っているロール認証情報は取り直しの時期まで使われる。`login` は端末から実行する（stdin が TTY でなければ拒否）。

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
sudo ./target/release/credshim service install   # Linux は systemd（ユーザー credshim）、macOS は launchd（ユーザー _credshim）
./target/release/credshim service install --print # 実行前に中身を確認する
```

管理者になる操作（`su`、`sudo`）と専用ユーザーとしての操作（秘密の入力、SSO のログイン）は、開発ユーザーが持つ端末では行わない。開発ユーザーのプロセスはその端末に打ち込まれた文字を読めるので、管理者のパスワードや登録する秘密を盗める。別のコンソール、管理者ユーザーでの SSH ログイン、別の GUI ユーザーのセッションから行う。最初の `service install` も、開発ユーザーが書き換えられない場所にあるバイナリをフルパスで指定する。

状態は `/var/lib/credshim`（専用ユーザーだけが読める）、公開用の CA 証明書・結合バンドル・シェル用の変数は `/etc/credshim` に置かれる。ルールと秘密の登録は専用ユーザーとして行い、ルールを変えたらインストール済みのバイナリで `service install` をもう一度実行して `/etc/credshim/env` を更新する（開発ユーザーが書き換えられるバイナリを sudo で動かさない）。別のバイナリで置き換えるときは `--upgrade` を付ける。

```sh
/usr/local/libexec/credshim/credshim preset openai | sudo -u credshim tee -a /var/lib/credshim/config.toml
sudo -u credshim /usr/local/libexec/credshim/credshim secret set openai --config /var/lib/credshim/config.toml
sudo /usr/local/libexec/credshim/credshim service install   # macOS は /Library/CredShim/bin/credshim

# 開発ユーザーのシェルで
. /etc/credshim/env && credshim doctor
```

SSH の鍵の生成と SSO のログインも専用ユーザーとして行う（秘密ストアが専用ユーザーの側にあるため）。`sudo` は端末をそのまま渡すので、`aws sso login` の TTY の確認も通る。

```sh
sudo -u credshim HOME=/var/lib/credshim /usr/local/libexec/credshim/credshim ssh keygen ssh-github --config /var/lib/credshim/config.toml
sudo -u credshim HOME=/var/lib/credshim /usr/local/libexec/credshim/credshim aws sso login sso --config /var/lib/credshim/config.toml
```

agent のソケットは `/var/lib/credshim-ssh/agent.sock`（ディレクトリは専用ユーザーの所有で 0755）。接続できるのは `[ssh] client_uids` の uid だけで、`service install` は開発ユーザー（`--user` か、`sudo` を実行したユーザー）の uid を新しく作る設定に書く。設定がすでにあれば、足すべき行を表示する。`/etc/credshim/env` に `SSH_AUTH_SOCK` と `AWS_CA_BUNDLE` が入る。

`scripts/stage-b/verify.sh` を開発ユーザーとして実行すると、設定・秘密（ロックファイルを含む）・CA鍵を読めず書けないこと、agent のディレクトリに書けないこと、agent から鍵の一覧を取れること、`/etc/credshim/env` の `AWS_CA_BUNDLE`・`SSH_AUTH_SOCK` が公開の場所を指すことを確かめる。

## コンテナ分離（段階C）

エージェントとアプリを devcontainer に入れ、プロキシはホスト（段階Bの専用ユーザー）で動かす。コンテナの外向きの通信をプロキシだけに絞ると、SSO OIDC やポータルへの直接の接続も含めて、すべてがプロキシの判定と監査を通る。

```toml
[listen]
addr = "172.17.0.1:8787"      # docker ブリッジのホスト側。0.0.0.0 は常に拒否
allow_non_loopback = true
```

AWS はコンテナ内の `aws` にプロキシと結合バンドルとダミーを渡す。

```sh
docker run --rm \
  -e HTTPS_PROXY=http://172.17.0.1:8787 -e HTTP_PROXY=http://172.17.0.1:8787 \
  -e AWS_CA_BUNDLE=/credshim/bundle.pem -v /etc/credshim/bundle.pem:/credshim/bundle.pem:ro \
  -e AWS_ACCESS_KEY_ID=CREDSHIMAWS... -e AWS_SECRET_ACCESS_KEY=credshim-dummy -e AWS_REGION=ap-northeast-1 \
  amazon/aws-cli sts get-caller-identity
```

SSH は agent のソケットをコンテナにマウントし、22番ポートへの接続は既存の CONNECT トンネルで出す（プロキシはインターセプトしないホストへの CONNECT を素の TCP として中継し、監査ログに `tunnel` で残す）。agent は接続元の uid を見る。user namespace を使わない Linux の docker ではコンテナ内の uid がそのままホストの uid になるので、コンテナを開発ユーザーの uid で動かす（`--user "$(id -u)"`。OpenSSH はパスワードエントリの無い uid では動かないので、イメージにその uid のユーザーを作っておく）か、コンテナの uid を `client_uids` に入れる。Docker Desktop（macOS）はホストの Unix ソケットをバインドマウントで渡せないので、ホストの agent をコンテナへ中継する `/run/host-services/ssh-auth.sock` を使う。どちらの構成も手動で確かめる段階にあり（計画の Phase 11 の手動マイルストーン）、ここに書いたのはその出発点。

```sh
docker run --rm --user "$(id -u)" \
  -v /var/lib/credshim-ssh/agent.sock:/credshim/agent.sock -e SSH_AUTH_SOCK=/credshim/agent.sock \
  -v "$PWD/ssh_config:/etc/ssh/ssh_config.d/credshim.conf:ro" \
  your-dev-image git clone git@github.com:you/repo.git
```

```text
# ssh_config（OpenBSD の nc を使う例。socat なら ProxyCommand socat - PROXY:172.17.0.1:%h:%p,proxyport=8787）
Host github.com
  ProxyCommand nc -X connect -x 172.17.0.1:8787 %h %p
```

## 既存の認証情報からの移行

移行前の鍵やキーはエージェントにすでに読まれた前提で扱い、取り込まずに作り直して古いものを無効にする。`credshim doctor` が残っているものを報告する。

- **SSH。** `credshim ssh keygen` で新しい鍵を作って公開鍵をサーバー（GitHub など）に登録し、`ssh -T` で通ることを確かめてから、古い公開鍵をサーバーから外し、`~/.ssh` の古い秘密鍵を削除する。
- **AWS の静的キー。** IAM で新しいアクセスキーを作って `credshim secret set` で登録し、`~/.aws/credentials` をダミーに書き換える。動作を確かめたら古いキーを無効化（`aws iam update-access-key --status Inactive`）してから削除する。
- **AWS SSO。** CredShim に移す前に `aws sso logout` でキャッシュのトークンを失効させ、`~/.aws/sso/cache` と `~/.aws/cli/cache` を削除する。`~/.aws/config` の `sso_session`・`sso_start_url` のプロファイルは、ダミーの静的キーのプロファイルに置き換える。
- **環境変数。** シェルの設定や `.env` に本物の `AWS_ACCESS_KEY_ID`・`AWS_SECRET_ACCESS_KEY`・`AWS_SESSION_TOKEN` が残っていれば消す。

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
