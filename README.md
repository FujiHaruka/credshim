# CredShim

ローカル開発用のクレデンシャル注入プロキシ。アプリやコーディングエージェントにはダミーのAPIキーだけを持たせ、登録済みホストへ出ていく直前にプロキシが本物へ差し替える。プロキシを専用のOSユーザーで動かせば、エージェントが暴走しても、プロンプトインジェクションで乗っ取られても、本物のキーの値は取り出せない。.env にも、アプリのメモリにも、ログにも、エージェントのコンテキストにも本物は現れない。

- `HTTPS_PROXY` で挟まる MITM プロキシ（HTTP/1.1、HTTP/2、SSE、WebSocket）。SDK は無改造で動く。
- CA を扱えないランタイム向けに、LiteLLM Proxy と同じ使い方の base URL モードもある。
- ダミーは束縛したホスト（とポート、任意でパス）宛てのときだけ差し替え、それ以外は403で止める。レスポンスに本物が現れればダミーに戻す。

守れないものもある。

- **キーを使うことはできる。** エージェントはプロキシ経由で本物のキーを使った要求を送れる。使えるのはルールが許した宛先、パス、操作、回数の範囲だけで、それ以外は403か429になる。
- **開発ユーザーが管理者だと保証は崩れる。** エージェントは開発ユーザー（エージェントが動く OS ユーザー）の権限で、シェルの設定に仕込みをして sudo のパスワードを盗み、root から秘密を読める。開発ユーザーは管理者にしない（下の手順0）。
- **プロキシを開発ユーザーのまま動かす試用の構成では守れない。** エージェントは秘密ストアと設定に手が届く。

設計と脅威モデルは [docs/plan.md](docs/plan.md) と [docs/threat-model.md](docs/threat-model.md)。

## 構成

| 構成 | 用途 | エージェントが本物の値を取り出せるか |
| --- | --- | --- |
| 専用ユーザー（段階B） | 推奨。下の「導入」 | 取り出せない |
| コンテナ分離（段階C） | Bに加え、エージェントの通信をすべてプロキシの判定と監査に通す | 取り出せない |
| 同一ユーザー（段階A） | 試用と動作確認だけ。下の「試用」 | 取り出せる |

## 導入（段階B）

プロキシは専用ユーザーのサービスとして常駐し、設定・秘密・CA鍵はそのユーザーだけが読める `/var/lib/credshim` に置く。開発ユーザーが触れるのは、公開用の CA 証明書とシェル用の変数を置く `/etc/credshim` だけ。

| | Linux | macOS |
| --- | --- | --- |
| 専用ユーザー | `credshim` | `_credshim` |
| インストール先 | `/usr/local/libexec/credshim/credshim` | `/Library/CredShim/bin/credshim` |
| サービス | systemd の `credshim.service` | launchd の `dev.credshim.proxy` |

### 0. 開発ユーザーを管理者にしない

開発ユーザーのプロセスは、その端末に打ち込まれた文字を読める（シェルの設定に `sudo` を横取りする関数やキー入力の記録を仕込める）。開発ユーザーが sudo できるか、その端末で管理者のパスワードを打つと、エージェントは root になって秘密を読める。

- **macOS。** 管理者アカウントを別に作り、普段のアカウントは「このコンピュータの管理を許可」を外して一般ユーザーにする。
- **Linux。** 開発ユーザーを `sudo`・`wheel`・`admin` グループから外す。

以降の「管理者のセッション」は、開発ユーザーが触れない経路を指す。ユーザーの切り替えで入った管理者の GUI セッション、管理者ユーザーでの SSH ログイン、別のコンソールのどれか。管理者のパスワードも、登録する本物のキーも、開発ユーザーの端末には打たない。

### 1. サービスを作る（管理者のセッション）

[Releases](https://github.com/FujiHaruka/credshim/releases) にビルド済みのバイナリがある。`target` は `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`（どちらも glibc 2.35 以降）、`aarch64-apple-darwin`、`x86_64-apple-darwin` のどれか。

```sh
# Linux は user=credshim bin=/usr/local/libexec/credshim/credshim
user=_credshim bin=/Library/CredShim/bin/credshim dev=yourname   # dev は開発ユーザーの名前

version=0.3.0
target=aarch64-apple-darwin
base=https://github.com/FujiHaruka/credshim/releases/download/v$version
curl -fsSLO "$base/credshim-$version-$target.tar.gz"
curl -fsSLO "$base/SHA256SUMS"
grep " credshim-$version-$target.tar.gz\$" SHA256SUMS | shasum -a 256 -c
tar -xzf "credshim-$version-$target.tar.gz"

./credshim service install --print            # 実行する内容を確かめる
sudo ./credshim service install --user "$dev"  # 専用ユーザー、状態、CA、サービスを作り、バイナリを $bin に置く
```

macOS のバイナリは Apple の署名と公証を受けていない。curl で取得すれば Gatekeeper には止められないが、ブラウザでダウンロードした場合は `xattr -d com.apple.quarantine credshim` で隔離属性を外す。ソースからビルドするなら `cargo install --locked --path crates/cli`（Rust が要る）でできたバイナリを使う。どちらでも、`service install` に渡すバイナリは開発ユーザーが書き換えられない場所に置く。

`--user` は開発ユーザーの uid を SSH エージェントの接続許可に書くためのもの。管理者のセッションで sudo すると、省略時は管理者自身が開発ユーザーとみなされる。

### 2. ルールと秘密を登録する（管理者のセッション）

OpenAI を例にする。専用ユーザーとして実行した credshim は、`--config` が無くても `/var/lib/credshim/config.toml` を読む。

```sh
alias svc="sudo -u $user $bin"

# ルールを追加する（ダミーは毎回ランダムに生成される）
$bin preset openai | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null

# 本物のキーを登録する（端末から入力。argv や環境変数は経由しない）
svc secret set openai

# /etc/credshim/keys.env に新しいダミーを載せ、サービスを再起動する
sudo $bin service install --user "$dev"
```

ルールや秘密を変えたら、毎回インストール済みのバイナリで `service install` をもう一度実行する（開発ユーザーが書き換えられるバイナリを sudo で動かさない）。別のバイナリで置き換えるときは `--upgrade` を付ける。

### 3. 使う（開発ユーザーのセッション）

```sh
. /etc/credshim/env                          # プロキシと CA の変数（ダミーキーは入らない）
export PATH="/Library/CredShim/bin:$PATH"    # Linux は /usr/local/libexec/credshim
credshim doctor                              # このシェルのランタイムがプロキシと CA を本当に使っているか
set -a; . /etc/credshim/keys.env; set +a     # 試しにこのシェルでダミーキーも使う

# ストリーミングで叩く（$OPENAI_API_KEY はダミー）
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

`/etc/credshim/env`（`credshim env` の出力）にあるのは `HTTPS_PROXY`・`HTTP_PROXY`（小文字も）、`NO_PROXY`、結合バンドルを指す `SSL_CERT_FILE`・`REQUESTS_CA_BUNDLE`・`CURL_CA_BUNDLE`、開発CAを指す `NODE_EXTRA_CA_CERTS`、`NODE_USE_ENV_PROXY=1`、`aws` コマンド向けに結合バンドルを指す `AWS_CA_BUNDLE`、`[[ssh_key]]` があれば agent のソケットを指す `SSH_AUTH_SOCK`。ダミーを含まない通信はプロキシを素通りするので、どのシェルで読み込んでもよい。

ダミーキーは `/etc/credshim/keys.env`（`credshim env --keys` の出力）に別にある。ルールに `env` がある場合はそのダミーキー（`OPENAI_API_KEY` など）、AWS のルールがちょうど1つならそのダミーの `AWS_ACCESS_KEY_ID` と `AWS_SECRET_ACCESS_KEY`（2つ以上なら `~/.aws/credentials` に書くプロファイルをコメントで出す）。python-dotenv、Node の dotenv、Next.js、Vite などはシェルにある変数を .env で上書きしないので、ダミーキーを全シェルに入れると、リポジトリの .env に書いた別のキーが黙って使われなくなる。AWS も環境変数のキーが `AWS_PROFILE` より優先される。そこでダミーキーはプロジェクトごとに選んで渡す。

- 要るキーの行だけプロジェクトの .env に写す（`KEY='値'` の形なので、そのまま貼れる。ダミーなのでコミットしてもよい）
- direnv なら `.envrc` に `dotenv /etc/credshim/keys.env`
- そのシェルで全部使うなら `set -a; . /etc/credshim/keys.env; set +a`

### 4. 分離を確かめる（開発ユーザーのセッション）

リポジトリの `scripts/stage-b/verify.sh` を開発ユーザーとして実行すると、開発ユーザーが管理者でないこと、設定・秘密（ロックファイルを含む）・CA鍵を読めず書けないこと、サービスの定義とプロキシのバイナリを書き換えられないこと、agent のディレクトリに書けないこと、agent から鍵の一覧を取れること、`/etc/credshim/env` の `AWS_CA_BUNDLE`・`SSH_AUTH_SOCK` が公開の場所を指し、`/etc/credshim/keys.env` のダミーキーを含まないことを確かめる。

### どのコマンドをどちらで実行するか

| 管理者のセッション（`svc` は専用ユーザーとして実行） | 開発ユーザーのセッション |
| --- | --- |
| ルールの追加（`preset` の追記）、`svc secret set`・`svc secret list`、`svc ssh keygen`、`svc aws sso login`・`logout`、`svc tail`、`svc status`、`sudo $bin service install` | `. /etc/credshim/env`、`credshim doctor`、アプリとエージェント |

以下の節のコマンドはこの分け方で書く。

## 試用（段階A）

動作確認のために、プロキシを開発ユーザーのまま動かす構成。この構成ではエージェントから守れない（秘密ストアと設定に開発ユーザーの権限で手が届く）。本物のキーを預けて常用するなら段階Bにする。

設定は `~/.config/credshim/config.toml`（`$XDG_CONFIG_HOME` に従う）、秘密は macOS ではキーチェーン、それ以外では `~/.config/credshim/secrets.age` に入る。

```sh
credshim ca init                                                   # 開発用CAを作る（OS の信頼ストアには入れない）
mkdir -p ~/.config/credshim
credshim preset openai >> ~/.config/credshim/config.toml
credshim secret set openai
credshim run

# 別のシェルで
eval "$(credshim env)"
credshim doctor
credshim env --keys      # ダミーキー。要る行をプロジェクトの .env に写す
```

以下の節を段階Aで試すときは、`svc` を `credshim` に、`$bin preset X | sudo -u $user tee -a /var/lib/credshim/config.toml` を `credshim preset X >> ~/.config/credshim/config.toml` に、`sudo $bin service install` を `credshim run` の再起動に、`. /etc/credshim/env` を `eval "$(credshim env)"` に、`/etc/credshim/keys.env` を `credshim env --keys` の出力に読み替える。

## credshim doctor

`credshim.test` はプロキシ自身が答える予約ホスト名で、DNS には存在しない。そこへ届けば「プロキシ経由」、TLS が通れば「CA を信頼している」、ALPN で h2 か http/1.1 かも分かる。

```text
[ok  ] proxy    credshim.test answered through 127.0.0.1:8787 over h2; its certificate chains to /etc/credshim/ca.pem
[ok  ] env      HTTPS_PROXY=http://127.0.0.1:8787
[ok  ] env      SSL_CERT_FILE=/etc/credshim/bundle.pem includes the CA
[ok  ] curl     via the proxy, CA trusted, h2
[ok  ] python   via the proxy, CA trusted, http/1.1
[ok  ] node     via the proxy, CA trusted, http/1.1
[ok  ] go       via the proxy, CA trusted, h2
[ok  ] ssh      SSH_AUTH_SOCK=/var/lib/credshim-ssh/agent.sock is the credshim agent (rules: github)
[ok  ] openssh  /usr/bin/ssh is OpenSSH 9.9, which sends session-bind
[ok  ] aws      the aws CLI reached credshim.test through the proxy and trusted the CA
[ok  ] files    no private keys in ~/.ssh and no real AWS credentials in ~/.aws or the environment
```

PATH にある curl、python3、node、go をこのシェルの環境のまま実行して確かめる。各言語から叩くワンライナー（requests、httpx、Node の fetch、Go）は `credshim doctor --snippets` で出る。

- **Node。** 組み込みの fetch は `NODE_USE_ENV_PROXY=1`（Node 24 以降）がないと `HTTPS_PROXY` を見ない。古い Node では undici の `EnvHttpProxyAgent` を dispatcher に渡す。doctor はプロキシを素通りした失敗（`ENOTFOUND credshim.test`）を見分けて案内する。
- **Python。** Apple 同梱の `/usr/bin/python3` の ssl モジュールは `SSL_CERT_FILE` を読まない。requests と httpx は `REQUESTS_CA_BUNDLE`・`SSL_CERT_FILE` を自分で読むので動く。
- **Go。** Linux では `SSL_CERT_FILE` を読む。macOS の Go は証明書の検証をキーチェーンに任せ、`SSL_CERT_FILE` を読まない。読むのは Go 1.27 以降でビルドしたプログラムが、go.mod の `go` 行が 1.27 以上のとき、または `GODEBUG=x509sslcertoverrideplatform=1` を付けて実行したときだけ。doctor は go.mod の無い一時ファイルを `go run` するので、macOS ではキーチェーンで信頼させていない限り失敗と報告する。対処は下の「macOS の Go 製ツール」。
- **SSH。** `SSH_AUTH_SOCK` の agent に鍵の一覧を求め、CredShim の鍵（コメント `credshim:<ルール>`）が無ければ別の agent を指していると警告する。PATH の `ssh` が session-bind を送らない OpenSSH 8.9 より前なら報告する。
- **AWS。** PATH の `aws` で `credshim.test` にダミーのキーの要求を送り、プロキシを通って CA を信頼しているかを見る（`AWS_CA_BUNDLE` は信頼ストアを置き換えるので結合バンドルを指す）。
- **残った本物。** `~/.ssh` の秘密鍵、`~/.aws/credentials`・`~/.aws/config` の本物のアクセスキーと `credential_process`・SSO のプロファイル、`~/.aws/sso/cache`・`~/.aws/cli/cache`、環境変数の本物のキーとセッショントークンを、パスとプロファイル名だけで報告する（値は出さない）。移行の手順は下の「既存の認証情報からの移行」。

### macOS の Go 製ツール

開発CAが要るのは、ルールのあるホスト（AWS のルールがあれば `amazonaws.com` 全体）への通信だけ。それ以外のホストへの CONNECT は素のトンネルで中継され、本物の証明書が届くので、Go 製ツールでもそのまま動く。たとえば Terraform のレジストリやプロバイダーのダウンロードは通り、AWS のルールがあるときの AWS プロバイダーの API 呼び出しは開発CAを信頼できずに失敗する。

順に試す。

1. Go 1.27 以降でビルドされたツールなら、`GODEBUG=x509sslcertoverrideplatform=1` を付けて実行する（`GODEBUG` に他の設定があればカンマでつなぐ）。自分のプロジェクトなら go.mod の `go` 行を 1.27 以上にすれば付けなくてよい。
2. ツールが API の接続先を変えられるなら、base URL モードを使う（開発CAが要らない）。
3. どちらもできない場合（古い Go でビルドされた配布バイナリなど）に限り、開発ユーザーのログインキーチェーンで開発CAを信頼させる。管理者権限は要らず、パスワードの確認が出る。

```sh
security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db /etc/credshim/ca.pem
```

キーチェーンで信頼させると、守りの前提が変わる。

- ブラウザを含め、その開発ユーザーのすべてのアプリが開発CAを信頼する。CA 鍵が漏れると、任意のサイトになりすましてそのユーザーの HTTPS 通信を読み書きできる。環境変数で渡すだけなら、影響はその変数を読み込んだプロセスに留まる。
- 段階Bに限る。CA 鍵は専用ユーザーしか読めないので、開発ユーザーの権限で動くエージェントからは取り出せず、漏れるのは専用ユーザーか管理者の権限が奪われたとき。段階Aでは開発ユーザーが CA 鍵を読めるので、エージェントが任意のサイトの証明書を作れてしまう。
- CA を作り直したら、古い CA の信頼を外してから新しいものを入れ直す。外すときは次のとおり。

```sh
security remove-trusted-cert /etc/credshim/ca.pem
security delete-certificate -c "credshim development CA" ~/Library/Keychains/login.keychain-db
```

## base URL モード

CA を設定できないランタイムや、プロキシ変数を見ないクライアント向け。`http://127.0.0.1:8788/openai/...` を `https://api.openai.com/...` に固定で対応させるリバースプロキシで、同じルール（束縛、許可リスト、上限、スクラブ）がそのまま掛かる。`/var/lib/credshim/config.toml` に書く（管理者のセッションで `sudo -u $user vi /var/lib/credshim/config.toml` など）。

```toml
[listen]
addr = "127.0.0.1:8787"
base_url_addr = "127.0.0.1:8788"
```

プリセットのルールには `base_url_prefix = "/openai"` が入っている。

```sh
OPENAI_BASE_URL=http://127.0.0.1:8788/openai/v1 OPENAI_API_KEY=sk-credshim-openai-... python app.py
```

`/etc/credshim/keys.env` には base URL が `# base URL for openai: http://127.0.0.1:8788/openai` のようにコメントで入る。対応表に無いパス、`..` や `%2f` を含むパス、ループバック以外を名乗る Host は拒否する。ダミーを含まない要求はそのまま上流へ転送する（本物は使わない）。

## SSH エージェント

CredShim は ssh-agent としても動く。鍵はプロキシの中で生成して秘密ストアにだけ置き、外へは公開鍵しか出さない。署名するのは、OpenSSH 8.9 以降の `ssh` が送る session-bind で検証できたサーバーのホスト鍵が設定の指紋に含まれ、許可したユーザー名でのログイン要求のときだけ。`ssh -A` の先からの要求、`ssh-keygen -Y sign`（コミット署名）、鍵の追加・削除は拒否する。

```sh
# 管理者のセッション
$bin preset github-ssh | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null   # GitHub のホスト鍵3種、ユーザー git
svc ssh keygen ssh-github                    # 公開鍵を GitHub に登録する
sudo $bin service install --user "$dev"

# 開発ユーザーのセッション
. /etc/credshim/env                          # SSH_AUTH_SOCK=/var/lib/credshim-ssh/agent.sock も入る
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

上限を超えた署名要求は拒否し、監査ログに `reason="limited"` を残す。agent は接続元の uid を確かめ、`client_uids` に無い接続はすぐに閉じる。`service install` は `--user` の uid を新しく作る設定の `client_uids` に書く。設定がすでにあれば、足すべき行を表示する。agent のソケットのディレクトリ `/var/lib/credshim-ssh` は専用ユーザーの所有で、開発ユーザーは書けない。

ProxyJump で踏み台にも同じ鍵で入るなら、踏み台のホスト鍵の指紋も `host_keys` に入れる。既存の `~/.ssh` の鍵は取り込まず、新しい鍵に入れ替えて古い鍵は無効化する。

## AWS（静的アクセスキー）

`~/.aws/credentials` にはダミーのアクセスキーだけを置く。`aws` コマンドはダミーで SigV4 署名した要求をプロキシへ送り、CredShim はアクセスキー ID でルールを引いて本物の認証情報で署名し直す。ダミーのシークレットは送信されないので、何を書いてもよい。

```sh
# 管理者のセッション
$bin preset aws | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null   # ダミーのアクセスキー ID は毎回ランダム
svc secret set aws-access-key-id             # 本物のアクセスキー ID
svc secret set aws-secret-access-key         # 本物のシークレット
sudo $bin service install --user "$dev"

# 開発ユーザーのセッション
. /etc/credshim/env       # 結合バンドルを指す AWS_CA_BUNDLE
set -a; . /etc/credshim/keys.env; set +a   # ダミーの AWS_ACCESS_KEY_ID・AWS_SECRET_ACCESS_KEY
aws sts get-caller-identity
```

AWS のルールが2つ以上あるときは、`/etc/credshim/keys.env` のコメントにあるプロファイルを `~/.aws/credentials` に書く。`AWS_CA_BUNDLE` は信頼ストアを置き換えるので、CA 単体ではなく結合バンドル（開発CA＋システムのルート）を指す。

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
# 管理者のセッション
$bin preset aws-sso | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null   # start_url、region、アカウント、ロールを書き換える
sudo $bin service install --user "$dev"
svc aws sso login sso            # 表示された URL をブラウザで開いてコードを確かめ、承認する

# 開発ユーザーのセッション
. /etc/credshim/env
set -a; . /etc/credshim/keys.env; set +a
aws sts get-caller-identity      # 認証情報はダミー（静的キーと同じ）

# 管理者のセッション
svc aws sso logout sso           # IAM Identity Center のセッションを終わらせ、保存したトークンを消す
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

ログインしていない、または SSO トークンが切れて更新できないときは、要求を上流へ送らずに `CredShimSsoLoginRequired` のエラー（`credshim aws sso login <session>` を促すメッセージ付き）を返し、監査ログに `sso_login_required` を残す。実行中のプロキシは次の AWS の要求で新しいログインを読み込むので、再起動は要らない。`logout` のあとも、プロキシがすでに持っているロール認証情報は取り直しの時期まで使われる。`login` は端末から実行する（stdin が TTY でなければ拒否）。`sudo` は端末をそのまま渡すので、`svc` でも通る。

## 監査ログと状態

`service install` が作る設定には、監査ログ `/var/lib/credshim/audit.jsonl` と状態のソケット `/var/lib/credshim/status.sock` が入っている。

```toml
[audit]
path = "/path/to/audit.jsonl"

[status]
socket = "/path/to/status.sock"
```

管理者のセッションで `svc tail` を実行すると監査ログがライブ表示され、エージェントが今どこを叩いているかが見える。`svc status` はルールごとのカウンタを出す。どちらにも秘密やダミーの値は出ない。どちらも専用ユーザーだけが読める場所にあるので、開発ユーザーからは見えない。

```text
2026-09-30T03:31:37.5Z inject      200 POST https://api.openai.com:443/v1/chat/completions [openai] via connect
2026-09-30T03:31:40.1Z deny        403 POST https://attacker.example:443/collect [openai] via connect
```

## コンテナ分離（段階C）

エージェントとアプリを devcontainer に入れ、プロキシはホストで段階Bのとおり専用ユーザーとして動かす。コンテナの外向きの通信をプロキシだけに絞ると、SSO OIDC やポータルへの直接の接続も含めて、すべてがプロキシの判定と監査を通る。

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

- **SSH。** `svc ssh keygen` で新しい鍵を作って公開鍵をサーバー（GitHub など）に登録し、`ssh -T` で通ることを確かめてから、古い公開鍵をサーバーから外し、`~/.ssh` の古い秘密鍵を削除する。
- **AWS の静的キー。** IAM で新しいアクセスキーを作って `svc secret set` で登録し、`~/.aws/credentials` をダミーに書き換える。動作を確かめたら古いキーを無効化（`aws iam update-access-key --status Inactive`）してから削除する。
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
