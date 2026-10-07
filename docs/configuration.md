# 設定

設定ファイルは TOML。推奨構成では `/var/lib/credshim/config.toml`（専用ユーザーだけが読み書きできる）、お試し構成では `~/.config/credshim/config.toml`。

このページのコマンドは推奨構成で書いてあり、`$user`・`$bin`・`svc` は [導入手順の変数](install.md#変数を決める) を使う。お試し構成では [読み替え](install.md#お試し構成で読み替える) のとおりに読む。設定ファイルの編集は、管理者のセッションで `sudo -u $user vi /var/lib/credshim/config.toml` などで行う。

## ルールを書く

ルールは「どのダミーを、どの宛先へ向かうときだけ、どの本物に差し替えるか」を決める。プリセットの無い API は、ルールを自分で書く。

```toml
[[rule]]
name = "stripe"
host = "api.stripe.com"
secret = "stripe"                                  # 秘密ストアに登録する名前
dummy = "sk_credshim_stripe_0123456789abcdef"       # アプリに渡すダミー（自分でランダムな文字列にする）
env = "STRIPE_API_KEY"                             # keys.env にダミーを載せる変数名
inject = { header = "authorization" }              # ダミーを探して差し替える場所
allow_methods = ["GET", "POST"]
allow_paths = ["/v1/charges", "/v1/customers"]
limits = { per_minute = 60, per_day = 1000 }
```

書いたら本物のキーを登録して反映する。

```sh
svc secret set stripe
sudo $bin service reload
```

| 項目 | 必須 | 意味 |
| --- | --- | --- |
| `name` | ○ | ルールの名前。英数字と `.`・`_`・`-` |
| `host` | ○ | 宛先のホスト名（小文字、ポートなし） |
| `port` | | 宛先のポート。既定は 443 |
| `path_prefix` | | 宛先をこのパスの下に絞る（`/v1` なら `/v1/...` だけ） |
| `secret` | ○ | 本物の値を入れる秘密ストアの名前。`svc secret set <名前>` で登録する |
| `dummy` | ○ | アプリに渡すダミー。24〜256文字の英数字と `-`・`.`・`_`・`~`。ほかのルールのダミーを含んだり、含まれたりしてはいけない |
| `inject` | ○ | ダミーを探して差し替える場所。`header = "<ヘッダー名>"`（値の中のダミーだけを置き換えるので `Bearer <ダミー>` の形でよい）、`query = "<パラメーター名>"`、`basic = true`（Basic 認証）のうち1つ以上 |
| `allow_methods` | | 許可する HTTP メソッド。省略するとすべて |
| `allow_paths` | | 許可するパス。前方一致で、パスの区切りの単位で照合する（`/v1/charges` は `/v1/charges/ch_1` に一致し、`/v1/chargesX` には一致しない）。省略するとすべて |
| `limits` | | 回数の上限。`per_minute`・`per_day`・`concurrent`（同時に処理中のリクエスト数）。省略すると無制限 |
| `env` | | `keys.env` にダミーを載せる環境変数名。`_KEY`・`_TOKEN`・`_SECRET`・`_PASSWORD` のどれかで終わる名前に限る |
| `base_url_prefix` | | [base URL モード](#base-url-モード) で使う接頭辞 |

### ルールの効き方

- ダミーを本物に差し替えるのは、実際の接続先が `host`・`port`（と `path_prefix`）に一致し、その宛先の TLS 証明書をシステムの信頼ストアで検証できたときだけ。平文の HTTP には差し替えない。
- ダミーが別の宛先に向かえば、差し替えずに 403 を返す。上流には何も送らない。
- 宛先は合っていても、`allow_methods`・`allow_paths` の外なら 403、`limits` を超えれば 429。どちらも上流には送らない。
- 応答に本物の値が含まれていれば、クライアントに返す前にダミーに戻す（スクラブ）。`[scrub] enabled = false` で止められるが、止めない方がよい。
- ルールの無いホストへの通信は、中身を見ずにそのまま中継する。開発用の CA が要るのは、ルールのあるホストへの通信だけ。

## 設定の反映

ルールや秘密を変えたら、管理者のセッションで `sudo $bin service reload` を実行する。プロセスは止まらない。

- 処理中のリクエスト（ストリーミングの応答や WebSocket を含む）は、読み直す前の設定のまま最後まで流れる。次のリクエストからは新しい設定を使う。開いたままの接続の上の次のリクエストも同じ。
- 上限のカウンタは引き継ぐ。
- `service reload` は先に、専用ユーザーとして設定と秘密を読めるかを確かめ（`run --check`）、読めなければ何も変えずに失敗する。プロキシ側で読み直しに失敗したときも、動いている設定のまま続ける。結果はサービスのログ（macOS は `/var/lib/credshim/credshim.log`、Linux は `journalctl -u credshim`）に出る。
- ルールの無かったホストへの開いたままの接続は中身を見ずに中継しているので、そのホストに足したルールは、クライアントが接続し直すまで効かない。

読み直しで反映される設定と、再起動が要る設定は次のとおり。再起動が要る設定を変えて reload すると、ログに警告が出る。

| すぐ反映される | 再起動が要る（`sudo $bin service install`。処理中の接続は切れる） |
| --- | --- |
| `[[rule]]`、`[scrub]`、AWS（`[aws]`、`[[aws_key]]`、`[[aws_sso_session]]`、`[[aws_sso_role]]`） | `[listen]`、`[ca]`、`[secrets]`、`[audit]`、`[status]`、SSH（`[ssh]`、`[[ssh_key]]`）、OAuth（`[[oauth]]`、`[vault]`、`[limits]`） |

## base URL モード

プロキシの環境変数や独自の CA を扱えないクライアント向けのモード。`http://127.0.0.1:8788/openai/...` を `https://api.openai.com/...` に決まった対応で転送するリバースプロキシで、ルール（宛先、許可リスト、上限、スクラブ）はそのまま掛かる。開発用の CA は要らない。

```toml
[listen]
addr = "127.0.0.1:8787"
base_url_addr = "127.0.0.1:8788"
```

`[listen]` を変えたら `sudo $bin service install` で再起動する。プリセットのルールには `base_url_prefix`（`openai` なら `/openai`）が入っている。

```sh
OPENAI_BASE_URL=http://127.0.0.1:8788/openai/v1 OPENAI_API_KEY=sk-credshim-openai-... python app.py
```

`/etc/credshim/keys.env` には、使える base URL が `# base URL for openai: http://127.0.0.1:8788/openai` のようにコメントで入る。

- 対応表に無いパス、`..` や `%2f` を含むパス、ループバック以外を名乗る Host は拒否する。
- ダミーを含まないリクエストはそのまま上流へ転送する（本物は使わない）。

## OAuth

OAuth のクライアントシークレットと、発行されたアクセストークン・リフレッシュトークンも、アプリにはダミーだけを見せる。

- アプリはダミーのクライアントシークレットでトークンエンドポイントを呼ぶ。プロキシが本物に差し替えて送る。
- トークンエンドポイントの応答のアクセストークンとリフレッシュトークンは、プロキシがダミーに置き換えてアプリに返す。本物は暗号化した保管庫（`[vault]`）に置く。
- アプリがダミーのアクセストークンを `Authorization` ヘッダーに入れて `resource_hosts` の API を呼ぶと、本物に差し替える。リフレッシュと失効（revoke）のリクエストも同じ。

```toml
[[oauth]]
name = "example"
token_endpoint = "https://oauth.example.com/token"
revoke_endpoint = "https://oauth.example.com/revoke"     # 省略できる
client_id = "your-client-id"
client_secret = { secret = "example-client", dummy = "credshim-example-client-0123456789abcdef" }
client_auth = "client_secret_post"                      # Basic 認証で送るなら "client_secret_basic"
resource_hosts = ["api.example.com"]                    # アクセストークンを差し替える API のホスト

[limits]
max_token_body_bytes = 65536                            # 省略できる。トークンエンドポイントで読むボディの上限（既定 64KiB）
```

本物のクライアントシークレットは `svc secret set example-client` で登録する。保管庫の暗号化の鍵は、初めて起動したときに秘密ストアに作られる。OAuth の設定を変えたら `sudo $bin service install` で再起動する。

## 秘密ストア

本物の値を置く場所は `[secrets]` で選ぶ。

| `backend` | 置き場所 | 既定になる構成 |
| --- | --- | --- |
| `age-file` | age で暗号化したファイル（`path`）。鍵は既定で同じ場所の `.key` | 推奨構成（`/var/lib/credshim/secrets.age`）、お試し構成の Linux |
| `keychain` | macOS のキーチェーン（サービス名は既定で `credshim`） | お試し構成の macOS |
| `command` | 外部コマンドの標準出力（`command = ["...", "{name}"]`、`{name}` は秘密の名前）。読み取り専用で、登録は外部のツールで行う | |

`svc secret list` で、登録した秘密の名前と更新時刻を見られる（値は出ない）。値を取り出すコマンドは無い。

## 監査ログと状態

`service install` が作る設定には、監査ログ `/var/lib/credshim/audit.jsonl` と状態のソケット `/var/lib/credshim/status.sock` が入っている。

```toml
[audit]
path = "/var/lib/credshim/audit.jsonl"

[status]
socket = "/var/lib/credshim/status.sock"
```

- `svc tail` は監査ログをライブで表示する。エージェントがいまどこを呼んでいるか、何が拒否されたかが分かる。
- `svc status` はルールごとのカウンタを表示する。

どちらにも秘密やダミーの値は出ない。どちらも専用ユーザーだけが読める場所にあるので、開発ユーザーからは見えない。

```text
2026-09-30T03:31:37.5Z inject      200 POST https://api.openai.com:443/v1/chat/completions [openai] via connect
2026-09-30T03:31:40.1Z deny        403 POST https://attacker.example:443/collect [openai] via connect
```
