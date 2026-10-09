# うまく動かないとき

まず開発ユーザーのセッションで `credshim doctor` を実行する。拒否されたリクエストの理由は、管理者のセッションの `credshim-svc tail`（お試し構成では `credshim run` の端末）で見る。`credshim-svc` は [導入手順の変数](install.md#変数を決める) を参照。

## credshim doctor

このシェルの環境のまま、PATH にある curl、python3、node、go、ssh、aws がプロキシを通り、開発用の CA を信頼できているかを確かめる。

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

`credshim.test` はプロキシ自身が答える予約ホスト名で、DNS には存在しない。そこへ届けばプロキシを通っている、TLS が通れば CA を信頼している、と分かる。各言語から同じことを確かめるワンライナー（requests、httpx、Node の fetch、Go）は `credshim doctor --snippets` で表示できる。

失敗したときに見るところ：

- **Node。** 組み込みの fetch は `NODE_USE_ENV_PROXY=1`（Node 24 以降）がないと `HTTPS_PROXY` を見ない。古い Node では undici の `EnvHttpProxyAgent` を dispatcher に渡す。プロキシを通らずに失敗した（`ENOTFOUND credshim.test`）ときは、doctor がそう案内する。
- **Python。** Apple 同梱の `/usr/bin/python3` の ssl モジュールは `SSL_CERT_FILE` を読まない。requests と httpx は `REQUESTS_CA_BUNDLE`・`SSL_CERT_FILE` を自分で読むので動く。
- **Go。** Linux では `SSL_CERT_FILE` を読む。macOS では読まないことが多い（下の [macOS の Go 製ツール](#macos-の-go-製ツール)）。doctor は go.mod の無い一時ファイルを `go run` するので、macOS ではキーチェーンで CA を信頼させていない限り失敗と報告する。
- **SSH。** `SSH_AUTH_SOCK` の先のエージェントに鍵の一覧を求め、CredShim の鍵（コメントが `credshim:<ルール名>`）が無ければ、別のエージェントを指していると警告する。PATH の `ssh` が OpenSSH 8.9 より前（session-bind を送らない）なら報告する。
- **AWS。** PATH の `aws` で `credshim.test` にダミーのキーのリクエストを送り、プロキシを通って CA を信頼しているかを見る。`AWS_CA_BUNDLE` は信頼ストアを置き換えるので、結合バンドルを指している必要がある。
- **残った本物（files）。** `~/.ssh` の秘密鍵、`~/.aws/credentials`・`~/.aws/config` の本物のアクセスキーと `credential_process`・SSO のプロファイル、`~/.aws/sso/cache`・`~/.aws/cli/cache`、環境変数の本物のキーとセッショントークンを、パスとプロファイル名だけで報告する（値は出さない）。片付け方は [既存の認証情報を入れ替える](install.md#6-既存の認証情報を入れ替える)。

## 403 や 429 が返る

CredShim が止めたリクエストは、上流へは何も送らずに 403 か 429 を返す。ボディは空（AWS だけは AWS の形式のエラー）なので、理由は監査ログで見る。

| 監査ログの判定 | 状態 | 意味と対処 |
| --- | --- | --- |
| `deny` | 403 | ダミーが、そのルールの宛先ではないホストへ送られた。平文の HTTP で送った場合や、クラウドのメタデータのアドレスへの接続もこれ。宛先が正しいならルールの `host`・`port`・`path_prefix` を直す |
| `not_allowed` | 403 | 宛先は合っているが、`allow_methods`・`allow_paths`（AWS は `operations`）の外。必要ならルールの許可リストに足す |
| `limited` | 429 | `limits` の上限を超えた。`credshim-svc status` でカウンタを見る |
| `misdirected` | 421 | 接続先と、リクエストの中の Host が食い違う |
| `error` | 500・502 | 差し替えに失敗した（ルールの秘密が登録されていない、空など）か、AWS SSO のロールの認証情報を取れなかった。理由はサービスのログに出る |
| `tunnel` | 502 | ルールの無いホストへの CONNECT で、プロキシが上流へ TCP で繋げなかった（名前解決できない、接続を拒否された、タイムアウト）。理由はサービスのログに出る |

ルールのあるホストなのに `inject` も `deny` も出ず、アプリ側で TLS の証明書エラーになるときは、そのアプリがプロキシの環境変数か CA を読んでいない。`credshim doctor` で確かめる。

## macOS の Go 製ツール

開発用の CA が要るのは、ルールのあるホスト（AWS のルールがあれば `amazonaws.com` 全体）への通信だけ。それ以外のホストへの通信は中身を見ずに中継し、本物の証明書が届くので、Go 製ツールでもそのまま動く。たとえば Terraform のレジストリやプロバイダーのダウンロードは通るが、AWS のルールがあるときの AWS プロバイダーの API 呼び出しは、開発用の CA を信頼できずに失敗する。

macOS の Go は証明書の検証をキーチェーンに任せ、`SSL_CERT_FILE` を読まない。読むのは、Go 1.27 以降でビルドしたプログラムが go.mod の `go` 行が 1.27 以上のとき、または `GODEBUG=x509sslcertoverrideplatform=1` を付けて実行したときだけ。

次の順に試す。

1. Go 1.27 以降でビルドされたツールなら、`GODEBUG=x509sslcertoverrideplatform=1` を付けて実行する（`GODEBUG` にほかの設定があればカンマでつなぐ）。自分のプロジェクトなら、go.mod の `go` 行を 1.27 以上にすれば付けなくてよい。
2. ツールが API の接続先を変えられるなら、[base URL モード](configuration.md#base-url-モード) を使う（開発用の CA が要らない）。
3. どちらもできない場合（古い Go でビルドされた配布バイナリなど）に限り、開発ユーザーのログインキーチェーンで開発用の CA を信頼させる。管理者権限は要らず、パスワードの確認が出る。

```sh
security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db /etc/credshim/ca.pem
```

キーチェーンで信頼させると、守りの前提が変わる。

- ブラウザを含め、その開発ユーザーのすべてのアプリが開発用の CA を信頼する。CA の秘密鍵が漏れると、任意のサイトになりすまして、そのユーザーの HTTPS 通信を読み書きできる。環境変数で渡すだけなら、影響はその変数を読み込んだプロセスに留まる。
- 推奨構成に限る。CA の秘密鍵は専用ユーザーしか読めないので、開発ユーザーの権限で動くエージェントからは取り出せず、漏れるのは専用ユーザーか管理者の権限が奪われたときだけ。お試し構成では開発ユーザーが CA の秘密鍵を読めるので、エージェントが任意のサイトの証明書を作れてしまう。
- CA を作り直したら、古い CA の信頼を外してから新しいものを入れ直す。

```sh
security remove-trusted-cert /etc/credshim/ca.pem
security delete-certificate -c "credshim development CA" ~/Library/Keychains/login.keychain-db
```
