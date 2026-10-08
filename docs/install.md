# 推奨構成の導入

プロキシを専用の OS ユーザーのサービスとして常駐させる。設定、秘密、CA の秘密鍵は、そのユーザーだけが読める `/var/lib/credshim` に置く。開発ユーザー（エージェントやアプリが動く普段の OS ユーザー）が触れるのは、公開用の CA 証明書と環境変数のファイルを置く `/etc/credshim` だけ。この分離で、エージェントは本物の値を取り出せなくなる。

| | Linux | macOS |
| --- | --- | --- |
| 専用ユーザー | `credshim` | `_credshim` |
| インストール先 | `/usr/local/libexec/credshim/credshim` | `/Library/CredShim/bin/credshim` |
| サービス | systemd の `credshim.service` | launchd の `dev.credshim.proxy` |
| ログ | `journalctl -u credshim` | `/var/lib/credshim/credshim.log` |

## 2つのセッションを使い分ける

この構成では、コマンドを実行する場所が2つある（下の表の `$bin`・`svc` は [変数を決める](#変数を決める) で定義する）。

- **管理者のセッション。** 開発ユーザーが触れない経路で入った管理者の端末。ユーザーの切り替えで入った管理者の GUI セッション、管理者ユーザーでの SSH ログイン、別のコンソールのどれか。
- **開発ユーザーのセッション。** 普段の作業とエージェントが動く端末。

開発ユーザーのプロセスは、その端末に打ち込まれた文字を読める（シェルの設定に `sudo` を横取りする関数やキー入力の記録を仕込める）。管理者のパスワードも、登録する本物のキーも、開発ユーザーの端末には打たない。

| 管理者のセッション | 開発ユーザーのセッション |
| --- | --- |
| インストールと更新、ルールの追加、本物のキーの登録（`svc secret set`）、SSH の鍵の生成、AWS SSO のログイン、監査ログ（`svc tail`）と状態（`svc status`）の確認、設定の反映（`sudo $bin service reload`） | 環境変数の読み込み（`. /etc/credshim/env`）、`credshim doctor`、アプリとエージェント |

## 1. 開発ユーザーを管理者でなくする

開発ユーザーが sudo できるか、その端末で管理者のパスワードを打つと、エージェントは root になって秘密を読める。

- **macOS。** 管理者アカウントを別に作り、普段のアカウントは「ユーザとグループ」で「このコンピュータの管理を許可」を外して一般ユーザーにする。
- **Linux。** 開発ユーザーを `sudo`・`wheel`・`admin` グループから外す。

## 2. インストールする（管理者のセッション）

`yourname` を開発ユーザーの名前に変えて実行する。

```sh
curl -fsSL https://raw.githubusercontent.com/FujiHaruka/credshim/4406ce71c01c11d4c495af7427f313d8932f1c61/scripts/install.sh | sudo bash -s -- --user yourname
```

実行する前に中身を読むなら、取得してから実行する。

```sh
curl -fsSLO https://raw.githubusercontent.com/FujiHaruka/credshim/4406ce71c01c11d4c495af7427f313d8932f1c61/scripts/install.sh
less install.sh
sudo bash install.sh --user yourname
```

このスクリプトは次のことをする。

1. [Releases](https://github.com/FujiHaruka/credshim/releases) から最新のバイナリと `SHA256SUMS` を、root だけが読み書きできる一時ディレクトリに取得する。取得はプロキシを通らない（プロキシの環境変数を消して実行する）。
2. ハッシュと `--version` を確かめる。
3. そのバイナリの `service install` で、専用ユーザー、設定と CA、サービスを作り、バイナリをインストール先に置いてサービスを起動する。

- `--user` には、sudo した管理者自身ではなく、エージェントが動く開発ユーザーを渡す。その uid を SSH エージェントの接続許可に書く。
- バージョンを固定するなら `--user yourname 0.6.0` のように末尾に付ける。
- URL はスクリプトのコミットに固定してあるので、main に入ったリリース前の変更は届かない。
- ビルド済みバイナリの無い環境（Intel の Mac など）では、リポジトリを clone して `cargo install --locked --path crates/cli` でビルドし、そのバイナリで `sudo ./credshim service install --user yourname` を実行する。そのバイナリは開発ユーザーが書き換えられない場所に置く。

### 変数を決める

以降の手順とほかのページのコマンドは、次の変数と alias を使う。管理者のセッションで、OS に合う方を実行しておく。

```sh
# macOS
user=_credshim bin=/Library/CredShim/bin/credshim
# Linux
user=credshim bin=/usr/local/libexec/credshim/credshim

alias svc="sudo -u $user $bin"   # 専用ユーザーとして credshim を実行する
```

専用ユーザーとして実行した credshim は、`--config` が無くても `/var/lib/credshim/config.toml` を読む。sudo で実行するのは常にインストール先のバイナリ `$bin` にする（開発ユーザーが書き換えられるバイナリを sudo で動かさない）。

## 3. ルールと本物のキーを登録する（管理者のセッション）

OpenAI を例にする。ほかのサービスは [プリセット](../README.md#プリセット) か [ルールを自分で書く](configuration.md#ルールを書く)。

```sh
# ルールを追加する（ダミーのキーは毎回ランダムに作られる）
$bin preset openai | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null

# 本物のキーを登録する（端末から入力する。コマンドライン引数や環境変数は経由しない）
svc secret set openai

# 動いているプロキシに設定を読み直させ、/etc/credshim/keys.env に新しいダミーを載せる
sudo $bin service reload
```

`service reload` は接続を切らずに設定を反映する。何がすぐ反映され、何に再起動が要るかは [設定の反映](configuration.md#設定の反映)。

## 4. 使う（開発ユーザーのセッション）

```sh
. /etc/credshim/env                          # プロキシと CA の環境変数（ダミーのキーは入らない）
export PATH="/Library/CredShim/bin:$PATH"    # Linux は /usr/local/libexec/credshim
credshim doctor                              # このシェルの curl・python・node などがプロキシと CA を使えているか
set -a; . /etc/credshim/keys.env; set +a     # このシェルでダミーのキーを使う

# ストリーミングで呼ぶ（$OPENAI_API_KEY はダミー）
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

`. /etc/credshim/env` はシェルの設定（`~/.zshrc` など）に書いてよい。ダミーを含まない通信はプロキシをそのまま通るので、どのシェルで読み込んでも困らない。

`/etc/credshim/env`（`credshim env` の出力と同じ）が設定する環境変数は次のとおり。

| 変数 | 指す先 |
| --- | --- |
| `HTTPS_PROXY`・`HTTP_PROXY`（小文字も）、`NO_PROXY` | プロキシ |
| `SSL_CERT_FILE`・`REQUESTS_CA_BUNDLE`・`CURL_CA_BUNDLE`・`AWS_CA_BUNDLE` | 結合バンドル（開発用の CA とシステムのルート証明書をまとめたファイル） |
| `NODE_EXTRA_CA_CERTS` | 開発用の CA |
| `NODE_USE_ENV_PROXY=1` | Node の組み込みの fetch に `HTTPS_PROXY` を使わせる |
| `SSH_AUTH_SOCK` | CredShim の SSH エージェント（SSH の鍵を登録したときだけ） |

### ダミーのキーをプロジェクトに渡す

ダミーのキーは `/etc/credshim/keys.env`（`credshim env --keys` の出力と同じ）に別に置いてある。中身は次のとおり。

- ルールに `env` があれば、そのダミーのキー（`OPENAI_API_KEY` など）
- AWS のルールがちょうど1つなら、そのダミーの `AWS_ACCESS_KEY_ID` と `AWS_SECRET_ACCESS_KEY`（2つ以上なら、`~/.aws/credentials` に書くプロファイルをコメントで出す）
- base URL モードを使うなら、その URL（コメント）

ダミーのキーをすべてのシェルに入れるのは勧めない。python-dotenv、Node の dotenv、Next.js、Vite などはシェルにある変数を .env で上書きしないので、リポジトリの .env に書いた別のキーが黙って使われなくなる。AWS も環境変数のキーが `AWS_PROFILE` より優先される。プロジェクトごとに、次のどれかで渡す。

- 要る行だけプロジェクトの .env に写す（`KEY='値'` の形なのでそのまま貼れる。ダミーなのでコミットしてもよい）
- direnv なら `.envrc` に `dotenv /etc/credshim/keys.env`
- そのシェルで全部使うなら `set -a; . /etc/credshim/keys.env; set +a`

## 5. 分離を確かめる（開発ユーザーのセッション）

リポジトリの `scripts/stage-b/verify.sh` を開発ユーザーとして実行すると、次のことを確かめる。

- 開発ユーザーが管理者でない
- 設定、秘密（ロックファイルを含む）、CA の秘密鍵を読めず、書けない
- サービスの定義とプロキシのバイナリを書き換えられない
- SSH エージェントのディレクトリに書けず、エージェントから鍵の一覧は取れる
- `/etc/credshim/env` の `AWS_CA_BUNDLE`・`SSH_AUTH_SOCK` が公開の場所を指し、ダミーのキーを含まない

## 6. 既存の認証情報を入れ替える

CredShim を入れる前から手元にあった鍵やキーは、エージェントにすでに読まれた前提で扱う。取り込まずに新しく作り直し、古いものを無効にする。`credshim doctor` が、手元に残っているものを値を出さずに報告する。

- **API キー。** 発行元で新しいキーを作って `svc secret set` で登録し、.env やシェルの設定に残った古いキーを消して、発行元で無効にする。お試し構成で登録したキーも同じように作り直す。
- **SSH。** `svc ssh keygen` で新しい鍵を作って公開鍵をサーバー（GitHub など）に登録し、`ssh -T` で通ることを確かめてから、古い公開鍵をサーバーから外し、`~/.ssh` の古い秘密鍵を消す。手順は [SSH エージェント](ssh.md)。
- **AWS の静的キー。** IAM で新しいアクセスキーを作って `svc secret set` で登録し、`~/.aws/credentials` をダミーに書き換える。動作を確かめたら、古いキーを無効にして（`aws iam update-access-key --status Inactive`）から消す。
- **AWS SSO。** CredShim に移す前に `aws sso logout` でキャッシュのトークンを失効させ、`~/.aws/sso/cache` と `~/.aws/cli/cache` を消す。`~/.aws/config` の `sso_session`・`sso_start_url` のプロファイルは、ダミーの静的キーのプロファイルに置き換える。
- **環境変数。** シェルの設定や .env に本物の `AWS_ACCESS_KEY_ID`・`AWS_SECRET_ACCESS_KEY`・`AWS_SESSION_TOKEN` が残っていれば消す。

## 新しいリリースに更新する（管理者のセッション）

```sh
$bin service upgrade --print        # 実行する内容を確かめる
sudo $bin service upgrade           # 最新のリリースへ。sudo $bin service upgrade 0.6.0 のようにバージョンも指定できる
```

インストールの1行と同じスクリプトを使う。すでにそのバージョンなら何もせず、違えば取得したバイナリで `$bin` を置き換えてサービスを再起動する（処理中の接続は切れる）。設定、秘密、CA はそのまま使う。0.5.0 以前には `service upgrade` が無いので、インストールの1行をもう一度実行する。

手元でビルドしたバイナリに置き換えるときは、そのバイナリで `sudo ./credshim service install --upgrade` を実行する。

## アンインストールする（管理者のセッション）

アンインストールのコマンドは無いので、インストールが作ったものを手で消す。`/var/lib/credshim` には本物のキーと CA の秘密鍵が入っているので、残す理由が無ければ消す。

```sh
# macOS
sudo launchctl bootout system/dev.credshim.proxy
sudo rm /Library/LaunchDaemons/dev.credshim.proxy.plist
sudo rm -rf /Library/CredShim /etc/credshim /var/lib/credshim /var/lib/credshim-ssh
sudo dscl . -delete /Users/_credshim
sudo dscl . -delete /Groups/_credshim
```

```sh
# Linux
sudo systemctl disable --now credshim.service
sudo rm /etc/systemd/system/credshim.service
sudo systemctl daemon-reload
sudo rm -rf /usr/local/libexec/credshim /etc/credshim /var/lib/credshim /var/lib/credshim-ssh
sudo userdel credshim
```

開発ユーザーのシェルの設定に書いた `. /etc/credshim/env` と、プロジェクトの .env に写したダミーのキーも消す。macOS のキーチェーンで開発用の CA を信頼させていたら、その信頼も外す（[macOS の Go 製ツール](troubleshooting.md#macos-の-go-製ツール)）。

## お試し構成で読み替える

ほかのページの手順は推奨構成で書いてある。お試し構成で試すときは次のように読み替える。

| 推奨構成 | お試し構成 |
| --- | --- |
| `svc` | `credshim` |
| `$bin preset X \| sudo -u $user tee -a /var/lib/credshim/config.toml` | `credshim preset X >> ~/.config/credshim/config.toml` |
| `/var/lib/credshim/config.toml` | `~/.config/credshim/config.toml` |
| `sudo $bin service reload` | `pkill -HUP -f 'credshim run'`（結果は `credshim run` の端末に出る） |
| `sudo $bin service install` | `credshim run` の再起動 |
| `. /etc/credshim/env` | `eval "$(credshim env)"` |
| `/etc/credshim/keys.env` | `credshim env --keys` の出力 |
