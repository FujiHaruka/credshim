# CredShim

コーディングエージェントやアプリに本物の API キーを渡さずに開発するための、ローカルのクレデンシャル注入プロキシ。

アプリやエージェントが持つのはダミーのキーだけ。リクエストが登録済みの宛先へ出ていく直前に、CredShim がダミーを本物に差し替える。.env にも、アプリのメモリにも、ログにも、エージェントのコンテキストにも本物は現れない。

```text
アプリ／エージェント ──（ダミーのキー）──▶ CredShim ──（本物のキー）──▶ api.openai.com
                                            │
                                            └─ ダミーが登録外の宛先へ向かえば 403 で止める
```

- `HTTPS_PROXY` で間に入る HTTPS プロキシ。HTTP/1.1、HTTP/2、SSE、WebSocket を中継し、SDK は改造なしで動く。
- プロキシの環境変数や独自の CA を扱えないクライアント向けに、API の接続先（base URL）を差し替えて使うモードもある。
- API キーのほかに、SSH の鍵（ssh-agent として動く）、AWS のアクセスキーと IAM Identity Center（SSO）、OAuth のトークンも同じ考え方で扱う。

## 守れるもの、守れないもの

プロキシを専用の OS ユーザーで動かす構成（推奨構成）なら、エージェントが暴走しても、プロンプトインジェクションで乗っ取られても、本物のキーの値は取り出せない。

ただし次のものは守れない。

- **キーを使うこと。** エージェントはプロキシ経由で、本物のキーを使ったリクエストを送れる。送れるのはルールで許した宛先、パス、操作、回数の範囲だけで、それ以外は 403 か 429 になる。
- **開発ユーザーが管理者のとき。** エージェントは開発ユーザー（エージェントが動く普段の OS ユーザー）の権限で、シェルの設定に仕込みをして sudo のパスワードを盗み、root になって秘密を読める。開発ユーザーは管理者にしない。
- **お試し構成。** プロキシを開発ユーザーのまま動かすので、エージェントは秘密ストアと設定に手が届く。

詳しくは [脅威モデル](docs/threat-model.md)。

## 対応環境

- ビルド済みバイナリ：macOS（Apple シリコン）、Linux（x86_64・aarch64、glibc 2.35 以降）
- それ以外（Intel の Mac など）：ソースからビルドする（Rust が要る）

## 構成を選ぶ

| 構成 | 向いている用途 | エージェントが本物の値を取り出せるか |
| --- | --- | --- |
| [お試し構成](#お試し構成) | 5分で動きを見る | 取り出せる |
| [推奨構成](docs/install.md) | 本物のキーを預けて普段使う。プロキシを専用の OS ユーザーで動かす | 取り出せない |
| [コンテナ分離](docs/container.md) | 推奨構成に加え、エージェントの通信をすべてプロキシの判定と監査に通す | 取り出せない |

## お試し構成

> **この構成はエージェントから守れない。** プロキシが開発ユーザーのまま動くので、エージェントは秘密ストアと設定を読み書きできる。動きを確かめるためだけに使い、ここで登録したキーは推奨構成に移るときに作り直す。

バイナリを取得する。

```sh
v=0.6.1
target=aarch64-apple-darwin   # Linux は x86_64-unknown-linux-gnu か aarch64-unknown-linux-gnu
curl -fsSL "https://github.com/FujiHaruka/credshim/releases/download/v$v/credshim-$v-$target.tar.gz" | tar -xzf - credshim
mkdir -p ~/.local/bin && mv credshim ~/.local/bin/   # PATH の通った場所に置く
```

OpenAI のキーを登録してプロキシを起動する。

```sh
credshim ca init                                            # 開発用の CA を作る（OS の信頼ストアには入れない）
mkdir -p ~/.config/credshim
credshim preset openai >> ~/.config/credshim/config.toml    # OpenAI 向けのルールを追加する
credshim secret set openai                                  # 本物のキーを端末から入力する
credshim run                                                # プロキシを起動する（このシェルは占有される）
```

別のシェルで使う。

```sh
eval "$(credshim env)"          # プロキシと CA の環境変数を設定する
credshim doctor                 # curl・python・node などがプロキシと CA を使えているか確かめる
set -a; eval "$(credshim env --keys)"; set +a   # ダミーのキー（OPENAI_API_KEY など）を設定する

curl https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}'
```

`$OPENAI_API_KEY` はダミーだが、応答は本物のキーで送ったときと同じになる。`credshim run` の端末には、差し替えたリクエストが記録される。

設定は `~/.config/credshim/config.toml`（`$XDG_CONFIG_HOME` に従う）、秘密は macOS ではキーチェーン（サービス名 `credshim`）、それ以外では `~/.config/credshim/secrets.age` に入る。やめるときは `credshim run` を止め、`~/.config/credshim` を消す。macOS ではキーチェーンの項目も消す（`security delete-generic-password -s credshim -a openai`）。

## 推奨構成

本物のキーを預けて普段使うなら、プロキシを専用の OS ユーザーのサービスとして動かす。おおまかな流れは次のとおり。

1. 開発ユーザーを管理者でなくする
2. 管理者のセッションでインストールの1行を実行し、専用ユーザーとサービスを作る
3. 管理者のセッションでルールと本物のキーを登録する
4. 開発ユーザーのセッションで環境変数を読み込んで使う

手順は [docs/install.md](docs/install.md)。

## プリセット

よく使うサービスのルールは `credshim preset <名前>` で生成できる。ダミーのキーは生成のたびにランダムに作られる。

| 名前 | 宛先 | ダミーを入れる環境変数 | 説明 |
| --- | --- | --- | --- |
| `openai` | `api.openai.com` | `OPENAI_API_KEY` | |
| `anthropic` | `api.anthropic.com` | `ANTHROPIC_API_KEY` | |
| `gemini` | `generativelanguage.googleapis.com` | `GEMINI_API_KEY` | |
| `github-ssh` | `github.com`（SSH） | | [SSH エージェント](docs/ssh.md) |
| `aws` | AWS の各サービス | `AWS_ACCESS_KEY_ID` など | [AWS](docs/aws.md) |
| `aws-sso` | AWS の各サービス | `AWS_ACCESS_KEY_ID` など | [AWS（SSO）](docs/aws.md#aws-iam-identity-centersso) |

それ以外の API は、ルールを自分で書いて登録する（[設定](docs/configuration.md#ルールを書く)）。

## コーディングエージェントで使う

エージェントを起動するシェルで、プロキシの環境変数とダミーのキーを読み込んでから起動する。エージェントが実行するコマンドやアプリは、その環境変数を引き継ぐ。

```sh
. /etc/credshim/env                              # 推奨構成。お試し構成なら eval "$(credshim env)"
set -a; . /etc/credshim/keys.env; set +a         # ダミーのキー。お試し構成なら set -a; eval "$(credshim env --keys)"; set +a
```

ルールのある宛先への通信は開発用の CA で中継するので、そこへ通信するエージェント自身も、この環境変数で CA を信頼している必要がある。ダミーを含まない通信は、本物のキーを使わずそのまま中継される。

ダミーのキーをすべてのシェルに入れると、プロジェクトの .env に書いた別のキーが使われなくなることがある。プロジェクトごとの渡し方は [docs/install.md](docs/install.md#ダミーのキーをプロジェクトに渡す)。

## ドキュメント

- [推奨構成の導入](docs/install.md)：インストール、更新、アンインストール、既存の認証情報からの移行
- [設定](docs/configuration.md)：ルールの書き方、設定の反映、base URL モード、OAuth、監査ログ
- [AWS](docs/aws.md)：静的アクセスキーと IAM Identity Center（SSO）
- [SSH エージェント](docs/ssh.md)
- [コンテナ分離](docs/container.md)
- [うまく動かないとき](docs/troubleshooting.md)：`credshim doctor`、403・429 の調べ方、macOS の Go 製ツール
- [脅威モデル](docs/threat-model.md)
- [開発](docs/development.md)

## ライセンス

[MIT](LICENSE-MIT) または [Apache-2.0](LICENSE-APACHE) のどちらか。
