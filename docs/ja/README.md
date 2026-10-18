# CredShim

コーディングエージェントやアプリに本物の API キーを渡さずに開発するための、ローカルのクレデンシャル注入プロキシ。

ドキュメントサイト：<https://fujiharuka.github.io/credshim/ja/>（[English](../../README.md)）

アプリやエージェントが持つのはダミーのキーだけ。リクエストが登録済みの宛先へ出ていく直前に、CredShim がダミーを本物に差し替える。.env にも、アプリのメモリにも、ログにも、エージェントのコンテキストにも本物は現れない。

```text
アプリ／エージェント ──（ダミーのキー）──▶ CredShim ──（本物のキー）──▶ api.openai.com
                                            │
                                            └─ ダミーが登録外の宛先へ向かえば 403 で止める
```

- アプリからは `HTTPS_PROXY` で使う HTTPS プロキシで、アプリは独自の開発用 CA を環境変数で信頼する。SDK は改造なしで動く。
- [プリセット](#プリセット) は OpenAI、Anthropic、Gemini、GitHub、AWS（IAM Identity Center を含む）に対応する。ssh-agent としても動き、OAuth のトークンも扱う。それ以外の API はルールを自分で書く。

## 構成を選ぶ

| 構成 | 向いている用途 | 必要なこと | エージェントが本物の値を取り出せるか |
| --- | --- | --- | --- |
| [お試し構成](#お試し構成) | 5分で動きを見る | バイナリ1つを普段の OS ユーザーで動かす | 取り出せる |
| [推奨構成](#推奨構成) | 本物のキーで日常的に使う | プロキシを専用の OS ユーザーで動かす。普段の OS ユーザー（エージェントやアプリが動く開発ユーザー）を管理者にせず、キーは別の管理者アカウントから登録する | 取り出せない |
| [コンテナ分離](container.md) | 推奨構成に加え、エージェントの通信をすべてプロキシの判定と監査に通す | 推奨構成で、エージェントをコンテナで動かす | 取り出せない |

ビルド済みのバイナリは macOS（Apple シリコン）と Linux（x86_64・aarch64、glibc 2.35 以降）向けにある。それ以外（Intel の Mac など）では Rust でソースからビルドする。

## 守れるもの、守れないもの

推奨構成なら、エージェントが暴走しても、プロンプトインジェクションで乗っ取られても、本物のキーの値は取り出せない。

ただし次のものは守れない。

- **キーを使うこと。** エージェントはプロキシ経由で、本物のキーを使ったリクエストを送れる。送れるのはルールで許した宛先、パス、操作、回数の範囲だけで、それ以外は 403 か 429 になる。
- **開発ユーザーが管理者のとき。** エージェントは開発ユーザーの権限で動く。そのユーザーが root になれるなら、エージェントはシェルの設定に仕込みをして sudo のパスワードを盗み、秘密を読める。

詳しくは [脅威モデル](threat-model.md)。

## お試し構成

> **この構成はエージェントから守れない。** プロキシが開発ユーザーのまま動くので、エージェントは秘密ストアと設定を読み書きできる。動きを確かめるためだけに使い、ここで登録したキーは推奨構成に移るときに作り直す。

バイナリを取得する。

```sh
v=0.8.1
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

やめるときは `credshim run` を止め、`~/.config/credshim` を消す。macOS ではキーチェーンの項目も消す（`security delete-generic-password -s credshim -a openai`）。

## 推奨構成

本物のキーで日常的に使うなら、プロキシを専用の OS ユーザーのサービスとして動かす。おおまかな流れは次のとおり。

1. 開発ユーザーを管理者でなくする
2. 管理者のセッションでインストールの1行を実行し、専用ユーザーとサービスを作る
3. 管理者のセッションでルールと本物のキーを登録する
4. 開発ユーザーのセッションで環境変数を読み込んで使う

手順は [docs/install.md](install.md)。手順のほとんどはコーディングエージェントに任せられる。[コーディングエージェントに導入を任せる](agent-setup.md) の1行をエージェントに渡せば、人がするのは、渡された管理者のコマンドの実行と本物のキーの入力になる。

## プリセット

よく使うサービスのルールは `credshim preset <名前>` で生成できる。ダミーのキーは生成のたびにランダムに作られる。

| 名前 | 宛先 | ダミーを入れる環境変数 |
| --- | --- | --- |
| `openai` | `api.openai.com` | `OPENAI_API_KEY` |
| `anthropic` | `api.anthropic.com` | `ANTHROPIC_API_KEY` |
| `gemini` | `generativelanguage.googleapis.com` | `GEMINI_API_KEY` |
| [`github`](github.md) | `api.github.com`（`gh` CLI） | `GH_TOKEN` |
| [`github-ssh`](ssh.md) | `github.com`（SSH） | |
| [`aws`](aws.md) | AWS の各サービス | `AWS_ACCESS_KEY_ID` など |
| [`aws-sso`](aws.md#aws-iam-identity-centersso) | AWS の各サービス | `AWS_ACCESS_KEY_ID` など |

それ以外の API は、ルールを自分で書いて登録する（[設定](configuration.md#ルールを書く)）。

## コーディングエージェントで使う

プロキシの環境変数とダミーのキーを読み込んだシェルからエージェントを起動する。エージェントが実行するコマンドやアプリは、その環境変数を引き継ぐ。お試し構成では、代わりに [お試し構成](#お試し構成) のコマンドを使う。

```sh
. /etc/credshim/env                              # プロキシと CA
set -a; . /etc/credshim/keys.env; set +a         # ダミーのキー
```

ダミーのキーは、エージェントを起動するシェルでだけ読み込み、シェルの設定には書かない。シェルにある変数はプロジェクトの .env より優先されるので、.env に書いた別のキーが黙って使われなくなる。プロジェクトごとの渡し方は [ダミーのキーをプロジェクトに渡す](install.md#ダミーのキーをプロジェクトに渡す)。

エージェント自身がルールのある宛先と通信するなら（たとえば `api.anthropic.com` にダミーの `ANTHROPIC_API_KEY` で）、この環境変数でエージェントも開発用の CA を信頼する。ダミーを含まない通信は、そのまま中継される。

リクエストが失敗すると、CredShim の応答が理由と、詳しく見るコマンドを示す。エージェントがそれをどう読むかと、`AGENTS.md` や `CLAUDE.md` に入れる文は [コーディングエージェント](agents.md) にある。`credshim docs` は、入っているバージョンのこのドキュメントを表示する。

## ドキュメント

- [推奨構成の導入](install.md)：インストール、更新、アンインストール、既存の認証情報からの移行
- [コーディングエージェントに導入を任せる](agent-setup.md)：エージェントに渡す1行と、エージェントが進める手順
- [設定](configuration.md)：ルールの書き方、設定の反映、base URL モード、OAuth、監査ログ
- [AWS](aws.md)：静的アクセスキーと IAM Identity Center（SSO）
- [SSH エージェント](ssh.md)
- [GitHub CLI（gh）](github.md)：`gh` 用の fine-grained トークンと、既存の `gh` のログインの入れ替え
- [コンテナ分離](container.md)
- [うまく動かないとき](troubleshooting.md)：`credshim doctor`、止められたリクエスト、macOS の Go 製ツール
- [コーディングエージェント](agents.md)：エージェントが持っているもの、リクエストが失敗したときの対処、エージェントへの指示に入れる文
- [脅威モデル](threat-model.md)
- [開発](development.md)

## ライセンス

[MIT](../../LICENSE-MIT) または [Apache-2.0](../../LICENSE-APACHE) のどちらか。
