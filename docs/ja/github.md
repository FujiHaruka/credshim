# GitHub CLI（gh）

SSH での `git` は [SSH エージェント](ssh.md) で動くが、`gh` は GitHub の API を呼び、API はトークンしか受け付けない。`github` プリセットは、トークンを `api.github.com` に束縛する。`gh` が持つのは `GH_TOKEN` のダミーだけで、プロキシが GitHub への途中で本物のトークンに差し替える。

このページのコマンドは推奨構成のもので、`$user`・`$bin`・`credshim-svc` は [導入手順の変数](install.md#変数を決める) を使う。お試し構成では [読み替え](install.md#お試し構成で読み替える) のとおりに読む。

## トークンを作る

ふつうの `gh auth login` が発行するトークンは、自分が触れるすべてのリポジトリを読み書きできる。代わりに fine-grained personal access token を作り（GitHub の Settings → Developer settings → Personal access tokens → Fine-grained tokens）、権限を絞る。

- **Resource owner。** 1つのトークンが扱えるのは、1つの所有者（自分のアカウントか、1つの Organization）のリポジトリだけ。Organization によっては、管理者の承認が要る。
- **Repository access。** Only select repositories にする。
- **有効期限。** 設定する。
- **権限。** プルリクエストを作って更新するエージェントなら次のとおり。

| 権限 | アクセス | 用途 |
| --- | --- | --- |
| Metadata | Read | GitHub が必須にしている |
| Pull requests | Read and write | プルリクエストの作成、編集、コメント |
| Contents | Read（マージもするなら Read and write） | ファイルの読み取りとマージ。push は SSH で通すので要らない |
| Actions | Read | `gh pr checks`、`gh run view`、`gh run watch` |
| Issues | 必要なときだけ Read and write | `gh issue` |
| Workflows | No access | 外しておくと、エージェントが CI の定義を書き換えてリポジトリのシークレットを読むことができない |

トークンに無い権限が要るコマンドには、GitHub が足りない権限を添えて 403 を返す。GitHub でトークンにその権限を足す。

## 登録する（管理者のセッション）

```sh
$bin preset github | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null
credshim-svc secret set github               # トークンを貼り付ける
sudo $bin service reload
```

開発ユーザーのセッションでは、`/etc/credshim/keys.env` に `GH_TOKEN` のダミーが入る。`gh` は、保存されたログインより `GH_TOKEN` を先に使う。`gh auth status` はプリセットが許さない API のルートも呼ぶので、`gh api` で確かめる。

```sh
set -a; . /etc/credshim/keys.env; set +a
gh api user --jq .login
```

## 既存の gh のログインを入れ替える

`gh auth login` はトークンを `~/.config/gh/hosts.yml` かシステムのキーリングに保存し、開発ユーザーとして動くエージェントはそれを読める。`credshim doctor` は両方を報告する（`files`）。これを消す。`GH_TOKEN` があると `gh` はログアウトを拒むので、そのコマンドだけ外して実行する。

```sh
env -u GH_TOKEN -u GITHUB_TOKEN gh auth logout --hostname github.com
```

そのあと、GitHub で古いトークンを無効にする。`gh auth login` のトークンは Settings → Applications → Authorized OAuth Apps → GitHub CLI、自分で作ったトークンは Settings → Developer settings → Personal access tokens。シェルの設定や .env に本物の `GH_TOKEN`・`GITHUB_TOKEN` が残っていれば消す。

## プリセットが許すもの

- メソッドは `GET`・`POST`・`PATCH`・`PUT`・`DELETE`。マージ、編集、ブランチの削除に要る。
- パスは `/graphql`・`/repos`・`/user`・`/users`・`/orgs`・`/search`・`/notifications`・`/gists`・`/rate_limit`・`/licenses`・`/gitignore`。`gh` のコマンドの多くは `/graphql` を通るので、パスではあまり絞れない。実際の制限は、トークンのリポジトリと権限。
- 宛先は `api.github.com` だけ。ほかへ送られたダミーは差し替えないので、GitHub が 401 を返す。`uploads.github.com` もこれに含まれるので、`gh release upload` と、ファイルを付けた `gh release create` は失敗する。リリースは CI から出す。HTTPS での `git` も対象外なので、SSH を使う。
- GitHub Enterprise Server では、自分のサーバーのホストでルールを手で書く（[ルールを書く](configuration.md#ルールを書く)）。

`gh` は Go のプログラム。macOS で開発用 CA を信頼させる方法は [macOS の Go 製ツール](troubleshooting.md#macos-の-go-製ツール) を参照。
