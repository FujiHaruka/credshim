# GitHub CLI（gh）

SSH での `git` は [SSH エージェント](ssh.md) で動くが、`gh` は GitHub の API を呼び、API はトークンしか受け付けない。`github` プリセットは、本物のトークンを `api.github.com` と `uploads.github.com` にだけ送る。`gh` が持つのは `GH_TOKEN` のダミーだけで、プロキシが GitHub への途中で本物のトークンに差し替える。

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
| Contents | 必要なときだけ Read and write | `gh release upload` と、ファイルを付けた `gh release create` |
| Issues | 必要なときだけ Read and write | `gh issue` |
| Workflows | No access | 外しておくと、エージェントが CI の定義を書き換えてリポジトリのシークレットを読むことができない |

`gh pr create`・`gh pr edit`・`gh pr comment` と `gh issue` のコマンドの `--attach`（gh 2.99.0 以降）は、ファイルを `uploads.github.com` に上げ、リポジトリへの書き込み権限が要る。

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

macOS でこれが証明書のエラーになるなら、[macOS の Go 製ツール](troubleshooting.md#macos-の-go-製ツール) のとおり `gh` に開発用 CA を信頼させる（`gh` は Go のプログラム）。

## 既存の gh のログインを入れ替える

`gh auth login` はトークンを `~/.config/gh/hosts.yml` かシステムのキーリングに保存し、開発ユーザーとして動くエージェントはそれを読める。`credshim doctor` は両方を報告する（`files`）。これを消す。`GH_TOKEN` があると `gh` はログアウトを拒むので、そのコマンドだけ外して実行する。

```sh
env -u GH_TOKEN -u GITHUB_TOKEN gh auth logout --hostname github.com
```

そのあと、GitHub で古いトークンを無効にする。`gh auth login` のトークンは Settings → Applications → Authorized OAuth Apps → GitHub CLI、自分で作ったトークンは Settings → Developer settings → Personal access tokens。シェルの設定や .env に本物の `GH_TOKEN`・`GITHUB_TOKEN` が残っていれば消す。

## 古い github ルールを更新する

古い `credshim preset github` で作った `github` ルールは、ダミーが `credshim-github-` で始まり、`extra_hosts` が無い。このままだと `--attach` は失敗する。`uploads.github.com` へのアップロードがダミーのまま届くので GitHub が 401 を返し、さらに gh 2.99.0〜2.103.1 は、`gho_`・`ghp_`・`github_pat_` で始まるトークンでしかファイルを付けないので、送る前に `unsupported authentication type` で止まる。新しいダミーは `github_pat_credshim_` で始まり、これらの版でも通り、本物の fine-grained トークンの形にはならない。ダミーを自分で書くときもこの接頭辞を残す。`github_pat_` で始まるほかの値は、`credshim doctor` が本物のトークンとして報告する。

`extra_hosts` のある版に [CredShim を更新](install.md#新しいリリースに更新する管理者のセッション) したあと、管理者のセッションでルールを入れ替える。登録したトークンはそのまま使う。

```sh
sudo -u $user vi /var/lib/credshim/config.toml   # name が "github" の [[rule]] を消す
$bin preset github | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null
sudo $bin service reload
```

ダミーが変わるので、開発ユーザーのセッションで `/etc/credshim/keys.env` を読み直し、プロジェクトの `.env` に古い `GH_TOKEN` を写していれば置き換える。

## プリセットが許すもの

- メソッドは `GET`・`POST`・`PATCH`・`PUT`・`DELETE`。マージ、編集、ブランチの削除に要る。
- パスは `/graphql`・`/repos`・`/user`・`/users`・`/orgs`・`/search`・`/notifications`・`/gists`・`/rate_limit`・`/licenses`・`/gitignore`・`/user-attachments`。`gh` のコマンドの多くは `/graphql` を通るので、パスではあまり絞れない。実際の制限は、トークンのリポジトリと権限。
- 宛先は `api.github.com` と `uploads.github.com` で、メソッドとパスは両方に同じものが効く。`uploads.github.com` は `--attach` のファイル（`/user-attachments`）と `gh release upload` のファイル（`/repos`）を受け取る。ほかへ送られたダミーは差し替えないので、GitHub が 401 を返す。HTTPS での `git` は対象外なので、SSH を使う。
- GitHub Enterprise Server では、自分のサーバーのホストでルールを手で書く（[ルールを書く](configuration.md#ルールを書く)）。
