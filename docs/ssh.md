# SSH エージェント

CredShim は ssh-agent としても動く。鍵はプロキシの中で生成して秘密ストアにだけ置き、外へは公開鍵しか出さない。`~/.ssh` に秘密鍵のファイルは作らない。

署名するのは、次の条件をすべて満たすログインのときだけ。

- `ssh` が OpenSSH 8.9 以降で、接続先のサーバーを証明する情報（session-bind）を送ってくる
- そのサーバーのホスト鍵の指紋が、設定の `host_keys` に含まれる
- ログインするユーザー名が、設定の `users` に含まれる

`ssh -A` で転送した先からの要求、`ssh-keygen -Y sign`（コミット署名など）、鍵の追加と削除は拒否する。

このページのコマンドは推奨構成で書いてあり、`$user`・`$bin`・`svc` は [導入手順の変数](install.md#変数を決める) を使う。お試し構成では [読み替え](install.md#お試し構成で読み替える) のとおりに読む。

## GitHub で使う

```sh
# 管理者のセッション
$bin preset github-ssh | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null   # GitHub のホスト鍵3種、ユーザー git
svc ssh keygen ssh-github                    # 表示された公開鍵を GitHub に登録する
sudo $bin service install --user yourname    # SSH の設定は再起動で反映する。yourname は開発ユーザー

# 開発ユーザーのセッション
. /etc/credshim/env                          # SSH_AUTH_SOCK=/var/lib/credshim-ssh/agent.sock も入る
ssh -T git@github.com
```

既存の `~/.ssh` の鍵は取り込まない。新しい鍵に入れ替え、古い鍵はサーバーから外す（[既存の認証情報を入れ替える](install.md#6-既存の認証情報を入れ替える)）。

## 設定

```toml
[ssh]
socket = "/var/lib/credshim-ssh/agent.sock"
client_uids = [501]          # 接続を受け付ける uid。省略するとプロキシ自身の uid だけ

[[ssh_key]]
name = "github"
secret = "ssh-github"        # svc ssh keygen に渡した名前
users = ["git"]
host_keys = ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"]
limits = { per_minute = 30, per_day = 500 }   # 署名の回数の上限（省略すると無制限）
```

- 上限を超えた署名の要求は拒否し、監査ログに `reason="limited"` を残す。
- エージェントは接続元の uid を確かめ、`client_uids` に無い接続はすぐに閉じる。`service install` は、新しく作る設定の `client_uids` に `--user` の uid を書く。設定がすでにあれば、足すべき行を表示する。
- ソケットのディレクトリ `/var/lib/credshim-ssh` は専用ユーザーの所有で、開発ユーザーは書けない。
- ProxyJump で踏み台を経由するなら、踏み台のホスト鍵の指紋も `host_keys` に入れる。
- `[ssh]` と `[[ssh_key]]` を変えたら、`sudo $bin service install --user yourname` で再起動する（`service reload` では変わらない）。
