# コンテナ分離

エージェントとアプリを devcontainer などのコンテナに入れ、プロキシはホストで [推奨構成](install.md) のとおり専用ユーザーとして動かす。コンテナの外向きの通信をプロキシだけに絞ると、SSO OIDC やポータルへの直接の接続も含めて、すべての通信がプロキシの判定と監査を通る。

> SSH の構成（下の「SSH」）はまだ手動で確かめていない。ここに書いたのはその出発点。

## プロキシをコンテナから使えるようにする

既定ではプロキシはループバック（`127.0.0.1`）でしか待ち受けない。コンテナから届くアドレスで待ち受けるよう、設定を変えて `sudo $bin service install` で再起動する（`$bin` は [導入手順の変数](install.md#変数を決める)）。

```toml
[listen]
addr = "172.17.0.1:8787"      # docker ブリッジのホスト側。0.0.0.0 は常に拒否
allow_non_loopback = true
```

## AWS

コンテナ内の `aws` に、プロキシ、結合バンドル、ダミーのキーを渡す。

```sh
docker run --rm \
  -e HTTPS_PROXY=http://172.17.0.1:8787 -e HTTP_PROXY=http://172.17.0.1:8787 \
  -e AWS_CA_BUNDLE=/credshim/bundle.pem -v /etc/credshim/bundle.pem:/credshim/bundle.pem:ro \
  -e AWS_ACCESS_KEY_ID=CREDSHIMAWS... -e AWS_SECRET_ACCESS_KEY=credshim-dummy -e AWS_REGION=ap-northeast-1 \
  amazon/aws-cli sts get-caller-identity
```

## SSH

SSH エージェントのソケットをコンテナにマウントし、22番ポートへの接続はプロキシの CONNECT で出す。プロキシは、ルールの無いホストへの CONNECT を中身を見ずに TCP のまま中継し、監査ログに `tunnel` として残す。

エージェントは接続元の uid を見る。

- **Linux の docker（user namespace なし）。** コンテナ内の uid がそのままホストの uid になる。コンテナを開発ユーザーの uid で動かす（`--user "$(id -u)"`）か、コンテナの uid を `client_uids` に入れる。OpenSSH はパスワードエントリの無い uid では動かないので、イメージにその uid のユーザーを作っておく。
- **Docker Desktop（macOS）。** ホストの Unix ソケットをバインドマウントで渡せないので、ホストのエージェントをコンテナへ中継する `/run/host-services/ssh-auth.sock` を使う。

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
