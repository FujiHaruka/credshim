# AWS

`~/.aws` と環境変数にはダミーのアクセスキーだけを置く。`aws` コマンドや SDK はダミーで署名（SigV4）したリクエストをプロキシへ送り、CredShim はアクセスキー ID でルールを引いて、本物の認証情報で署名し直して AWS へ送る。ダミーのシークレットは送信されないので、何を書いてもよい。

本物の認証情報は、IAM ユーザーの静的なアクセスキーか、IAM Identity Center（SSO）のロールのどちらかで持つ。

このページのコマンドは推奨構成で書いてあり、`$user`・`$bin`・`svc` は [導入手順の変数](install.md#変数を決める) を使う。お試し構成では [読み替え](install.md#お試し構成で読み替える) のとおりに読む。

## 静的アクセスキー

```sh
# 管理者のセッション
$bin preset aws | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null   # ダミーのアクセスキー ID は毎回ランダム
svc secret set aws-access-key-id             # 本物のアクセスキー ID
svc secret set aws-secret-access-key         # 本物のシークレット
sudo $bin service reload

# 開発ユーザーのセッション
. /etc/credshim/env                          # AWS_CA_BUNDLE が結合バンドルを指す
set -a; . /etc/credshim/keys.env; set +a     # ダミーの AWS_ACCESS_KEY_ID・AWS_SECRET_ACCESS_KEY
aws sts get-caller-identity
```

AWS のルールが2つ以上あるときは、環境変数ではなく、`/etc/credshim/keys.env` のコメントにあるプロファイルを `~/.aws/credentials` に書いて `AWS_PROFILE` で選ぶ。

`AWS_CA_BUNDLE` は信頼ストアを置き換えるので、開発用の CA 単体ではなく、結合バンドル（開発用の CA とシステムのルート証明書をまとめたファイル）を指す。`/etc/credshim/env` はそうなっている。

### 使えるサービスと操作を絞る

```toml
[aws]
max_body_bytes = 16777216   # S3 以外で署名のために読むボディの上限（既定 16MiB）

[[aws_key]]
name = "aws"
dummy_access_key_id = "CREDSHIMAWS..."
access_key_id = "aws-access-key-id"          # 秘密ストアの名前
secret_access_key = "aws-secret-access-key"  # 秘密ストアの名前
services = ["sts", "s3", "dynamodb"]         # 省略すると全サービス（execute-api は明示したときだけ）
regions = ["ap-northeast-1"]                 # 省略すると全リージョン
operations = ["sts:GetCallerIdentity", "s3:GetObject", "s3:ListObjects*", "dynamodb:Describe*"]
limits = { per_minute = 120, per_day = 5000, concurrent = 8 }
```

- `services` は署名のスコープに入るサービス名で照合する。
- `operations` は `<サービス>:<操作名>` の許可リスト。末尾の `*` は前方一致で、`s3:*` はそのサービスの全操作。許可リストに無い操作と、操作を特定できないリクエストは `CredShimOperationNotAllowed` の 403 になり、AWS には送らない。
- 許可リストを作るには、まず `operations` を書かずに使い、`svc tail` の `operation` に出る操作名を集めるとよい。
- 同じ形のリクエストに当てはまる操作が複数あるとき（たとえば `GetBucketLifecycle` と `GetBucketLifecycleConfiguration`）は、その両方を許可する必要がある。
- `limits` を超えると `CredShimLimitExceeded` の 429。
- `services`・`regions`・`operations`・`limits` は SSO のロールにも書ける。

操作は、リクエストの形から botocore のモデルをもとに特定する（Query と EC2 は `Action`、JSON は `X-Amz-Target`、rpc-v2-cbor はパス、REST はメソッド、パス、必須のクエリとヘッダー）。

### 使えないもの

- 認証情報を発行する操作（`sts:AssumeRole`・`GetSessionToken`、`iam:CreateAccessKey`、`s3:CreateSession` など37操作）は、ルールによらず拒否する。本物の認証情報が応答で返ってしまうため。
- SSO OIDC、SSO ポータル、`aws login` の signin のホストへの接続は、AWS の設定が無くても常に拒否する。そのため `aws sso login`（代わりに `credshim aws sso login` を使う）は動かない。
- AssumeRole するプロファイル、`aws s3 presign` などクライアント側で署名するもの、S3 Express One Zone は動かない。

## AWS IAM Identity Center（SSO）

SSO のロールも、`~/.aws` にはダミーの静的アクセスキーだけを置いて使う。ログインは `aws sso login` ではなく `credshim aws sso login` で人間が行う。SSO のトークンは秘密ストアに、ロールの認証情報はプロキシのメモリにだけ置く。プロキシは期限の10分前にロールの認証情報と SSO のトークンを取り直す（リフレッシュトークンがあれば）。

```sh
# 管理者のセッション
$bin preset aws-sso | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null
sudo -u $user vi /var/lib/credshim/config.toml   # start_url、region、アカウント、ロールを書き換える
sudo $bin service reload
svc aws sso login sso            # 表示された URL をブラウザで開き、コードを確かめて承認する

# 開発ユーザーのセッション
. /etc/credshim/env
set -a; . /etc/credshim/keys.env; set +a
aws sts get-caller-identity      # 認証情報はダミー（静的キーと同じ）

# 使い終わったら（管理者のセッション）
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

- ログインしていないか、SSO のトークンが切れて更新できないときは、リクエストを AWS へ送らずに `CredShimSsoLoginRequired` のエラー（`credshim aws sso login <session>` を促すメッセージ付き）を返し、監査ログに `sso_login_required` を残す。
- 動いているプロキシは、次の AWS のリクエストで新しいログインを読み込むので、ログインし直したあとの再起動は要らない。
- `logout` のあとも、プロキシがすでに持っているロールの認証情報は、取り直しの時期まで使われる。
- `login` は端末から実行する（標準入力が端末でなければ拒否する）。`sudo` は端末をそのまま渡すので、`svc` でも動く。
- 覚えのないデバイスコードの承認を求められたら承認しない。エージェントが自分でログインを始めて、人間に承認させようとしている可能性がある。
