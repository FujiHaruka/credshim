# AWS

Put only dummy access keys in `~/.aws` and in environment variables. The `aws` command and the SDKs sign requests with the dummy (SigV4) and send them to the proxy. CredShim looks up the rule by the access key ID, signs the request again with the real credentials, and sends it to AWS. The dummy secret is never sent, so it can be anything.

The real credentials are either a static access key of an IAM user or a role in IAM Identity Center (SSO).

The commands on this page are for the recommended setup. `$user`, `$bin`, and `credshim-svc` are [the install variables](install.md#set-the-variables). For the trial setup, read them as described in [adapting the commands](install.md#adapting-the-commands-to-the-trial-setup).

## Static access keys

```sh
# admin session
$bin preset aws | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null   # the dummy access key ID is random each time
credshim-svc secret set aws-access-key-id      # real access key ID
credshim-svc secret set aws-secret-access-key  # real secret
sudo $bin service reload

# developer session
. /etc/credshim/env                          # AWS_CA_BUNDLE points to the combined bundle
set -a; . /etc/credshim/keys.env; set +a     # dummy AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
aws sts get-caller-identity
```

When there are two or more AWS rules, do not use the environment variables. Write the profiles from the comments in `/etc/credshim/keys.env` into `~/.aws/credentials` and select one with `AWS_PROFILE`.

`AWS_CA_BUNDLE` replaces the trust store, so point it at the combined bundle (one file with the development CA and the system root certificates), not at the development CA alone. `/etc/credshim/env` already does this.

### Restricting services and operations

```toml
[aws]
max_body_bytes = 16777216   # limit on the body read for signing, for services other than S3 (default 16MiB)

[[aws_key]]
name = "aws"
dummy_access_key_id = "CREDSHIMAWS..."
access_key_id = "aws-access-key-id"          # name in the secret store
secret_access_key = "aws-secret-access-key"  # name in the secret store
services = ["sts", "s3", "dynamodb"]         # all services if omitted (execute-api only when listed)
regions = ["ap-northeast-1"]                 # all regions if omitted
operations = ["sts:GetCallerIdentity", "s3:GetObject", "s3:ListObjects*", "dynamodb:Describe*"]
limits = { per_minute = 120, per_day = 5000, concurrent = 8 }
```

- `services` matches the service name in the signing scope.
- `operations` is an allowlist of `<service>:<operation>`. A trailing `*` is a prefix match, and `s3:*` is every operation of that service. An operation that is not in the allowlist, and a request whose operation cannot be identified, get a 403 `CredShimOperationNotAllowed` and are not sent to AWS.
- To build the allowlist, first use it without `operations` and collect the operation names shown in `operation` in `credshim-svc tail`.
- When more than one operation matches the same request shape (for example `GetBucketLifecycle` and `GetBucketLifecycleConfiguration`), you must allow both.
- Exceeding `limits` gives a 429 `CredShimLimitExceeded`.
- `services`, `regions`, `operations`, and `limits` can also be set on SSO roles.

The operation is identified from the shape of the request, based on the botocore models (`Action` for Query and EC2, `X-Amz-Target` for JSON, the path for rpc-v2-cbor, and for REST the method, the path, and the required query parameters and headers).

### What does not work

- Operations that issue credentials (37 operations, such as `sts:AssumeRole`, `GetSessionToken`, `iam:CreateAccessKey`, and `s3:CreateSession`) are denied regardless of the rules, because the response would contain real credentials.
- Connections to the SSO OIDC, SSO portal, and `aws login` signin hosts are always denied, even with no AWS configuration. So `aws sso login` does not work (use `credshim aws sso login` instead).
- Profiles that use AssumeRole, client-side signing such as `aws s3 presign`, and S3 Express One Zone do not work.

## AWS IAM Identity Center (SSO)

SSO roles also work with only a dummy static access key in `~/.aws`. A human logs in with `credshim aws sso login`, not `aws sso login`. The SSO token is kept in the secret store, and the role credentials only in the proxy's memory. The proxy fetches new role credentials and a new SSO token 10 minutes before they expire (if there is a refresh token).

```sh
# admin session
$bin preset aws-sso | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null
sudo -u $user vi /var/lib/credshim/config.toml   # change start_url, region, account, and role
sudo $bin service reload
credshim-svc aws sso login sso   # open the URL shown in a browser, check the code, and approve

# developer session
. /etc/credshim/env
set -a; . /etc/credshim/keys.env; set +a
aws sts get-caller-identity      # the credentials are dummies (same as static keys)

# when you are done (admin session)
credshim-svc aws sso logout sso  # end the IAM Identity Center session and delete the saved token
```

```toml
[[aws_sso_session]]
name = "sso"
start_url = "https://your-portal.awsapps.com/start"
region = "us-east-1"                 # IAM Identity Center region

[[aws_sso_role]]
name = "aws-sso"
dummy_access_key_id = "CREDSHIMAWS..."
session = "sso"
account_id = "123456789012"
role_name = "Developer"
services = ["sts", "s3"]             # all services if omitted (same as static keys)
regions = ["ap-northeast-1"]
```

- If you are not logged in, or the SSO token has expired and cannot be refreshed, the proxy does not send the request to AWS. It returns a `CredShimSsoLoginRequired` error (with a message that asks you to run `credshim aws sso login <session>`) and writes `sso_login_required` to the audit log.
- A running proxy reads the new login on the next AWS request, so you do not need to restart after you log in again.
- After `logout`, role credentials that the proxy already holds are still used until they are due to be fetched again.
- Run `login` from a terminal (it refuses to run if standard input is not a terminal). `sudo` passes the terminal through, so it also works with `credshim-svc`.
- If you are asked to approve a device code you do not recognize, do not approve it. An agent may have started a login on its own and be trying to get a human to approve it.
