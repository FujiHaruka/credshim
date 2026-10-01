# CredShim v0.2：SSH 鍵と AWS 認証情報の保護

Sep 30, 2026 · @Haruka Fuji

## 目的とスコープ

`~/.ssh` の秘密鍵や `~/.aws` の認証情報（`credentials` のアクセスキー、`sso/cache` の SSO トークン、`cli/cache` のロール認証情報）は、コーディングエージェントが読んで外へ送れてしまう。v0.2 ではこれらの本物をプロキシの中だけに置き、エージェントとアプリは値を一度も見ずに `ssh`、`git` over SSH、`aws` コマンドを使える状態を作る。AWS は静的なアクセスキーと IAM Identity Center（SSO）の両方を対象にする。

v0.1 と同じく、**守るもの**は認証情報の「値」、**守らないもの**は「利用」。エージェントは束縛先に対しては本物の権限を使える。これは許可リスト、上限、監査ログで緩和する。

## 前提

SSH も AWS も、秘密そのものを送らず署名で認証する。v0.1 の「ダミーを送らせて本物に差し替える」方式はそのままでは使えず、プロキシが署名を肩代わりする必要がある。

- SSH は公開鍵署名によるチャレンジ応答。署名だけを代行する ssh-agent の仕組みがそのまま使える。
- AWS は SigV4 で、リクエスト全体（メソッド、パス、クエリ、署名対象ヘッダー、ボディのハッシュ）に HMAC で署名する。クライアントがダミーで付けた署名を、プロキシが本物で付け直す。

## アプローチ

### SSH：CredShim を ssh-agent にする

CredShim が ssh-agent プロトコルを話す Unix ソケットを出し、開発者側は `SSH_AUTH_SOCK` をそこに向ける。鍵は既存の秘密ストアに置き、プロキシの外へは公開鍵しか出さない。

署名は、宛先を確かめられたときだけ行う。OpenSSH 8.9 以降のクライアントは、SSH 接続ごとに agent への接続を1本開き、最初に `session-bind@openssh.com` でサーバーのホスト鍵と、そのホスト鍵によるセッション ID への署名を渡し、同じ agent 接続で署名を求める。プロキシはこれを検証し、次の条件をすべて満たす要求にだけ署名する。

- 同じ agent 接続に、検証済みの bind がある。クライアントは bind が拒否されても署名要求を続けるので、束縛を強制できるのは agent 側だけ。
- ホスト鍵が、その鍵の束縛先として設定された指紋に含まれる（ホスト名や DNS は信用しない。v0.1 の原則3「照合はクライアントが操れる値でなく接続先で」と同じ）。
- 署名対象が、その接続で最後に bind したセッション ID と許可されたユーザー名を含むユーザー認証要求の形をしている。method は `publickey-hostbound-v00@openssh.com`（ユーザー公開鍵の後ろにサーバーのホスト鍵が付き、bind のホスト鍵と一致しなければならない）か、hostbound に対応しないサーバー向けの `publickey`。セッション ID の長さは鍵交換の方式で変わる（32 または 64 バイト）。
- フォワードされた接続（`ssh -A` の先）からの要求ではない。フォワード経由の agent 接続には、手元の `ssh` が `is_forwarding=1` の bind を先に送るので、その接続に一度でも `is_forwarding=1` があれば拒否する。

session-bind の無い要求、任意データへの署名要求は拒否する（fail closed）。素の ssh-agent は制約なしの鍵なら bind の無い接続でも任意のデータに署名する。`ssh-add -h` で宛先を制約した鍵は bind の無い接続での署名を拒否するので、宛先の制約そのものは素の ssh-agent でも得られる。CredShim の存在理由はそれ以外の点にある：鍵がプロキシの中で生成され、ディスクに一度も現れない、段階Bで agent と鍵を別ユーザーに置ける、許可するユーザー名を絞れる、監査ログとレート制限、設定ファイルで束縛を管理できる。

鍵はプロキシの中で生成するのを基本にし、公開鍵だけを出す。既存の `~/.ssh` の鍵はすでに読まれた前提で扱い、取り込みではなく入れ替えを案内する。

### AWS：ダミーのアクセスキーで署名させ、プロキシが再署名する

`aws` コマンドは v0.1 と同じく `HTTPS_PROXY` と CA バンドル（`AWS_CA_BUNDLE`）でプロキシを通す。`AWS_CA_BUNDLE` は信頼ストアを追加ではなく置き換えるので、v0.1 の `SSL_CERT_FILE` と同じ結合バンドル（開発CA＋システムのルート）を指す。開発CAだけにすると、MITM せずトンネルするホストで TLS 検証が落ちる。`~/.aws` に置くのは、静的キーの場合も SSO の場合も**ダミーの静的アクセスキー**だけにする。

- プロキシは AWS のエンドポイントを MITM し、Authorization ヘッダーのアクセスキー ID でルールを引く。クライアントの署名は捨て、本物の認証情報で SigV4 署名を付け直して上流へ送る。ダミーのシークレットキーは送信されないので、プロキシは知らなくてよい。本物がセッショントークン付き（SSO のロール認証情報）なら `X-Amz-Security-Token` を足して署名する。
- ダミーのアクセスキー ID が束縛外のホストに現れたら、v0.1 の原則4と同じく403。
- 静的キーのルールは、ダミーのアクセスキー ID と、秘密ストアの本物（アクセスキー ID とシークレット）の組。
- SSO のルールは、ダミーのアクセスキー ID と、SSO のセッション（開始 URL、リージョン）、アカウント、ロールの組。SSO のログインは `aws sso login` ではなく、人間が `credshim` のコマンドで行う。プロキシが SSO OIDC のデバイス認可フローを実行し、人間はブラウザで承認するだけ。得た SSO トークンはプロキシの中だけに置き、ロール認証情報はプロキシが必要なときに取得してメモリに持ち、期限前に取り直す。
  - `aws sso login` の往復を MITM して SSO キャッシュにダミーを書かせる案は採らない。CLI 内部のキャッシュ形式と SSO API の往復に依存して壊れやすく、エージェント自身にログインを始めさせる経路も残るため。
  - `credential_process` やコンテナ認証エンドポイントで一時認証情報を渡す案も採らない。短命でも本物の値がエージェントの手に渡るため。
- 束縛先の API には、新しい認証情報を発行させる操作がある（`iam:CreateAccessKey`、`sts:AssumeRole*`、`sts:GetSessionToken`、`sts:GetFederationToken`、`s3:CreateSession` など）。応答に本物の新しい値が乗るので、これらは既定で拒否する。IAM 側でも最小権限のロールを使うよう案内する。
- 署名の無い（`noAuth`）認証情報発行の API は、ダミーのアクセスキー ID を運ばないのでルールでは引けない。SSO OIDC（`oidc.<region>.amazonaws.com` の `RegisterClient`・`StartDeviceAuthorization`・`CreateToken`）、SSO ポータル（`portal.sso.<region>.amazonaws.com` の `GetRoleCredentials` などで、認証は `x-amz-sso_bearer_token` ヘッダー）、`sts:AssumeRoleWithWebIdentity`・`AssumeRoleWithSAML`、`aws login` の signin（`<region>.signin.aws.amazon.com`、`<region>.oauth.signin.aws`）がそれにあたる。これらはルールと無関係に、ホストと操作で常に拒否する（SSO OIDC とポータルはホストごと CONNECT の段階で拒否）。エージェントが自分でデバイス認可フローを始めて人間に承認させる経路もこれで塞ぐ（段階Cではプロキシが唯一の出口なので効く）。プロキシ自身の SSO 通信はプロキシの待ち受けを通らないので影響しない。
- SSO トークンは OAuth 保管庫か秘密ストアに置く（どちらにするかは実装時に決める）。
- プロキシが持つ本物（アクセスキー ID、シークレット、セッショントークン）はレスポンスのスクラブ対象に加える。

**v0.1 のルールの変更**

- 再署名にはボディのハッシュが要る。S3 はクライアントが `x-amz-content-sha256` を付けるので、その値をそのまま署名に使い、ボディはストリームのまま流す（`STREAMING-UNSIGNED-PAYLOAD-TRAILER`、`UNSIGNED-PAYLOAD`、空ボディのハッシュ、小さい XML ボディの実ハッシュのどれでも、ボディとの整合は S3 が検証する）。それ以外のサービスはヘッダーが無いので、サイズ上限付きでボディを読み込んでハッシュを計算する。操作名の判定もこれを使う（Query と EC2 はフォームの `Action`、JSON は `X-Amz-Target`、rpc-v2-cbor はパスの `/service/<svc>/operation/<op>`、REST はメソッドとパス）。「ボディを丸ごと読まない、例外は OAuth のトークンエンドポイントだけ」というルールにこの例外を加える。
- v0.1 の束縛先はホストの完全一致だが、AWS はサービス、リージョン、S3 のバケットごとにホストが変わる。`amazonaws.com` 配下への束縛（サービスやリージョンでの絞り込みを含む）と、それに合わせた MITM 対象の指定を加える。束縛の照合はホスト（接続先）で行い、サービスとリージョンの絞り込みには Authorization の資格スコープ（`<AKID>/<date>/<region>/<service>/aws4_request`）を使う。スコープはクライアントが書く値だが、再署名もこのスコープで行い、スコープとエンドポイントの食い違いは AWS が拒否する前提なので、偽っても別のサービスやリージョンには届かない（この前提は Phase 9 の手動マイルストーンで確かめる。成り立たなければ、ホストの束縛は保たれるが、スコープで引くサービスの許可リストは迂回できる）。
- `expose_secret()` の許可先に SigV4 の署名処理と SSO のトークン交換を加える。

## 脅威モデルへの追加

| エージェントが取りうる行動 | 対策 |
| --- | --- |
| `~/.ssh` やプロセスのメモリから秘密鍵を読む | 鍵はプロキシの中だけ。ディスク上の鍵ファイルは作らない |
| agent ソケットを自作クライアントで叩き、攻撃者のサーバーへの認証に使う | session-bind 必須。ホスト鍵が束縛先でなければ署名しない |
| 束縛先への正規セッションで得た署名を別ホストへ流用する | 署名はそのセッション ID に結び付いており、他の接続では通らない |
| 任意のデータ（コミット署名、別プロトコルの challenge）に署名させる | ユーザー認証要求の形以外は拒否 |
| agent フォワードを経由して別ホストから使う | フォワードされた接続からの要求は拒否 |
| `~/.aws` の credentials、SSO キャッシュ、CLI キャッシュを読む | そこにはダミーのアクセスキーしか無い。SSO トークンとロール認証情報はプロキシの中だけ |
| ダミーのアクセスキーで署名した要求を AWS 以外のホストへ送る | 束縛外は403。本物での再署名は束縛先の AWS エンドポイント宛てにしか行わない |
| 束縛先の API で新しい認証情報を発行させ、応答から本物の値を得る | 認証情報を発行する操作は既定で拒否 |
| 署名の要らない API（SSO OIDC のデバイス認可、SSO ポータル、`AssumeRoleWithWebIdentity`、`aws login`）で自分で認証情報を得る、人間に承認させる | ルールと無関係に、ホストと操作で常に拒否 |
| AWS の応答に本物のキーをエコーさせる | プロキシが持つ本物をスクラブ対象に加える |
| 束縛先へ本物の権限でアクセスし乱用する | 残存リスク。SSH はホスト鍵とユーザー名、AWS はサービスと操作の許可リスト、上限、監査ログで緩和。AWS は最小権限のロールも併用 |

## Phase 8: SSH エージェント

このフェーズの終わりで、同一ユーザー構成（段階A）のまま `ssh -T git@github.com` と `git clone git@github.com:...` が、ディスクに秘密鍵の無い状態で通る。

**作るもの**

- ssh-agent プロトコルのソケット。公開鍵の一覧と署名要求に応え、鍵の追加・削除・ロックなど書き込み系の要求は拒否する。
- 鍵の生成コマンド。秘密鍵は秘密ストアに保存し、出力するのは公開鍵だけ。
- 設定ファイルに SSH 鍵のルール：鍵の参照、束縛先ホスト鍵の指紋、許可するユーザー名。ProxyJump では踏み台と宛先で agent 接続が別になり、それぞれ bind と署名が来るので、踏み台に同じ鍵で入るなら踏み台のホスト鍵も束縛先に入れる。
- session-bind の検証と、アプローチ節の条件による署名判定。判定は v0.1 のルールエンジンと同じく I/O の無い純粋関数にする。
- 監査ログ：時刻、ルール名、宛先ホスト鍵の指紋、ユーザー名、判定。署名や鍵の値は出さない。
- テスト用 SSH サーバーは、OpenSSH の `sshd` を一般ユーザーのまま高いポートで起動する（`UsePAM no`、`StrictModes no`、絶対パスの `AuthorizedKeysFile`）。macOS の `/usr/sbin/sshd`（9.9p2）でこの起動と `sshd-session` の動作を確認済み。ログインできるのは実行ユーザーだけ。

**完了条件**

- [x] テスト用 SSH サーバーに対し、OpenSSH の `ssh` が CredShim の agent 経由で認証できる（ホスト鍵は Ed25519、ECDSA、RSA の3種）。
- [x] 束縛外のホスト鍵を持つサーバーへの認証では署名せず、拒否が監査ログに残る。
- [x] session-bind を送らないクライアント、bind が検証に失敗した接続、フォワードされた接続、ユーザー認証要求以外のデータ（`ssh-keygen -Y sign` の `SSHSIG` を含む）への署名要求がすべて拒否される。
- [x] `publickey-hostbound-v00@openssh.com` の署名対象に入ったホスト鍵が bind のホスト鍵と違えば拒否される。
- [x] 許可されていないユーザー名での認証要求が拒否される。
- [x] 秘密鍵がログ、エラー、ディスク上のファイルに現れない（`capture_logs().assert_absent(..)`）。
- [x] 脅威モデルの SSH の追加行それぞれに回帰テストがある。
- [ ] 人間が生成した公開鍵を GitHub に登録し、実物の `git clone` と `git push` を確認する（手動マイルストーン）。

**実装メモ（Phase 8）**

- agent は新しいクレート `credshim-ssh`（`crates/ssh`）に置いた。`rule.rs` が設定の `[[ssh_key]]`、`policy.rs` が I/O の無い判定（接続ごとの bind の状態と署名の可否）、`key.rs` が鍵の生成と署名（`expose_secret` の許可先に追加）、`agent.rs` がソケット。ssh-agent-lib は `proto` の型だけを使い（`default-features = false`）、フレームの読み書きは自前にした。ライブラリの `listen` はフレーム長に上限が無く、デコードに失敗すると接続を切り、要求を `Debug` でログに出すため。
- フレームは 256KiB（OpenSSH の `AGENT_MAX_LEN`）を超えるか長さ0なら接続を切る。長さを受け取ったあと本体が10秒以内に届かなければ切り、本体は届いた分だけ確保する。同時接続は64本までで、超えた接続はすぐ閉じる（同じプロセスの HTTP プロキシの fd を使い切らせないため）。解釈できない要求、鍵の追加・削除・ロック・スマートカード、session-bind 以外の拡張には `SSH_AGENT_FAILURE` を返して接続は保つ。
- bind の状態：最初の bind が検証でき `is_forwarding=0` なら束縛済み、`is_forwarding=1` ならフォワード扱い（以後ずっと拒否）、検証に失敗（セッション ID が 128 バイト超を含む）すればその接続を汚染済みにする。束縛済みの接続への2回目の bind も汚染済みにする（OpenSSH の ssh-agent も認証用に束縛した接続への再 bind を拒否する）。署名の判定は bind の状態だけを見るので、bind への応答（成功／失敗）はクライアントへの通知でしかない。
- 署名の判定：要求の公開鍵が設定の鍵と一致（証明書は不可）→ 束縛済み → bind のホスト鍵の SHA256 指紋がルールの `host_keys` に含まれる → 署名対象がユーザー認証要求ちょうどの形（セッション ID、`50`、ユーザー名、`ssh-connection`、method、`TRUE`、アルゴリズム名、公開鍵、hostbound ならホスト鍵、で余りのバイトが無い）→ セッション ID が bind と一致 → ユーザー名が `users` に含まれる → アルゴリズム名と公開鍵が署名に使う鍵と一致 → hostbound のホスト鍵が bind と一致 → flags が0。どれかで落ちれば `SSH_AGENT_FAILURE`。
- `REQUEST_IDENTITIES` は bind の有無に関係なく全部の鍵を返す（束縛先で絞ると `ssh` が署名を求めず、束縛外への試みが監査に残らないため）。コメントは `credshim:<ルール名>`。
- 監査ログは target `credshim::audit`（定数を core に移した）で `ingress="ssh_agent"`、`rules`、`host_key`（SHA256 指紋）、`user`、`decision`（`sign`・`deny`・`error`）、`reason`（`no_session_bind`、`bind_failed`、`forwarded`、`host_key_not_bound`、`not_user_auth`、`session_mismatch`、`user_not_allowed`、`hostbound_key_mismatch`、`key_mismatch`、`unsupported_flags`、`unknown_key`）。`user` はクライアントが書く値なので、ルール名と同じ文字（英数字と `.`・`_`・`-`）だけのときに記録し、それ以外は `<invalid>` にする。`credshim tail` は `sign ssh <user>@<指紋> [<ルール>] via ssh_agent` の形で出し、どのフィールドも制御文字をエスケープする（偽の行や端末の制御シーケンスを出させない）。ステータスソケットのカウンタにはまだ入れていない。
- 設定は `[ssh] socket`（既定 `$XDG_CONFIG_HOME/credshim/ssh-agent.sock`、0600）と `[[ssh_key]]`（`name`、`secret`、`host_keys` は `SHA256:` の指紋だけ、`users`）。名前の重複と、同じ秘密を2つのルールで使う設定は読み込み時に拒否する。`credshim run` は起動時に全部の鍵を秘密ストアから読んで解析し、無い・解析できない・暗号化されている・Ed25519 でない鍵があれば起動しない。
- `credshim ssh keygen <秘密の名前>` は Ed25519 の鍵を生成して秘密ストアに OpenSSH 形式で保存し、公開鍵（コメント `credshim:<名前>`）だけを標準出力に出す。同じ名前の秘密があれば上書きせず失敗する（登録済みの鍵を黙って入れ替えると締め出されるため）。`credshim preset github-ssh` は GitHub のホスト鍵3種とユーザー `git` のルールを出す。
- 既存の SSH 鍵ファイルの取り込みは用意しない（計画どおり入れ替えを案内する）。使うたびの確認（`ssh-add -c` 相当）も v0.2 では用意しない。
- テスト用 SSH サーバーは `credshim_testkit::sshd::TestSshd`（ホスト鍵3種を `ssh-keygen` で作り、`sshd -D -e` を一般ユーザーのまま高いポートで起動）。クライアントは `HOME` を一時ディレクトリにし、`-F /dev/null`、存在しない `IdentityFile`、known_hosts 無効で動かすので、開発者の `~/.ssh` を読まない。CI の Linux では `openssh-server` を入れる。

## Phase 9: AWS 静的キー（SigV4 再署名）

このフェーズの終わりで、`~/.aws/credentials` にダミーのアクセスキーだけがある状態で、`aws` コマンドが実際の AWS を操作できる。

**作るもの**

- SigV4 の再署名。ヘッダー署名方式で、S3 のペイロード無署名（`UNSIGNED-PAYLOAD` と aws-chunked のトレーラー方式）と、それ以外のサービスの上限付きボディ読み込みに対応する。
- `amazonaws.com` 配下への束縛と MITM 対象の指定。
- 静的キーのルール：ダミーのアクセスキー ID、本物のアクセスキー ID とシークレットの秘密参照、束縛先。本物の登録は v0.1 と同じく TTY から。
- 認証情報を発行する操作の既定拒否と、署名の要らない認証情報発行 API（SSO OIDC、SSO ポータル、`AssumeRoleWithWebIdentity`・`AssumeRoleWithSAML`、signin）の常時拒否。
- 本物のスクラブ対象への追加。
- 監査ログにサービス、リージョン、操作名を加える。
- testkit に SigV4 を検証するモック AWS（JSON、Query、REST-XML の各プロトコルと S3 のアップロード）。S3 のアップロードは `aws` CLI v2 の既定の形（`Content-Encoding: aws-chunked`、`Transfer-Encoding: chunked`、`x-amz-trailer` の CRC64NVME、`Expect: 100-continue`）で受ける。

**完了条件**

- [x] モック AWS で、ダミーで署名した要求が本物の認証情報で検証を通る（JSON、Query、REST-XML、S3 の各形式）。
- [x] `aws` CLI（v2）が、ダミーのプロファイルのままモック AWS に対して動く E2E テストが通る。
- [x] ダミーのアクセスキーを束縛外のホストへ送ると403になり、上流に何も届かない。
- [x] 認証情報を発行する操作が拒否され、上流に何も届かない。署名の要らない認証情報発行 API は、ルールが無くても拒否される。
- [x] S3 へのアップロード（`Expect: 100-continue` 付きの aws-chunked を含む）とダウンロードがボディをバッファせずに通る。`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`（署名付きチャンク）は拒否される。それ以外のサービスでボディの上限を超えると拒否される。
- [x] 本物のアクセスキー ID、シークレットがログ、エラー、クライアントへの応答に現れない。
- [ ] 人間が本物のキーを登録し、実 AWS で `aws sts get-caller-identity` と `aws s3 cp` を確認する（手動マイルストーン）。

**実装メモ（Phase 9）**

- 置き場所は新しいクレート `credshim-aws`（`crates/aws`）。`auth.rs` が Authorization と `X-Amz-Date` の解析、`operation.rs` が操作名の候補と認証情報を発行する操作の照合、`policy.rs` が I/O の無い判定、`resign.rs` が再署名（`expose_secret` の許可先に追加）。mitm は `Session::relay` の中で core の差し替えと OAuth の交換のあとにこれを呼ぶ。
- 束縛：`[[aws_key]]` のホストは常に `amazonaws.com` 配下で、`Intercept` に接尾辞での MITM 指定（`with_domains`）を足した。`services`・`regions` は資格スコープで照合する。ダミーが `amazonaws.com` 配下以外（平文 HTTP を含む）に現れれば403、Authorization の `Credential=` 以外（署名付き URL のクエリなど）に現れても403。ダミーはルールの dummy と互いに含まない（設定読み込み時に検査）。
- 再署名：クライアントの `SignedHeaders` と同じ集合（`host`・`x-amz-date` は aws-sigv4 が入れる。`authorization`・`x-amz-security-token` は捨てる）を、受け取った値のまま、クライアントの `X-Amz-Date` の時刻で署名する。`excluded_headers` は空にして、クライアントが署名したヘッダーを落とさない。URI は検証済みの接続先から作る。S3 は `PercentEncodingMode::Single` と `UriPathNormalizationMode::Disabled`、他は既定。
- ボディ：S3（スコープのサービスが `s3`）は `x-amz-content-sha256` の値（実ハッシュ、`UNSIGNED-PAYLOAD`、`STREAMING-UNSIGNED-PAYLOAD-TRAILER`）で署名しボディはストリームのまま。`STREAMING-` で始まる他の値は400、ヘッダーが無いか不正なら400。S3 以外は上限付きで読み（既定 16MiB、`[aws] max_body_bytes`）、超えたら413。DynamoDB の `BatchWriteItem`（16MB）まで通る値にした。Lambda の zip の直接アップロードなど、それより大きい要求は上限を上げるか S3 経由にする。
- 認証情報を発行する操作：`scripts/aws/credential-operations.py` が botocore のモデル（aws-cli 2.37.7 同梱）から37操作を抜き出し、`credential_operations.rs` を生成する。操作名の候補はクエリ文字列とボディのフォームの `Action`（大文字小文字を区別しない。片方に無害な名前を書いてもう片方で発行させる迂回を塞ぐ）、`X-Amz-Target` の最後の `.` 以降、rpc-v2-cbor のパスの操作名。REST の操作はメソッドとパスのテンプレート（`{x}` は1セグメント、S3 の先頭の `{Bucket}` は仮想ホスト形式のため省略可、クエリは必須キー）で照合する。サービスはスコープの署名名（`s3express` は `s3` として扱う）か、ホストのラベルがエンドポイント接頭辞と一致するかで決める。
- 署名の要らない発行 API：SSO OIDC（`oidc`・`oidc-fips`）、SSO ポータル（`portal.sso`・`portal.sso-fips`）は `amazonaws.com`・`amazonaws.com.cn`・`api.aws`・`api.amazonwebservices.com.cn` 配下で、signin は `signin.aws.amazon.com`・`signin.aws`・`signin.amazonaws.cn` 配下で、CONNECT と平文 HTTP の段階で AWS の設定が無くても403にする。v0.1 だけの利用者がプロキシ経由で `aws sso login` を実行しても通らなくなる（計画どおり）。STS の `AssumeRoleWithWebIdentity`・`AssumeRoleWithSAML` と Cognito Identity の `GetCredentialsForIdentity` は、AWS のルールがあって `amazonaws.com` 配下を MITM しているときに、ダミーの有無と無関係に操作名で拒否する（STS と Cognito Identity のホストでは、ダミーが無くてもボディを上限付きで読む）。デュアルスタック（`*.api.aws`）の STS は MITM しないので操作名では拒否できない（デュアルスタックは範囲外）。
- 認証情報以外の、サーバーが使える値を返す操作（`ecr:GetAuthorizationToken`、`codeartifact:GetAuthorizationToken` など）は Phase 9 では拒否せず、正当な「利用」として通す。絞り込みは Phase 11 のサービスと操作の許可リストで行う。
- 本物のアクセスキー ID はダミーに、シークレットは固定の文字列にスクラブする（`Injector::also_scrub`）。aws-sigv4 は trace レベルのログに署名パラメータ（アクセスキー ID を含む）を出すので、署名の呼び出しの間だけ `NoSubscriber` に切り替える。本物は起動時に読み、アクセスキー ID とシークレットが空か可視 ASCII 以外なら起動しない。
- 監査ログ：AWS の要求には `service`、`region`（どちらも資格スコープから。解析時に小文字・数字・`-` だけに制限）、`operation`（候補のうち英数字と `_`・`-`・`.` だけのもの）、拒否の理由 `reason`（`not_bound`、`unsupported_location`、`bad_authorization`、`service_not_allowed`、`region_not_allowed`、`credential_operation`、`unsigned_credential_operation`、`signed_chunks`、`bad_payload_hash`、`body_too_large`、`sso_oidc`、`sso_portal`、`signin`）を加えた。再署名の判定は `resign` で、ステータスソケットのカウンタでは `injected` に数える。ルールに当たらない拒否はカウンタに入れない。`credshim tail` は ` aws:<service>/<region>:<operation> (<reason>)` を付けて出す。
- 設定：`[[aws_key]]`（`name`、`dummy_access_key_id`、`access_key_id` と `secret_access_key` は秘密ストアの名前、`services`、`regions`）と `[aws] max_body_bytes`。`credshim preset aws` は `CREDSHIMAWS` で始まるダミーのルールを出す。`AWS_CA_BUNDLE` などを `credshim env` に出すのは Phase 11。
- テスト：testkit の `MockAws` は受け取った `SignedHeaders` と本物の鍵で署名を計算し直して照合し、資格スコープのサービスとリージョンがホストと食い違えば拒否する（AWS の前提を模したもの）。aws-chunked はボディのフレームを解いて長さとトレーラーを確かめる。E2E は mise の aws-cli 2.37.7 を `HOME` と `AWS_*` を一時ディレクトリに向けて実行し、`s3 cp` の 3MiB のアップロードが aws-chunked・CRC64NVME のトレーラー・`Expect: 100-continue` で届くことを確かめる。
- レビューで足したもの：
  - 再署名は、ホストが資格スコープのサービスのエンドポイントであるときだけ行う（`endpoint_mismatch`）。署名名とエンドポイント接頭辞の対応は同じスクリプトが botocore から `service_endpoints.rs` に生成する。接頭辞（`-fips` 付きも可）の左には仮想ホスト形式のバケットやアカウントのラベルがあってよく、右はリージョン1つ（スコープのリージョンと一致すること）か何も無いこと。S3 は `s3-<region>` と `s3-external-1` の旧形式と `s3-accesspoint` も認める。アプローチ節の「スコープとエンドポイントの食い違いは AWS が拒否する前提」は、これでプロキシ側でも確かめる。IoT のデータ（`<id>-ats.iot`）のようにアカウント固有の形のエンドポイントは再署名しない。
  - 利用者が作る API の前段（`execute-api`、API Gateway の呼び出し）は、署名した要求が API の持ち主のバックエンドに届くので、`services` に明示したときだけ再署名する。
  - `X-Amz-Date` が現在時刻から15分より離れていれば400（先の時刻の署名を作らせない）。
  - 署名の要らない発行 API の判定と、ダミーが無いときのボディ読み込みは `sts-fips`・`cognito-identity-fips` のホストにも効く。REST のテンプレート照合はパスのドットセグメントを解決し、リテラルを大文字小文字を区別せずに比べる。`X-Amz-Target` はカンマで区切った各値を見る。読み込んだボディに `identity` 以外の `Content-Encoding` があれば拒否する（`encoded_body`）。
  - 読み込み中のボディの合計は `max_body_bytes` の4倍までにし、空きを30秒待っても取れなければ503（`buffer_busy`）。
- 既知の制約：S3 のオブジェクトが `Content-Encoding: gzip` などで保存されていると、スクラブが有効なときダウンロードが502になる（v0.1 と同じくエンコードされた応答はスクラブできないため）。ワークスペースの `rust-version` は aws-sigv4 に合わせて 1.94.1 に上げた。

## Phase 10: AWS SSO

このフェーズの終わりで、人間が `credshim` のコマンドで SSO にログインすれば、`~/.aws` にダミーしか無い状態で、SSO のロールの権限で `aws` コマンドが動く。

**作るもの**

- SSO ログインのコマンド。デバイス認可フローの URL とコードを TTY に出し、人間がブラウザで承認する。得た SSO トークンはプロキシの中に保存し、期限前に更新する。
- SSO のルール：ダミーのアクセスキー ID、SSO のセッション、アカウント、ロール、束縛先。
- ロール認証情報の取得、メモリ上のキャッシュ、期限前の取り直し。取得した本物はスクラブ対象に加える。
- SSO トークンが切れたときの応答。上流へ送らず、人間に再ログインを促すエラーを返し、監査ログに残す。
- SSO のログアウト（トークンの失効と削除）。

**完了条件**

- [x] testkit のモック SSO（デバイス認可、トークン発行と更新、ロール認証情報の発行）に対し、ログインから `aws` CLI の実行までが通る。
- [x] ロール認証情報の期限切れ前後で、`aws` CLI の要求が途切れずに通る。
- [x] SSO トークンの期限切れ後は上流へ送らずエラーになり、再ログインで復旧する。
- [x] SSO トークンとロール認証情報がログ、エラー、ディスク上の平文、クライアントへの応答に現れない。
- [x] 脅威モデルの AWS の追加行それぞれに回帰テストがある。
- [ ] 人間が実際の IAM Identity Center でログインし、`aws` コマンドを確認する（手動マイルストーン）。

**実装メモ（Phase 10）**

- 保存先：SSO トークン（アクセストークン、リフレッシュトークン、`RegisterClient` のクライアント ID とシークレット、それぞれの期限）は**秘密ストア**に、セッションごとに1つの JSON（`credshim-aws-sso-<session>`）として置く。OAuth 保管庫はダミーをキーにした表で、プロキシのプロセスがファイル全体を書き直すので、別プロセスの `credshim aws sso login` が書く先には向かない。秘密ストアは `login` とプロキシの両方がすでに使っている経路で、段階Bでは専用ユーザーの側にある（Phase 11 の「SSO ログインは `secret set` と同じく専用ユーザーとして」に合う）。age-file はロックファイル（`<path>.lock`）で読み書きを直列にし、`secret set` とプロキシの書き戻しが互いの値を消さないようにした。`SecretStore` に `remove` を足した（`command` は読み取り専用なので拒否）。
- 書き戻し：プロキシはトークンを更新したら秘密ストアへ書き戻す。`SecretStore::update`（age-file ではロックの中で読んで書く。keychain は読んでから書く）で、保存されたログインを見てから決める。ID が自分の更新元と違うか、同じ ID でも期限が後なら（人間のログインし直し、同じストアを使う別のプロキシの更新）、書かずにそちらを採る。ログインが消えていれば（`logout`）、書き戻さずに使うのをやめる。`command` のように書けないストアでは、更新したトークンはメモリだけに置き、一度だけ警告する。
- 読み直し：実行中のプロキシは、トークンが無いか使えない（期限切れで更新できない、ポータルが401を返した）ときに秘密ストアを読み直す（1秒に1回まで）。再ログインは再起動なしで効く。
- 期限前の取り直し：ロール認証情報と SSO トークンは期限の10分前から取り直す（botocore の目安に合わせた）。取得はルールごとに直列にし、同時の要求で何度も取らない。ロール認証情報の取得がネットワークの失敗なら、まだ期限内の手持ちを使い続ける。取得に失敗したら5秒は同じ失敗を返し、トークンの更新に失敗したら30秒は再試行しない（期限切れでも同じ。期限内なら手持ちを使う）。どちらも要求ごとに IAM Identity Center を叩かないため。
- SSO トークンは要求ごとに期限を確かめる。ロール認証情報がまだ有効でも、SSO のログインが切れて更新できなければ上流へ送らない（完了条件の「SSO トークンの期限切れ後は上流へ送らずエラー」をそのまま守る）。`logout` はポータルの `Logout` でサーバー側のセッションを終わらせてから秘密ストアから消す（アクセストークンが切れていれば先に更新する。401 は失効を確かめられなかったものとして報告する）が、実行中のプロキシのメモリにあるトークンは、次にロール認証情報を取り直す時に401を受けるまで使われる。
- ログインが要るときの応答：403 で、要求の形に合わせたエラー（JSON は `__type`、Query は `<ErrorResponse>`、S3 は `<Error>`、EC2 は `<Response><Errors>`。どれも `x-amzn-ErrorType` 付き）を返す。コードは `CredShimSsoLoginRequired`、メッセージに `credshim aws sso login <session>` を入れ、`aws` CLI の表示に出ることを E2E で確かめた。拒否の理由は `sso_login_required`、`sso_refused`（ポータルが401以外の4xx）、`sso_unavailable`（届かない、5xx、429。502 を返す）。
- `RegisterClient` は `clientType: public`、`scopes: ["sso:account:access"]`、`grantTypes: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"]` で登録する。デバイス認可でリフレッシュトークンが出るかは実物では未確認（手動マイルストーンで確かめる）。出なければトークンの期限（IAM Identity Center の設定、既定8時間）まで使い、切れたら再ログインを促す。ポーリングは応答の `interval`（最低1秒）で行い、`slow_down` で5秒延ばし、`expiresIn` で打ち切る。`GetRoleCredentials` の `expiration` はミリ秒として扱う。
- プロキシ自身の SSO 通信は `UpstreamTransport`（mitm）が `Upstream` で直接 TLS を張って行う。応答は1MiB、全体は30秒まで。`testing` フィーチャーの DNS 上書きで MockSso に向けてテストする。待ち受けを通らないので、クライアントからの `oidc.*`・`portal.sso.*` への CONNECT の拒否はそのまま。
- スクラブ：core に `ScrubSource`（世代つきの置き換え対の提供元）を足し、SSO のプロバイダが取得したロール認証情報（アクセスキー ID はダミーに、シークレットとセッショントークンは固定文字列に）と SSO トークンを、キーごとに直近2世代まで渡す。
- 設定：`[[aws_sso_session]]`（`name`、`start_url` は `https://` のみ、`region` は小文字・数字・`-`）と `[[aws_sso_role]]`（`name`、`dummy_access_key_id`、`session`、`account_id` は12桁、`role_name` は IAM の文字種で64文字まで、`services`、`regions`）。静的キーと名前空間とダミーの重なり検査を共有する。`credshim preset aws-sso`、`credshim aws sso login <session>`（stdin が TTY でなければ拒否。疑似端末で迂回できるので、最後の防壁は人間が覚えのないコードを承認しないこと。URL とユーザーコードだけを表示し、デバイスコードは出さない）、`credshim aws sso logout <session>`。
- `expose_secret()` の許可先に `crates/aws/src/sso/api.rs`（トークン交換）と `crates/aws/src/sso/stored.rs`（保存形式）を足した。
- 既知の制約：`credshim aws sso login` のバイナリは TTY の確認と `testing` の DNS 上書きが無いため、テストでは拒否の経路だけを通す。デバイス認可フローそのものはライブラリの `sso::login` をモック SSO に対して通し（統合テストと aws CLI の E2E）、実物は手動マイルストーンで確かめる。`logout` には TTY の確認を付けていない（段階Aでは秘密ストアを直接消せるので守るものが無い）。keychain の `update` は読んでから書くだけで、age-file のようなロックは無い。保存されたログインが読めない（壊れている、別の `start_url`・`region` で作られた）ときも、消えたときと同じく書き戻さずに使うのをやめる（fail closed）。
- テスト：testkit の `MockSso` は `oidc.<region>` と `portal.sso.<region>` を1つの待ち受けで受け、クライアント登録、デバイス認可（`approve` するまで `authorization_pending`）、トークン発行と回転するリフレッシュ、ロール認証情報の発行、ログアウトを行う。発行したロール認証情報は `MockAws` と共有する鍵束（`Keyring`）に期限とセッショントークン付きで入り、`MockAws` は期限切れを `ExpiredToken` で拒否し、`x-amz-security-token` が署名されていることを確かめる。

## Phase 11: 運用への組み込み

v0.1 の段階B・Cと開発体験の仕組みに SSH と AWS を載せる。

**作るもの**

- 段階B：agent ソケットを専用ユーザーの所有にし、開発ユーザーは接続だけできるようにする。SSO ログインは `secret set` と同じく専用ユーザーとして人間が行う。`credshim service install` と `scripts/stage-b/verify.sh` を対応させる。
- 乱用の緩和：SSH はルールごとのレートと日次回数。AWS はサービスと操作の許可リスト、レート、日次回数。
- `credshim env` に `SSH_AUTH_SOCK` と `AWS_CA_BUNDLE`、ダミーのプロファイルの設定を出す。`credshim doctor` で agent への到達、session-bind に対応した OpenSSH のバージョン、`aws` CLI がプロキシを通ること、`~/.ssh` と `~/.aws` に本物が残っていないことを確かめる。
- 段階C：コンテナ内の `ssh` から agent を使う方法と、22番ポートを既存の CONNECT トンネル経由で出す設定例。コンテナ内の `aws` コマンドの設定例。
- 既存の認証情報からの移行手順のドキュメント。SSH は新しい鍵を生成して登録し、古い鍵を無効化して削除する。AWS は静的キーを作り直して古いキーを無効化し、SSO は `aws sso logout` で失効させ、`~/.aws/sso/cache` と `~/.aws/cli/cache` を削除する。

**完了条件**

- [x] 段階Bで、開発ユーザーが agent と AWS の再署名を使えるが、秘密ストアと設定を読めず書けないことを `verify.sh` が確かめる。
- [x] 上限を超えた SSH の署名要求と AWS の要求、許可リスト外の AWS の操作が拒否される。
- [x] `credshim doctor` が、agent に届かない場合、OpenSSH が古い場合、`aws` がプロキシを通らない場合、`~/.ssh` や `~/.aws` に本物が残っている場合をそれぞれ報告する。
- [ ] 段階C の構成でコンテナ内から `git clone` over SSH と `aws` コマンドが通る（手動マイルストーン）。

**実装メモ（Phase 11）**

- AWS の操作の許可リスト：`[[aws_key]]`・`[[aws_sso_role]]` の `operations`。書き方は `<署名名>:<操作名>`（署名名は `services` と同じく資格スコープのサービス名で、`s3express` は `s3`）で、末尾の `*` だけを前方一致として認める。操作名は大文字小文字を区別しない。認証情報以外の、サーバーが使える値を返す操作（`ecr:GetAuthorizationToken` など）は既定では通し、絞りたい人がこの許可リストで絞る（拒否リストでは網羅できないため）。
- 操作の特定：Query・EC2 の `Action`、JSON の `X-Amz-Target`、rpc-v2-cbor のパスに加え、REST は `scripts/aws/credential-operations.py` が botocore から生成する `rest_operations.rs`（rest-json と rest-xml の全操作、約1万件。メソッド、パスのテンプレート、URI のリテラルのクエリと必須のクエリ引数、必須のヘッダー）で照合する。一致したもののうち、ほかの一致に「上回られる」ものだけを外す。上回るのは、必須のクエリとヘッダーを包含し、パスのリテラルが少なくなく、どちらかで真に多いとき（`GET /key` は `GetObject`、`uploadId` 付きは `ListParts`、`x-amz-copy-source` 付きの `PUT` は `CopyObject`）。貪欲なラベル（`{x+}`）を含むテンプレートどうしは、パスが同じときしかリテラルの数で比べない（ARN に `/` が入ると別のテンプレートにも一致するため、両方を残す）。貪欲なラベルは後ろのテンプレートの部分が一致するように区切る。パスに `.`・`..`・空のセグメント（末尾の `/` を除く）があれば REST の操作は特定しない（S3 は解決せずキーとして扱うので、こちらで解決すると別の操作に見える）。REST のエンドポイントで表のどれにも一致しなければ、`Action` などの名前だけでは特定したことにしない。S3 はホストのラベルを右から見て、仮想ホスト形式（アクセスポイントを含む）かパス形式かを決め、テンプレートの先頭の `{Bucket}` の扱いを決める（`s3.` で始まる名前のバケットをパス形式と取り違えないため）。許可するのは、特定した操作が1つ以上あり、そのすべてが許可リストにあるときだけ（`Action` をクエリとボディで食い違わせても、両方が許可されていなければ通らない。同じ形の操作が複数あれば全部が要る）。特定できなければ拒否する。判定は再署名の直前（サービス・リージョン・エンドポイントの検査のあと）で、403 と要求の形に合わせた AWS のエラー（`CredShimOperationNotAllowed`、許可されていない操作名をメッセージに入れる）を返し、監査ログは decision `not_allowed`、reason `operation_not_allowed`。許可リストが無いルールでも特定した操作名を監査ログの `operation` に出すので、REST の操作名もログに残るようになった。
- 上限：AWS のルールは `limits = { per_minute, per_day, concurrent }`、SSH の鍵は `limits = { per_minute, per_day }`（署名には長さが無いので `concurrent` は読み込み時に拒否）。どちらも `credshim_core::Limiter` を、HTTP のルールとは別のインスタンスで持つ（名前空間が別なので窓を混ぜない）。AWS は許可リストの判定を通ったあと、ロール認証情報の取得より前に数え（上限を超えた要求で IAM Identity Center を叩かない）、超えたら 429 と `CredShimLimitExceeded`、decision `limited`、reason `limited`。同時実行数は応答のボディを返し終えるまで数える。SSH は署名を認めた要求だけを数え、超えたら `SSH_AGENT_FAILURE` と監査の reason `limited`。
- agent の接続元：`[ssh] client_uids`（既定はプロキシ自身の uid）。受け付けた接続ごとに `peer_cred`（Linux は `SO_PEERCRED`、macOS は `getpeereid`）で uid を確かめ、無ければすぐ閉じる。自分以外の uid があるときだけソケットを 0666 にする（ディレクトリの権限と uid の検査で絞る。macOS は人間のユーザーがみな `staff` なので、グループの権限では開発ユーザーだけに絞れない）。uid は数値で書く（名前の解決に libc を持ち込まない。構築スクリプトが `id -u` で書く）。`run` の起動時の権限の確認は、ソケットそのものではなくソケットのディレクトリにした（0666 のソケットが次の起動で弾かれるため）。
- 段階B：ソケットは `/var/lib/credshim-ssh/agent.sock`（ディレクトリは専用ユーザーの所有で 0755。`/var/run` は macOS で再起動時に消え、専用ユーザーは作り直せないので使わない）。systemd の `ReadWritePaths` にこのディレクトリを足した。`credshim service install --user <開発ユーザー>`（省略時は `SUDO_USER`）がその uid を構築スクリプトに渡し、スクリプトは新しく作る設定に `[ssh] socket` と `client_uids` を書く。設定がすでにあれば書き換えず、足すべき行を表示する。SSH の鍵の生成と SSO のログインは `sudo -u credshim HOME=/var/lib/credshim credshim ... --config /var/lib/credshim/config.toml` で専用ユーザーとして行う（設定の例のコメントと README に書いた）。`verify.sh` は、agent のディレクトリが専用ユーザーの所有で書けないこと、ソケットがあれば専用ユーザーの所有で `ssh-add -l` が届くこと、秘密ストアのロックファイルを読めず書けないこと、`/etc/credshim/env` の `AWS_CA_BUNDLE` が読める公開のバンドルを、`SSH_AUTH_SOCK` が agent を指すことを確かめる。AWS の再署名そのものは段階Aと同じコードで、段階Bの開発ユーザーからは `credshim doctor` の aws の確認でプロキシと CA まで確かめる。CI の `stage-b` ジョブは開発ユーザーを先に作って `--user` で渡し、専用ユーザーとして鍵を作ったあと開発ユーザーが `ssh-add -l` で鍵を見られることを確かめるように変えた（CI は GitHub Actions の課金の問題で動いておらず、構築スクリプトはこの環境でも実行していない。`bash -n` と読み合わせだけ）。
- `credshim env`：`AWS_CA_BUNDLE`（結合バンドル。`SSL_CERT_FILE` と同じく常に出す）、`[[ssh_key]]` があるときだけ `SSH_AUTH_SOCK`（無いのに出すと開発者の `ssh` を壊すため）。ダミーのプロファイルは、AWS のルールがちょうど1つなら `AWS_ACCESS_KEY_ID` と `AWS_SECRET_ACCESS_KEY=credshim-dummy` を出し、2つ以上なら `~/.aws/credentials` に書く値をルールごとのコメントで出す（環境変数では1つのプロファイルしか表せないため）。
- `credshim doctor`：設定を読まずに環境変数だけで動く（段階Bの開発ユーザー向け）。`ssh` は `SSH_AUTH_SOCK` の agent に鍵の一覧を求め、届かなければ fail、CredShim の鍵（コメント `credshim:`）が無ければ warn。`openssh` は `ssh -V` の版が 8.9 より前なら、agent が CredShim のとき fail、それ以外は warn。`aws` は `aws --endpoint-url https://credshim.test dynamodb list-tables` を、固定のダミーのキーと `AWS_REGION` を与え `AWS_PROFILE`・`AWS_SESSION_TOKEN` などを外して実行する（本物のキーで署名させない。プロキシの応答は JSON なので CLI は成功する）。名前解決の失敗は「プロキシを通らない」、証明書の失敗は「`AWS_CA_BUNDLE`」と案内する。`files` は `~/.ssh` の通常のファイルの先頭の1行だけを読んで秘密鍵を探し、`~/.aws/credentials`・`~/.aws/config`（`AWS_SHARED_CREDENTIALS_FILE`・`AWS_CONFIG_FILE` を優先）の本物のアクセスキー（`AKIA`・`ASIA` などで始まる20文字）とセッショントークン、`credential_process`・SSO・`aws login` のプロファイル、`~/.aws/sso/cache`・`cli/cache`・`login/cache` の JSON、環境変数の本物のキーとセッショントークンを報告する。出すのはパスとプロファイル名だけ。`ssh`・`aws` のプログラムの実行は `--no-runtimes` で省く。
- 段階Cと移行：README に節を足した。コンテナからの SSH は agent のソケットのマウントと、既存の CONNECT トンネル（インターセプトしないホストへの CONNECT は任意のポートを素の TCP で中継する）を使う `ProxyCommand` の例。uid の扱い（userns の無い docker ではコンテナの uid がそのままホストの uid）と Docker Desktop のソケット中継は、手動マイルストーンで確かめる。

## 範囲外

- git のコミット署名（`ssh-keygen -Y sign`）。署名対象の形式が認証と異なり、同じ許可経路には乗せない。v0.2 では拒否する。
- SSH 接続そのものの中継（コマンド単位の許可リスト）。必要になったら別フェーズで検討する。
- git の SSH を HTTPS に書き換えてトークン注入で扱う方法。既存機能と git の設定だけで実現でき、新しいコードは要らない。
- SSH 証明書の発行、FIDO（`sk`）鍵、session-bind に対応しない SSH クライアント。
- AssumeRole によるロールの切り替え。認証情報を発行する操作を既定で拒否するので、`role_arn` と `source_profile` を使うプロファイルや `aws sts assume-role` は v0.2 では動かない。返ってきた一時認証情報を保管庫にしまってダミーを返す形（v0.1 の OAuth と同じ）で後から足せる。
- クライアント側で署名するもの（クエリ文字列による SigV4）。エージェントがダミーで作った値は無効になる。影響するのは `aws s3 presign`、`aws eks get-token`（`update-kubeconfig` 経由の `kubectl`）、`aws rds generate-db-auth-token`、CodeCommit の git 認証ヘルパー。
- SigV4a（マルチリージョンアクセスポイント）。
- S3 Express One Zone（ディレクトリバケット）。`aws` CLI は `s3:CreateSession` で得たセッション認証情報で署名するが、`CreateSession` は認証情報を発行する操作として拒否するので動かない。
- デュアルスタックのエンドポイント（`*.api.aws`、`use_dualstack_endpoint`）。束縛は `amazonaws.com` 配下だけ。
- `aws` CLI 以外の AWS SDK での動作保証。同じ仕組みで動く見込みだが、v0.2 の完了条件には入れない。
- AWS 以外の SSO（Okta などの SAML から AWS へ入る構成）。
- 中国リージョン（`amazonaws.com.cn`）と GovCloud 以外の独立パーティション。束縛と MITM は `amazonaws.com` 配下だけ。

## 事前検証の結果

Oct 1, 2026 に実機で確かめた。環境は macOS 15（Darwin 24.6）、OpenSSH_9.9p2（クライアント、`ssh-agent`、`/usr/sbin/sshd`）、`aws-cli/2.37.7`（`mise exec aws-cli@2.37.7`、同梱の botocore モデル）、Rust 1.98。

**SSH**（一般ユーザーで起動した `sshd` と GitHub に対し、`ssh` と scratch の `ssh-agent` の間に agent プロトコルを記録する中継を挟んで観察）

- 確認：SSH 接続ごとに agent 接続は1本で、順序は bind → `REQUEST_IDENTITIES` → `SIGN_REQUEST`。bind のホスト署名は Ed25519、ECDSA P-256、RSA（`rsa-sha2-512`、強制すれば `rsa-sha2-256`）のすべてで検証でき、`ssh-rsa`（SHA-1）は出なかった。署名対象はユーザー認証要求として解析でき、セッション ID は bind と一致した。
- 確認：署名対象の method は `publickey-hostbound-v00@openssh.com` で、末尾のホスト鍵は4種の接続すべてで bind のホスト鍵と一致した。GitHub も `publickey-hostbound@openssh.com` を広告している。セッション ID は `sntrup761x25519-sha512` で 64 バイト、`curve25519-sha256` で 32 バイト。
- 確認：`ssh -A` の先から `ssh` すると、フォワード経由の agent 接続に `is_forwarding=1`（外側のセッション）→ `is_forwarding=0`（内側）の順で bind が来て、署名のセッション ID は最後の bind と一致する。ProxyJump は踏み台と宛先で agent 接続が分かれ、どちらも `is_forwarding=0`。
- 確認：agent が bind に失敗を返しても `ssh` は署名要求を続け、ログインに成功する。束縛は agent 側でしか強制できない。署名を拒否すると `ssh` は残りの認証方式に進み、`Permission denied (publickey)` で終わる。
- 確認：`ssh-keygen -Y sign` は bind を送らず、署名対象は `SSHSIG` で始まる（namespace は `git`）。
- 確認：素の `ssh-agent` は制約なしの鍵なら、bind の無い接続で任意のバイト列と偽の認証要求に署名する。
- **前提が誤り**：`ssh-add -h` で制約した鍵は、bind の無い接続での署名を拒否した。アプローチ節の CredShim の存在理由を書き直した。
- 確認：`ssh -T git@github.com` と `git ls-remote`（`GIT_SSH_COMMAND` 経由）は認証の前に bind を送り、ホスト鍵は GitHub の公開値と一致した。`ssh.github.com:443` も同じホスト鍵3種。
- 確認：`ssh-agent-lib` 0.6.0 の `SessionBind::verify_signature()` は実際に取った bind 7件（手元の3種と RSA-256、GitHub の3種）をすべて通し、セッション ID を1ビット変えると7件とも拒否した。

**AWS**（`mitmdump` を `HTTPS_PROXY` に置き、`AWS_CA_BUNDLE` をその CA にして、`--endpoint-url` を使わず実際のホスト名で要求を記録、応答はモック）

- 確認：`aws` CLI はアクセスキー ID の形式を検証しない。32文字の英大文字、`-`・`.`・`_` を含む小文字混じり、20文字の `AKIA…` のどれも受け付け、Authorization の `Credential=` にそのまま載せる。v0.1 のダミーの形式（24文字以上の unreserved 文字）がそのまま使える。
- 確認：`AWS_CA_BUNDLE` は信頼ストアを置き換える。開発CAだけを入れてプロキシを外すと実 STS で `CERTIFICATE_VERIFY_FAILED`。
- 確認：通信はすべて HTTP/1.1 の CONNECT。STS はリージョン別のエンドポイント（`sts.ap-northeast-1.amazonaws.com`）。S3 は仮想ホスト形式（`<bucket>.s3.<region>.amazonaws.com`）。
- 確認：S3 のアップロード（`s3 cp` の単一と 8MiB ごとのマルチパート、`s3api put-object`）は `x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER`、`Content-Encoding: aws-chunked`、`Transfer-Encoding: chunked`、`x-amz-trailer: x-amz-checksum-crc64nvme`、`x-amz-decoded-content-length` で、8MiB のパートと 19MiB の `put-object` には `Expect: 100-continue` が付いた（`--debug` で確認）。署名付きチャンク（`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`）は HTTPS では使われなかった。ボディの無い要求は空文字列のハッシュ、`CompleteMultipartUpload` の XML は実ハッシュ。
- 確認：S3 以外（STS、EC2、DynamoDB、CloudWatch Logs、CloudWatch、Lambda）は `x-amz-content-sha256` を付けず、ボディは `Content-Length` 付き。CloudWatch はモデル上 rpc-v2-cbor が第一だが、CLI は JSON（`X-Amz-Target` と `x-amzn-query-mode: true`）で送った。
- 確認：採取した要求 20件（S3 の各形式、日本語と空白を含むキー、DynamoDB、Logs、CloudWatch、EC2、Lambda）の署名を、ダミーのシークレットを使って `aws-sigv4` 1.6 で再計算し、20件すべて一致した。S3 は `PercentEncodingMode::Single` と `UriPathNormalizationMode::Disabled`、他は既定の設定。
- botocore モデル（436 サービス）：Query は17サービス（`autoscaling`、`cloudformation`、`elb`・`elbv2`、`iam`、`rds`、`redshift`、`ses`、`sns`、`sts` など）と EC2。rpc-v2-cbor が第一のものが18サービス。応答に AWS の認証情報（`SecretAccessKey` と `SessionToken`）が乗る操作は17サービスの37操作（`sts` の7操作、`iam:CreateAccessKey`、`s3:CreateSession`、`s3control:GetDataAccess`、`sso:GetRoleCredentials`、`cognito-identity:GetCredentialsForIdentity`、`ssm:GetAccessToken`、`eks-auth:AssumeRoleForPodIdentity`、`lakeformation:GetTemporary*`、`lightsail:CreateBucketAccessKey` など）。このうち `sso`、`sso-oidc`、`signin`、`sts:AssumeRoleWithWebIdentity`・`AssumeRoleWithSAML`、`cognito-identity` は `noAuth` で、ダミーのアクセスキー ID を運ばない。アプローチ節を書き直した。
- 未確認：資格スコープとエンドポイントが食い違う要求を AWS が拒否すること（ドキュメント上の挙動）。Phase 9 の手動マイルストーンで、スコープのサービスを書き換えた要求が拒否されることも確かめる。
- 未確認：SSO（デバイス認可、リフレッシュトークン、`GetRoleCredentials`）は実物の IAM Identity Center が要る。モデル上は `RegisterClient`（`/client/register`）→ `StartDeviceAuthorization` → `CreateToken`（`grantType` が device_code か refresh_token）で、`GetRoleCredentials` は `GET /federation/credentials?role_name=&account_id=` に `x-amz-sso_bearer_token`。Phase 10 の手動マイルストーンで確かめる。

**決まったこと**

- クレート：SSH は `ssh-agent-lib` 0.6（`ssh-key` 0.6 を `crypto` フィーチャー付きで、`secrecy` 0.10 はワークスペースと同じ）。SigV4 は `aws-sigv4` 1.6 と `aws-credential-types` 1.3。`aws-sigv4` の MSRV は 1.94.1 なので、ワークスペースの `rust-version` を 1.85 から上げる。
- 鍵の種類：生成するユーザー鍵は Ed25519 だけ。ホスト鍵の検証は Ed25519、ECDSA、RSA（`rsa-sha2-256`・`rsa-sha2-512`）に対応する（GitHub は3種とも出す）。
- ホスト鍵の書き方：`SHA256:` の指紋（GitHub が公開している形式）。GitHub のプリセットは `SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`（Ed25519）、`SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM`（ECDSA）、`SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s`（RSA）で、`github.com:22` と `ssh.github.com:443` の両方に効く。
- ダミーのアクセスキー ID：v0.1 のダミーの形式と長さ制約をそのまま使う。
- AWS の束縛先：ホストの接尾辞（`amazonaws.com` 配下）で束縛し、サービスとリージョンの絞り込みは資格スコープで行う（アプローチ節）。
- S3 の署名付きチャンク：対応しない。`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` と `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` は拒否する。
- 認証情報を発行する操作の一覧：botocore モデルから、応答に `SecretAccessKey` か `SessionToken` を含む操作を機械的に抜き出したものを既定の拒否リストにする。`noAuth` の操作はホストと操作で常に拒否する（SSO OIDC、SSO ポータル、signin はホストごと）。

## 実装時に決めること

- agent と SigV4 の実装の置き場所（mitm とは別クレートにするか）。
- 既存の SSH 鍵ファイルの取り込みを用意するか。用意する場合は TTY から1回だけ読む。
- 使うたびの確認（`ssh-add -c` 相当）を用意するか。
- 許可リストでの操作名の書き方。AWS の認証情報以外の、サーバーが使える値を返す操作（`ecr:GetAuthorizationToken` による `aws ecr get-login-password`、`codeartifact:GetAuthorizationToken` など）を拒否するか、正当な「利用」として許すか。モデル上、秘密らしい値（トークン、パスワード、秘密鍵）を返す操作は183あり、拒否リストで網羅するのは無理なので、ここから先は許可リストで扱う。
- 非 S3 のボディ上限の既定値。上限を超える操作は動かなくなる（`aws lambda update-function-code --zip-file`（直接アップロードは最大 50MB）、大きな入力の Bedrock `InvokeModel`、DynamoDB の `BatchWriteItem`（最大 16MB）、CloudWatch Logs の `PutLogEvents`（最大 1MB）など）。
- SSO トークンとリフレッシュトークンの保存先（秘密ストアか OAuth 保管庫か）。
