# CredShim 脅威モデルと設計原則

**守るもの**は秘密の「値」そのもの。.env、アプリのメモリ、ログ、テストfixture、エージェントのコンテキストに本物が現れないこと。

**守らないもの**は秘密の「利用」。エージェントは値を知らなくても、プロキシ経由で本物の権限を使ってAPIを叩ける。これは仕組み上避けられない前提で、許可リスト・上限・監査ログで緩和する。

一番危ないのは「本物のキーが別ホストへ注入されること」と「プロキシの設定や秘密ストアを書き換え・読み出しされること」。以下の原則はほぼこの2点を塞ぐためにある。

| エージェントが取りうる行動 | 対策（原則） |
| --- | --- |
| リポジトリ、環境変数、アプリのメモリ、ログを読む | 本物がそこに存在しない（1） |
| ダミーキー付きリクエストを攻撃者のホストへ送る | ホスト束縛、束縛外は403（2, 4） |
| CONNECT先と内側のHostヘッダーを食い違わせる | 接続先で照合、不一致は拒否（3） |
| APIのエラー応答などに本物の値をエコーさせる | レスポンスのスクラブ（5） |
| 設定を書き換えて秘密を別ホストに束縛し直す | 設定をエージェントが書けない場所へ（6） |
| プロキシのメモリ、秘密ストア、CA秘密鍵を読む | OSユーザー／コンテナ分離（6, 9） |
| プロキシ経由でクラウドのメタデータ（`169.254.169.254` など）からマシンの認証情報を得る | リンクローカル、未指定アドレス、AWS の `fd00:ec2::/32`、GCP の `fd20:ce::254` へは、名前解決のあとで接続を拒否（403。インターセプトするホストでも同じ） |
| プロキシ経由で本物の権限を乱用する | 残存リスク。許可リスト、上限、監査ログで緩和。`allow_methods` のあるルールでは、メソッドを上書きするヘッダーとクエリの `_method` も許可リストのメソッドでなければ拒否し、`allow_paths` のあるルールでは `X-Original-URL`・`X-Rewrite-URL` を拒否する。フォームのボディの `_method` はボディを読まないので見ていない |

1. **秘密はプロキシプロセスの中だけ。** 登録は人間がTTYから行い、argvや環境変数を経由しない。値を取り出すコマンドは作らない。
2. **ホスト束縛。** 各秘密は宛先（scheme、host、port、任意でpath prefix）に束縛する。差し替えるのは、実際に接続する上流が束縛先と一致し、かつ上流のTLS証明書をシステムの信頼ストアで検証できたときだけ。
3. **照合はクライアントが操れる値でなく接続先で。** CONNECTのauthorityを正とし（末尾のドットは取り除いてから照合する）、内側のHostや:authorityが一致しなければ拒否する。
4. **束縛外に現れたダミーは差し替えず403と警告ログ。** 平文HTTPの上流への注入は明示許可がない限り禁止。リダイレクトはプロキシが追わずクライアントへ返す。
5. **ボディは既定でバッファしない。** 書き換えはトークンエンドポイントのような小さいボディに限り、サイズ上限を設ける。レスポンス中の秘密値スクラブは安全網として別に持つ。WebSocket の 101 以降のフレームはスクラブしない。
6. **設定・秘密ストア・CA秘密鍵はエージェントが触れない場所に。** 最終形ではプロキシを別OSユーザー、またはエージェントが動くコンテナの外で動かす。ルール設定も秘密と同じくらい重要な資産として扱う。起動時の検査は、状態ファイルと、それを置くディレクトリ、シンボリックリンクをたどった各段のディレクトリまで。その上のディレクトリは見ないので、他人が書けるディレクトリの下に状態を置くと、途中のディレクトリごと差し替えられうる。
7. **登録済みホストだけMITMし、他は素のTCPトンネル。** 証明書ピン留めや無関係な通信を壊さない。
8. **ログやエラーに秘密を出さない仕組みを型で強制。** 秘密は専用型で持ち、Debug/Display出力をマスクする。
9. **ルートCAはOSの信頼ストアに入れない。** アプリにだけ環境変数で渡し、CA鍵が漏れた場合の被害をこの開発用途に閉じ込める。例外は、macOS で環境変数を読まない Go 製ツールのために README が任意で案内する、段階Bの開発ユーザーのログインキーチェーンでの信頼。その場合 CA 鍵の漏洩はその開発ユーザーのすべての HTTPS 通信に及ぶ（残存リスク）。

設定の読み直し（SIGHUP、段階Bでは `sudo credshim service reload`）を起こせるのは、プロキシと同じユーザーか root だけで、段階Bの開発ユーザーは起こせない。読み直しても上限のカウンタは引き継ぐので、読み直しで上限を0に戻すことはできない。設定が壊れている、秘密が無いなどで読み直せなければ、動いている設定を使い続ける。読み直しのあとは、開いたままの接続の上でも次の要求から新しいルールで判定する（ルールを消すか秘密を変えれば、次の要求からは古い秘密を注入しない）。処理中の要求は読み直す前のルールで最後まで流れる。秘密ストア、CA、待ち受け、監査ログ、OAuth、SSH は起動時の設定のままで、読み直しでは変えない。

base URL モードでは、接続先はクライアントが操れる値ではなく設定の対応表（接頭辞→ルールのホスト）で決まる。クライアントが選べるのはパスだけなので、接頭辞の照合はセグメント単位で行い、ドットセグメントやエンコードされた区切りを含むパスは一致させない。listener はループバックだけに bind し、ループバック以外を名乗る Host は拒否する（DNS リバインディング対策）。ダミーを含まない要求はそのまま転送するが、本物は使わないので MITM の pass と同じ扱いになる。

## SSH エージェント（v0.2）

CredShim は ssh-agent として、鍵をプロキシの中だけに置いて署名を代行する。署名するのは、同じ agent 接続で検証済みの `session-bind@openssh.com` があり、そのホスト鍵の SHA256 指紋がルールの束縛先に含まれ、署名対象が bind のセッション ID と許可されたユーザー名を含むユーザー認証要求（`publickey` か `publickey-hostbound-v00@openssh.com`。後者はホスト鍵が bind と一致すること）ちょうどの形をしているときだけ。1本の接続で受け付ける bind は1回で、検証に失敗した bind や2回目の bind のあとはその接続での署名をすべて拒否し、`is_forwarding=1` の bind を一度でも受けた接続（`ssh -A` の先）も拒否する。

| エージェントが取りうる行動 | 対策 |
| --- | --- |
| `~/.ssh` やプロセスのメモリから秘密鍵を読む | 鍵はプロキシの中で生成し秘密ストアにだけ置く。ディスク上の鍵ファイルは作らない |
| agent ソケットを自作クライアントで叩き、攻撃者のサーバーへの認証に使う | session-bind 必須。ホスト鍵が束縛先でなければ署名しない |
| 束縛先への正規セッションで得た署名を別ホストへ流用する | 署名対象に bind のセッション ID が入り、他の接続では通らない |
| 任意のデータ（コミット署名、別プロトコルの challenge）に署名させる | ユーザー認証要求ちょうどの形以外は拒否 |
| agent フォワードを経由して別ホストから使う | フォワードされた接続からの要求は拒否 |
| 束縛先への本物の権限を乱用する（署名を大量に得る） | 残存リスク。ルールごとの毎分・日次の上限、ホスト鍵とユーザー名の許可リスト、監査ログで緩和 |
| 同じマシンの別ユーザーが agent ソケットにつなぐ | 接続元の uid を `SO_PEERCRED`／`getpeereid` で確かめ、`[ssh] client_uids`（既定はプロキシ自身の uid）以外は切る。段階Bのソケットは専用ユーザーが所有し開発ユーザーが書けないディレクトリに置く |
| 移行前の鍵を `~/.ssh` から読む | 残存リスク。`credshim doctor` が `~/.ssh` に残った秘密鍵を報告する。既存の鍵は読まれた前提で、新しい鍵に入れ替えてサーバーから外す |

## AWS 認証情報（v0.2）

`~/.aws` にはダミーのアクセスキーだけを置く。CredShim は `amazonaws.com` 配下を MITM し、Authorization の資格スコープにダミーのアクセスキー ID が入った SigV4 要求だけを、本物の認証情報で署名し直して上流へ送る。署名し直すヘッダーはクライアントが署名したものと同じ集合で、時刻とスコープもクライアントの値を使う。S3 は `x-amz-content-sha256` の値をそのまま署名に使いボディはストリームで流し、それ以外のサービスは上限付きでボディを読んでハッシュを計算する。サービスとリージョンの絞り込みはスコープで行い、ホストがスコープのサービスとリージョンのエンドポイントでなければ再署名しない（対応表は botocore から生成）。利用者が作る API の前段（`execute-api`）は、署名した要求が持ち主のバックエンドに届くので、ルールに明示したときだけ再署名する。`X-Amz-Date` が現在時刻から15分より離れた要求も再署名しない。

SSO のロールでは、SSO のログインを CredShim が行う。`credshim aws sso login` がデバイス認可フローで得たトークンを秘密ストアに置き、プロキシはそれでロール認証情報を取得してメモリに持ち、期限前に取り直す。プロキシ自身の SSO の通信は待ち受けを通らないので、クライアントからの SSO OIDC とポータルへの CONNECT は引き続き拒否される。

| エージェントが取りうる行動 | 対策 |
| --- | --- |
| `~/.aws` の credentials を読む | ダミーのアクセスキーしか無い。本物は秘密ストアとプロキシのメモリだけ |
| ダミーのアクセスキーで署名した要求を AWS 以外のホストへ送る | `amazonaws.com` 配下以外でダミーが見つかれば403（平文 HTTP も同じ）。本物での署名は、スコープのサービスのエンドポイント宛てにしか行わない。API Gateway など利用者のバックエンドに届くエンドポイントは明示したときだけ |
| 束縛先の API で新しい認証情報を発行させ、応答から本物の値を得る | botocore のモデルから抜き出した、応答に `SecretAccessKey` か `SessionToken` を含む37操作を拒否。Query の `Action` はクエリ文字列とボディの両方、JSON は `X-Amz-Target`、rpc-v2-cbor はパス、REST はメソッドとパスのテンプレートで判定する |
| 署名の要らない API（SSO OIDC のデバイス認可、SSO ポータル、`AssumeRoleWithWebIdentity`・`AssumeRoleWithSAML`、`GetCredentialsForIdentity`、`aws login`）で自分で認証情報を得る、人間に承認させる | ルールと無関係に拒否。SSO OIDC、SSO ポータル、signin はホストごと CONNECT の段階で（AWS の設定が無くても）、STS と Cognito Identity の操作は MITM したうえで操作名で |
| AWS の応答に本物のキーをエコーさせる | 本物のアクセスキー ID とシークレットをスクラブ対象に加える |
| 署名付きチャンク（`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`）でプロキシの知らない署名を続けさせる | 拒否 |
| SSO のキャッシュ（`~/.aws/sso/cache`、`~/.aws/cli/cache`）を読む | ログインは `credshim aws sso login` で行い、`~/.aws` には何も書かない。SSO トークン（アクセス、リフレッシュ、クライアントのシークレット）は秘密ストアに暗号化して置き、ロール認証情報はプロキシのメモリだけ |
| SSO トークンやロール認証情報を、ログ、エラー、応答から得る | 取得したロール認証情報と SSO トークンは直近2世代までスクラブ対象に加える。ログとエラーには状態コードと AWS のエラーコードだけを出す |
| SSO の期限切れやログアウトのあとも使い続ける | プロキシは要求ごとに SSO トークンの期限を確かめ、更新できなければ上流へ送らず拒否する。ロール認証情報の取得が401なら秘密ストアを読み直し、新しいログインが無ければ拒否する。秘密ストアからログインが消えていれば、更新したトークンを書き戻さずに使うのをやめる。`logout` はアクセストークンが切れていれば更新してからポータルのセッションを終わらせる |
| 束縛先の API で本物の権限を乱用する、認証情報以外の秘密（`ecr:GetAuthorizationToken` など）を得る | 残存リスク。ルールの `operations` で操作を許可リストにでき、要求から特定した操作のどれかが許可リストに無ければ、または操作を特定できなければ403。ルールごとの毎分・日次・同時実行の上限は429。どちらも上流へは何も送らない。IAM 側の最小権限を併用する |
| 移行前の認証情報を `~/.aws` や環境変数から読む | 残存リスク。`credshim doctor` が `~/.aws` の本物のアクセスキー、`credential_process`・SSO のプロファイル、SSO と CLI のキャッシュ、環境変数の本物のキーとセッショントークンを報告する（値は出さない） |
| 自分で `credshim aws sso login` を実行して人間に承認させる | 残存リスクを含む。`login` は stdin が TTY でなければ拒否するが、疑似端末で迂回でき、`--config` で自分の秘密ストアを指せば得たトークンを読める（そのトークンは SSO の本人の全アカウントとロールに効く）。最後の防壁は、人間が覚えのないデバイスコードを承認しないこと。段階Cではコンテナから SSO OIDC とポータルへの出口がプロキシしか無く、プロキシはそれらへの CONNECT を拒否するので、コンテナ内の `login` は届かない。ただし拒否はホスト名によるので、IP アドレスや自前の DNS 名で CONNECT されると届く |

## 回帰テスト対応表

脅威モデルの各行に対応する回帰テスト。

| 脅威 | テスト |
| --- | --- |
| リポジトリ、環境変数、アプリのメモリ、ログを読む | `crates/mitm/tests/inject.rs` の `secrets_and_dummies_never_reach_the_logs_and_requests_are_audited`、`crates/cli/tests/config.rs` の `secret_list_prints_names_and_times_but_never_values`・`audit_log_records_decisions_as_json_without_values`、`crates/core/tests/rules.rs` の `debug_output_never_contains_secret_values`、`crates/core/tests/scrub.rs` の `debug_output_never_contains_secret_values`、`crates/mitm/tests/oauth.rs` の `code_exchange_hands_the_app_dummies_and_the_api_real_tokens`、`crates/mitm/tests/forward_proxy.rs` の `userinfo_stays_out_of_the_host_header_and_logs`（URL の userinfo をログにも上流にも出さない） |
| ダミーキー付きリクエストを攻撃者のホストへ送る | `crates/mitm/tests/base_url.rs` の `a_dummy_bound_to_another_host_is_refused`・`paths_outside_a_prefix_and_proxy_forms_are_refused`、`crates/core/tests/base_url.rs` の `paths_that_could_climb_out_of_a_prefix_never_resolve`・`unsafe_or_ambiguous_prefixes_are_rejected`、`crates/mitm/tests/inject.rs` の `dummy_sent_to_another_intercepted_host_is_403_and_nothing_reaches_upstream`・`dummy_over_plain_http_is_403_and_nothing_reaches_upstream`・`dummy_over_plain_http_to_its_own_bound_destination_is_403_and_never_injected`（束縛先そのものでも平文HTTPには注入しない）、`crates/core/tests/rules.rs` の `dummy_sent_to_an_unbound_destination_is_denied_and_left_untouched`・`dummy_hidden_anywhere_in_the_request_is_found`・`path_prefix_binds_the_dummy_to_that_subtree`、`crates/mitm/tests/oauth.rs` の `client_secret_dummy_is_refused_away_from_the_token_endpoint`、fuzz の `inject_request`（束縛外の宛先に本物が現れないこと） |
| CONNECT先と内側のHostヘッダーを食い違わせる | `crates/mitm/tests/base_url.rs` の `requests_naming_a_foreign_host_are_refused`（base URL モードの Host 検査）、`crates/mitm/tests/mitm_h1.rs` の `sni_for_another_host_is_rejected_and_audited`・`missing_sni_is_rejected`・`inner_requests_naming_another_authority_are_rejected`、`crates/mitm/tests/protocols.rs` の `h2_streams_run_concurrently_and_only_the_misdirected_one_is_rejected` |
| APIのエラー応答などに本物の値をエコーさせる | `crates/mitm/tests/base_url.rs` の `responses_are_scrubbed_and_streams_stay_unbuffered`、`crates/mitm/tests/scrub.rs` の `echoed_secret_never_reaches_the_client_even_across_chunk_boundaries`・`encoded_responses_are_refused_rather_than_passed_unscrubbed`、`crates/mitm/tests/oauth.rs` の `real_tokens_echoed_by_an_api_are_scrubbed_to_their_dummies`・`token_endpoint_errors_echoing_the_client_secret_are_scrubbed`、`crates/core/tests/scrub.rs` の `every_chunking_yields_the_same_scrubbed_output`、fuzz の `scrub_stream`、`crates/core/tests/scrub.rs` の `base64url_echoes_are_scrubbed_too`（JWT などに base64url で埋め込まれたエコー）・`header_whose_scrubbed_value_is_not_a_valid_header_is_removed`（スクラブ後の値がヘッダーにできなければ元の値を残さず消す）、`crates/mitm/tests/oauth.rs` の `token_requests_on_disguised_paths_never_reach_upstream`・`base_url_token_requests_on_disguised_paths_never_reach_upstream`、`crates/oauth/tests/exchange.rs` の `paths_that_reach_an_endpoint_only_after_normalization_are_refused`（`//token` や `/x/../token` でトークン応答の書き換えを迂回させない）、`crates/core/tests/scrub.rs` の `form_encoded_echoes_are_scrubbed_too`（プロキシがフォームに入れた形のエコー）、`crates/oauth/tests/exchange.rs` の `client_ids_are_checked_wherever_they_appear`（本物の client secret を client_id の位置に入れさせない）・`json_bodies_with_a_repeated_key_never_leave_the_proxy`（JSON の重複キーで検査と上流の解釈を食い違わせない） |
| 設定を書き換えて秘密を別ホストに束縛し直す | `crates/cli/tests/dev_tools.rs` の `env_refuses_config_values_that_could_run_or_redirect_the_shell`（`credshim env` の出力で開発ユーザーのシェルを乗っ取らせない）、`crates/cli/tests/hardening.rs` の `run_refuses_a_config_others_could_rewrite`・`every_config_reading_command_refuses_a_config_others_could_rewrite`（`secret set` などで秘密ストアの場所を差し替えさせない）・`run_refuses_a_config_directory_others_could_write`、段階Bの `scripts/stage-b/verify.sh`（CI の `stage-b` ジョブで、sudo できない開発ユーザーが設定を読めず書けないことを検証）、`crates/cli/tests/hardening.rs` の `a_config_named_without_a_directory_still_has_its_directory_checked`・`a_symlinked_config_has_the_directory_of_its_target_checked`、`crates/cli/src/harden.rs` の `every_directory_along_a_symlink_chain_is_checked`（途中のリンクのディレクトリと、まだ無いリンク先のディレクトリも検査する） |
| プロキシのメモリ、秘密ストア、CA秘密鍵を読む | `crates/cli/tests/hardening.rs` の `run_refuses_secret_store_and_ca_key_others_could_write`・`proxy_memory_and_environment_are_closed_to_the_same_user`（Linux）、`crates/cli/src/harden.rs` の `core_dumps_are_disabled`、`crates/cli/tests/ca.rs` の `ca_init_writes_a_private_key_only_the_owner_can_read`、段階Bの `scripts/stage-b/verify.sh`、`crates/cli/tests/hardening.rs` の `run_and_env_refuse_ca_certificates_others_could_rewrite`（信頼させる CA 証明書を差し替えさせない）・`run_refuses_a_secret_store_command_others_could_rewrite`・`run_resolves_the_secret_store_command_on_path_once_and_checks_that_file`（検査したファイルと実行するファイルを食い違わせない）、`crates/secrets/tests/stores.rs` の `command_store_runs_the_absolute_path_it_resolved_on_path`・`command_store_refuses_a_program_it_cannot_pin_down` |
| プロキシ経由でクラウドのメタデータからマシンの認証情報を得る | `crates/mitm/tests/forward_proxy.rs` の `cloud_metadata_and_unspecified_addresses_are_refused`・`intercepted_host_on_a_cloud_metadata_address_is_refused_with_403` |
| プロキシ経由で本物の権限を乱用する | `crates/mitm/tests/policy.rs` の `paths_and_methods_outside_the_allow_list_are_403_and_never_reach_upstream`・`requests_over_the_rate_limit_are_429_and_never_reach_upstream`・`daily_limit_caps_total_requests`・`concurrency_limit_holds_for_the_whole_streamed_response`、`crates/core/tests/policy.rs`、`crates/cli/tests/hardening.rs` の `status_socket_reports_rule_names_and_counters_only`、監査ログの `audit_log_records_decisions_as_json_without_values`、`crates/mitm/tests/forward_proxy.rs` の `connect_tunnels_to_non_intercepted_hosts_are_audited`（インターセプトしないホストへのトンネルも監査に残す）、`crates/mitm/tests/oauth.rs` の `revoked_refresh_dummies_are_not_replayed`、`crates/oauth/tests/exchange.rs` の `revoke_query_tokens_of_another_provider_are_refused`・`refreshes_with_unknown_tokens_are_never_replayed`、`crates/core/tests/policy.rs` の `method_overrides_must_name_a_listed_method`・`path_override_headers_are_refused_when_paths_are_listed` |
| `~/.ssh` やプロセスのメモリから秘密鍵を読む | `crates/cli/tests/ssh.rs` の `keygen_stores_the_private_key_and_prints_only_the_public_half`・`run_serves_the_agent_and_openssh_logs_in_without_a_key_on_disk`（鍵がディスク上の平文にも出力にも現れない）、`crates/ssh/tests/openssh.rs` の各テストの `assert_key_never_logged`、`crates/ssh/tests/agent.rs` の `debug_output_never_contains_secret_values` |
| agent ソケットを自作クライアントで叩き、攻撃者のサーバーへの認証に使う | `crates/ssh/tests/openssh.rs` の `servers_whose_host_key_is_not_bound_get_no_signature_and_the_refusal_is_audited`・`users_outside_the_allow_list_are_refused`、`crates/ssh/tests/policy.rs` の `requests_without_a_session_bind_are_refused`・`a_bind_that_fails_verification_poisons_the_connection`・`host_keys_outside_the_binding_are_refused_and_reported`、`crates/ssh/tests/agent.rs` の `binds_that_fail_verification_are_refused_on_the_wire`・`write_requests_fail_and_leave_the_keys_unchanged`・`oversized_frames_close_the_connection_without_buffering` |
| 束縛先への正規セッションで得た署名を別ホストへ流用する | `crates/ssh/tests/policy.rs` の `a_session_id_other_than_the_bound_one_is_refused`・`a_second_bind_on_an_authentication_connection_poisons_it`・`a_hostbound_host_key_that_differs_from_the_bind_is_refused`、`crates/ssh/tests/agent.rs` の `hostbound_requests_naming_another_host_key_get_no_signature` |
| 任意のデータ（コミット署名、別プロトコルの challenge）に署名させる | `crates/ssh/tests/openssh.rs` の `ssh_keygen_signatures_are_refused`、`crates/ssh/tests/policy.rs` の `data_that_is_not_exactly_a_user_authentication_request_is_refused`・`a_request_naming_another_key_or_algorithm_is_refused`・`unknown_keys_and_signature_flags_are_refused` |
| agent フォワードを経由して別ホストから使う | `crates/ssh/tests/openssh.rs` の `requests_through_a_forwarded_agent_are_refused`、`crates/ssh/tests/policy.rs` の `forwarded_connections_are_refused_even_after_a_later_authentication_bind`、`crates/ssh/tests/agent.rs` の `an_undecodable_bind_poisons_the_connection`（デコードできない bind、たとえばホスト証明書の bind のあとも署名しない） |
| `~/.aws` の credentials を読む | `crates/e2e/tests/aws_cli.rs` の `aws_cli_query_and_json_services_work_with_only_a_dummy_profile`・`aws_cli_s3_upload_list_and_download_stream_through_the_proxy`（ダミーのプロファイルだけで動き、本物が CLI の出力とログに現れない）、`crates/cli/tests/aws.rs` の `the_aws_preset_runs_once_both_secrets_exist_and_keeps_the_dummy_off_plain_http` |
| ダミーのアクセスキーで署名した要求を AWS 以外のホストへ送る | `crates/mitm/tests/aws.rs` の `dummy_sent_outside_aws_is_refused_before_leaving_the_proxy`・`a_scope_that_names_another_service_or_region_is_never_resigned`、`crates/aws/tests/policy.rs` の `the_host_must_be_an_endpoint_of_the_scope_service_and_region`、`crates/aws/tests/policy.rs` の `dummy_outside_aws_or_outside_the_authorization_credential_is_denied` |
| 束縛先の API で新しい認証情報を発行させ、応答から本物の値を得る | `crates/mitm/tests/aws.rs` の `credential_issuing_operations_are_refused`、`crates/aws/tests/policy.rs` の `credential_issuing_operations_are_denied_whichever_way_they_are_named`・`dot_segments_and_case_do_not_hide_rest_credential_operations`・`comma_joined_targets_and_encoded_bodies_do_not_hide_operations`、`crates/e2e/tests/aws_cli.rs` の `aws_cli_cannot_mint_new_credentials` |
| 署名の要らない API で自分で認証情報を得る、人間に承認させる | `crates/mitm/tests/aws.rs` の `unsigned_credential_apis_are_refused_without_any_rule_matching`（末尾のドットや大文字のホスト名でも）、`crates/cli/tests/aws.rs` の `sso_and_signin_endpoints_are_refused_even_without_aws_config`、`crates/aws/tests/policy.rs` の `unsigned_credential_apis_are_denied_without_any_rule`・`unsigned_credential_apis_are_denied_on_fips_endpoints` |
| AWS の応答に本物のキーをエコーさせる | `crates/mitm/tests/aws.rs` の `query_protocol_request_signed_with_the_dummy_is_resigned_and_echoes_are_scrubbed` |
| 署名付きチャンクでプロキシの知らない署名を続けさせる | `crates/mitm/tests/aws.rs` の `signed_chunk_uploads_and_oversized_non_s3_bodies_never_reach_aws` |
| SSO のキャッシュを読む | `crates/e2e/tests/aws_sso_cli.rs` の `aws_cli_uses_an_sso_role_after_a_credshim_login_with_only_a_dummy_profile`（`~/.aws/sso` が作られず、一時 HOME のどのファイルにも SSO トークンとロール認証情報の平文が無い）、`crates/mitm/tests/aws_sso.rs` の `an_expiring_sso_token_is_refreshed_and_saved_back_encrypted` |
| SSO トークンやロール認証情報を、ログ、エラー、応答から得る | `crates/mitm/tests/aws_sso.rs` の `requests_need_a_login_then_use_role_credentials_that_never_reach_the_client`・`role_credentials_are_replaced_before_they_expire_and_no_request_fails`（MockAws がエコーしたロールのアクセスキー ID がダミーに置き換わる）、`crates/e2e/tests/aws_sso_cli.rs` の `aws_cli_keeps_working_while_role_credentials_expire_and_are_replaced`、`crates/core/tests/scrub.rs` の `a_scrub_source_is_reread_when_its_generation_moves` |
| SSO の期限切れやログアウトのあとも使い続ける | `crates/mitm/tests/aws_sso.rs` の `after_the_sso_token_expires_nothing_reaches_aws_until_the_next_login`・`logout_revokes_the_token_and_the_next_role_fetch_needs_a_login`・`a_login_removed_from_the_store_is_never_written_back_by_a_refresh`・`logout_after_the_access_token_expired_refreshes_it_to_end_the_session`、`crates/e2e/tests/aws_sso_cli.rs` の `aws_cli_reports_an_expired_sso_login_and_recovers_after_logging_in_again` |
| 自分で `credshim aws sso login` を実行して人間に承認させる | `crates/cli/tests/aws.rs` の `sso_login_is_for_a_person_at_a_terminal_and_logout_needs_no_network_without_a_login`、`crates/mitm/tests/aws_sso.rs` の `clients_still_cannot_reach_the_sso_endpoints_the_proxy_itself_uses` |
| 束縛先への本物の権限を乱用する（SSH） | `crates/ssh/tests/agent.rs` の `signatures_beyond_a_rule_limit_are_refused_and_audited`・`concurrent_and_zero_limits_are_rejected_for_ssh_keys` |
| 同じマシンの別ユーザーが agent ソケットにつなぐ | `crates/ssh/tests/agent.rs` の `connections_from_uids_outside_the_client_list_are_closed`、段階Bの `scripts/stage-b/verify.sh`（ソケットのディレクトリが専用ユーザーの所有で開発ユーザーが書けず、開発ユーザーが鍵の一覧を取れること） |
| 移行前の鍵や認証情報を `~/.ssh`・`~/.aws`・環境変数から読む | `crates/cli/tests/dev_tools.rs` の `doctor_reports_an_unreachable_agent_an_old_openssh_and_leftover_credentials`（報告に値が出ないことも確かめる）、`crates/cli/src/leftovers.rs` の単体テスト |
| 束縛先の API で本物の権限を乱用する、認証情報以外の秘密を得る（AWS） | `crates/mitm/tests/aws.rs` の `operations_outside_the_allow_list_are_refused_with_an_aws_error`・`requests_over_a_rule_limit_get_429_and_never_reach_aws`、`crates/e2e/tests/aws_cli.rs` の `aws_cli_requests_outside_the_operations_allow_list_are_refused`（実際の `aws` CLI の `s3 ls`・`s3 cp` が想定した操作として特定される）、`crates/aws/tests/policy.rs` の `every_identified_operation_must_be_on_the_allow_list`・`rest_operations_are_identified_by_their_most_specific_route`・`operation_patterns_and_limits_are_validated` |
