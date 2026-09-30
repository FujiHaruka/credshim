# CredShim 脅威モデルと設計原則

**守るもの**は秘密の「値」そのもの。.env、アプリのメモリ、ログ、テストfixture、エージェントのコンテキストに本物が現れないこと。

**守らないもの**は秘密の「利用」。エージェントは値を知らなくても、プロキシ経由で本物の権限を使ってAPIを叩ける。これは仕組み上避けられない前提で、Phase 6の許可リスト・上限・監査ログで緩和する。

一番危ないのは「本物のキーが別ホストへ注入されること」と「プロキシの設定や秘密ストアを書き換え・読み出しされること」。以下の原則はほぼこの2点を塞ぐためにある。

| エージェントが取りうる行動 | 対策（原則） |
| --- | --- |
| リポジトリ、環境変数、アプリのメモリ、ログを読む | 本物がそこに存在しない（1） |
| ダミーキー付きリクエストを攻撃者のホストへ送る | ホスト束縛、束縛外は403（2, 4） |
| CONNECT先と内側のHostヘッダーを食い違わせる | 接続先で照合、不一致は拒否（3） |
| APIのエラー応答などに本物の値をエコーさせる | レスポンスのスクラブ（5） |
| 設定を書き換えて秘密を別ホストに束縛し直す | 設定をエージェントが書けない場所へ（6） |
| プロキシのメモリ、秘密ストア、CA秘密鍵を読む | OSユーザー／コンテナ分離（6, 9） |
| プロキシ経由で本物の権限を乱用する | 残存リスク。許可リスト、上限、監査ログで緩和 |

1. **秘密はプロキシプロセスの中だけ。** 登録は人間がTTYから行い、argvや環境変数を経由しない。値を取り出すコマンドは作らない。
2. **ホスト束縛。** 各秘密は宛先（scheme、host、port、任意でpath prefix）に束縛する。差し替えるのは、実際に接続する上流が束縛先と一致し、かつ上流のTLS証明書をシステムの信頼ストアで検証できたときだけ。
3. **照合はクライアントが操れる値でなく接続先で。** CONNECTのauthorityを正とし、内側のHostや:authorityが一致しなければ拒否する。
4. **束縛外に現れたダミーは差し替えず403と警告ログ。** 平文HTTPの上流への注入は明示許可がない限り禁止。リダイレクトはプロキシが追わずクライアントへ返す。
5. **ボディは既定でバッファしない。** 書き換えはトークンエンドポイントのような小さいボディに限り、サイズ上限を設ける。レスポンス中の秘密値スクラブは安全網として別に持つ。
6. **設定・秘密ストア・CA秘密鍵はエージェントが触れない場所に。** 最終形ではプロキシを別OSユーザー、またはエージェントが動くコンテナの外で動かす。ルール設定も秘密と同じくらい重要な資産として扱う。
7. **登録済みホストだけMITMし、他は素のTCPトンネル。** 証明書ピン留めや無関係な通信を壊さない。
8. **ログやエラーに秘密を出さない仕組みを型で強制。** 秘密は専用型で持ち、Debug/Display出力をマスクする。
9. **ルートCAはOSの信頼ストアに入れない。** アプリにだけ環境変数で渡し、CA鍵が漏れた場合の被害をこの開発用途に閉じ込める。

base URL モード（Phase 7）では、接続先はクライアントが操れる値ではなく設定の対応表（接頭辞→ルールのホスト）で決まる。クライアントが選べるのはパスだけなので、接頭辞の照合はセグメント単位で行い、ドットセグメントやエンコードされた区切りを含むパスは一致させない。listener はループバックだけに bind し、ループバック以外を名乗る Host は拒否する（DNS リバインディング対策）。ダミーを含まない要求はそのまま転送するが、本物は使わないので MITM の pass と同じ扱いになる。

## SSH エージェント（v0.2）

CredShim は ssh-agent として、鍵をプロキシの中だけに置いて署名を代行する。署名するのは、同じ agent 接続で検証済みの `session-bind@openssh.com` があり、そのホスト鍵の SHA256 指紋がルールの束縛先に含まれ、署名対象が bind のセッション ID と許可されたユーザー名を含むユーザー認証要求（`publickey` か `publickey-hostbound-v00@openssh.com`。後者はホスト鍵が bind と一致すること）ちょうどの形をしているときだけ。1本の接続で受け付ける bind は1回で、検証に失敗した bind や2回目の bind のあとはその接続での署名をすべて拒否し、`is_forwarding=1` の bind を一度でも受けた接続（`ssh -A` の先）も拒否する。

| エージェントが取りうる行動 | 対策 |
| --- | --- |
| `~/.ssh` やプロセスのメモリから秘密鍵を読む | 鍵はプロキシの中で生成し秘密ストアにだけ置く。ディスク上の鍵ファイルは作らない |
| agent ソケットを自作クライアントで叩き、攻撃者のサーバーへの認証に使う | session-bind 必須。ホスト鍵が束縛先でなければ署名しない |
| 束縛先への正規セッションで得た署名を別ホストへ流用する | 署名対象に bind のセッション ID が入り、他の接続では通らない |
| 任意のデータ（コミット署名、別プロトコルの challenge）に署名させる | ユーザー認証要求ちょうどの形以外は拒否 |
| agent フォワードを経由して別ホストから使う | フォワードされた接続からの要求は拒否 |

## AWS 認証情報（v0.2）

`~/.aws` にはダミーのアクセスキーだけを置く。CredShim は `amazonaws.com` 配下を MITM し、Authorization の資格スコープにダミーのアクセスキー ID が入った SigV4 要求だけを、本物の認証情報で署名し直して上流へ送る。署名し直すヘッダーはクライアントが署名したものと同じ集合で、時刻とスコープもクライアントの値を使う。S3 は `x-amz-content-sha256` の値をそのまま署名に使いボディはストリームで流し、それ以外のサービスは上限付きでボディを読んでハッシュを計算する。サービスとリージョンの絞り込みはスコープで行い、ホストがスコープのサービスとリージョンのエンドポイントでなければ再署名しない（対応表は botocore から生成）。利用者が作る API の前段（`execute-api`）は、署名した要求が持ち主のバックエンドに届くので、ルールに明示したときだけ再署名する。`X-Amz-Date` が現在時刻から15分より離れた要求も再署名しない。

| エージェントが取りうる行動 | 対策 |
| --- | --- |
| `~/.aws` の credentials を読む | ダミーのアクセスキーしか無い。本物は秘密ストアとプロキシのメモリだけ |
| ダミーのアクセスキーで署名した要求を AWS 以外のホストへ送る | `amazonaws.com` 配下以外でダミーが見つかれば403（平文 HTTP も同じ）。本物での署名は、スコープのサービスのエンドポイント宛てにしか行わない。API Gateway など利用者のバックエンドに届くエンドポイントは明示したときだけ |
| 束縛先の API で新しい認証情報を発行させ、応答から本物の値を得る | botocore のモデルから抜き出した、応答に `SecretAccessKey` か `SessionToken` を含む37操作を拒否。Query の `Action` はクエリ文字列とボディの両方、JSON は `X-Amz-Target`、rpc-v2-cbor はパス、REST はメソッドとパスのテンプレートで判定する |
| 署名の要らない API（SSO OIDC のデバイス認可、SSO ポータル、`AssumeRoleWithWebIdentity`・`AssumeRoleWithSAML`、`GetCredentialsForIdentity`、`aws login`）で自分で認証情報を得る、人間に承認させる | ルールと無関係に拒否。SSO OIDC、SSO ポータル、signin はホストごと CONNECT の段階で（AWS の設定が無くても）、STS と Cognito Identity の操作は MITM したうえで操作名で |
| AWS の応答に本物のキーをエコーさせる | 本物のアクセスキー ID とシークレットをスクラブ対象に加える |
| 署名付きチャンク（`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`）でプロキシの知らない署名を続けさせる | 拒否 |

## 回帰テスト対応表

脅威モデルの各行に対応する回帰テスト。

| 脅威 | テスト |
| --- | --- |
| リポジトリ、環境変数、アプリのメモリ、ログを読む | `crates/mitm/tests/inject.rs` の `secrets_and_dummies_never_reach_the_logs_and_requests_are_audited`、`crates/cli/tests/config.rs` の `secret_list_prints_names_and_times_but_never_values`・`audit_log_records_decisions_as_json_without_values`、`crates/core/tests/rules.rs` の `debug_output_never_contains_secret_values`、`crates/core/tests/scrub.rs` の `debug_output_never_contains_secret_values`、`crates/mitm/tests/oauth.rs` の `code_exchange_hands_the_app_dummies_and_the_api_real_tokens`、`crates/mitm/tests/forward_proxy.rs` の `userinfo_stays_out_of_the_host_header_and_logs`（URL の userinfo をログにも上流にも出さない） |
| ダミーキー付きリクエストを攻撃者のホストへ送る | `crates/mitm/tests/base_url.rs` の `a_dummy_bound_to_another_host_is_refused`・`paths_outside_a_prefix_and_proxy_forms_are_refused`、`crates/core/tests/base_url.rs` の `paths_that_could_climb_out_of_a_prefix_never_resolve`・`unsafe_or_ambiguous_prefixes_are_rejected`、`crates/mitm/tests/inject.rs` の `dummy_sent_to_another_intercepted_host_is_403_and_nothing_reaches_upstream`・`dummy_over_plain_http_is_403_and_nothing_reaches_upstream`・`dummy_over_plain_http_to_its_own_bound_destination_is_403_and_never_injected`（束縛先そのものでも平文HTTPには注入しない）、`crates/core/tests/rules.rs` の `dummy_sent_to_an_unbound_destination_is_denied_and_left_untouched`・`dummy_hidden_anywhere_in_the_request_is_found`・`path_prefix_binds_the_dummy_to_that_subtree`、`crates/mitm/tests/oauth.rs` の `client_secret_dummy_is_refused_away_from_the_token_endpoint`、fuzz の `inject_request`（束縛外の宛先に本物が現れないこと） |
| CONNECT先と内側のHostヘッダーを食い違わせる | `crates/mitm/tests/base_url.rs` の `requests_naming_a_foreign_host_are_refused`（base URL モードの Host 検査）、`crates/mitm/tests/mitm_h1.rs` の `sni_for_another_host_is_rejected_and_audited`・`missing_sni_is_rejected`・`inner_requests_naming_another_authority_are_rejected`、`crates/mitm/tests/protocols.rs` の `h2_streams_run_concurrently_and_only_the_misdirected_one_is_rejected` |
| APIのエラー応答などに本物の値をエコーさせる | `crates/mitm/tests/base_url.rs` の `responses_are_scrubbed_and_streams_stay_unbuffered`、`crates/mitm/tests/scrub.rs` の `echoed_secret_never_reaches_the_client_even_across_chunk_boundaries`・`encoded_responses_are_refused_rather_than_passed_unscrubbed`、`crates/mitm/tests/oauth.rs` の `real_tokens_echoed_by_an_api_are_scrubbed_to_their_dummies`・`token_endpoint_errors_echoing_the_client_secret_are_scrubbed`、`crates/core/tests/scrub.rs` の `every_chunking_yields_the_same_scrubbed_output`、fuzz の `scrub_stream`、`crates/core/tests/scrub.rs` の `base64url_echoes_are_scrubbed_too`（JWT などに base64url で埋め込まれたエコー）・`header_whose_scrubbed_value_is_not_a_valid_header_is_removed`（スクラブ後の値がヘッダーにできなければ元の値を残さず消す）、`crates/mitm/tests/oauth.rs` の `token_requests_on_disguised_paths_never_reach_upstream`・`base_url_token_requests_on_disguised_paths_never_reach_upstream`、`crates/oauth/tests/exchange.rs` の `paths_that_reach_an_endpoint_only_after_normalization_are_refused`（`//token` や `/x/../token` でトークン応答の書き換えを迂回させない） |
| 設定を書き換えて秘密を別ホストに束縛し直す | `crates/cli/tests/dev_tools.rs` の `env_refuses_config_values_that_could_run_or_redirect_the_shell`（`credshim env` の出力で開発ユーザーのシェルを乗っ取らせない）、`crates/cli/tests/hardening.rs` の `run_refuses_a_config_others_could_rewrite`・`every_config_reading_command_refuses_a_config_others_could_rewrite`（`secret set` などで秘密ストアの場所を差し替えさせない）・`run_refuses_a_config_directory_others_could_write`、段階Bの `scripts/stage-b/verify.sh`（CI の `stage-b` ジョブで、sudo できない開発ユーザーが設定を読めず書けないことを検証） |
| プロキシのメモリ、秘密ストア、CA秘密鍵を読む | `crates/cli/tests/hardening.rs` の `run_refuses_secret_store_and_ca_key_others_could_write`・`proxy_memory_and_environment_are_closed_to_the_same_user`（Linux）、`crates/cli/src/harden.rs` の `core_dumps_are_disabled`、`crates/cli/tests/ca.rs` の `ca_init_writes_a_private_key_only_the_owner_can_read`、段階Bの `scripts/stage-b/verify.sh` |
| プロキシ経由で本物の権限を乱用する | `crates/mitm/tests/policy.rs` の `paths_and_methods_outside_the_allow_list_are_403_and_never_reach_upstream`・`requests_over_the_rate_limit_are_429_and_never_reach_upstream`・`daily_limit_caps_total_requests`・`concurrency_limit_holds_for_the_whole_streamed_response`、`crates/core/tests/policy.rs`、`crates/cli/tests/hardening.rs` の `status_socket_reports_rule_names_and_counters_only`、監査ログの `audit_log_records_decisions_as_json_without_values`、`crates/mitm/tests/forward_proxy.rs` の `connect_tunnels_to_non_intercepted_hosts_are_audited`（インターセプトしないホストへのトンネルも監査に残す）、`crates/mitm/tests/oauth.rs` の `revoked_refresh_dummies_are_not_replayed`、`crates/oauth/tests/exchange.rs` の `revoke_query_tokens_of_another_provider_are_refused`・`refreshes_with_unknown_tokens_are_never_replayed` |
| `~/.ssh` やプロセスのメモリから秘密鍵を読む | `crates/cli/tests/ssh.rs` の `keygen_stores_the_private_key_and_prints_only_the_public_half`・`run_serves_the_agent_and_openssh_logs_in_without_a_key_on_disk`（鍵がディスク上の平文にも出力にも現れない）、`crates/ssh/tests/openssh.rs` の各テストの `assert_key_never_logged`、`crates/ssh/tests/agent.rs` の `debug_output_never_contains_secret_values` |
| agent ソケットを自作クライアントで叩き、攻撃者のサーバーへの認証に使う | `crates/ssh/tests/openssh.rs` の `servers_whose_host_key_is_not_bound_get_no_signature_and_the_refusal_is_audited`・`users_outside_the_allow_list_are_refused`、`crates/ssh/tests/policy.rs` の `requests_without_a_session_bind_are_refused`・`a_bind_that_fails_verification_poisons_the_connection`・`host_keys_outside_the_binding_are_refused_and_reported`、`crates/ssh/tests/agent.rs` の `binds_that_fail_verification_are_refused_on_the_wire`・`write_requests_fail_and_leave_the_keys_unchanged`・`oversized_frames_close_the_connection_without_buffering` |
| 束縛先への正規セッションで得た署名を別ホストへ流用する | `crates/ssh/tests/policy.rs` の `a_session_id_other_than_the_bound_one_is_refused`・`a_second_bind_on_an_authentication_connection_poisons_it`・`a_hostbound_host_key_that_differs_from_the_bind_is_refused`、`crates/ssh/tests/agent.rs` の `hostbound_requests_naming_another_host_key_get_no_signature` |
| 任意のデータ（コミット署名、別プロトコルの challenge）に署名させる | `crates/ssh/tests/openssh.rs` の `ssh_keygen_signatures_are_refused`、`crates/ssh/tests/policy.rs` の `data_that_is_not_exactly_a_user_authentication_request_is_refused`・`a_request_naming_another_key_or_algorithm_is_refused`・`unknown_keys_and_signature_flags_are_refused` |
| agent フォワードを経由して別ホストから使う | `crates/ssh/tests/openssh.rs` の `requests_through_a_forwarded_agent_are_refused`、`crates/ssh/tests/policy.rs` の `forwarded_connections_are_refused_even_after_a_later_authentication_bind` |
| `~/.aws` の credentials を読む | `crates/e2e/tests/aws_cli.rs` の `aws_cli_query_and_json_services_work_with_only_a_dummy_profile`・`aws_cli_s3_upload_list_and_download_stream_through_the_proxy`（ダミーのプロファイルだけで動き、本物が CLI の出力とログに現れない）、`crates/cli/tests/aws.rs` の `the_aws_preset_runs_once_both_secrets_exist_and_keeps_the_dummy_off_plain_http` |
| ダミーのアクセスキーで署名した要求を AWS 以外のホストへ送る | `crates/mitm/tests/aws.rs` の `dummy_sent_outside_aws_is_refused_before_leaving_the_proxy`・`a_scope_that_names_another_service_or_region_is_never_resigned`、`crates/aws/tests/policy.rs` の `the_host_must_be_an_endpoint_of_the_scope_service_and_region`、`crates/aws/tests/policy.rs` の `dummy_outside_aws_or_outside_the_authorization_credential_is_denied` |
| 束縛先の API で新しい認証情報を発行させ、応答から本物の値を得る | `crates/mitm/tests/aws.rs` の `credential_issuing_operations_are_refused`、`crates/aws/tests/policy.rs` の `credential_issuing_operations_are_denied_whichever_way_they_are_named`・`dot_segments_and_case_do_not_hide_rest_credential_operations`・`comma_joined_targets_and_encoded_bodies_do_not_hide_operations`、`crates/e2e/tests/aws_cli.rs` の `aws_cli_cannot_mint_new_credentials` |
| 署名の要らない API で自分で認証情報を得る、人間に承認させる | `crates/mitm/tests/aws.rs` の `unsigned_credential_apis_are_refused_without_any_rule_matching`、`crates/cli/tests/aws.rs` の `sso_and_signin_endpoints_are_refused_even_without_aws_config`、`crates/aws/tests/policy.rs` の `unsigned_credential_apis_are_denied_without_any_rule`・`unsigned_credential_apis_are_denied_on_fips_endpoints` |
| AWS の応答に本物のキーをエコーさせる | `crates/mitm/tests/aws.rs` の `query_protocol_request_signed_with_the_dummy_is_resigned_and_echoes_are_scrubbed` |
| 署名付きチャンクでプロキシの知らない署名を続けさせる | `crates/mitm/tests/aws.rs` の `signed_chunk_uploads_and_oversized_non_s3_bodies_never_reach_aws` |
