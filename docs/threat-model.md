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

## 回帰テスト対応表

脅威モデルの各行に対応する回帰テスト。

| 脅威 | テスト |
| --- | --- |
| リポジトリ、環境変数、アプリのメモリ、ログを読む | `crates/mitm/tests/inject.rs` の `secrets_and_dummies_never_reach_the_logs_and_requests_are_audited`、`crates/cli/tests/config.rs` の `secret_list_prints_names_and_times_but_never_values`・`audit_log_records_decisions_as_json_without_values`、`crates/core/tests/rules.rs` の `debug_output_never_contains_secret_values`、`crates/core/tests/scrub.rs` の `debug_output_never_contains_secret_values`、`crates/mitm/tests/oauth.rs` の `code_exchange_hands_the_app_dummies_and_the_api_real_tokens`、`crates/mitm/tests/forward_proxy.rs` の `userinfo_stays_out_of_the_host_header_and_logs`（URL の userinfo をログにも上流にも出さない） |
| ダミーキー付きリクエストを攻撃者のホストへ送る | `crates/mitm/tests/base_url.rs` の `a_dummy_bound_to_another_host_is_refused`・`paths_outside_a_prefix_and_proxy_forms_are_refused`、`crates/core/tests/base_url.rs` の `paths_that_could_climb_out_of_a_prefix_never_resolve`・`unsafe_or_ambiguous_prefixes_are_rejected`、`crates/mitm/tests/inject.rs` の `dummy_sent_to_another_intercepted_host_is_403_and_nothing_reaches_upstream`・`dummy_over_plain_http_is_403_and_nothing_reaches_upstream`、`crates/core/tests/rules.rs` の `dummy_sent_to_an_unbound_destination_is_denied_and_left_untouched`・`dummy_hidden_anywhere_in_the_request_is_found`・`path_prefix_binds_the_dummy_to_that_subtree`、`crates/mitm/tests/oauth.rs` の `client_secret_dummy_is_refused_away_from_the_token_endpoint`、fuzz の `inject_request`（束縛外の宛先に本物が現れないこと） |
| CONNECT先と内側のHostヘッダーを食い違わせる | `crates/mitm/tests/base_url.rs` の `requests_naming_a_foreign_host_are_refused`（base URL モードの Host 検査）、`crates/mitm/tests/mitm_h1.rs` の `sni_for_another_host_is_rejected`・`missing_sni_is_rejected`・`inner_requests_naming_another_authority_are_rejected`、`crates/mitm/tests/protocols.rs` の `h2_streams_run_concurrently_and_only_the_misdirected_one_is_rejected` |
| APIのエラー応答などに本物の値をエコーさせる | `crates/mitm/tests/base_url.rs` の `responses_are_scrubbed_and_streams_stay_unbuffered`、`crates/mitm/tests/scrub.rs` の `echoed_secret_never_reaches_the_client_even_across_chunk_boundaries`・`encoded_responses_are_refused_rather_than_passed_unscrubbed`、`crates/mitm/tests/oauth.rs` の `real_tokens_echoed_by_an_api_are_scrubbed_to_their_dummies`・`token_endpoint_errors_echoing_the_client_secret_are_scrubbed`、`crates/core/tests/scrub.rs` の `every_chunking_yields_the_same_scrubbed_output`、fuzz の `scrub_stream`、`crates/core/tests/scrub.rs` の `base64url_echoes_are_scrubbed_too`（JWT などに base64url で埋め込まれたエコー） |
| 設定を書き換えて秘密を別ホストに束縛し直す | `crates/cli/tests/dev_tools.rs` の `env_refuses_config_values_that_could_run_or_redirect_the_shell`（`credshim env` の出力で開発ユーザーのシェルを乗っ取らせない）、`crates/cli/tests/hardening.rs` の `run_refuses_a_config_others_could_rewrite`・`run_refuses_a_config_directory_others_could_write`、段階Bの `scripts/stage-b/verify.sh`（CI の `stage-b` ジョブで、sudo できない開発ユーザーが設定を読めず書けないことを検証） |
| プロキシのメモリ、秘密ストア、CA秘密鍵を読む | `crates/cli/tests/hardening.rs` の `run_refuses_secret_store_and_ca_key_others_could_write`・`proxy_memory_and_environment_are_closed_to_the_same_user`（Linux）、`crates/cli/src/harden.rs` の `core_dumps_are_disabled`、`crates/cli/tests/ca.rs` の `ca_init_writes_a_private_key_only_the_owner_can_read`、段階Bの `scripts/stage-b/verify.sh` |
| プロキシ経由で本物の権限を乱用する | `crates/mitm/tests/policy.rs` の `paths_and_methods_outside_the_allow_list_are_403_and_never_reach_upstream`・`requests_over_the_rate_limit_are_429_and_never_reach_upstream`・`daily_limit_caps_total_requests`・`concurrency_limit_holds_for_the_whole_streamed_response`、`crates/core/tests/policy.rs`、`crates/cli/tests/hardening.rs` の `status_socket_reports_rule_names_and_counters_only`、監査ログの `audit_log_records_decisions_as_json_without_values` |
