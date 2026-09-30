# CredShim：開発用クレデンシャル注入プロキシ（Rust）アーキテクチャと開発ステップ

Sep 29, 2026 · @Haruka Fuji

## 目的とスコープ

アプリケーションサーバーとコーディングエージェントが本物のAPIキー・OAuthトークンを一度も見ずに、実際の外部APIで開発できる状態を作る。アプリはダミー値だけを持ち、プロキシが送信直前に本物へ差し替える。LiteLLM Proxyに近いが、base URLを変える方式ではなく、HTTPS\_PROXYで挟まる透過MITMプロキシを主とする。

| ケース | アプリが持つもの | プロキシだけが持つもの | 差し替える場所 |
| --- | --- | --- | --- |
| 静的APIキー（OpenAI、Anthropic、Geminiなど） | ダミーキー | 本物のキー | 登録済みホスト宛のヘッダー／クエリ |
| OAuth（認可コード、client credentials） | client\_id、ダミーのclient\_secret、ダミーのアクセス／リフレッシュトークン | client\_secret、本物のアクセス／リフレッシュトークン | トークンエンドポイントの往復、リソースAPIのBearer |

**守るもの**は秘密の「値」そのもの。.env、アプリのメモリ、ログ、テストfixture、エージェントのコンテキストに本物が現れないこと。

**守らないもの**は秘密の「利用」。エージェントは値を知らなくても、プロキシ経由で本物の権限を使ってAPIを叩ける。これは仕組み上避けられない前提で、Phase 6の許可リスト・上限・監査ログで緩和する。

**透過性の目標**は、OpenAI SDKなどがHTTPS\_PROXYとCA証明書の指定だけで無改造に動くこと。HTTP/1.1、HTTP/2、SSEストリーミング、WebSocketを対象にする。

## 脅威モデルと設計原則

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

## 全体アーキテクチャ

アプリはダミー付きのリクエストをCredShimへ送り、本物のキーは検証済みの上流接続にだけ注入される。何をどこへ差し替えるかの判断は、中央のルールエンジン1か所に集める。

&#91;embedded content: CredShim の構成 · 開発環境と分離されたプロキシ\]

応答は同じ経路を逆向きに通る。トークンエンドポイントの応答はOAuth保管庫でダミーに置き換えられ、それ以外の応答は秘密値のスクラブを経て返る。監査ログは各段から書かれる（図では省略）。

## 技術スタック

hyper 1.x の上に自前でMITMを組む。差し替えの可否を「上流TLSの検証結果」と「実際の接続先」に厳密に結びつけたいので、制御点を手元に持っておきたい。既存のRust製MITMライブラリ（hudsuckerなど）はスパイクや実装の参考に使う程度にする。

| 領域 | クレート | 用途 |
| --- | --- | --- |
| ランタイム | tokio | 非同期I/O全般 |
| HTTP | hyper 1.x、hyper-util、http、http-body-util、bytes | 下流サーバーと上流クライアントの両方。h1/h2、Upgrade、ボディをストリームのまま扱う |
| TLS | rustls、tokio-rustls | 下流の終端（ALPNでh2/http1.1を交渉）と上流接続 |
| 上流の検証 | rustls-platform-verifier（またはrustls-native-certs） | OSの信頼ストアで上流証明書を検証する |
| 証明書生成 | rcgen | ルートCAとホストごとのリーフ証明書 |
| 証明書キャッシュ | moka | ホスト名→ServerConfigのキャッシュ |
| 設定・CLI | serde、toml、clap | 設定ファイルとサブコマンド |
| 秘密の型 | secrecy、zeroize | 出力時のマスク、破棄時のメモリ消去 |
| 秘密ストア | keyring、age | OSキーチェーン、または暗号化ファイル |
| ボディ書き換え | serde\_urlencoded、serde\_json | トークンエンドポイントのフォーム／JSON |
| スクラブ | aho-corasick | ストリーム中の秘密値検出 |
| 乱数 | getrandom | ダミートークン生成 |
| ログ | tracing、tracing-subscriber | 構造化ログと監査ログ |
| テスト | axum、reqwest、rcgen | モック上流とモックOAuthサーバー、テスト用CA |

WebSocketはフレームを解析せず、Upgradeリクエストのヘッダーだけ差し替えて以降は双方向のバイトコピーにする。そのためWebSocket用クレートは本体には不要。

## リポジトリ構成とClaude Codeでの進め方

判断ロジック（何をどこへ差し替えるか）をI/Oのない純粋な層に切り出し、単体テストで固めるのが最重要。I/O層はそれを呼ぶだけにする。

```text
credshim/
├─ Cargo.toml            # workspace
├─ CLAUDE.md
├─ docs/threat-model.md  # 前章の内容
├─ crates/
│  ├─ core/     # ルール照合、差し替え、ダミー生成、スクラブ（I/Oなし）
│  ├─ mitm/     # CA、証明書キャッシュ、CONNECT、TLS終端、h1/h2中継
│  ├─ secrets/  # 秘密ストアのバックエンド
│  ├─ oauth/    # トークン保管庫、トークンエンドポイント処理
│  ├─ testkit/  # モック上流、モックOAuthサーバー、テストCA
│  └─ cli/      # credshim バイナリ
└─ tests/       # E2E（実SDKを使うものは別ジョブ）
```

**進め方。** 1フェーズを1〜数セッションで扱い、各フェーズの「完了条件」を自動テストで満たすまで進める。完了条件がテストで書けているので、Claude Codeが自分で検証できる。セキュリティに関わる変更（core の照合・差し替え）は、別セッションでレビューさせる。

**開発中も本物の鍵は使わない。** テストはすべてモック上流とテスト用の偽秘密で行う。実キーでの確認は、各マイルストーンで人間が自分で登録して行う。

**CLAUDE.md に書くルール：**

- 秘密は必ず secrecy の型で持つ。値を取り出す呼び出しは core の差し替え関数と secrets の中だけに限り、CIでgrepして検査する。
- リクエスト／レスポンスのボディを丸ごと読み込まない。例外は oauth のトークンエンドポイント処理だけで、必ずサイズ上限を付ける。
- ログ、エラー、パニックに秘密やトークンの値を出さない。テスト用の偽秘密がログ出力に一度も現れないことを検査するテストを常に通す。
- 新しい挙動には統合テストを付ける。`cargo fmt`、`cargo clippy -D warnings`、`cargo test --workspace` が通ってから完了とする。
- 実運用の設定ディレクトリや秘密ストアを読まない・編集しない。Claude Code の permission の deny ルールでも塞いでおく（ただしこれは補助的な層で、本当の防御は Phase 6 の分離）。

## Phase 0: 土台づくり

後の全フェーズがテストで自己検証できるよう、先にテスト基盤を作る。ここを手厚くするほど、Claude Codeの手戻りが減る。

**作るもの**

- workspace と CI（fmt、clippy、test）、CLAUDE.md、docs/threat-model.md。
- testkit のテスト用CA。rcgenでテストごとに生成し、モック上流の証明書を署名する。
- testkit のモック上流（axum + rustls、h1/h2両対応）。受け取ったヘッダー・クエリ・ボディをそのまま返すエコー、一定間隔でイベントを送るSSE、数十MBのボディ、WebSocketエコーを用意する。
- テスト専用の差し込み口。上流検証に追加の信頼アンカーを足す口と、`api.openai.com` のような名前をモックの 127.0.0.1 に解決させる口。どちらも cargo feature `testing` の裏に置き、リリースバイナリには含めない（含めると、偽の上流に本物のキーを送らせる抜け道になる）。
- ログ出力をキャプチャして「偽秘密の文字列が一度も出ていない」ことを検査するヘルパー。

**完了条件**

- [x] CIがグリーン。
- [x] モック上流に reqwest で h1 と h2 の両方で接続するテストが通る。
- [x] リリースビルドに `testing` の口が含まれないことを確認するテストがある。

**実装メモ（Phase 0）**

- `testing` の口は `credshim-mitm` の `Upstream::with_testing_hooks` にある。リリースビルドでは `compile_error!` で止め、`scripts/check-release-excludes-testing.sh` がそのガードとバイナリ中のマーカー文字列の不在を検査する。
- 上流検証は rustls-platform-verifier の `new_with_extra_roots` を使う。macOS でも有効期限7日・EKU serverAuth のテスト用リーフで通る。
- 暗号プロバイダは aws-lc-rs に統一（reqwest 0.13 の rustls が aws-lc-rs 固定のため、ring と混在させない）。

## Phase 1: HTTPフォワードプロキシとCONNECTトンネル

まだ何も差し替えない、素直なフォワードプロキシを作る。ここで「ボディを溜めない」中継の骨格を決めておくと、後のSSEやWebSocketで作り直さずに済む。

**作るもの**

- 127.0.0.1 だけで listen する。外部インターフェースには bind しない。
- 絶対形式URI（`GET http://host/path`）のリクエストを上流へ中継する。hop-by-hop ヘッダー（Connection とそこに列挙されたもの、Keep-Alive、Proxy-Connection、Proxy-Authorization、TE、Trailer、Transfer-Encoding、Upgrade）を落とす。
- `CONNECT host:port` を受けたら上流とTCP接続し、200を返して双方向コピーする。この時点では全ホストが素通し。
- ボディは hyper の受信ボディをそのまま上流へ渡し、レスポンスも同様に返す。
- 上流へのコネクションプール、接続・アイドルのタイムアウト、上流エラー時の502。

**完了条件**

- [x] `curl -x` でモックの http 上流に GET/POST できる。
- [x] CONNECT 経由で https のモックに繋がり、クライアントにはモック自身の証明書が見える。
- [x] SSEモックの各イベントが、プロキシ経由でも溜められずに届く（送出から到着までの遅延に上限を決めてテストする）。
- [x] 数十MBのアップロード／ダウンロードがバイト単位で一致する。

**実装メモ（Phase 1）**

- `credshim_mitm::Proxy` が下流を hyper の http1 サーバーで受ける（CONNECT と絶対形式URIのプロキシ要求はどちらも h1）。listen 先がループバック以外なら `BindError::NotLoopback` で起動しない。
- 絶対形式の転送は hyper-util の legacy `Client` に絶対URIのまま渡す。プールは scheme＋authority 単位、接続は `Upstream::connect_tcp` 経由なので `testing` の名前解決上書きも効く。Host はクライアントの値ではなくリクエスト先の authority で上書きする。
- ログに出すのはメソッド、authority、パスまで。クエリは出さない（Phase 3 以降 `?key=` に秘密が載るため）。

## Phase 2: TLS MITM（HTTP/1.1）

登録済みホストへのCONNECTだけTLSを終端し、中身を読める状態にする。このフェーズの本当の成果物は、後で差し替え判定に使う「検証済み接続コンテキスト」である。

**作るもの**

- `credshim ca init`：ルートCA（ECDSA P-256）を生成する。秘密鍵はプロキシ専用ディレクトリに 0600 で置き、公開証明書だけを外に出す。
- `credshim ca bundle`：OSのルート証明書と開発CAを結合したバンドルを出力する。SSL\_CERT\_FILE のような変数は既定のバンドルを置き換えるため、結合しないと他のHTTPSが壊れる。
- インターセプト対象ホストの一覧（設定）。CONNECT先が一覧にあればMITM、なければPhase 1のトンネルに流す。
- リーフ証明書の動的発行。SANはそのホスト名だけ、有効期限は短く、CAで署名してキャッシュする。
- 下流のTLS終端。ALPNはまだ `http/1.1` のみ提示する。SNIとCONNECT先が一致しなければ拒否する。
- 上流へのTLS接続。SNIはCONNECT先、検証はOSの信頼ストア。検証に失敗したら502を返し、下流に成功を見せない。
- 内側リクエストの Host がCONNECT先と一致するかの検査（原則3）。
- 接続コンテキスト型。「上流TLS検証済み、宛先は host:port」という事実を型で持ち回し、差し替え判定はこの型がないと呼べないようにする（原則2を型で強制）。

**完了条件**

- [ ] 対象ホストでは開発CA署名の証明書、非対象ホストではモック自身の証明書がクライアントに見える。
- [ ] 上流証明書が期限切れ・名前不一致・未知のCAのとき502になる。
- [ ] SNIやHostがCONNECT先と食い違うリクエストが拒否される。
- [ ] Phase 1のSSEと大容量ボディのテストがMITM経由でも通る。

**実装メモ（Phase 2）**

- CAは `credshim_mitm::CertificateAuthority`。`init` はディレクトリを 0700、`ca-key.pem` を 0600 で新規作成し、鍵が既にあれば置き換えを拒否する（信頼済みCAを黙って作り直さない）。既定の置き場所は `$XDG_CONFIG_HOME/credshim/ca`（未設定なら `~/.config/credshim/ca`）で、テストは必ず `--dir` にtempdirを渡す。
- リーフはSANがCONNECT先ホスト名だけ、有効期限24時間、moka で12時間キャッシュ（ホスト名は小文字化してキー）。
- MITM経路は `Handler::intercept`。200を返す前に `Upstream::connect_tls` で上流TLSを確立・検証し、失敗なら502。成功したときだけ `VerifiedTarget`（host、port、コンストラクタ非公開）を作り、以後の内側リクエスト処理はこれを持つ `Session` 経由で行う。Phase 3の差し替えは `&VerifiedTarget` を引数に取る。
- 下流TLSは `LazyConfigAcceptor` で ClientHello を先に読み、SNIが無いかCONNECT先と違えば証明書を出さずに切る。内側の Host（と絶対形式URIのauthority）はポート省略時443として (host, port) で比較し、不一致は421。
- 上流は1トンネルにつき1本の h1 接続を使い回し、閉じていたら `connect_tls` で再検証して張り直す。インターセプト対象は `credshim run --intercept <host>`（複数可）。設定ファイルは Phase 3。
- `credshim ca bundle` は rustls-native-certs のOSルートをDER順に並べ重複を除き、末尾に開発CAを足す（出力を決定的にするため）。

## Phase 3: シークレットストアと静的キー注入（MVP）

このフェーズの終わりで、OpenAI SDK がダミーキーのまま実APIを叩ける最初の実用版になる。HTTP/2はまだ無いが、SDKはHTTP/1.1で普通に動く。

**作るもの（secrets）**

- `SecretStore` トレイト。名前で取得・保存でき、値を列挙する操作は持たない。
- バックエンドは3種：OSキーチェーン（keyring）、age暗号化ファイル（コンテナやヘッドレスLinux向け）、起動時に外部コマンドで取得（1Password CLIなど）。
- `credshim secret set <name>`：TTYからエコーなしで読む。TTYでなければ拒否する。
- `credshim secret list`：名前と更新日時だけを出す。`get` は作らない。

**作るもの（core のルールエンジン）**

- ルールは「宛先の一致条件（host、port、任意でpath prefix）」「ダミー値」「秘密の参照」「差し替え場所」の組。
- 差し替え場所はヘッダー値の中の文字列、Basic認証（デコードして置換し再エンコード）、クエリパラメータの3種。Bearer、x-api-key、`?key=` などはこれで全部表せる。
- 判定関数は「接続コンテキスト＋リクエストヘッダー」を受けて「素通し／差し替え内容／拒否理由」を返す純粋関数にする。
- 全ルールのダミー値を常に探し、宛先が一致しないルールのダミーが見つかったら403で拒否して警告を出す（原則4）。ダミーを含まないリクエストは一切変更しない。
- ダミー値はルールごとに設定可能にする。SDKが接頭辞を検査する場合に合わせるため（例：`sk-credshim-openai-...`）。誤一致しないよう十分長くする。
- OpenAI、Anthropic、Gemini のプリセット。中身はただの設定スニペット。

**作るもの（監査ログ）**：時刻、宛先、メソッド、パス（クエリ値は除く）、適用ルール名、判定、ステータス。値は一切出さない。

**完了条件**

- [ ] テスト用DNS上書きで api.openai.com をモックに向け、エコーされた Authorization が偽秘密に置き換わっている。
- [ ] 同じダミーを別ホストへ送ると403になり、上流に何も届かない。
- [ ] Basic認証とクエリパラメータの差し替えが効く。ダミーを含まないリクエストはバイト単位で変わらない。
- [ ] 公式の openai SDK（Python と Node）が、モック上流相手にストリーミング込みで動くE2Eテストが通る。
- [ ] 人間が本物のキーを登録し、実APIでストリーミング応答を確認する（手動マイルストーン）。

## Phase 4: HTTP/2・ストリーミング・WebSocket

プロトコル面の透過性を仕上げる。差し替えロジックには手を入れず、Phase 3のテストがプロトコルの組み合わせ全部で通ることを目標にする。

**作るもの**

- 下流のALPNで `h2` と `http/1.1` を提示し、上流とも独立に交渉する。下流と上流でバージョンが違っても中継できるようにし、h2で禁止されている接続固有ヘッダーの除去と Host と :authority の対応を正規化する。
- h2ではストリームごとに :authority がCONNECT先と一致するかを検査する。一致しないストリームだけをリセットする。
- バックプレッシャーの確認。下流の読み取りが遅いとき、上流から無制限に読み込まないこと。
- トレーラーの中継（gRPCを通すため）。
- クライアント切断の伝播。SSEの途中でクライアントが切れたら上流も閉じる。LLMの生成と課金が止まる。
- WebSocket（HTTP/1.1 Upgrade）。Upgradeリクエストにも差し替えルールを適用し、上流が101を返したら両側の接続を取り出して双方向コピーする。OpenAI Realtime API のような用途を想定する。
- h2上のWebSocket（Extended CONNECT）は扱わない。プロキシがその設定を広告しなければ、クライアントはh1で接続してくる。

**完了条件**

- [ ] 下流h1/h2 × 上流h1/h2 の4通りで、Phase 3の差し替えテストとSSEテストが全部通る。
- [ ] 1本のh2接続で複数ストリームを並行処理でき、:authority 不一致のストリームだけが拒否される。
- [ ] WebSocketエコーがヘッダー差し替え込みで動く。
- [ ] SSE途中でクライアントを切ると、モック上流が切断を観測する。
- [ ] openai SDK のE2EがHTTP/2を有効にしたクライアントでも通る。

## Phase 5: OAuthトークン保管庫

プロキシはトークンエンドポイントの往復を横取りし、本物のトークンを保管庫にしまってアプリにはダミーを返す。以後のAPI呼び出しは、保管庫の「ダミー→本物」対応を動的なルールとして Phase 3 のエンジンに渡すだけで済む。

**プロバイダーごとの設定**：トークンエンドポイント（host＋path）、失効エンドポイント、client\_id、client\_secret の秘密参照とダミー値、クライアント認証方式（client\_secret\_post／client\_secret\_basic）、アクセストークンを差し替えてよいリソースホストの一覧、id\_token の扱い。

**各段階でプロキシがすること**

1. **認可リクエスト**（ブラウザ→プロバイダー）：秘密が要らないので関与しない。PKCE の code\_verifier もアプリが持ったままでよい。
2. **コード交換**：リクエストボディ（上限付きで読み込む）またはBasic認証のダミー client\_secret を本物に差し替える。上流には Accept-Encoding: identity で送る。応答はJSONとフォーム形式の両方を解析し、access\_token と refresh\_token をダミーに置き換え、Content-Length を付け直して返す。expires\_in、scope、token\_type は変えない。
3. **API呼び出し**：Bearer のダミーを、リソースホスト一覧に一致するときだけ本物に差し替える。一致しなければ403。
4. **リフレッシュ**：ダミーの refresh\_token を本物に差し替えて送る。新しいトークンが返ったら保存し、新しいダミーを発行する。refresh\_token がローテーションされなかった場合は既存のダミーを維持する。
5. **失効**：ダミーを本物に差し替えて送り、保管庫から消す。
6. **client credentials グラント**：2と同じ処理で、リフレッシュが無いだけ。

**ダミートークンと保管庫**

- ダミーは `csh_at_` や `csh_rt_` の接頭辞に十分な長さのランダム値を付けた形にする。
- 保管庫はダミーをキーに「本物、プロバイダー、種別、有効期限、作成日時」を持つ。暗号化ファイルに永続化し、鍵はキーチェーンに置く。プロキシを再起動してもアプリのリフレッシュが通るようにするため。
- 期限切れのアクセストークンは定期的に掃除する。
- 同じ refresh\_token での同時リフレッシュはプロキシ側で直列化し、直後の重複要求には同じ結果を返す。ローテーション型のプロバイダーで2本目が失敗するのを防ぐ。
- id\_token は既定で素通しにする。アプリが署名やnonceを検証するため、ダミーに置き換えると壊れる。id\_token をBearerとして受け付けるサービスを使う場合だけ、ブロック設定を検討する。

**完了条件**

- [ ] testkit にモックOAuthサーバーがある。認可コード＋PKCE、client\_secret\_post と basic、JSONとフォーム形式の応答、ローテーションあり／なしのリフレッシュ、失効に対応する。
- [ ] アプリから見えるトークンがすべてダミーで、モックAPIに届く Bearer が本物になっている。
- [ ] ローテーション、同時リフレッシュ、プロキシ再起動後のリフレッシュが通る。
- [ ] ダミーのアクセストークンをリソースホスト以外へ送ると403になる。
- [ ] 人間が実プロバイダー（例：Google、GitHub）で一連のフローを確認する（手動マイルストーン）。

## Phase 6: ハードニングとプロセス分離

ここまでで機能は揃うが、同じOSユーザーでエージェントとプロキシが動く限り、原理的な保証にはならない。このフェーズで「エージェントには原理的に読めない」状態に持っていく。

**レスポンスのスクラブ**

- 登録済みの秘密と保管庫の本物トークンを、レスポンスのヘッダーとボディから検出してダミーに置き換える。
- Aho-Corasick でストリーム処理する。チャンク境界をまたぐ一致に備え、「秘密の先頭部分になりうる末尾」だけを次のチャンクまで保留し、それ以外は即座に流す。SSEの遅延はほぼ増えない。
- 対象はMITMしているホストだけでよい。本物を送っていないホストの応答に本物は現れない。圧縮されたボディに対応するため、スクラブ対象の上流には Accept-Encoding: identity を要求する。

**乱用の緩和**

- ルールごとのメソッド・パス許可リスト。例えば OpenAI なら推論系のパスだけ許し、組織管理系のパスは拒否する。
- ルールごとのレート、同時実行数、日次リクエスト数の上限。

**分離の段階**

| 段階 | 構成 | 防げる | 防げない |
| --- | --- | --- | --- |
| A：同一ユーザー | プロキシも開発ユーザーで動き、秘密はキーチェーン | .env・ログ・コンテキストへの混入 | 同一ユーザー権限でのストア読み出し、設定改ざん |
| B：別OSユーザー | 専用ユーザーで launchd／systemd 常駐。設定・秘密・CA鍵はそのユーザー所有の 0600。開発ユーザーは sudo 不可 | Aに加え、ストアとメモリの読み出し、設定改ざん | プロキシを経由しない通信（そもそも秘密は無いので実害は小さい） |
| C：コンテナ分離 | Claude Code とアプリは devcontainer 内、プロキシはホスト側。コンテナの外向き通信はプロキシだけ | Bに加え、全通信がプロキシの監査下に入る | 許可済みAPIの乱用（上の緩和策で抑える） |

- 開発中の既定はA、実運用はBかCにする。Bでの秘密登録は `sudo -u credshim credshim secret set` のように、人間だけが知るパスワードを経由させる。
- Cではプロキシをdockerブリッジ側のインターフェースにだけ bind する。
- 全段階で、コアダンプを無効化する。Linuxでは PR\_SET\_DUMPABLE を 0 にし、同一ユーザーからの ptrace と /proc/pid/mem の読み出しも塞ぐ。
- 管理用のHTTP APIは作らない。状態確認は、ルール名とカウンタだけを返す読み取り専用のUnixソケットにする。

**完了条件**

- [ ] モック上流が秘密をエコーしても（チャンク境界をまたいでも）クライアントに届かない。スクラブ有効時もSSEの遅延が上限内。
- [ ] 許可リスト外のパスと上限超過が403／429になる。
- [ ] 脅威モデルの表の各行に、対応する回帰テストがある。
- [ ] 段階Bの構築スクリプトがあり、開発ユーザーから設定・秘密・CA鍵を読めず書けないことを検証するスクリプトが通る。
- [ ] Basic認証のデコード、トークン応答の解析、ヘッダー書き換えを cargo-fuzz にかけ、クラッシュしない。

## Phase 7: 開発体験（env出力、doctor、base URLモード）

MITMプロキシで一番つまずくのは「そのランタイムがプロキシとCAを本当に使っているか」。これを1コマンドで確かめられるようにして仕上げる。

**作るもの**

- `credshim env`：シェルに読み込む変数を出力する。HTTPS\_PROXY、HTTP\_PROXY、NO\_PROXY（localhost など）、結合バンドルを指す SSL\_CERT\_FILE・REQUESTS\_CA\_BUNDLE・CURL\_CA\_BUNDLE、開発CAを指す NODE\_EXTRA\_CA\_CERTS、それに各サービスのダミーキー（OPENAI\_API\_KEY など）。ダミーなので .env にそのまま書いてよい。
- `credshim doctor`：予約ホスト名（例：`credshim.test`）へのCONNECTをプロキシ自身が応答し、「プロキシ経由か」「CAを信頼しているか」「h2で繋がったか」を返す。Python（requests、httpx）、Node、Go、curl から叩くワンライナーを添える。
- Node の注意書き。組み込みの fetch はバージョンによって HTTPS\_PROXY を自動では見ない（環境変数での有効化や undici の EnvHttpProxyAgent が必要）。doctor で検出して案内する。
- base URLモード。`http://127.0.0.1:8788/openai/` を `https://api.openai.com/` に固定で対応させるリバースプロキシで、LiteLLM Proxy と同じ使い方になる。CA設定が不要で、プロキシ変数を見ないランタイムでも使える。対応表は設定で固定されるのでホスト混同の余地がなく、同じルールエンジンをそのまま使える。
- `credshim service install`：launchd／systemd への常駐登録（段階Bの専用ユーザー向け）。
- `credshim tail`：監査ログのライブ表示。エージェントが今何を叩いているかが見える。

**完了条件**

- [ ] `credshim env` を読み込んだ新しいシェルで、Python、Node、Go、curl のサンプルが doctor を通る。
- [ ] base URLモードで openai SDK のE2Eが通る。
- [ ] README に、インストールから最初のストリーミング応答までの手順がある。

## 付録：設定ファイル例

設定は静的キーのルールとOAuthプロバイダーの2種類。ホスト束縛がここに書かれるので、段階B以降はこのファイル自体をプロキシ専用ユーザーの所有にする。

```toml
[listen]
addr = "127.0.0.1:8787"          # MITM（HTTPS_PROXY 用）
base_url_addr = "127.0.0.1:8788" # base URLモード

[ca]
dir = "/var/lib/credshim/ca"

[secrets]
backend = "age-file"             # keychain | age-file | command
path = "/var/lib/credshim/secrets.age"

# ---- 静的キー ----
[[rule]]
name = "openai"
host = "api.openai.com"
secret = "openai"
dummy = "sk-credshim-openai-<十分長いランダム>"
inject = { header = "authorization" }
allow_paths = ["/v1/chat/completions", "/v1/responses", "/v1/embeddings"]
base_url_prefix = "/openai"

[[rule]]
name = "anthropic"
host = "api.anthropic.com"
secret = "anthropic"
dummy = "sk-ant-credshim-<十分長いランダム>"
inject = { header = "x-api-key" }

[[rule]]
name = "gemini"
host = "generativelanguage.googleapis.com"
secret = "gemini"
dummy = "credshim-gemini-<十分長いランダム>"
inject = { header = "x-goog-api-key", query = "key" }

# ---- OAuth ----
[[oauth]]
name = "google"
token_endpoint = "https://oauth2.googleapis.com/token"
revoke_endpoint = "https://oauth2.googleapis.com/revoke"
client_id = "<client-id>"
client_secret = { secret = "google-client-secret", dummy = "credshim-google-secret-<ランダム>" }
client_auth = "client_secret_post"
resource_hosts = ["www.googleapis.com", "gmail.googleapis.com"]
id_token = "passthrough"

[scrub]
enabled = true

[limits]
max_token_body_bytes = 65536
```

アプリ側の .env にはダミーだけが並ぶ（`OPENAI_API_KEY=sk-credshim-openai-...`、`GOOGLE_CLIENT_SECRET=credshim-google-secret-...`）。

## 範囲外と未決事項

**範囲外**（必要になったら同じ枠組みで足せる）

- HTTP/3（QUIC）。HTTPS\_PROXY 経由のクライアントは使わない。
- 署名型の認証（AWS SigV4 など）。リクエスト全体に署名するので単純な置換では済まず、プロキシが再署名する機能が別途要る。
- private\_key\_jwt やサービスアカウントのJWT bearer グラント。プロキシが署名を肩代わりする形で追加できる。
- mTLS のクライアント証明書。
- 本番環境での利用。あくまでローカル開発専用。

**未決事項**

- [ ] Webhook の署名検証用シークレット（Stripe など）。受信側の秘密はこの仕組みでは守れない。プロキシが受信時に検証して結果をヘッダーで渡す逆方向の機能を作るか決める。
- [ ] OAuth のアクセストークンがJWTで、アプリがクレームを読む場合の扱い。ダミーを「同じペイロードで署名だけ無効なJWT」にするか。
- [ ] 秘密ストアの既定バックエンド（キーチェーンか age ファイルか）。
- [ ] SDK がキーの形式を検証するサービスの洗い出しと、プリセットのダミー形式の決定。
