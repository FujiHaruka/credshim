# Configuration

The configuration file is TOML. In the recommended setup it is `/var/lib/credshim/config.toml` (only the service user can read and write it). In the trial setup it is `~/.config/credshim/config.toml`.

The commands on this page are for the recommended setup. `$user`, `$bin`, and `credshim-svc` are [the install variables](install.md#set-the-variables). For the trial setup, read them as described in [adapting the commands](install.md#adapting-the-commands-to-the-trial-setup). Edit the configuration file in the admin session, for example with `sudo -u $user vi /var/lib/credshim/config.toml`.

## Writing rules

A rule says which dummy to replace with which real value, and only when the request goes to which destination. For an API that has no preset, write the rule yourself.

```toml
[[rule]]
name = "stripe"
host = "api.stripe.com"
secret = "stripe"                                  # name registered in the secret store
dummy = "sk_credshim_stripe_0123456789abcdef"      # dummy given to the app (make it your own random string)
env = "STRIPE_API_KEY"                             # variable in keys.env that carries the dummy
inject = { header = "authorization" }              # where to look for the dummy and replace it
allow_methods = ["GET", "POST"]
allow_paths = ["/v1/charges", "/v1/customers"]
limits = { per_minute = 60, per_day = 1000 }
```

After you write it, register the real key and apply the change.

```sh
credshim-svc secret set stripe
sudo $bin service reload
```

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Rule name. Letters, digits, `.`, `_`, and `-` |
| `host` | yes | Destination host name (lowercase, no port) |
| `port` | | Destination port. Default 443 |
| `path_prefix` | | Limits the destination to paths under this prefix (with `/v1`, only `/v1/...`) |
| `secret` | yes | Name in the secret store that holds the real value. Register it with `credshim-svc secret set <name>` |
| `dummy` | yes | Dummy given to the app. 24 to 256 characters: letters, digits, `-`, `.`, `_`, and `~`. It must not contain, or be contained in, another rule's dummy |
| `inject` | yes | Where to look for the dummy and replace it. One or more of `header = "<header name>"` (only the dummy inside the value is replaced, so `Bearer <dummy>` works), `query = "<parameter name>"`, and `basic = true` (Basic authentication) |
| `allow_methods` | | Allowed HTTP methods. All if omitted |
| `allow_paths` | | Allowed paths. Prefix match on path segment boundaries (`/v1/charges` matches `/v1/charges/ch_1` and does not match `/v1/chargesX`). All if omitted |
| `limits` | | Request count limits: `per_minute`, `per_day`, and `concurrent` (requests in progress at the same time). No limit if omitted |
| `env` | | Environment variable name that carries the dummy in `keys.env`. The name must end in `_KEY`, `_TOKEN`, `_SECRET`, or `_PASSWORD` |
| `base_url_prefix` | | Prefix used in [base URL mode](#base-url-mode) |

### How rules apply

- The dummy is replaced with the real value only when the actual destination matches `host` and `port` (and `path_prefix`), and the destination's TLS certificate verifies against the system trust store. Plain HTTP is never replaced.
- If the dummy goes to another destination, the proxy returns 403 and does not replace it. Nothing is sent upstream.
- If the destination matches but the request is outside `allow_methods` or `allow_paths`, the response is 403. If it exceeds `limits`, the response is 429. In both cases nothing is sent upstream.
- If a response contains the real value, the proxy changes it back to the dummy before it returns the response to the client (scrub). `[scrub] enabled = false` turns this off, but leave it on.
- Traffic to a host with no rule is relayed as is, without looking inside. The development CA is needed only for traffic to hosts that have a rule.

## Applying changes

After you change rules or secrets, run `sudo $bin service reload` in the admin session. The process keeps running.

- Requests in progress (including streaming responses and WebSockets) run to the end on the configuration from before the reload. The next request uses the new configuration. This includes the next request on a connection that stays open.
- Limit counters carry over.
- `service reload` first checks that the service user can read the configuration and the secrets (`run --check`). If it cannot, the reload fails and changes nothing. If the proxy fails to reload, it also keeps running on its current configuration. The result goes to the service log (`/var/lib/credshim/credshim.log` on macOS, `journalctl -u credshim` on Linux).
- An open connection to a host that had no rule is relayed without looking inside, so a rule added for that host does not apply until the client reconnects.

The table shows which settings apply on reload and which need a restart. If you change a setting that needs a restart and then reload, the log shows a warning.

| Applies immediately | Needs a restart (`sudo $bin service install`; connections in progress are closed) |
| --- | --- |
| `[[rule]]`, `[scrub]`, AWS (`[aws]`, `[[aws_key]]`, `[[aws_sso_session]]`, `[[aws_sso_role]]`) | `[listen]`, `[ca]`, `[secrets]`, `[audit]`, `[status]`, SSH (`[ssh]`, `[[ssh_key]]`), OAuth (`[[oauth]]`, `[vault]`, `[limits]`) |

## Base URL mode

A mode for clients that cannot use the proxy environment variables or a custom CA. It is a reverse proxy that forwards `http://127.0.0.1:8788/openai/...` to `https://api.openai.com/...` by a fixed mapping. Rules (destination, allowlists, limits, scrub) still apply. The development CA is not needed.

```toml
[listen]
addr = "127.0.0.1:8787"
base_url_addr = "127.0.0.1:8788"
```

After you change `[listen]`, restart with `sudo $bin service install`. Preset rules include `base_url_prefix` (`/openai` for `openai`).

```sh
OPENAI_BASE_URL=http://127.0.0.1:8788/openai/v1 OPENAI_API_KEY=sk-credshim-openai-... python app.py
```

`/etc/credshim/keys.env` lists the available base URLs as comments, such as `# base URL for openai: http://127.0.0.1:8788/openai`.

- The proxy rejects paths that are not in the mapping, paths that contain `..` or `%2f`, and a Host that names anything other than loopback.
- A request that contains no dummy is forwarded upstream as is (the real value is not used).

## OAuth

For OAuth, the app also sees only dummies for the client secret and for the access tokens and refresh tokens that are issued.

- The app calls the token endpoint with the dummy client secret. The proxy replaces it with the real one and sends the request.
- The proxy replaces the access token and the refresh token in the token endpoint response with dummies and returns them to the app. The real tokens are kept in an encrypted vault (`[vault]`).
- When the app calls an API in `resource_hosts` with the dummy access token in the `Authorization` header, the proxy replaces it with the real one. The same applies to refresh and revoke requests.

```toml
[[oauth]]
name = "example"
token_endpoint = "https://oauth.example.com/token"
revoke_endpoint = "https://oauth.example.com/revoke"    # optional
client_id = "your-client-id"
client_secret = { secret = "example-client", dummy = "credshim-example-client-0123456789abcdef" }
client_auth = "client_secret_post"                      # "client_secret_basic" to send it with Basic authentication
resource_hosts = ["api.example.com"]                    # API hosts where the access token is replaced

[limits]
max_token_body_bytes = 65536                            # optional. Limit on the body read at the token endpoint (default 64KiB)
```

Register the real client secret with `credshim-svc secret set example-client`. The vault encryption key is created in the secret store on the first start. After you change the OAuth settings, restart with `sudo $bin service install`.

## Secret stores

`[secrets]` selects where the real values are kept.

| `backend` | Storage | Default in |
| --- | --- | --- |
| `age-file` | A file encrypted with age (`path`). The key defaults to `.key` in the same location | Recommended setup (`/var/lib/credshim/secrets.age`), trial setup on Linux |
| `keychain` | The macOS keychain (service name `credshim` by default) | Trial setup on macOS |
| `command` | Standard output of an external command (`command = ["...", "{name}"]`, where `{name}` is the secret name). Read-only. Register secrets with the external tool | |

`credshim-svc secret list` shows the names of the registered secrets and when they were updated (not the values). There is no command that prints a value.

## Audit log and status

The configuration that `service install` writes includes the audit log `/var/lib/credshim/audit.jsonl` and the status socket `/var/lib/credshim/status.sock`.

```toml
[audit]
path = "/var/lib/credshim/audit.jsonl"

[status]
socket = "/var/lib/credshim/status.sock"
```

- `credshim-svc tail` shows the audit log live. You can see where the agent is calling now and what was denied.
- `credshim-svc status` shows the counters for each rule.

Neither shows secret or dummy values. Both are in a location that only the service user can read, so the developer user cannot see them.

```text
2026-09-30T03:31:37.5Z inject      200 POST https://api.openai.com:443/v1/chat/completions [openai] via connect
2026-09-30T03:31:40.1Z deny        403 POST https://attacker.example:443/collect [openai] via connect
```
