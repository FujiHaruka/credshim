# Troubleshooting

First run `credshim doctor` in the developer session. To see why a request was refused, use `credshim-svc tail` in the admin session (in the trial setup, the terminal running `credshim run`). For `credshim-svc`, see [the install variables](install.md#set-the-variables).

## credshim doctor

Checks, with this shell's environment as is, that curl, python3, node, go, ssh, and aws on PATH go through the proxy and trust the development CA.

```text
[ok  ] proxy    credshim.test answered through 127.0.0.1:8787 over h2; its certificate chains to /etc/credshim/ca.pem
[ok  ] env      HTTPS_PROXY=http://127.0.0.1:8787
[ok  ] env      SSL_CERT_FILE=/etc/credshim/bundle.pem includes the CA
[ok  ] curl     via the proxy, CA trusted, h2
[ok  ] python   via the proxy, CA trusted, http/1.1
[ok  ] node     via the proxy, CA trusted, http/1.1
[ok  ] go       via the proxy, CA trusted, h2
[ok  ] ssh      SSH_AUTH_SOCK=/var/lib/credshim-ssh/agent.sock is the credshim agent (rules: github)
[ok  ] openssh  /usr/bin/ssh is OpenSSH 9.9, which sends session-bind
[ok  ] aws      the aws CLI reached credshim.test through the proxy and trusted the CA
[ok  ] files    no private keys in ~/.ssh and no real AWS credentials in ~/.aws or the environment
```

`credshim.test` is a reserved host name that the proxy itself answers; it does not exist in DNS. Reaching it shows that the traffic goes through the proxy, and a successful TLS handshake shows that the CA is trusted. `credshim doctor --snippets` prints one-liners that check the same thing from each language (requests, httpx, Node's fetch, Go).

What to check when something fails:

- **Node.** The built-in fetch does not look at `HTTPS_PROXY` without `NODE_USE_ENV_PROXY=1` (Node 24 and later). On older Node, pass undici's `EnvHttpProxyAgent` as the dispatcher. When the request failed without going through the proxy (`ENOTFOUND credshim.test`), doctor says so.
- **Python.** The ssl module of Apple's bundled `/usr/bin/python3` does not read `SSL_CERT_FILE`. requests and httpx read `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` themselves, so they work.
- **Go.** On Linux, Go reads `SSL_CERT_FILE`. On macOS it often does not (see [Go tools on macOS](#go-tools-on-macos) below). doctor runs a temporary file with no go.mod through `go run`, so on macOS it reports a failure unless the CA is trusted in the keychain.
- **SSH.** doctor asks the agent at `SSH_AUTH_SOCK` for its key list and, if there is no CredShim key (comment `credshim:<rule name>`), warns that it points at a different agent. It reports when `ssh` on PATH is older than OpenSSH 8.9 (which does not send session-bind).
- **AWS.** doctor uses `aws` on PATH to send a request with the dummy key to `credshim.test`, and checks that it goes through the proxy and trusts the CA. `AWS_CA_BUNDLE` replaces the trust store, so it must point at the combined bundle.
- **Leftover real credentials (files).** doctor reports private keys in `~/.ssh`, real access keys and `credential_process` and SSO profiles in `~/.aws/credentials` and `~/.aws/config`, `~/.aws/sso/cache` and `~/.aws/cli/cache`, and real keys and session tokens in environment variables, by path and profile name only (without printing the values). To clean them up, see [Replace existing credentials](install.md#6-replace-existing-credentials).

## 403 or 429 responses

For a request that CredShim stops, it returns 403 or 429 and sends nothing upstream. The body is empty (except for AWS, which gets an error in the AWS format), so check the audit log for the reason.

| Audit log verdict | Status | Meaning and fix |
| --- | --- | --- |
| `deny` | 403 | A dummy was sent to a host that is not that rule's destination. Sending over plaintext HTTP and connecting to a cloud metadata address also land here. If the destination is correct, fix the rule's `host`, `port`, `path_prefix` |
| `not_allowed` | 403 | The destination is right, but the request is outside `allow_methods`, `allow_paths` (`operations` for AWS). If needed, add it to the rule's allowlist |
| `limited` | 429 | A limit in `limits` was exceeded. Check the counters with `credshim-svc status` |
| `misdirected` | 421 | The connection target and the Host inside the request disagree |
| `error` | 500, 502 | Replacing failed (the rule's secret is not registered, is empty, and so on), or the role credentials for AWS SSO could not be obtained. The reason is in the service log |
| `tunnel` | 502 | On a CONNECT to a host with no rule, the proxy could not open a TCP connection upstream (name resolution failed, the connection was refused, timeout). The reason is in the service log |

If the host has a rule but neither `inject` nor `deny` appears, and the app gets a TLS certificate error, the app does not read the proxy environment variables or the CA. Check with `credshim doctor`.

## Go tools on macOS

The development CA is needed only for traffic to hosts that have a rule (all of `amazonaws.com` if there is an AWS rule). Traffic to other hosts is relayed without being inspected and gets the real certificate, so Go tools work there unchanged. For example, Terraform registry and provider downloads go through, but when there is an AWS rule, the AWS provider's API calls fail because they cannot trust the development CA.

On macOS, Go leaves certificate verification to the keychain and does not read `SSL_CERT_FILE`. It reads it only when a program built with Go 1.27 or later has a `go` line of 1.27 or higher in its go.mod, or when the program runs with `GODEBUG=x509sslcertoverrideplatform=1`.

Try these in order.

1. If the tool was built with Go 1.27 or later, run it with `GODEBUG=x509sslcertoverrideplatform=1` (if `GODEBUG` already has other settings, join them with commas). For your own project, set the `go` line in go.mod to 1.27 or higher and you do not need it.
2. If the tool lets you change the API endpoint, use [base URL mode](configuration.md#base-url-mode) (it does not need the development CA).
3. Only if neither works (for example, a distributed binary built with an old Go), trust the development CA in the developer user's login keychain. This does not need admin rights; it asks for your password.

```sh
security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db /etc/credshim/ca.pem
```

Trusting the CA in the keychain changes the security assumptions.

- Every app of that developer user, browsers included, trusts the development CA. If the CA private key leaks, it can be used to impersonate any site and read and write that user's HTTPS traffic. When the CA is passed only through environment variables, the impact stays within the processes that read those variables.
- Recommended setup only. Only the service user can read the CA private key, so an agent running with the developer user's privileges cannot extract it, and it leaks only if the service user's or an admin's privileges are taken over. In the trial setup, the developer user can read the CA private key, so the agent can create certificates for any site.
- If you recreate the CA, remove trust in the old CA first, then add the new one again.

```sh
security remove-trusted-cert /etc/credshim/ca.pem
security delete-certificate -c "credshim development CA" ~/Library/Keychains/login.keychain-db
```
