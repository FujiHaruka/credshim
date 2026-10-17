# Troubleshooting

First run `credshim doctor` in the developer session. A request that CredShim refused says why in its response, along with the command that shows its audit log entry (see [Refused requests](#refused-requests)). To watch every request, use `credshim-svc tail` in the admin session (in the trial setup, `credshim tail`). For `credshim-svc`, see [the install variables](install.md#set-the-variables).

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
[ok  ] files    no leftover keys, tokens or logins found
```

`credshim.test` is a reserved host name that the proxy itself answers; it does not exist in DNS. Reaching it shows that the traffic goes through the proxy, and a successful TLS handshake shows that the CA is trusted. `credshim doctor --snippets` prints one-liners that check the same thing from each language (requests, httpx, Node's fetch, Go).

A line marked `fail` or `warn` names a check, and each check has a section below. At the end, doctor prints the command for each of those sections. `credshim doctor --verbose` also prints the full output of each failed probe.

### `proxy`

doctor could not get an answer from `credshim.test` through the proxy, or the certificate did not chain to the CA. Check that the proxy is running (`credshim-svc status`, or the `credshim run` terminal in the trial setup) and that `HTTPS_PROXY` points at its address.

### `env`

An environment variable that apps need is missing or points at the wrong file. Load the variables with `. /etc/credshim/env` (in the trial setup, `eval "$(credshim env)"`). `SSL_CERT_FILE` and `AWS_CA_BUNDLE` must point at the combined bundle, not the CA alone, because they replace the trust store.

### `curl`

curl did not reach `credshim.test` through the proxy or did not trust the CA. curl reads `HTTPS_PROXY` and `SSL_CERT_FILE` (or `CURL_CA_BUNDLE`).

### `python`

The ssl module of Apple's bundled `/usr/bin/python3` does not read `SSL_CERT_FILE`. requests and httpx read `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` themselves, so they work.

### `node`

The built-in fetch does not look at `HTTPS_PROXY` without `NODE_USE_ENV_PROXY=1` (Node 24 and later). On older Node, pass undici's `EnvHttpProxyAgent` as the dispatcher. When the request failed without going through the proxy (`ENOTFOUND credshim.test`), doctor says so. Node trusts the CA through `NODE_EXTRA_CA_CERTS`.

### `go`

On Linux, Go reads `SSL_CERT_FILE`. On macOS it often does not (see [Go tools on macOS](#go-tools-on-macos) below). doctor runs a temporary file with no go.mod through `go run`, so on macOS it reports a failure unless the CA is trusted in the keychain.

### `ssh`

doctor asks the agent at `SSH_AUTH_SOCK` for its key list and, if there is no CredShim key (comment `credshim:<rule name>`), warns that it points at a different agent. If the agent does not answer, check that the proxy is running and that this uid is in `[ssh] client_uids`.

### `openssh`

The `ssh` on PATH is older than OpenSSH 8.9, or is not OpenSSH. The CredShim agent needs session-bind, which OpenSSH sends from 8.9.

### `aws`

doctor uses `aws` on PATH to send a request with the dummy key to `credshim.test`, and checks that it goes through the proxy and trusts the CA. `AWS_CA_BUNDLE` replaces the trust store, so it must point at the combined bundle.

### `files`

doctor reports private keys in `~/.ssh`, real access keys and `credential_process` and SSO profiles in `~/.aws/credentials` and `~/.aws/config`, `~/.aws/sso/cache` and `~/.aws/cli/cache`, `gh` logins in `~/.config/gh/hosts.yml` (whether the token is in the file or in the system keyring), and real AWS keys, session tokens, and GitHub tokens in environment variables, by path, profile name, and host only (without printing the values). To clean them up, see [Replace existing credentials](install.md#6-replace-existing-credentials).

## Refused requests

When CredShim stops a request, it sends nothing upstream and answers itself. The response says that it came from CredShim, why, and which commands show more.

```text
HTTP/1.1 403 Forbidden
credshim-error: not_allowed
credshim-request-id: 3f9c2a7b1e04
content-type: text/plain; charset=utf-8

credshim: POST /v1/files is outside the allow_methods or allow_paths of rule "openai"
details: sudo -u credshim /usr/local/libexec/credshim/credshim tail --config /var/lib/credshim/config.toml --id 3f9c2a7b1e04
docs: credshim docs troubleshooting#not_allowed
```

- `credshim-error` is the kind of refusal, and each kind has a section below.
- `details` is the command that prints the whole audit log entry of this request. In the recommended setup only the admin can read the audit log, so an agent passes this line to a person. In the trial setup, the developer user can run it as is. If no audit log is configured, this line says so.
- `docs` prints the matching section of this page.
- AWS SDKs and the aws CLI get the same text as the message of an AWS-format error (for example, `CredShimOperationNotAllowed`).
- Every response that went through a rule's host carries `credshim-request-id`, including the ones the upstream answered, so you can also look up a request that the upstream refused (for example, to see whether the real key was put in).

If the host has a rule but the app gets a TLS certificate error and no `credshim-error`, the app does not read the proxy environment variables or the CA. Check with `credshim doctor`.

### `deny`

403 (400 or 413 for some AWS refusals). A dummy was sent to a host that is not that rule's destination, a dummy was sent over plain HTTP, or the target is a link-local or cloud metadata address or an AWS sign-in or SSO endpoint. If the destination is correct, fix the rule's `host`, `port`, `path_prefix`. For AWS, the message gives the reason (for example, an operation that issues credentials).

### `not_allowed`

403. The destination is right, but the request is outside `allow_methods`, `allow_paths` (`operations` for AWS). If it should be allowed, add it to the rule's allowlist.

### `limited`

429. A limit in `limits` (`per_minute`, `per_day`, `concurrent`) was exceeded. The first line names the limit and says when to retry, and `Retry-After` gives the same wait in seconds (for `concurrent`, there is none: retry when one of the rule's requests finishes). Retrying before then fails again. Check the counters with `credshim-svc status`.

### `misdirected`

421. The host the connection was opened to and the Host inside the request disagree, or a request to the base URL listener names another host.

### `error`

500 or 502. CredShim could not complete its own part: the rule's secret is not registered or is empty, the AWS SSO role credentials could not be obtained (the message says when `credshim aws sso login` is needed), the request could not be re-signed, or the upstream sent a compressed response that cannot be scrubbed of secrets.

### `upstream`

502. The proxy could not connect to the upstream or the request to it failed (name resolution failed, the connection was refused, timeout, or the upstream's certificate could not be verified). The first line has the error. In the audit log, a CONNECT to a host with no rule appears as `tunnel`.

### `rejected`

400, 404, 405, or 503. The request itself could not be handled: it was not a valid proxy request, no rule's `base_url_prefix` matched the path on the base URL listener, or too many AWS request bodies were being buffered (retry shortly).

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
