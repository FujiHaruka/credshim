# CredShim

A local credential-injection proxy for developing without giving real API keys to coding agents or apps.

Apps and agents hold only dummy keys. Right before a request leaves for a registered destination, CredShim replaces the dummy with the real key. The real key never appears in .env, in app memory, in logs, or in the agent's context.

```text
App / agent ──(dummy key)──▶ CredShim ──(real key)──▶ api.openai.com
                              │
                              └─ stops a dummy headed to an unregistered destination with 403
```

- An HTTPS proxy that sits in between through `HTTPS_PROXY`. It relays HTTP/1.1, HTTP/2, SSE, and WebSocket, and SDKs work without modification.
- For clients that cannot handle proxy environment variables or a custom CA, there is also a mode that replaces the API endpoint (base URL).
- Besides API keys, it handles SSH keys (it runs as an ssh-agent), AWS access keys and IAM Identity Center (SSO), and OAuth tokens the same way.

## What it protects and what it does not

In the setup that runs the proxy as a dedicated service user (the recommended setup), an agent cannot extract the value of a real key, even if it goes rogue or is hijacked by prompt injection.

It does not protect against the following.

- **Using the key.** The agent can send requests that use the real key through the proxy. It can send them only within the destinations, paths, operations, and counts that the rules allow. Anything else gets 403 or 429.
- **A developer user who is an admin.** With the permissions of the developer user (the normal OS user the agent runs as), the agent can plant something in the shell config, steal the sudo password, become root, and read the secrets. Do not make the developer user an admin.
- **The trial setup.** The proxy runs as the developer user, so the agent can reach the secret store and the config.

See the [threat model](docs/threat-model.md) for details.

## Supported platforms

- Prebuilt binaries: macOS (Apple silicon), Linux (x86_64 and aarch64, glibc 2.35 or later)
- Anything else (such as Intel Macs): build from source (requires Rust)

## Choosing a setup

| Setup | Suited for | Can the agent extract the real values? |
| --- | --- | --- |
| [Trial setup](#trial-setup) | Seeing it work in 5 minutes | Yes |
| [Recommended setup](docs/install.md) | Everyday use with real keys entrusted to it. The proxy runs as a dedicated service user | No |
| [Container isolation](docs/container.md) | The recommended setup, plus all agent traffic goes through the proxy's checks and audit | No |

## Trial setup

> **This setup does not protect against agents.** The proxy runs as the developer user, so the agent can read and write the secret store and the config. Use it only to see how it works, and recreate the keys registered here when you move to the recommended setup.

Get the binary.

```sh
v=0.6.3
target=aarch64-apple-darwin   # on Linux, x86_64-unknown-linux-gnu or aarch64-unknown-linux-gnu
curl -fsSL "https://github.com/FujiHaruka/credshim/releases/download/v$v/credshim-$v-$target.tar.gz" | tar -xzf - credshim
mkdir -p ~/.local/bin && mv credshim ~/.local/bin/   # put it somewhere on PATH
```

Register an OpenAI key and start the proxy.

```sh
credshim ca init                                            # create a development CA (not added to the OS trust store)
mkdir -p ~/.config/credshim
credshim preset openai >> ~/.config/credshim/config.toml    # add rules for OpenAI
credshim secret set openai                                  # enter the real key from the terminal
credshim run                                                # start the proxy (this shell stays occupied)
```

Use it from another shell.

```sh
eval "$(credshim env)"          # set the proxy and CA environment variables
credshim doctor                 # check that curl, python, node, and others use the proxy and CA
set -a; eval "$(credshim env --keys)"; set +a   # set the dummy keys (OPENAI_API_KEY and others)

curl https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}'
```

`$OPENAI_API_KEY` is a dummy, but the response is the same as when you send the real key. The `credshim run` terminal records the replaced request.

The config is in `~/.config/credshim/config.toml` (it follows `$XDG_CONFIG_HOME`). Secrets are in the keychain (service name `credshim`) on macOS and in `~/.config/credshim/secrets.age` elsewhere. To stop using it, stop `credshim run` and delete `~/.config/credshim`. On macOS, also delete the keychain item (`security delete-generic-password -s credshim -a openai`).

## Recommended setup

For everyday use with real keys, run the proxy as a service under a dedicated service user. The rough flow is as follows.

1. Make the developer user a non-admin
2. In an admin session, run the install one-liner to create the service user and the service
3. In an admin session, register the rules and the real keys
4. In the developer session, load the environment variables and use it

The steps are in [docs/install.md](docs/install.md).

## Presets

`credshim preset <name>` generates rules for common services. The dummy keys are generated at random each time.

| Name | Destination | Environment variable for the dummy | Description |
| --- | --- | --- | --- |
| `openai` | `api.openai.com` | `OPENAI_API_KEY` | |
| `anthropic` | `api.anthropic.com` | `ANTHROPIC_API_KEY` | |
| `gemini` | `generativelanguage.googleapis.com` | `GEMINI_API_KEY` | |
| `github-ssh` | `github.com` (SSH) | | [SSH agent](docs/ssh.md) |
| `aws` | AWS services | `AWS_ACCESS_KEY_ID` and others | [AWS](docs/aws.md) |
| `aws-sso` | AWS services | `AWS_ACCESS_KEY_ID` and others | [AWS (SSO)](docs/aws.md#aws-iam-identity-center-sso) |

For other APIs, write and register the rules yourself ([Configuration](docs/configuration.md#writing-rules)).

## Using it with coding agents

In the shell that starts the agent, load the proxy environment variables and the dummy keys, then start the agent. Commands and apps that the agent runs inherit those environment variables.

```sh
. /etc/credshim/env                              # recommended setup. For the trial setup: eval "$(credshim env)"
set -a; . /etc/credshim/keys.env; set +a         # dummy keys. For the trial setup: set -a; eval "$(credshim env --keys)"; set +a
```

Traffic to destinations that have rules is relayed through the development CA, so an agent that itself talks to those destinations must also trust the CA through these environment variables. Traffic that contains no dummy is relayed as is, without using a real key.

If you put the dummy keys into every shell, other keys written in a project's .env can stop being used. For how to pass them per project, see [docs/install.md](docs/install.md#giving-the-dummy-keys-to-a-project).

## Documentation

- [Installing the recommended setup](docs/install.md): install, update, uninstall, and migrating from existing credentials
- [Configuration](docs/configuration.md): writing rules, applying changes, base URL mode, OAuth, audit log
- [AWS](docs/aws.md): static access keys and IAM Identity Center (SSO)
- [SSH agent](docs/ssh.md)
- [Container isolation](docs/container.md)
- [Troubleshooting](docs/troubleshooting.md): `credshim doctor`, investigating 403 and 429, Go tools on macOS
- [Threat model](docs/threat-model.md)
- [Development](docs/development.md)

## License

Either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
