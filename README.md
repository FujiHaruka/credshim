# CredShim

A local credential-injection proxy for developing without giving real API keys to coding agents or apps.

Documentation site: <https://fujiharuka.github.io/credshim/> ([日本語](docs/ja/README.md))

Apps and agents hold only dummy keys. Right before a request leaves for a registered destination, CredShim replaces the dummy with the real key. The real key never appears in .env, in app memory, in logs, or in the agent's context.

```text
App / agent ──(dummy key)──▶ CredShim ──(real key)──▶ api.openai.com
                              │
                              └─ stops a dummy headed to an unregistered destination with 403
```

- It is an HTTPS proxy that apps reach through `HTTPS_PROXY`, with its own development CA that apps trust through environment variables. SDKs work without modification.
- [Presets](#presets) cover OpenAI, Anthropic, Gemini, GitHub, and AWS (including IAM Identity Center). CredShim also runs as an ssh-agent and handles OAuth tokens. For other APIs, you write the rules.

## Choosing a setup

| Setup | Suited for | What it takes | Can the agent extract the real values? |
| --- | --- | --- | --- |
| [Trial setup](#trial-setup) | Seeing it work in 5 minutes | One binary, run as your everyday OS user | Yes |
| [Recommended setup](#recommended-setup) | Everyday use with real keys | The proxy runs as a dedicated service user. Your everyday OS user (the developer user, which runs agents and apps) must not be an admin, and you register keys from a separate admin account | No |
| [Container isolation](docs/container.md) | The recommended setup, plus all agent traffic goes through the proxy's checks and audit | The recommended setup, with agents in a container | No |

Prebuilt binaries exist for macOS (Apple silicon) and Linux (x86_64 and aarch64, glibc 2.35 or later). Elsewhere (such as Intel Macs), build from source with Rust.

## What it protects and what it does not

In the recommended setup, an agent cannot extract the value of a real key, even if it goes rogue or is hijacked by prompt injection.

It does not protect against the following.

- **Using the key.** The agent can send requests that use the real key through the proxy. It can send them only within the destinations, paths, operations, and counts that the rules allow. Anything else gets 403 or 429.
- **A developer user who is an admin.** The agent runs with the developer user's permissions. If that user can become root, the agent can plant something in the shell config, steal the sudo password, and read the secrets.

See the [threat model](docs/threat-model.md) for details.

## Trial setup

> **This setup does not protect against agents.** The proxy runs as the developer user, so the agent can read and write the secret store and the config. Use it only to see how it works, and recreate the keys registered here when you move to the recommended setup.

Get the binary.

```sh
v=0.8.1
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

To stop using it, stop `credshim run` and delete `~/.config/credshim`. On macOS, also delete the keychain item (`security delete-generic-password -s credshim -a openai`).

## Recommended setup

For everyday use with real keys, run the proxy as a service under a dedicated service user. The rough flow is as follows.

1. Make the developer user a non-admin
2. In an admin session, run the install one-liner to create the service user and the service
3. In an admin session, register the rules and the real keys
4. In the developer session, load the environment variables and use it

The steps are in [docs/install.md](docs/install.md). A coding agent can do most of them for you: give it the one line in [Setting up with a coding agent](docs/agent-setup.md). You run the admin commands it hands you and type the real keys.

## Presets

`credshim preset <name>` generates rules for common services. The dummy keys are generated at random each time.

| Name | Destination | Environment variable for the dummy |
| --- | --- | --- |
| `openai` | `api.openai.com` | `OPENAI_API_KEY` |
| `anthropic` | `api.anthropic.com` | `ANTHROPIC_API_KEY` |
| `gemini` | `generativelanguage.googleapis.com` | `GEMINI_API_KEY` |
| [`github`](docs/github.md) | `api.github.com` (the `gh` CLI) | `GH_TOKEN` |
| [`github-ssh`](docs/ssh.md) | `github.com` (SSH) | |
| [`aws`](docs/aws.md) | AWS services | `AWS_ACCESS_KEY_ID` and others |
| [`aws-sso`](docs/aws.md#aws-iam-identity-center-sso) | AWS services | `AWS_ACCESS_KEY_ID` and others |

For other APIs, write and register the rules yourself ([Configuration](docs/configuration.md#writing-rules)).

## Using it with coding agents

Start the agent from a shell that has loaded the proxy environment variables and the dummy keys. Commands and apps that the agent runs inherit them. In the trial setup, use the commands from [Trial setup](#trial-setup) instead.

```sh
. /etc/credshim/env                              # proxy and CA
set -a; . /etc/credshim/keys.env; set +a         # dummy keys
```

Load the dummy keys only in the shell that starts the agent, not in your shell config. A variable already in the shell wins over a project's .env, so a different key written there silently stops being used. For per-project ways, see [Giving the dummy keys to a project](docs/install.md#giving-the-dummy-keys-to-a-project).

If the agent itself calls a destination that has a rule (for example, `api.anthropic.com` with the dummy `ANTHROPIC_API_KEY`), these variables also make it trust the development CA. Traffic that contains no dummy is relayed as is.

When a request fails, CredShim's response says why and which command shows more. [Coding agents](docs/agents.md) explains how an agent reads it, and has a note to put in `AGENTS.md` or `CLAUDE.md`. `credshim docs` prints these docs for the installed version.

## Documentation

- [Installing the recommended setup](docs/install.md): install, update, uninstall, and migrating from existing credentials
- [Setting up with a coding agent](docs/agent-setup.md): the one line to give an agent, and the steps it follows
- [Configuration](docs/configuration.md): writing rules, applying changes, base URL mode, OAuth, audit log
- [AWS](docs/aws.md): static access keys and IAM Identity Center (SSO)
- [SSH agent](docs/ssh.md)
- [GitHub CLI (gh)](docs/github.md): a fine-grained token for `gh`, and replacing an existing `gh` login
- [Container isolation](docs/container.md)
- [Troubleshooting](docs/troubleshooting.md): `credshim doctor`, refused requests, Go tools on macOS
- [Coding agents](docs/agents.md): what an agent holds, what to do when a request fails, a note for the agent's instructions
- [Threat model](docs/threat-model.md)
- [Development](docs/development.md)

## License

Either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
