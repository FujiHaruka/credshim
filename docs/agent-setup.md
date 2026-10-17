# Setting up with a coding agent

A coding agent can do most of the work of setting up CredShim: it finds which APIs and credentials your projects use, writes the configuration, checks it, and verifies the result. You keep the parts the agent must not do: anything that needs admin rights, typing the real keys, and checking where each key is allowed to go.

## For the person

Give the agent this one line, in the developer user's session where it normally works:

```text
Set up CredShim on this machine by following https://fujiharuka.github.io/credshim/en/agent-setup.md
```

The agent asks you one combined question, then hands you a short list of commands to run in the admin session (see [Two sessions](install.md#two-sessions)). Before you run them:

- Read the "Where it lets each real key go" table. A line marked `!!` names a destination that does not come from a preset. Confirm with the service's own documentation that the host, or the SSH host keys, really belong to it. A wrong host here sends a real key to that host.
- Create new keys with each service for `secret set`. Keys that were on this machine before should be treated as already read by an agent (see [Replace existing credentials](install.md#6-replace-existing-credentials)).

## For the agent

You are working as the developer user. Follow the steps in order. Show the person your findings and your plan, and do not skip the review in step 4.

### Rules

- Never read, print, copy, or ask for the value of a real key. When you look for credentials, collect names and file paths only.
- Do not run `sudo` or anything that needs admin rights. Give those commands to the person.
- Do not register existing keys. The person creates new ones.
- Do not apply the configuration yourself, even where you could, as in the trial setup. The person applies it after reviewing where each key goes.
- When a command fails, read the `docs:` line it prints and run that command.

### 1. Survey

Collect the following without changing anything:

- The OS and architecture (`uname -sm`), the developer user (`id -un`), and whether it can administer the machine: `id -Gn` lists `sudo`, `wheel`, or `admin`, or `sudo -n true` succeeds. In the recommended setup it must not, and the person fixes that first.
- Whether CredShim is installed: `/usr/local/libexec/credshim/credshim --version` on Linux, `/Library/CredShim/bin/credshim --version` on macOS.
- The APIs the projects call: SDKs in the dependency files (for example `openai`, `anthropic` or `@anthropic-ai/sdk`, `@google/genai`, `boto3` or `@aws-sdk/*`), base URLs in the code, and the paths the code calls.
- The names of credentials in use, without values. For example, `env | cut -d= -f1 | grep -E '_(KEY|TOKEN|SECRET|PASSWORD)$'`, and `grep -ohE '^[A-Za-z_]+_(KEY|TOKEN|SECRET|PASSWORD)=' .env*` in each project.
- AWS profile names (`grep '^\[' ~/.aws/config`) and whether they use SSO. Git remotes that use SSH (`git remote -v`). Whether `gh` is logged in: `grep -E '^[^ #]' ~/.config/gh/hosts.yml` lists the hosts (the file can hold a real token, so do not read the rest, and do not run `gh auth token`).

To draft and check the configuration before CredShim is installed, download the release binary as in the [trial setup](../README.md#trial-setup) into a directory of your own (for example `~/.cache/credshim-setup`), not onto `PATH`. Use it only for `docs`, `preset`, and `config check`. If CredShim is already installed, use the installed binary.

### 2. Ask once

Summarize what you found in a table: each service, the preset or hand-written rule you propose, and the evidence (a dependency, a variable name, a remote). Then ask the person one question that covers everything:

- Which services to put behind CredShim, and which to leave out.
- For a service without a preset, its API host and the paths the projects need.
- The developer user's name, if it is not the account you run as.

The presets are `openai`, `anthropic`, `gemini`, `github` (the `gh` CLI), `github-ssh`, `aws`, and `aws-sso` (`credshim preset --help`).

### 3. Draft and check

Write the rules into a file of your own, for example `draft.toml`. Use `credshim preset <name>` for presets and write the others by hand (`credshim docs configuration#writing-rules`). Keep `allow_methods` and `allow_paths` to what the projects use. Then run:

```sh
credshim config check draft.toml
```

Fix every problem it lists until it reports a valid config.

### 4. Hand over

The commands that `config check` prints follow the binary that ran it. Only the installed binary prints them in the form for the admin session (`sudo -u $user $bin ...`), so hand over its output, not the downloaded one's.

1. If the developer user can administer the machine, or CredShim is not installed, first give the person [step 1 of the installation](install.md#1-make-the-developer-user-a-non-admin) as needed and the install one-liner from [step 2](install.md#2-install-admin-session), with `--user` set to the developer user. Wait until they say it is installed.
2. Run `config check` on the draft again with the installed binary (`$bin` in [the install variables](install.md#set-the-variables)).
3. Give the person one message with: the "Where it lets each real key go" table from that run and a request to confirm every line marked `!!`; the command that adds the draft to the config in the admin session, `sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null < draft.toml` (`$user` is the service user); and the steps that run printed after that (the `secret set`, `ssh keygen`, and `aws sso login` commands, and the reload).

Then wait until the person says they are done.

### 5. Verify

In the developer user's session:

```sh
. /etc/credshim/env
export PATH="/Library/CredShim/bin:$PATH"    # on Linux, /usr/local/libexec/credshim
credshim verify    # the developer user cannot reach the real keys, and the proxy refuses what it must
credshim doctor    # the tools in this shell go through the proxy and trust its CA
```

For each failure, run the `credshim docs` command it points to, and give the person any fix that needs admin rights.

### 6. Finish

- Give the projects the dummy keys ([Giving the dummy keys to a project](install.md#giving-the-dummy-keys-to-a-project)).
- Add [the note for the agent's instructions](agents.md#a-note-for-the-agents-instructions) to the project's `AGENTS.md` or `CLAUDE.md`.
- Give the person the old credentials that `credshim doctor` still finds on the machine, so they can revoke them ([Replace existing credentials](install.md#6-replace-existing-credentials)).
