# Coding agents

This page is for a coding agent that runs behind CredShim, and for the person who sets it up. It covers what the agent holds, how to tell what happened when a request fails, how to propose a change to the configuration, and a short note to put in the agent's instructions.

## What the agent holds

The API keys, AWS access keys, and SSH agent that the agent sees are CredShim's. The keys are dummies; most contain `credshim` (for example, `sk-credshim-openai-...`). CredShim swaps in the real key only for the destinations, paths, and operations that its rules allow. In the recommended setup, the real values are out of the agent's reach, so there is nothing to find by searching files or the environment.

Every CredShim failure says how to see more. A response that CredShim refused gives the reason and the commands to run, `credshim doctor` lists the docs for each failed check, and every CLI error and `--help` ends with a `credshim docs` command. `credshim docs` prints the docs of the installed version without network access or any config.

## When a request fails

Go down this list and stop at the first case that fits.

1. **The response has a `credshim-error` header, or the body starts with `credshim:`.** CredShim stopped the request and sent nothing upstream. The first line is the reason. `docs:` is the command that explains this kind of refusal (`credshim docs troubleshooting#<kind>`), and `details:` is the command that prints the request's whole audit log entry. In the recommended setup `details:` needs the admin (it starts with `sudo -u`), so pass that line to the person instead of running it. For `limited`, do not retry in a loop. For `deny` and `not_allowed`, do not work around it by calling another host or using another key; if the request should be allowed, ask the person to change the rule. AWS SDKs and the aws CLI show the same text as the message of a `CredShim...` error code.
2. **The API itself answered with an error (401, 403, and so on), and the response has `credshim-request-id` but no `credshim-error`.** The request went through CredShim and the upstream refused it. Ask the person to look up the id with the `tail --id` command: `inject` means the real key was sent, so the problem is the key's permissions or the request itself; `pass` means CredShim found no dummy where the rule expects it (for example, the key went in a different header).
3. **A 401 that says the key is invalid, and no `credshim-request-id`.** CredShim did not inspect the request. Either the tool bypassed the proxy (it ignores `HTTPS_PROXY`, or the environment variables are not loaded in this shell; run `credshim doctor`), or the host has no rule, so the dummy went through as is (ask the person to check the rule's `host` and `port`).
4. **A TLS certificate error for a host that has a rule.** The tool does not trust the development CA. Run `credshim doctor`; for Go tools on macOS, see `credshim docs troubleshooting#go-tools-on-macos`.
5. **SSH says `agent refused operation`.** The CredShim agent refused to sign for that host or user. See `credshim docs ssh`.

## Changing the configuration

In the recommended setup the agent can read neither the config nor the secrets, and a real key must never pass through it. When a task needs a new rule, a wider allowlist, or another key, the agent prepares the change and a person applies it. Leave it to the person in the trial setup too, even though the agent could edit the config there.

1. Write the sections to add in a file of your own. `credshim preset <name>` prints a ready-made rule for common APIs; for others, see `credshim docs configuration#writing-rules`.
2. Run `credshim config check <file>` and fix every problem it lists. Each comes with the docs section to read.
3. Give the person the draft's path and the steps that `config check` printed. The person copies the draft to a file you cannot change, runs `config check` on that copy, and reads the table of where each real key goes from their own terminal before adding the copy (the commands are in `credshim docs agent-setup#4-hand-over`). Some of the steps, such as `secret set` and `aws sso login`, are for a person at a terminal: do not pipe a value into them or fake a terminal.

## A note for the agent's instructions

Put this in the project's `AGENTS.md` or `CLAUDE.md` (or the agent's own instructions).

```markdown
## Credentials (CredShim)

API keys in this environment are CredShim dummies. CredShim swaps in the real key only for
the destinations its rules allow; do not look for real keys or work around a refusal.

- A response with a `credshim-error` header or a body starting with `credshim:` was refused
  by CredShim. Read its first line, run its `docs:` command, and do not retry a `limited`
  refusal in a loop. If its `details:` command starts with `sudo`, ask me to run it.
- When a tool cannot connect or gets a certificate error, run `credshim doctor`.
- To change CredShim's rules, write a draft, check it with `credshim config check <file>`,
  and give me the draft and the steps it prints.
- `credshim docs` prints the CredShim docs for this version.
```
