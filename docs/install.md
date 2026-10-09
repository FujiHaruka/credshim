# Installing the recommended setup

The proxy runs as a service under a dedicated OS user. The config, the secrets, and the CA private key live in `/var/lib/credshim`, which only that user can read. The developer user (the everyday OS user that runs agents and apps) can reach only `/etc/credshim`, which holds the public CA certificate and the environment variable files. This separation keeps agents from getting the real values.

| | Linux | macOS |
| --- | --- | --- |
| Service user | `credshim` | `_credshim` |
| Install path | `/usr/local/libexec/credshim/credshim` | `/Library/CredShim/bin/credshim` |
| Service | systemd `credshim.service` | launchd `dev.credshim.proxy` |
| Logs | `journalctl -u credshim` | `/var/lib/credshim/credshim.log` |

## Two sessions

This setup runs commands in two places (`$bin` and `credshim-svc` in the table below are defined in [Set the variables](#set-the-variables)).

- **Admin session.** An admin terminal reached by a path the developer user cannot touch: an admin GUI session entered by switching users, an SSH login as the admin user, or a separate console.
- **Developer session.** The terminal where everyday work and agents run.

Processes of the developer user can read what is typed into that terminal (they can plant a function that hijacks `sudo`, or a keystroke logger, in the shell config). Do not type the admin password or the real keys you register into the developer user's terminal.

| Admin session | Developer session |
| --- | --- |
| Installing and updating, adding rules, registering real keys (`credshim-svc secret set`), generating SSH keys, AWS SSO login, checking the audit log (`credshim-svc tail`) and status (`credshim-svc status`), applying changes (`sudo $bin service reload`) | Loading the environment variables (`. /etc/credshim/env`), `credshim doctor`, apps and agents |

## 1. Make the developer user a non-admin

If the developer user can sudo, or types the admin password in its terminal, an agent can become root and read the secrets.

- **macOS.** Create a separate admin account. In Users & Groups, turn off "Allow this user to administer this computer" for your everyday account to make it a standard user.
- **Linux.** Remove the developer user from the `sudo`, `wheel`, and `admin` groups.

## 2. Install (admin session)

Replace `yourname` with the developer user's name and run the following.

```sh
curl -fsSL https://raw.githubusercontent.com/FujiHaruka/credshim/4406ce71c01c11d4c495af7427f313d8932f1c61/scripts/install.sh | sudo bash -s -- --user yourname
```

To read the script before running it, download it first.

```sh
curl -fsSLO https://raw.githubusercontent.com/FujiHaruka/credshim/4406ce71c01c11d4c495af7427f313d8932f1c61/scripts/install.sh
less install.sh
sudo bash install.sh --user yourname
```

The script does the following.

1. Downloads the latest binary and `SHA256SUMS` from [Releases](https://github.com/FujiHaruka/credshim/releases) into a temporary directory that only root can read and write. The download does not go through the proxy (it runs with the proxy environment variables cleared).
2. Checks the hash and `--version`.
3. Runs that binary's `service install`, which creates the service user, the config and CA, and the service, places the binary in the install path, and starts the service.

- Pass `--user` the developer user that runs the agents, not the admin who ran sudo. Its uid is written into the SSH agent's connection allowlist.
- To pin a version, append it, as in `--user yourname 0.6.0`.
- The URL is pinned to the script's commit, so unreleased changes merged into main do not reach it.
- Where no prebuilt binary exists (Intel Macs, for example), clone the repository, build with `cargo install --locked --path crates/cli`, and run `sudo ./credshim service install --user yourname` with that binary. Keep that binary in a place the developer user cannot modify.

### Set the variables

The rest of this guide and the commands on other pages use the following variables and alias. In the admin session, run the lines for your OS.

```sh
# macOS
user=_credshim bin=/Library/CredShim/bin/credshim
# Linux
user=credshim bin=/usr/local/libexec/credshim/credshim

alias credshim-svc="sudo -u $user $bin"   # run credshim as the service user
```

credshim run as the service user reads `/var/lib/credshim/config.toml` without `--config`. Always use sudo on the installed binary `$bin` (never run a binary the developer user can modify with sudo).

## 3. Register rules and real keys (admin session)

This example uses OpenAI. For other services, see [Presets](../README.md#presets) or [write the rules yourself](configuration.md#writing-rules).

```sh
# Add the rule (the dummy key is generated at random each time)
$bin preset openai | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null

# Register the real key (typed at the terminal, never passed through command-line arguments or environment variables)
credshim-svc secret set openai

# Make the running proxy reload its config and put the new dummy in /etc/credshim/keys.env
sudo $bin service reload
```

`service reload` applies changes without dropping connections. For what applies at once and what needs a restart, see [Applying changes](configuration.md#applying-changes).

## 4. Use it (developer session)

```sh
. /etc/credshim/env                          # proxy and CA environment variables (no dummy keys)
export PATH="/Library/CredShim/bin:$PATH"    # on Linux, /usr/local/libexec/credshim
credshim doctor                              # whether curl, python, node, and others in this shell use the proxy and CA
set -a; . /etc/credshim/keys.env; set +a     # use the dummy keys in this shell

# Call with streaming ($OPENAI_API_KEY is the dummy)
curl -N https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model": "gpt-4o-mini", "stream": true, "messages": [{"role": "user", "content": "hi"}]}'
```

SDKs work as is.

```sh
uv run --with openai python -c '
import openai
for chunk in openai.OpenAI().chat.completions.create(
    model="gpt-4o-mini", stream=True, messages=[{"role": "user", "content": "hi"}]):
    print(chunk.choices[0].delta.content or "", end="", flush=True)
'
```

You can put `. /etc/credshim/env` in your shell config (`~/.zshrc` or similar). Traffic that carries no dummy passes through the proxy unchanged, so loading it in any shell does no harm.

`/etc/credshim/env` (the same as the output of `credshim env`) sets these environment variables.

| Variable | Points to |
| --- | --- |
| `HTTPS_PROXY`, `HTTP_PROXY` (and lowercase), `NO_PROXY` | The proxy |
| `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `AWS_CA_BUNDLE` | The combined bundle (one file with the development CA and the system root certificates) |
| `NODE_EXTRA_CA_CERTS` | The development CA |
| `NODE_USE_ENV_PROXY=1` | Makes Node's built-in fetch use `HTTPS_PROXY` |
| `SSH_AUTH_SOCK` | CredShim's SSH agent (only when an SSH key is registered) |

### Giving the dummy keys to a project

The dummy keys are kept separately in `/etc/credshim/keys.env` (the same as the output of `credshim env --keys`). It contains:

- For each rule with `env`, its dummy key (`OPENAI_API_KEY` and so on)
- If there is exactly one AWS rule, its dummy `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` (with two or more, the profiles to write in `~/.aws/credentials`, as comments)
- If you use base URL mode, its URL (as a comment)

Putting the dummy keys in every shell is not recommended. python-dotenv, Node's dotenv, Next.js, Vite, and others do not let .env override variables already in the shell, so a different key written in the repository's .env silently stops being used. With AWS, keys in environment variables also take precedence over `AWS_PROFILE`. Give the keys to each project in one of these ways.

- Copy only the lines you need into the project's .env (they are in `KEY='value'` form, so you can paste them as is; they are dummies, so committing them is fine)
- With direnv, `dotenv /etc/credshim/keys.env` in `.envrc`
- To use all of them in that shell, `set -a; . /etc/credshim/keys.env; set +a`

## 5. Verify the isolation (developer session)

Run the repository's `scripts/stage-b/verify.sh` as the developer user. It checks that:

- The developer user is not an admin
- It cannot read or write the config, the secrets (including the lock file), or the CA private key
- It cannot modify the service definition or the proxy binary
- It cannot write to the SSH agent's directory, and can list keys from the agent
- `AWS_CA_BUNDLE` and `SSH_AUTH_SOCK` in `/etc/credshim/env` point to public locations, and the file contains no dummy keys

## 6. Replace existing credentials

Treat any keys you had before installing CredShim as already read by an agent. Do not import them. Create new ones and revoke the old ones. `credshim doctor` reports what is left on the machine without printing the values.

- **API keys.** Create a new key with the issuer and register it with `credshim-svc secret set`. Delete the old key from .env files and shell config, then revoke it with the issuer. Recreate keys you registered in the trial setup the same way.
- **SSH.** Create a new key with `credshim-svc ssh keygen` and register the public key on the server (GitHub or similar). After `ssh -T` confirms it works, remove the old public key from the server and delete the old private key in `~/.ssh`. For the steps, see [SSH agent](ssh.md).
- **AWS static keys.** Create a new access key in IAM, register it with `credshim-svc secret set`, and rewrite `~/.aws/credentials` with the dummy. Once it works, deactivate the old key (`aws iam update-access-key --status Inactive`), then delete it.
- **AWS SSO.** Before moving to CredShim, run `aws sso logout` to revoke the cached tokens, and delete `~/.aws/sso/cache` and `~/.aws/cli/cache`. Replace the `sso_session` and `sso_start_url` profiles in `~/.aws/config` with profiles that use the dummy static keys.
- **Environment variables.** If your shell config or .env files still hold a real `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `AWS_SESSION_TOKEN`, delete it.

## Updating to a new release (admin session)

```sh
$bin service upgrade --print        # check what it will do
sudo $bin service upgrade           # to the latest release; a version can be given, as in sudo $bin service upgrade 0.6.0
```

This uses the same script as the install one-liner. If that version is already installed, it does nothing. Otherwise it replaces `$bin` with the downloaded binary and restarts the service (connections in progress are dropped). The config, secrets, and CA are kept as they are. Versions 0.5.0 and earlier have no `service upgrade`, so run the install one-liner again.

To replace it with a binary you built locally, run `sudo ./credshim service install --upgrade` with that binary.

## Uninstalling (admin session)

There is no uninstall command, so remove what the install created by hand. `/var/lib/credshim` holds the real keys and the CA private key, so delete it unless you have a reason to keep it.

```sh
# macOS
sudo launchctl bootout system/dev.credshim.proxy
sudo rm /Library/LaunchDaemons/dev.credshim.proxy.plist
sudo rm -rf /Library/CredShim /etc/credshim /var/lib/credshim /var/lib/credshim-ssh
sudo dscl . -delete /Users/_credshim
sudo dscl . -delete /Groups/_credshim
```

```sh
# Linux
sudo systemctl disable --now credshim.service
sudo rm /etc/systemd/system/credshim.service
sudo systemctl daemon-reload
sudo rm -rf /usr/local/libexec/credshim /etc/credshim /var/lib/credshim /var/lib/credshim-ssh
sudo userdel credshim
```

Also remove the `. /etc/credshim/env` line from the developer user's shell config and the dummy keys copied into project .env files. If you made the macOS keychain trust the development CA, remove that trust too ([Go tools on macOS](troubleshooting.md#go-tools-on-macos)).

## Adapting the commands to the trial setup

The steps on other pages are written for the recommended setup. To follow them in the trial setup, substitute as follows.

| Recommended setup | Trial setup |
| --- | --- |
| `credshim-svc` | `credshim` |
| `$bin preset X \| sudo -u $user tee -a /var/lib/credshim/config.toml` | `credshim preset X >> ~/.config/credshim/config.toml` |
| `/var/lib/credshim/config.toml` | `~/.config/credshim/config.toml` |
| `sudo $bin service reload` | `pkill -HUP -f 'credshim run'` (the result appears in the `credshim run` terminal) |
| `sudo $bin service install` | Restart `credshim run` |
| `. /etc/credshim/env` | `eval "$(credshim env)"` |
| `/etc/credshim/keys.env` | The output of `credshim env --keys` |
