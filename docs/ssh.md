# SSH agent

CredShim also runs as an ssh-agent. It generates keys inside the proxy and keeps them only in the secret store. Only the public key leaves it. It does not create private key files in `~/.ssh`.

It signs only for a login that meets all of the following conditions.

- `ssh` is OpenSSH 8.9 or later and sends information that proves which server it connects to (session-bind)
- The fingerprint of that server's host key is in `host_keys` in the config
- The login user name is in `users` in the config

It rejects requests from hosts reached through `ssh -A` forwarding, `ssh-keygen -Y sign` (commit signing and the like), and adding or removing keys.

The commands on this page are written for the recommended setup, and `$user`, `$bin`, and `credshim-svc` are [the install variables](install.md#set-the-variables). For the trial setup, read them as described in [adapting the commands to the trial setup](install.md#adapting-the-commands-to-the-trial-setup).

## Using it with GitHub

```sh
# admin session
$bin preset github-ssh | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null   # GitHub's three host keys, user git
credshim-svc ssh keygen ssh-github           # register the printed public key on GitHub
sudo $bin service install --user yourname    # SSH settings apply on restart. yourname is the developer user

# developer session
. /etc/credshim/env                          # also sets SSH_AUTH_SOCK=/var/lib/credshim-ssh/agent.sock
ssh -T git@github.com
```

It does not import existing keys from `~/.ssh`. Switch to a new key and remove the old key from the server ([Replace existing credentials](install.md#6-replace-existing-credentials)).

## Configuration

```toml
[ssh]
socket = "/var/lib/credshim-ssh/agent.sock"
client_uids = [501]          # uids it accepts connections from. If omitted, only the proxy's own uid

[[ssh_key]]
name = "github"
secret = "ssh-github"        # the name passed to credshim-svc ssh keygen
users = ["git"]
host_keys = ["SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"]
limits = { per_minute = 30, per_day = 500 }   # limit on the number of signatures (unlimited if omitted)
```

- It rejects signing requests over the limit and records them in the audit log with `reason="limited"`.
- The agent checks the uid of the connecting client and closes a connection from a uid not in `client_uids` at once. `service install` writes the `--user` uid into `client_uids` when it creates a new config. If the config already exists, it prints the line to add.
- The socket directory `/var/lib/credshim-ssh` is owned by the service user, and the developer user cannot write to it.
- If you go through a bastion host with ProxyJump, also add the bastion's host key fingerprint to `host_keys`.
- After you change `[ssh]` or `[[ssh_key]]`, restart with `sudo $bin service install --user yourname` (`service reload` does not apply them).
