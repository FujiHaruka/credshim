# GitHub CLI (gh)

`git` over SSH works with the [SSH agent](ssh.md), but `gh` calls the GitHub API, which accepts only a token. The `github` preset binds a token to `api.github.com`. `gh` holds only a dummy in `GH_TOKEN`, and the proxy replaces it with the real token on the way to GitHub.

The commands on this page are written for the recommended setup, and `$user`, `$bin`, and `credshim-svc` are [the install variables](install.md#set-the-variables). For the trial setup, read them as described in [adapting the commands to the trial setup](install.md#adapting-the-commands-to-the-trial-setup).

## Creating the token

A normal `gh auth login` issues a token that can read and write every repository you can reach. Create a fine-grained personal access token instead (GitHub: Settings → Developer settings → Personal access tokens → Fine-grained tokens), and narrow it.

- **Resource owner.** One token covers repositories of a single owner: your account or one organization. An organization may require its admins to approve the token.
- **Repository access.** Only select repositories.
- **Expiration.** Set one.
- **Permissions.** For an agent that opens and updates pull requests:

| Permission | Access | Used for |
| --- | --- | --- |
| Metadata | Read | Required by GitHub |
| Pull requests | Read and write | Creating, editing, and commenting on pull requests |
| Contents | Read (Read and write to merge) | Reading files and merging. Pushes go over SSH, so they do not need it |
| Actions | Read | `gh pr checks`, `gh run view`, and `gh run watch` |
| Issues | Read and write, only if needed | `gh issue` |
| Workflows | No access | Leaving it out keeps the agent from rewriting CI definitions to read repository secrets |

When a command needs a permission the token lacks, GitHub answers 403 with the missing permission; add it to the token on GitHub.

## Registering it (admin session)

```sh
$bin preset github | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null
credshim-svc secret set github               # paste the token
sudo $bin service reload
```

In the developer session, `/etc/credshim/keys.env` now has `GH_TOKEN` with the dummy. `gh` uses `GH_TOKEN` before any stored login. `gh auth status` also calls the API root, which the preset does not allow, so check with `gh api`.

```sh
set -a; . /etc/credshim/keys.env; set +a
gh api user --jq .login
```

## Replacing an existing gh login

`gh auth login` stores its token in `~/.config/gh/hosts.yml` or in the system keyring, where an agent running as the developer user can read it. `credshim doctor` reports both (`files`). Remove it; `gh` refuses to log out while `GH_TOKEN` is set, so clear it for the command:

```sh
env -u GH_TOKEN -u GITHUB_TOKEN gh auth logout --hostname github.com
```

Then revoke the old token on GitHub: Settings → Applications → Authorized OAuth Apps → GitHub CLI for a `gh auth login` token, or Settings → Developer settings → Personal access tokens for a token you created. Also delete any real `GH_TOKEN` or `GITHUB_TOKEN` from shell config and .env files.

## What the preset allows

- Methods `GET`, `POST`, `PATCH`, `PUT`, and `DELETE`, which merging, editing, and deleting a branch need.
- Paths `/graphql`, `/repos`, `/user`, `/users`, `/orgs`, `/search`, `/notifications`, `/gists`, `/rate_limit`, `/licenses`, and `/gitignore`. Most `gh` commands go through `/graphql`, so paths narrow little. The token's repositories and permissions are the real limit.
- Only `api.github.com`. Anywhere else the dummy is not replaced, so GitHub answers 401. This includes `uploads.github.com`, so `gh release upload` and `gh release create` with files fail; publish releases from CI instead. `git` over HTTPS is not covered either; use SSH.
- For GitHub Enterprise Server, write the rule yourself with your server's host ([Writing rules](configuration.md#writing-rules)).

`gh` is a Go program. On macOS, see [Go tools on macOS](troubleshooting.md#go-tools-on-macos) for making it trust the development CA.
