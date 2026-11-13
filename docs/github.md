# GitHub CLI (gh)

`git` over SSH works with the [SSH agent](ssh.md), but `gh` calls the GitHub API, which accepts only a token. The `github` preset lets the real token go only to `api.github.com` and `uploads.github.com`. `gh` holds only a dummy in `GH_TOKEN`, and the proxy replaces it with the real token on the way to GitHub.

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
| Contents | Read and write, only if needed | `gh release upload` and `gh release create` with files |
| Issues | Read and write, only if needed | `gh issue` |
| Workflows | No access | Leaving it out keeps the agent from rewriting CI definitions to read repository secrets |

`--attach` on `gh pr create`, `gh pr edit`, `gh pr comment`, and the `gh issue` commands (gh 2.99.0 and later) uploads the files to `uploads.github.com` and needs write access to the repository.

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

On macOS, if this fails with a certificate error, make `gh` trust the development CA as in [Go tools on macOS](troubleshooting.md#go-tools-on-macos) (`gh` is a Go program).

## Replacing an existing gh login

`gh auth login` stores its token in `~/.config/gh/hosts.yml` or in the system keyring, where an agent running as the developer user can read it. `credshim doctor` reports both (`files`). Remove it; `gh` refuses to log out while `GH_TOKEN` is set, so clear it for the command:

```sh
env -u GH_TOKEN -u GITHUB_TOKEN gh auth logout --hostname github.com
```

Then revoke the old token on GitHub: Settings → Applications → Authorized OAuth Apps → GitHub CLI for a `gh auth login` token, or Settings → Developer settings → Personal access tokens for a token you created. Also delete any real `GH_TOKEN` or `GITHUB_TOKEN` from shell config and .env files.

## Updating an older github rule

A `github` rule from an older `credshim preset github` has a dummy that starts with `credshim-github-` and no `extra_hosts`. With it, `--attach` fails: GitHub answers 401 because the upload to `uploads.github.com` keeps the dummy, and gh 2.99.0 to 2.103.1 also refuse before sending, with `unsupported authentication type`, because they attach files only with a token that starts with `gho_`, `ghp_`, or `github_pat_`. The new dummy starts with `github_pat_credshim_`, which those versions accept and which does not have the shape of a real fine-grained token.

After [updating CredShim](install.md#updating-to-a-new-release-admin-session) to a release that has `extra_hosts`, replace the rule in the admin session. The stored token stays.

```sh
sudo -u $user vi /var/lib/credshim/config.toml   # delete the [[rule]] whose name is "github"
$bin preset github | sudo -u $user tee -a /var/lib/credshim/config.toml >/dev/null
sudo $bin service reload
```

The dummy changes, so load `/etc/credshim/keys.env` again in the developer session, and replace any copy of the old `GH_TOKEN` in a project's `.env`.

## What the preset allows

- Methods `GET`, `POST`, `PATCH`, `PUT`, and `DELETE`, which merging, editing, and deleting a branch need.
- Paths `/graphql`, `/repos`, `/user`, `/users`, `/orgs`, `/search`, `/notifications`, `/gists`, `/rate_limit`, `/licenses`, `/gitignore`, and `/user-attachments`. Most `gh` commands go through `/graphql`, so paths narrow little. The token's repositories and permissions are the real limit.
- Hosts `api.github.com` and `uploads.github.com`, with the same methods and paths on both. `uploads.github.com` takes the files of `--attach` (`/user-attachments`) and of `gh release upload` (`/repos`). Anywhere else the dummy is not replaced, so GitHub answers 401. `git` over HTTPS is not covered; use SSH.
- For GitHub Enterprise Server, write the rule yourself with your server's host ([Writing rules](configuration.md#writing-rules)).
