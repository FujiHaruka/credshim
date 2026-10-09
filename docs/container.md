# Container isolation

Put the agent and apps in a container such as a devcontainer, and run the proxy on the host as the service user, as in the [recommended setup](install.md). If you limit the container's outbound traffic to the proxy alone, all traffic goes through the proxy's checks and audit, including direct connections to SSO OIDC and the portal.

> The SSH setup ("SSH" below) has not been checked by hand yet. What is written here is a starting point.

## Making the proxy reachable from containers

By default the proxy listens only on loopback (`127.0.0.1`). To listen on an address that containers can reach, change the config and restart with `sudo $bin service install` (`$bin` is one of [the install variables](install.md#set-the-variables)).

```toml
[listen]
addr = "172.17.0.1:8787"      # host side of the docker bridge. 0.0.0.0 is always rejected
allow_non_loopback = true
```

## AWS

Pass the proxy, the combined bundle, and the dummy keys to `aws` in the container.

```sh
docker run --rm \
  -e HTTPS_PROXY=http://172.17.0.1:8787 -e HTTP_PROXY=http://172.17.0.1:8787 \
  -e AWS_CA_BUNDLE=/credshim/bundle.pem -v /etc/credshim/bundle.pem:/credshim/bundle.pem:ro \
  -e AWS_ACCESS_KEY_ID=CREDSHIMAWS... -e AWS_SECRET_ACCESS_KEY=credshim-dummy -e AWS_REGION=ap-northeast-1 \
  amazon/aws-cli sts get-caller-identity
```

## SSH

Mount the SSH agent socket into the container, and send connections to port 22 out through the proxy's CONNECT. The proxy relays a CONNECT to a host that has no rule as plain TCP without looking at the contents, and records it in the audit log as `tunnel`.

The agent checks the uid of the connecting client.

- **Docker on Linux (without user namespaces).** A uid inside the container is the same uid on the host. Run the container with the developer user's uid (`--user "$(id -u)"`), or add the container's uid to `client_uids`. OpenSSH does not run under a uid that has no password entry, so create a user with that uid in the image.
- **Docker Desktop (macOS).** You cannot pass a host Unix socket through a bind mount, so use `/run/host-services/ssh-auth.sock`, which relays the host's agent into the container.

```sh
docker run --rm --user "$(id -u)" \
  -v /var/lib/credshim-ssh/agent.sock:/credshim/agent.sock -e SSH_AUTH_SOCK=/credshim/agent.sock \
  -v "$PWD/ssh_config:/etc/ssh/ssh_config.d/credshim.conf:ro" \
  your-dev-image git clone git@github.com:you/repo.git
```

```text
# ssh_config (example with OpenBSD nc. With socat: ProxyCommand socat - PROXY:172.17.0.1:%h:%p,proxyport=8787)
Host github.com
  ProxyCommand nc -X connect -x 172.17.0.1:8787 %h %p
```
