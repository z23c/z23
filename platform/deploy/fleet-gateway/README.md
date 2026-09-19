<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Fleet gateway hosting seam

A hosted AI client (a Claude custom connector on web, desktop, or mobile)
cannot reach a shell, an onion address, or the node's operator-private API.
This directory is the minimal hosting seam that makes the existing
`z23-fleet-gateway` reachable over public HTTPS without changing who
enforces what:

```text
public HTTPS (:443) -> zcl-portfwd (the one capability-holding forwarder)
-> loopback :<front-port> build/bin/zcl-fleet-front (TLS terminates, bytes
preserved, ONE path decision) -> either
   loopback :<gw-port> z23-fleet-gateway (frozen /steer, Streamable HTTP)
     -> build/bin/z23 (node grant authority: scope, expiry, revocation per call)
   or loopback :8443 the node's own HTTPS site (every path the gateway
     does not own; it keeps every route it has today)
```

The front is `tools/zcl_fleet_front.c`: one persistent listen socket (no
rebind gap), fork-per-connection capped at 16 concurrent children, 64 KiB
streaming relay buffers (memory never grows with body size), TLS 1.2 floor
on system OpenSSL, reseeded RNG per child, SIGPIPE ignored, loopback-only
gateway leg, and no traffic or credential logging — one startup line only.
It is built with plain `cc` like `tools/zcl_portfwd.c`, with no Makefile
target and no new packages.

The front also decides, per connection, which backend gets it. That decision
is why the surface can live on the apex at all: a hosted AI client fetches
port 443 and nothing else, so a gateway published on a high port is not
"inconvenient", it is unreachable, and the failure it shows the owner is an
opaque connect timeout. The gateway owns `/steer`, `/oauth/*` and the OAuth
well-knowns; the node site keeps every other path it has today; neither one
moved.

The gateway file is `tools/fleet_gateway.c` (CONTRACT header); this seam only
hosts it. Owner minting stays in `fleet.steer.grant`, outside AI-callable
tools. Nothing here logs a credential, grants an authority, or bypasses one.

## Endpoints (after the owner deploy below)

`<base>` is the value of `FLEET_GW_ISSUER`. On the apex deploy that is
`https://<public-host>` with NO port: every URL a hosted client is told to
fetch has to be one its fetcher will actually open, and 443 is the only
port it opens.

| Surface | URL |
|---|---|
| Server URL (Streamable HTTP POST) | `<base>/steer` |
| Protected-resource discovery (RFC 9728) | `<base>/.well-known/oauth-protected-resource` (and `…/steer`) |
| Authorization-server discovery (RFC 8414) | `<base>/.well-known/oauth-authorization-server` |
| Dynamic client registration (RFC 7591) | `<base>/oauth/register` |
| Authorize (owner approval + PKCE S256) | `<base>/oauth/authorize` |
| Token exchange (form-encoded) | `<base>/oauth/token` |
| Readiness (loopback only, never proxied) | `http://127.0.0.1:<gw-port>/healthz` |

initialize, tools/list and ping need no credential. A tools/call
with no credential is answered `401 Unauthorized` with
`WWW-Authenticate: Bearer … resource_metadata="<base>/.well-known/oauth-protected-resource", scope="brief send evidence"`
around the typed `-32001` body. That transport-level 401 is what makes a
hosted client show its **Connect** step; a 200 carrying the same error
would reach the model as a failed call and no sign-in would start.

## Connecting a Claude custom connector (owner, after deploy)

Requirements (Claude Help Center, custom connectors): a plan that allows
custom connectors (on Pro/Max the user adds their own; on Team/Enterprise
only an Owner can); the server reachable from the public internet from
Anthropic's egress range `160.79.104.0/21`; OAuth with DCR and PKCE S256;
the hosted-surface redirect URI Claude documents on claude.ai, which must be
named in `FLEET_GW_REDIRECT_ALLOW` before the connector can register;
discovery, registration and token answers inside 10 s.

1. In Claude on the web: **Customize → Connectors → Add custom connector**.
   Name it, set the URL to `<base>/steer`, leave the advanced OAuth fields
   empty (DCR registers the client).
2. A connector added there is available in the mobile apps on the same
   account; enable it in a conversation from the tools menu.
3. Ask Claude for the fleet brief. The first protected call shows
   **Connect**; the approval page on `<base>` asks for the owner key
   (`FLEET_GW_OWNER_KEY`). Only the owner types it; the page names the
   scopes and the redirect target before approval.
4. Claude retries the call with the issued token: `steer_brief`, then
   `steer_send` / `steer_evidence` for the round-trip in
   [EXTERNAL_ACCEPTANCE.md](./EXTERNAL_ACCEPTANCE.md).

An issued token is a scoped steer grant with no refresh token and **no
expiry**: owner rule of 2026-09-19, an approved connector keeps working
until it is revoked (`tools/fleet_gateway.c`, `gw_oauth_mint`, mints with
`ttl_seconds:0`). This page used to say "a 24 h scoped steer grant", which
no code had ever done; the rule is the contract, so the sentence is
corrected rather than the mint. Revocation is therefore the whole lifecycle,
which is why it has to be inspectable:

```bash
z23 fleet steer grant --action=list            # what exists, and its state
z23 fleet steer grant --action=revoke --id=<32-hex>
```

`list` prints one row per grant — an 8-character id prefix, label, scopes,
created, expires, revoked, state — and never a whole id, so the listing is
not itself a credential file. `revoke` still needs the full 32-character id
that `mint` returned.

After a grant is revoked, calls return the node's typed refusal as tool
content; reconnect the connector to sign in again.

## Owner deploy (owner-authorized; agents never run this unasked)

The front binds a HIGH loopback port and needs no capability. Public 443 is
mapped onto it by `zcl-portfwd`, the single binary that already carries
`cap_net_bind_service` (`docs/BLOCK_EXPLORER_HOSTING.md`), so putting the
steering surface on the apex adds no new privilege anywhere. The node site keeps
binding 8443 exactly as before and is now reached THROUGH the front.
Deployment is an explicit owner act and stays one:

```bash
# 0. Exact position: a clean checkout at the QUALIFIED sha (see below).
git fetch origin main
git rev-parse HEAD   # must equal the qualified SHA, tracked tree clean

# 1. Build the exact images.
devbuild --wait make z23 fleet-gateway
cc -O2 -Wall -Wextra -Werror -std=c2x -o build/bin/zcl-fleet-front tools/zcl_fleet_front.c -lssl -lcrypto
sha256sum build/bin/z23 build/bin/z23-fleet-gateway build/bin/zcl-fleet-front   # must equal the qual report

# 2. Owner-private config (outside the repo; never committed, never logged).
mkdir -p ~/.config/z23-fleet-gateway
cat > ~/.config/z23-fleet-gateway/<gw-port>.env <<ENV
FLEET_GW_ISSUER=https://<public-host>:<front-port>
FLEET_GW_OWNER_KEY=<owner approval secret>
FLEET_GW_NODE=<checkout>/build/bin/z23
# Which https callbacks a registered client may be sent back to. REQUIRED
# for any hosted client: registration is anonymous, so without this only
# loopback redirects can be registered at all. Space- or comma-separated
# origins (or origin+path prefixes); a match must end at the origin or a
# path boundary, so "https://a.test" never admits "https://a.test.evil".
FLEET_GW_REDIRECT_ALLOW=https://claude.ai https://<other hosted callback>
# Optional bounds (defaults shown): per-socket read/write deadline, and the
# hard concurrent-connection-child cap.
# FLEET_GW_IO_TIMEOUT_MS=10000
# FLEET_GW_MAX_CHILDREN=64
ENV
cat > ~/.config/z23-fleet-gateway/front-<front-port>.env <<ENV
# '*' listens on every address; the unit default binds loopback only,
# which is right for qualification and unreachable for a hosted client.
FRONT_HOST=*
GW_PORT=<gw-port>
FRONT_CERT=<path to the public certificate chain for <public-host>>
FRONT_KEY=<path to its private key>
# Apex deploy: the node HTTPS site that answers every non-gateway path.
# Omit it and this front serves the gateway alone, exactly as it always did.
FRONT_SITE=127.0.0.1:8443
ENV
chmod 600 ~/.config/z23-fleet-gateway/*.env

# 3. Install and start (user units, no sudo). Both ExecStart lines name
#    %h/github/zclassic23; a checkout elsewhere overrides them with
#    `systemctl --user edit <unit>`.
mkdir -p ~/.config/systemd/user
install -m 644 platform/deploy/fleet-gateway/'z23-fleet-gateway@.service' ~/.config/systemd/user/
install -m 644 platform/deploy/fleet-gateway/'z23-fleet-gateway-front@.service' ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now 'z23-fleet-gateway@<gw-port>'
systemctl --user enable --now 'z23-fleet-gateway-front@<front-port>'

# 4. Apex only: point the capability-holding forwarder at the front instead
#    of straight at the node, so public 443 lands on the path router. The
#    node site is unchanged; it is now reached through the front.
mkdir -p ~/.config/systemd/user/zcl-portfwd.service.d
cat > ~/.config/systemd/user/zcl-portfwd.service.d/10-front.conf <<CONF
[Service]
ExecStart=
ExecStart=%h/.local/bin/zcl-portfwd 443:<front-port>
CONF
systemctl --user daemon-reload && systemctl --user restart zcl-portfwd

# 5. Allow inbound TCP/443 (at least from the hosted client's egress range).
# 6. Verify from OUTSIDE this box with a real (non -k) TLS client: the two
#    discovery docs, an unauthenticated tools/call answering 401 with the
#    challenge, a DCR registration, AND an ordinary site page — that last
#    one is what proves the apex move cost the node site nothing.
```

## Qualification (before any deploy)

`tools/scripts/qualify_fleet_gateway_front.sh` builds the target SHA in an
isolated scratch worktree (never the invoking checkout), then proves,
through a throwaway-cert TLS front on loopback: discovery, `initialize` /
`tools.list` / `tools.call`, full OAuth DCR/PKCE/token exchange,
`steer_brief` / `steer_send` / `steer_evidence`, missing / conflicting /
unknown / wrong-scope / revoked credential refusals (including the 401
challenge), restart persistence, oversize-body bounds, exact running-image
identity, and a clean credential-log scan. The throwaway certificate proves
the seam only; it is not acceptance by a hosted client. It qualifies the SHA
it is given and nothing else, and must run from a clean tracked tree:

```bash
bash -c 'set -o pipefail; devbuild --wait bash tools/scripts/qualify_fleet_gateway_front.sh --sha <40-hex> 2>&1 | tee <log>; echo "HARNESS-EXIT=${PIPESTATUS[0]}"'
```

A stale candidate is never deployed: the script refuses a dirty closure, a
SHA mismatch, and a reused node image, and the deploy step above re-checks
HEAD and image hashes.

## Bounds and refusals (what the seam guarantees by construction)

- Front children are capped and the cap cannot grow with load: 16 for a
  gateway-only front, 128 when a site backend makes it the apex (one browser
  opens six connections, so 16 there would be a capacity ceiling rather than
  a safety bound), `FRONT_MAX_CHILDREN` to override up to a hard 512. Over
  the cap a connection is refused at once and waits in the kernel backlog.
- 120 s idle budget per front connection; handshakes covered by 120 s socket
  timeouts; stale half-close signals exit instead of spinning.
- 64 KiB streaming relay buffers: front memory never grows with body size.
- Gateway caps: 64 KiB headers, 1 MiB bodies, 4 MiB replies; oversize
  bodies are refused before the node is forked. Every accepted socket
  carries a 10 s read AND write deadline (`FLEET_GW_IO_TIMEOUT_MS`) and the
  listener refuses past 64 concurrent connection children
  (`FLEET_GW_MAX_CHILDREN`, hard maximum 512): a half-open connection costs
  one timeout, not a child held for as long as the peer likes. Request
  heads are read in 4 KiB refills rather than one `read(2)` per byte.
- The owner approval POST needs a single-use nonce minted by the approval
  GET and bound to that exact request, and an `Origin` or `Referer` naming
  `FLEET_GW_ISSUER`; owner-key failures spend a persistent, fail-closed
  window (5 per 15 min). Registration is bounded the same way (20 per hour)
  and the client store is capped at 2048 rows / 256 KiB.
- A tool call's input reaches the node on **stdin** (`--input=-`), never in
  an argv string: `/proc/<pid>/cmdline` is world-readable, so a bearer on
  argv would be readable by every local account for the life of the call.
- Missing credential → `-32001 grant required`; two differing credentials →
  `-32002 conflicting grants`; unknown → `STEER_GRANT_UNKNOWN`; wrong scope →
  `STEER_GRANT_SCOPE`; revoked → `STEER_GRANT_REVOKED` — all before or by the
  node, never by the front, and the front logs none of them.
- `GET /steer` → 405. `/healthz` is loopback-only and is never proxied.
- The front routes to the gateway on `/steer`, `/oauth/`, and the
  `oauth-protected-resource` / `oauth-authorization-server` /
  `openid-configuration` well-knowns — prefix match on a path-segment
  boundary, so `/steerage` stays the site's. Every other path is the node's
  site. The front reads at most 8 KiB of request head to decide and forwards
  those bytes VERBATIM, Host and all: it still rewrites nothing.
- Revoking a grant kills the credential and best-effort cancels the queued
  work it sent (reply carries the `cancelled` count); completed history is
  never rewritten and stays readable under a fresh grant.
