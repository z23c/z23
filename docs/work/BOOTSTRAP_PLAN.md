# The one-line bootstrap

A stranger should be able to paste one line and have a running, verified node.

```
curl -fsSL https://z23.sh | sh          # macOS, Linux
irm https://z23.sh/install.ps1 | iex    # Windows
```

This document is the plan for that. It is a work plan, not a description of
what exists; each section says plainly which half it is.

## What already exists

`tools/scripts/install_z23.sh` fetches a packaged runtime from **any** node
URL, verifies every byte against `SHA256SUMS`, refuses loudly on a mismatch,
installs to `~/.local/bin`, writes a user service, and prints one next command.
No server is hardcoded in it. `packaging/release/build_release.sh` produces the
packaged set it consumes. Those two are the engine and they work.

## The problem with every `curl … | sh`

Whoever controls the domain controls what runs on the machine. The checksum
does not help when the checksum ships from the same server as the script, and
nobody finds out afterwards.

Our own installer already refuses a remote source unless it is handed the
expected checksum *obtained independently of the mirror*. That instinct is
right and the plan keeps it. It is made real in two steps.

### Step one — the pin comes from three places at once

The installer learns the expected release **pin** from three independent
systems: a value baked into the front-door script, a `TXT` record on the
domain, and the source repository.

The pin names two digests, not one: the `SHA256SUMS` manifest **and the
installer script itself**. Pinning the second is what stops the domain
substituting its own installer code -- without it, whoever serves the script
could simply serve a script that checks nothing.

The rule when they disagree is refusal, never a majority vote. Two answers
that differ mean a rollback, a half-finished publish, or a compromise, and
installing the more popular one hides the exact event the mechanism exists to
surface. Two agreeing answers proceed, and say out loud which source was
missing and why. Fewer than two refuse.

Two rather than all three, deliberately: `TXT` lookups are dropped by plenty
of corporate resolvers, and a minimal container often has no DNS tool at all.
Requiring all three would handed any such resolver a veto, and an installer
that fails for honest strangers is not safer -- it pushes them to a worse
install path. Two independent systems still means taking over the web server
alone cannot change what a stranger installs.

A source that answers with something that is not a pin -- a captive portal, an
error page, the unset sentinel -- counts as unreachable, never as
disagreement. The two are different events and are reported differently.

### Step two — the node checks itself against the swarm

The first thing the installed node does is ask several peers what digest the
network agrees the release carries. Agreement is reported; disagreement is
loud. This turns *trust this domain forever* into *trust it for about a
minute*, and it is only the project's existing rule applied to the install
path: every node publishes what it observed, and nobody vouches.

No other install script does this. It is a reason to prefer this one.

## Certificates — the part that silently breaks

`curl -fsSL https://…` fails hard on an expired certificate, with no warning
beforehand, and certificates last ninety days. Today the project has no
automatic renewal: `docs/BLOCK_EXPLORER_HOSTING.md` tells an operator to run
certbot by hand and wire a renewal hook. That is an external tool, a manual
step, and a ninety-day timer to an outage.

So the node renews its own certificate, in C, with no external program.

**The challenge type is forced, and the forced answer is the good one.** The
port forwarder is 443-only by design; port 80 is deliberately not forwarded, so
the usual `HTTP-01` challenge cannot work. `DNS-01` would need a registrar API,
which is an external dependency we do not take. `TLS-ALPN-01` runs entirely
over 443 — the one port already forwarded — and is answered by the TLS server
we already own. It needs no new port, no new dependency, and no new operator
step.

## The node must not become a TLS client

`lib/test/src/test_cold_join_sovereign.c` asserts that no object file this
project authors carries an undefined reference to a TLS-client or
CA-trust-store entry point. Its own words: *if a Z23 object ever carries one,
the node has become a TLS client and can be told who to trust by whoever
ships the trust store.* The CA machinery is present in the linked OpenSSL and
deliberately unreachable -- present and unreachable, not absent.

Talking to a certificate authority means being a TLS client, so those two
facts collide, and the test is the one that wins. The certificate work
therefore lives in a **separate executable**, the way the confined package
verifier already does. That program owns the conversation with the authority;
the node keeps doing what it does today, which is read a certificate and a
key from two files.

This is better than putting it in the node, not a concession. The trust
boundary ends up exactly where it belongs: on the optional clearnet
convenience surface. The paths that carry consensus -- onion and
peer-to-peer -- never touch a public authority at all.

Answering the challenge is different and stays in the node: it happens on our
own listener, uses no client or trust-store entry point, and does not touch
the property above.

## What is served, and by whom

The domain serves only small files: the two install scripts, the checksum
manifest, and a starting list of peers. Kilobytes. Any machine can serve that,
including a slow one.

The runtime itself is tens of megabytes and does **not** come from the domain.
It comes from the swarm, because the installer already accepts any node URL as
a source. A machine that runs a node adds download capacity to the bootstrap
without anyone configuring anything.

## What still needs a human, honestly

Two things cannot be hosted by the swarm and never will be:

- **The domain registration.** Once a year.
- **The initial delegation of the domain to nameservers.** Once.

Everything else — issuing the certificate, renewing it, serving the scripts,
serving the runtime, adding capacity — is the node's job.

## Order of work

1. **Certificate renewal in C** (`TLS-ALPN-01`). First, because it is the piece
   whose absence breaks the bootstrap silently and on a timer.
2. **Three-place checksum agreement** in the installer, and the small front-door
   script the domain serves.
3. **Windows and macOS**, once those builds land. Two things are in the
   way, and the second is larger than it looks. The release packager is
   x86_64-linux only, so there is nothing to package for those hosts yet.
   And the installer does not merely name three Linux binaries -- it
   writes a **systemd user service**, which has no equivalent on macOS
   (launchd) or Windows (services / scheduled tasks). Starting the node
   at login therefore needs a second and third implementation, not a
   changed filename. `deploy_z23_release.sh` is Linux-only for the same
   reason, built on `systemctl --user` and `/proc/<pid>/exe` throughout.
4. **Node self-check against the swarm.**

## Working with coding agents

The bootstrap must survive being run by a program rather than a person. That
means no prompt, no terminal required, and no step that assumes someone is
watching. A previous refusal of the form *"stop unless this is a terminal"*
crash-looped every fresh install; the rule is that a refusal names the thing it
protects, never the shape of the caller.

After installing, the node answers in typed output with stable exit codes,
which is already what an agent needs. What is missing is discovery: the release
should carry a short description of what the node offers, so an assistant that
installs it also knows what it can now do.

## Before a stranger can install anything

The mechanism is built and tested; the values it checks against do not exist
yet. Until they are published the front door refuses at the pin quorum, which
is the correct state to be in — it is not broken, it is unpinned.

Cutting the first release means publishing, together:

1. the `TXT` record `_z23-pin.z23.sh`, carrying the pin,
2. `packaging/install/RELEASE_PIN`, carrying the same pin,
3. the pin baked into the served front-door script.

All three name the same two digests: the manifest, and the installer script.
Publish them in one motion — a partial publish is precisely the disagreement
the installer is built to refuse, and it will refuse it.
