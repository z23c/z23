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

### Step one — the checksum comes from three places at once

The installer learns the expected `SHA256SUMS` digest from:

1. a value baked into the install script,
2. a `TXT` record on the domain,
3. the source repository.

All three must agree or the install refuses. These are three different systems
with three different operators. Taking over the web server is no longer enough
to change what a stranger installs.

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
3. **Windows and macOS**, once those builds land. The release packager is
   x86_64-linux only today, so Linux ships first.
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
