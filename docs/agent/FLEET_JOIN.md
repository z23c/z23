<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Joining a computer to a fleet

This is the page an owner points an AI agent at when they want a new
computer added to their fleet. It contains no hostnames, no addresses and
no ports: everything specific to a particular fleet arrives in the token
the owner pastes.

## What you are doing

A fleet is a set of computers one owner runs. Joining one adds a **machine
record**: a signed statement that this owner admitted this computer under a
name they chose. It is an inventory entry, not a permission. It grants no
shell, no remote execution, and no authority over anything.

There are two pasted strings and three commands.

| Step | Where | Command |
|---|---|---|
| 1 | The manager computer | `z23 fleet invite --name=<name>` |
| 2 | The new computer | `z23 fleet join <token>` |
| 3 | The manager computer | `z23 fleet admit <receipt>` |

Step 1 prints step 2's command. Step 2 prints step 3's command. The owner
carries each line between the two machines by hand — nothing is sent over a
network, so no port has to be open and neither machine has to be reachable
from the other.

## The name

Every machine has one **required, unique, human name**, chosen by the owner
at step 1. It is 2 to 24 characters of `a-z`, `0-9` and interior dashes:
`studio`, `node-4`, `workshop`. It is the handle every command prints first
and every refusal names, because it is how people talk about a computer.

A machine's onion address, Noise fingerprint and ZID are a different kind
of thing. They are observed, they can rotate, and none of them is ever used
as the name.

Renaming is not supported. The name is bound inside the signature the new
computer makes over its own enrolment receipt, so nobody — including the
owner — can rewrite it in place. Pick a name you will still want later.

## Prerequisites on the new computer

You need a C23 toolchain, `git`, and enough disk for a build.

**Linux.** A recent gcc or clang, `make`, and the usual build headers.

**macOS.** Xcode command line tools (`xcode-select --install`).

**Windows.** Join from inside **WSL2 Ubuntu**, not from native Windows.
The build cross-compiles for Windows and the enrolment code compiles there,
but the supported path for running a fleet member today is WSL2: the mesh
terminal worker is POSIX-only, so a native Windows box cannot yet serve the
remote-shell side of the fleet at all. Install WSL2, open the Ubuntu shell,
and follow the Linux steps inside it.

## What the AI agent on the new computer does

```sh
git clone https://github.com/z23c/z23.git
cd z23
make -j8 build/bin/z23-dev
build/bin/z23-dev fleet join <token>
```

Then hand the printed `z23 fleet admit …` line back to the owner.

## What is in each string

**The invite token** carries the name, an expiry, a one-time random nonce,
an optional relay endpoint, the operator's Ed25519 public key, and a
signature by that key over all of it. Nothing private is in it. A leaked
token can enrol one computer under that one name, once, before it expires —
and the resulting machine still has to be admitted on the manager.

**The enrolment receipt** carries the whole invite unchanged, what the new
computer says about itself, its own new Ed25519 public key, an ssh public
key if it has the dedicated one described below, and a signature by the new
computer's key over all of it. Nothing private is in it either.

Everything a computer says about itself — hostname, OS, architecture, core
count, memory, free disk, toolchain, source commit — is **self-reported**.
The computer signed it, so it is authenticated; nobody measured it, so it is
not verified. `z23 fleet machines` keeps self-reported facts in their own
object, separate from what the operator's signature actually attests (the
name, the public key, the assigned port, the time).

## The ssh bridge

If the new computer has a **dedicated** public key at
`~/.ssh/z23_fleet.pub`, `fleet admit` adds exactly one line to the
operator's `~/.ssh/authorized_keys`:

```
restrict,port-forwarding,permitlisten="127.0.0.1:<port>" <key> z23-fleet-<name>
```

`restrict` denies everything sshd knows how to deny — no shell, no command,
no agent forwarding, no X11, no pty — and denies future restrictions by
default too. The single re-grant is one loopback listen port. The line is
added once per name; re-admitting the same computer adds nothing.

Create the key with `ssh-keygen -t ed25519 -f ~/.ssh/z23_fleet` before
joining. Use a key you use for nothing else: this line narrows exactly the
key it names, and a key you also use for shell access would be narrowed
wherever sshd matched this line first. `fleet admit --bridge=no` skips the
line entirely, and a computer with no such key simply gets a machine record
and no bridge.

The bridge needs an sshd running on the computer being reached, and
`~/.ssh` must already exist on the manager. Neither is created for you: a
fleet command guessing at an owner's ssh layout is not a thing this
repository does.

## What comes next

The bridge is a bridge. The native path is mesh pairing over the node's own
Noise transport — `ops mesh pair plan` and `ops mesh pair commit` — which
needs the new computer to be running a node with an on-chain identity
delegation. `fleet join` prints that as its `next_step` rather than
pretending it already happened. See `docs/work/SOVEREIGN_MACHINE_MESH_PLAN.md`.

## Where the state lives

Under the owner-private state root, never inside a checkout:

| File | What it is |
|---|---|
| `fleet/box.ed25519` | This computer's own key, mode 0600, created on first use |
| `fleet/operator.pub` | The operator key this computer was told to trust |
| `fleet/machines.roster` | One operator-sealed line per admitted machine |
| `fleet/invites.spent` | One line per invite nonce already used |

Every roster line is re-verified against the operator key on every read. A
line that key did not seal is counted and never listed, so editing the file
by hand can remove a machine but cannot invent one.

## Typed refusals

Each of these is the exact evidence string a refusal carries.

| Refusal | Meaning |
|---|---|
| `invite_name_invalid` | The name is not 2-24 characters of `a-z`, `0-9` and interior dashes |
| `invite_ttl_invalid` | `--ttl-hours` is outside 1 to 168 |
| `invite_relay_invalid` | `--relay` has a character a host or `host:port` cannot contain |
| `invite_malformed` | The pasted token is not a token — usually a copy that lost its tail |
| `invite_signature_invalid` | The token's bytes and its signature disagree |
| `invite_expired` | The invite's expiry has passed |
| `invite_not_ours` | The invite was minted by some other key, so this manager will not honour it |
| `invite_replayed` | That invite has already enrolled a computer |
| `invite_name_taken` | Another computer already holds that name |
| `receipt_malformed` | The pasted receipt is not a receipt |
| `box_signature_invalid` | The receipt's facts and the joining computer's signature disagree |
| `box_key_unwritable` | The state root is unreachable or the key file is not this user's alone |
| `roster_full` | Every assignable relay port is taken |
| `roster_unreadable` / `roster_unwritable` | The roster could not be read or appended to |
| `authorized_keys_unwritable` | `~/.ssh` does not exist, or the file cannot be written |
