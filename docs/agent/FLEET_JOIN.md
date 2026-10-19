<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Joining a computer to a fleet

This is the page an owner points an AI agent at when they want a new
computer added to their fleet. It contains no hostnames, no addresses and
no ports: everything specific to a particular fleet arrives in the token
the owner pastes.

## Check your setup

Not sure where this computer is in the setup? Run `z23 fleet doctor --datadir=<node-datadir>`. It
reads only (it changes nothing and prints public fingerprints, never keys)
and lists eight checks in order: node, identity, membership, delegation,
transport, pairing, mail, wiki. Each is `ok`, `missing`, `blocked` or
`unknown`, with one sentence and the command to run next; the top-level
`next` is the first one to run. The mail check is marked `informational`
and never changes either.

## What you are doing

A fleet is a set of computers one owner runs. Joining one adds a **machine
record**: a signed statement that this owner admitted this computer under a
name they chose. It is an inventory entry, not a permission. It grants no
shell, no remote execution, and no authority over anything.

There are two pasted strings and three commands.

| Step | Where | Command |
|---|---|---|
| 1 | The manager computer | `z23 fleet invite --name=<name> --datadir=<node-datadir>` |
| 2 | The new computer | `z23 fleet join <token>` |
| 3 | The manager computer | `z23 fleet admit <receipt> --datadir=<node-datadir>` |

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
as the name. See "The onion column" below for the one of those the record
carries today.

Renaming is not supported. The name is bound inside the signature the new
computer makes over its own enrolment receipt, so nobody — including the
owner — can rewrite it in place. Pick a name you will still want later.

## Prerequisites on the new computer

You need a C23 toolchain, `git`, and enough disk for a build.

**Linux.** A recent gcc or clang, `make`, and the usual build headers.

**macOS.** Xcode command line tools (`xcode-select --install`).

**Windows.** The Windows path is the **native MSYS2 UCRT64 build** — install
MSYS2, open the UCRT64 shell, and follow `docs/node/WINDOWS.md`. Enrolment is
native Windows code: it reads the computer's own facts through the Win32
calls and writes its key under the Windows state root, with no Linux layer
underneath.

The mesh terminal worker has a Windows arm (ConPTY, with the shell's process
tree held in a kill-on-close Job Object), described in
`docs/node/WINDOWS.md`. The terminal lane is refused on Windows by default,
because the shell has no confined identity there: a Windows machine enrols,
appears in `fleet machines` and holds a name like any other, and answers
terminal opens with `CONFINEMENT_UNAVAILABLE`. The owner can start the node
with `-terminalacceptunconfined` to turn the lane on anyway: the remote shell
then runs as your Windows user with all its rights, and only peers you paired
with the terminal capability can open it. A paired machine connects with
`z23 ops mesh terminal --pairing_id=<64hex>`. A
restricted-identity launch remains the intended follow-up. Without the flag this
is a missing capability on a real member, not a reason to join from somewhere
else.

## What the AI agent on the new computer does

```sh
git clone https://github.com/z23c/z23.git
cd z23
make -j8 build/bin/z23-dev
build/bin/z23-dev fleet join <token>          # add --onion=<v3>.onion if this box has one
```

Then hand the printed `z23 fleet admit …` line back to the owner, with `--datadir=<node-datadir>` added to it.

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

## The onion column

A machine may also carry an **onion** — the persistent v3 onion hostname it
says it will answer on. Pass it at step 2:

```sh
z23 fleet join <token> --onion=<56-characters>.onion
```

It is optional. A computer with no persistent onion yet joins without one
and the column is empty.

It is **self-reported**, exactly like the hardware facts. The joining
computer signs the string, so the record proves that computer claimed that
address; nobody has dialled it, so the record proves nothing about whether
it answers. `fleet machines` prints it in the `self_reported` object beside
the hostname, never in the `verified` object beside the name. A later change
that actually dials the address and gets the machine's key back is what
would move it.

It is a column, not a handle. Two machines that rotate their onions are
still the same two names, and a refusal still says the name.

The grammar is closed: 56 characters of `a-z` and `2-7`, then `.onion`, with
an optional `:port`. A v2 address, an uppercase spelling, a plain hostname
and an IP literal are all refused as `join_onion_invalid` on the computer
that typed it — where somebody can fix the typo — rather than signed into a
record nobody can use.

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

## Anchoring the fleet root (optional)

The operator key is a plain Ed25519 key, the same shape as a ZID master key,
so it can be anchored on chain with no second key format. This is optional:
a fleet that never anchors keeps enrolling and listing exactly as before.

1. `fleet invite` prints the `operator_pubkey`. To anchor a master key on a
   node with a wallet, run this sequence. Anchoring spends a fee and is
   always your decision.
   1. `z23 core identity keygen --input='{"seed_file":"<absolute private path>"}'`
      creates the seed file and prints its pubkey. The seed is never printed.
   2. `z23 core identity anchor --datadir=<node-datadir> --input='{"wallet_scope":"prod","pubkey":"<pubkey>","idempotency_key":"<key>"}'`
      prints a `plan_id`.
   3. `z23 core identity anchor --datadir=<node-datadir> --input='{"wallet_scope":"prod","plan_id":"<plan_id>","confirm":true}'`
      broadcasts it. The fee is 100 zat from the transparent wallet.
   4. Wait until the tip is at least the anchor height plus 20.
   5. `z23 core identity resolve --datadir=<node-datadir> --pubkey=<pubkey>` must report the anchor.
   6. `z23 zcode network delegate --datadir=<node-datadir> --input='{"seed_file":"<absolute private path>"}'`
      (the node must be running).
   7. `z23 fleet vitals sample`.
2. Once the node has folded the anchor, point the fleet leaves at its
   datadir: `--datadir=<dir>` on the CLI (`fleet admit` and `fleet import`
   also take `datadir` in the input). They open
   `<dir>/node.db` read-only and never create it.
3. `fleet invite`, `fleet admit`, `fleet import` and `fleet machines` then
   report `operator_anchor`: `state` is one of `active`, `rotated` (with its
   `successor`), `revoked`, `not_anchored`, `unchecked` (no datadir, or no
   `node.db` there) or `unreadable` (a `node.db` that could not be read). It
   is its own object and never merged into the `verified` object, because
   "the operator sealed this" and "the operator is anchored" are two facts.
4. To make it a gate, pass `--require_anchor=yes` to `fleet admit` or
   `fleet import`. They then refuse unless the state is `active`, naming
   `fleet_root_not_anchored`, `fleet_root_rotated`, `fleet_root_revoked` or
   `fleet_root_anchor_unverifiable` (no datadir, no `node.db`, unreadable:
   a required anchor nobody checked fails closed). `admit` checks before it
   spends the invite, so a refusal leaves the invite usable. Any value other
   than `no`, `false` or `0` requires it. `fleet machines` only reports.

A line the operator did not seal is still refused as
`roster_line_not_operator_sealed`, whatever the chain says.

## Publishing the roster to the board

The machine roster is also how the board knows who may carry fleet-private
posts (ZRC 0012 step 2). It is opt-in and off by default: until you turn it
on, nothing is published and fleet carriage is exactly pairing plus role.

The manager's `-fleetrostergate` is the fleet-wide opt-in. Members need no
flag: a member box enforces the roster as soon as it holds a verified sealed
row from the manager, and a box with no fleet root (never joined) is not
gated at all. Use `-fleetrostergate=0` on a member only as a local escape.
A change reaches a box within about 10 seconds plus one rebuild of its
cached roster (the cache lives at most 10 seconds and is dropped when a roster
row arrives); that is also the lag before a root rotation or revocation
stops fleet-scope relay.

To turn it on, start the manager's node (the box whose key is the fleet root)
with `-fleetrostergate`. Within about 30 seconds the node writes each admitted
machine's sealed line to the board as a fleet-scope note whose agent is
`fleet-roster`, and writes it again every 10 days (a note lives 30 days, so if
the manager's node stays down for more than 20 days the roster lapses and
fleet carriage goes back to pairing plus role, with a WARN in each box's log).
The other boxes learn the rows through the normal paired board pull; each box
checks every roster row's seal before it stores it, and logs once, at INFO
with the member count, when the roster arms.

1. Start every box's node before you `fleet join` it, so its receipt names
   the board signing key the roster will admit. A receipt that names none
   still enrols the machine but makes it no roster member.
2. Admit the manager itself (`fleet invite`, `fleet join`, `fleet admit` on
   the manager), or members will not accept its fleet posts. A manager that
   joins its own fleet is still recognised as the manager.
3. Every box must also hold the manager's line in its own roster
   (`fleet import`), so the role bootstrap grants the manager's key the
   worker role there: roster rows arrive as fleet notes and the board role
   check still applies to the key that posts them.
4. Before you start the manager with the flag, check `fleet machines`: once
   the roster arms, a machine that is not on it (one enrolled without a
   signing key, or the manager if it was never admitted) stops exchanging
   fleet-scope posts until it is re-admitted. That is the point of the
   gate, and it is also why it is not on by default.
5. If the fleet root is rotated or revoked on chain, no fleet-scope post moves
   until you re-establish a root and re-admit the machines. To remove one
   machine today, change the fleet root.

The escape hatch is the same flag set to zero on the box that needs it:
`-fleetrostergate=0` makes that box stop enforcing the roster (it logs that at
WARN and follows pairing plus role again). Use it on a member whose manager
lapsed or whose roster is wrong, and on a manager you want silent. Public
scope is never gated either way.

## What comes next

The bridge is a bridge. The native path is mesh pairing over the node's own
Noise transport — `ops mesh pair plan` and `ops mesh pair commit` — which
needs the new computer to be running a node with an on-chain identity
delegation. `fleet join` prints that as its `next_step` rather than
pretending it already happened. See `docs/work/SOVEREIGN_MACHINE_MESH_PLAN.md`.

Once a pairing carries the terminal capability (`ops mesh pair commit` with
its `terminal` input set to true), the paired machine's confined shell is one command away:

```sh
z23 ops mesh terminal --pairing_id=<64hex>
```

The command talks to the local node's `mesh_terminal_*` RPCs over the
established Noise session; it never dials. On a terminal it puts the local tty
in raw mode, sends the window size, follows resizes, and restores the tty on
every exit path. `~.` at the start of a line detaches (`~~` sends one `~`).
When stdin is not a terminal it sends stdin, writes only remote output to
stdout, ends the input with one end-of-transmission byte (finish the last line
with a newline), and prints every diagnostic on stderr:

```sh
printf 'uname -a\nexit\n' | z23 ops mesh terminal --pairing_id=<64hex>
```

Refusals print `z23: refused: <name>: <words>` (`not-paired`,
`capability-unavailable`, `confinement-unavailable`, `concurrency-limit`: 4
terminals per node); a node that stops answering after attach prints `z23:
connection lost: ...`. A session end prints `z23: terminal closed: reason=<name>
... - <words>`: `worker-exited`, `idle-timeout` (600 s), `lifetime-limit`
(3600 s), `byte-limit` (default 1 GiB out, 16 MiB in), `session-lost` (peer
dropped), `shutdown`, `revoked`, `expired`, `peer-closed` (no close report:
the stream ended without one and prints `z23: terminal ended:
reason=peer-closed ...`, exit `5`).

The remote exit status is carried. The signed close report
(`zcl.terminal_close_evidence.v1`) holds `bytes_in`, `bytes_out`,
`duration_s`, `reason`, and for `worker-exited` exactly one optional key:
`exit_code` (0-255) when the shell exited, or `signal` (1-64) when a signal
killed it. The line then reads `reason=worker-exited exit_code=3` or
`... signal=15`. The two keys are optional additions to the same signed
capsule, which is hashed as opaque bytes: a node that predates them sends
neither (a missing status exits `0`), and an older client ignores them. Exit
codes: `0` detached or the remote shell exited 0; `N` (1-255) the remote
shell exited with status N, `128+S` when signal S killed it (SIGTERM gives
`143`), like ssh; and the local classes `2` invalid, `3` blocked, `4` denied,
`5` transient or any limit or loss, `6` internal, `130` interrupted. A remote
status that equals a local class number is told apart by the stderr line
(`reason=worker-exited exit_code=3` versus `refused:` or `reason=<limit>`).

Limits per session: 600 s idle, 3600 s lifetime, 16 MiB in, and 1 GiB out
unless the node sets `-terminalmaxbytesout=<bytes>` (1048576 to 68719476736;
anything else keeps the default). The byte budgets are a runaway backstop;
the rate is bounded separately at 16 reads of 4 KiB per 100 ms drain tick
(about 640 KiB/s ceiling, measured near 480 KiB/s end to end) and by the
64 KiB stream credit window. Memory per session does not grow with the
budget: one 4 KiB read buffer on the responder, at most 64 KiB in flight, and
one 64 KiB screen FIFO on the requester; at most 4 sessions per node.

In raw mode Ctrl-C and the other control keys go to the remote shell; only
`~.` or an external SIGINT, SIGTERM, SIGHUP or SIGQUIT ends the command, and
the local tty is then restored. Modes the remote program set by escape
sequence (alternate screen, mouse reporting, bracketed paste) are not reset;
run `reset` locally if a remote program left one on. Remote output is shown
with nothing filtered, but the command's own diagnostics replace control bytes
in node and responder text with `?`. For a Windows peer, piped input must use
CR line ends and the trailing end-of-transmission byte is not end-of-file
there; there is no option for it yet.

### A confined shell over the PSK device-host tunnel (terminal hub)

For a fleet machine that has the device-host receiver but no paired node, no
ZID master and no sshd, `z23 ops mesh terminal serve` and `connect` give the
same confined shell over the existing device-host tunnel. The direct hub
speaks its own hub frames over the device-host client, whose outer channel is
a static SHAKE256-Wrap PSK. There is no inner OpenSSH key exchange here, so
nothing post-quantum or ephemeral is negotiated, and the tunnel has no
forward secrecy: anyone who later obtains the PSK and a recording of the
session can read it (see
[the forward-secrecy design](../spec/TUNNEL_PQ_FORWARD_SECRECY.md)). This is not the
earlier hybrid SSH trial (`sntrup761x25519-sha512` inside OpenSSH); that
measurement belongs to the SSH path and says nothing about the hub. The
receiver is unchanged: it connects to a loopback
port, and `serve` is what listens there (point the receiver's `target_port` at
it; the second receiver unit is the hub operator's change, not this one).

```sh
# once, on the server host: make the terminal key (never printed, 0600)
z23 ops mesh terminal serve --init-key --key_file=/path/hub.key
#   event=TERMINAL_HUB_KEY_CREATED key_fingerprint=<16 hex> path=...
# copy the key to the lead over a channel you trust; compare the fingerprint.

z23 ops mesh terminal serve --key_file=/path/hub.key \
    --shell=/abs/path/fbsh --workdir=/abs/dir --listen_port=<port> \
    --audit_file=/path/audit.log          # default audit: stderr
#   event=TERMINAL_HUB_LISTENING listen_port=<port> key_fingerprint=<16 hex>

# on the lead, through the tunnel (the device-host client runs as a child):
z23 ops mesh terminal connect --key_file=/path/hub.key \
    --route_input=<device-host client json> [--name=<label>]
# or straight to a loopback server, with no tunnel:
z23 ops mesh terminal connect --key_file=/path/hub.key --direct_port=<port>
```

Admission. `serve` binds `127.0.0.1` only, and anything on the host can reach
that port, so every connection first answers a random 32-byte challenge with
a SHA3-256 MAC keyed by the terminal key, within 2 s; any other first bytes,
a wrong key, a replayed hello or silence closes the connection and no shell
starts. The key file must be a regular file you own with mode exactly `0600`
and 32 bytes, and is never followed through a symlink; `serve` and `connect`
refuse anything else (`KEY_FILE_REFUSED`, exit 2). The key is separate from
the PSK, so losing one does not give the other. Anyone who can read the key
file can open a shell: that is the same trust boundary as the PSK store. A
local process without the key can still occupy a session slot for up to 2 s;
the slots are `--max_active` (default 4, at most 16, pre-authentication
connections included), and an over-limit connection is told `busy` before any
work is done. `--max_sessions` is a connection-attempt limit, not an
authenticated-session count: it counts every connection the server accepts,
wrong key included, and `serve` stops once that many have been taken (0 runs
until signalled; values past 4294967295 are refused as invalid).

What the tunnel gives and what it does not. The tunnel is the confidentiality
and authenticity layer for the bytes. The hub's frames carry no signed
evidence (no receipt, no capsule): the exit status rides an unsigned `EXIT`
frame and is exactly as trustworthy as the tunnel. The hello `--name` is a
label the lead chooses; it is not verified and the audit line says so
(`name_verified=0`). A hello that fails the MAC leaves no label at all.

Confinement is the existing terminal worker, unchanged except for the argv
option below: Landlock grants the per-server `--workdir` (read, write, create,
execute; shared by that server's sessions, and also the shell's cwd and HOME)
plus the one granted binary, with the terminal seccomp set and (for the default
shell) strict W^X. The
environment has no `PATH`. A program you want to run must either be that
binary or live inside the workdir.

`connect --exec='["/abs/program","arg",...]'` runs that argv (1 to 16 strings,
2000 bytes in all, `argv[0]` an absolute path) instead of the server's shell,
in the same cage: `argv[0]` becomes the one granted binary (read and
execute), the standard library directories that exist (`/lib`, `/lib64`,
`/usr/lib`, `/usr/lib64`) are granted read and execute, the workdir is
read-write, and the exec mode is relaxed from strict W^X to file-backed
executable mappings (`mmap` with `PROT_EXEC` needs a real fd and no
`MAP_ANONYMOUS`); anonymous executable mappings and any `mprotect` to
executable stay killed by SIGSYS. This is not W^X: the workdir is writable, so
a program can write a payload there and map it executable (or run it through
the dynamic loader). Containment does not rely on W^X; it relies on what every
process in the cage is denied: no network (the socket family and io_uring), no
signals outside the session (pid 0, -1 and the server's own pid and group are
refused; thread, pidfd and queued signals are killed), no inherited
descriptors, and the filesystem grant. A dynamically linked program (such as
`/usr/bin/true`) runs, and so does a statically linked program (such as
`fbsh -c '...'`). A program the server
cannot run (relative path, missing, not a regular executable file) is refused
by name before any process starts: `EXEC_REFUSED`, exit 2. A write outside the
workdir fails inside the cage with the program's own error.

Client. On a terminal `connect` puts the tty in raw mode, sends the window
size in the hello and every SIGWINCH as a resize, and restores the tty on
every exit path (the termination signals are turned into a close, exit `130`).
When stdin is not a terminal the remote echo is turned off, so the output is
only what the remote wrote; end the input with `exit` (a bare end of input
sends one end-of-transmission byte, which a shell takes only at a prompt). The
screen always ends on a fresh line. The process exit code is the remote shell's
(`128+S` for a signal), like ssh; the local classes are `2` invalid or
refused request, `3` blocked, `4` the key was refused, `5` transient (busy,
lost, no answer, idle or lifetime limit), `6` internal, `1` other. An error is
one line, `z23: refused|ended: <CODE>: <words>`, with the codes
`AUTH_REFUSED`, `BUSY`, `EXEC_REFUSED`, `CONFINEMENT_UNAVAILABLE`,
`CONNECTION_LOST`, `NO_ANSWER`, `IDLE_TIMEOUT`, `LIFETIME_LIMIT`,
`BYTE_LIMIT`, `SERVER_STOPPING`, `INTERRUPTED`; a failed tunnel adds the
client's own `error=` line in parentheses.

An exit report the server could not have sent (no status, both a code and a
signal, a signal outside 1 to 64, an unknown ending) is never read as success:
it is the `PROTOCOL` error, exit `1`. `connect` stays responsive to a
termination signal while the screen cannot be written (output piped to a
reader that stopped), and it ends the tunnel child within a few seconds
whatever the child does. The shell's process group is killed at the end of
every session, so a program that ignored HUP does not outlive it.

Limits per session (flags on `serve`): `--idle_s` 600, `--lifetime_s` 3600,
`--max_bytes_in` 16 MiB, `--max_bytes_out` 1 GiB; a session is one forked
child, so a crash in one cannot touch another. On SIGTERM `serve` asks each
session to end and kills any still running after 5 s. A session's audit line
waits at most 2 s for the audit sink; if the sink never takes it the line is
dropped and `serve` says `event=TERMINAL_HUB_AUDIT_DROPPED count=N` on
stderr when it stops.

Audit. One line per connection on the server, to `--audit_file` (appended) or
stderr:

```text
event=TERMINAL_HUB_SESSION admitted=1 refusal=none start=<unix> end=<unix> duration_s=N reason=worker-exited exit_code=7 signal=- bytes_in=N bytes_out=N name=<label> name_verified=0 exec="-"
```

`exec` is the escaped argv (`-` for the shell): space, `"`, `\` and every
non-printable byte appear as `\xNN`, cut at 256 bytes with `...`. A refused
connection shows `admitted=0 refusal=auth|busy|request|exec|confinement` and
`name=-`.

Cost. A keystroke or a screen chunk is one 3-byte frame header and one
`send`/`write`; there is no polling, sleep or tick on the path (the server and
client block in `poll`), TCP_NODELAY is set on both loopback ends, and the
only wakeups are bytes and the lifetime and idle deadlines. The census check
that watches for a fork bomb runs at most once a second while busy. The
measured keystroke round trips (kernel echo through the hub) are in the
`mesh_terminal_hub` and `device_host_runtime` test output.

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
| `invite_ttl_invalid` | `--ttl_hours` is outside 1 to 168 hours |
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
| `join_onion_invalid` | `--onion` is not a v3 onion hostname with an optional port |
| `authorized_keys_unwritable` | `~/.ssh` does not exist, or the file cannot be written |
| `fleet_root_not_anchored` / `fleet_root_rotated` / `fleet_root_revoked` | `--require_anchor=yes` was given and the operator key is not an active ZID anchor in the node.db read |
| `fleet_root_anchor_unverifiable` | `--require_anchor=yes` was given and no anchor state could be read (no datadir, no node.db, or unreadable) |
