<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Fleet operator guide

This is the single operator page for a Z23 fleet: which machines belong to
it, how to add one, how to reach one, and how to read its health. Agent and
coordinator policy (storage admission, task ownership, cost accounting) is in
[`work/AGENT_FLEET.md`](../work/AGENT_FLEET.md). Priorities are in
[`work/FLEET_SCORECARD.md`](../work/FLEET_SCORECARD.md).

A route to a machine grants no shell, no consensus authority and no custody
authority. Implemented commands and their input contracts are those of the
selected binary: `z23 discover describe <leaf>` and `z23 discover schema <leaf>`.

## Machines

A fleet's machines are exactly what `z23 fleet machines` reports: admitted
inventory records, not a list kept in documentation. This page names no
particular hosts. To work with the roster:

| Task | Command |
| --- | --- |
| List machines | `z23 fleet machines` |
| See the next missing step for this node | `z23 fleet doctor --datadir=<node-datadir>` |
| Enrol and admit a machine | the three-step sequence under *Joining a machine* |
| Read paired-machine status | `z23 ops mesh machines`, `z23 ops mesh status` |

If `z23` is not on a remote host's non-interactive `PATH`, call it by its
absolute path. Host build admission and storage reserves are local policy; see
`work/AGENT_FLEET.md`.

## Joining a machine

A machine record is a signed inventory entry. It grants no shell, no remote
execution and no authority. Three commands and two pasted strings, with no
network connection between the machines:

| Step | Where | Command |
| --- | --- | --- |
| 1 | manager | `z23 fleet invite --name=<name> --datadir=<node-datadir>` |
| 2 | new machine | `z23 fleet join <token>` |
| 3 | manager | `z23 fleet admit <receipt> --datadir=<node-datadir>` |

The name is required, unique and permanent: 2 to 24 characters of `a-z`,
`0-9` and interior dashes. `z23 fleet doctor --datadir=<node-datadir>` reads
state only and lists the next missing step (node, identity, membership,
delegation, transport, pairing, mail, wiki). `z23 fleet machines` lists the
roster. Hardware facts in a record are self-reported, not verified.

The full procedure, refusal names, the optional `ssh` bridge, on-chain root
anchoring and the roster gate (`-fleetrostergate`) are in
[`agent/FLEET_JOIN.md`](FLEET_JOIN.md).

## Tunnel

Current status:

- The hub host runs one supervised user unit per client,
  `z23-tunnel-receiver@<client>.service`.
- The outer transport is backend 2 (SHAKE256-Wrap) with a static pairwise
  PSK. It has no forward secrecy.
- Inner OpenSSH negotiates `sntrup761x25519-sha512@openssh.com` and verifies
  the existing pinned host key. Ed25519 host authentication is classical; the
  combination claims no post-quantum host signatures.
- macOS is blocked pending native HOST qualification: Darwin strict
  descendant cleanup is not qualified.
- Forward-secrecy design (proposal, not implemented):
  [`TUNNEL_PQ_FORWARD_SECRECY.md`](../spec/TUNNEL_PQ_FORWARD_SECRECY.md).

Install and run each host from an immutable release directory of a reviewed,
landed build; record the host, source, image hash, peer, target and lifetime
in the task receipt. Keep the existing pinned SSH route available for rollback.

Pairing uses a separate owner-private profile, never a canonical node datadir:

```sh
"$Z23" ops mesh device identity --directory="$PROFILE"
"$Z23" ops mesh device prepare-secret --input="$(cat prepare-secret.json)"
"$Z23" ops mesh device plan --input="$(cat grant-plan.json)"
"$Z23" ops mesh device commit --input="$(cat grant-commit.json)"
```

`prepare-secret.json` carries `directory`, `peer_key`,
`capability="host-forward"`, `backend=2`, `destination` and `confirm=true`.
The 32-byte secret moves only over an already authenticated private route,
never through the board, wiki, argv or logs. Revocation is sticky.

Bounded receiver (hub side) and client:

```sh
"$Z23" ops mesh device host receiver --input="$(cat receiver.json)"
"$Z23" ops mesh device host client   --input="$(cat client.json)"
```

The receiver input is `directory`, `peer_key`, `expected_root`, `target_port`,
`route_id`, `listen_address`, `listen_port`, `allow_external`, `lifetime_ms`,
`handshake_ms`, `session_ms`, `idle_ms`, `max_active`, `max_sessions`,
`confirm`. The client input is `directory`, `peer_key`, `expected_root`,
`target_port`, `route_id`, `route_address`, `route_port`, `connect_ms`,
`handshake_ms`, `session_ms`, `idle_ms`, `confirm`. Use the literal approved
IPv4 route. To verify, run OpenSSH with the client as its `ProxyCommand`,
`StrictHostKeyChecking=yes` and `KexAlgorithms=sntrup761x25519-sha512@openssh.com`.

Terminal tokens: `HOST_RECEIVER_LISTENING` proves binding only.
`HOST_RUNTIME_TERMINAL` reports `result` (`eof`, `refused`, `deadline`,
`io_error`, `cancelled`, `unsupported`), `cleanup_complete`, `accepted`,
`completed`, `refused` and `preauth_refused`. `HOST_RUNTIME_INPUT_REFUSED`,
`HOST_RUNTIME_FAILURE` and `HOST_RUNTIME_UNSUPPORTED platform=unqualified` are
the refusals. Raw carrier EOF without an authenticated FIN is truncation, not
completion. Rollback is `kill -TERM` of the receiver this rollout started;
revoke only the new grant, with its inspected root.

Throughput benchmark (read-only, needs no pairing and no network):

```sh
"$Z23" ops mesh device host bench --mib=64 --repeats=3 [--receipt_out=/abs/path/tunnel.json]
```

It drives the real receiver and client PSK bridge pair in this process over
loopback sockets, with a throwaway paired authority in a private temp profile
that is removed before the leaf returns; it never opens an operator profile.
`mib` is 1..512 per direction (default 64), `repeats` 1..5 (default 3).
The result is `zcl.tunnel_bench.v1`: `forward_mib_s` and `reverse_mib_s` (the
median), the per-run `forward_runs_mib_s` and `reverse_runs_mib_s`, `records`,
`acquisitions_per_record` (`full`, `cached`), `build_flags`, `source_id_sha256`,
`host_load1`, `profile_removed` and `timestamp`. Speed is measured on the
monotonic clock and is an observation of this host and build, never a gate;
compare `build_flags` and `host_load1` before comparing two results.
`receipt_out`, when given, writes the same JSON atomically (tmp, fsync, rename)
into an existing directory so a probe can read it. The t-fast bridge group
shares this implementation (`ZCL_DEVICE_HOST_BENCH_MIB` sizes its run).

## Shells and remote commands

Existing OpenSSH peer access (aliases above, existing key and host pins, hybrid
key exchange):

```sh
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o ControlMaster=no -o ControlPath=none \
  -o KexAlgorithms=sntrup761x25519-sha512@openssh.com \
  <host-alias> 'hostname; id -un'
```

Through a command-scoped forwarding carrier to the peer's loopback sshd, add
`-o "ProxyCommand=ssh <same options> -W 127.0.0.1:22 <host-alias>"`. A directed-pair
check of one fleet passed on 2026-10-15; that record is historical:
[`experiments/FLEET_SHELL_ROUTES_2026-10-15.md`](../experiments/FLEET_SHELL_ROUTES_2026-10-15.md).

Native confined terminal over a paired node:

```sh
z23 ops mesh terminal --pairing_id=<64hex>
printf 'uname -a\nexit\n' | z23 ops mesh terminal --pairing_id=<64hex>
```

The remote exit status is carried (`128+S` for signal S). Limits per session:
600 s idle, 3600 s lifetime, 16 MiB in, 1 GiB out, 4 sessions per node. The
macOS worker is refused; Windows is refused unless the node runs with
`-terminalacceptunconfined`.

For a machine with only the device-host receiver, `z23 ops mesh terminal
serve` and `connect` give a confined shell over the tunnel, authenticated by a
separate 0600 terminal key. See [`agent/FLEET_JOIN.md`](FLEET_JOIN.md)
for flags, refusal codes and the audit line. The terminal contract inventory
is [`experiments/FLEET_TERMINAL_CONTRACT.md`](../experiments/FLEET_TERMINAL_CONTRACT.md).

## Health and vitals

`z23 fleet vitals sample` measures this box and appends signed rows to the
fleet ledger; unmeasurable facts are stored absent, never as zero. The metric
catalog, ledger kinds and refusals are in [`FLEET_LEDGER.md`](FLEET_LEDGER.md);
the telemetry shape and unknown-value rules are in
[`TELEMETRY_CONTRACT.md`](../node/TELEMETRY_CONTRACT.md).

Read another machine's load, memory and disk over the host tunnel (200 to 220 ms in three runs on 2026-10-18):

```sh
z23 fleet vitals table --machines='[{"label":"<name>","route_file":"<route-file>","slot":"<remote-z23-path>","host_alias":"<host-alias>"}]'
```

Other telemetry: `z23 ops telemetry watch --since=<sequence>` (resumable
batches with cursor, epoch and gap fields), `ops.mesh.machines` and
`ops.mesh.status` (paired-machine status, bounded probes). A cached or
unchanged feed is not a fresh observation.

## Board, wiki and agents

### Board and wiki

The board is a signed, append-only record of requests, claims and receipts;
the wiki holds procedures. Neither is an authority: gates decide. Details and
the agent protocol: [`FLEET_BOARD.md`](FLEET_BOARD.md).

```sh
z23 fleet board list [--kind=K] [--host=H] [--since=T] [--open] [--scope=S] [--room=R] [--limit=N]
z23 fleet board show <id>
z23 fleet wiki find [q]
z23 fleet wiki read <slug>
z23 fleet board post <kind> <text> [--scope=public|fleet] [--room=R]
z23 fleet wiki write <slug> <title> <body>
```

Posting and wiki writes are local-only and never remotely invocable. Keep
endpoints, credentials and private paths out of public scope.

### Agents

`z23-dev fleet agents` lists the agent workspaces on this box, the processes
running in them, and each executor's grade from the experiment ledger
(`~/.local/state/zclassic23/experiments/rows.tsv`, 22 tab-separated columns).
`--publish` posts this box's rows to the board; `--fleet` merges the newest
post per host (stale after 15 minutes); `--since=<hours>` (default 168) and
`--by=executor|lane|class` shape the grades. A running process is evidence of
activity, never of a result.

Grades use outcomes `LAND`, `READY`, `landed`, `PASS` as success and `HOLD`,
`FAIL`, `failed`, `timeout` as failure; others are excluded from the rate.
A needs success at or above 90 percent and a median wall-time ratio at or
below 1.5; B 80 percent and 2.0; C 65 percent; D 50 percent. Fewer than three
results print `n/a (n<3)`; executors with no predictions are capped at C.

### Objectives

`z23-dev fleet objectives [--format=json]` prints each named objective with
its current value, target and status (`met`, `unmet`, `unmeasured(<reason>)`).
The closed catalog is [`engine/composition/objectives.def`](../../engine/composition/objectives.def):
`landing_latency_s`, `landing_attempts_per_train`, `proof_lint_wall_s`,
`proof_test_wall_s`, `commits_landed_today`, `lint_families_over_ceiling`,
`functions_over_complexity_cap`, `fresh_node_sync_eta_s` and
`tokens_per_landed_commit`. It is a report, not a gate.

### Goals

`z23 fleet goals [--format=json]` prints the live report card: one row for each fleet
goal G1-G13, public-node criterion C1-C8 and development milestone D1-D8, with its
id, title, grade (`pass`, `partial`, `fail` or `unmeasured`), the A+ bar, one evidence
string from a local probe and `next`, the command or card that would raise it. The
closed catalog is [`engine/composition/goals.def`](../../engine/composition/goals.def);
the targets are in [FLEET_SCORECARD.md](../work/FLEET_SCORECARD.md),
[MVP.md](../quality/MVP.md) and [DEVELOPMENT_MVP.md](DEVELOPMENT_MVP.md).

A row passes only when every numeric clause of its bar was measured and met. A row
whose probe is missing is `unmeasured` with the reason; the leaf never guesses a grade.
Probes run in the process: the landing outcomes ledger and `git log origin/main` (G9),
a warm `code find` over five samples (G7), the wiki read path (G4), vitals history per
admitted host (G8), the lane claims ledger (G13), the shell-script allowlist (D8) and
the release update leaf (G6). Host-set goals (G1, G3, G5, G6, G8, G12) take their hosts
from the admitted roster (`z23 fleet machines`) and are unmeasured without one. The
first call after a checkout change rebuilds the code index and can take seconds.
The G7 lookup uses the working directory's code index and can refresh it, writing under
`.codeindex`; the leaf writes nothing else and contacts no peer. It is a report, not a gate.

### Roles

Which key may call which fleet leaf is decided by each node alone, from a
signed local store (`<datadir>/fleet_roles/roles.chain`). Roles
(`engine/composition/roles.def`): `operator` (this node's key, implicit),
`worker` (fleet-private board posts, ledger replication, experiment rows),
`observer` (read-only), `landing` (board `result` posts about trains).

```sh
z23 fleet roles list
z23 fleet roles grant  --fp=<64-hex> --role=worker
z23 fleet roles revoke --fp=<64-hex> --role=worker
z23 fleet roles check  --fp=<64-hex> --leaf=fleet.board.post --kind=result
```

Ledger replication (`fleet.ledger.replicate`) and fleet board ingress
(`fleet.board.post`) refuse foreign keys without an active grant; public posts
need none, and a missing checker refuses. `fleet admit` grants `worker` to the
admitted box key and signing key, and node start grants it to every roster key
and every signer already stored. Refusals are counted as `role_refused` in
`fleet ledger status` and `fleet board status`; `grandfather_truncated` above
zero means the boot walk hit its 64-key bound and `roles grant` must name the
rest. A grant is local policy, not consensus.

### Triggers

A closed registry of reactions to local events, evaluated once per call by
`z23-dev fleet triggers check`; there is no daemon. See
[`FLEET_TRIGGERS.md`](FLEET_TRIGGERS.md).

### Plugin distribution

Status: design only. Remote installation is not implemented. The local
sequence for already verified receiver-held bytes is:

```sh
z23 zcode package checkout --datadir=<receiver-datadir> --input='{"root":"<64-hex-package-root>","destination":"./plugin-received"}'
z23 plugin install --manifest=./plugin-received/NAME.plugin.json
```

Install does not select or run the plugin; the receiver's owner approves each
stage. A generation is the SHA3-512 digest of the exact signed manifest bytes
(128 lowercase hex characters); a version label or abbreviated prefix is not
its identity. `steer_deliver` accepts source only, not executables. See
[`PLUGINS.md`](../dev/PLUGINS.md).

## Troubleshooting

| Symptom | Cause and action |
| --- | --- |
| `z23: command not found` over a non-interactive shell | `z23` is not on the remote non-interactive `PATH`; call it by absolute path. |
| A generic leaf needs JSON input | Pass `--input='<json>'`, or `--input=-` to read stdin. |
| `fleet board` or `fleet wiki` fails closed | No local node answered. Check `z23-dev status` and the RPC port and datadir. |
| A machine is missing from `fleet machines` | It was never admitted or its record was not sealed by the operator key. Run `z23 fleet doctor --datadir=<node-datadir>`. |
| A Windows machine does not answer | Check its route. The terminal lane is also refused without `-terminalacceptunconfined`. |
| macOS shell is refused | The confined terminal worker does not run on macOS; use a plain SSH `<host-alias>`. |
| Vitals show a machine as unknown | Absent is not zero. Rerun the `vitals table` command above and check the route file. |
