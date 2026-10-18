<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Z23: the whole picture

This page sits under the North Star in [`AGENTS.md`](../AGENTS.md): "Software
made for you, not imposed on you." It draws the parts of Z23 in one picture so
a reader can see how the node, the commons, the emulated machine and the
tunnels fit together. It does not set priorities. The ranked priorities are in
[`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md#five-product-acceptance-priorities), and the acceptance criteria are in
[`MVP.md`](MVP.md). Every element below carries exactly one status label, and
each row of the table says what its evidence does not show.

![Nested boxes: a Z23 program inside the local-authority boundary of your machine, holding a full node, the C23 Commons (with an ML-KEM-768 module used by the unintegrated zssh engine) and an emulated RISC-V machine that contains a FreeBSD guest and one post-quantum key-exchange experiment, with mesh tunnels, an onion transport and the landing path below; every element carries one of four labels, ON MAIN, CANDIDATE, EXPERIMENT or TARGET](assets/z23-whole-picture.svg)

## Execution and transport choices

The [fleet operating contract](work/AGENT_FLEET.md#consolidated-operating-model)
is the shared reference for disk admission, task ownership and JSON monitoring.
Execution and connection are separate choices. Confined native shell/SSH,
hardware virtualization where qualified, and the emulated guest must each
retain receiver policy. Direct peer connections, SSH tunnels and embedded Tor
can carry permitted traffic without expanding execution authority.

The native mesh terminal is **on main**, with a Linux confined shell worker
that refuses sockets and bounds execution. Native OpenSSH integration,
protected macOS terminal execution and complete transport combinations remain
**targets**. The separate confined package runner refuses child processes
and networking. Neither a host terminal connection nor Tor availability
qualifies the guest route. Compare complete workloads before asserting an emulator
performance penalty; measured startup, throughput and accepted-task cost belong
in exact experiment receipts.

## Status labels

- **On main**: in the tracked source at the commit you are reading.
- **Candidate**: delivered for review, not landed.
- **Experiment**: one recorded run under `docs/experiments/`, not a product
  claim.
- **Target**: a stated goal with no passing evidence yet.

## The parts

| Part | What it is | Status | Evidence | What it does not show |
| --- | --- | --- | --- | --- |
| Full node | A ZClassic full node in the one C23 program. Version 1 is defined by eight pass/fail criteria. | On main | [`MVP.md`](MVP.md) | `MVP.md` marks criteria 6 (seven-day soak) and 8 (consensus parity) as partial, and says a checkmark "records a historically demonstrated run" and "is not current-candidate qualification". It says to ask a running node for the live state: `build/bin/z23 milestone`. Criterion 4 is worded as receiving 1 ZCL with the balance reflected within 2 blocks, while the evidence its row records is a 0.02 ZCL note decrypted after the transaction entered the mempool. |
| C23 Commons | Source identified by the exact `package_root` of its bytes, fetched as inert bytes on another node and rebuilt byte-identically. | On main | [`C23_COMMONS_QUICKSTART.md`](C23_COMMONS_QUICKSTART.md) | The quickstart is the installed-node path for an ordinary C23 static-library package. A [recorded journey across three physical hosts](experiments/COMMONS_MULTIHOST_2026-09-29.md) lists run 3 as "PASS 12/12" beside runs that failed; that journey is opt-in and is not part of `make ci`. |
| Emulated RISC-V machine | A small RISC-V computer in `z23-dev`: one RV64 IMAFDC hart, a serial console, a virtio block device and a device tree. | On main | [`RISCV_MACHINE.md`](RISCV_MACHINE.md) | "One hart; no network device is attached." The registered tests run only small guests committed under `tests/fixtures/rvmachine`. |
| FreeBSD guest | An unmodified FreeBSD 15.1 riscv64 kernel booted in that machine. | Experiment | [`RISCV_MACHINE.md`](RISCV_MACHINE.md), [experiment record](experiments/2026-10-11-guest-pq-ssh-loopback.md) | `RISCV_MACHINE.md` calls these boots "an operator recipe: they are run by hand through the command and are not part of the registered tests". No kernel or disk image is kept in the repository. |
| Network device source | A virtio network device in `platform/modules/rvvirtio/src/rvvirtio_net.c`, exercised by that module's standalone test. | On main as source | [`rvvirtio_net.c`](../platform/modules/rvvirtio/src/rvvirtio_net.c) | Nothing outside the module and its tests calls it; the machine does not attach it. |
| Post-quantum key exchange | A hybrid key exchange between `sshd` and `ssh` on guest loopback, in one run. | Experiment | [experiment record](experiments/2026-10-11-guest-pq-ssh-loopback.md) | Host and user identities are classical Ed25519. No machine-to-machine route was used, and the guest has no network device. A fixture, `tools/guest_ssh_fixture.c`, requests the hybrid algorithm; it does not implement it. |
| ML-KEM-768 module | Allocation-free C23 ML-KEM-768, called by the sans-IO zssh hybrid handshake. | On main | [Module contract](../platform/modules/mlkem/README.md), [SSH contract](../contexts/commons/modules/zssh/README.md), `zssh_kex.c` | Module and handshake tests do not establish a deployed SSH endpoint. zssh has no production session owner and no accepted guest route; the guest loopback experiment uses OpenSSH. |
| Mesh tunnels | Loopback TCP tunnels between paired machines, carried on the mesh stream, with an explicit allow table that permits nothing by default. | On main | [`mesh_tunnel.c`](../engine/composition/src/mesh_tunnel.c), `engine/composition/commands/dev.def` | Whether anything is carried is the far machine's decision. No guest-to-guest route is qualified by the cited evidence. |
| Tunnel entrances that survive a restart | Local entrances that return after a restart. | Candidate | None on main. | Not landed. On main, entrances are not restored after a restart; only the allow table is kept. |
| Onion transport | Embedded Tor for the onion service; the default build (`ZCL_TOR=full`) builds the pinned Tor and links it. | On main | [`BUILD.md`](BUILD.md) | `ZCL_TOR=stub` is a development-only build that cannot reach the onion network and must be requested by name. This page cites no measurement of an onion session between machines. |
| Evidence-bound landing | A change moves through orient, inspect, edit, local feedback, focused proof, integration against current main, then gates and a push. | On main | [`DEVELOPING.md`](DEVELOPING.md) | "A push is a checkpoint, not completion"; acceptance stays a local policy decision over exact objects. The page shows no landing time. |
| Fast development feedback from reused verified work | Warm compile and focused proof, p95 within 10 seconds on a frozen small-change corpus; publication retains all mandatory evidence. | Target | [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) | It is not an end-to-end landing time. The nearest record, the [development-loop performance ledger](dev/C23_DEV_LOOP_PERFORMANCE.md), measures a narrower thing: warm feedback on a replayed set of past edits, "p95 4.595 s" against a five-second gate, and a changed-object replay that "became partial" at the 10 s bound. No document states that this target is met. |

## What is not true yet

- No guest-to-guest route is qualified by the cited evidence.
- Post-quantum protection applies to the key exchange only, in one loopback
  run; peer authentication is classical.
- The guest has no attached network device.
- The ML-KEM-768 module is called by zssh's hybrid handshake, but the SSH
  engine has no production session owner or accepted guest integration.
  Module tests do not establish a deployed quantum-resistant route.
- `MVP.md` records criteria 6 and 8 as partial, and the evidence recorded for
  criterion 4 is a smaller amount, seen at mempool entry, than its wording asks
  for.
- The figure of warm compile and focused proof, p95 within 10 seconds on a
  frozen small-change corpus, is a target; this page cites no measurement that
  meets it.

## What would make it real

Priorities live only in [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md) and
[`MVP.md`](MVP.md). [`AGENTS.md`](../AGENTS.md) says: "No other plan, scorecard,
runbook, handoff, vendor skill, or old session note may reorder that mission."
This page does not rank anything. The gaps its own table
exposes, in no order:

- The machine has no network device attached (a fact about what it has, not a
  required step of any guest route).
- No guest-to-guest route is qualified by the cited evidence.
- Post-quantum key exchange has been observed only on loopback, in one run, with
  classical identities.
- Criteria 6 and 8 are recorded as partial in `MVP.md`.
- The evidence recorded for criterion 4 does not show its literal wording: 1
  ZCL received, with the balance reflected within 2 blocks.
- The warm compile and focused proof target (p95 within 10 seconds on a frozen
  small-change corpus) is not shown as met.

## Where to read next

- [`AGENTS.md`](../AGENTS.md): the North Star and authority boundaries.
- [`MVP.md`](MVP.md): the acceptance criteria and their evidence.
- [`work/FORWARD_PLAN.md`](work/FORWARD_PLAN.md): the ordered queue.
- [`RISCV_MACHINE.md`](RISCV_MACHINE.md): the machine, its limits and the
  recorded guest boots.
- [Guest loopback key-exchange record](experiments/2026-10-11-guest-pq-ssh-loopback.md)
  and its "What this does not establish" list.
- [`DEVELOPING.md`](DEVELOPING.md): how a change lands.
