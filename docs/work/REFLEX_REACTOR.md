# Local zero-wait reflex reactor

North star: edit C23, receive the first exact result that can change the next
action almost immediately, and keep working while stronger proof proceeds.
One warm local service owns the loop. `drive` is the compact human form:

```text
begin -> edit -> drive
```

The machine form is attach once and never block the agent's edit loop:

```text
begin -> dev loop events --after=<cursor> --format=jsonl
      -> edit -> continue thinking
      <- IMPACT_READY / COMPILE_GREEN / STORY_GREEN
      <- STORY_RED + zcl.dev_diagnostic_capsule.v1
```

Git, Make, a database, network I/O, publication, full links, full scans and
full-suite proof are behind the latency firewall. They may consume an immutable
candidate, but cannot be prerequisites for reflex feedback.

## Stage and authority contract

```text
EDIT_SEEN -> IMPACT_READY -> COMPILE_GREEN / COMPILE_RED
                              |
                              v
                       STORY_GREEN / STORY_RED       REFLEX
                              |
                              v
                       FOCUSED_GREEN / FOCUSED_RED   ASYNC PROOF
                              |
                              v
                         PROOF_PENDING               ACCEPTANCE
                              |
                        human approval
                              |
                              v
                        ZVCS evidence -> P2P publication
```

`SUPERSEDED` terminates obsolete work when a newer save arrives. Every event is
an observation about one immutable edit epoch, never approval or publication
authority. `dev loop wait` exposes every event. A normal `dev drive` consumes
the mechanical acknowledgements and returns the first action-changing
diagnostic/story for the new edit. `FOCUSED_GREEN` still keeps
`proof_complete=false`; only the conservative source-wide proof can create
reusable acceptance, and only a later human-approved ZVCS boundary may publish.
Verify mode never publishes a runtime.

## Why this owner

The frozen recent-history replay selected
`contexts/wallet/controllers/src/vault_intent_controller.c` as the highest-frequency
ordinary production owner (6 weighted edits), rather than choosing a toy file.
That controller mixed custody authority with a deterministic planning decision.
The refactor leaves parsing, wallet snapshots, coin reservation, persistence,
signing and broadcast in the static controller. Only the proposal moves to
`contexts/wallet/services/src/vault_intent_decision_service.c`:

```text
STATIC AUTHORITY SHELL                 PURE DECISION CORE
wallet/database/value authority  ---> immutable copied snapshot
                                      proposal-only decision
                               <---   no effect capabilities
```

Its five-case KAT is the smallest executable user story: current funds permit
an exact reservation, while stale money, bad fees, insufficient funds and the
development cap refuse. The candidate runs as `HOT_SHADOW` in a confined child
of the clean zygote runner against frozen fixtures. It cannot acquire wallet,
database, network, reducer, custody, supervisor, deployment or publication
authority.

## Before extraction: exact trace

The original ordinary-edit path took 12.677 s to its first green receipt. Tests
consumed 9.906 s, aggregate compilation 1.066 s and aggregate overlay linking
2.028 s. After the first stage split—but before this reactor—the same owner
reached candidate feedback in 2.463 s and five-group proof in 10.603 s:

| Work | Monotonic time | Processes |
|---|---:|---:|
| `EDIT_SEEN` | missed by latest-value polling | 0 |
| observable `IMPACT_READY` | 164.468 ms | 0 |
| path impact | 0.113 ms | 0 |
| closure snapshot | 20.263 ms | 0 |
| exact test selection | 207.636 ms | 0 |
| three incremental source guards | 98.428 ms | 0 |
| candidate + proof compiler startup/body | 12.232 / 1,009.205 ms | 4 |
| candidate + proof linker startup/body | 6.541 / 3,353.458 ms | 2 |
| test startup/body | 2.742 / 4,741.473 ms | 1 |
| bounded runtime probe | receipt-bound | 1 |

The exact selected groups were `test_db_migration_idempotent`,
`test_transaction_intent`, `test_wallet_funds_safety`,
`test_command_registry_catalog` and `test_command_input_bounds`; 71 broader
groups remained named. This trace identified polling, broad proof and process
setup as latency, not the 0.113 ms path rule itself.

## Implemented reactor

The resident watcher now keeps the last reconciled Merkle snapshot in memory.
One save hashes only known changed paths and creates an immutable epoch carrying
changed paths, previous/new SHA3 blob roots and sizes, owner/component,
dependency generation, sequence and parent epoch. No Git status or repository
inventory scan occurs on this path. A newer save constructs and publishes its
impact inside the old proof's cancellation observation, so process reaping
cannot delay the new epoch.

The progressive stream is a 64-slot bounded local ring ahead of an append-only,
SHA3-sealed journal. Ring publication has no fsync or storage acknowledgement.
After the action-changing event is visible, `flush-through` seals every epoch
in order; the journal remains evidence authority and restart recovery rejects
gaps or bad seals. Inside the watcher that seal is a request to one persistent
sealer child, so reading the next save never waits on journal fsyncs. A
backlog of more than 32 unsealed epochs, or a sealer that has exited, seals in
the watcher instead; a proof worker seals what was requested before it runs;
stop sends the sealer a stop request (so a forked copy of the pipe cannot
hold it open), lets it drain, and seals any remainder before reporting
stopped, exiting nonzero if that seal fails or cannot be checked. A sealer
that cannot be sent the stop request (its pipe is full) is killed after a
2 s wait. Only the stop request or pipe EOF stops the sealer (it ignores
SIGINT, SIGTERM and SIGHUP), and it keeps the watcher singleton lock until it
exits, so a watcher killed with seals still owed cannot be replaced until its
sealer has drained; a stopping watcher likewise releases the lock only after
its proof worker has exited (after SIGTERM and a 2 s wait it is killed),
and a proof worker is asked to cancel if its watcher dies. A
restarting watcher first seals valid ring events past the journal tail
instead of discarding them; a tail the ring has already overwritten is given
up with its epoch range logged, while a tail the journal cannot take (a full
or failing disk) refuses the restart. Journal events are staged and then
renamed into place without replacing anything (link then unlink where the
filesystem has no such rename), so a kill mid-write never leaves a torn
event; staging files left by a dead writer are swept under the cycle lock at
restart, or when one blocks the journal tail.
A direct journal write takes the ring's next epoch under the
seal lock while the ring is live (inside the watcher the sealer then seals
it), and ring publication is serialized by a lock on the ring file. `dev
drive` waits with inotify, closing the check/sleep race; there is no polling
sleep, and a sealer holding the cycle lock never delays it, because a busy
lock reads a sealed event file directly once the ring marks it durable.

The candidate builder keeps its frozen action/dependency plan and artifact
cache warm, invokes the compiler and module linker directly, then hands the
artifact to the clean zygote runner for the story. No command shell, Make
parser, test runner or full-program linker enters the reflex. Publishing a
candidate artifact (the worktree module copy and the host artifact-cache entry)
verifies its SHA-256 but never waits for a storage acknowledgement: every
consumer re-verifies the bytes, and a torn cache entry fails verification
instead of being served. On a host with busy disks those fsync calls had been
the largest single stage between a save and its story. Exact affected proof
starts only after the story. Scheduling remembers the prior failed exact group for the task,
then runs the goal story, cheap likely regression, direct owner invariant and
the complete affected batch; priority changes, required proof does not.

## Clean zygote runner

### Threat model

- **Attacker:** candidate native code in the confined leaf child, from the
  first ELF constructor that `dlopen` runs onward. It controls the leaf's
  whole address space, every byte it writes to the report pipe, and when and
  how the leaf exits.
- **Assets:** the verdict and every host-owned claim in it (image digest,
  confinement, descriptor and environment census, resident canary, process
  outcome, W^X layer count); the runner and resident processes; their
  descriptors; every other process on the host.
- **Trusted:** the resident, the runner, and the leaf child up to the instant
  before `dlopen`. Nothing the leaf says after that point is trusted.
- **Guarantees:**
  - Every host-owned claim comes from a fixed pre-load frame the leaf writes
    before any candidate byte is mapped, or from the runner's own
    observation: exit status, signal, deadline, and the leaf's final seccomp
    layer count read from `/proc/<pid>/status`.
  - The leaf refuses to map the candidate when any pre-load claim fails.
  - After `dlopen` the candidate contributes only one bounded observation
    frame, which is data. A second pre-load frame, a duplicate or malformed
    observation, an unknown kind, a wrong size, a missing frame or trailing
    bytes is RED with a named reason.
  - The candidate cannot signal, fork, exec, open sockets or files, create
    executable memory during its story, or outlive its deadline.
  - Descriptor hygiene uses `close_range`, falling back to a full
    `/proc/self/fd` enumeration. Where neither works it refuses. The census
    is the same full enumeration, never a bounded range.
- **Non-guarantees:**
  - A story verdict is a self-report. Candidate code can claim its own story
    or HOT_SHADOW frozen KAT passed, because both run in its address space.
  - The descriptor binding check and the W^X install run after constructors.
    A hostile constructor can bypass the binding check. It can also make its
    own executable memory before W^X exists, or replace the W^X layer with a
    decoy filter.
  - Descriptors a candidate opens die with the leaf. The post-story census
    that reports them is candidate-influenced data.
  - Side channels, CPU and memory pressure within the rlimits, and kernel
    exploits are out of scope.

The resident never forks itself to run candidate bytes, because a fork would
copy its heap, environment and descriptors into the candidate. On first use it
execs `/proc/self/exe` once as `z23-dev __reflex-runner`, with an empty
environment, stdio on `/dev/null` and exactly one extra descriptor: a
`SOCK_SEQPACKET` control socket at fd 3. It keeps that runner warm. The runner
sets `PDEATHSIG`, checks that its peer is its parent, sets `no_new_privs` and
closes every other descriptor. It never reads config, datadir or keys. Its
hello frame must report zero environment entries, zero extra descriptors and a
zeroed resident canary, or the resident refuses it.

For each candidate, the resident verifies the artifact SHA-256, copies it into
a sealed memfd (`WRITE|SHRINK|GROW`), and sends a fixed versioned request plus
that memfd over `SCM_RIGHTS`. The runner checks the seals, re-hashes the
image, then forks a disposable child. The child runs these steps in order:

1. Close every descriptor except the image and the report pipe, with
   `close_range` or, without it, a full allocation-free `/proc/self/fd`
   enumeration (`getdents64`). If neither works the child refuses.
2. Lower the rlimits and set `no_new_privs`.
3. Open the census directory, then enter Landlock deny-all, the seccomp
   session deny-list, and the runner and leaf layers. The runner installs its
   layer before it serves anything: io_uring, which could issue socket and
   connect past the syscall filter, plus pidfd, userfaultfd, kcmp,
   process_madvise, ptrace and process_vm_*. The leaf adds the kill family,
   pidfd_send_signal, setsid and setpgid. Then count every remaining
   descriptor through the census directory and close it.
4. Re-hash the image.
5. Write the **pre-load frame** and stop without mapping anything if any
   claim in it failed.
6. `dlopen("/proc/self/fd/N")`.
7. Add the W^X seccomp layer.
8. Run the `HOT_FORK` story or the `HOT_SHADOW` service probe, then write the
   **observation frame**.

The leaf reports on one pipe in exactly two fixed frames. Each starts with
magic, ABI, kind and size:

| Frame | Written | Carries | Trust |
|-------|---------|---------|-------|
| pre-load | before `dlopen` | confinement installed, the leaf's re-hash and digest, environment count, full descriptor census, resident canary, start and confine timings | host-owned claims |
| observation | after the story | story bit, descriptor binding, candidate-executed bit, dlopen and story timings, `HOT_FORK` observation, `HOT_SHADOW` service report | candidate-influenced data |

The runner reads the whole byte stream and parses it strictly: pre-load
first, observation second, nothing after. A missing frame, a second pre-load
frame, a duplicate observation, an observation before the pre-load frame, a
wrong size, an unknown kind, a wrong magic or ABI, a truncated frame or
trailing bytes is RED with a named reason. The runner adds what it saw
itself: exit status or signal, the deadline, and the exited leaf's
`Seccomp_filters` from `/proc/<pid>/status`. W^X counts as installed only when
that equals the runner's own count plus the three pre-load layers plus one.
At the deadline it kills the child with `SIGKILL`. That includes a child
that closed its pipe but has not exited by the same deadline, which is RED as
"leaf outlived its deadline after closing its report pipe". The runner
survives crashing children.

The resident checks every string and flag in the reply and both frames
before using any of them. Strings must be NUL-terminated inside their arrays,
digests exactly 64 lowercase hex, and flag bytes 0 or 1. A bad field is RED
and names the field. Environment facts come only from the pre-load frame and
the runner. GREEN needs well-formed frames, a clean exit inside the deadline,
the observed W^X layer, every pre-load claim, and a passing observation. Any
spawn, transport, seal, digest, framing or confinement failure is a named red
or unavailable result. There is no unconfined fallback.

Receipts add `runner:"zygote_exec"`, `env_inherited_count`,
`inherited_fd_count`, `address_space_fresh` and the stage timings. Windows and
macOS report the runner as unavailable. `make t-fast-exact
ONLY=reflex_runner` proves the runner with hostile fixture images:

- Environment, global, file, socket and parent-descriptor canaries, probed in
  the constructor and in the story.
- A regression goes red and leaves the last green root unchanged.
- An infinite loop and a `SIGSEGV` go red, and the same runner survives both.
- Socket and W^X attempts end in `SIGSYS`. So do `pidfd_open(getppid())`,
  `kill(getppid())`, and fork or execve from the constructor or the story.
- Before it serves anything, the runner forks one probe per surface under
  exactly the leaf filters: `io_uring_setup`, `pidfd_open` and `kill`. Each
  probe must die by `SIGSYS`. Otherwise the runner sends no hello, and the
  resident reports it unavailable.
- A digest mismatch fails closed.

## Dependency map and latency firewall

```text
REFLEX
  inotify -> resident path/blob epoch -> direct module compile/link
          -> zygote-runner HOT_SHADOW story -> volatile event

ASYNC PROOF
  exact path floor + code-index closure -> failure-first focused groups

ACCEPTANCE
  conservative source-wide compile + tests + lint-fast

PUBLICATION
  reusable proof -> human approval -> ZVCS receipt -> DHT/P2P workers
```

The audited reflex events carry explicit zero counters for Make, shells, Git,
publication, remote/network operations, storage-ack waits, SQLite, full-tree
scans and full-program links. Local candidate artifacts are content-addressed
inputs, not acceptance. The foreground has no call edge into ZVCS, DHT, P2P,
wallet or runtime activation.

## General development substrate

Recent-edit coverage is measured, not inferred, by `make
reflex-coverage-audit`. It freezes the most recent 100 production-C commits,
weights repeated edits as repeated occurrences, applies two distinct safe edits
to every registered fast owner, and records the first result-bound event plus
every fallback reason. `engine/composition/hotswap_shadow_owners.def` is the coverage map:
a static authority shell is compile-checked exactly, while only its declared
pure service core runs as `HOT_SHADOW`. `HOTSHADOW_SERVICE_MEMBERS` admits a
helper TU into executable candidate bytes only after the same no-state,
no-effects lint as the service itself.

Every `STORY_GREEN` contains a `zcl.dev_proof_handoff.v1` object with exactly:

```text
candidate_epoch + source_epoch
affected_component + affected_file_count
action + proof_inputs_sha3
compile_green + story_obtained + focused_evidence_sha3
```

That immutable value is the entire handoff to later server-side proof. It
carries no path capability, command handle, database handle, network handle,
or publication authority. Remote proof may append receipts later; it cannot
reach backward into the reflex lane or change an already emitted verdict.

## Reproducible measurement

Run `make reflex-reactor-bench`. It applies 20 randomized, distinct atomic
source edits plus one compile-valid behavior regression, uses one verify-only
watcher and one `drive` per edit, reads the exact sealed event range, restores
the source bytes and writes the ignored receipt
`build/dev-loop/reflex-reactor-benchmark.json`.

The final 21-edit run measured:

| Result | p50 | p95 | max | Gate |
|---|---:|---:|---:|---:|
| `EDIT_SEEN` | 13 us | 14 us | 16 us | <10 ms p95 |
| `IMPACT_READY` | 238 us | 302 us | 1.340 ms | <50 ms p95 |
| compile diagnostic | 61.631 ms | 67.090 ms | 68.838 ms | <250 ms p95 |
| green `HOT_SHADOW` story | 65.076 ms | 70.763 ms | 73.506 ms | <1 s p95 |
| edit to compact `drive` reply | 260.685 ms | 294.323 ms | 294.707 ms | measured |
| useful `STORY_RED` | 67.935 ms feedback | 286.265 ms wall | n/a | <1 s |

The run observed 21 each of `EDIT_SEEN`, `IMPACT_READY`, `COMPILE_GREEN` and
shadow forks, 20 `STORY_GREEN`, one `STORY_RED`, and 20 `SUPERSEDED`. Every
candidate was distinct: 21 compiler children, 21 module-linker children and
zero foreground test processes. Every firewall counter was zero.

The `<2% active-development time blocked` target requires longitudinal editor
telemetry and is not claimed from a synthetic 21-edit latency run. The reactor
now makes the necessary behavior true—proof is asynchronous and obsolete work
is cancelled—but that ratio remains a product/workload measurement, not a
fabricated benchmark result.

## Self-hosting safety

The pre-change binary remains trusted stage 0. A changed watcher, scheduler,
event system, loader, identity layer or proof router is only a stage-1 shadow
candidate until that saved stage-0 binary proves the final source. Candidate
KATs and focused tests cannot certify or replace the machinery that ran them.
