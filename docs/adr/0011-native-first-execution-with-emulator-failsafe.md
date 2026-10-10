# ADR-0011: Native-first execution with an emulator failsafe

- **Status:** Accepted 2026-10-10.
- **Deciders:** Project maintainer.
- **Partially supersedes:** [`ADR-0003`](./0003-os-substrate-verdict.md)'s
  rejection of any nested operating system, only for the deterministic
  emulator tier described below. The host kernel stays the scheduler, memory
  manager and security boundary for everything that runs natively.
- **Extends:** [`ADR-0004`](./0004-capability-service-fabric-and-app-checkpoints.md).
  Its native App process contract (static PIE generations from the private
  CAS, one descriptor-pinned `execveat`, `zcl.app.manifest.v2`) is Tier 0
  here. Nothing in this ADR changes ADR-0004's authority planes or rollout
  gates.
- **Related:** [`ADR-0002`](./0002-sealed-consensus-core.md). Consensus,
  wallet keys and signing, and publication signatures never run inside any
  tier described here.

---

## Context

Developers should be able to build applications from content-addressed
binaries fetched from peers, combine them, and run them at the same speed
as any other program on the machine. Three requirements pull against each
other:

1. **Speed.** Users run binaries at native speed. Emulation and binary
   translation always cost something, and hardware virtualization needs a
   host grant.
2. **Trust without a trusted builder.** A binary from a peer is accepted
   only when its bytes are proven, not because of who sent it.
3. **It always runs.** Some hosts lack the sandbox features native
   confinement needs, such as an old kernel or a platform backend that does
   not exist yet. Refusing to run there is safe, but it is not a product.

## Decision

### 1. Three execution tiers, chosen automatically, best first

| Tier | Path | Speed | Needs |
|---|---|---|---|
| 0 | Native process under the host OS sandbox | native | a working sandbox backend |
| 1 | Same-architecture guest under hardware virtualization | near native | an explicit user grant |
| 2 | Deterministic RISC-V emulator inside the binary | slower | nothing |

- **Tier 0** is the default. The binary runs as an ordinary process, and its
  instructions execute directly on the CPU. Confinement uses the host's
  unprivileged primitives: Landlock and seccomp-bpf on Linux, the sandbox
  profile on macOS, AppContainer with a job object on Windows, and Capsicum
  on FreeBSD. Sandbox setup is paid once at start. After that, only system
  calls see filter cost.
- **Tier 1** is optional. It runs a same-architecture kernel when the user
  grants KVM, Hypervisor.framework or WHP access.
- **Tier 2** is the failsafe. Its availability target is any host OS and
  any CPU with no root and no kernel features. A host counts as supported
  only after the emulator, its system-call layer and the same manifest pass
  there. It costs more, the way a relay costs more than a direct connection.

**Rule:** when no tier is available that confines the program, the program
does not run. A missing sandbox moves execution down the chain. It never
moves execution to unconfined native code.

The tier is selected before exec. After the program has started, or after
a launch whose outcome is unknown, there is no retry and no fallback, and a
grant is never widened silently.

### 2. Binaries are named by hash and verified by agreement

- Every build is bit-for-bit reproducible. Its inputs are the source roots,
  the target triple, path-neutral flags and the toolchain closure: compiler,
  assembler, linker, runtime objects and sysroot, each named by the hash of
  its bytes, not by a version string.
- A build action's identity is the hash of those inputs, and its result is
  an output root.
- Distinct nodes signing the same output root for the same action establish
  exact reproduction of those bound inputs under the receiver's policy. They
  do not establish safety or physical independence. The record reuses the
  signed proof ticket and the distinct-signer quorum already in the tree
  rather than adding a new one. A disagreement is preserved as evidence and
  never overwritten.
- Outputs are compared only for the same target. A riscv64 build is
  compared with other riscv64 builds, never with an x86-64 or arm64 one.
- Standard targets are x86-64 and arm64 for each supported host OS, plus
  riscv64. The riscv64 build is the universal copy that Tier 2 runs.

### 3. Applications are composed from hashed parts

An application is a content-addressed graph of components, edges and
per-component grants. Its root hash covers all three. Each edge is one of
three kinds:

- **Link:** static link into one native binary. Calls cost nothing.
- **Connect:** separate confined processes joined by typed channels. A
  channel can be a local socket pair, shared memory, or a mesh stream to
  another machine.
- **Load:** a library resolved by hash. This edge comes last, because
  in-process loading conflicts with per-process confinement and ADR-0004
  keeps third-party code out of Core.

Interfaces are typed contracts with an ABI hash. Composition checks them
before anything runs.

### 4. The emulator tier

- **ISA:** rv64gc, later with the vector extension. The vector length is
  pinned, and unordered reductions use a fixed order.
- **Time:** the emulator keeps three counters apart: the architectural
  retired-instruction count, a deterministic virtual time derived from it,
  and a host work budget. The work budget also bounds attempts that retire
  nothing, such as traps, repeated faults and device transitions. Waiting
  for an interrupt advances virtual time to the next event and never
  counts as retired instructions. Events are delivered at exact
  architectural boundaries. Host input enters only as recorded events at
  fixed points, so a run replays byte for byte on any host.
- **User mode first:** the emulator runs an application directly, and the
  binary itself answers the program's system calls, so no guest kernel
  boots. Kernel boots are exact-mode work and come later: a small real-time
  kernel first, then a FreeBSD kernel.
- **Exact mode:** the same machine settles disputed builds by replay. It
  also gives hard real time in logical time: a deadline is an exact
  instruction count, the same on every host. Wall-clock real time is a
  separate claim. It depends on host speed and on the scheduling grants
  below.
- **Licence:** all emulator code is Apache-2.0 and written in-tree.
  Permissive projects may serve as references. No GPL code is compiled or
  linked into the binary.

### 5. User grants

z23 probes for each grant and reports it. None is required.

- `RLIMIT_RTPRIO` and `RLIMIT_MEMLOCK` enable wall-clock real-time
  scheduling and locked memory.
- Isolated CPU cores and a preemptible real-time host kernel reduce jitter.
- Hardware virtualization access enables Tier 1.

### 6. Time

Every binary keeps disciplined wall-clock time without changing consensus
time rules:

- signed answers from several public Roughtime servers;
- peer exchange over the existing authenticated mesh;
- interval intersection that drops sources outside the agreement;
- a slewed offset over the monotonic clock, never stepped, and never written
  to the host clock.

## Order of work

1. Tier 0 runner on Linux: confined launch of a CAS generation, refusal when
   no confinement is available, and a measured overhead bound.
2. Reproducible builds: one translation unit on two hosts gives one object
   hash, then one whole binary, then the verified-by-agreement record.
3. Emulator failsafe: the core, then the A, C, F and D extensions, then the
   user-mode system-call layer, then running a riscv64 application under the
   same grants.
4. Composition: manifest exports and interfaces, then connect channels, then
   link edges.
5. Time service and the grant probe.
6. Exact mode kernel boots, Tier 1, and the macOS, Windows and FreeBSD
   sandbox backends.

## Consequences

- Native speed is the default, and a host without sandbox support still runs
  applications through the failsafe tier.
- Trust in fetched binaries comes from reproducible builds and agreement
  between nodes, not from a signing authority.
- The project now maintains an emulator. Its scope stays bounded: the user
  mode failsafe first, and kernel boots only for exact mode.

## Acceptance constraints

Numeric targets below are acceptance targets until measured. No speed,
confinement or determinism claim stands without a passing test
that measures it:

- **Tier 0:** a confined CPU-bound run stays within 5% of the unconfined run.
- **Tier 0:** a path outside the grant is refused.
- **Tier 0:** a missing sandbox refuses the launch.
- **Builds:** two hosts produce one output root.
- **Emulator:** it passes the official RISC-V conformance tests for each
  extension it claims.
- **Emulator:** two runs from the same inputs give byte-identical output and
  an identical final instruction count.
