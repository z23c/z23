<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# The built-in RISC-V machine

`z23-dev` carries a small RISC-V computer: one RV64 IMAFDC hart with
supervisor and user modes and Sv39 paging, an interrupt controller, a timer,
a serial console, a virtio block device and a device tree. It has no firmware
image; the host answers the supervisor's firmware calls. It is enough to boot
an unmodified FreeBSD 15.1 riscv64 kernel to a shell.

The machine reads no host clock. Its default and explicitly seeded test modes
read no host randomness; the development command can also explicitly request
host OS randomness. Guest time is the number of instructions retired. In
deterministic test mode, the same kernel, disk and inputs give the same console
output and counts; fresh host randomness is not a replayable input. The
module is `platform/modules/rvmachine`; its README states the machine
contract.

## Execution and transport boundaries

The guest is one execution option in the
[fleet operating contract](../work/AGENT_FLEET.md#consolidated-operating-model).
Native terminal access already has a separate `ops.mesh.terminal` owner:
its Linux worker confines a granted FreeBSD shell and refuses sockets.
OpenSSH integration and protected macOS terminal execution remain separate
qualification work. Native execution avoids instruction emulation but does
not supply a guest kernel boundary. Hardware virtualization is a separate option where supported
and qualified. None may fall back to unprotected execution.

A transport route and an execution environment are independent choices.
Direct authenticated connections, SSH tunnels, and embedded Tor must retain
receiver authorization, identity verification, revocation and resource limits.
An available Tor service is not evidence that a guest byte route is connected.
A successful host SSH session does not qualify guest SSH.

The native terminal worker and `app.run.confined` are different profiles.
The package runner refuses child processes and networking; it is not a general
development shell. The guest commands
below establish their stated boot, console, disk or snapshot behavior.
Persistent guest service ownership and cross-machine SSH require separate
acceptance, including initialized entropy, retained identities, wrong-key and
downgrade rejection, and recovery across disconnect and restart.

## Booting a kernel

```
z23-dev dev app machine boot --input='{"kernel":"KERNEL","max_instr":1000000000,"until":"mountroot>"}'
```

The command is `dev.app.machine.boot`; `z23-dev dev machine boot` is an alias
of it and takes the same input.

The input is one JSON object:

| key | meaning |
| --- | --- |
| `kernel` | path of the kernel, an ELF64 RISC-V image or a flat binary; exactly one of `kernel`, `accepted_kernel`, `public_kernel`, `protected_kernel` or `builtin_kernel` is required |
| `accepted_kernel` | installed Commons output selector: `datadir`, `package_root`, `output`, `max_artifact_bytes`, `max_verification_bytes`; all five fields are required, unique and typed |
| `public_kernel` | local copied-byte observation selector: `datadir`, `observation_root`, `max_artifact_bytes`, `max_verification_bytes`; requires the fixed PUBLIC unlock owner |
| `protected_kernel` | distinct fixed protected-image observation selector; requires `protected_unlock` and current local authority |
| `disk` | path of a raw disk image, attached as the virtio block device |
| `ram_mib` | RAM in MiB, an even number from 64 to 65536 (default 1024) |
| `bootargs` | the kernel command line placed in the device tree; at most 511 bytes |
| `max_instr` | work budget: retired instructions plus firmware calls plus device work (default 1000000000) |
| `type_after` | console script: an array of `[marker, text]` pairs; each text is typed once, in order, when the console output ends with its marker; an empty text only waits for the marker |
| `until` | stop the run when this text appears, after the last `type_after` step |
| `transcript` | path of a new file that receives every console byte |
| `test_entropy_seed` | a non-negative integer; attaches the virtio entropy device, fed by a fixed test stream derived from this seed (repeatable, not secure). Without it or `entropy` the machine has no entropy device |
| `early_seed` | `"test"`: enter an ELF kernel at its loader entry with a 2048-byte boot seed from a second test stream of `test_entropy_seed`, which must be given (repeatable, not secure). `"host"` requires `"entropy":"host"` and requests a fresh host OS boot seed |
| `entropy` | `"host"`: explicitly attach an OS CSPRNG-backed entropy device; mutually exclusive with `test_entropy_seed` |
| `ports` | one or two local test-fixture byte exchanges: each row contains a unique device `name`, read-only `input` file and exact `expect` reply file; all files together are limited to 64 KiB. Optional `after` requires an exact complete console line, including its final newline, before input is sent to an opened guest port |

### A protected host credential

Use `protected_kernel` with `protected_unlock` for the separate fixed protected
image. The kernel selector has the same four observation fields as
`public_kernel`; its image and evidence pins are different. Choose exactly one
kernel selector. PUBLIC profiles and their literal fixture credential are never
used by this branch.

`protected_unlock` requires `policy:"protected_host"`,
`purpose:"protected_geli_keyfile"`, `receiver_revision:1`, the exact
`authorized_kernel_sha256`, `mode`, `credential_mode`, and six distinct paths:
`volume`, `record`, `credential`, `extension`, `reserve_stage`, `ready_stage`.
The two stage paths must be fresh siblings of `extension` in the same directory.
For `mode:"initial"`, choose `credential_mode:"create_new_host"` to create a
new 32-byte host credential using the native OS RNG. All output paths must be
fresh. Creation never overwrites an existing credential or falls back after a
write, flush or readback failure. `existing_locked_host` instead uses an
existing private, current-user-only 32-byte credential.

`mode:"recover"` requires `existing_locked_host` and the retained volume,
record and READY extension. It reserves a new durable generation before guest
execution and attaches the existing GELI volume; it does not initialize or
format it again. An uncertain prior initialization or publication refuses
rather than silently restarting INITIAL. Preserve failed evidence for
reconciliation.

The invocation checks current owner authority before execution and delivery.
A retained READY record describes the observed identity; its checksum is not
an unlock grant. Credential delivery is single-use for that generation, with
separate delivery and authority deadlines. The host can inspect guest memory;
this is not an HSM boundary. This development entry does not yet supply retained
automatic-start configuration across host restart, deployment, or PQ transport
acceptance. Those remain separate required product acceptance.

Protected refusals may report `phase=N format_dispatch=F format_return=R`.
`N` is the queued phase (step minus one); `F` is cumulative work at formatting
dispatch, and `R` is a returned-drive upper boundary after accepted formatting
completion and next enqueue. These are historical observations, not exact
formatter retirement or identity readiness. Missing observations are `unknown`;
invalid bindings are `unavailable`. No private bytes or paths are reported.
The suffix is omitted if it cannot fit without truncating established fields.

### An installed kernel output

`public_kernel` is restricted to the fixed PUBLIC unlock pilot. It selects an
unsigned observation in the existing local CAS; the owner independently fixes
the allowed image SHA-256 and byte length. The reader checks the observation,
image and three opaque evidence objects within the supplied byte budgets.
The existing CAS loader may retire a verified legacy staging alias; this is
not a read-only namespace operation. The budgets bound object payload reads.
The owner checks its copied image and current policy before starting the guest,
delivering the PUBLIC credential and accepting the attach result. This is not
an installed package, a license audit, independent reproduction, private key
custody or SSH readiness. The original provenance, license and source
inventories remain opaque evidence. An observation alone grants no execution.

PUBLIC owner refusals report whether fixture files were created, the last
observed lifecycle state and reason, script step, and cumulative guest work.
They omit console bytes and credential paths. A failed invocation can leave
its isolated volume and credential behind; preserve them as failure evidence
and use fresh destinations for a new initial invocation.

Between manager drives, the retained-volume storage observation requires a
successful backend flush after the latest successful write for the current
instance. A later write invalidates it; failed I/O and ordering overflow refuse.
This observation alone does not establish a mounted filesystem or guest key.

The default PUBLIC owner profile remains the attach-only fixture. Explicit
`public_unlock.profile_revision: 2` selects the fixed `db2440` image and its
separate enrollment policy. Initial mode creates a guest Ed25519 identity on
the encrypted volume, checks its permissions, unmounts and flushes it, and
reads back its public identity from a read-only mount. Recover mode requires
the existing volume and enrollment record; it never formats, repairs or
regenerates a key. Both modes retain the service's 120-second startup deadline
and require each command's successful status from the current instance and
port epochs. The owner's outer 240-second loop bound does not extend that
startup deadline. Instruction work and elapsed startup time are separate
limits; a startup-deadline refusal can occur below the work budget.
After the fixed attach helper succeeds, profile 2 uses the guest shell's
character-device check for `/dev/vtbd0.eli`, avoiding another utility launch.
This checks provider presence only; the helper's successful attach remains
required and the check grants no filesystem, identity, or durability credit.

A successful profile 2 result includes `ssh_fingerprint_sha256` and
`ssh_public_key_wire_base64`. `identity_ready` records that identity verification
and manager readiness were observed before the command joined and destroyed
its guest. It does not describe a running SSH service or an authenticated
tunnel. This remains a PUBLIC test-credential fixture. A failed or late
operation can leave an enrollment record on disk; failure is not rollback.
Refusal evidence includes `p7=dd:newfs`: each bit records a successful fixed
filesystem-preparation step. These observations grant no completion or readiness
credit; zero means the corresponding success marker was not observed.
Before formatting, two checked writes authenticate 4 KiB pages 2–3 and 15–17
of the fresh GELI provider. These cover the pinned formatter's old-superblock
and recovery-area reads, and the mount superblock read. Other unwritten sectors
retain authentication failure; this preparation is not full-volume erasure.
Explicit `public_unlock.profile_revision: 3` selects the separate `ac1dd2`
image. Its `geli-bootstrap-public --public-initial-prepare` command moves
these same five page writes and two flushes into the fixed helper after attach
proof. It confines descriptor rights and retains the helper's original deadline;
the no-argument path performs no preparation I/O. Shared-body host controls do
not qualify FreeBSD confinement or guest execution. Native FreeBSD/RISC-V
compilation and image assembly passed; actual V7 INITIAL/RECOVER remains
unqualified. The owner requires a unique preparation-complete marker from the
current phase, instance and console epochs before accepting INITIAL attach
success. RECOVER uses the no-argument helper and rejects that marker.
Profile 2 keeps its original image, commands, and enrollment identities.
Explicit profiles 4 and 5 select a new paired kernel build using the same
prepared helper and filesystem as profile 3. Profile 4 binds baseline image
`fca910590d9b3171712883285fb30743b30f7715a4b8fb41c17a51bfdcca6a6e`
(43,408,024 bytes); profile 5 binds Zbb image
`c7df418c75c63125a6ea77edba7b654486c5912bc1fd60c53fcc39778dbb1bf7`
(43,406,744 bytes). Each has separate enrollment and grant labels, exact
capture evidence, and kernel PC ranges. The Zbb SHA object uses unchanged
upstream source with an additional compiler ISA flag. The paired link and
strip checks preserve each image's loaded bytes and filesystem; they do not
qualify boot, performance, SSH, or INITIAL/RECOVER. Both profiles retain
profile 3's preparation requirements and attach-only RECOVER commands.
Profile 6 binds combined portable-plus-Zbb image
`82d6598d9669339eb9890d9c8b5152597beac22cbfc5c86200a23f1dc2cd3562`
(43,412,608 bytes), with distinct enrollment and grant labels and kernel PC
ranges. Its capture retains the actual portable SHA source change, complete
changed translation unit, and additional attribution alongside the V7 source.
The candidate link reuses the verified baseline and embedded filesystem;
strip checks preserve its loaded bytes. Isolated SHA parity and instruction
measurements do not establish whole-kernel performance, boot, SSH or recovery.
Profile 6 retains the same preparation and attach-only RECOVER requirements.
Profile 7 binds image
`f7e7379fb08fd0035cf67bd98d5896376e103ab80851363d2c1f1a16a53e675d`
(43,412,608 bytes) to its own enrollment and grant labels. Its filesystem
`9541a135ed646af120c182fb19b7586a8f3ead63b1edd1cc880d8f584c674cac`
uses the same prepared helper and replaces only the SSH library with the
qualified Ed25519 `-O3` object build. This is a new deterministic filesystem
action with fixed time 1791773063; two baseline assemblies match exactly.
It does not reproduce the historical filesystem bytes. The paired kernel
build preserves profile 6's non-filesystem code, program headers, and dynamic
dependency name. Capture preserves the upstream source and licenses and adds
the exact new build provenance. Boot, SSH, identity creation and recovery
remain unqualified. Preparation, recovery commands and boot limits are unchanged.
Profile 3 does not emit the profile 2 phase-7 preparation diagnostics below.
Its `newfs=1` observation means the formatter succeeded before mounting began;
`newfs=0` means that success marker was not observed. Neither grants readiness.
During profile 3 INITIAL formatting, `d=` records cumulative work when the
format command was queued, while `k=` samples returned kernel PCs and `g=`
records observed formatter geometry. Sampling requires the same instance and
both console epochs as dispatch, completed helper preparation, and an exact
image binding. Unknown or invalid observations remain visibly unavailable.
These measurements do not identify the cost of an individual syscall. The
kernel outside the embedded root, its program headers, and the formatter
bytes match the retained profile 2 image; only its helper was replaced.
`work=retired/fw/device` retains the last returned cumulative counters.
Profiles 3–6 INITIAL refusal diagnostics at script step 8 add
`dispatch[0..7]=W0:...:W7` to the explanatory error message. Each entry is
the checked sum of retired instructions, firmware calls, and device work
from the latest actual returned result when that phase command was queued.
The producing result and enqueue must share a machine, instance, and both
console epochs. Each entry has its own epoch binding; the eight phases need
not share epochs. A no-run result retains the prior observation and its
original binding. Only successful INITIAL enqueues are observed.

At script steps 9–17, the message instead reports
`phase=N dispatch=W format_dispatch=F`, where `N` is the latest queued
phase (step minus one), `W` is its cumulative dispatch work, and `F` is
phase 7 formatting dispatch work. This includes the key-generation enqueue
at phase 9. The same binding and validity rules apply; these values do not
prove that the queued command completed.

`unknown` means no boundary observation was captured. `unavailable` means
the observation failed its binding, checked-sum or monotonicity checks, or
does not fit 32 bits. An attempted boundary is never retried. Numeric
differences are meaningful only for valid entries from the same retained
machine and instance; never treat unknown or unavailable entries as zero.
Phase 7 marks formatting dispatch, so phase 7 minus phase 6 includes the
attach helper, its preparation, and shell overhead rather than isolated
write cost. These are cumulative boundaries, not phase-completion proofs.

The message uses at most 183 bytes of its 192-byte field. Existing
256-byte refusal evidence, including `work`, `k`, `g`, `newfs`, `d`, and the
profile 2 `a` bracket, is preserved. The trace adds no completion, recovery,
deadline, or budget authority.

Within the fixed PUBLIC profile 2 INITIAL phase-7 scope, `a=dispatch:lower:upper`
records cumulative work after preparation is queued and bounds work across
the returned slice containing the first `P7A`. The dispatch and crossing must
share a machine, instance, and both console epochs. Subtracting dispatch bounds
preparation plus shell overhead, not isolated disk-write cost. Reported values
must fit 32 bits in ascending order; wider observations report unavailable.
Both totals use checked addition and require a prior actual returned result,
positive work, and unchanged instance and console epochs. This is a slice
bracket, not the exact marker cost. `a=unknown` means no crossing was captured;
`a=unavailable` means its observation was refused and cannot be retried.
For the fixed PUBLIC profile 2 INITIAL image, phase 7 can also report
`k=bucket:matched/total u=unknown`, selecting the highest-count matched kernel
bucket. Each sample is the hart's stop location
after a positive-work governed slice, with the same guest instance and both
console epochs before and after the slice, between the two preparation markers.
Bucket IDs name exact kernel symbol intervals: 1 SHA256, 2 AES, 3 GELI run,
4 GELI write completion, 5 GELI read completion, 6 BIO delivery, 7 virtqueue
poll, and 8 other declared kernel executable ranges. Bucket 0 means no matched kernel
sample. Unknown samples remain in the total; they do not identify a userspace
process. These counts are observations, not execution-cost percentages.
Profile 7 INITIAL formatting may append `p=UUUU/SSSS/MMMM/XXXX`: four
hexadecimal returned-slice sample counts for U mode, S mode, M mode, and an
unknown privilege value, in that order. The actual hart PC must match the
returned result, with the same owned machine, instance and both console
epochs. This reads architectural state; it does not read guest memory or
guess the relocated executable or library owning a userspace PC. Counts do
not measure retired-work share, elapsed time, or process attribution.
Overflow, mismatched observations or inconsistent counts report
`p=unavailable`. An absent `p` field is unavailable, including when the whole
suffix cannot fit without truncating established evidence. Existing `k`,
`u`, `g` and dispatch fields retain their meanings. Recovery and old profiles
do not emit this field; the 600m work cap and 120s startup deadline are unchanged.
After successful formatting completion, Profile 7 INITIAL may instead append
`p7priv=UUUU/SSSS/MMMM/XXXX` to a later refusal. This preserves the formatting
counts at the actual phase 7 to 8 command transition, bound to its completed
dispatch, exact image, machine, instance and both console epochs. It uses the
last qualified returned-slice observation. The snapshot survives intentional
manager teardown, including an automatic stop; it is historical evidence,
not current authority or a final stopping-slice observation. Live validation
before and after a drive and before join makes observed binding changes
permanently unavailable. It does not sample later key generation or replace
the current formatting `p` field. Missing completion or history, changed
image or completed dispatch, overflow or inconsistent counts are unavailable;
`p7priv=unavailable` or an absent field provides no privilege attribution.
Slice-end sampling is biased by slice boundaries and is not a work share,
elapsed-time measurement or process identity. Existing caps remain unchanged.
An inconsistent or overflowing counter reports `k=unavailable`. Recovery,
private images, and later key-generation phases do not expose this summary.
In the same scope, `g=groups:blocks_per_group:inodes_per_group` records the
fixed formatter's planned geometry from one complete console line. Each field
is bounded to 1–65535. Duplicate, malformed, or larger observations report
`g=unavailable`; an absent observation reports `g=unknown`. Output buffering
can delay this line, so absence does not establish failure to plan the geometry.
These counts prove neither completed writes nor successful filesystem creation.

`accepted_kernel` selects an already installed output by its package root and
receipt-declared relative path. It never reconstructs a native executable path
or fetches, builds or installs a package. The explicit development boot request
authorizes this bounded guest invocation; a stored package or reader handle
alone grants no execution authority.

```json
{"accepted_kernel":{"datadir":"<isolated Commons context>","package_root":"<64 lowercase hex digits>","output":"<declared relative output>","max_artifact_bytes":67108864,"max_verification_bytes":268435456},"ram_mib":64,"max_instr":100000}
```

The artifact limit is positive and at most 1 GiB and `SIZE_MAX`. The verification
limit is positive and at most `INT64_MAX`; JSON integers use the existing signed
parser. The command allocates the explicit artifact capacity, rather than an
unbounded file size. Opening accounts for every declared output plus its EOF
probe and the selected retained pass. Each subsequent verified copy reads at
most the selected declared size plus one EOF probe; this command copies once
before loading and once after running. Receipt parsing has separate existing
caps. Both selectors, unknown fields, null limits and invalid types refuse.

The same retained regular-file handle supplies the image. Current receipt,
dependency lock, copied-byte digest and descriptor checks run before loading
and again before reporting success. A later refusal cannot retract guest work
already performed. `inputs.accepted_kernel` identifies the selected root/path,
original copied SHA256, byte count, allocated capacity and final qualification;
it is not a self-contained accepted-receipt projection. Installed namespace
replacement is not historical immutability. Existing path-based inputs retain
their original checks, and transcript creation still refuses existing files.

This proves installed-output binding at those checks, not FreeBSD recipe
correctness, RV64 compilation/reproduction, persistent failsafe readiness,
protected identity unlock or deployment. The isolated acceptance fixture uses
a deliberately binary PUBLIC `kernel.h` through the existing copied-header
rail; its native C23 library/test never includes that nonusable header. The
real publish/plan/commit receipt proves copied declared bytes, not a compiled
RV64 kernel.

Byte fixtures are inert files, not attached host network routes. The guest must
receive every offered byte, repost its receive descriptor to establish driver
consumption, and return exactly the expected bytes. A console marker alone
cannot satisfy the exchange. Driver consumption is not an application ACK.
Changed inputs, reset epochs, mismatched replies, missing readiness, or an
exchange exceeding its cumulative work budget fail. These tests do not qualify
FreeBSD raw mode, authenticated peer framing, real entropy, or guest SSH.

The work a run may do is bounded by one number:

```
work = retired + fw_calls + device_work
```

`device_work` is the disk data the block device moved for the guest, read or
written, and the entropy the entropy device delivered to it: one unit per
started 4096 bytes moved by each queue notification or service round. A guest
can therefore not make the host copy device data, or answer firmware calls,
for free: every one of them uses up `max_instr`.

## An interactive shell

```
z23-dev dev app machine shell --input='{"kernel":"KERNEL","disk":"DISK","bootargs":"-s vfs.root.mountfrom=ufs:/dev/vtbd0p3"}'
```

`dev.app.machine.shell` boots the same machine and connects its console to the
terminal that runs the command. It needs no script and no transcript: what the
caller types is the guest's console input, and what the guest prints appears
on the terminal. With the FreeBSD 15.1 images the guest comes up in
single-user mode at a `#` prompt; `halt -p` powers it off.

| key | meaning |
| --- | --- |
| `kernel` | path of the kernel, required |
| `disk` | path of a raw disk image, opened read-only; guest writes stay in memory |
| `ram_mib`, `bootargs` | as for `dev.app.machine.boot` |
| `max_instr` | optional work cap, counted as for `dev.app.machine.boot`; without it a session has no cap |
| `escape` | the control key that prefixes a session command: one letter of either case, or one of `\ ] ^ _`, default `]` (Ctrl-]). The letters `h`, `i`, `j` and `m` (backspace, tab, line feed, carriage return) and every other character, `@` and `[` included, fail as `INVALID_INPUT` |
| `stdio` | `"pipe"` connects stdin and stdout as plain byte streams; without it both must be terminals, else the command fails as `NOT_A_TERMINAL` |
| `eof_quiet_ms` | pipe mode: after stdin ends, the session ends once the console has printed nothing for this many milliseconds (default 5000) |
| `receipt` | path of a new file that also receives the result; an existing path fails as `RECEIPT_UNWRITABLE` |

The escape prefix followed by `q` ends the session. The prefix twice sends one
prefix byte to the guest; the prefix followed by any other byte sends both
bytes. A prefix at the end of input is sent as itself.

On a terminal the command puts stdin in raw mode, so every key, Ctrl-C
included, goes to the guest, and restores the original settings on every exit
the command controls: the guest powering off, the escape, end of input, an
error, and SIGINT, SIGTERM, SIGHUP or SIGQUIT (these only set a flag, and the
session then ends as `signal`). A stop signal (SIGSTOP, SIGTSTP) leaves the
terminal raw while the process is stopped, and a fatal signal that cannot be
caught (SIGKILL, or a crash such as SIGSEGV) leaves it raw for good; `stty sane`
repairs it. If the restore itself fails the result says
`TERMINAL_RESTORE_FAILED`. SIGPIPE is ignored during the session and every
signal disposition is put back afterwards. The window size is not forwarded. Pipe
mode is the form for scripts and tests: bytes from stdin go to the guest, the
guest's bytes go to stdout, and the session ends when the guest powers off,
when stdin has ended and the console has been quiet for `eof_quiet_ms`, at the
cap, or on a signal. A session that ends by signal, work cap or end of input is
not a failure: the status is `passed` and the exit code 0, and only the `end`
member tells these apart from `guest_shutdown`. Input is queued to the guest
console only while the guest's serial queue (4096 bytes) has room. A guest that
reads its console through the firmware call alone and never from the serial
port does not drain that queue, so after 4096 input bytes the command reads no
more input from it; FreeBSD reads the serial port.

The run is interactive and not deterministic. The entropy device and, for an
ELF kernel, the 2048-byte boot seed come from the host OS CSPRNG, never from a
test seed; a failure of that source ends the run as `ENTROPY_SOURCE_FAILED`.
A flat image has no loader entry to take a seed and gets the device only.
Guest time follows retired instructions while the guest runs. While it waits
for its timer or for input, the command sleeps in the host until the timer,
input or 100 ms, and then moves guest time forward by the host time that
passed, never beyond the armed timer, so guest timers keep real-time pace and
an idle guest costs almost no host CPU.

Stdout carries only the console bytes. After the session the command prints
the result envelope on stderr (on a terminal a line break is added first if
the console output did not end with one). It marks the run
`"interactive":true,"deterministic":false`, states `"guest_exit":"unobserved"`
(console end, quiet output and power-off carry no guest exit status, so none is
reported) and reports `end` (`guest_shutdown`, `guest_reboot`, `escape`, `stdin_eof`,
`signal`, `work_cap`, `guest_fault` or `error`), the retired, skip, firmware
call and device work counts, `bytes_in` and `bytes_out` on the console, and the
entropy source. The `verdict` member holds `status` (`passed` or `failed`) and
the error `code` (empty when passed), so the data alone says whether the
session was clean. `receipt` writes the same data to a file, so a script can
read it without capturing stderr; a receipt is not left behind when
the terminal or signal setup fails. A console output that cannot be written
(a closed pipe) ends the session as `error` and fails it as `SESSION_FAILED`,
also when the guest powered off in the same step. The command is reachable only
as a one-shot `z23-dev` call; no resident process dispatches it, and it refuses
input that was itself read from stdin (`--input=-`) as `INPUT_ON_STDIN`. The
tests are the group `dev_machine_shell`.

## Entropy

For a qualified isolated guest image, request host entropy explicitly:

```bash
z23-dev dev app machine boot --input='{"kernel":"QUALIFIED_KERNEL","ram_mib":1024,"bootargs":"-s kern.random.initial_seeding.bypass_before_seeding=0","max_instr":1000000000,"entropy":"host","early_seed":"host"}'
```

`QUALIFIED_KERNEL` is a placeholder, not an accepted image receipt. This command
runs immediately in the development lane; it does not install a product profile
or activate a service. Inspect the image startup behavior before running it.
Host-source failure clears the requested buffer and never falls back to a test
stream. Boot-seed failure refuses loading with `MACHINE_REFUSED` in phase `load`;
entropy-device source failure stops execution with `ENTROPY_SOURCE_FAILED` in
phase `run`. Receipts name
`host_os_csprng` and report `guest_rng_health` as `unobserved`: delivering
random bytes alone does not establish guest initialization or safe key generation.
Before generating even disposable keys, observe the actual guest seeding/bypass
state and a bounded successful initialized random-device read. The host can
inspect emulator RAM; this is not an HSM boundary.

Retained automatic-start configuration for protected guest identities is not
exposed by this development command. Disposable storage
tests do not qualify production key persistence or recovery.

The machine itself has no source of randomness and reads no clock. Its
entropy device exists only when the embedder gives it a source, and hands the
guest that source's bytes and nothing else. The command offers two explicit sources: `test_entropy_seed` for public
deterministic tests, and `entropy` set to `"host"` for fresh host OS CSPRNG bytes. Block `i` of the public test stream is

```
sha256("z23 dev.app.machine.boot test entropy v1" || le64(seed) || le64(i))
```

so anyone who knows the seed knows every byte the guest will ever read. A
seeded run is for tests and replay only and gives the guest no secret: keys a
guest generates in such a run are test keys. The receipt says so in
`data.entropy`: `source` is `test_seed`, `secure` is `false`, and `bytes`
counts what the guest was given; a seeded run that fails says it in
`error.current_state` (`... entropy=test_seed,not_secure`, or
`... entropy+early_seed=test_seed,not_secure` with the boot seed below). A
run without either source has no entropy device and no `entropy` member, and is the
same run as before the device existed. Like the rest of the command, the key
exists only in the development build: a release build lists the command and
runs nothing.

### The boot seed

The entropy device is found late in a boot. A FreeBSD kernel first uses
randomness much earlier, and seeds its random device before that only from a
module its boot loader preloaded (type `boot_entropy_platform`); nothing
handed over through the firmware entry or the device tree is read. Without
such a module the kernel says so and goes on unseeded:

```
random: no platform bootloader entropy
arc4random: WARNING: initial seeding bypassed the cryptographic random device because it was not yet seeded and the knob 'bypass_before_seeding' was enabled.
```

With `"early_seed":"test"` the machine enters the kernel the way that loader
does (at the ELF entry, with the loader's list of modules in `a0`) and
preloads 2048 bytes, the size the FreeBSD loader itself passes. Block `i` of
the 64 blocks is

```
sha256("z23 dev.app.machine.boot test early seed v1" || le64(seed) || le64(i))
```

with the seed of `test_entropy_seed`. The label puts this stream in a domain
of its own, distinct from the entropy device's stream (the two are separate
hash inputs; equal byte values can still occur), and it is exactly as public. The
receipt names it in `data.early_seed`: `source` (`test_seed`), `secure`
(`false`), `bytes` (2048) and `cleared`, which is true once the guest has
overwritten the whole seed in its memory with zeros, as the kernel does when
it has taken it. The kernel must be an ELF image with an entry point inside
its executable code; a flat image is refused (`MACHINE_REFUSED`, phase `load`,
"the kernel image has no loader entry to take a boot seed").

The test boot seed is public. With both `"entropy":"host"` and
`"early_seed":"host"`, the command instead requests a fresh 2048-byte host OS
seed through the same boot-seed interface. A source that gives no bytes, too
few, or fails stops loading before the guest starts; no test fallback is used.

The inputs are opened read-only, without following a final symbolic link, and
are never written: what the guest writes to its disk stays in memory and is
gone when the run ends. The transcript is created only after the inputs were
identified, and never over something that exists: a path that already exists
is refused, whatever it is (a symbolic link is not followed), and a path or
hard link that is the kernel or the disk is refused by that name. No node
data directory and no network is used.

## The receipt

A caller can rely on two shapes. A run that reached its goal is a passed
result whose `data` carries:

| field | meaning |
| --- | --- |
| `stop` | `requested` (the `until` text was seen), `shutdown`, `reboot`, `idle` or `budget` |
| `marker_seen` | whether the `until` text appeared |
| `retired` | instructions retired |
| `skip` | time units fast-forwarded while the hart waited for its timer |
| `fw_calls` | firmware calls answered; a firmware call does not count as retired |
| `device_work` | disk and entropy data moved, in units of 4096 bytes (see the work formula above) |
| `entropy` | present with either entropy source: `source`, `bytes` and `source_failed`; test streams have `secure:false`, host streams have `guest_rng_health:unobserved` |
| `early_seed` | present when requested: `source`, `bytes` (2048 on success) and `cleared` (the guest zeroed the seed); test streams have `secure:false`, host streams have `guest_rng_health:unobserved` |
| `guest_time`, `timebase_hz` | `retired / 10 + skip`, at 10 MHz |
| `reset_type`, `reset_reason` | the guest's own values; present only when `stop` is `shutdown` or `reboot` |
| `console_bytes`, `transcript_sha256` | length and SHA-256 of everything the guest printed |
| `script_fired`, `script_total` | `type_after` steps typed, of those given |
| `ram_mib` | RAM the machine was built with |
| `overlay_blocks` | 4 KiB disk blocks the guest wrote (kept in memory) |
| `inputs.kernel`, `inputs.disk` | `size`, `mtime`, `mtime_nsec` and `changed`, read from the open file before and after the run; `inputs.disk` only when a disk was given |
| `console_tail` | the last printed bytes (at most 256), for a quick look |

For deterministic test inputs, compare receipts, not exit codes: two hosts agree when `retired`, `skip`,
`fw_calls`, `device_work` and `transcript_sha256` are equal.

Every other outcome is a failed result: a nonzero exit, no `data`, and an
`error` object with a stable `code`, a `phase` and a `message`.

| `error.code` | `phase` | when |
| --- | --- | --- |
| `INVALID_INPUT` | `input` | a key is missing, mistyped or out of range |
| `ENTROPY_SOURCE_FAILED` | `run` | the explicit host source failed; guest execution stops without fallback |
| `SEED_SOURCE_NOT_OFFERED` | `input` | `early_seed` asked for `host` without `entropy:host` |
| `INPUT_UNREADABLE` | `open`, `read` | the kernel or disk is missing, empty, not a regular file, or reached through a final symbolic link |
| `MACHINE_REFUSED` | `disk`, `create`, `load`, `run` | the machine refused the disk size, the RAM size, the kernel image or the run |
| `TRANSCRIPT_IS_AN_INPUT` | `open` | the transcript path is the kernel or the disk, by path or hard link |
| `TRANSCRIPT_EXISTS` | `open` | something already exists at the transcript path, a symbolic link included |
| `TRANSCRIPT_UNWRITABLE` | `open` | the transcript could not be created |
| `GOAL_MISSED` | `run` | a `type_after` marker or the `until` text never appeared, including when the budget ran out first |
| `GUEST_FAULT` | `run` | the guest could not continue |
| `CONSOLE_LIMIT` | `run` | the guest printed 64 MiB; the run was stopped at that byte |
| `INPUT_CHANGED` | `verify` | the kernel or the disk changed during the run: its size, modification or change time, or identity |
| `TRANSCRIPT_WRITE_FAILED` | `write` | the transcript is incomplete |
| `OUT_OF_MEMORY` | `setup` | the host could not provide the memory |

Five codes (`GOAL_MISSED`, `GUEST_FAULT`, `CONSOLE_LIMIT`, `INPUT_CHANGED`,
`TRANSCRIPT_WRITE_FAILED`) happen after the guest ran, so they still hand
over the receipt: `error.current_state` is the `stop` name (`fault` for a
guest fault) and `error.evidence` is one line of `key=value` pairs in this
order: `stop`, `marker_seen`, `retired`, `skip`, `fw_calls`, `device_work`,
`console_bytes`, `script` (fired/total), `sha256`, and for a guest fault
`pc`, `cause` and `tval`. A failure in any phase other than `run`, `verify`
and `write` started no guest and created no file.

## FreeBSD 15.1 riscv64

No kernel or disk image is kept in this repository. The first two inputs are
the published FreeBSD 15.1-RELEASE riscv64 artifacts: the GENERIC kernel from
the release kernel set, and the release UFS virtual machine image,
decompressed to a raw file.

| input | bytes | sha256 |
| --- | --- | --- |
| KERNEL: release GENERIC kernel | 62745584 | `69320e312d5601c5fe228aa3bcbdc4bbc55e0d86a4cf9e68eb6ffdc7247701b1` |
| DISK: release UFS image, raw | 7550318080 | `084980a2299d2a8bca7033fc4eefcc8e22b64096e7952ce63366d8408605ff15` |
| EMBEDDED: a GENERIC kernel with a small root file system built in | 43331264 | `fd7773e9e867e85a571235bf6c83a99f8242718eb3b49a1095d66a720babbba9` |
| SOURCE: a kernel and embedded root built entirely from the 15.1 sources | 43331264 | `4560d264f2696b398645ddc078349426051a6746c0394e9d90ff0c0c3ed7f239` |
| DEVICES: the SOURCE build with the virtio entropy and console drivers added | 43347880 | `1365caefc0254a3a3575b32d01bd859e0243e825d33d03202f7d29550b1b30df` |

EMBEDDED, SOURCE and DEVICES are local builds; their hashes name the exact files the
numbers below were measured on, and a rebuilt kernel gives its own numbers.

Runs A and B are guarded by the registered group `rvmachine_freebsd_release`;
runs C to E remain an operator recipe. The groups `rvmachine` and
`dev_machine_boot` run only the small guests committed under
`tests/fixtures/rvmachine`, so they need no kernel, no disk image and no
RISC-V toolchain.

The group runs when `ZCL_TEST_FREEBSD_RELEASE_KERNEL` names the KERNEL file:

```
ZCL_TEST_FREEBSD_RELEASE_KERNEL=/path/to/kernel \
ZCL_TEST_FREEBSD_RELEASE_DISK=/path/to/disk.raw \
  make t-fast-exact ONLY=rvmachine_freebsd_release
```

Each file is checked against the size and sha256 in the table above before
anything boots. A variable that is set but names a path that cannot be read
fails the group. A readable file of another size or sha256 is reported as
unobserved, neither passed nor failed; a different disk leaves only the
single-user shell case unobserved, and a different kernel leaves the whole
group unobserved. With the kernel alone the group runs run A and asserts that
the root mount prompt appears within 1,000,000,000 retired instructions. With
the pinned disk as well it also runs run B and asserts that the transcript
contains `15.1-RELEASE`, `GENERIC riscv` and `hw.ncpu: 1` within 2,000,000,000
retired instructions, and that the disk file's size, modification time and
inode are unchanged afterwards. The disk's sha256 is taken before the run only;
the command keeps guest writes in an overlay and never opens the disk for
writing. With neither variable set the group is unobserved. The group takes
about two minutes, most of it hashing the disk.

Run A, kernel to the root mount prompt:

```
z23-dev dev app machine boot --input='{"kernel":"KERNEL","max_instr":1000000000,
  "until":"mountroot>"}'
```

Run B, kernel and release disk to a single-user shell:

```
z23-dev dev app machine boot --input='{"kernel":"KERNEL","disk":"DISK",
  "bootargs":"-s vfs.root.mountfrom=ufs:/dev/vtbd0p3","max_instr":2000000000,
  "type_after":[["RETURN for /bin/sh:","\n"],["# ","uname -a\n"],
    ["# ","sysctl hw.machine hw.ncpu hw.physmem\n"]],
  "until":"# "}'
```

Run C, the embedded root, shell built-ins only:

```
z23-dev dev app machine boot --input='{"kernel":"EMBEDDED","bootargs":"-s",
  "max_instr":2000000000,
  "type_after":[["RETURN for /bin/sh:","\n"],["# ","echo /*\n"],["# ","echo $0\n"],
    ["# ","echo z23-freebsd-$((6*7))\n"],["z23-freebsd-42",""]],
  "until":"# "}'
```

Run D, the source-built kernel and root:

```
z23-dev dev app machine boot --input='{"kernel":"SOURCE","bootargs":"-s",
  "max_instr":3000000000,
  "type_after":[["RETURN for /bin/sh:","\n"],["# ","uname -a\n"],
    ["# ","sysctl hw.machine hw.ncpu hw.physmem\n"],["# ","ls /\n"],
    ["# ","echo z23-freebsd-$((6*7))\n"],["z23-freebsd-42",""]],
  "until":"# "}'
```

Expected receipts (every run: `stop` is `requested`, `marker_seen` is true,
all script steps fired, `overlay_blocks` 0). Only run B has a disk, so only
it moves device data:

| run | retired | skip | fw_calls | device_work | console_bytes | transcript_sha256 |
| --- | --- | --- | --- | --- | --- | --- |
| A | 336235854 | 0 | 296 | 0 | 4463 | `092f291f06398edb7c74e6b8f67e177d99e0ac5b253027e4bc707dbfe1c498c6` |
| B | 404021906 | 19977788 | 1660 | 1203 | 4863 | `5fab6ad84c008b183fe0a3d1fb0309de99b473ee4273444c25de8a9cfe94036d` |
| C | 285721481 | 0 | 594 | 0 | 4417 | `3c4f3e15f22bd8c4d590b78b5a7ec11751793819f80b3c17288df1c3ff405cf4` |
| D | 298186705 | 0 | 876 | 0 | 4643 | `fa8e6893ff099098cc23774ef5c1b25e19db8d2bfeefd4ed6f205003e67e3fc3` |

Run E, the kernel with the entropy driver, once without and once with the test
entropy source (the line with `test_entropy_seed` is the only difference):

```
z23-dev dev app machine boot --input='{"kernel":"DEVICES","bootargs":"-s",
  "max_instr":3000000000,"test_entropy_seed":23,
  "type_after":[["RETURN for /bin/sh:","\n"],
    ["# ","echo z23-freebsd-$((6*7))\n"],["z23-freebsd-42",""]],
  "until":"# "}'
```

| run | retired | skip | fw_calls | device_work | console_bytes | transcript_sha256 |
| --- | --- | --- | --- | --- | --- | --- |
| E, no seed | 286482332 | 0 | 608 | 0 | 4383 | `81dde2c26ec67131471b5f9901762f541c8ebfe0a7821cafaf8abcbb2f7b6944` |
| E, seed 23 | 287239666 | 0 | 620 | 265 | 4621 | `6f11c5bbfdd204264fdc10741b365a22dd45802b6b45da38d6744f94ca915f53` |

Without the seed the kernel finds nothing in slot 1 (`virtio_mmio@10002000 ...
no driver attached`). With it the driver attaches and the kernel's random
device is seeded from it:

```
vtrnd0: <VirtIO Entropy Adapter> on virtio_mmio0
random: registering fast source VirtIO Entropy Adapter
random: unblocking device.
```

and the receipt carries `"entropy":{"source":"test_seed","secure":false,"bytes":2120}`:
2120 bytes, charged as 265 units of device work.

Run F, the same kernel asked whether it was seeded before its first use of
randomness, once entered the firmware way and once at its loader entry with
the test boot seed (the `early_seed` key is the only difference):

```
z23-dev dev app machine boot --input='{"kernel":"DEVICES","bootargs":"-s",
  "max_instr":3000000000,"test_entropy_seed":23,"early_seed":"test",
  "type_after":[["RETURN for /bin/sh:","\n"],
    ["# ","sysctl kern.random.initial_seeding\n"],
    ["# ","echo z23-freebsd-$((6*7))\n"],["z23-freebsd-42",""]],
  "until":"# "}'
```

| run | retired | skip | fw_calls | device_work | console_bytes | transcript_sha256 |
| --- | --- | --- | --- | --- | --- | --- |
| F, firmware entry | 291990460 | 0 | 726 | 265 | 4940 | `378dfafc03cd0cbe016a056750e3c1e2ad76c17ce8af65b94bdec1cc1de1978a` |
| F, boot seed | 291812327 | 0 | 716 | 13 | 4857 | `55871e8133d9a1f1b19cd9951e436bd719f7ce66975904abb6ac3d0ee8ae6c74` |

The two transcripts differ in five places and nowhere else. Entered the
firmware way the kernel reports

```
random: no platform bootloader entropy
arc4random: WARNING: initial seeding bypassed the cryptographic random device ...
kern.random.initial_seeding.arc4random_bypassed_before_seeding: 1
```

and unblocks its random device only when the entropy driver has attached.
With the boot seed it reports

```
Preloaded boot_entropy_platform "entropy" at 0xffffffc0029a2088.
random: read 2048 bytes from platform bootloader
random: unblocking device.
kern.random.initial_seeding.arc4random_bypassed_before_seeding: 0
kern.random.initial_seeding.read_random_bypassed_before_seeding: 0
```

before any device is probed, prints no warning, and the receipt carries
`"early_seed":{"source":"test_seed","secure":false,"bytes":2048,"cleared":true}`.
The entropy device then has less to do: 104 bytes, 13 units of device work.
The fifth difference is the address at which the kernel finds its own module
record. The other three kernels above take the seed the same way.

Run B ends with the kernel identifying itself as
`FreeBSD 15.1-RELEASE releng/15.1-n283562-96841ea08dcf GENERIC riscv` and
reporting `hw.machine: riscv`, `hw.ncpu: 1`, `hw.physmem: 1058951168`.

A run takes a few seconds on a current desktop processor; the machine
interprets some tens of millions of guest instructions per second.

### Snapshots

`dev app machine snapshot` boots as `dev app machine boot` does and writes the
machine's state to `snapshot_out` when the run ends. `dev app machine resume`
restores that file and continues. The file is little-endian, versioned and
written field by field: the hart, interrupt controller, timer, serial port,
firmware state, the device queues, every non-zero 4 KiB page of RAM, the
disk overlay blocks, and a SHA-256 trailer over everything before it. The
header records the format version and the machine model version
(`RVMACHINE_MODEL_VERSION`, bumped when interpreter or device model behaviour
changes). It is created with mode 0600 under a temporary name, flushed and
renamed.

What a snapshot is and is not:

- It holds all guest memory, including any keys present. Mode 0600 is its
  only protection.
- The trailer is an unkeyed SHA-256. It detects corruption of the file; it
  does not authenticate who wrote it.
- A snapshot you did not make supplies the guest's code and generator state.
  Restoring it is equivalent to running a guest someone else prepared.

A restore reads the file once, up to 2 GiB, and checks the trailer, the
format and model versions, the RAM size, the boot arguments, the kernel hash
and the disk binding on that one copy before it builds a machine. Every
mismatch is a named refusal (`TRAILER`, `VERSION`, `MODEL`, `KERNEL_HASH`,
`RAM_SIZE`, `DISK_BINDING`, `SLOT_UNKNOWN`, `TRUNCATED`, `TOO_LARGE`, and
others) and no machine is returned. Content that passes the trailer but is
inconsistent (a ready queue the transport would reject, a boot seed address
outside RAM, page or overlay indices out of order or out of range) is
refused as `FORMAT`. The disk is bound by size and SHA-256;
`disk_verify: "size"` skips the hash of the disk image, the receipt reports
`disk_binding: size_only`, and `snapshot_out` is then refused because the new
file would carry a hash that was not checked. The boot seed buffer and the
host entropy source are never written. A machine with a writable data disk,
named console ports, a live boot seed or a private (cleansed) configuration
is refused. Guest time resumes at the snapshot's time; no clock is added.

Restore leaves every cache derived from machine state invalid, through one
call, `invalidate_derived_state` in `rvmachine_snapshot.c`.

`mode: "replay"` continues bit for bit: the same retired-instruction count,
console transcript and hart and RAM state as an uninterrupted run. The
guest's random pool is the snapshot's, so replay is NOT FOR USE WITH SECRETS.
It is accepted only for snapshots taken with no entropy device or with a test
stream; a snapshot taken with the host entropy device cannot repeat and is
refused.

`mode: "fresh"` is accepted only for a snapshot taken with the host entropy
device, in a guest that had attached its entropy driver
(`kldload virtio_random` on the published GENERIC kernel); whether it had
cannot be observed from outside. The restored guest draws new host bytes
through that device, and `resume` runs the guest, before any typed input,
until the device has delivered 4096 new bytes. FreeBSD feeds each fast source
in 8-byte events (`HARVESTSIZE`, `random_harvestq.h`) round-robin over 32
Fortuna pools (`RANDOM_FORTUNA_NPOOLS`), and a reseed needs 64 bytes in pool 0
(`RANDOM_FORTUNA_DEFPOOLSIZE`) and 100 ms since the last one
(`fortuna.c`); from an empty pool 0 that is 8 x 32 events, 2048 bytes, and the
threshold is twice that. If 60000 ms of guest time pass without it, the command
refuses with `FRESH_NO_HARVEST` and delivers no input. The receipt reports the
bytes, requests and guest milliseconds observed.

Fresh mode refreshes the kernel pool at the guest's next read, and nothing
else:

- A process already running at save time keeps its own userland generator
  state; libc `arc4random` reseeds on fork or by its own interval, not on
  restore, and the behaviour of OpenSSL-family generators is not established.
- In-kernel `arc4random` consumers may repeat output for up to 300 s or
  64 KiB (`CHACHA20_RESEED_SECONDS`, `CHACHA20_RESEED_BYTES`,
  the FreeBSD libkern arc4random source).
- A snapshot meant for fresh use must therefore be taken before any
  long-running process that uses randomness exists and before any long-lived
  key exists, and nothing security-relevant may rely on kernel randomness
  drawn in the first 300 s after restore unless that is separately shown.

Measured on FreeBSD 15.1 riscv64 (AMD Ryzen 9 7950X3D, gcc 14.2.0,
2026-10-12), the snapshot at the single-user prompt is 49,045,536 bytes
(11,949 non-zero pages). Resume to the first prompt response takes a median
0.245 s wall (0.151 s user) with `disk_verify: "size"` and 5.415 s with the
full disk hash. After a snapshot taken with the entropy device attached, a
restore that types `sleep N; dd if=/dev/random bs=32 count=1 2>/dev/null |
sha256` returned equal digests across two restores at N = 0, 0.2 and 0.5 and
different digests at N = 1, 1.5, 2 and 5; a test-stream snapshot restored in
replay mode returned equal digests at every N. In fresh mode the device
delivered 5144 bytes in 643 requests over 17065 ms of guest time (about
300 bytes per second), two restores differed, and a snapshot taken without the
entropy driver was refused as `FRESH_NO_HARVEST` after 70501 ms.

### A built-in kernel

A binary built with `Z23_GUEST_KERNEL` carries the KERNEL file of the table
above, gzip-compressed, and `dev.app.machine.boot` boots it with
`"builtin_kernel":true` in place of `kernel`, `accepted_kernel`, `public_kernel`
or `protected_kernel`; exactly one of the five is required. Called PUBLIC and
protected unlock owners refuse built-in kernels and data disks.

```
make z23-dev Z23_GUEST_KERNEL=/path/to/kernel
z23-dev dev app machine boot --input='{"builtin_kernel":true,"max_instr":1000000000,"until":"mountroot>"}'
```

No kernel is committed to the repository. The build refuses a file that does
not have the pinned length and sha256, compresses it with
`tools/gen_guest_kernel.c` (zlib level 9, a fixed gzip header with no time and
no name, so the same file and zlib give the same bytes), and links the result
as a read-only array. `#embed` is not available in GCC 14 or Clang 18, hence the
generated source. Without the variable the binary carries no kernel.

At boot the bytes are inflated into memory, stopping one byte past the pinned
length, and accepted only if the length and sha256 equal the pin
(`tools/command/native_builtin_kernel.h`, checked against the table above by
the group `dev_builtin_kernel`). Any other result is a refusal and no machine
is built: `builtin_kernel_absent` (not compiled in), `builtin_kernel_inflate_failed`,
`builtin_kernel_length_mismatch`, `builtin_kernel_hash_mismatch`,
`builtin_kernel_too_large`, `builtin_kernel_no_memory`; the error code is the
same name in capitals. The receipt reports `inputs.kernel` as
`{"source":"built_in","size":62745584,"sha256":"6932...","changed":false}`.

Measured on an Intel Xeon E3-1241 v3 with GCC 14.2.0 (2026-10-12):

| quantity | value |
| --- | --- |
| kernel, compressed | 5311455 bytes |
| `z23-dev` without / with the kernel | 56899464 / 62211968 bytes (+5312504) |
| inflate and verify | about 0.35 s |

With `"until":"mountroot>"` and `max_instr` 1000000000 the built-in kernel and
the same kernel by path give `retired` 336235854 and `transcript_sha256`
`092f291f06398edb7c74e6b8f67e177d99e0ac5b253027e4bc707dbfe1c498c6`. With the
release disk, the bootargs and the script of run B, both reach the single-user
shell with `retired` 404021906 and `transcript_sha256`
`5fab6ad84c008b183fe0a3d1fb0309de99b473ee4273444c25de8a9cfe94036d`.

The built-in kernel alone reaches only the root-mount prompt. A root file
system and the loadable drivers (`virtio_console`, `virtio_random`,
`geom_eli`) still come from a disk, so this does not by itself make a
self-contained guest.


### Expandable guest data disk

A guest can have a second, writable block device that outlives the run. It is
a sparse file on the host at `<home>/.z23/guests/<name>/data.img` (`<home>` is
the `home` input key, else `$HOME`; the directories are mode 0700 and the file
0600). The guest sees it at virtio slot 3 as `/dev/vtbd1`; the read-only root
disk and its overlay are unchanged. A name matches `[a-z0-9][a-z0-9-]{0,31}`.

```sh
z23-dev dev app machine data --input='{"action":"create","name":"work","size_mib":1024}'
z23-dev dev app machine data --input='{"action":"status","name":"work"}'
z23-dev dev app machine boot --input='{"kernel":"KERNEL","disk":"DISK","data_disk":"work", ...}'
z23-dev dev app machine data --input='{"action":"grow","name":"work","size_mib":4096}'
```

`status` reports the apparent size, the bytes allocated on the host and a
`state`: `free`, `locked` (a run holds the disk) or `unavailable` (the file
cannot be opened; `locked` is then false). Growth is offline: `grow` extends the file while
no machine holds it, the guest sees the new size at its next boot, and the
guest grows its file system itself (`growfs -y /dev/vtbd1` on FreeBSD). A disk
never shrinks, and the limit is 1 TiB. The refusals are `DATA_DISK_NAME_INVALID`,
`DATA_DISK_TOO_LARGE`, `DATA_DISK_EXISTS`, `DATA_DISK_ABSENT`,
`DATA_DISK_SHRINK_REFUSED` (a size not larger than the current one),
`DATA_DISK_LOCKED`, `DATA_DISK_DIRECTORY_REFUSED`, `DATA_DISK_NOT_REGULAR`,
`DATA_DISK_OPEN_FAILED`, `DATA_DISK_CREATE_FAILED`, `DATA_DISK_GROW_FAILED`,
`DATA_DISK_ATTACH_FAILED` and `DATA_DISK_NOT_AVAILABLE`.

Every command checks the path before it opens anything. `<home>/.z23` must be
a real directory owned by the user (its mode is left as it is); `guests` and
`<name>` must be real directories owned by the user with no group or other
access, and a symlink at any level is `DATA_DISK_DIRECTORY_REFUSED`. `data.img`
must be a regular file owned by the user with one link; a symlink, FIFO or
hard link is `DATA_DISK_NOT_REGULAR`, checked again on the open descriptor.
A disk that exists but cannot be opened for another reason is
`DATA_DISK_OPEN_FAILED`. A boot with `data_disk` and `public_unlock` is
`DATA_DISK_NOT_AVAILABLE`: no data disk is attached under the PUBLIC owner.
On a Windows host every data disk request is `DATA_DISK_UNSUPPORTED_HOST`: the
owner-private directory checks exist for POSIX hosts only.

A run holds the file under an exclusive lock from attach to exit, so a second
boot, a `grow` or a second holder of the same disk is refused as
`DATA_DISK_LOCKED`. A guest flush reaches the host file's `fsync`; the run also flushes the file once more at release; a failed
host write or flush returns an I/O error to the guest. A run with a data disk
carries `"data_disk":{"name":...,"bytes":...,"persistent":true,"repeatable":false}`
in its receipt: the disk's content is state the run changes, not an input, so
the input-changed verdict does not consider it and the run is not repeatable.
Without `data_disk` the receipt and the run are unchanged. Online resize is
not offered.

## Limits

One hart; no network device is attached. Configured named virtio-console ports
provide bounded guest channels alongside the console. The published GENERIC
kernel has no console driver built in; `kldload virtio_console` attaches it and
returns, and the ports appear under `/dev/vtcon/`. The driver sends
DEVICE_READY and waits for its completion during attach, before the transport
sets DRIVER_OK, so the console control transmit queue is served from
FEATURES_OK; every other queue is served only from DRIVER_OK. The development boot
command offers explicit host entropy and early boot seed modes, described
below, as well as insecure test streams. Delivery of host OS bytes alone does
not establish guest RNG initialization or qualify private-key generation.
The block device is read-through with an in-memory overlay of at most 256 MiB
of guest writes; past that a write fails in the guest as an I/O error. A
kernel must be able to read its device tree within the first gigabyte of RAM,
which is where the machine places it. A run may print fewer than 64 MiB on
its console; a guest that reaches that is stopped and the run fails as
`CONSOLE_LIMIT`. The work budget is looked at between instructions, so a run
can pass `max_instr` by one instruction and the requests of one queue
notification of each device (at most 129 MiB of disk data and 64 KiB of
entropy).

### Explicit host entropy in the development boot command

`entropy="host"` selects the native OS provider and excludes
`test_entropy_seed`. `early_seed="host"` requires this mode and obtains fresh
bytes separately from device delivery. Requests use bounded 4096-byte chunks;
any source refusal cleans the entire request, latches failure, and refuses the
run without a test or device-file fallback. Host mode also refuses a final
atomic device round above the requested work budget.

The receipt identifies OS delivery and byte counts without recording entropy
contents. It does not establish guest RNG initialization, safe key generation,
or SSH acceptance. Secure FreeBSD launch must disable
`kern.random.initial_seeding.bypass_before_seeding`, then observe initialized
random health and zero bypass counters before creating keys. The host source
alone cannot establish those guest facts.

### Public FreeBSD named-port acceptance

The registered `test_rvmachine_freebsd_ports` group uses an exact externally
retained kernel selected by `ZCL_TEST_FREEBSD_PORT_FIXTURE_KERNEL`. An absent
packet is unobserved; a different kernel is refused. Its fixed PUBLIC fixture
opens `/dev/vtcon/z23.l0.t` and `/dev/vtcon/z23.l0.p`, verifies raw mode on the
held descriptors, and exchanges exact 4097-byte binary patterns separately
and concurrently. Short host input and output acceptance must preserve every
suffix. Each child has a bounded execution cap within a shared 240-second cap.

The close case pauses after one guest byte has been read and observes completed
RX descriptors that have not been reposted. It then observes guest close,
rebinds the host port, and requires an exact distinct pattern after fresh raw
readiness. This checks guest close handling together with host rebind; it does
not retract bytes already consumed by an application. A diagnostic kernel that
omits the guest close/open discard fails this case while the restored kernel
passes. The surplus-byte check covers bytes queued at that check only.

These are nonsecret tty and backpressure fixtures. They do not qualify SSH,
peer authentication, protected credentials, or a private identity.

### PUBLIC mounted GELI bootstrap acceptance

The existing `rvmachine_geli_volume` group retains its four raw-volume legs and
adds four fresh-process mounted legs using the same packet environment variable.
A fixed PUBLIC 32-byte pattern enters the reserved bootstrap port once, after
raw readiness bound to the current port generation. Internal fixed-line matching
produces declared counters and booleans; private-mode console bytes are not
exported.

The write leg checks authenticated GELI attach, UFS formatting, a 4096-byte
PUBLIC payload with `fsync`, nonforce unmount, and a checked flush through the
still-attached encrypted provider. Readback remounts that same provider read
only with no atime updates. A fresh machine then attaches the retained backing
without initialization and checks exact payload and wrong-path absence. Wrong
key refusal requires actual child status, the fixed GELI diagnostic, and absent
provider. A copied backing with a mapped authenticated DATA-byte mutation in
the primary superblock must attach with the correct key and then refuse mount
with integrity failure. The original backing inode and bytes remain unchanged.

This qualifies PUBLIC filesystem persistence and mount-phase tamper refusal
within shared execution and work caps. It does not prove file-payload extent
mapping, private credential custody, automatic unlock, guest identity, or SSH.
Retained recipes record observed source and static ELF inputs; complete
compiler runtime closure remains unavailable and `fully_qualified_action=false`.

The fixture also accepts `mounted-format-diagnostic` with a fresh 16 MiB
PUBLIC backing volume and the separately pinned diagnostic kernel
`f7e7379fb08fd0035cf67bd98d5896376e103ab80851363d2c1f1a16a53e675d`.
This mode uses 256 MiB guest RAM, at most 600 million work units, and a
120-second monotonic deadline including input binding and setup. It retains
AES-XTS-256, HMAC-SHA256 and 4096-byte sectors. It initializes and attaches
using fixed PUBLIC fixture credentials, prepares the formatter's probe
regions, formats, mounts, unmounts and flushes; it creates no SSH identity.

`PUBLIC_FORMAT_RETURN` records returned work upper boundaries when a script
step is enqueued, provided the machine and both port generations remain
unchanged across that run slice. Differences include slice boundary bias;
they are not exact instruction or function costs. Missing steps remain
unknown. Early observations may precede credential delivery; successful
receiver proof still requires actual delivery. A work-cap refusal, even
after successful formatting, does not establish mounted-volume acceptance.
These diagnostic observations do not replace the registered persistence and
tamper controls or qualify protected keys, SSH, or restart recovery.

The diagnostic modes may also report `PUBLIC_PC_ENDPOINT` counts for stable
returned script phases: U, S, M and unrecognized privilege. A sample requires
positive retirement, the same machine and port generations, a matching
returned PC, and no script-step crossing during the slice. Crossings and
rejected samples are reported separately. Only selected S-mode function
intervals from the exact pinned kernel receive symbol labels; userspace
remains unattributed. `S_OTHER` includes unlisted functions, with at most four
public kernel-text PC examples per phase. These are first observed examples,
not ranked hotspots. Counts describe endpoint frequency, not retired-work
share or exact function cost. At most 65,536 accepted observations are retained
per phase; further eligible observations set `limited=1`, so flagged phases
are partial distributions.
Zero samples do not mean zero execution cost. Host sampling overhead remains
unqualified and consumes the existing deadline. No guest memory, private
bytes or transcript is read, and the work and time limits remain unchanged.

`mounted-format-diagnostic-128m` selects 128 MiB RAM for a controlled
comparison with the 256 MiB mode. All other diagnostic limits, image pins,
commands and proof requirements are identical. Native RAM bounds permit this
configuration; FreeBSD runtime fit and complete acceptance must still be
observed. A smaller startup bracket alone does not qualify it for protected
identity service.

`mounted-format-candidate` uses 256 MiB RAM for a separate PUBLIC kernel
experiment. It requires an exact candidate kernel hash and selected function
and executable-text intervals derived from that artifact. An unqualified
candidate refuses before input binding or machine creation. The original
256 MiB and 128 MiB diagnostic modes retain their original image and intervals.
The candidate uses the same formatter commands, proof requirements, work cap,
deadline and endpoint sampling limits. It grants no owner-profile, protected
identity, SSH or recovery authority.

Function parity and four 4 KiB memset benchmark batches qualify only their
exact function experiment. They do not establish a whole-guest speedup.
The candidate kernel requires independent assembly review, exact original
control reproduction, unchanged embedded MFS evidence, focused compatibility
controls and a fresh PUBLIC run. Partial formatting or endpoint observations
do not establish mounted-volume acceptance or exact function costs.
