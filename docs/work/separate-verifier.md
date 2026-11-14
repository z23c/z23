<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Separate-account proof verifier

A push proof may reuse a compiled object only on the word of a verifier that
runs under its own account. Same-account reuse is refused, and stays refused:
anything the proving account can write, a candidate can plant. This is a
design and an uninstalled trust boundary, not a working speed path. The
current wrapper compiles cold in proof mode with `verified:no_verifier_key`.

## Byte contract v2

Every artifact the verifier produces or consumes now uses one versioned
contract, `z23verify.fixed_result.v2`, specified byte for byte in
[`verifier-contract-v2.md`](./verifier-contract-v2.md). The artifacts are
the pins file, the launch request, the worker result packet, the launch
receipt, the signed record v2 with its receipt binding, the store key and the
store layout. That document supersedes the v1 formats that appear below as
history: closure v1, environment v1, text pins v1, the `launch.v1` receipt,
the strict profile and the `zcl.verify_attest.v1` record. A v2 consumer
refuses each of them by a stable token.

## Fixed result.c installation packet (not installed)

The first translation-unit scope is only
`platform/modules/base/src/result.c` on Linux x86-64. The older local GCC 13
direct-source probe uses `tools/verify/real_tu_probe.sh`; the current
build-only production profile below resolves `cc` to GCC 14. The local
`tools/verify/tree_closure.c` utility hashes a complete bounded tree in sorted
order, including path, entry type, mode, owner, link target and regular-file
bytes. It refuses special entries, writable entries, escaping links and
unsafe ancestry. Its output says `attest_eligible=0`: it is a prerequisite,
not an installed signer or an assertion that a compiler used only that tree.
Its local test mode permits ancestors owned by the testing UID; installed
trust requires root-owned ancestors and read-only mounts instead.

The tree helper now emits two domain-separated SHA3-256 roots from one checked
walk. `tree_sha3` includes each entry's UID and is a local owner-bound
snapshot identity. `content_sha3` covers the same sorted path, type, mode,
symlink target and regular-file bytes but omits UID, so a receiver-owned
generation tree and a signer-owned copied snapshot can have the same content
root. Both modes still enforce the caller's expected UID and refuse unsafe
ancestors. A `tree_sha3` from a developer-owned tree therefore cannot be used
as the signer's owner root. The local probe proves this mismatch refuses.

`tools/verify/fixed_result_closure.c` defines the narrow, unqualified closure
format for this one TU. Its six 32-byte inputs, in order, are tool content
root, source content root, root-owned tool tree root, signer-owned source tree
root, installed jail-policy root **claim**, and preprocessed stream root. It
then hashes the canonical physical cwd, the exact direct-source argv encoding,
the fixed environment identity and the relative source spelling. SHA3-256
uses domain `z23.verify.fixed_result.closure.v1`, fixed-width roots in that
order, and 64-bit little-endian length prefixes for text fields. The fixed
environment is exactly `LC_ALL=C`, `TZ=UTC`, `TMPDIR=/work`,
`PATH=/usr/bin:/bin` in that order, each length-prefixed under domain
`z23.verify.fixed_result.env.v1`. `argv_norm` is a concatenation of decimal
byte-length, colon and bytes for each argument, beginning with
`/usr/bin/gcc`, `-std=c2x`; it includes the physical-cwd file-prefix map,
all flags from the direct-source profile, `/work/result.d`, target `result.o`,
the real `.c` source and `/work/result.o`. The CLI prints the complete value.
Its `toolchain_id` is `z23.gcc13.x86_64.fixed_result.v1:` followed by the
tool content root. This argv is the `real_tu_probe.sh` profile. It does not
match the production epoch-object recipe in `Makefile`: that recipe expands
additional CFLAGS and uses its own `-MT`, `-MF`, and `-o` paths. The receiver
must refuse a record from this format for a production compile. Before any
HIT, an installed producer and receiver must bind the observed exact epoch
argv and physical cwd; this probe-only command cannot be normalized into
production equivalence by assertion.

The combiner does **not** validate its six supplied roots against a jail or
the compiler's actual I/O. Its policy input is a claim, not evidence of an
installed mount; even all-zero owner, policy and preprocessed claims are
accepted only as ineligible format fixtures. Cross-UID content equality is
structural until two real accounts can create and compare separate trees.
Every result says `attest_eligible=0` with
`probe_profile_and_jail_unverified`. An eligible producer must obtain owner and
policy roots from a root-owned pinned manifest and verify the mount namespace
and separate UIDs at execution. The receiver must construct the expected
source content root from its own exact generation tree and read the installed
tool and policy pins independently; it cannot copy a candidate's six claims.

### Current build-only result.c command

`tools/verify/fixed_result_gcc14.args` pins the **ordered** current Make
`BUILD_ONLY_OBJECT_CFLAGS` for `result.c`: `cc` plus 180 arguments, including
`-std=c23`, every define and include in its original order, the physical-cwd
prefix map, and the literal source random seed. The manifest SHA3-256 is
`befa08b481efd3d6387c61d39095f77ec65e9bf229f55a3da4a9cf4efdd20cfa`.
`@CWD@` is replaced only with the verified physical cwd. The local witness
requires `/usr/bin/cc` to resolve to GCC 14, compares every expanded Make
argument to this manifest, and then runs direct-source GCC under exactly
`LC_ALL=C`, `TZ=UTC`, `TMPDIR=/tmp`, `PATH=/usr/bin:/bin`. It appends the real
epoch recipe's `-MMD -MP -MF <dep> -MT <epoch target> -c -o <object> <source>`.
Two distinct output paths must produce byte-identical objects, depfiles and
stderr; a fresh `-E` with the same target must produce the same depfile. The
witness prints its exact hashes and compiler launch counts. The current
combiner above still describes its earlier GCC 13 probe profile and must not
be used as the expected key for this GCC 14 command.

This tracked manifest is a reviewable build-profile input, **not** an
installed root pin. Make expansion checks detect drift for local development;
candidate-controlled Make is never the receiver's authority. An installed
producer must use a root-owned copy of the reviewed profile and current tool
image, and the receiver must compare the fixed profile, physical cwd, source
snapshot, full namespace and fixed environment independently. Epoch `-MT`,
`-MF` and `-o` values need typed normalization supported by an observed
byte-equivalence witness; the receiver writes its own current-target depfile.
The local witness says `attest_eligible=0`, launches two compilers and one
preprocessor, and avoids zero proof compiles.

The witness prints its exact object, depfile and raw `-E` hashes, byte counts and
the run's wall/CPU each time. It launches two direct `-c` GCC 14 children and
one fresh `-E`, avoiding **zero** proof compiler launches; both compiler stderr
files are empty and the `-E` depfile matches the cold depfile byte for byte. It
is a local baseline only: no service, store lookup, link or test child runs.

The first eligible candidate is restricted to the exact current three-file
translation-unit chain. SHA3-256 of `result.c` is
`f8a4357fa0cd51537c90b476512c18869a940fd6442a1f140baacec1367a923a`,
of `base/result.h` is
`e92c831f3170655fd955fcc8ca3ec7d886c7b15416e4c9045822bc87029fdd68`,
and of `base/format_attribute.h` is
`1667ffb42ea55553d38f931037cae523dfe61cabe6ec8a1f7c78b3b6b960d9be`.
A changed source or header is a cold miss. These bytes must be delivered to
the signer because the proof worktree files are mode 0600 and cannot be read
by `z23verify`; the offline root publisher freezes the verified three-file
snapshot under root ownership before the compiler starts. The signer and
receiver must
each run fresh raw `-E` with the exact pinned flags, environment and cwd, bind
the whole resulting stream and depfile, and reject a namespace that changes
either. A sparse snapshot or an installed tool image is not qualified merely
by these three hashes.

A separate sparse-tree test under `devbuild` job
`4091410-45533905-1790601582793771072` (16.74 s queue wait) copied exactly
these three files, created empty ordered `-I` directories, and used the same
GCC 14 profile, fixed environment and dep target from a different physical
cwd. Depfiles and stderr matched, but raw preprocessing differed at its
physical-cwd line marker. The full-tree object SHA256 was the baseline
`9c5a64f6007d0307885c5548dbff51bc278368fcf833cea47ce0de793c851368`,
while the sparse object was
`11a186c57b1f3c815ab6473d3b77b62c1ee57ab0c85854d76d5741e623e55d7a`.
The sparse PP SHA256 was
`d427248f3b7f8eda4492c9444abb7886805b5ab7228e34e8351cf2a0b28054a5`.
This is a RED witness for relocation: the compiler must see a read-only
snapshot at the **same physical cwd** as the cold proof. Rootless bind
mounting is denied on this host, so byte equivalence at that path remains an
installed-jail acceptance gate.

`-fno-working-directory` is insufficient as a profile repair. Under
`devbuild` job `126656-45543999-1790601683730422570`, it made raw `-E`,
depfile and stderr bytes equal across the same original/sparse relocation,
but the original object stayed at SHA256
`9c5a64f6007d0307885c5548dbff51bc278368fcf833cea47ce0de793c851368`
and the sparse object was
`04db133444cef76d2d8755f4a3df390e33e4eb7cb1fde16f645c64d6f99957a0`.
Independent read-only inspection found the first differing payload in a
compressed `.gnu.lto_zcl_result_set_literal.*` function section: its IR
contains the literal original or relocated physical cwd. Matching
preprocessing cannot substitute for direct-source object equivalence under
this `-g -flto=auto` profile. A verifier record keyed to one ephemeral proof
generation's cwd may be ineligible for reuse by the next generation. The
installed acceptance must show an unchanged cold proof and a later warm proof
using the **same qualifying physical cwd**, or demonstrate and review a new
byte-equivalent production profile before enabling any HIT.

### First proof target: test-fast non-LTO result.c

The mandatory `dev-proof-bundle-prefork` graph compiles the `test-fast`
runner; it does not build the separate strict `test_parallel` object tree.
That discovery cancelled native row 304 before publication. The signed
strict worker remains historical, ineligible local qualification only.
`tools/verify/fixed_result_fast.args` pins the real test-fast ordered GCC 14
direct-source arguments (200 lines including `cc` and the literal random
seed), SHA3-256
`41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082`.
The original qualification target was
`build/test-obj/epochs/0033ccae6a292700d2b299aec57e346aa7f719bac2798a620d2ba9e155ebca5e/platform/modules/base/src/result.o`.
The test-fast profile is non-LTO at `-O1` and includes `-DZCL_TESTING`;
release LTO result.c remains cold.

The current profile repins the Make recipe with `-g1`, updated include roots
and warning flags. Local requalification produced a 4,496-byte object with
SHA256 `e6cc944b229437d98654b1222d208ca932fb8b17c565ac512c6f7becc6d4892e`,
matching the Make-built object. Full and sparse source trees agreed on the
object, depfile, stderr and preprocessing bytes; epoch, descriptor, header
shadow, changed-source and same-UID checks passed. This remains local evidence
with `attest_eligible=0` and zero proof launches avoided. Installed pins and
images require separate qualification. The measurements below describe the
retired 183-argument profile, not the current profile.

The one-request `fixed_result_worker` runs the exact test-fast `-c` argv and a
fresh checker `-E` with only `-fno-working-directory` added, under a fixed
four-entry `execve` environment. An initial direct-GCC parity probe under
`devbuild` job `2920421-46114889-1790607392629817218`, original and relocated sparse
source trees yielded identical direct objects, depfiles, stderr and raw
checker PP: object SHA256
`32a13af795e799469c81dcf5e961a41fd3a6cb59745942efc17d2ae140454660`
(10,128 bytes), dep SHA256
`6dc86a0691bc19c99e346c011b1106bcc49edd44f657edbef3f1c55c20f48277`
(365 bytes), empty stderr, checker PP SHA256
`3ab6e90809157054042b29fc870f0ec728e3426b05f94cf3c0fb17f583e935fb`
(43,372 bytes). Two full compilers and two preprocessors ran; zero proof
launches were avoided. Local qualification emitted `attest_eligible=0`.

For this versioned test-fast policy only, the verifier's physical cwd inside
its installed jail is `/zclassic23`, so a signed `recorded_cwd=/zclassic23`
would literally name the verifier's physical cwd. The receiver may construct
that expected value across ephemeral proof cwd paths only after independently
checking pinned raw source/header bytes, ordered search roots, fresh checker
PP/dep bytes, tool image and current checker implementation root, plus the
cross-cwd direct object equality gate. The receiver's actual cwd stays in
its local proof receipt. This is a proposed policy, not an installed
expected-key implementation or an eligible observation.
Its closure root must include exact worker, signer, publisher and receiver
admission/check implementation bytes (including ZCC, `verify_store` and
`verify_attest`) as well as GCC driver, cc1, assembler, ELF loader, DSOs,
specs, profile and jail policy. A changed implementation is a cold miss even
when an ABI or output happens to remain the same.
For the first exact pinned TU, a nonzero verifier `-E` or `-c` under otherwise
eligible inputs blocks that request; it cannot fall through to a cold
compile. The worker currently seals no FAIL, so this slice has no durable
cross-request FAIL memory. Timeout and cancellation produce no observation.
Any already signed FAIL in the root-owned observation store still blocks an
exact-key PASS through the receiver's conflict rule.

The administrator must run the following staging commands as root on a host
where UIDs/GIDs 60092 and 60093 are free. These commands create no key, socket
or running service. A pre-existing user or group with either ID is a hard
refusal; do not remap an existing account or reuse its files.

```sh
set -eu
test -z "$(getent passwd 60092)" && test -z "$(getent group 60092)"
test -z "$(getent passwd 60093)" && test -z "$(getent group 60093)"
test -z "$(getent passwd z23verify)" && test -z "$(getent passwd z23vcc)"
test -z "$(getent group z23verify)" && test -z "$(getent group z23vcc)"
groupadd --system --gid 60092 z23verify
groupadd --system --gid 60093 z23vcc
useradd --system --uid 60092 --gid 60092 --home-dir /var/lib/z23verify --shell /usr/sbin/nologin z23verify
useradd --system --uid 60093 --gid 60093 --home-dir /var/lib/z23vcc --shell /usr/sbin/nologin z23vcc
install -d -o root -g root -m 0755 /etc/z23verify /var/lib/z23verify /var/lib/z23verify/jails
install -d -o z23verify -g z23verify -m 0700 /var/lib/z23verify/key
install -d -o z23verify -g z23verify -m 0755 /var/lib/z23verify/cas
install -d -o root -g root -m 0755 /var/lib/z23verify/store
install -d -o root -g root -m 0755 /var/lib/z23verify/locks
install -o root -g root -m 0644 /dev/null \
  /var/lib/z23verify/locks/fixed_result.lock
install -d -o z23vcc -g z23vcc -m 0700 /var/lib/z23vcc /var/lib/z23vcc/work
```

The reviewed test-fast non-LTO profile is staged only from a root-owned directory after
the administrator verifies its SHA3-256 against the value above. This pins
the profile bytes but starts no compiler or signer. The staging path and
installed profile must not be writable by either service account or the
developer:

```sh
set -eu
stage=/root/z23verify-staging
test "$(stat -c %u "$stage")" = 0
test "$(stat -c %u "$stage/fixed_result_fast.args")" = 0
test "$(stat -c %a "$stage")" = 700
test "$(openssl dgst -sha3-256 "$stage/fixed_result_fast.args" | awk '{print $NF}')" = \
  41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082
install -o root -g root -m 0444 "$stage/fixed_result_fast.args" \
  /etc/z23verify/fixed_result_fast.args
test "$(openssl dgst -sha3-256 /etc/z23verify/fixed_result_fast.args | awk '{print $NF}')" = \
  41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082
```

The later service installer must pin the exact GCC 14 tool image, source
generation and mount policy in separate root-owned records and install the
root-owned public key. No private key, socket or service is installed by this
staging packet; proof reuse stays cold. A writable source checkout or the
developer's copy of this manifest cannot serve as the installed pin.
The administrator also pins the store's distinct signer and publisher UIDs in
`/etc/z23verify/store.policy`, owned by root with mode 0444 and a root-owned,
non-writable parent. Its exact bytes are:

```text
z23verify.store.v1
signer_uid=60092
publisher_uid=0
```

The one-TU observation store uses root-owned
`/var/lib/z23verify/store/<store-key>/<record-sha3>/attest.bin`, `object.o`,
`deps.d` and `stderr.bin`. The root-precreated `fixed_result.lock` serializes
all fixed-result keys: an offline root publisher takes an exclusive lock
across staging, fsync and atomic no-clobber publication; the receiver takes a
shared lock across the complete observation scan and verified artifact
materialization. The signer writes only private staging and cannot mutate
root-owned observation history. Neither side creates or follows a lock
symlink. A developer may open this public lock and delay a bounded request,
so lock acquisition needs a deadline and refusal.

The later, reviewed installer must create a **root-owned, read-only mount
namespace** for the compiler account. Its root contains only the pinned GCC
driver, cc1, assembler, ELF interpreter, every loaded shared object, GCC specs
and start files actually reachable by this compile, all system include trees,
one signer-copied source snapshot at the same physical cwd and source argv
spelling as the cold build, a fixed `/dev/null`, and bounded scratch. The
developer account cannot write any mounted input. `z23vcc` cannot write any
input or see the signer key. The signer controls its source snapshot and checks
its tree before and after the child exits. The tool image and namespace
skeleton are root-owned and immutable while requests are served. The child
starts with empty environment plus an explicit, hashed whitelist, no inherited
file descriptors except stdio and authenticated IPC, no network, and fails if
any mount/confinement operation fails. Landlock remains a second layer; it
cannot replace the mount namespace because this kernel lets a Landlocked child
observe ungranted path metadata with `stat(2)` and `access(2)`.

The closure identifier must hash canonical complete tool-image and source
trees, the immutable namespace skeleton, exact environment, direct-source
argv, physical cwd, and isolation policy. Hash the trees before and after the
compile, and refuse on a changed hash or any missing/unreadable entry. The
receiver independently reconstructs the expected closure from its current
generation worktree; it must not copy the signer's claimed hash. Whole-tree
identity binds absent header lookups such as `__has_include("optional.h")`:
adding a previously absent file changes the directory hash. An observation
can become eligible only after the installed service proves this confinement
and the receiver verifies a root-pinned key and every stored artifact.

One fixed-TU acceptance run must first prove direct-source object, depfile
and stderr byte equality against a cold compile under the exact profile. RED
fixtures must replace `cc1` while leaving the GCC driver unchanged, set
`COMPILER_PATH`/`GCC_EXEC_PREFIX`, add an optional header absent in the prior
snapshot, change a DSO/spec file, inject an escaping symlink, and change an
input during compilation. Each must alter the closure or refuse before any
eligible record. The receiver must reject a wrong key, wrong argv/cwd,
tampered object/dep/stderr, and conflicting signed PASS/FAIL observations.
The offline root publisher must hold the root-owned global lock exclusively
while publishing each root-owned observation; the receiver holds it shared from
the complete observation scan through verified artifact materialization.
Store and lock paths require trusted ownership and descriptor-based,
no-symlink traversal. A directory scan alone cannot rule out a signed FAIL
published after the scan and before a PASS object is used.
Until this run succeeds under the real accounts and root-owned image, proof
reuse remains cold and `attest_eligible=0`.

The proposed verifier would compile each translation unit itself, with its
own pinned compiler, and never run the candidate's build scripts. Its only
reusable product would be a signed record: "this compiler, with these flags
and complete input closure, produced these bytes". A future proof may reuse
an object only when its own input checks and the record verify under current
receiver policy.
The preprocessed stream is one input, but it is not a sufficient object key
under the current debug/LTO profiles: a real Z23 unit compiled directly from
`.c` differs bytewise from the same unit compiled from its exact `.i` stream.
`tools/verify/real_tu_probe.sh` reproduces this on Linux x86-64 with GCC
13/14 from one working directory. An eligible
verifier must compile the real source with equivalent path and working
directory semantics, then bind the implementation bytes of all tools it used.

## Receiver in the landing proof

`tools/dev/verify_receiver.{h,c}` and `verify_receiver_input.c` let a proof
use a signed observation for `platform/modules/base/src/result.c` (test-fast)
instead of compiling it. Proven by `test_verify_receiver`.

### Where admission lives: the driver, with zcc as a thin client

Two designs were considered:

- (a) The driver pre-materializes the object into the epoch tree.
- (b) The driver admits the bytes into a private directory, and zcc copies
  them into the epoch target.

We chose (b). Design (a) cannot work, for three reasons:

- The epoch directory is named by `TEST_FAST_COMPILE_EPOCH`, and that name
  is only known after make parses the Makefile.
- The object rule depends on `$(ZCC_BIN)` and `$(VIEW_GEN_HEADERS)`. The
  same make rebuilds both, so a pre-placed object is older than its
  prerequisites and make compiles over it.
- `build-epoch-session.sh` recover mode quarantines a whole epoch directory
  that holds `.unverified` and no live lease. It also collects non-current
  epochs beyond the three it keeps.

In (b) the object travels zcc's normal staged publication, so it survives
exactly as a compiled object would.

The driver is the lander's pinned `z23-dev`, not the candidate's build. It
does all admission before the bundle make:

1. Load the root-pinned verifier key. With none installed, the result is
   `cold(no_verifier_key)` and nothing else is read.
2. Load the pins through `zcl_verify_store_pins_load`, and the root-owned
   profile `/etc/z23verify/fixed_result_fast.args`.
3. Run its own `-E` in the generation, with `/usr/bin/cc`, the fixed
   four-entry environment, and `-MT` set to the placeholder target. The
   placeholder has an all-zero epoch and the same 121-byte length, so the
   depfile wraps identically.
4. Hash the source content (below) over the files that `-E` read, and
   require it to equal the pin.
5. Build key v2 through `zcl_fixed_result_expected_v2`. Its synthetic `-c`
   argv writes into the private directory as `/proc/self/fd/<n>`.
6. Call the store lookup.
7. On a HIT, require the donor depfile after its own 121-byte target to equal
   the driver's own depfile tail, byte for byte. The donor depfile names the
   donor's epoch, so it is never published as it stands.
8. Write `argv`, `object.o`, `depfile.tail`, `stderr.bin` and `root` (the
   physical generation path) into `<state>/receiver.<key>`, which must lie
   outside the generation. The store's shared publication lock stays held
   until the step ends.

`ZCC_ADMITTED` and `ZCC_LOG` are removed from the inherited proof
environment and set only for an admitted step.

zcc serves only when all of these hold:

- proof mode (`ZCC_VERIFIED`) and `dep` mode;
- this source and a well-formed `build/test-obj/epochs/<64 hex>` target;
- make's compiler tokens equal the admitted `argv` exactly;
- its cwd equals `root`, so a sub-make with `-C` into another tree and the
  same argv is not served.

It writes the object and `<exact target>` + the driver's depfile tail, then
logs `VERIFIED admitted:fixed_result.v2 <target>`. In every other case it
compiles and logs `MISS admitted:<why>`.

zcc holds no authority. Its checks are correctness guards, not a trust
boundary. After make, the driver rechecks everything whatever the log
claims:

- every target the log names: the object must be the admitted bytes and the
  depfile must be the exact target plus the driver's tail;
- every `build/test-obj/epochs/<64 hex>` whose `result.o` holds the admitted
  bytes, logged or not: the same depfile check;
- every source input it measured.

Any failed recheck blocks. So does a log that is missing, over 16 MiB,
names a served path the driver cannot record, or names no consumption at
all. A step that admits an observation but never compiles `result.c`
therefore blocks, so admission is only worth making for a step that
compiles it. A HIT needs a readable log naming the served targets. A
`MISS admitted:<why>` with every recheck passing is `cold(admitted_<why>)`.

A candidate that bypasses zcc can produce any object at all, but it cannot
make the driver report a HIT for bytes the driver did not admit.

**Known limit: generated-header shadowing.** The driver's `-E` runs before
make. A make step could generate a header into an earlier `-I` directory,
so that the real compile of `result.c` would read different text while
every source the driver measured stays unchanged. Serving the admitted
object would then skip that difference. This needs a candidate Makefile
change, which review sees in the diff, and it is out of scope here. The fix,
if wanted, is to re-run the receiver's `-E` at finish and require the same
preprocessed hash and depfile before a HIT.

### Source content root v2

The receiver and the launcher share one definition and one reader:

- `zcl_fr_source_content_v2` in `tools/verify/fixed_result_contract.c`
  defines the root.
- `zcl_fr_source_content_at` in `tools/verify/fixed_result_source.c` reads
  the files.

The full definition is in `docs/work/verifier-contract-v2.md`, section 3a.
The receiver hashes the files its own `-E` read. The launcher hashes the
fixed chain in the installed source image:

- `result.c`
- `result.h`
- `format_attribute.h`

`test_verify_receiver` proves the receiver's root equals the launcher's pin
for the real chain.

Owner and mode are excluded, so a 0600 proof generation and a root-owned
0444 image of the same bytes agree.

### phases.txt rows

```text
object_reuse_admit=hit(<store_key>,<record_sha3>) | cold(<token>) | block(<token>)
compile_launches_avoided=<n>
object_reuse_cost=wall_us=<n> cpu_us=<n> bytes=<n> compile_launches=<n>
```

A `block(...)` fails the step with `object_reuse_blocked_<token>`. When the
build itself fails, the build's own message takes precedence.

Cold tokens:

- `no_verifier_key`
- `receiver_platform_unsupported`
- pins: `store_pins_path_unsafe`, `store_pins_missing`, `store_pins_unsafe`,
  `store_pins_changed`
- profile and generation: `receiver_profile_{missing,path_unsafe,unsafe,mismatch,shape}`,
  `receiver_cwd_unsupported`, `receiver_preprocess_{failed,deadline,empty,spawn_failed,wait_failed}`,
  `receiver_generation_unreadable`,
  `receiver_work_unsafe`, `receiver_work_inside_generation`
- inputs: `receiver_depfile_unparsed`, `receiver_inputs_missing`,
  `receiver_input_path_unsafe`, `receiver_file_*`, `source_content_{unreadable,unsafe,limit,changed,out_of_memory}`
- `receiver_source_content_mismatch`, `receiver_depfile_mismatch`
- every store and attest refusal that is not blocking, for example:
  `store_path_unsafe`, `store_owner_same_uid`, `attest_no_observation`,
  `attest_record_v1_unbound`, `attest_receipt_mismatch`,
  `contract_receipt_artifact_mismatch`
- after make: `admitted_<zcc reason>`, for
  example `admitted_argv_mismatch`, `admitted_target_invalid` or
  `admitted_cwd_mismatch`

Block tokens:

- the store's blocking verdicts, for example `attest_exit_nonzero`,
  `attest_eligible_conflict`, `store_lock_unavailable`,
  `store_scan_incomplete`
- after make: `admitted_object_mismatch`, `admitted_object_missing`,
  `receiver_depfile_mismatch`, `admitted_target_invalid`,
  `admitted_served_overflow`, `receiver_source_changed`,
  `admitted_log_unreadable`, `admitted_not_consumed`,
  `receiver_epochs_unreadable`, `receiver_epochs_limit`

### Still needed from root

The following are all absent today, so production reports
`cold(no_verifier_key)`:

- `/etc/z23verify/verifier.pub`
- `fixed_result.pins`, whose first root is what `z23-fixed-result-launcher source-content <source image>` prints
- `fixed_result_fast.args`
- the store and its policy
- the installed images and accounts

## Threat model

1. The candidate controls its Makefile, build scripts, generators, tests,
   headers and environment. All of it runs as the developer account, with
   nothing confining it.
2. Anything that account can write is suspect: the compiler cache, warm donor
   trees, the version-control store, and the per-box proof signer key and its
   allowlist. A candidate can read that key and extend that allowlist, so
   neither can be the verifier's root of trust.
3. The attack defended here is hidden state: a planted object or PASS that
   changes a later, honest-looking proof. A malicious diff is out of scope;
   review sees it.
4. The signer never runs candidate-controlled code while it holds its key:
   no Makefiles, configure scripts, compiler plugins or spec files. The
   compiler runs under a different account with no access to that key.
5. The verifier computes its own binding hash from bytes it copied itself and
   signs with a key only its account can read. Its public key is pinned in a
   root-owned file.
6. Any doubt compiles the unit cold, and the refusal is named.

## Architecture

**Account and files.** A signer account `z23verify` owns its private key and
staging area; root retains custody of published observations. A separate
compiler account `z23vcc` runs
compiler children. The signer prepares a source snapshot that `z23vcc` can
read but cannot write. Neither account can switch to the other. The
developer account can read published items marked (r) and write none of them.

| Path | Mode | Purpose |
| --- | --- | --- |
| `/var/lib/z23verify/key/` | 0700 | Ed25519 private key |
| `/var/lib/z23verify/cas/` | 0755 | file contents copied and hashed by signer |
| `/var/lib/z23verify/store/` (r) | root 0755 | root-published observations; signer cannot unlink prior FAIL |
| `/var/lib/z23verify/jails/` | root 0755 | versioned jail roots; synthetic source paths are signer-writable and compiler-read-only |
| `/var/lib/z23vcc/work/` | 0700 | compiler scratch/output, no signing key |
| `/etc/z23verify/verifier.pub` (r) | root 0644 | pinned public key |
| `/etc/z23verify/store.policy` (r) | root 0444 | signer UID 60092, publisher UID 0 |
| `/etc/z23verify/toolchain.conf` (r) | root 0644 | pinned compiler identity |
| `/usr/local/libexec/z23-verifyd` | root 0755 | daemon binary |

**Request path target.** The first installed path is one fixed test-fast
`result.c` request. A root-owned launcher authenticates the signer account
on its external Unix connection, constructs the pinned jail, and starts the
compiler worker as UID 60093. The worker accepts one bounded `SOCK_SEQPACKET`
request only from launcher UID 0 on a private socket. It runs the direct
source checker and compile under the fixed environment, then returns the
object, depfile, stderr and preprocessed stream as descriptors to the
launcher. Its result packet also binds the private scratch path, exact target,
both raw GCC argv hashes and fixed environment root. The root launcher must
observe the worker live, independently rederive those argv hashes from the
pinned profile, copy and hash the descriptors, then send one byte `A` on the
private socket within 30 seconds. The worker cleans scratch and exits normally
only after that acknowledgment. The launcher writes a root-owned receipt only
after observing exit 0, with no receipt on timeout, cancel, malformed packet,
or missing acknowledgment. The receipt binds the exact mounted
source/tool image and effective policy. The signer may seal only after it
authenticates that launch receipt and independently checks the output and
input closure. The root publisher reopens the receipt and signed staging,
checks the installed pins, and adds the observation under `fixed_result.lock`.
The current local worker qualification exercises no root peer or mounted jail;
the launcher, signer and publisher authority checks still require installation
and live separate-account acceptance.

This sequence remains an acceptance target. The current attestation record's
`toolchain_id` must cover the driver, compiler backend, assembler, ELF loader,
dynamic libraries, GCC specs and any other executable bytes the compile used.
A driver hash alone does not qualify. Source snapshots must reproduce the
direct-source object's path semantics, including debug and LTO sections; a
matching preprocessed hash alone does not qualify.
For LTO, `recorded_cwd` means the effective physical cwd used by GCC, not a
prefix-mapped DWARF directory. Source argv spelling, symlink policy, random
seed, environment and profile are part of the expected compile input.
Current admission checks signed cwd and closure fields against receiver
expectations, and its store key includes both. No installed verifier currently
constructs those expectations. `SO_PEERCRED` on the worker socket attests the
root launcher's UID, not the truth of the launch receipt or the mounted bytes.
The installed launcher and publisher remain trust boundaries requiring
independent qualification.

**The record.** `zcl.verify_attest.v1` carries `toolchain_id`, `argv_norm`,
`recorded_cwd`, `pp_sha3`, `closure_sha3`, `obj_sha3`, `dep_sha3`,
`stderr_sha3` and `exit`, in one canonical little-endian encoding, followed
by the signer's public key and an Ed25519 signature over a domain-separated
message. The implementation and its byte layout live in
`tools/dev/verify_attest.h`.

**How the proof will use it.** The compiler wrapper's verified mode is set by
the proof environment and currently compiles cold. Future reuse must compute
the full expected key from the generation worktree, load an entry from the
separate verifier, and admit it under current receiver policy. Admission
checks the signature, toolchain, flags, cwd, preprocessed input, complete
closure and fetched object bytes before writing the object. The proof must
generate its own depfile for its exact target during the input check; a donor
depfile can name another `-MT` target even when object bytes match. Coverage
sidecars remain fresh. Any mismatch compiles cold; an eligible contradiction
remains blocking. The
epoch-object publish path needs the same admission.

**Admission refusals.** Each is a stable token: `no_verifier_key`,
`attest_schema_unknown`, `attest_record_malformed`,
`attest_signed_by_box_signer`, `attest_signer_not_verifier`,
`attest_signature_invalid`,
`attest_toolchain_mismatch`, `attest_argv_mismatch`, `attest_cwd_mismatch`,
`attest_pp_mismatch`, `attest_closure_mismatch`,
`attest_obj_hash_mismatch`, and `verifier_key_is_box_signer` when the pinned
key is the per-box signer key.
An exact signed record with a nonzero compiler exit returns blocking
`attest_exit_nonzero`; it is a failed compile, not a missing cache entry.

**Trust-root refusals.** The loader refuses a key file that is missing
(`no_verifier_key`, the normal state until a verifier is installed), not a
regular file, not root-owned, group- or world-writable, under any parent
directory that is not root-owned or is group- or world-writable, or
malformed. A test-only override path exists only in `ZCL_TESTING` builds.

**Why per-unit compiles, not the Makefile.** Makefiles, configure scripts and
generators are arbitrary code. Running them as the verifier would put
candidate code inside the signer's account, and their output is not a
function of anything the verifier can bind.

**Safety conditions for the proposed verifier.**

- Candidate-supplied argv is parsed against an allowlist. Source/header bytes,
  manifest and requested cwd are also untrusted inputs and require
  independent validation in the compiler service.
- Preprocessing reads files but runs no code. Includes are limited to the
  snapshot by Landlock and bounded by rlimits.
- Refused flags, because they can run other programs or write elsewhere:
  `-fplugin*`, `-specs`, `-B`, `-wrapper`, `@file`, `--sysroot`, `-iprefix`,
  `-save-temps`, `-fdump-*`, and absolute `-I`/`-include` outside the pinned
  roots.
- `GCC_EXEC_PREFIX`, `COMPILER_PATH` and `DEPENDENCIES_OUTPUT` are scrubbed.
- Generated headers are data; the preprocessed-text hash covers them.
- A record claims only what a compiler run produced, not that the code is
  correct. Candidate code must still be treated as hostile compiler input.

**Warm donors.** Same-account donor seeding stays refused. The verified path
replaces it: the verifier becomes the donor.

## Privileged installation packet (pending implementation and grant)

No installation command is valid yet: there is no daemon, signer, root-owned
toolchain closure pin, or qualified object-equivalence test in the tree. An
operator-granted install must review the exact signed source commit and binary
hashes, create the two non-switchable accounts above, pin the full compiler
closure and public key in root-owned files, and install separate Unix sockets.
The signer service needs `User=z23verify`, `ProtectHome=yes`,
`ProtectSystem=strict`, `PrivateNetwork=yes`, `NoNewPrivileges=yes`, and an
empty capability bounding set. The compiler service needs `User=z23vcc`,
`RootDirectory=` set to the reviewed jail, `ProtectHome=no` inside that jail,
the other restrictions above, no key read permission, and bounded
snapshot/toolchain filesystem access. The jail contains no host home and no
signing key. Serialize requests sharing a jail/path or use disjoint jail
versions. Qualify both directions of peer credentials, exact output
copy/hash, key isolation, cancellation, and a real debug/LTO unit before
enabling either socket. Installation and service activation need their own
operator grant; development authorization does not include them.

## Teardown

```sh
systemctl disable --now z23-verifyd.socket z23-verifyd.service z23-vccd.socket z23-vccd.service
rm /etc/systemd/system/z23-verifyd.* /etc/systemd/system/z23-vccd.*
systemctl daemon-reload
userdel z23verify
userdel z23vcc
rm -rf /var/lib/z23verify /var/lib/z23vcc /etc/z23verify /usr/local/libexec/z23-verifyd /usr/local/libexec/z23-vccd
```

Once the public key is gone, proofs go cold again automatically.

## Slices

Each slice fails closed by default.

1. **Record, pinned key, admission.**
   - 1a (landed with this document): `tools/dev/verify_attest.{h,c}` — the
     record and its canonical encoding, the store key, the root-pinned key
     loader, and the admission decision, proven by `test_verify_attest`.
   - 1b: the compiler wrapper's verified mode, which refuses everything until
     a key is pinned; the proof environment sets it, and the proof note gains
     `object_reuse_admit=cold(no_verifier_key)` (see "Receiver in the landing proof"). RED: an object
     planted in the same-account cache is served by a proof-mode compile
     today. GREEN: it compiles for real.
2. **Daemon compile core.** tools/verify/z23_verifyd.c (planned; not yet in
   the tree), using the existing
   Landlock code. Tests run it unprivileged with a trust root injected only
   under `ZCL_TESTING`. The refused flags, an out-of-snapshot include, a
   mismatched preprocessed hash and a device file are all refused; an honest
   real debug/LTO unit yields a verifiable record whose object is
   byte-identical to a local cold compile. The current experimental `.i` core
   did not pass this requirement and is not part of the admitted path.
3. **Client submission and pre-warming main.** On a miss the wrapper queues
   a bounded, non-blocking request; a `verify warm` command pre-builds main's
   units after publication. With no socket, proofs are unchanged.
4. **Units and install scripts.** `packaging/systemd/z23-verifyd.{socket,service}`
   and install/uninstall scripts, with a lint for `User=z23verify`,
   `ProtectHome=yes` and `PrivateNetwork=yes`.
5. **Receipt binding.** The compile dimension records `verified_reused` and
   the verifier's public key (receipt schema bump); the land queue refuses
   `verifier_unknown`.
6. **Deferred: test-verdict reuse.** Tests execute candidate code, so this
   needs a second, disposable account and a signer separated from the
   executor.

## Expected speed (estimates, not measured)

- Refusing warm donors alone moves the bundle phase from about 10 s to about
  205 s.
- With the verified path, each unchanged unit costs one `-E` pass (about
  30–60 ms), a signature check (about 50 µs) and a copy. For a narrow edit
  against a pre-warmed main this should recover most of the compile gap.
- Still cold: changed units, links, archives, vendor builds, generators, all
  lint gates and test groups, and any toolchain change until it is re-pinned.
- A cheaper later path could compare file hashes instead of running `-E`. It
  is sound only if it also records include lookups that found nothing.

## Open questions

1. **Binary provenance.** The daemon is built from an owner-signed commit by
   `z23verify`, and every upgrade needs root. Is that acceptable?
2. **Path equivalence.** Reproduce direct-source debug/LTO object bytes from
   the compiler account's owned snapshot without exposing the signing key.
3. **Toolchain pin.** A compiler package upgrade makes everything miss until
   someone re-pins. Manual, or a root timer?
4. **Test verdicts.** Reuse requires executing candidate code under a
   disposable account with no network. Approve in principle, or defer?
5. **Build-script bypass.** A candidate's Makefile could switch verified mode
   off. This is treated as visible in the diff. Should the proof instead
   require the wrapper for every compile?
