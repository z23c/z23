<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Verifier contract `z23verify.fixed_result.v2`

This document fixes every byte that the separate-account verifier for
`platform/modules/base/src/result.c` produces or consumes. The code that
encodes and parses these bytes is
[`tools/verify/fixed_result_contract.h`](../../tools/verify/fixed_result_contract.h)
and `.c`. The signed record and store key are in
[`tools/dev/verify_attest.h`](../../tools/dev/verify_attest.h). The store
reader is [`tools/dev/verify_store.h`](../../tools/dev/verify_store.h). The
test group `verify_contract` holds the adversarial fixtures.

Parsing any artifact never makes it trustworthy. Before a record can admit
anywhere outside `ZCL_TESTING`, all of the following must hold:

- the key is root-pinned;
- the pins are root-owned;
- the signer is UID 60092 (`z23verify`) and the compiler is UID 60093
  (`z23vcc`);
- the publisher's store entries are not owned by the caller's UID.

The test trust roots exist only under `ZCL_TESTING`.

## 1. Framing

`F(x)` is `u64le(len(x)) ‖ x`, where `u64le` is the 8-byte little-endian
byte count. Every v2 artifact is laid out the same way:

```text
F(domain) F(label_1) F(value_1) … F(label_n) F(value_n)
```

The domain is ASCII `z23verify.<artifact>.v2` and is at most 64 bytes. Each
label is ASCII, at most 64 bytes, and must equal the label listed for its
position. Field order is fixed. Nothing may follow the last field unless the
artifact defines a trailer (only the signed record does). Every hash is
SHA3-256. A hash preimage uses the same framing as the artifact it hashes.
Each value has one of these kinds:

| Kind | Bytes |
|---|---|
| TEXT | 1..max bytes, each 0x21–0x7e (no space, NUL, LF) |
| ROOT | exactly 32 bytes, not all zero |
| U64 | exactly 8 bytes, little-endian |
| BLOB | 0..max bytes, no NUL (record text only) |
| EXACT | exactly max bytes, any value |

The decoder checks, in order:

1. A v1 text header refuses `contract_version_v1_retired`.
2. The domain frame must be well formed.
   - An 8-byte prefix that is really ASCII `z23…`, meaning a raw LF- or
     NUL-terminated domain, refuses `contract_domain_malformed`.
   - A framed domain containing a byte outside 0x21–0x7e (for example a
     trailing LF or NUL inside the frame) also refuses
     `contract_domain_malformed`.
3. The domain must be the one expected.
   - Another known v2 domain refuses `contract_artifact_kind_mismatch`.
   - Any other domain, including `…v3`, refuses `contract_version_unknown`.
4. Each field is checked in turn.
   - A wrong or oversize label refuses `contract_field_order`.
   - The end of input where a label should start refuses
     `contract_field_missing`.
   - A length prefix larger than the remaining bytes, or fewer than 8 bytes
     of prefix, refuses `contract_frame_truncated`.
   - A length above the field's max refuses `contract_frame_oversize`.
   - A value of the wrong kind refuses `contract_field_malformed`, or
     `contract_hash_zero` for an all-zero root.
5. Bytes left after the last field refuse `contract_trailing_bytes`.

Every encoder runs the same value checks before it writes, so no encoder
emits bytes that its own parser refuses.

## 2. Fixed values

| Name | Value |
|---|---|
| contract | `z23verify.fixed_result.v2` |
| profile | `test_fast`, file `tools/verify/fixed_result_fast.args`, installed as `/etc/z23verify/fixed_result_fast.args` |
| profile digest | `41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082` |
| recorded cwd | `/zclassic23` |
| source | `platform/modules/base/src/result.c` |
| target | `build/test-obj/epochs/<64 lowercase hex>/platform/modules/base/src/result.o` (121 bytes) |
| scratch | `/work/result.<6 [0-9A-Za-z]>` (19 bytes) |
| toolchain id | `z23.gcc14.fast_result.v2:` ‖ lowercase hex of `tool_image_sha3` (89 bytes) |
| compiler identity | UID/GID 60093 in all six slots, no supplementary groups, no capabilities, `no_new_privs` 1, seccomp mode 2 |

The retired strict profile digest is
`5fb3b13597488c20a9f5aeca2b654fad92b39714d93069c12c082206977aadaf`.
Wherever a profile digest appears, it refuses `contract_profile_mismatch`.
A `test_strict` profile text refuses the same way. A `build/test-rel-obj/…`
target refuses `contract_target_invalid`. Any toolchain other than the one
above, including a `z23.gcc13…` id, refuses
`contract_toolchain_unsupported`.

**Environment root v2.** This is SHA3-256 of the following, in this order:

```text
F("z23verify.fixed_result.env.v2")
F("env") F("LC_ALL=C")
F("env") F("TZ=UTC")
F("env") F("TMPDIR=/tmp")
F("env") F("PATH=/usr/bin:/bin")
```

Any other set or order, including `TMPDIR=/work`, refuses
`contract_env_mismatch`.

**Exec argv v2.** This is SHA3-256 of `F("z23verify.fixed_result.exec_argv.v2")`,
followed by `F("arg") F(arg)` for each argument that the worker passes to
`execve`.

## 3. Pins v2 — `/etc/z23verify/fixed_result.pins`

The pins file is root-owned, nlink 1, mode 0444, and every ancestor is
root-owned and not writable. `z23-fixed-result-launcher pins-encode <12 hex>`
writes it. The layout is:

```text
F("z23verify.fixed_result.pins.v2")
F("profile") F("test_fast")
F("source_content_sha3") F(32)   portable source content root
F("profile_args_sha3")   F(32)   must be the profile digest above
F("source_image_sha3")   F(32)   installed UID-bound source tree
F("tool_image_sha3")     F(32)
F("worker_sha3")         F(32)
F("launcher_sha3")       F(32)
F("check_image_sha3")    F(32)
F("environment_sha3")    F(32)   must be environment root v2
F("policy_sha3")         F(32)
F("seccomp_filter_sha3") F(32)
F("bwrap_sha3")          F(32)
F("tree_checker_sha3")   F(32)
```

These twelve roots are key v2's roots, in the same order, and each file
carries all twelve. `source_content` was added so that pins equal the key.

Preflight checks the installed source image twice:

- The tree checker's `tree_sha3` must equal `source_image`.
- The source content root v2 (section 3a) of the fixed chain in that image
  must equal `source_content`. A mismatch refuses
  `source_content_mismatch`.

The tree checker's `content_sha3` is not a pin. It covers the whole tree
with its modes, which a proof generation cannot reproduce.

A missing `tree_checker` root refuses `contract_field_missing`. A reordered
root refuses `contract_field_order`. A zero root refuses `contract_hash_zero`.

## 3a. Source content root v2

`zcl_fr_source_content_v2` (`tools/verify/fixed_result_contract.c`) is the
only definition of the root:

```text
SHA3-256( F("z23verify.fixed_result.source_content.v2")
          then, for each file:  F("path") F(relative path) F("bytes") F(file bytes) )
```

Rules for the paths:

- Paths are strictly ascending by `strcmp`, so they are sorted and unique.
  Otherwise the root refuses `contract_field_order`.
- Paths are relative, with no empty, `.` or `..` component. Otherwise the
  root refuses `contract_field_malformed`.
- Owner, mode and file type are not hashed.

`zcl_fr_source_content_at` (`tools/verify/fixed_result_source.c`) is the
only reader. It opens each path beneath one root, one component at a time
with `O_NOFOLLOW`, and requires a regular file. Each file must stay unchanged
while it is read and fit within 4 MiB, and all files together within 64 MiB.
Its refusals are `source_content_unreadable`, `_unsafe`, `_limit`,
`_changed` and `_out_of_memory`.

Two callers use it:

- **Launcher.** It measures the fixed chain `zcl_fr_source_chain`:
  - `platform/modules/base/include/base/format_attribute.h`
  - `platform/modules/base/include/base/result.h`
  - `platform/modules/base/src/result.c`

  `z23-fixed-result-launcher source-content <dir>` prints the pin value for
  `pins-encode`. `preflight` measures `SOURCE_IMAGE` the same way.
- **Receiver.** It measures the files its own `-E` read in the proof
  generation.

The two roots are equal exactly when the include chain is still those three
files. `test_verify_receiver` proves this for the real chain, and shows the
root does not change with mode but does change with any byte.


## 4. Launch request v2 (launcher → worker, one SEQPACKET)

```text
F("z23verify.fixed_result.request.v2")
F("profile") F("test_fast")  F("recorded_cwd") F("/zclassic23")  F("target") F(target)
```

Another cwd refuses `contract_cwd_mismatch`. The worker compiles only in
`/zclassic23`.

## 5. Worker result packet v2 (worker → launcher, with four FDs)

```text
F("z23verify.fixed_result.packet.v2")
F("profile") F("test_fast")  F("scratch") F(scratch)  F("target") F(target)
F("compile_argv_sha3") F(32)  F("preprocess_argv_sha3") F(32)
F("environment_sha3") F(32)
F("artifact") F("object.o")  F("artifact") F("deps.d")
F("artifact") F("stderr.bin")  F("artifact") F("preprocessed.i")
```

The SCM_RIGHTS descriptors follow the artifact order: FD 0 is the object,
FD 1 the depfile, FD 2 stderr and FD 3 the `-E` stream.

The worker's own scratch spellings never leave the worker:

| Canonical name | Worker scratch name |
|---|---|
| `object.o` | `result.o` |
| `deps.d` | `deps.d` |
| `stderr.bin` | `stderr.bin` |
| `preprocessed.i` | `result.i` |

Name checks refuse as follows:

- an unknown name refuses `contract_artifact_unknown`;
- a repeated name refuses `contract_artifact_duplicate`;
- a missing or reordered name refuses `contract_artifact_order`.

## 6. Launch receipt v2 — `launch.bin`

The root launcher writes the receipt last, as root-owned, nlink 1, mode 0444,
in `/var/lib/z23verify/launches/<launch_id>/`. It has 46 fields after the
domain:

```text
F("z23verify.fixed_result.receipt.v2")
 1 profile            TEXT  "test_fast"
 2 launch_id          TEXT  32 lowercase hex
 3 request_nonce      TEXT  32 lowercase hex
 4 recorded_cwd       TEXT  "/zclassic23"
 5 source             TEXT  "platform/modules/base/src/result.c"
 6 target             TEXT  121-byte epoch target
 7 toolchain_id       TEXT  toolchain id for field 11
 8-19 the twelve pins v2 roots, same labels and order as §3
20 scratch            TEXT  19-byte scratch
21 compile_argv_sha3  ROOT  exec argv v2 of the -c argv
22 preprocess_argv_sha3 ROOT exec argv v2 of the -E argv
23 mount_namespace_dev U64
24 mount_namespace_ino U64
25-30 compiler_ruid compiler_euid compiler_suid
      compiler_rgid compiler_egid compiler_sgid   U64 = 60093
31 supplementary_groups U64 = 0
32-35 cap_effective cap_permitted cap_inheritable cap_ambient U64 = 0
36 no_new_privs       U64 = 1
37 seccomp_mode       U64 = 2
38 worker_exit        U64 = 0
39 object_size        U64 1..8 MiB    40 object_sha3        ROOT
41 deps_size          U64 1..4 MiB    42 deps_sha3          ROOT
43 stderr_size        U64 0..4 MiB    44 stderr_sha3        ROOT
45 preprocessed_size  U64 1..4 MiB    46 preprocessed_sha3  ROOT
```

Receipt-specific refusals:

- another UID, a group or a capability refuses `contract_identity_mismatch`;
- a nonzero worker exit refuses `contract_worker_exit_nonzero`;
- another source refuses `contract_source_mismatch`;
- an invalid scratch refuses `contract_scratch_invalid`.

A failed compile therefore has no launch receipt.

## 6a. Failure receipt v2 — `launch.bin` for a failed compile

A signed FAIL record must be bound to root-written evidence too, or any
account could make the signer deny a key forever. When the worker's fresh
`-E` succeeded and its `-c` then exited nonzero, the root launcher writes
this artifact instead of a launch receipt, with the same custody (root,
nlink 1, mode 0444). Fields 1–37 are exactly the launch receipt's fields
1–37 (profile through `seccomp_mode`), with the same checks. Then:

```text
F("z23verify.fixed_result.failure.v2")
 1-37 as §6
38 compile_exit       U64 1..255, the -c child's exit status
39 stderr_size        U64 0..4 MiB    40 stderr_sha3        ROOT
41 preprocessed_size  U64 1..4 MiB    42 preprocessed_sha3  ROOT
```

It names no object and no depfile. A `compile_exit` of 0 or above 255
refuses `contract_failure_exit_invalid`. A launch receipt parser refuses a
failure receipt with `contract_artifact_kind_mismatch`, and the reverse. A
failed `-E` has no preprocessed stream, so it has no store key and no
failure receipt; timeout, signal and cancellation produce neither artifact.

The signer seals the FAIL record from it with `exit_code = compile_exit`,
`receipt_sha3` = SHA3 of the failure receipt bytes, `stderr_sha3` from its
field 40, and all-zero `obj_sha3` and `dep_sha3`. The FAIL observation is
stored as `attest.bin`, `stderr.bin` and `launch.bin` (the failure
receipt); its missing `object.o` and `deps.d` never let a PASS through,
because a verified signed FAIL blocks first (§8, step 4).

## 7. Record-to-receipt binding

**Choice: record v2 carries the binding.** The record names four values:

- `contract`
- `profile_sha3`
- `target`
- `receipt_sha3`, the SHA3-256 of the exact `launch.bin` bytes

The alternative was to fold the receipt into `closure_sha3`. It was rejected
because a receipt is per launch: it holds the launch ID, the nonce, the mount
namespace and the artifact hashes. Folding it in would make the store key
differ on every observation, so a receiver could never predict the key from
its own inputs. The store key stays a pure function of what the receiver
measures (§9). The binding is checked per observation.

For each observation, the receiver calls `zcl_fr_receipt_bind(launch.bin,
own pins, own expected, fetched bytes)`. The call succeeds only when all of
these hold:

- the receipt parses as v2;
- its twelve roots equal the receiver's own root-loaded pins
  (`contract_pin_mismatch`);
- its toolchain equals the expected toolchain, the expected cwd is
  `/zclassic23`, and its `preprocessed_sha3` equals the receiver's fresh `-E`
  hash (`contract_receipt_input_mismatch`);
- the object, depfile and stderr sizes and hashes equal the fetched bytes
  (`contract_receipt_artifact_mismatch`);
- the fetched depfile's first rule is `<receipt target>:`
  (`contract_depfile_target_mismatch`).

On success it returns the binding `{contract, pins.profile_args, receipt
target, SHA3(launch.bin)}`. Admission then requires the signed record to
repeat each value exactly:

| Value | Refusal on mismatch |
|---|---|
| contract | `attest_contract_mismatch` |
| profile | `attest_profile_mismatch` |
| target | `attest_target_mismatch` |
| receipt hash | `attest_receipt_mismatch` |

No binding refuses `attest_binding_missing`. A zero or empty expectation is
never a wildcard.

A signed FAIL record (nonzero `exit_code`) still blocks fallback without a
binding, because there is no receipt for a failed worker. It can only deny
reuse, never grant it.

The target is donor evidence. `argv_norm` normalizes the target, so donors in
other epochs share one store key. The stored `deps.d` names the donor's
target. A receiver regenerates its own depfile before it links. That step
belongs to the proof executor, not to this contract.

## 8. Signed record v2 — `attest.bin`

The body:

```text
F("z23verify.attest.v2")
F("contract")     F(BLOB 1..64)      "z23verify.fixed_result.v2"
F("toolchain_id") F(BLOB 1..256)
F("argv_norm")    F(BLOB 1..65536)   key v2 argv_norm
F("recorded_cwd") F(BLOB 0..4096)
F("target")       F(BLOB 0..4096)
F("pp_sha3") F(32)  F("closure_sha3") F(32)  F("profile_sha3") F(32)
F("receipt_sha3") F(32)  F("obj_sha3") F(32)  F("dep_sha3") F(32)
F("stderr_sha3") F(32)
F("exit_code")    F(u64le of the sign-extended int32)
```

The trailer is 150 bytes and follows the body directly:
`F("signer_pubkey") F(32) F("signature") F(64)`.

The signature is Ed25519 over `F("z23verify.attest.signature.v2") ‖ body`.

Admission checks run in this order:

1. schema v2 (v1 refuses `attest_record_v1_unbound`)
2. signer (the box key refuses `attest_signed_by_box_signer`, whatever key the
   trailer claims)
3. toolchain, argv, cwd, pp and closure
4. signed FAIL → block
5. binding
6. artifact bytes

A `zcl.verify_attest.v1` record still parses, with `schema_version` 1, so
that it can be named. It never admits. Any other unknown or framed-wrong
domain refuses `attest_schema_unknown`. An exit code outside the int32 range,
or trailing bytes, refuses `attest_record_malformed`.

A signed FAIL blocks only after schema v2 and the signer check pass. A v1
record carrying a signed FAIL therefore no longer blocks, as it did before
v2. It refuses `attest_record_v1_unbound` and the lookup stays COLD, so the
receiver compiles locally. This is conservative and intended: a v1 record
names no launch receipt, so its FAIL cannot be tied to a root launch.

## 9. Expected key and store key

The expected key (key v2, `tools/verify/fixed_result_key_v2.h`) is
`{toolchain_id, argv_norm, recorded_cwd, pp_sha3, closure_sha3}`:

- **`argv_norm`** is the text line `z23verify.fixed_result.argv.v2\n`
  followed by decimal `len:bytes` for each profile line, then `-MMD -MP -MF
  <DEP> -MT <EPOCH_TARGET> -c -o <OBJECT> <source>`. This is the one
  deliberate non-framed value, because record text must be NUL-free.
- **`closure_sha3`** is SHA3-256 of
  `F("z23verify.fixed_result.closure.v2")`, the twelve roots as
  `F(label) F(32)` in pins order, `F("recorded_cwd") F("/zclassic23")`,
  `F("source") F(source)` and `F("argv_norm") F(argv_norm)`.
- **`pp_sha3`** is the receiver's fresh `-E` hash.

For the probe fixture (every byte of root i is `i+1`, with the real profile
and environment roots), the closure is
`d0fe6bd7bd3689b9cf78e87d4afd3d8acfcbc43c151b9e836ea676b97b5e6dd2`.
`verify_contract` pins this value.

The store key v2 is SHA3-256 of:

```text
F("z23verify.attest.store_key.v2")
F("toolchain_id") F(…) F("argv_norm") F(…) F("recorded_cwd") F(…)
F("pp_sha3") F(32) F("closure_sha3") F(32)
```

It is written as 64 lowercase hex.

## 10. Store layout v2

```text
<root>/locks/fixed_result.lock
<root>/store/<store-key>/<record-sha3>/attest.bin
                                     /object.o
                                     /deps.d
                                     /stderr.bin
                                     /launch.bin
```

`<record-sha3>` is the lowercase-hex SHA3-256 of the whole `attest.bin`.
`preprocessed.i` is not stored, because the receiver makes its own. Any other
child refuses `store_observation_child_unknown`. A missing child refuses
`store_artifact_missing`.

The publisher is root custody. The production reader refuses
`store_owner_same_uid` when the caller's effective UID is the signer UID or
the publisher UID. The `ZCL_TESTING` fixture refuses the same way unless the
test sets `allow_same_uid`.

The production reader takes no pins argument. On every call,
`zcl_verify_store_lookup` loads `/etc/z23verify/fixed_result.pins` itself
with `zcl_verify_store_pins_load`. It walks from `/` by descriptor, and every
directory must be root-owned and not group or world writable. It opens the
file with `O_NOFOLLOW`, and the file must be root-owned, regular, nlink 1 and
mode exactly `0444`. The walk then applies `zcl_fr_pins_parse`. The refusal
tokens are:

The receiver also reloads and compares all twelve pins after scanning a HIT,
before it hands verified artifact bytes to the caller. A root installer that
rotates pins must take `fixed_result.lock` exclusively through atomic pin
replacement, so the reader's shared lock protects artifact materialization
against a later rotation. A changed or unavailable pin set at the final check
returns COLD `store_pins_changed`.

| Condition | Token |
|---|---|
| A directory on the walk is not root-owned, is writable, or is missing | `store_pins_path_unsafe` |
| The pins file is absent | `store_pins_missing` |
| The file is a symlink, not root-owned, not exactly `0444`, has nlink > 1, or is empty or oversized | `store_pins_unsafe` |
| The file changed while it was being read | `store_pins_changed` |
| The bytes are bad | The contract token (for example `contract_version_v1_retired`) |

Every refusal leaves the lookup COLD. Only the `ZCL_TESTING` fixture lookup
takes pins as an argument, and there a NULL pins argument refuses
`store_pins_unqualified`.

### Publishing a conflict

A signed PASS and a signed FAIL for the same exact store key mean either a
nondeterministic compile or a compromise. The publisher does not choose
between them, and it never hides one:

- The second observation, of either verdict, is published no-clobber as its
  own `<record-sha3>/` directory in the same `store/<store-key>/`. This is
  the directory every receiver scans for that key.
- The receiver's `zcl_verify_attest_admit_set` sees both records. It returns
  FAIL with `attest_eligible_conflict`, which the store reader reports as
  BLOCK. The order does not matter: FAIL then PASS and PASS then FAIL both
  block, and neither ever HITs.
- The publisher's result names the conflict: `publisher_conflict_fail_exists`
  when a FAIL was already stored, or `publisher_conflict_pass_exists` when a
  PASS was.
- It also writes a root-private audit copy of the new `attest.bin` to
  `conflicts/<store-key>.<record-sha3>.attest`. That copy is for the
  operator only. The record in the store is what blocks.
- Only an identical `<record-sha3>` refuses, with `publisher_record_exists`.
  Nothing under `store/` is ever unlinked or rewritten.
- The publisher scans at most 96 record directories per key (`FRP_SCAN_MAX`).
  Once a key holds more than 96, the scan overflows and
  every further publish to that key refuses `publisher_store_unsafe`.
  Receivers already BLOCK with `store_scan_incomplete` once the key holds
  more than 64 observations (`VS_MAX_OBSERVATIONS`). A key that full is an
  operator incident, not a reuse path.

## 11. Retired v1 artifacts

A v2 consumer refuses every retired artifact by name. Nothing parses a v1
artifact as v2.

| v1 artifact | Refusal |
|---|---|
| `z23verify.fixed_result.pins.v1` LF text pins | `contract_version_v1_retired` |
| `z23.vcc.fixed_result.fast.v1` LF text request | `contract_version_v1_retired` |
| `z23vcc.result.fast.v1` LF text packet | `contract_version_v1_retired` |
| `z23verify.launch.v1` LF text receipt | `contract_version_v1_retired` |
| `z23verify.fixed_result.env.v1` LF text environment root (`19c5ed02…a3ec`) | `contract_env_mismatch` wherever it appears as a root |
| `z23verify.fixed_result.exec_argv.v1` argv hash | worker no longer produces it; a receipt carrying it fails the argv binding |
| `zcl.verify_attest.v1` record with NUL-terminated `zcl.verify_attest.sig.v1` signature and `zcl.verify_attest.store.v2` store key | parses to be named, then `attest_record_v1_unbound` |
| strict profile `fixed_result_strict.args` (`5fb3b135…`) | `contract_profile_mismatch`; the installer refuses `fast_profile_mismatch` |

Two historical tools are kept:

- **`tools/verify/fixed_result_closure.c`** (closure v1:
  `z23.verify.fixed_result.closure.v1`, `z23.gcc13.x86_64.fixed_result.v1`,
  `TMPDIR=/work`). It is kept only because `tree_closure_probe.sh` runs it.
- **`tools/verify/compile_core.c`** (the GCC 13/14 direct-source probe). It is
  kept only because `real_tu_probe.sh` runs it.

Both are marked historical in their headers, and no v2 consumer accepts
their output.

## 12. Refusal tokens

**Contract** (`ZCL_FR_WHY_*`):

- `contract_arguments_invalid`
- `contract_buffer_limit`
- `contract_version_v1_retired`
- `contract_version_unknown`
- `contract_artifact_kind_mismatch`
- `contract_domain_malformed`
- `contract_frame_truncated`
- `contract_frame_oversize`
- `contract_field_missing`
- `contract_field_order`
- `contract_field_malformed`
- `contract_hash_zero`
- `contract_trailing_bytes`
- `contract_profile_mismatch`
- `contract_target_invalid`
- `contract_toolchain_unsupported`
- `contract_env_mismatch`
- `contract_cwd_mismatch`
- `contract_source_mismatch`
- `contract_scratch_invalid`
- `contract_identity_mismatch`
- `contract_worker_exit_nonzero`
- `contract_artifact_duplicate`
- `contract_artifact_unknown`
- `contract_artifact_order`
- `contract_pin_mismatch`
- `contract_receipt_artifact_mismatch`
- `contract_receipt_input_mismatch`
- `contract_depfile_target_mismatch`
- `contract_failure_exit_invalid`

**Record admission, new in v2:**

- `attest_record_v1_unbound`
- `attest_binding_missing`
- `attest_contract_mismatch`
- `attest_profile_mismatch`
- `attest_target_mismatch`
- `attest_receipt_mismatch`

The existing `attest_*`, `verifier_key_*` and `store_*` tokens are unchanged.
