<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0. -->

# Fixed result.c launcher staging

This packet prepares pinned material for one test-fast, non-LTO `result.c`
compile. It does not install a key, start a socket or service, run `bwrap`,
write a launch receipt, or admit reuse. `fixed_result_launcher preflight`
returns exit 2 even when every pinned byte matches. That remains true until
the root launcher, worker ACK, signer, publisher, and receiver are qualified
under distinct host UIDs. Same-UID fixtures are always ineligible.

## Installed policy and pins

The administrator stages reviewed files in root-owned mode 0700
`/root/z23verify-staging`. The install script requires already-created exact
accounts `z23verify` UID/GID 60092 and `z23vcc` UID/GID 60093, plus root-owned
source, tool, and check images at the paths in
`fixed_result_launch_policy.v1`. It does not create accounts or images.

The staged policy's SHA3-256 is
`1315fa7fb2a718829a881955bf7415c3b4bdabc30d89ddeda0e0781983cc4abe`.
The profile is `test_fast`: `tools/verify/fixed_result_fast.args`, installed
as `/etc/z23verify/fixed_result_fast.args`, SHA3-256
`41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082`. The
strict profile (`5fb3b135…aadaf`) is retired; a pins file, receipt or record
that names it refuses `contract_profile_mismatch`.

Every byte string below is one framing, `z23verify.fixed_result.v2`: F(x) is
the 8-byte little-endian length of x followed by x, and an artifact is
F(domain) then F(label) F(value) per field in a fixed order.
[`docs/work/verifier-contract-v2.md`](../../docs/work/verifier-contract-v2.md)
spells out every artifact; `tools/verify/fixed_result_contract.h` is the one
encoder and parser. The environment root is SHA3-256 of
F(`z23verify.fixed_result.env.v2`) then F(`env`) F(entry) for `LC_ALL=C`,
`TZ=UTC`, `TMPDIR=/tmp` and `PATH=/usr/bin:/bin`, in that order. Any other
environment, including `TMPDIR=/work`, refuses `contract_env_mismatch`.

The policy names the root image paths, fixed host UIDs, `/zclassic23`,
read-only tool/source mounts, private `/work` and `/tmp`, no network, and the
exact seccomp-filter path. A flag saying seccomp mode 2 or a read-only mount
flag alone does not establish this policy. An installed launcher must prove
the actual namespace/filter and the host-side UID before issuing a receipt.

`/etc/z23verify/fixed_result.pins` is one root-owned nlink-1 regular file
with mode 0444 and root-owned, nonwritable ancestors. It is a pins v2 file:
F(`z23verify.fixed_result.pins.v2`), F(`profile`) F(`test_fast`), then the
twelve roots below, each F(label) F(32 raw bytes), in exactly this order,
which is also key v2's order:

```text
source_content_sha3   profile_args_sha3   source_image_sha3
tool_image_sha3       worker_sha3         launcher_sha3
check_image_sha3      environment_sha3    policy_sha3
seccomp_filter_sha3   bwrap_sha3          tree_checker_sha3
```

`z23-fixed-result-launcher pins-encode <12 hex roots>` writes that file to
stdout without privilege and refuses a zero root, the strict profile or
another environment by its contract token. The v1 LF text pins file
(`z23verify.fixed_result.pins.v1`) refuses `contract_version_v1_retired`.

The three image roots are the installed, UID-bound `tree_sha3` values printed by the pinned
`z23-tree-closure hash <absolute-image-path> 0` helper, not a list of only
opened headers. The tree hash includes path names, directory entries,
ownership, modes, and file bytes; absent optional headers therefore remain
bound. The launcher rehashes the helper before invoking it and rehashes all
three images during preflight. The administrator verifies these values and
the reviewed executable bytes before staging pins. A writable source
checkout, an unreviewed binary, or a pin supplied by the signer is not a
root of trust.
The receiver's portable source identity is not the helper's `content_sha3`,
which includes modes. It is the source content root v2 of the fixed
`result.c` chain, as defined in `docs/work/verifier-contract-v2.md`
section 3a.

- `z23-fixed-result-launcher source-content <source image>` prints it.
- It is pinned as `source_content_sha3`.
- Preflight recomputes it over the installed image with the same reader
  the receiver uses.

The receiver independently rechecks the current source, headers, search
namespace and preprocessed bytes. It must not equate a developer-owned
checkout's UID-bound tree hash to the root-owned installed image hash.
`check_image_sha3` must
include an independently pinned current-main proof executor and publisher;
a candidate-built `zcc` cannot establish admission authority.

After staging, the administrator can run
`platform/deploy/fixed-result-launcher-install.sh install`. It checks file
ownership, the two fixed profile/policy digests, account IDs, image presence,
and refuses any previously installed target before copying anything. It then copies
root-owned binaries/configuration and runs the installed preflight. The only
successful installer output is
`fixed_result_installed_material=1 service_started=0 signed_observation=0 attest_eligible=0`.
An absent or changed pin, image, filter, worker, launcher, bwrap, or tree
checker refuses by name; there is no fallback to same-UID signing.

## Launch receipt v2 for the next slice

The root launcher alone may create
`/var/lib/z23verify/launches/<32-lowercase-hex-id>/` (root:root 0700).
The worker receives a launch request v2 (F(`z23verify.fixed_result.request.v2`),
`profile`=`test_fast`, `recorded_cwd`=`/zclassic23`, one
`build/test-obj/epochs/<64 hex>/platform/modules/base/src/result.o` target)
and answers with a result packet v2 (F(`z23verify.fixed_result.packet.v2`))
plus four FDs, named once each and in this order: `object.o`, `deps.d`,
`stderr.bin`, `preprocessed.i`. The worker's scratch spellings (`result.o`,
`result.i`) never leave the worker; an unknown, duplicate or reordered name
refuses by name.

After a normal worker exit and a live host-UID/mount witness, the launcher
copies all four worker FDs into root-owned, nlink-1, mode-0400 siblings under
those canonical names. It writes `launch.bin` last as a root-owned, nlink-1,
mode-0444 file: a launch receipt v2, F(`z23verify.fixed_result.receipt.v2`)
then 46 labeled fields — profile, launch ID, request nonce, `/zclassic23`,
the source path, the epoch target, `z23.gcc14.fast_result.v2:<tool image
hex>`, the twelve pins v2 roots, the scratch directory, both exec-argv v2
hashes, the mount namespace, the fixed compiler identity (UID/GID 60093, no
groups, no capabilities, no_new_privs 1, seccomp mode 2, worker exit 0), and
size plus SHA3 for each of the four artifacts. The v1 LF text receipt
(`z23verify.launch.v1`) refuses `contract_version_v1_retired`.

The launcher sends the signer a root-authenticated one-packet statement with
launch ID and receipt SHA3 plus descriptor copies of the root-owned receipt
and four artifacts. The signer copies those bytes into private staging; the
offline root publisher independently descriptor-opens the private root launch
record and compares its exact bytes and pins before publishing
`<store-key>/<record-sha3>/{attest.bin,object.o,deps.d,stderr.bin,launch.bin}`.
The signed record v2 names that receipt's SHA3, the contract, the fast
profile digest and the target. A launch receipt is evidence of this one
execution only. The receiver still derives the expected closure from its own
current inputs and policy, rebinds `launch.bin` against its own pins, and
verifies the signed record and artifact bytes. An unqualified, missing or
different launch receipt is a cold/refused proof, never a HIT.
