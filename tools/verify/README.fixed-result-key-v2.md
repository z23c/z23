<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->

# Test-fast result.c key v2 (format only)

`fixed_result_key_v2.c` formats the expected input identity for one existing
`TEST_FAST` GCC 14 compile reached by `dev-proof-bundle-prefork`. It does not
load pins, authenticate an image, verify a mount, establish account separation,
or set `attest_eligible`. No
caller may use successful formatting as permission to reuse an object.

The fixed profile is the exact 200 LF-terminated ordered arguments in
`fixed_result_fast.args`, SHA3-256
`41d985cfdd672074e903b3ff05efec58f4cb4c8d0057a685207d69f007bac082`.
The first argument is `cc`; the final profile argument is the literal
`-frandom-seed=platform/modules/base/src/result.c`. Only a target shaped
`build/test-obj/epochs/<64 lowercase hex>/platform/modules/base/src/result.o`
is accepted. The constructor requires the *actual* ordered 210-token driver
argv: 200 profile tokens (starting at `cc`), then
`-MMD -MP -MF <dep> -MT <target> -c -o <object> source`.
It checks every fixed token, expands
`@CWD@` only against the caller's measured physical cwd, and requires the
target token to match the supplied epoch target. The constructor also requires
the complete actual `execve` environment in this exact four-entry order:
`LC_ALL=C`, `TZ=UTC`, `TMPDIR=/tmp`, `PATH=/usr/bin:/bin`. The caller must
prove the epoch was derived by trusted current-main Make rules, the compiler
image and actual environment were observed, and the two destinations lie in
private safe scratch. The formatter accepts only matching worker paths
`/work/result.<6 alphanumeric>/{deps.d,result.o}` or matching Linux ZCC
paths `/proc/self/fd/<decimal>/{result.d,result.o}`. The caller must verify
the actual directory descriptor or worker scratch ownership and identity.
This pure formatter cannot observe `execve` or prove
those external facts. An untrusted caller can fabricate matching parameters.

`argv_norm` is the bytes `z23verify.fixed_result.argv.v2\n`, followed by each
profile line as decimal byte length, colon, and raw bytes, then the same
encoding of `-MMD`, `-MP`, `-MF`, `<DEP>`, `-MT`, `<EPOCH_TARGET>`, `-c`, `-o`,
`<OBJECT>`, and `platform/modules/base/src/result.c`. No separator or NUL is
inserted. Only the three destination/target values are normalized. The
`recorded_cwd` is `/zclassic23`, which must be the worker's actual physical cwd
inside its qualified jail. The receiver's changing physical proof cwd belongs
in the local execution receipt, after fresh `-E` and a cross-cwd byte-equality
check. The LTO build-only profile cannot use this key.

`argv_norm` keeps its own decimal `len:bytes` text on purpose: it is a record
text field, which must be NUL-free, so it cannot hold binary u64 prefixes.
Every other preimage uses the contract framing F(x) = 8-byte little-endian
length then x (`docs/work/verifier-contract-v2.md`).

`closure_sha3` is SHA3-256 of F(`z23verify.fixed_result.closure.v2`), then
the **twelve** roots, each F(label) F(32 raw bytes), then
F(`recorded_cwd`) F(`/zclassic23`), F(`source`) F(source spelling) and
F(`argv_norm`) F(complete `argv_norm`). The twelve roots are the root-owned
pins v2 (`fixed_result.pins`) exactly, labels and order included:

```text
source_content_sha3  profile_args_sha3  source_image_sha3  tool_image_sha3
worker_sha3          launcher_sha3      check_image_sha3   environment_sha3
policy_sha3          seccomp_filter_sha3  bwrap_sha3       tree_checker_sha3
```

`source_content` is the portable source-content tree; `source_image` is the
installed UID-bound tree. `profile_args` must be the test-fast profile digest
in this version; the strict profile refuses.

The check image must contain the signer, publisher, receiver admission code,
key constructor, pinned current-main proof executor, and all check logic.
The root-owned installer and receiver must prove those membership and image
bytes. The signer key and box key are independently reloaded, pinned, and
checked by the admission policy; neither is treated as a substitute for a
compiler input root. Revocation must refuse any old observation.

The environment root must equal environment root v2: SHA3-256 of
F(`z23verify.fixed_result.env.v2`) then F(`env`) F(entry) for `LC_ALL=C`,
`TZ=UTC`, `TMPDIR=/tmp` and `PATH=/usr/bin:/bin`, in that order. The v1 LF
text root (`19c5ed02…a3ec`) is retired.

`toolchain_id` is
`z23.gcc14.fast_result.v2:<lowercase tool-image root>`.
`pp_sha3` is the SHA3-256 of the receiver's fresh checker `-E` stream;
the existing `zcl_verify_attest_store_key` then binds the five expected fields.
The source-content root measured from the current developer tree must match
the portable root pin. It must **not** be compared to the installed UID-bound
tree hash. All twelve roots currently enter the formatter as caller data;
the root-owned pin loader, live mount/image checks, and source namespace proof
are still required before either signer or receiver can call them trusted.
Until every ordered project search root (including absent earlier headers),
system include tree, compiler backend, loader, DSO, specs and exact installed
mount generation are qualified, the named outcome is
`include_search_namespace_unqualified`; no eligible expected key exists.

The signed donor `deps.d` remains donor evidence. It cannot be copied to an
epoch with another `-MT` target: the receiver's fresh `-E -MMD -MP` must
produce the current-target depfile, which is independently checked and
materialized. A trusted current-main proof executor must verify Make skipped
the physical `-c`, rehash the final object and current depfile, and observe the
executed image. Candidate-built `zcc` has no authority to make that decision.
Any missing pin, changed checker body, unknown source search, malformed target,
or failed fresh check keeps the path cold or blocked under the later policy.
The pinned first-source revision can be reused unchanged; a body edit requires
an administrator to qualify and install a new source image/pin before an
eligible record can exist. The current worker does not durably sign compiler
FAIL observations. A nonzero checker/compiler under otherwise eligible inputs
must block the request and cannot be silently treated as a cold miss.

The local probe exercises formatting only. Its synthetic root vector yields
`closure_sha3=d0fe6bd7bd3689b9cf78e87d4afd3d8acfcbc43c151b9e836ea676b97b5e6dd2`;
the `verify_contract` test group pins the same vector.
It launches zero compilers and avoids zero proof launches. It is not an
eligibility or performance witness.
