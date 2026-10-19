<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Inert release artifact carrier

Base: `16aefcf146b3e095e54e31552e5c755e7c659e25`.

The release artifact codec prepares one content.v2 root from immutable caller
snapshots. Its three files are `LICENSE` (0100644), `bin/program` (0100755),
and `release.json` (0100644). It reuses package manifest, chunk and CAS
verification. No build, signing, anchor, installation or execution occurs.
The existing C23 source-recipe publication path remains unchanged.

`release.json` is canonical JSON with this exact field order and no whitespace:

```json
{"schema":"z23.release-artifact/1","name":"z23","version":"1.0.0","target":{"os":"linux","arch":"x86_64","abi":"gnu","isa":"x86-64-v3"},"artifact":{"path":"bin/program","size":8,"sha3_256":"<64 lowercase hexadecimal digits>"}}
```

The displayed digest is a placeholder explaining the field, not an executable
example. The codec derives the whole-program SHA3-256 and size from the actual
snapshot. The manifest root independently commits all three files through the
existing domain-separated content.v2 authority and 1 MiB chunk hashes.

Name and version are nonempty printable ASCII labels bounded to 64 and 32
bytes, respectively, matching ZIDR capacities. Target labels are nonempty,
case-sensitive `[A-Za-z0-9._+-]`, each at most 32 bytes. Labels declare the
producer target; they do not qualify compatibility. Receiver policy checks
supported targets. The parser requires exact canonical reserialization, which
refuses unknown or duplicate fields, alternate escapes, whitespace, trailing
data, invalid labels and integer overflow.

Preparation persists nothing. Admission writes through existing coordinate-
verified CAS and checks exact program readback. Interrupted admission may leave
resumable staging. Exact redelivery is idempotent. Filesystem callers must supply
stable bounded snapshots and independently validate their expected digests;
the pure codec neither opens paths nor claims pathname race protection.

The separate ZIDR document signs `(name, version, manifest_root)` beside the
carrier. Consumers must verify that document under their pinned signer policy,
match its labels and exact root, verify the carrier, check target compatibility,
and separately authorize installation. Carrier verification alone establishes
bytes and shape, not signer verification or safe execution.

The public shape classifier remains unchanged and refuses this carrier.
Completeness, pins and storage classes grant no serving authority. Fleet
transport requires its separate authenticated private-scope admission; this
codec introduces no transport permission or public exposure.

## Qualification

On 2026-10-16, GCC 14.2.0 on Linux x86_64 (AMD Ryzen 9 7950X3D),
through the installed admission rail and canonical C23 test-fast profile:

- Final structure GREEN: 0/1 groups failed, zero skips, 2.0 s wall.
- Digest-only mutation: bypassed only the whole-program digest comparison;
  chunk, canonical metadata, license and size checks remained intact. The
  hash-consistent wrong-digest fixture failed its refusal assertion at test
  line 517. Result: 1/1 groups failed, zero skips, 3.2 s wall. The size
  refusal has GREEN coverage; this experiment does not claim a size-only RED.
- Exact original production bytes restored and compared with the retained
  GREEN backup. Restored GREEN: 0/1 groups failed, zero skips, 1.5 s wall.

These are focused test observations, not performance measurements. The
registry fixtures execute prepare and admit with an OWNER authority ceiling;
they do not establish lower-authority refusal. Mutation flags are asserted
at the direct-handler boundary; serialized mutation reporting is not claimed.
No signing, transport, installation, deployment or execution qualification is
claimed. The native command reads and stores inert fixture bytes only.

Receipts are retained under `build/scratch/release-artifact-carrier/`:
`refactor-green.log`, `refactor-digest-red.log`,
`refactor-digest-mutant.diff`, `refactor-green-production.sha256`,
`refactor-restored-production.sha256`, and `refactor-green-restored.log`. Earlier
compile diagnostics (`focused-green-initial.log`, `focused-green-repair.log`)
and fixture diagnostics (`focused-green-fixed.log`) are preserved separately;
they are not the digest-refusal RED witness.

Reproduction and required lint acceptance:

```sh
env VENDOR_CC=gcc devbuild --wait make t-fast-exact ONLY=zcode_release_artifact
env VENDOR_CC=gcc devbuild --wait make lint-fast
```

The retained `lint-fast.log` and its exit file govern lint acceptance. Exact
source and receipt hashes are retained in `qualification.sha256`.

## Native command stages

The authored prepare/admit handlers accept `name`, `version`, `os`, `arch`, `abi`, `isa`,
`program_file`, `program_sha3_256`, `license_file`, and `license_sha3_256`.
Files are read using the existing expected-digest retained-descriptor helper:
regular no-link leaf, bounded exact EOF, matching before/after descriptor
metadata, and exact expected SHA3-256. Ancestor ownership remains a caller
prerequisite. The binary is never executed. File hex input is refused.

Prepare does not open or create a package store. Admit additionally requires
an explicit `datadir`; it has no implicit canonical-datadir fallback. Bounded
root, manifest and metadata output is rendered before any store open. A
refusal clears output data. Any failure after store opening begins reports
`mutated=true` conservatively because directories or staging may remain.
Failures before that boundary report `mutated=false`. A rendered `admitted`
stage is returned only after exact CAS readback succeeds.

Handler fixtures additionally cover pure preparation without CAS creation,
output-allocation refusal before CAS, quota refusal with honest mutation
reporting, exact admission, and wrong expected input digest. The verifier has
separate complete, hash-consistent carriers with incorrect declared program
size or whole-file digest; these must refuse beyond chunk-integrity checks.
The multi-chunk fixture is exactly one existing chunk plus one byte.

## Exact qualified source

| File | SHA-256 |
| --- | --- |
| `release_artifact.h` | `68c1a40529c3a246ba7464478957b27cb81bd0449e9ba42e07cbd062a1fa1880` |
| `release_artifact.c` | `f88b15fc0e051c9c33cbe0fa2c5c6ed39359794bc5f2940b41b6fea5db72fb8b` |
| `native_zcode_release_artifact_command.c` | `d04ac135dd1a26a936cd48946a5a6b094af1cc8970abe8bf5387f1f8ad9cbe89` |
| `test_zcode_release_artifact.c` | `79affb26e1daf90fc3dcfeb0056c8a86cc895a554662947a3fd1a464c17df0c0` |

## Capability closure and final acceptance

`lint-fast: OK` (exit 0) qualified the code and generated documentation.
Two subsequent module declarations record only the direct `CAP_FS_WRITE`
reach of checked-allocation diagnostics, verified against the built objects
and existing symbol classification; no implementation changed.

The initial closure attempt reported an incomplete epoch with nine missing
objects against its unchanged baseline of two. That result was UNPROVEN,
not a pass or a capability violation. Completing the diagnostic's two dev
binary targets succeeded under admission and the checkout lock. The resulting
non-release dev-v2 epoch was
`a5544d0aa08c45bc176e5fa916d657293f96b3c5e1e74c9cd65e7fad8193e0fb`;
`build/bin/z23-dev` had SHA-256
`0cdbe39bc015d3903086cb948fd23ba21d96b3a26cfa4b592b4a89219eb1b43d`.
This is build evidence, not release or deployment acceptance.

The subsequent canonical gate completed with exit 0:
`check_capability_closure: OK — closed`. Receipts are
`capability-closure-incomplete.log`, `complete-dev-epoch.log`, and
`capability-closure.log`, with their retained exit files. The only later
tracked change is this evidence note; no additional build or gate was run
during closeout.
