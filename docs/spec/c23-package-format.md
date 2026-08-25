<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# C23 Commons package format

This is the normative reading of the Commons package format: what a package
IS, how it is named (never by name), how versions relate, what a conforming
package looks like inside, and how a build proves determinism instead of
hoping for it.

The byte-level wire contracts live in the authority headers listed in the
[index](#wire-format-index) — each is a pure codec with its canonical
encoding frozen in its own header comment. This document binds those
contracts into one format discipline and states the rules that sit BETWEEN
the wires. Where this document and a header disagree, the header is right;
fix this document. Wire formats change only by an explicit new schema
version; old evidence is never relabeled.

The journey these formats serve is [`../C23_COMMONS_QUICKSTART.md`](../C23_COMMONS_QUICKSTART.md).

## 1. Identity: semantic vs artifact

**A package is a Merkle tree of content-addressed file chunks.** The
content.v2 manifest (`ZCLPKG\r\n`) maps canonical package-relative paths to
exact sizes, restricted modes, and ordered raw SHA3-256 hashes of 1 MiB
chunks; `package_root` is a domain-separated flat commitment over the sorted
per-file leaf hashes. Chunk identity is raw SHA3-256 with no path context,
so chunks deduplicate across files, across packages, and across the
transport carrier for free.

<!-- claim: symbol-present VCS_PACKAGE_CHUNK_BYTES lib/vcs/include/vcs/package_manifest.h # 1 MiB chunk constant -->

`package_root` is the ONLY semantic identity. Everything else is a label or
a claim about that root:

- `name` ("publisher/package"), `semver`, and a ZNAM pointer are display
  labels. They are never resolved on the wire, never index content, and no
  network-wide name lookup exists. A local name binding that disagrees with
  the root it resolves to fails closed (`ERR_LABEL_MISMATCH`).
- A **version is a DAG edge, not a name**. The signed release envelope
  (`ZCLREL\r\n`) carries `parent_root` + a monotonic `publisher_sequence`
  under one publisher key: release history is a publisher-keyed chain of
  exact roots. There are no version ranges, no "latest", no floating tags —
  a consumer pins a root, and an upgrade is a new root whose edge points at
  the old one.

<!-- claim: symbol-present parent_root lib/vcs/include/vcs/package_release.h # lineage edge in the envelope -->

- **Dependencies are exact roots.** The declaration file is itself a member
  of the content.v2 tree (editing a dependency changes the package root);
  the resolver emits a canonical post-order lock wire (`ZCLLCK\r\n`) whose
  `lock_root` every downstream build pins. No ranges, no conflict
  resolution: the DAG is closed at author time.

Semantic identity — what the package IS — is the triple
`(package_root, recipe_root, lock_root)`: the exact source tree, the
declarative build recipe, and the exact dependency closure.

**Artifact identity is separate and narrower.** A build receipt
(`ZCLBLD\r\n`) binds that triple plus the compiler identity, the exact flag
string, the isolation level, and the SHA3-256 of every emitted artifact.
Two nodes that agree on `package_root` agree on what the package is; they
agree on artifact BYTES only when the full receipt tuple matches. Receipts
are evidence about one exact build, never a property of the package itself.

## 2. Package anatomy discipline

One package is one component. The anatomy rules exist so that any node can
read, verify, and rebuild any package without knowing its author:

- **Directory contract.** `zcode-package.json` manifest, `LICENSE` (bytes
  held against the declared SPDX identifier at serve time), `README.md`,
  `include/<name>/<name>.h` public headers, `src/` sources, `tests/` tests.
  `packages/zhex/` is the reference shape.
- **Single translation unit per component.** A package installs exactly one
  public compilation unit. Internal helper TUs are permitted only when they
  are listed in the manifest and install no additional public header
  (`packages/zdogfight/` is the standing example). A component that wants
  two public TUs is two packages joined by a dependency edge.
- **Zero function-like macros in public headers.** Constants are `enum` or
  C23 `constexpr`; polymorphism is `_Generic`/`typeof`; contracts are
  `static_assert`. A function-like macro is untyped, unhygienic,
  textually-scoped, and invisible to the API capsule that commits the
  public surface — C23 made it unnecessary, so the format forbids it.
- **No function bodies in public headers** (no `static inline` APIs): the
  installed artifact is the static archive; the header is its exact
  interface.
- **Opaque structs are the abstraction barrier.** Public headers declare
  handle types and pointer-taking functions. The standing exception is a
  caller-allocated value type (arena, parser context, fixed-size point)
  whose storage the caller must own — such a struct is defined in the
  header, documented as a value type, and never grows private state.
- **C23 only.** `-std=c23` is in the frozen build profile; extensions are
  not part of the format.

These rules are enforced, not aspirational: `make check-package-anatomy`
scans every package under `packages/` (manifest exactness, namespaced
guarded header, no function-like macros, no inline bodies, declared
internal TUs, no executable build logic), and the public-serve shape
refuses a package whose declared license text does not match its LICENSE
bytes.

<!-- claim: gate-passes check-package-anatomy # anatomy discipline is a hard gate -->

## 3. Determinism: proven, not hoped

A Commons build is a confined observation, not an act of faith:

- **Hermetic, path-scrubbed build.** The isolated worker
  (`tools/package_verify.c`) compiles under seccomp + Landlock + rlimits
  with a scrubbed, pinned environment (`TMPDIR`, `LANG=C`, `TZ=UTC`,
  `SOURCE_DATE_EPOCH=0` — so neither locale, clock, nor `__DATE__`/
  `__TIME__` can enter diagnostics or artifacts) and
  `-ffile-prefix-map=SOURCE=.` so the checkout path cannot enter the
  artifact. The frozen profile forces the original AMD64/SSE2 baseline
  (`-march=x86-64 -mtune=generic`) so artifacts never depend on the build
  host's CPU, and the archiver runs in explicit deterministic mode
  (`ar rcsD`: zeroed uid/gid/mtime) rather than relying on a toolchain
  default.

<!-- claim: symbol-present ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2 config/include/config/c23_commons_build_profile.h # frozen portable profile -->

- **The receipt is the build's identity.** Everything the artifact depends
  on is committed in the receipt wire: semantic triple, compiler id and
  version, exact flags, the toolchain capsule root (schema v2 — the gcc
  driver/cc1/assembler/sysroot/ABI fingerprint, so "same toolchain" is a
  receipt property, not a side-band comparison), isolation level, test
  verdict, and per-artifact hashes. The install lifecycle re-hashes every
  emitted byte against the receipt before anything is installed — a worker
  that lied cannot install.
- **Reproduction is quorum, not hope.** `vcs_package_reproduce_scan`
  requires at least two distinct matching receipts before a package may be
  called reproduced, and `--reproduce-against` names the first diverging
  rule on any mismatch. A reproduction claim is NEVER served from a compile
  cache: the zcc cache is disabled for every reproduction target, and the
  package fast-object cache verifies cached bytes against sidecars before
  admitting them.
- **Toolchain fingerprint.** The toolchain capsule
  (`vcs_toolchain_capsule_v1`) pins compiler driver bytes, backend bytes,
  assembler identity, sysroot, and ABI files into one root. Work-fabric
  receipts and schema-v2 build receipts both commit it; byte-identical
  reproduction across DIFFERENT toolchains still counts — the comparator
  deliberately judges output bytes, with the capsule as named evidence.

<!-- claim: symbol-present vcs_package_build_set_toolchain_capsule lib/vcs/include/vcs/package_build.h # receipt v2 capsule binding -->

### Open hardening in this lane

The following format rules are being landed; until each does, this section
— not prose elsewhere — is their status:

1. **Publish requires two agreeing reproduction hashes.** Network
   publication (`zcode network publish`) refuses a package whose local
   store cannot show two distinct agreeing build receipts for the exact
   semantic triple. Local CAS admission (`zcode create` commit) stays free
   — it is not publication.

## Wire format index

| Format | Magic | Authority | Root / id domain |
| --- | --- | --- | --- |
| Package tree (content.v2) | `ZCLPKG` | `lib/vcs/include/vcs/package_manifest.h` | `zcl.package_file.v1`, `zcl.package_manifest.v1` |
| Signed release envelope | `ZCLREL` | `lib/vcs/include/vcs/package_release.h` | `zcl.zcode_release.v1` |
| Declarative build recipe | `ZCLRCP` | `lib/vcs/include/vcs/package_recipe.h` | see header |
| Dependency lock | `ZCLLCK` | `lib/vcs/include/vcs/package_deps.h` | `zcl.zcode_lock.v1` |
| Build receipt | `ZCLBLD` | `lib/vcs/include/vcs/package_build.h` | `zcl.zcode_build.v1` |
| Transport carrier | (content.v2) | `lib/vcs/include/vcs/package_transport.h` | reuses manifest domains |
| API capsule | `ZCLAPI` | `lib/vcs/src/package_capsule.c` | see source |
| Toolchain capsule | (struct) | `lib/vcs/include/vcs/build_action.h` | `zcl.toolchain_capsule.v1` |

Transport framing, POINTER/PROVIDER records, and the swarm wire are the
wire lane's concern; they carry these roots verbatim and never reinterpret
them.
