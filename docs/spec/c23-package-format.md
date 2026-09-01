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

<!-- claim: symbol-present VCS_PACKAGE_CHUNK_BYTES contexts/commons/modules/vcs/include/vcs/package_manifest.h # 1 MiB chunk constant -->

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

<!-- claim: symbol-present parent_root contexts/commons/modules/vcs/include/vcs/package_release.h # lineage edge in the envelope -->

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
  `contexts/commons/packages/zhex/` is the reference shape.
- **Single translation unit per component.** A package installs exactly one
  public compilation unit. Internal helper TUs are permitted only when they
  are listed in the manifest and install no additional public header
  (`contexts/commons/packages/zdogfight/` is the standing example). A component that wants
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
scans every package under `contexts/commons/packages/` (manifest exactness, namespaced
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

<!-- claim: symbol-present ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2 engine/composition/include/config/c23_commons_build_profile.h # frozen portable profile -->

- **The receipt is the build's identity.** Everything the artifact depends
  on is committed in the receipt wire: semantic triple, compiler id and
  version, exact flags, the toolchain capsule root (schema v2 — the gcc
  driver/cc1/assembler/sysroot/ABI fingerprint, so "same toolchain" is a
  receipt property, not a side-band comparison), isolation level, test
  verdict, and per-artifact hashes. The flags string's sanitizer segment
  records the OBSERVED outcome, not the profile name: `clean` only when
  both ASan and UBSan ran clean, `not-run` when the recipe declares no
  tests, `unavailable` when the diagnostic could not run, and `findings`
  when a run produced a real report. The install lifecycle re-hashes every
  emitted byte against the receipt before anything is installed — a worker
  that lied cannot install.
- **Reproduction is quorum, not hope.** `vcs_package_reproduce_scan`
  requires at least two distinct matching receipts before a package may be
  called reproduced, and `--reproduce-against` names the first diverging
  rule on any mismatch. A reproduction claim is NEVER served from a compile
  cache: the zcc cache is disabled for every reproduction target, and the
  package fast-object cache verifies cached bytes against sidecars before
  admitting them.
- **Reproduction evidence says HOW independent it is.** `reproduced`
  asserts byte-identity among >= 2 distinct build events. The scan report
  also carries `distinct_toolchains` (the count of distinct nonzero pinned
  toolchain-capsule roots among the matching receipts) and
  `cross_toolchain` — the stronger claim that at least two DIFFERENT pinned
  toolchain capsules produced those identical bytes. Capsule-less v1
  receipts count toward neither: same-capsule reproduction is honest
  evidence of process determinism, not of toolchain independence. These
  are telemetry, not a gate — the publish gate still judges `reproduced`
  alone.
- **Publication requires that evidence.** Network publication of a
  `zclassic23.package` POINTER (`zcode network publish`) refuses by name
  (`REPRODUCTION_NOT_EVIDENCED`) unless the publishing node's own store
  shows two distinct byte-identical installable build receipts for the
  exact (package root, recipe root) pair the signed release commits —
  the install lifecycle files the first, `zcode package reproduce` files
  the distinct second. A node announces only what it has itself built
  twice. Local CAS admission (`zcode create` commit) stays free — it is
  not publication. Other namespaces, PROVIDER records, and the ACK
  evidence kinds are not gated.
- **Toolchain fingerprint.** The toolchain capsule
  (`vcs_toolchain_capsule_v1`) pins compiler driver bytes, backend bytes,
  assembler identity, sysroot, and ABI files into one root. Work-fabric
  receipts and schema-v2 build receipts both commit it; byte-identical
  reproduction across DIFFERENT toolchains still counts — the comparator
  deliberately judges output bytes, with the capsule as named evidence.

<!-- claim: symbol-present vcs_package_build_set_toolchain_capsule contexts/commons/modules/vcs/include/vcs/package_build.h # receipt v2 capsule binding -->

## 4. Evidence: who may say what

Two evidence lanes exist, and they are not interchangeable:

- **Build receipts (`ZCLBLD\r\n`) are unsigned local evidence.** A receipt
  says "THIS node's worker ran THIS build and got THESE bytes." It is
  written only by the node's own install/reproduce lifecycle into its own
  store's `receipts/` directory, keyed by receipt id. Receipts never travel:
  an unsigned receipt received from the network would prove nothing, so no
  wire or command imports one. The reproduction quorum
  (`vcs_package_reproduce_scan`) is therefore always a LOCAL observation —
  and that is why the publish gate can demand it of the publisher's own
  store.
- **Attestations (`ZCLATT\r\n`) are signed portable evidence.** One
  attestation binds the package root, the exact release id, the recipe
  root, per-compiler and sanitizer outcomes, the test facts, and the
  isolation level, signed under the verifier's secp256k1 key
  (`zcl.zcode_attest.v1` domain). Only the separate
  `zclassic23-package-verify` program signs them; the node never compiles
  or executes downloaded code. Attestations are filed under
  `attestations/<attestation-id-hex>` and evaluated by
  `zcode package verify`. They are portable: `zcode package attest import`
  files a third party's signed wire into the local store (filing is not
  acceptance — the local approved-verifier policy applies at evaluation),
  and `zcode package attest offer` / `pull` / `admit` move them between
  nodes over the existing swarm with no human carrying bytes (§4.1).

<!-- claim: symbol-present VCS_PACKAGE_ATTEST_ID_DOMAIN contexts/commons/modules/vcs/include/vcs/package_attest.h # attestation id domain -->

**Verification is quorum over named keys, never anonymous volume.** A
release counts as verified only when at least `VCS_VERIFY_QUORUM_REQUIRED`
(2) APPROVED, INDEPENDENT verifier keys sign MATCHING attestations. The
approved-verifier allowlist (`<datadir>/zcode/approved_verifiers`, one
66-hex pubkey per line) is explicit local configuration and never comes
from the network; self-verification by the publisher's key and duplicate
signers are named rejections. A missing allowlist means no quorum is
possible — a named refusal, not a silent "unverified". The signer quorum is
the latency fast path over bit-identical reproduction, never a substitute
for it.

<!-- claim: symbol-present VCS_VERIFY_QUORUM_REQUIRED contexts/commons/modules/vcs/include/vcs/package_verify_policy.h # quorum constant -->

Evidence establishes only its exact stated claim: a hash identifies bytes,
a signature identifies the key that made a statement, a receipt records a
bound observation. None of them proves that arbitrary code is safe or worth
accepting — acceptance stays a local policy act.

### 4.1 How a signed attestation travels

An attestation is at most `VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES` (681 bytes),
comfortably under `VCS_BLOB_MAX_BYTES`. It therefore moves as an ORDINARY
BLOB — a one-file, one-chunk `content.v2` package carried by the frozen
`zpkgswm` ANNOUNCE/WANT/DATA codec. **No new wire message, no new bound,
and no new store exist for attestation transport, and none may be added.**
A compile-time assertion in `vcs/package_attest_transport.h` breaks the
build if the attestation schema ever outgrows the blob bound; that is the
moment to decide whether attestations still ride as blobs, never a reason
to raise `VCS_BLOB_MAX_BYTES`.

Two roots must not be confused. The TRANSPORT ROOT is
`vcs_blob_root(attestation wire)` — a pure function of the exact signed
bytes, identical on every node forever. The ATTESTATION ID is
`vcs_package_attest_id()`, the SHA3-256 over the canonical encoding minus
the signature; it is the `attestations/` filename and the quorum's signer
coordinate. They are different values and neither substitutes for the
other.

Discovery uses two ordinary signed DHT records in the
`zclassic23.attestation` namespace, and **both are required**:

| Record | Binds | Answers |
| --- | --- | --- |
| `PROVIDER` | `transport_root` = attestation blob root | "ask me for these bytes" |
| `POINTER` | `semantic_root` = attested package root, `transport_root` = attestation blob root | "that blob attests this package" |

The fetch path routes on the PROVIDER record; the puller looks up the
POINTER when all it knows is a package root. Publishing only one is a
silent no-op at pull time. `zcode package attest offer` admits the bytes
into the local store and returns both ready-to-run publish inputs;
`zcode package attest pull` resolves the pointers, fetches each distinct
blob, and admits what arrives. N independent verifiers for one package are
N records at one key, each in its own signed sequence stream; none can
overwrite another.

Carriage does not depend on that discovery layer. A node that ALREADY
holds the bytes — `zcode package fetch` on the transport root, or the swarm
delivering the blob some other way — admits them with
`zcode package attest admit`, naming the transport root directly and
contacting no network. Without it, fetched evidence is stranded wherever
the authenticated record layer is not up, since `import` wants hex the node
does not hold and `pull` wants a working DHT.

<!-- claim: symbol-present VCS_PACKAGE_ATTEST_DHT_NAMESPACE engine/composition/src/boot_zcode_dht_rpc.c # the publish path gates on this exact namespace -->

**The publish-side gate is hygiene; the receiver-side binding check is the
security property.** A node refuses to publish an attestation POINTER for
bytes it does not hold, bytes that are not a canonical `ZCLATT` wire, a
wire whose signature does not verify, or a wire attesting a different
package than the pointer claims. That rule constrains only the node
applying it. A hostile node runs its own build and can publish any pointer
it likes. What protects a reader is that every admission made in answer to
a question about a package passes that package's root as
`expect_package_root`: an attestation whose own `package_root` differs is
refused `package-root-binding` and never filed. `zcode package attest pull`
always passes that root — it resolved the blob FROM a pointer keyed on it,
so an unbound admission there would let a hostile pointer deliver an
attestation for a DIFFERENT package as evidence about yours — and so must
any future puller. `zcode package attest admit` takes `package_root` as an
OPTIONAL input for the deliberately narrower case where the caller names a
transport root directly and is asking about no package; a caller who IS
asking about one MUST pass it, and omitting it is not a safe default but a
strictly weaker act that asserts nothing about any package. Do not treat a
published attestation pointer as trustworthy because the publish gate
exists.

**Admitting is not accepting.** The transport commands deliberately file
attestations signed by keys this node has never approved, carrying failure
result classes, for packages it does not hold. Refusing evidence at intake
would let a node's own allowlist decide what it is allowed to SEE, and a
quorum you can only observe when you already agree with it proves nothing.
The approved-verifier quorum above is applied later, by
`zcode package verify`.

## Wire format index

| Format | Magic | Authority | Root / id domain |
| --- | --- | --- | --- |
| Package tree (content.v2) | `ZCLPKG` | `contexts/commons/modules/vcs/include/vcs/package_manifest.h` | `zcl.package_file.v1`, `zcl.package_manifest.v1` |
| Signed release envelope | `ZCLREL` | `contexts/commons/modules/vcs/include/vcs/package_release.h` | `zcl.zcode_release.v1` |
| Declarative build recipe | `ZCLRCP` | `contexts/commons/modules/vcs/include/vcs/package_recipe.h` | see header |
| Dependency lock | `ZCLLCK` | `contexts/commons/modules/vcs/include/vcs/package_deps.h` | `zcl.zcode_lock.v1` |
| Build receipt | `ZCLBLD` | `contexts/commons/modules/vcs/include/vcs/package_build.h` | `zcl.zcode_build.v1` |
| Verifier attestation | `ZCLATT` | `contexts/commons/modules/vcs/include/vcs/package_attest.h` | `zcl.zcode_attest.v1` |
| Transport carrier | (content.v2) | `contexts/commons/modules/vcs/include/vcs/package_transport.h` | reuses manifest domains |
| API capsule | `ZCLAPI` | `contexts/commons/modules/vcs/src/package_capsule.c` | see source |
| Toolchain capsule | (struct) | `contexts/commons/modules/vcs/include/vcs/build_action.h` | `zcl.toolchain_capsule.v1` |

Transport framing, POINTER/PROVIDER records, and the swarm wire are the
wire lane's concern; they carry these roots verbatim and never reinterpret
them.
