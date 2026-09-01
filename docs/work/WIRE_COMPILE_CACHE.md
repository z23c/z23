<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# The wire lane: transfer, discovery, and the cross-node compile cache

This is the working design note for the Commons WIRE lane. The normative
package format authority is [`../spec/c23-package-format.md`](../spec/c23-package-format.md);
its last line is this lane's charter: *transport framing, POINTER/PROVIDER
records, and the swarm wire carry the format roots verbatim and never
reinterpret them.* Identity (content.v2 roots, `ZCLBLD` receipts, recipes,
locks, package anatomy) belongs to the format lane. If this note and the
format spec disagree, the format spec is right.

## Mission

The wire lane's product claim: **a node that wants software never compiles
what the network has already compiled.** Every node that ever built a package
becomes an accelerator for every other node, with no new trust: fetched
objects are inert bytes until the receiving owner's existing admission path
accepts them.

## The two halves of the compile cache

**The local half already exists.** `zcl.fastobj.v1` (in
`tools/package_verify.c`, driven by `--fast-cache=<dir>`) keys each cached
translation-unit object by exactly the compile-action identity:
the v1 toolchain capsule root, target, profile, the root-normalized compile
argv, and the SHA3-256 of the preprocessed unit (which subsumes the TU and
its transitive headers). A hit is admitted only after the sidecar's
`object_sha3` is verified against the cached bytes and the materialized bytes
are re-verified; the build receipt still re-hashes every output, so a hit can
change build time but never build identity. Reproduction targets never use
the cache.

**The P2P half is this lane's work**, in ordered slices:

1. **BLAKE3 primitive.** A portable C23 implementation in `core/modules/crypto/`
   beside blake2b/blake2s, pinned to the official test vectors. No consumer
   yet; it is the foundation of the transfer-verification layer below.
2. **Object-set carrier (offline proof).** A builder's cached objects plus
   sidecars exported as an ordinary content.v2 package — the
   transport-carrier pattern: no new CAS object, no new wire frame, and a
   deterministic root for identical object bytes. Proven first between two
   local cache directories with a C23 helper (no daemon): export, fetch by
   root, admit into the second cache, build there with zero compiler spawns,
   and identical receipt bytes.
3. **Live wiring.** The package build path opts into the shared cache;
   the commons journey acceptance grows the "second node never compiles"
   observation, and the publisher-vanish topology from the multihost
   acceptance is reused for the artifact shelf.
4. **Discovery and economics.** A DHT PROVIDER record namespace for object
   sets (requesters derive the same fastobj keys locally — the toolchain
   capsule root is stable across ordinary hosts because assembler identity
   is the GNU as version string). Serving nodes earn the existing verified
   upload credit through the existing service book; tiers, quotas, and the
   FREE allowance are unchanged.
5. **Swarm wire v2 (measured, not assumed).** BLAKE3 streaming verification
   for large transfers — sub-chunk early abort, parallel verification,
   cheap bad-peer pruning — as an explicit new wire schema version anchored
   to the frozen SHA3-256 chunk identity. Adopted only if measurement shows
   verification throughput or wasted-bytes-per-bad-peer actually binds; old
   evidence is never relabeled.

## Invariants

- **A fastobj key is an INPUT identity.** No fetched object is ever admitted
  on its own key alone: the output anchor is a `ZCLBLD` receipt's artifact
  hash (schema v2 binds the toolchain capsule root), and admission runs the
  existing local policy path. Fetch, verify, build, and install stay separate
  stages with separate receipts.
- **BLAKE3 is a transfer hash, never an identity hash.** Stored identity
  stays content.v2 SHA3-256; consensus hashes are untouched. A BLAKE3
  commitment is transport-local and disposable.
- **The blockchain wins.** Object transfer is package activity: bounded,
  quota'd, asynchronous, and never ahead of consensus or peer health.
- **No second source of truth.** Objects ride the existing CAS, swarm, DHT
  record, receipt, and credit authorities. This lane adds carriers and
  records, not parallel machinery.
