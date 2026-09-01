/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_attest_transport — how a signed ZCLATT attestation MOVES.
 *
 * Before this layer, an attestation could only reach another node as
 * operator-carried hex: the verifier program wrote it into its own
 * store's attestations/ dir, and a human moved the bytes. That made the
 * independent-verifier quorum unreachable for anyone who could not walk
 * bytes between machines, which is the opposite of runs-anywhere.
 *
 * IT ADDS NO WIRE MESSAGE, NO NEW BOUND, AND NO NEW STORE. A canonical
 * attestation is at most VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES (681) — far
 * under VCS_BLOB_MAX_BYTES (8192) — so it travels as an ordinary BLOB
 * (vcs/blob_store.h): a content.v2 package with exactly one file and
 * exactly one chunk, announced/wanted/served over the already-frozen
 * 'zpkgswm' ANNOUNCE/WANT/DATA codec unchanged. The static assertion
 * below makes that structural rather than incidental. Nothing here
 * raises the store quota, the package cap, the swarm frame ceiling, or
 * the blob bound.
 *
 *   TRANSPORT ROOT  = vcs_blob_root(attestation wire) — a pure function
 *                     of the exact signed bytes, identical on every node
 *                     forever. It is NOT the attestation id.
 *   ATTESTATION ID  = vcs_package_attest_id() — SHA3-256 over the
 *                     canonical encoding minus the signature. It is the
 *                     store filename and the quorum's signer coordinate.
 *
 * DISCOVERY is a signed DHT POINTER record (vcs/zcode_dht_record.h) in
 * VCS_PACKAGE_ATTEST_DHT_NAMESPACE binding
 *     semantic_root  = the attested package root
 *     transport_root = the attestation blob root
 * so a lookup at key(genesis, POINTER, <ns>, package_root) returns ONE
 * pointer per verifier that published one. N independent verifiers for
 * one package are N records at one key, each in its own signed
 * sequence stream; none can overwrite another.
 *
 * THE AUTHENTICATION SPLIT IS PRESERVED. The blob layer proves BYTES
 * ONLY: the root commits the length and the SHA3-256 of the content,
 * nothing else. Whether those bytes are a genuine attestation is asked
 * AFTER they arrive, by this layer, against the ZCLATT grammar and the
 * embedded secp256k1 signature. Whether that signer COUNTS — approved,
 * independent, quorum — remains the policy layer's rule
 * (vcs/package_verify_policy.h), applied at evaluation time by
 * `zcode package verify`, NEVER at admission time here.
 *
 * ADMITTING IS NOT ACCEPTING, exactly as filing is not acceptance for
 * `zcode package attest import`. This layer will file an attestation
 * whose verifier this node has never approved, whose result class is a
 * failure, and whose package is not locally present. That is
 * deliberate: refusing evidence at intake would let a node's own
 * allowlist decide what it is allowed to SEE, and a quorum you can only
 * observe when you already agree with it proves nothing.
 *
 * WHAT IT REFUSES, ALWAYS BY NAME: bytes that are not a canonical
 * ZCLATT wire; a wire whose embedded signature does not verify; a wire
 * whose recomputed id does not match where it is being filed; and — on
 * the pull path — a wire whose package_root does not equal the root the
 * caller asked about. That last one is what stops a pointer in this
 * namespace from delivering an attestation for a DIFFERENT package.
 *
 * This layer has no sockets, no threads, and no wall clock. Scheduling
 * a transfer is the swarm engine's job and the caller drives it. */

#ifndef ZCL_VCS_PACKAGE_ATTEST_TRANSPORT_H
#define ZCL_VCS_PACKAGE_ATTEST_TRANSPORT_H

#include "vcs/blob_store.h"
#include "vcs/package_attest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The DHT record namespace attestation pointers live in. Canonical
 * lower-case ASCII, inside VCS_ZCODE_DHT_RECORD_NAMESPACE_MAX (31).
 * Allocated by owner decision on 2026-08-25, alongside the existing
 * zclassic23.source / .package / .service / .pid / .other. ONE
 * definition, so a future reassignment is one line here and a spec row,
 * never a search through call sites. */
#define VCS_PACKAGE_ATTEST_DHT_NAMESPACE "zclassic23.attestation"

/* The blob-carriage claim, enforced at compile time rather than
 * asserted in prose. If a future attestation schema grows past the blob
 * bound, this breaks the BUILD — which is the correct moment to decide
 * whether attestations still ride as blobs, and never something to
 * "fix" by raising VCS_BLOB_MAX_BYTES. */
static_assert(VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES <= VCS_BLOB_MAX_BYTES,
              "an attestation must fit one blob: it is carried as a "
              "one-file one-chunk content.v2 package over the frozen "
              "zpkgswm codec, with no new message and no new bound");

struct vcs_package_store;

/* Every rejection names the failed rule. The enum order is frozen. */
enum vcs_package_attest_transport_result {
    VCS_PACKAGE_ATTEST_TRANSPORT_OK = 0,
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_NULL,      /* null argument */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ALLOC,     /* allocation failure */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_PATH,      /* zcode dir path too long */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ABSENT,    /* no such local object */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BLOB,      /* blob layer refused
                                                 * (see *_blob_error) */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ATTEST,    /* not a canonical ZCLATT,
                                                 * or the embedded signature
                                                 * does not verify (see
                                                 * *_attest_error) */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_ID,        /* recomputed id does not
                                                 * match the coordinate the
                                                 * caller named */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_BINDING,   /* package_root is not the
                                                 * root the caller asked
                                                 * about: a pointer in this
                                                 * namespace delivered an
                                                 * attestation for another
                                                 * package */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_STORE,     /* store write/read refused */
    VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT,  /* a different or unreadable
                                                 * object already occupies
                                                 * this attestation id —
                                                 * impossible for honest
                                                 * wires, so fail closed */
};

const char *vcs_package_attest_transport_result_string(
    enum vcs_package_attest_transport_result result);

/* A bounded outcome record. `blob_error` and `attest_error` carry the
 * underlying layer's exact rule when `result` is ERR_BLOB / ERR_ATTEST,
 * so a caller never has to re-derive why. Both are 0 otherwise. */
struct vcs_package_attest_transport_outcome {
    enum vcs_package_attest_transport_result result;
    enum vcs_blob_result blob_error;
    enum vcs_package_attest_error attest_error;
    uint8_t attestation_id[VCS_PACKAGE_ATTEST_ID_BYTES];
    uint8_t transport_root[32];
    struct vcs_package_attest attestation; /* valid only when result is OK */
    bool filed;           /* the bytes were newly written */
    bool already_present; /* identical bytes were already filed */
};

/* ── pure: the transport root of these exact bytes ──────────────────── */

/* The blob root a POINTER must name for this wire. Pure: no store, no
 * network, no filesystem. The wire is parsed and its signature verified
 * FIRST — a node never advertises a transport root for bytes it has not
 * proven are a genuine attestation. */
enum vcs_package_attest_transport_result vcs_package_attest_transport_root(
    const uint8_t *wire, size_t wire_len,
    struct vcs_package_attest_transport_outcome *out);

/* ── local filing (the one implementation) ──────────────────────────── */

/* File the exact bytes at <zcode_dir>/attestations/<attestation-id-hex>
 * with tmp+fsync+rename discipline, creating the directory if needed.
 * `wire`/`wire_len` must already have been parsed and verified by the
 * caller, and `id` must be its recomputed attestation id.
 *
 * Idempotent: the id IS the content hash, so a same-name file holding
 * identical bytes is a no-op success reporting already_present=true. A
 * same-name file that does not read back identical is store corruption
 * and returns ERR_CONFLICT — it is never silently overwritten.
 *
 * This is the SINGLE writer used by both the operator import path and
 * the swarm pull path; neither keeps its own copy of this discipline. */
enum vcs_package_attest_transport_result vcs_package_attest_transport_file(
    const char *zcode_dir, const uint8_t *wire, size_t wire_len,
    const uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES], bool *out_filed,
    bool *out_already_present);

/* ── publish side: make a local attestation reachable ───────────────── */

/* Read <zcode_dir>/attestations/<id-hex>, re-parse it, re-verify its
 * signature, re-derive its id, and admit the exact bytes into `store`
 * as a blob. On OK, `out->transport_root` is the root a POINTER in
 * VCS_PACKAGE_ATTEST_DHT_NAMESPACE must carry and the swarm will serve.
 *
 * Idempotent: re-offering identical bytes yields the same root and is
 * OK. Nothing is announced or published here — putting an attestation
 * within reach and telling the network about it are separate acts, and
 * the second one is the caller's. */
enum vcs_package_attest_transport_result vcs_package_attest_transport_offer(
    struct vcs_package_store *store, const char *zcode_dir,
    const uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES],
    struct vcs_package_attest_transport_outcome *out);

/* ── receive side: admit what the swarm delivered ───────────────────── */

/* Read the blob at `transport_root` back out of `store` (the blob layer
 * re-verifies the manifest, the root, and the chunk hash), parse it as
 * a ZCLATT wire, verify the embedded secp256k1 signature over the
 * attestation id, and file it.
 *
 * `expect_package_root` is the binding check and is the whole reason a
 * hostile pointer cannot poison a package's evidence: when non-NULL,
 * an attestation whose package_root differs is refused ERR_BINDING and
 * NOT filed. Callers that resolved this root from a POINTER keyed on a
 * package root MUST pass that root. NULL is for the paths that are not
 * answering a question about one specific package.
 *
 * Returns OK for both a fresh file and an identical re-admission;
 * `out->filed` and `out->already_present` distinguish them.
 *
 * Admitting is NOT accepting: the approved-verifier quorum policy is
 * applied later by `zcode package verify`, and this call deliberately
 * files attestations from unapproved signers, failure result classes,
 * and packages this node does not hold. */
enum vcs_package_attest_transport_result vcs_package_attest_transport_admit(
    struct vcs_package_store *store, const char *zcode_dir,
    const uint8_t transport_root[32], const uint8_t *expect_package_root,
    struct vcs_package_attest_transport_outcome *out);

#endif /* ZCL_VCS_PACKAGE_ATTEST_TRANSPORT_H */
