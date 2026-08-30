/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * receipt — one node's claim that a named test group reached a named verdict
 * over an exactly identified source tree, in the fixed form it travels in,
 * and the rule a receiving node applies to it.
 *
 * ── A RECEIVED RECEIPT IS A CLAIM, NOT A FACT ────────────────────────────
 *
 * That sentence is the whole design, and it is the same one
 * metaverse/node_character_wire.h already argues for a different payload.
 * The bytes arrived from somebody with an interest in how they read, so every
 * field is an assertion until this node has recomputed it or reproduced it.
 * The three answers are different and are kept apart deliberately:
 *
 *   RECOMPUTED   the receipt id. It is SHA3-256 over the canonical bytes, so
 *                the receiver derives it and refuses the whole receipt on any
 *                disagreement. Nothing here is taken on trust.
 *
 *   ASSERTED     source_root, toolchain, env_class, group, checks_total. A
 *                stranger cannot observe which tree the sender built or what
 *                compiler it used. These are carried as the sender's word,
 *                are checked for internal consistency, and are never promoted.
 *
 *   UNVERIFIED   the verdict and its vector — the actual claim. A stranger's
 *                receipt starts at UNVERIFIED and STAYS there until this node
 *                has run the group itself. There is no field, and no
 *                signature, that can move it.
 *
 * ── THE BOUNDARY, DRAWN EXPLICITLY ───────────────────────────────────────
 *
 * A node must not be able to talk itself into a pass.
 *
 * 1. WHAT THE RECEIVER BELIEVES IS NEVER READ OFF THE WIRE. The belief is a
 *    function of THIS node's own run and nothing else. A node with no run of
 *    its own believes ZCL_RECEIPT_UNVERIFIED no matter what the receipt says,
 *    and renders the claim beside it marked unverified. A sender cannot raise
 *    that by editing its own receipt, because the receiver never reads the
 *    sender's verdict as an input.
 *
 * 2. ONLY A PASS WITH A VECTOR MAY BE PUBLISHED AS A PASS. HOLLOW, NO_CHANGE,
 *    TIMEOUT, REFUSED and UNVERIFIED publish as themselves and are never
 *    summarised as success. This is the field-level form of a lesson this
 *    tree has already paid for twice: "ALL TESTS PASSED (CACHED)" CONTAINS
 *    the pass token while having executed nothing, and a selector that
 *    matches no group exits 0. A receipt that let either through would turn
 *    a local hollow green into a network-wide one.
 *
 * 3. A GROUP THAT CANNOT PRODUCE A VECTOR CANNOT PRODUCE A RECEIPT. Not a
 *    receipt with an empty vector — no receipt at all, refused by name. An
 *    absent field reads as "fine"; a refusal reads as what it is.
 *
 * ── WHY THE VECTOR IS NOT THE TRANSCRIPT ─────────────────────────────────
 *
 * verdict_vector is a digest over the ORDERED (check name, outcome) sequence
 * a run produced — not over its output. A transcript carries timestamps,
 * paths, pids and durations, so two honest nodes running the same code
 * produce different transcripts and would refute each other forever. The
 * ordered outcome sequence is the part that is supposed to be identical, and
 * making exactly that the digest is what lets a disagreement mean something.
 *
 * This module does not COMPUTE the vector. It carries one, because the code
 * that observes per-check outcomes belongs with the test runner and the
 * determinism ledger, not here. An all-zero vector means "none was measured"
 * and is the only value this module rejects on sight.
 *
 * ── WHAT REFUTED MEANS, AND WHAT IT DOES NOT ─────────────────────────────
 *
 * REFUTED is not an accusation. A different toolchain or environment class is
 * a legitimate reason for two honest nodes to get different vectors, which is
 * precisely why both are inside the canonical bytes rather than alongside
 * them: a refutation carries the conditions it was made under. The
 * interesting refutation — the one worth a human — is one at an IDENTICAL
 * source root, toolchain and env class. Callers that report a refutation
 * without those three are reporting noise.
 *
 * ── A RECEIPT IS EVIDENCE, NEVER PERMISSION ──────────────────────────────
 *
 * Nothing here is consulted by metaverse_grant_check(), and no code path that
 * decides anything may call into this header. There is no `approved` field
 * and no signer list. "No referee, no authority — everyone runs a full node"
 * is the project's oldest rule; a receipt that gated an action would be a
 * referee, and a referee is the thing this project refuses.
 *
 * ── WHY THIS MODULE DOES NOT SIGN ────────────────────────────────────────
 *
 * It carries a producer's public key and stops there. Signing is lib/zid's,
 * whose ed25519 envelope, monotonic seq and expiry are already proven; a
 * caller encodes a receipt and hands the bytes to zid_doc_sign() as a doc
 * body. Canonical bytes are ZCL_RECEIPT_WIRE_BYTES, comfortably inside
 * ZID_BODY_MAX. Keeping identity out of here is what lets this module sit at
 * link rank 4 with base and sha3 as its only dependencies, and it means a
 * receipt can be recomputed and compared by code that holds no keys at all.
 */

#ifndef ZCL_RECEIPT_H
#define ZCL_RECEIPT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_RECEIPT_VERSION      1
#define ZCL_RECEIPT_GROUP_MAX    64
#define ZCL_RECEIPT_TOOLCHAIN_MAX 64
#define ZCL_RECEIPT_ENV_MAX      64

/* version 1 + kind 1 + verdict 1 + source_root 32 + base_root 32 +
 * group 64 + verdict_vector 32 + checks_total 4 + toolchain 64 +
 * env_class 64 + producer 32 */
#define ZCL_RECEIPT_WIRE_BYTES   327

/* What KIND of claim this is. A plain pass says a tree was green. A red-delta
 * says something stronger and much harder to manufacture: that a named
 * artifact was RED on the base tree and GREEN on this one, both built by the
 * producer. "Tests pass" is satisfiable by changing nothing; a witness that
 * was born red is not. */
enum zcl_receipt_kind {
    ZCL_RECEIPT_KIND_PASS      = 1,
    ZCL_RECEIPT_KIND_RED_DELTA = 2,
};

/* The ways a run ends. Everything but PASS is a way green can lie, and each
 * publishes as itself. */
enum zcl_receipt_verdict {
    ZCL_RECEIPT_VERDICT_PASS       = 1,
    ZCL_RECEIPT_VERDICT_FAIL       = 2,
    ZCL_RECEIPT_VERDICT_HOLLOW     = 3,  /* ran nothing, or fully cached */
    ZCL_RECEIPT_VERDICT_NO_CHANGE  = 4,  /* the tree was not modified */
    ZCL_RECEIPT_VERDICT_TIMEOUT    = 5,  /* reports as itself, never as fail */
    ZCL_RECEIPT_VERDICT_REFUSED    = 6,
    ZCL_RECEIPT_VERDICT_UNVERIFIED = 7,  /* no group could judge it */
};

/* What THIS node believes, derived from its own run and nothing on the wire. */
enum zcl_receipt_belief {
    ZCL_RECEIPT_UNVERIFIED   = 0,  /* the honest default for every stranger */
    ZCL_RECEIPT_CORROBORATED = 1,  /* re-ran it, same vector */
    ZCL_RECEIPT_REFUTED      = 2,  /* re-ran it, different vector */
};

struct zcl_proof_receipt {
    uint8_t  version;
    uint8_t  kind;                 /* enum zcl_receipt_kind */
    uint8_t  verdict;              /* enum zcl_receipt_verdict */
    uint8_t  source_root[32];      /* codeindex_source_root_sha3() of the tree */
    uint8_t  base_root[32];        /* RED_DELTA only; all-zero otherwise */
    char     group[ZCL_RECEIPT_GROUP_MAX];
    uint8_t  verdict_vector[32];   /* all-zero means none was measured */
    uint32_t checks_total;         /* how many checks the vector covers */
    char     toolchain[ZCL_RECEIPT_TOOLCHAIN_MAX];
    char     env_class[ZCL_RECEIPT_ENV_MAX];
    uint8_t  producer[32];         /* a ZID master_pubkey; may be all-zero */
};

const char *zcl_receipt_kind_label(enum zcl_receipt_kind k);
const char *zcl_receipt_verdict_label(enum zcl_receipt_verdict v);
const char *zcl_receipt_belief_label(enum zcl_receipt_belief b);

/* The canonical bytes: fixed width, versioned, big-endian, field by field.
 * Writes exactly ZCL_RECEIPT_WIRE_BYTES and returns that, or 0 when `cap` is
 * too small or the receipt is structurally invalid. Character fields are
 * emitted NUL-padded to their full width so two receipts that differ only in
 * uninitialised tail bytes cannot produce two ids. */
size_t zcl_receipt_encode(uint8_t *out, size_t cap,
                          const struct zcl_proof_receipt *r);

/* Bounds-strict decode. `len` must be EXACTLY ZCL_RECEIPT_WIRE_BYTES, the
 * version must match, every enum must be in range, and every character field
 * must be NUL-terminated inside its width with no embedded control bytes. On
 * any failure the output is zeroed and false is returned — a refusal never
 * leaves a half-filled receipt behind. */
bool zcl_receipt_decode(struct zcl_proof_receipt *r,
                        const uint8_t *buf, size_t len);

/* SHA3-256 over the canonical bytes. Returns false when the receipt does not
 * encode. This is the receipt's name: content-addressed, so receipts request,
 * cache and serve like any other content-addressed object. */
bool zcl_receipt_id(uint8_t out[32], const struct zcl_proof_receipt *r);

/* Structural validity, independent of any belief: version, enums in range,
 * NUL-terminated fields, and base_root all-zero unless kind is RED_DELTA. */
bool zcl_receipt_is_valid(const struct zcl_proof_receipt *r);

/* True only for a receipt that may be PUBLISHED AS A PASS: verdict PASS, a
 * non-zero verdict_vector, and checks_total > 0. Every other verdict answers
 * false — including HOLLOW, which is the one that looks like success. */
bool zcl_receipt_is_publishable_pass(const struct zcl_proof_receipt *r);

/* What this node believes after running the group itself.
 *
 * `observed_vector` / `observed_checks` are THIS node's measurement. When no
 * run has happened, pass an all-zero vector: the answer is UNVERIFIED, which
 * is also the answer for a claim that was never a publishable pass. Otherwise
 * the vectors are compared in constant time and the answer is CORROBORATED or
 * REFUTED.
 *
 * checks_total disagreeing is a REFUTATION even when the digests happen to
 * differ anyway: it means the two nodes did not run the same set of checks,
 * which is a real difference and not a rounding error. */
enum zcl_receipt_belief zcl_receipt_corroborate(
    const struct zcl_proof_receipt *claim,
    const uint8_t observed_vector[32], uint32_t observed_checks);

/* Whether a refutation is worth a human: same source root, same toolchain and
 * same env class means the two nodes should have agreed and did not. A
 * difference in any of the three explains the disagreement by itself. */
bool zcl_receipt_refutation_is_material(const struct zcl_proof_receipt *claim,
                                        const uint8_t observed_source_root[32],
                                        const char *observed_toolchain,
                                        const char *observed_env_class);

/* ── eligibility: which groups may produce a receipt at all ───────────────
 *
 * A DECLARED HOLE, wired the way lib/territory's trust ledger is wired. The
 * determinism ledger that answers "is this group reproducible, and is it
 * timing sensitive" is being built on another lane. Until it lands, a NULL
 * lookup means every group answers UNKNOWN — and UNKNOWN is NOT eligible.
 *
 * That direction is the whole point. A timing-sensitive group re-run under
 * load produces a different vector, and an honest node would then issue
 * REFUTED for a receipt that was never wrong: a false accusation manufactured
 * by scheduling. Refusing to issue the receipt costs nothing; issuing one
 * costs the network its ability to mean anything by a refutation. */
enum zcl_receipt_eligibility {
    ZCL_RECEIPT_ELIGIBILITY_UNKNOWN = 0,  /* no ledger, or no answer: refuse */
    ZCL_RECEIPT_ELIGIBLE            = 1,
    ZCL_RECEIPT_INELIGIBLE_NONDETERMINISTIC = 2,
    ZCL_RECEIPT_INELIGIBLE_TIMING_SENSITIVE = 3,
    ZCL_RECEIPT_INELIGIBLE_NO_VECTOR        = 4,
};

typedef enum zcl_receipt_eligibility (*zcl_receipt_eligibility_fn)(
    const char *group, void *user);

struct zcl_receipt_ledger {
    zcl_receipt_eligibility_fn lookup;  /* NULL until the ledger lands */
    void *user;
    const char *source;                 /* where the answer came from */
};

const char *zcl_receipt_eligibility_label(enum zcl_receipt_eligibility e);

/* Ask the ledger. A NULL ledger, a NULL lookup, or an out-of-range answer all
 * yield UNKNOWN, and only ZCL_RECEIPT_ELIGIBLE permits a receipt. */
enum zcl_receipt_eligibility zcl_receipt_group_eligibility(
    const struct zcl_receipt_ledger *ledger, const char *group);

/* The one constructor. Fills `out` and returns true only when the group is
 * ELIGIBLE and the result is structurally valid; otherwise `out` is zeroed,
 * false is returned, and `why` (when non-NULL) receives a sentence naming the
 * group and the reason. There is deliberately no way to build a receipt that
 * skips this check. */
bool zcl_receipt_build(struct zcl_proof_receipt *out,
                       const struct zcl_receipt_ledger *ledger,
                       enum zcl_receipt_kind kind,
                       enum zcl_receipt_verdict verdict,
                       const uint8_t source_root[32],
                       const uint8_t base_root[32],
                       const char *group,
                       const uint8_t verdict_vector[32],
                       uint32_t checks_total,
                       const char *toolchain,
                       const char *env_class,
                       const uint8_t producer[32],
                       char *why, size_t why_cap);

#endif /* ZCL_RECEIPT_H */
