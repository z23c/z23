/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: Signed per-node moderation sign-off
 * (zcl.moderation.node_attestation.v1) and the local, non-authoritative
 * composition of many nodes' sign-offs.
 *
 * WHAT THIS IS
 * ------------
 * A node that hosts content can state, verifiably and self-contained:
 *
 *     "I, the node holding Ed25519 public key P, reviewed content C under
 *      profile general-audience.v1 (policy text hashing to R) at chain
 *      height H / median-time T, and my verdict is
 *      reviewed_ok | hidden | unreviewed."
 *
 * The statement is 272 fixed-width bytes, signed over a domain-separated
 * preimage. Anybody holding the bytes and P can verify it offline: no chain
 * state, no session, no directory, no second identity system. Signing reuses
 * lib/crypto Ed25519 and lib/sha3 SHA3-256 exactly as lib/vcs
 * commons_admission.v1 and lib/zswap zswap_quote.v1 already do.
 *
 * WHAT THIS IS NOT
 * ----------------
 *  1. NOT CONSENSUS. A moderation attestation can never make a block or a
 *     transaction more or less acceptable. Nothing in this header is reachable
 *     from validation; the only thing a verdict decides is whether the LOCAL
 *     node puts the content on its own listing/serving surfaces. Consensus-
 *     affecting moderation is a chain-split mechanism, so the separation is
 *     structural, not conventional: this module links base/crypto/sha3 only.
 *  2. NOT DELETION. "hidden" hides a row from a view. The content stays
 *     stored, served on exact-root request per the node's own hosting policy,
 *     and tradable. Nothing here ever drops a row.
 *  3. NOT AN AUTHORITY. There is no privileged signer, no quorum baked into
 *     the wire, and no box whose silence blocks a verdict. Composition over
 *     the EMPTY set is defined and returns a verdict (unreviewed -> not
 *     served). Every attestation is optional evidence; the reader composes.
 *  4. NOT A WHITELIST. A remote sign-off can only ever be counted against a
 *     trust set the local operator configured, in a threshold the local
 *     operator chose. With the zero-initialised policy (no trusted keys,
 *     threshold 0) no volume of remote attestations, however well-signed,
 *     changes what this node serves. Local trust is sovereignty; a rule
 *     shipped in the protocol that made some signer count everywhere would be
 *     an authority, and this file deliberately contains no such rule.
 *
 * COMPOSITION IS A VECTOR, NOT A SCALAR
 * -------------------------------------
 * zcl_moderation_compose_v1() answers WHO said WHAT: a per-signer effective
 * verdict list plus tallies split by trusted/untrusted, plus the counts of
 * evidence it refused (rejected / expired / not-yet-valid / equivocated /
 * superseded). `serve` is one derived bit for the caller's convenience; the
 * reader can ignore it and decide from the vector.
 *
 * FAIL CLOSED, EVERY EDGE
 * -----------------------
 * Bad signature, wrong pubkey, truncated record, wrong content, wrong or
 * unknown profile, malformed shape, a signer that equivocates, an attestation
 * outside its validity window, a null argument, an allocation failure -> the
 * evidence is DISCARDED (counted, never trusted) and the affected signer's
 * effective verdict is UNREVIEWED, which does not serve. There is no input
 * that turns an error into a serve.
 *
 * SUPERSESSION AND REPLAY
 * -----------------------
 * A signer supersedes its own prior statement by signing a higher `sequence`
 * for the same (content_root, profile_root) and naming the superseded
 * statement's root in `predecessor_root`. Highest sequence wins, so an old
 * attestation can never be replayed over a newer one that the reader also
 * holds. Two DIFFERENT statements at the same highest sequence by one signer
 * is equivocation: that signer's effective verdict collapses to UNREVIEWED
 * rather than the reader picking a winner.
 *
 * `predecessor_root` makes the order tamper-evident, but chain completeness
 * is NOT required for a verdict to count -- requiring it would make whoever
 * holds an intermediate link an authority over the verdict. It is reported as
 * the advisory `chain_linked` bit and nothing else.
 *
 * Against a censor who withholds a newer attestation and re-serves an older
 * one, sequence ordering alone cannot help (the reader cannot see what it was
 * not given). `expires_mtp` is the answer: a statement is evidence only
 * inside [reviewed_mtp, expires_mtp), so a withheld refresh decays to
 * unreviewed -> not served, which is the safe direction.
 */
#ifndef ZCL_VCS_MODERATION_ATTESTATION_H
#define ZCL_VCS_MODERATION_ATTESTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_MODERATION_ATTESTATION_VERSION 1u
#define ZCL_MODERATION_ATTESTATION_WIRE_BYTES 272u
#define ZCL_MODERATION_ATTESTATION_BODY_BYTES 208u
#define ZCL_MODERATION_ATTESTATION_DOMAIN \
    "zcl.moderation.node_attestation.v1"
#define ZCL_MODERATION_ATTESTATION_SIGNATURE_DOMAIN \
    "zcl.moderation.node_attestation.signature.v1"
#define ZCL_MODERATION_ATTESTATION_ROOT_DOMAIN \
    "zcl.moderation.node_attestation.root.v1"
#define ZCL_MODERATION_PROFILE_NAME_DOMAIN \
    "zcl.moderation.profile_name.v1"
#define ZCL_MODERATION_POLICY_TEXT_DOMAIN \
    "zcl.moderation.policy_text.v1"
#define ZCL_MODERATION_COMPOSITION_DOMAIN \
    "zcl.moderation.composition.v1"

/* The immutable default hosting profile. Byte-identical to
 * MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1 in
 * app/services/include/services/market_moderation_service.h -- lib/ may not
 * include app/, so the two constants are bound by a test assertion instead of
 * a shared header (test_zcode_moderation_attestation.c). */
#define ZCL_MODERATION_PROFILE_GENERAL_AUDIENCE_V1 "general-audience.v1"
#define ZCL_MODERATION_PROFILE_NAME_MAX 64u

#define ZCL_MODERATION_MAX_ATTESTATIONS 4096u
#define ZCL_MODERATION_MAX_TRUSTED 1024u
/* An attestation may not claim a validity window longer than this. A review
 * is a perishable statement about content the reviewer looked at once; an
 * unbounded window would let one old sign-off serve forever. */
#define ZCL_MODERATION_MAX_LIFETIME_SECS (INT64_C(90) * 24 * 60 * 60)

/* Deliberately numbered to match enum market_review_state
 * (app/models/include/models/review_state.h): unreviewed 0, reviewed_ok 1,
 * hidden/sensitive 2. Bound by test assertion. */
enum zcl_moderation_verdict_v1 {
    ZCL_MODERATION_VERDICT_UNREVIEWED = 0,
    ZCL_MODERATION_VERDICT_REVIEWED_OK = 1,
    ZCL_MODERATION_VERDICT_HIDDEN = 2,
    ZCL_MODERATION_VERDICT_COUNT = 3,
};

enum zcl_moderation_error {
    ZCL_MODERATION_OK = 0,
    ZCL_MODERATION_NULL,
    ZCL_MODERATION_SIZE,
    ZCL_MODERATION_MAGIC,
    ZCL_MODERATION_VERSION,
    ZCL_MODERATION_FLAGS,
    ZCL_MODERATION_ENUM,
    ZCL_MODERATION_ROOT,
    ZCL_MODERATION_TIME,
    ZCL_MODERATION_SIGNATURE,
    ZCL_MODERATION_CHAIN,
    ZCL_MODERATION_LIMIT,
    ZCL_MODERATION_NOMEM,
};

const char *zcl_moderation_error_string(enum zcl_moderation_error error);
const char *zcl_moderation_verdict_string(
    enum zcl_moderation_verdict_v1 verdict);

/* Wire layout (exact, fixed width, little-endian integers):
 *   body (208 bytes)
 *     0    8  magic {'Z','M','A','T','T','1',0,0}
 *     8    2  schema_version == ZCL_MODERATION_ATTESTATION_VERSION
 *     10   2  flags -- MUST be 0 in v1 (reserved; unknown bits fail closed)
 *     12   2  verdict (enum zcl_moderation_verdict_v1, < COUNT)
 *     14   2  reserved == 0
 *     16   8  sequence, != 0
 *     24   8  reviewed_height, != 0
 *     32   8  reviewed_mtp, > 0
 *     40   8  expires_mtp, > reviewed_mtp, <= reviewed_mtp + MAX_LIFETIME
 *     48  32  content_root   -- what was reviewed; non-zero
 *     80  32  profile_root   -- SHA3(profile-name domain || name); non-zero
 *     112 32  policy_root    -- SHA3 of the policy text applied; non-zero
 *     144 32  predecessor_root -- zero iff sequence == 1, else non-zero
 *     176 32  signer_pubkey  -- the attesting node; non-zero
 *   208 64  signature -- Ed25519 by signer_pubkey over
 *             SIGNATURE_DOMAIN || body
 * total 272 bytes.
 *
 * root = SHA3-256(ROOT_DOMAIN || NUL || wire) -- commits the signature too,
 * so a byte-identical re-gossip dedups on root and two statements that differ
 * anywhere have different roots. */
struct zcl_moderation_attestation_v1 {
    uint16_t schema_version;
    uint16_t flags;
    uint16_t verdict;
    uint16_t reserved;
    uint64_t sequence;
    uint64_t reviewed_height;
    int64_t reviewed_mtp;
    int64_t expires_mtp;
    uint8_t content_root[32];
    uint8_t profile_root[32];
    uint8_t policy_root[32];
    uint8_t predecessor_root[32];
    uint8_t signer_pubkey[32];
    uint8_t signature[64];
};

/* profile_root = SHA3-256(PROFILE_NAME_DOMAIN || NUL || name || NUL).
 * A name longer than ZCL_MODERATION_PROFILE_NAME_MAX, or empty, is refused --
 * an unknown/oversized profile can never hash to something that matches a
 * configured profile, so the caller fails closed. */
enum zcl_moderation_error zcl_moderation_profile_root_v1(
    const char *profile_name, uint8_t out[32]);
/* policy_root for the policy text the reviewer applied. Same construction,
 * distinct domain, no length cap (a policy document is not a name). */
enum zcl_moderation_error zcl_moderation_policy_root_v1(
    const char *policy_text, uint8_t out[32]);

/* Fills signer_pubkey from signer_seed, signs, and re-validates. On success
 * the object is a complete, verifiable statement. */
enum zcl_moderation_error zcl_moderation_attestation_v1_sign(
    struct zcl_moderation_attestation_v1 *attestation,
    const uint8_t signer_seed[32]);
/* Full shape + signature check. Never OK on a malformed object. */
enum zcl_moderation_error zcl_moderation_attestation_v1_validate(
    const struct zcl_moderation_attestation_v1 *attestation);
enum zcl_moderation_error zcl_moderation_attestation_v1_encode(
    const struct zcl_moderation_attestation_v1 *attestation,
    uint8_t *wire, size_t wire_capacity, size_t *wire_len);
/* Zeroes `out` on ANY failure -- a caller that ignores the return value
 * cannot end up looking at half-parsed attacker bytes. */
enum zcl_moderation_error zcl_moderation_attestation_v1_decode(
    struct zcl_moderation_attestation_v1 *out,
    const uint8_t *wire, size_t wire_len);
enum zcl_moderation_error zcl_moderation_attestation_v1_root(
    const struct zcl_moderation_attestation_v1 *attestation,
    uint8_t out[32]);

/* One piece of evidence as the reader holds it: the bytes' root plus the
 * decoded statement. object_root MUST equal the recomputed root or the
 * evidence is rejected -- a reader cannot be made to index a statement under
 * a root it does not hash to. */
struct zcl_moderation_source_v1 {
    uint8_t object_root[32];
    struct zcl_moderation_attestation_v1 attestation;
};

/* THE LOCAL, PER-NODE TRUST CONFIGURATION. Every field is the operator's
 * own; none of it is on the wire, none of it is discoverable by a peer, and
 * nothing in this module ships a default trust set.
 *
 * A zero-initialised policy (the safe default) has no trusted keys and
 * ok_threshold 0, which means: only this node's OWN sign-off can make this
 * node serve. That is the fail-closed baseline. */
struct zcl_moderation_local_policy_v1 {
    /* The profile THIS node hosts under. Evidence carrying any other
     * profile_root is rejected, not silently accepted. Non-zero required. */
    uint8_t profile_root[32];
    /* This node's own signing identity. All-zero means "this node has not
     * signed off on anything", which is not an error. */
    uint8_t self_pubkey[32];
    /* Reviewers this operator chose to count. Not an allowlist for content:
     * an allowlist for WHOSE OPINION IS TALLIED, locally. */
    const uint8_t (*trusted)[32];
    size_t trusted_count;
    /* "N of my configured trusted reviewers say ok". 0 disables remote
     * sign-off entirely and is the default. */
    uint32_t ok_threshold;
    /* When true, one trusted reviewer saying hidden stops this node serving
     * even if the threshold is met. This can only ever move the decision
     * toward not-serving, so it can never be used to force a serve. */
    bool trusted_hidden_vetoes;
    /* Reader's clock, in the same median-time-past units the attestation
     * uses. An attestation is evidence only while
     * reviewed_mtp <= now_mtp < expires_mtp. */
    int64_t now_mtp;
};

enum zcl_moderation_reason_v1 {
    /* Order is stable evidence; it is hashed into the composition root. */
    ZCL_MODERATION_REASON_UNREVIEWED = 0,
    ZCL_MODERATION_REASON_SELF_HIDDEN,
    ZCL_MODERATION_REASON_SELF_OK,
    ZCL_MODERATION_REASON_LOCAL_TRUST_DISABLED,
    ZCL_MODERATION_REASON_TRUSTED_VETO,
    ZCL_MODERATION_REASON_TRUSTED_QUORUM,
    ZCL_MODERATION_REASON_NO_QUORUM,
    ZCL_MODERATION_REASON_COUNT,
};

const char *zcl_moderation_reason_string(enum zcl_moderation_reason_v1 reason);

/* One signer's EFFECTIVE position after supersession, equivocation and
 * window checks. This is the "who said what" the reader composes from. */
struct zcl_moderation_signer_verdict_v1 {
    uint8_t signer_pubkey[32];
    uint8_t attestation_root[32];
    uint64_t sequence;
    enum zcl_moderation_verdict_v1 verdict; /* effective, after fail-closed */
    enum zcl_moderation_verdict_v1 stated;  /* what the winning bytes said */
    bool trusted;       /* in the LOCAL trust set */
    bool self;          /* signed by this node */
    bool equivocated;   /* >=2 distinct statements at the winning sequence */
    bool expired;       /* now_mtp >= expires_mtp */
    bool not_yet_valid; /* now_mtp < reviewed_mtp (clock weirdness) */
    bool chain_linked;  /* predecessor statement was also in the input set */
    uint32_t superseded_count;
};

/* Tallies. Deliberately NOT reducible to one boolean: `serve` is derived, and
 * a reader that wants to decide differently has every count it needs. */
struct zcl_moderation_tally_v1 {
    uint8_t content_root[32];
    uint8_t profile_root[32];
    uint32_t trusted_ok;
    uint32_t trusted_hidden;
    uint32_t trusted_unreviewed;
    uint32_t untrusted_ok;
    uint32_t untrusted_hidden;
    uint32_t untrusted_unreviewed;
    uint32_t equivocations;
    uint32_t expired;
    uint32_t not_yet_valid;
    uint32_t superseded;
    uint32_t rejected; /* evidence that failed validation/binding outright */
    uint32_t signer_count;
    enum zcl_moderation_verdict_v1 self_verdict;
    bool self_present;
    bool threshold_met;
    bool serve;
    enum zcl_moderation_reason_v1 reason;
};

struct zcl_moderation_composition;

/* Compose evidence into a local verdict.
 *
 * Pure: no globals, no I/O, no clock read (the caller supplies now_mtp), so
 * two readers holding the same bytes and the same policy derive the same
 * composition root. `sources` is not mutated.
 *
 * count == 0 is VALID and yields a defined composition: zero signers,
 * self_verdict UNREVIEWED, serve false. There is no "pending" and no error
 * path that leaves the caller without a verdict -- which is exactly why no
 * box's silence can block one. */
enum zcl_moderation_error zcl_moderation_compose_v1(
    const struct zcl_moderation_local_policy_v1 *policy,
    const uint8_t content_root[32],
    const struct zcl_moderation_source_v1 *sources, size_t source_count,
    struct zcl_moderation_composition **out);
void zcl_moderation_composition_free_v1(
    struct zcl_moderation_composition *composition);
struct zcl_moderation_tally_v1 zcl_moderation_composition_tally_v1(
    const struct zcl_moderation_composition *composition);
size_t zcl_moderation_composition_signer_count_v1(
    const struct zcl_moderation_composition *composition);
/* Signers in ascending pubkey order -- stable, so the vector is evidence. */
const struct zcl_moderation_signer_verdict_v1 *
zcl_moderation_composition_signer_at_v1(
    const struct zcl_moderation_composition *composition, size_t index);
const struct zcl_moderation_signer_verdict_v1 *
zcl_moderation_composition_signer_find_v1(
    const struct zcl_moderation_composition *composition,
    const uint8_t signer_pubkey[32]);
/* SHA3-256 over the policy inputs and the full signer vector. Zeroed for a
 * NULL composition. */
void zcl_moderation_composition_root_v1(
    const struct zcl_moderation_composition *composition, uint8_t out[32]);

#endif /* ZCL_VCS_MODERATION_ATTESTATION_H */
