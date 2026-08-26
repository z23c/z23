/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: compose many nodes' moderation sign-offs into ONE reader's local
 * verdict, with no referee anywhere in the construction.
 *
 * THE AUTHORITY TEST, APPLIED HERE
 * --------------------------------
 * "If one box stops, is any verdict blocked?" No, by construction:
 *
 *  - source_count == 0 is a valid input and produces a complete composition
 *    (zero signers, self UNREVIEWED, serve false). There is no "pending"
 *    state and no error return that leaves a caller without an answer, so a
 *    silent peer cannot stall a reader.
 *  - Every attestation verifies standalone from its own bytes plus the
 *    signer's public key. No lookup, no directory, no chain read.
 *  - Chain completeness is NOT required. A signer's newest statement counts
 *    whether or not the reader also holds the statement it superseded --
 *    otherwise whoever held the intermediate link would gate the verdict.
 *    Linkage is reported as the advisory `chain_linked` bit.
 *  - No signer is named in the protocol. The only signers that count toward
 *    serving are the ones the LOCAL operator listed, in a threshold the LOCAL
 *    operator chose. Zero-initialised policy => nothing remote counts at all.
 *  - Removing any subset of evidence still yields a defined verdict, and the
 *    only direction that removal can move `serve` is toward false, which is
 *    the fail-closed direction. (A quorum member's absence CHANGES a verdict;
 *    it never BLOCKS one. That is the distinction the doctrine's test draws.)
 *
 * Everything here is a pure function of (policy, content_root, sources). No
 * globals, no I/O, no clock: the reader supplies now_mtp, so two readers with
 * the same bytes and the same configuration derive the same composition root
 * and can compare notes without either being the judge. */

#include "vcs/moderation_attestation.h"

#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

struct zcl_moderation_composition {
    struct zcl_moderation_tally_v1 tally;
    struct zcl_moderation_signer_verdict_v1 *signers;
    size_t count;
    uint8_t root[32];
};

static bool compose_nonzero(const uint8_t *bytes, size_t count)
{
    uint8_t any = 0;
    if (!bytes) return false;
    for (size_t i = 0; i < count; i++) any |= bytes[i];
    return any != 0;
}

/* Canonical order: signer, then sequence, then the statement's own root.
 * Total and deterministic, so grouping and the composition root do not depend
 * on the order evidence happened to arrive in. */
static int compose_source_compare(const void *left_ptr, const void *right_ptr)
{
    const struct zcl_moderation_source_v1 *left = left_ptr;
    const struct zcl_moderation_source_v1 *right = right_ptr;
    int cmp = memcmp(left->attestation.signer_pubkey,
                     right->attestation.signer_pubkey, 32);
    if (cmp != 0) return cmp;
    if (left->attestation.sequence != right->attestation.sequence)
        return left->attestation.sequence < right->attestation.sequence ? -1
                                                                        : 1;
    return memcmp(left->object_root, right->object_root, 32);
}

static bool compose_is_trusted(
    const struct zcl_moderation_local_policy_v1 *policy,
    const uint8_t pubkey[32])
{
    if (!policy->trusted) return false;
    for (size_t i = 0; i < policy->trusted_count; i++)
        if (memcmp(policy->trusted[i], pubkey, 32) == 0) return true;
    return false;
}

/* Evidence binding. Anything that fails here is DISCARDED and counted in
 * `rejected` -- it never reaches a tally, so no malformed, misbound or
 * forged record can move the verdict in either direction. */
static bool compose_accept_source(
    const struct zcl_moderation_local_policy_v1 *policy,
    const uint8_t content_root[32],
    const struct zcl_moderation_source_v1 *source)
{
    if (zcl_moderation_attestation_v1_validate(&source->attestation) !=
        ZCL_MODERATION_OK)
        return false;
    uint8_t derived[32];
    if (zcl_moderation_attestation_v1_root(&source->attestation, derived) !=
        ZCL_MODERATION_OK)
        return false;
    /* The bytes must hash to the root the reader indexed them under. */
    if (memcmp(derived, source->object_root, 32) != 0) return false;
    /* An attestation about OTHER content proves nothing about this content. */
    if (memcmp(source->attestation.content_root, content_root, 32) != 0)
        return false;
    /* An attestation under another profile -- including an unknown profile
     * name, whose root can match nothing configured -- is not evidence about
     * what THIS node hosts under ITS profile. */
    if (memcmp(source->attestation.profile_root, policy->profile_root, 32) !=
        0)
        return false;
    return true;
}

/* Was the statement this one supersedes also in the accepted set? Advisory
 * only: never gates the verdict (see the authority note at the top). */
static bool compose_chain_linked(
    const struct zcl_moderation_source_v1 *sources, size_t begin, size_t end,
    const struct zcl_moderation_source_v1 *winner)
{
    if (winner->attestation.sequence == 1u) return true;
    for (size_t i = begin; i < end; i++)
        if (sources[i].attestation.sequence ==
                winner->attestation.sequence - 1u &&
            memcmp(sources[i].object_root,
                   winner->attestation.predecessor_root, 32) == 0)
            return true;
    return false;
}

/* One signer's group [begin,end) -- already sorted by sequence. */
static void compose_signer(
    const struct zcl_moderation_local_policy_v1 *policy,
    const struct zcl_moderation_source_v1 *sources, size_t begin, size_t end,
    struct zcl_moderation_signer_verdict_v1 *out)
{
    /* Highest sequence wins: an older statement can never be replayed over a
     * newer one the reader also holds. */
    uint64_t highest = sources[end - 1u].attestation.sequence;
    size_t winner_at = end - 1u;
    while (winner_at > begin &&
           sources[winner_at - 1u].attestation.sequence == highest)
        winner_at--;
    size_t at_highest = end - winner_at;
    const struct zcl_moderation_source_v1 *winner = &sources[winner_at];

    memset(out, 0, sizeof(*out));
    memcpy(out->signer_pubkey, winner->attestation.signer_pubkey, 32);
    memcpy(out->attestation_root, winner->object_root, 32);
    out->sequence = highest;
    out->stated =
        (enum zcl_moderation_verdict_v1)winner->attestation.verdict;
    out->trusted = compose_is_trusted(policy, out->signer_pubkey);
    out->self = compose_nonzero(policy->self_pubkey, 32) &&
                memcmp(policy->self_pubkey, out->signer_pubkey, 32) == 0;
    /* Distinct statements at the same top sequence: the signer contradicts
     * itself. The reader does not pick a winner for it -- the signer's
     * position collapses to unreviewed, which does not serve. */
    out->equivocated = at_highest > 1u;
    out->superseded_count = (uint32_t)(winner_at - begin);
    out->expired = policy->now_mtp >= winner->attestation.expires_mtp;
    out->not_yet_valid = policy->now_mtp < winner->attestation.reviewed_mtp;
    out->chain_linked = compose_chain_linked(sources, begin, end, winner);
    out->verdict = (out->equivocated || out->expired || out->not_yet_valid)
                       ? ZCL_MODERATION_VERDICT_UNREVIEWED
                       : out->stated;
}

static void compose_hash_u32(struct sha3_256_ctx *sha, uint32_t value)
{
    uint8_t le[4];
    zcl_write_u32_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

static void compose_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t le[8];
    zcl_write_u64_le(le, value);
    sha3_256_write(sha, le, sizeof(le));
}

/* Commits the reader's own configuration as well as the evidence: two
 * readers agree on this root only if they hold the same statements AND ran
 * the same local policy at the same clock. That is the honest thing to
 * publish -- it says "here is what I saw and how I read it", never "here is
 * the answer". */
static void compose_derive_root(
    const struct zcl_moderation_local_policy_v1 *policy,
    struct zcl_moderation_composition *composition)
{
    static const char domain[] = ZCL_MODERATION_COMPOSITION_DOMAIN;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&sha, composition->tally.content_root, 32);
    sha3_256_write(&sha, composition->tally.profile_root, 32);
    sha3_256_write(&sha, policy->self_pubkey, 32);
    compose_hash_u32(&sha, policy->ok_threshold);
    compose_hash_u64(&sha, (uint64_t)policy->trusted_count);
    uint8_t veto = policy->trusted_hidden_vetoes ? 1u : 0u;
    sha3_256_write(&sha, &veto, 1);
    compose_hash_u64(&sha, (uint64_t)policy->now_mtp);
    compose_hash_u32(&sha, composition->tally.rejected);
    compose_hash_u64(&sha, (uint64_t)composition->count);
    for (size_t i = 0; i < composition->count; i++) {
        const struct zcl_moderation_signer_verdict_v1 *signer =
            &composition->signers[i];
        sha3_256_write(&sha, signer->signer_pubkey, 32);
        sha3_256_write(&sha, signer->attestation_root, 32);
        compose_hash_u64(&sha, signer->sequence);
        compose_hash_u32(&sha, (uint32_t)signer->verdict);
        compose_hash_u32(&sha, (uint32_t)signer->stated);
        compose_hash_u32(&sha, signer->superseded_count);
        uint8_t bits = (uint8_t)((signer->trusted ? 1u : 0u) |
                                 (signer->self ? 2u : 0u) |
                                 (signer->equivocated ? 4u : 0u) |
                                 (signer->expired ? 8u : 0u) |
                                 (signer->not_yet_valid ? 16u : 0u) |
                                 (signer->chain_linked ? 32u : 0u));
        sha3_256_write(&sha, &bits, 1);
    }
    compose_hash_u32(&sha, (uint32_t)composition->tally.reason);
    uint8_t serve = composition->tally.serve ? 1u : 0u;
    sha3_256_write(&sha, &serve, 1);
    sha3_256_finalize(&sha, composition->root);
}

/* THE COMPOSITION RULE, in precedence order. Each step is fail-closed; the
 * only steps that can produce serve=true are 2 (this node's own sign-off) and
 * 5 (a threshold the operator configured over reviewers the operator listed).
 *
 *   1. this node signed HIDDEN            -> false. Own policy is final for
 *                                            own hosting, and one node's
 *                                            attestation can never override
 *                                            another node's own decision.
 *   2. this node signed REVIEWED_OK       -> true.
 *   3. ok_threshold == 0                  -> false. Default. Remote sign-off
 *                                            counts for nothing until the
 *                                            operator says whose counts.
 *   4. veto enabled and a trusted reviewer
 *      says HIDDEN                        -> false. Can only restrict.
 *   5. trusted_ok >= ok_threshold         -> true.
 *   6. otherwise                          -> false (NO_QUORUM if there is a
 *                                            trust set to fall short of,
 *                                            UNREVIEWED if there is not). */
static void compose_decide(
    const struct zcl_moderation_local_policy_v1 *policy,
    struct zcl_moderation_tally_v1 *tally)
{
    tally->threshold_met =
        policy->ok_threshold > 0 && tally->trusted_ok >= policy->ok_threshold;
    if (tally->self_present &&
        tally->self_verdict == ZCL_MODERATION_VERDICT_HIDDEN) {
        tally->serve = false;
        tally->reason = ZCL_MODERATION_REASON_SELF_HIDDEN;
        return;
    }
    if (tally->self_present &&
        tally->self_verdict == ZCL_MODERATION_VERDICT_REVIEWED_OK) {
        tally->serve = true;
        tally->reason = ZCL_MODERATION_REASON_SELF_OK;
        return;
    }
    if (policy->ok_threshold == 0) {
        tally->serve = false;
        tally->reason = ZCL_MODERATION_REASON_LOCAL_TRUST_DISABLED;
        return;
    }
    if (policy->trusted_hidden_vetoes && tally->trusted_hidden > 0) {
        tally->serve = false;
        tally->reason = ZCL_MODERATION_REASON_TRUSTED_VETO;
        return;
    }
    if (tally->threshold_met) {
        tally->serve = true;
        tally->reason = ZCL_MODERATION_REASON_TRUSTED_QUORUM;
        return;
    }
    tally->serve = false;
    tally->reason = policy->trusted_count > 0
                        ? ZCL_MODERATION_REASON_NO_QUORUM
                        : ZCL_MODERATION_REASON_UNREVIEWED;
}

static void compose_tally_signer(
    struct zcl_moderation_tally_v1 *tally,
    const struct zcl_moderation_signer_verdict_v1 *signer)
{
    tally->equivocations += signer->equivocated ? 1u : 0u;
    tally->expired += signer->expired ? 1u : 0u;
    tally->not_yet_valid += signer->not_yet_valid ? 1u : 0u;
    tally->superseded += signer->superseded_count;
    if (signer->self) {
        tally->self_present = true;
        tally->self_verdict = signer->verdict;
    }
    /* Untrusted opinions are REPORTED, never counted toward serving. This is
     * the whole difference between composition and a whitelist. */
    if (signer->trusted) {
        switch (signer->verdict) {
        case ZCL_MODERATION_VERDICT_REVIEWED_OK: tally->trusted_ok++; break;
        case ZCL_MODERATION_VERDICT_HIDDEN: tally->trusted_hidden++; break;
        case ZCL_MODERATION_VERDICT_UNREVIEWED:
        case ZCL_MODERATION_VERDICT_COUNT: tally->trusted_unreviewed++; break;
        }
        return;
    }
    switch (signer->verdict) {
    case ZCL_MODERATION_VERDICT_REVIEWED_OK: tally->untrusted_ok++; break;
    case ZCL_MODERATION_VERDICT_HIDDEN: tally->untrusted_hidden++; break;
    case ZCL_MODERATION_VERDICT_UNREVIEWED:
    case ZCL_MODERATION_VERDICT_COUNT: tally->untrusted_unreviewed++; break;
    }
}

static enum zcl_moderation_error compose_policy_validate(
    const struct zcl_moderation_local_policy_v1 *policy)
{
    if (!policy) return ZCL_MODERATION_NULL;
    if (!compose_nonzero(policy->profile_root, 32)) return ZCL_MODERATION_ROOT;
    if (policy->trusted_count > ZCL_MODERATION_MAX_TRUSTED)
        return ZCL_MODERATION_LIMIT;
    if (policy->trusted_count > 0 && !policy->trusted)
        return ZCL_MODERATION_NULL;
    /* A threshold nobody could ever meet is a configuration error, not a
     * silent permanent hide: say so rather than let the operator believe
     * remote sign-off is working. */
    if (policy->ok_threshold > policy->trusted_count)
        return ZCL_MODERATION_LIMIT;
    if (policy->now_mtp <= 0) return ZCL_MODERATION_TIME;
    return ZCL_MODERATION_OK;
}

enum zcl_moderation_error zcl_moderation_compose_v1(
    const struct zcl_moderation_local_policy_v1 *policy,
    const uint8_t content_root[32],
    const struct zcl_moderation_source_v1 *sources, size_t source_count,
    struct zcl_moderation_composition **out)
{
    if (out) *out = NULL;
    if (!out || !content_root || (!sources && source_count))
        return ZCL_MODERATION_NULL;
    enum zcl_moderation_error error = compose_policy_validate(policy);
    if (error != ZCL_MODERATION_OK) return error;
    if (!compose_nonzero(content_root, 32)) return ZCL_MODERATION_ROOT;
    if (source_count > ZCL_MODERATION_MAX_ATTESTATIONS)
        return ZCL_MODERATION_LIMIT;

    struct zcl_moderation_composition *composition =
        zcl_calloc(1, sizeof(*composition), "moderation composition");
    if (!composition) return ZCL_MODERATION_NOMEM;
    memcpy(composition->tally.content_root, content_root, 32);
    memcpy(composition->tally.profile_root, policy->profile_root, 32);
    composition->tally.self_verdict = ZCL_MODERATION_VERDICT_UNREVIEWED;

    struct zcl_moderation_source_v1 *accepted = NULL;
    size_t accepted_count = 0;
    if (source_count) {
        accepted = zcl_calloc(source_count, sizeof(*accepted),
                              "moderation attestation sources");
        if (!accepted) {
            free(composition);
            return ZCL_MODERATION_NOMEM;
        }
        for (size_t i = 0; i < source_count; i++) {
            if (!compose_accept_source(policy, content_root, &sources[i])) {
                composition->tally.rejected++;
                continue;
            }
            accepted[accepted_count++] = sources[i];
        }
        qsort(accepted, accepted_count, sizeof(*accepted),
              compose_source_compare);
        /* A byte-identical statement gossiped twice is one statement. */
        size_t deduped = 0;
        for (size_t i = 0; i < accepted_count; i++) {
            if (deduped > 0 && memcmp(accepted[deduped - 1u].object_root,
                                      accepted[i].object_root, 32) == 0)
                continue;
            accepted[deduped++] = accepted[i];
        }
        accepted_count = deduped;
    }
    if (accepted_count) {
        composition->signers =
            zcl_calloc(accepted_count, sizeof(*composition->signers),
                       "moderation signer verdicts");
        if (!composition->signers) {
            free(accepted);
            free(composition);
            return ZCL_MODERATION_NOMEM;
        }
    }
    for (size_t begin = 0; begin < accepted_count;) {
        size_t end = begin + 1u;
        while (end < accepted_count &&
               memcmp(accepted[begin].attestation.signer_pubkey,
                      accepted[end].attestation.signer_pubkey, 32) == 0)
            end++;
        struct zcl_moderation_signer_verdict_v1 *signer =
            &composition->signers[composition->count++];
        compose_signer(policy, accepted, begin, end, signer);
        compose_tally_signer(&composition->tally, signer);
        begin = end;
    }
    free(accepted);
    composition->tally.signer_count = (uint32_t)composition->count;
    compose_decide(policy, &composition->tally);
    compose_derive_root(policy, composition);
    *out = composition;
    return ZCL_MODERATION_OK;
}

void zcl_moderation_composition_free_v1(
    struct zcl_moderation_composition *composition)
{
    if (!composition) return;
    free(composition->signers);
    free(composition);
}

struct zcl_moderation_tally_v1 zcl_moderation_composition_tally_v1(
    const struct zcl_moderation_composition *composition)
{
    /* A NULL composition answers the fail-closed default rather than a
     * caller-visible error the caller might skip. */
    struct zcl_moderation_tally_v1 empty = {0};
    empty.self_verdict = ZCL_MODERATION_VERDICT_UNREVIEWED;
    empty.reason = ZCL_MODERATION_REASON_UNREVIEWED;
    return composition ? composition->tally : empty;
}

size_t zcl_moderation_composition_signer_count_v1(
    const struct zcl_moderation_composition *composition)
{
    return composition ? composition->count : 0;
}

const struct zcl_moderation_signer_verdict_v1 *
zcl_moderation_composition_signer_at_v1(
    const struct zcl_moderation_composition *composition, size_t index)
{
    return composition && index < composition->count
               ? &composition->signers[index]
               : NULL;
}

const struct zcl_moderation_signer_verdict_v1 *
zcl_moderation_composition_signer_find_v1(
    const struct zcl_moderation_composition *composition,
    const uint8_t signer_pubkey[32])
{
    if (!composition || !signer_pubkey) return NULL;
    size_t low = 0, high = composition->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2u;
        int cmp = memcmp(composition->signers[mid].signer_pubkey,
                         signer_pubkey, 32);
        if (cmp < 0) low = mid + 1u;
        else if (cmp > 0) high = mid;
        else return &composition->signers[mid];
    }
    return NULL;
}

void zcl_moderation_composition_root_v1(
    const struct zcl_moderation_composition *composition, uint8_t out[32])
{
    if (!out) return;
    memset(out, 0, 32);
    if (composition) memcpy(out, composition->root, 32);
}
