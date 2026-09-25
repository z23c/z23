/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The receiver's retained ticket set and delta-only verification
 *          of per-issuer signed MMR checkpoints, with equivocation kept. */

#include "proof_reuse_priv.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define PRV_LOG "vcs.proof_receiver"

struct vcs_proof_receiver *vcs_proof_receiver_new(void)
{
    struct vcs_proof_receiver *r =
        zcl_calloc(1, sizeof(*r), "proof_receiver");
    if (!r) LOG_RETURN(NULL, PRV_LOG, "receiver: out of memory");
    return r;
}

void vcs_proof_receiver_free(struct vcs_proof_receiver *r)
{
    if (!r) return;
    for (size_t i = 0; i < r->issuer_count; i++) free(r->issuers[i].cps);
    free(r->issuers);
    free(r->entries);
    free(r);
}

/* ── Retained tickets ───────────────────────────────────────────────── */

struct pr_entry *pr_entry_find(const struct vcs_proof_receiver *r,
                               const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    for (size_t i = 0; i < r->count; i++)
        if (memcmp(r->entries[i].observation_root, root,
                   VCS_PROOF_ROOT_BYTES) == 0)
            return &r->entries[i];
    return NULL;
}

static bool pr_entries_reserve(struct vcs_proof_receiver *r, size_t additional)
{
    if (additional > SIZE_MAX - r->count)
        LOG_RETURN(false, PRV_LOG, "receiver ticket count overflow");
    size_t needed = r->count + additional;
    if (needed <= r->cap) return true;
    size_t cap = r->cap ? r->cap : 64u;
    while (cap < needed) {
        if (cap > SIZE_MAX / 2u) {
            cap = needed;
            break;
        }
        cap *= 2u;
    }
    if (cap > SIZE_MAX / sizeof(struct pr_entry))
        LOG_RETURN(false, PRV_LOG, "receiver ticket capacity overflow");
    struct pr_entry *grown =
        zcl_realloc(r->entries, cap * sizeof(*grown), "proof_receiver_entries");
    if (!grown) LOG_RETURN(false, PRV_LOG, "receiver: out of memory");
    r->entries = grown;
    r->cap = cap;
    return true;
}

struct pr_entry *pr_entry_put(struct vcs_proof_receiver *r,
                              const uint8_t *wire,
                              const struct vcs_proof_ticket_v1 *t,
                              const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    struct pr_entry *e = pr_entry_find(r, root);
    if (e) return e;
    if (!pr_entries_reserve(r, 1)) return NULL;
    e = &r->entries[r->count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->input_key, t->input_key, VCS_PROOF_ROOT_BYTES);
    memcpy(e->observation_root, root, VCS_PROOF_ROOT_BYTES);
    memcpy(e->producer, t->producer_pubkey, VCS_PROOF_PUBKEY_BYTES);
    e->issuer_seq = t->issuer_seq;
    memcpy(e->wire, wire, VCS_PROOF_TICKET_WIRE_BYTES);
    return e;
}

bool vcs_proof_receiver_add_ticket(struct vcs_proof_receiver *r,
                                   const uint8_t *wire, size_t len,
                                   bool *added)
{
    if (added) *added = false;
    if (!r || !wire)
        LOG_RETURN(false, PRV_LOG, "receiver add: null argument");
    struct vcs_proof_ticket_v1 t;
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    if (!vcs_proof_ticket_decode(wire, len, &t) ||
        !vcs_proof_ticket_observation_root(wire, len, root))
        LOG_RETURN(false, PRV_LOG, "receiver add: undecodable ticket");
    size_t before = r->count;
    if (!pr_entry_put(r, wire, &t, root)) return false;
    if (added) *added = r->count > before;
    return true;
}

size_t vcs_proof_receiver_lookup(const struct vcs_proof_receiver *r,
                                 const uint8_t input_key[VCS_PROOF_ROOT_BYTES],
                                 const uint8_t **wires, size_t cap)
{
    if (!r || !input_key) return 0;
    size_t total = 0;
    for (size_t i = 0; i < r->count; i++) {
        if (memcmp(r->entries[i].input_key, input_key,
                   VCS_PROOF_ROOT_BYTES) != 0)
            continue;
        if (wires && total < cap) wires[total] = r->entries[i].wire;
        total++;
    }
    return total;
}

size_t vcs_proof_receiver_ticket_count(const struct vcs_proof_receiver *r)
{
    return r ? r->count : 0;
}

/* ── Issuers ────────────────────────────────────────────────────────── */

const struct pr_issuer *pr_issuer_find(const struct vcs_proof_receiver *r,
                                       const uint8_t pubkey[32])
{
    for (size_t i = 0; r && i < r->issuer_count; i++)
        if (memcmp(r->issuers[i].pubkey, pubkey, 32) == 0)
            return &r->issuers[i];
    return NULL;
}

static struct pr_issuer *pr_issuer_get(struct vcs_proof_receiver *r,
                                       const uint8_t pubkey[32])
{
    struct pr_issuer *found = (struct pr_issuer *)pr_issuer_find(r, pubkey);
    if (found) return found;
    if (r->issuer_count == r->issuer_cap) {
        size_t cap = r->issuer_cap ? r->issuer_cap * 2u : 8u;
        struct pr_issuer *grown = zcl_realloc(
            r->issuers, cap * sizeof(*grown), "proof_receiver_issuers");
        if (!grown) LOG_RETURN(NULL, PRV_LOG, "receiver issuers: out of memory");
        r->issuers = grown;
        r->issuer_cap = cap;
    }
    struct pr_issuer *is = &r->issuers[r->issuer_count++];
    memset(is, 0, sizeof(*is));
    memcpy(is->pubkey, pubkey, 32);
    mmr_init(&is->mmr);
    return is;
}

uint64_t vcs_proof_receiver_issuer_leaves(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES])
{
    const struct pr_issuer *is = issuer ? pr_issuer_find(r, issuer) : NULL;
    return is ? is->mmr.num_leaves : 0;
}

bool vcs_proof_receiver_issuer_equivocating(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES])
{
    const struct pr_issuer *is = issuer ? pr_issuer_find(r, issuer) : NULL;
    return is && is->equivocating;
}

size_t vcs_proof_receiver_issuer_checkpoints(
    const struct vcs_proof_receiver *r,
    const uint8_t issuer[VCS_PROOF_PUBKEY_BYTES])
{
    const struct pr_issuer *is = issuer ? pr_issuer_find(r, issuer) : NULL;
    return is ? is->cp_count : 0;
}

/* ── Sync ───────────────────────────────────────────────────────────── */

struct pr_sync {
    struct vcs_proof_receiver *r;
    struct pr_issuer *is;
    struct vcs_proof_checkpoint_v1 c;
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    const uint8_t *const *delta;
    const size_t *lens;
    size_t n;
    struct vcs_proof_sync_report *out;
};

static bool pr_done(struct vcs_proof_sync_report *out,
                    enum vcs_proof_sync_outcome outcome, const char *why)
{
    out->outcome = outcome;
    out->reason = why;
    return true;
}

static bool pr_retain(struct pr_issuer *is, const struct pr_sync *s,
                      bool verified)
{
    for (size_t i = 0; i < is->cp_count; i++)
        if (memcmp(is->cps[i].root, s->root, VCS_PROOF_ROOT_BYTES) == 0)
            return true;
    if (is->cp_count == is->cp_cap) {
        size_t cap = is->cp_cap ? is->cp_cap * 2u : 8u;
        struct pr_checkpoint *grown =
            zcl_realloc(is->cps, cap * sizeof(*grown), "proof_checkpoints");
        if (!grown) LOG_RETURN(false, PRV_LOG, "checkpoints: out of memory");
        is->cps = grown;
        is->cp_cap = cap;
    }
    struct pr_checkpoint *cp = &is->cps[is->cp_count++];
    cp->verified = verified;
    cp->leaf_count = s->c.leaf_count;
    memcpy(cp->mmr_root, s->c.mmr_root, VCS_PROOF_ROOT_BYTES);
    memcpy(cp->prev, s->c.prev_checkpoint_root, VCS_PROOF_ROOT_BYTES);
    memcpy(cp->root, s->root, VCS_PROOF_ROOT_BYTES);
    memcpy(cp->wire, s->wire, VCS_PROOF_CHECKPOINT_WIRE_BYTES);
    return true;
}

static bool pr_equivocate(struct pr_sync *s)
{
    s->is->equivocating = true;
    LOG_WARN(PRV_LOG, "issuer signed contradictory checkpoints at %llu leaves",
             (unsigned long long)s->c.leaf_count);
    if (!pr_retain(s->is, s, false))
        return pr_done(s->out, VCS_PROOF_SYNC_EQUIVOCATION,
                       VCS_PROOF_SYNC_WHY_RESOURCES);
    return pr_done(s->out, VCS_PROOF_SYNC_EQUIVOCATION,
                   VCS_PROOF_SYNC_WHY_EQUIVOCATION);
}

static const struct pr_checkpoint *pr_verified_at(const struct pr_issuer *is,
                                                  uint64_t leaf_count)
{
    for (size_t i = 0; i < is->cp_count; i++)
        if (is->cps[i].verified && is->cps[i].leaf_count == leaf_count)
            return &is->cps[i];
    return NULL;
}

static bool pr_verified_prev(const struct pr_issuer *is,
                             const uint8_t prev[VCS_PROOF_ROOT_BYTES])
{
    for (size_t i = 0; i < is->cp_count; i++)
        if (is->cps[i].verified &&
            memcmp(is->cps[i].prev, prev, VCS_PROOF_ROOT_BYTES) == 0)
            return true;
    return false;
}

/* Check each delta ticket is this issuer's, at its position. Fills roots. */
static bool pr_delta_shape(const struct pr_sync *s, uint8_t (*roots)[32],
                           struct vcs_proof_ticket_v1 *tickets)
{
    uint64_t base = s->is->mmr.num_leaves;
    for (size_t i = 0; i < s->n; i++) {
        struct vcs_proof_ticket_v1 *t = &tickets[i];
        if (!s->delta[i] ||
            !vcs_proof_ticket_decode(s->delta[i], s->lens[i], t) ||
            !vcs_proof_ticket_signature_valid(t) ||
            memcmp(t->producer_pubkey, s->c.issuer_pubkey, 32) != 0 ||
            t->issuer_seq != base + i ||
            !vcs_proof_ticket_observation_root(s->delta[i], s->lens[i],
                                               roots[i]))
            return false;
    }
    return true;
}

static bool pr_prefix_matches(const struct pr_sync *s, uint8_t (*roots)[32],
                              struct mmr *next)
{
    *next = s->is->mmr;
    for (size_t i = 0; i < s->n; i++) mmr_append(next, roots[i]);
    uint8_t root[VCS_PROOF_ROOT_BYTES], peaks[VCS_PROOF_ROOT_BYTES];
    mmr_root(next, root);
    return vcs_proof_checkpoint_peaks_root(next, peaks) &&
           memcmp(root, s->c.mmr_root, VCS_PROOF_ROOT_BYTES) == 0 &&
           memcmp(peaks, s->c.peaks_root, VCS_PROOF_ROOT_BYTES) == 0;
}

static bool pr_commit(struct pr_sync *s, const struct mmr *next,
                      const struct vcs_proof_ticket_v1 *tickets,
                      uint8_t (*roots)[32])
{
    /* No covered ticket or verified checkpoint becomes visible unless all
     * receiver storage needed by this delta is available. */
    if (!pr_entries_reserve(s->r, s->n))
        return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_RESOURCES);
    if (!pr_retain(s->is, s, true))
        return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_RESOURCES);
    for (size_t i = 0; i < s->n; i++) {
        struct pr_entry *e = pr_entry_put(s->r, s->delta[i], &tickets[i],
                                          roots[i]);
        if (!e)
            return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                           VCS_PROOF_SYNC_WHY_RESOURCES);
        e->covered = true;
    }
    /* s->is may have moved if pr_entry_put grew entries; issuers are a
     * separate array, so the pointer is still valid. */
    s->is->mmr = *next;
    memcpy(s->is->last_root, s->root, VCS_PROOF_ROOT_BYTES);
    s->is->verified_count++;
    s->out->leaves_after = next->num_leaves;
    return pr_done(s->out, VCS_PROOF_SYNC_ADVANCED, VCS_PROOF_SYNC_WHY_OK);
}

/* The delta does not reproduce the signed root. When every delta ticket is
 * validly signed by the issuer at its position, the issuer signed both
 * sides: equivocation. Otherwise the relay supplied bad bytes: refuse. */
static bool pr_mismatch(struct pr_sync *s,
                        const struct vcs_proof_ticket_v1 *tickets)
{
    for (size_t i = 0; i < s->n; i++)
        if (!vcs_proof_ticket_signature_valid(&tickets[i]))
            return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                           VCS_PROOF_SYNC_WHY_DELTA);
    return pr_equivocate(s);
}

static bool pr_extend(struct pr_sync *s)
{
    if (s->n != s->c.leaf_count - s->is->mmr.num_leaves)
        return pr_done(s->out, VCS_PROOF_SYNC_REFUSED, VCS_PROOF_SYNC_WHY_COUNT);
    uint8_t (*roots)[32] = zcl_calloc(s->n, 32, "proof_sync_roots");
    struct vcs_proof_ticket_v1 *tickets =
        zcl_calloc(s->n, sizeof(*tickets), "proof_sync_tickets");
    bool ok;
    if (!roots || !tickets) {
        ok = pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                     VCS_PROOF_SYNC_WHY_RESOURCES);
    } else if (!pr_delta_shape(s, roots, tickets)) {
        ok = pr_done(s->out, VCS_PROOF_SYNC_REFUSED, VCS_PROOF_SYNC_WHY_DELTA);
    } else {
        struct mmr next;
        ok = pr_prefix_matches(s, roots, &next) ?
                 pr_commit(s, &next, tickets, roots) :
                 pr_mismatch(s, tickets);
    }
    free(roots);
    free(tickets);
    return ok;
}

static bool pr_classify(struct pr_sync *s)
{
    struct pr_issuer *is = s->is;
    if (is->equivocating) return pr_equivocate(s);
    const struct pr_checkpoint *same = pr_verified_at(is, s->c.leaf_count);
    if (same)
        return memcmp(same->mmr_root, s->c.mmr_root, 32) == 0 ?
                   pr_done(s->out, VCS_PROOF_SYNC_CURRENT,
                           VCS_PROOF_SYNC_WHY_OK) :
                   pr_equivocate(s);
    if (s->c.leaf_count < is->mmr.num_leaves)
        return pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_UNVERIFIABLE);
    if (is->verified_count > 0 &&
        memcmp(s->c.prev_checkpoint_root, is->last_root, 32) != 0)
        return pr_verified_prev(is, s->c.prev_checkpoint_root) ?
                   pr_equivocate(s) :
                   pr_done(s->out, VCS_PROOF_SYNC_REFUSED,
                           VCS_PROOF_SYNC_WHY_GAP);
    return pr_extend(s);
}

static size_t pr_bytes(size_t cp_len, const size_t *lens, size_t n)
{
    size_t total = cp_len;
    for (size_t i = 0; lens && i < n; i++) total += lens[i];
    return total;
}

bool vcs_proof_receiver_sync(struct vcs_proof_receiver *r,
                             const uint8_t *checkpoint, size_t checkpoint_len,
                             const uint8_t *const *delta,
                             const size_t *delta_lens, size_t delta_count,
                             struct vcs_proof_sync_report *out)
{
    if (!out) LOG_RETURN(false, PRV_LOG, "sync: no report buffer");
    memset(out, 0, sizeof(*out));
    out->outcome = VCS_PROOF_SYNC_REFUSED;
    out->reason = VCS_PROOF_SYNC_WHY_MALFORMED;
    if (!r || !checkpoint || (delta_count && (!delta || !delta_lens)))
        LOG_RETURN(false, PRV_LOG, "sync: null argument");
    out->bytes = pr_bytes(checkpoint_len, delta_lens, delta_count);
    struct pr_sync s = {.r = r, .delta = delta, .lens = delta_lens,
                        .n = delta_count, .out = out};
    if (!vcs_proof_checkpoint_decode(checkpoint, checkpoint_len, &s.c) ||
        !vcs_proof_checkpoint_root(checkpoint, checkpoint_len, s.root))
        return pr_done(out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_MALFORMED);
    if (!vcs_proof_checkpoint_signature_valid(&s.c))
        return pr_done(out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_SIGNATURE);
    memcpy(s.wire, checkpoint, VCS_PROOF_CHECKPOINT_WIRE_BYTES);
    s.is = pr_issuer_get(r, s.c.issuer_pubkey);
    if (!s.is)
        return pr_done(out, VCS_PROOF_SYNC_REFUSED,
                       VCS_PROOF_SYNC_WHY_RESOURCES);
    out->leaves_before = s.is->mmr.num_leaves;
    out->leaves_after = s.is->mmr.num_leaves;
    return pr_classify(&s);
}
