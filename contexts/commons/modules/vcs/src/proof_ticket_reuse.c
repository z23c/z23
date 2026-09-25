/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Append-only proof ticket index and the receiver's exact-key
 *          reuse decision (HIT / HIT_FAIL / MISS / REFUSE). */

#include "vcs/proof_ticket.h"

#include "vcs/blob_store.h"
#include "vcs/package_store.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

#define PTR_LOG "vcs.proof_ticket"
#define PTR_REBUILD_BATCH 256u

/* ── Index ──────────────────────────────────────────────────────────── */

void vcs_proof_ticket_index_init(struct vcs_proof_ticket_index *index)
{
    if (index) memset(index, 0, sizeof(*index));
}

void vcs_proof_ticket_index_free(struct vcs_proof_ticket_index *index)
{
    if (!index) return;
    free(index->entries);
    memset(index, 0, sizeof(*index));
}

static bool ptr_index_has(const struct vcs_proof_ticket_index *index,
                          const uint8_t root[VCS_PROOF_ROOT_BYTES])
{
    for (size_t i = 0; i < index->count; i++)
        if (memcmp(index->entries[i].observation_root, root,
                   VCS_PROOF_ROOT_BYTES) == 0)
            return true;
    return false;
}

static bool ptr_index_reserve(struct vcs_proof_ticket_index *index)
{
    if (index->count < index->cap) return true;
    size_t cap = index->cap ? index->cap * 2u : 64u;
    if (cap < index->cap ||
        cap > SIZE_MAX / sizeof(struct vcs_proof_ticket_index_entry))
        LOG_RETURN(false, PTR_LOG, "ticket index capacity overflow at %zu",
                   index->cap);
    struct vcs_proof_ticket_index_entry *grown =
        zcl_realloc(index->entries, cap * sizeof(*grown),
                    "proof_ticket_index");
    if (!grown)
        LOG_RETURN(false, PTR_LOG, "ticket index: out of memory (%zu entries)",
                   cap);
    index->entries = grown;
    index->cap = cap;
    return true;
}

bool vcs_proof_ticket_index_add(struct vcs_proof_ticket_index *index,
                                const uint8_t *wire, size_t len,
                                bool *added)
{
    if (added) *added = false;
    if (!index || !wire)
        LOG_RETURN(false, PTR_LOG, "ticket index add: null argument");
    struct vcs_proof_ticket_v1 ticket;
    if (!vcs_proof_ticket_decode(wire, len, &ticket))
        LOG_RETURN(false, PTR_LOG, "ticket index add: undecodable ticket");
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    if (!vcs_proof_ticket_observation_root(wire, len, root))
        LOG_RETURN(false, PTR_LOG, "ticket index add: no observation root");
    if (ptr_index_has(index, root)) return true;
    if (!ptr_index_reserve(index)) return false;
    struct vcs_proof_ticket_index_entry *e = &index->entries[index->count++];
    memcpy(e->input_key, ticket.input_key, VCS_PROOF_ROOT_BYTES);
    memcpy(e->observation_root, root, VCS_PROOF_ROOT_BYTES);
    memcpy(e->wire, wire, VCS_PROOF_TICKET_WIRE_BYTES);
    if (added) *added = true;
    return true;
}

size_t vcs_proof_ticket_index_lookup(
    const struct vcs_proof_ticket_index *index,
    const uint8_t input_key[VCS_PROOF_ROOT_BYTES],
    const struct vcs_proof_ticket_index_entry **out, size_t cap)
{
    if (!index || !input_key) return 0;
    size_t total = 0;
    for (size_t i = 0; i < index->count; i++) {
        if (memcmp(index->entries[i].input_key, input_key,
                   VCS_PROOF_ROOT_BYTES) != 0)
            continue;
        if (out && total < cap) out[total] = &index->entries[i];
        total++;
    }
    return total;
}

static void ptr_rebuild_one(struct vcs_proof_ticket_index *index,
                            struct vcs_package_store *store,
                            const uint8_t root[VCS_PROOF_ROOT_BYTES],
                            size_t *added, size_t *skipped)
{
    uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES + 1u];
    size_t len = 0;
    struct vcs_proof_ticket_v1 probe;
    bool is_ticket =
        vcs_blob_get_from(store, root, wire, sizeof(wire), &len) ==
            VCS_BLOB_OK &&
        len == VCS_PROOF_TICKET_WIRE_BYTES &&
        memcmp(wire, "Z23PTK1\0", 8) == 0 &&
        vcs_proof_ticket_decode(wire, len, &probe);
    bool fresh = false;
    if (is_ticket && vcs_proof_ticket_index_add(index, wire, len, &fresh)) {
        if (fresh) (*added)++;
        return;
    }
    (*skipped)++;
}

bool vcs_proof_ticket_index_rebuild(struct vcs_proof_ticket_index *index,
                                    struct vcs_package_store *store,
                                    size_t *added, size_t *skipped)
{
    size_t local_added = 0, local_skipped = 0;
    if (!index || !store)
        LOG_RETURN(false, PTR_LOG, "ticket index rebuild: null argument");
    struct vcs_package_store_summary *rows =
        zcl_calloc(PTR_REBUILD_BATCH, sizeof(*rows), "proof_ticket_rebuild");
    if (!rows)
        LOG_RETURN(false, PTR_LOG, "ticket index rebuild: out of memory");
    size_t n = vcs_package_store_list_summaries(store, true, rows,
                                                PTR_REBUILD_BATCH);
    bool truncated = n >= PTR_REBUILD_BATCH;
    for (size_t i = 0; i < n; i++)
        ptr_rebuild_one(index, store, rows[i].root, &local_added,
                        &local_skipped);
    free(rows);
    if (added) *added = local_added;
    if (skipped) *skipped = local_skipped;
    if (truncated)
        LOG_RETURN(false, PTR_LOG,
                   "ticket index rebuild: store lists %zu+ packages, more "
                   "than one batch; refusing a partial projection", n);
    return true;
}

/* ── Receiver decision ──────────────────────────────────────────────── */

struct ptr_local {
    const struct vcs_component_proof_key_v1 *preimage;
    const struct vcs_proof_candidate_domain *domain;
    const struct vcs_proof_reuse_policy *policy;
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint8_t preimage_root[VCS_PROOF_ROOT_BYTES];
};

static bool ptr_key_in(const uint8_t key[VCS_PROOF_PUBKEY_BYTES],
                       const uint8_t (*set)[VCS_PROOF_PUBKEY_BYTES],
                       size_t count)
{
    for (size_t i = 0; set && i < count; i++)
        if (memcmp(set[i], key, VCS_PROOF_PUBKEY_BYTES) == 0) return true;
    return false;
}

static bool ptr_in_domain(const struct vcs_proof_candidate_domain *d,
                          const uint8_t key[VCS_PROOF_PUBKEY_BYTES])
{
    if (memcmp(d->author_pubkey, key, VCS_PROOF_PUBKEY_BYTES) == 0)
        return true;
    if (d->has_local_signer &&
        memcmp(d->local_signer_pubkey, key, VCS_PROOF_PUBKEY_BYTES) == 0)
        return true;
    return ptr_key_in(key, d->extra, d->extra_count);
}

static const char *ptr_freshness(const struct vcs_proof_reuse_policy *p,
                                 uint64_t created)
{
    if (p->now_unix == 0) return NULL;
    if (created > p->now_unix && created - p->now_unix > p->max_future_seconds)
        return VCS_PROOF_TICKET_FUTURE;
    if (p->max_age_seconds && created < p->now_unix &&
        p->now_unix - created > p->max_age_seconds)
        return VCS_PROOF_TICKET_STALE;
    return NULL;
}

/* Everything that makes one decodable ticket ineligible, cheapest first.
 * Domain membership outranks the verifier set: a key in both never
 * authorizes reuse for this candidate. */
static const char *ptr_ineligible(const struct ptr_local *l,
                                  const struct vcs_proof_ticket_v1 *t)
{
    if (memcmp(t->input_key, l->input_key, VCS_PROOF_ROOT_BYTES) != 0)
        return VCS_PROOF_TICKET_KEY_MISMATCH;
    if (memcmp(t->key_preimage_root, l->preimage_root,
               VCS_PROOF_ROOT_BYTES) != 0)
        return VCS_PROOF_TICKET_PREIMAGE_MISMATCH;
    if (ptr_in_domain(l->domain, t->producer_pubkey))
        return VCS_PROOF_TICKET_SIGNER_IN_DOMAIN;
    if (!ptr_key_in(t->producer_pubkey, l->policy->verifiers,
                    l->policy->verifier_count))
        return VCS_PROOF_TICKET_SIGNER_UNTRUSTED;
    if (!t->reproduced) return VCS_PROOF_TICKET_NOT_REPRODUCED;
    const char *fresh = ptr_freshness(l->policy, t->created_unix);
    if (fresh) return fresh;
    /* Signature last among the checks, first among the costs: only a
     * ticket that could matter pays for Ed25519, and a forged one is still
     * retained with its reason. */
    if (!vcs_proof_ticket_signature_valid(t))
        return VCS_PROOF_TICKET_SIGNATURE_INVALID;
    return NULL;
}

static bool ptr_seen_root(const struct vcs_proof_ticket_class *classes,
                          size_t upto, const uint8_t root[32])
{
    for (size_t i = 0; i < upto; i++)
        if (memcmp(classes[i].observation_root, root, 32) == 0) return true;
    return false;
}

static void ptr_classify(const struct ptr_local *l, const uint8_t *wire,
                         size_t len, struct vcs_proof_ticket_class *all,
                         size_t index)
{
    struct vcs_proof_ticket_class *c = &all[index];
    memset(c, 0, sizeof(*c));
    c->reason = VCS_PROOF_TICKET_MALFORMED;
    if (!wire || !vcs_proof_ticket_observation_root(wire, len,
                                                    c->observation_root))
        return;
    struct vcs_proof_ticket_v1 t;
    if (!vcs_proof_ticket_decode(wire, len, &t)) return;
    c->verdict = t.verdict;
    memcpy(c->producer_pubkey, t.producer_pubkey, VCS_PROOF_PUBKEY_BYTES);
    if (ptr_seen_root(all, index, c->observation_root)) {
        c->reason = VCS_PROOF_TICKET_DUPLICATE;
        return;
    }
    const char *why = ptr_ineligible(l, &t);
    c->eligible = why == NULL;
    c->reason = why ? why : VCS_PROOF_TICKET_ELIGIBLE;
}

static void ptr_use(struct vcs_proof_reuse_decision *out,
                    const struct vcs_proof_ticket_class *c)
{
    if (out->used_count >= VCS_PROOF_REUSE_MAX_USED) return;
    memcpy(out->used[out->used_count++], c->observation_root,
           VCS_PROOF_ROOT_BYTES);
}

static void ptr_count(const struct vcs_proof_ticket_class *classes,
                      size_t count, struct vcs_proof_reuse_decision *out)
{
    for (size_t i = 0; i < count; i++) {
        const struct vcs_proof_ticket_class *c = &classes[i];
        if (!c->eligible) continue;
        if (c->verdict == VCS_PROOF_VERDICT_FAIL) {
            out->eligible_fail++;
            continue;
        }
        out->eligible_pass++;
        bool repeat = false;
        for (size_t j = 0; j < i && !repeat; j++)
            repeat = classes[j].eligible &&
                     classes[j].verdict == VCS_PROOF_VERDICT_PASS &&
                     memcmp(classes[j].producer_pubkey, c->producer_pubkey,
                            VCS_PROOF_PUBKEY_BYTES) == 0;
        if (!repeat) out->distinct_pass_signers++;
    }
}

static void ptr_use_verdict(const struct vcs_proof_ticket_class *classes,
                            size_t count, bool pass, bool fail,
                            struct vcs_proof_reuse_decision *out)
{
    for (size_t i = 0; i < count; i++) {
        if (!classes[i].eligible) continue;
        bool is_pass = classes[i].verdict == VCS_PROOF_VERDICT_PASS;
        if ((is_pass && pass) || (!is_pass && fail)) ptr_use(out, &classes[i]);
    }
}

static void ptr_conclude(const struct vcs_proof_reuse_policy *policy,
                         const struct vcs_proof_ticket_class *classes,
                         size_t count, struct vcs_proof_reuse_decision *out)
{
    ptr_count(classes, count, out);
    if (out->eligible_pass && out->eligible_fail) {
        out->outcome = VCS_PROOF_REUSE_REFUSE;
        out->reason = VCS_PROOF_OBSERVATION_CONFLICT;
        ptr_use_verdict(classes, count, true, true, out);
    } else if (out->eligible_fail) {
        out->outcome = VCS_PROOF_REUSE_HIT_FAIL;
        out->reason = VCS_PROOF_REUSE_WHY_KNOWN_FAIL;
        ptr_use_verdict(classes, count, false, true, out);
    } else if (out->distinct_pass_signers >= policy->quorum) {
        out->outcome = VCS_PROOF_REUSE_HIT_PASS;
        out->reason = VCS_PROOF_REUSE_WHY_HIT;
        ptr_use_verdict(classes, count, true, false, out);
    } else {
        out->outcome = VCS_PROOF_REUSE_MISS;
        out->reason = count == 0 ? VCS_PROOF_REUSE_WHY_NONE :
                      out->eligible_pass ? VCS_PROOF_REUSE_WHY_QUORUM :
                                           VCS_PROOF_REUSE_WHY_INELIGIBLE;
    }
}

static bool ptr_refuse(struct vcs_proof_reuse_decision *out, const char *why)
{
    out->outcome = VCS_PROOF_REUSE_REFUSE;
    out->reason = why;
    LOG_RETURN(false, PTR_LOG, "proof reuse refused: %s", why);
}

static const char *ptr_setup_why(const struct vcs_proof_candidate_domain *d,
                                 const struct vcs_proof_reuse_policy *p,
                                 const struct vcs_component_proof_key_v1 *k)
{
    static const uint8_t zero[VCS_PROOF_PUBKEY_BYTES];
    if (!d || !p || !k) return VCS_PROOF_REUSE_WHY_ARGUMENTS;
    if (!vcs_component_proof_key_valid(k)) return VCS_PROOF_REUSE_WHY_PREIMAGE;
    if (p->quorum == 0 || (!p->verifiers && p->verifier_count))
        return VCS_PROOF_REUSE_WHY_POLICY;
    if (memcmp(k->roots[VCS_CPK_POLICY], p->policy_root,
               VCS_PROOF_ROOT_BYTES) != 0)
        return VCS_PROOF_REUSE_WHY_POLICY_ROOT;
    if (memcmp(d->author_pubkey, zero, sizeof(zero)) == 0 ||
        (!d->extra && d->extra_count))
        return VCS_PROOF_REUSE_WHY_DOMAIN;
    return NULL;
}

static bool ptr_prepare(const struct vcs_component_proof_key_v1 *local,
                        const struct vcs_proof_candidate_domain *domain,
                        const struct vcs_proof_reuse_policy *policy,
                        struct ptr_local *l,
                        struct vcs_proof_reuse_decision *out)
{
    memset(out, 0, sizeof(*out));
    const char *why = ptr_setup_why(domain, policy, local);
    if (why) return ptr_refuse(out, why);
    l->preimage = local;
    l->domain = domain;
    l->policy = policy;
    if (!vcs_component_proof_key_derive(local, l->input_key) ||
        !vcs_component_proof_key_preimage_root(local, l->preimage_root))
        return ptr_refuse(out, VCS_PROOF_REUSE_WHY_PREIMAGE);
    memcpy(out->input_key, l->input_key, VCS_PROOF_ROOT_BYTES);
    return true;
}

bool vcs_proof_reuse_decide(const struct vcs_component_proof_key_v1 *local,
                            const struct vcs_proof_candidate_domain *domain,
                            const struct vcs_proof_reuse_policy *policy,
                            const uint8_t *const *wires, const size_t *lens,
                            size_t count,
                            struct vcs_proof_ticket_class *classes,
                            struct vcs_proof_reuse_decision *out)
{
    if (!out) LOG_RETURN(false, PTR_LOG, "proof reuse: no decision buffer");
    struct ptr_local l;
    if (!ptr_prepare(local, domain, policy, &l, out)) return false;
    if (count && (!wires || !lens || !classes))
        return ptr_refuse(out, VCS_PROOF_REUSE_WHY_ARGUMENTS);
    if (count > UINT32_MAX)
        return ptr_refuse(out, VCS_PROOF_REUSE_WHY_CAPACITY);
    out->tickets_seen = (uint32_t)count;
    for (size_t i = 0; i < count; i++)
        ptr_classify(&l, wires[i], lens[i], classes, i);
    ptr_conclude(policy, classes, count, out);
    return true;
}

bool vcs_proof_reuse_decide_index(
    const struct vcs_component_proof_key_v1 *local,
    const struct vcs_proof_candidate_domain *domain,
    const struct vcs_proof_reuse_policy *policy,
    const struct vcs_proof_ticket_index *index,
    struct vcs_proof_ticket_class *classes, size_t class_cap,
    struct vcs_proof_reuse_decision *out)
{
    if (!out) LOG_RETURN(false, PTR_LOG, "proof reuse: no decision buffer");
    struct ptr_local l;
    if (!ptr_prepare(local, domain, policy, &l, out)) return false;
    if (!index || (class_cap && !classes))
        return ptr_refuse(out, VCS_PROOF_REUSE_WHY_ARGUMENTS);
    const struct vcs_proof_ticket_index_entry *hits[64];
    size_t cap = class_cap < 64u ? class_cap : 64u;
    size_t total = vcs_proof_ticket_index_lookup(index, l.input_key, hits, cap);
    if (total > cap) return ptr_refuse(out, VCS_PROOF_REUSE_WHY_CAPACITY);
    const uint8_t *wires[64];
    size_t lens[64];
    for (size_t i = 0; i < total; i++) {
        wires[i] = hits[i]->wire;
        lens[i] = VCS_PROOF_TICKET_WIRE_BYTES;
    }
    return vcs_proof_reuse_decide(local, domain, policy, wires, lens, total,
                                  classes, out);
}

const char *vcs_proof_reuse_outcome_name(enum vcs_proof_reuse_outcome o)
{
    switch (o) {
    case VCS_PROOF_REUSE_MISS: return "MISS";
    case VCS_PROOF_REUSE_HIT_PASS: return "HIT";
    case VCS_PROOF_REUSE_HIT_FAIL: return "HIT_FAIL";
    case VCS_PROOF_REUSE_REFUSE: return "REFUSE";
    }
    return "UNKNOWN";
}
