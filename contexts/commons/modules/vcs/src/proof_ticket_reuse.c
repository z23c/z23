/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The receiver's exact-key reuse decision (HIT / HIT_FAIL / MISS /
 *          REFUSE) over checkpoint-covered tickets, with artifact bytes
 *          re-verified before any build output is reused. */

#include "proof_reuse_priv.h"

#include "base/log_macros.h"

#include <string.h>

#define PTR_LOG "vcs.proof_reuse"
#define PTR_MAX_TICKETS 64u

/* Everything the decision derives from the LOCAL preimage and the
 * request. Nothing here comes from a ticket. */
struct ptr_local {
    const struct vcs_proof_receiver *r;
    const struct vcs_proof_reuse_request *req;
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

/* Identity: the ticket must be about exactly the local obligation. */
static const char *ptr_identity(const struct ptr_local *l,
                                const struct vcs_proof_ticket_v1 *t)
{
    const struct vcs_component_proof_key_v1 *k = l->req->local;
    if (memcmp(t->input_key, l->input_key, VCS_PROOF_ROOT_BYTES) != 0)
        return VCS_PROOF_TICKET_KEY_MISMATCH;
    if (memcmp(t->key_preimage_root, l->preimage_root,
               VCS_PROOF_ROOT_BYTES) != 0)
        return VCS_PROOF_TICKET_PREIMAGE_MISMATCH;
    if (memcmp(t->source_root, k->roots[VCS_CPK_SOURCE_CLOSURE],
               VCS_PROOF_ROOT_BYTES) != 0)
        return VCS_PROOF_TICKET_SOURCE_MISMATCH;
    if (t->action_class != l->req->action_class)
        return VCS_PROOF_TICKET_CLASS_MISMATCH;
    return NULL;
}

/* Authority, read from the CURRENT request. Domain membership outranks
 * the verifier set: a key in both never authorizes reuse here. */
static const char *ptr_authority(const struct ptr_local *l,
                                 const struct vcs_proof_ticket_v1 *t)
{
    const struct vcs_proof_reuse_policy *p = l->req->policy;
    if (ptr_in_domain(l->req->domain, t->producer_pubkey))
        return VCS_PROOF_TICKET_SIGNER_IN_DOMAIN;
    if (ptr_key_in(t->producer_pubkey, p->revoked, p->revoked_count))
        return VCS_PROOF_TICKET_SIGNER_REVOKED;
    if (!ptr_key_in(t->producer_pubkey, p->verifiers, p->verifier_count))
        return VCS_PROOF_TICKET_SIGNER_UNTRUSTED;
    if (t->basis != VCS_PROOF_BASIS_EXECUTED) return VCS_PROOF_TICKET_REUSED;
    return ptr_freshness(p, t->created_unix);
}

/* Log facts: the issuer is not equivocating and a verified checkpoint
 * covers this exact observation. Coverage is what authenticates the
 * ticket: the issuer's checkpoint signature commits to its root. */
static const char *ptr_coverage(const struct ptr_local *l,
                                const struct pr_entry *e)
{
    const struct pr_issuer *is = pr_issuer_find(l->r, e->producer);
    if (is && is->equivocating) return VCS_PROOF_TICKET_EQUIVOCATION;
    if (!e->covered) return VCS_PROOF_TICKET_NOT_CHECKPOINTED;
    return NULL;
}

static void ptr_classify(const struct ptr_local *l, const struct pr_entry *e,
                         struct vcs_proof_ticket_class *c)
{
    memset(c, 0, sizeof(*c));
    memcpy(c->observation_root, e->observation_root, VCS_PROOF_ROOT_BYTES);
    c->reason = VCS_PROOF_TICKET_MALFORMED;
    struct vcs_proof_ticket_v1 t;
    if (!vcs_proof_ticket_decode(e->wire, sizeof(e->wire), &t)) return;
    c->verdict = t.verdict;
    memcpy(c->producer_pubkey, t.producer_pubkey, VCS_PROOF_PUBKEY_BYTES);
    memcpy(c->artifact_root, t.artifact_root, VCS_PROOF_ROOT_BYTES);
    const char *why = ptr_identity(l, &t);
    if (!why) why = ptr_authority(l, &t);
    if (!why) why = ptr_coverage(l, e);
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

static bool ptr_repeat_signer(const struct vcs_proof_ticket_class *classes,
                              size_t upto)
{
    const struct vcs_proof_ticket_class *c = &classes[upto];
    for (size_t j = 0; j < upto; j++)
        if (classes[j].eligible &&
            classes[j].verdict == VCS_PROOF_VERDICT_PASS &&
            memcmp(classes[j].producer_pubkey, c->producer_pubkey,
                   VCS_PROOF_PUBKEY_BYTES) == 0)
            return true;
    return false;
}

static void ptr_count(const struct vcs_proof_ticket_class *classes,
                      size_t count, struct vcs_proof_reuse_decision *out)
{
    for (size_t i = 0; i < count; i++) {
        if (!classes[i].eligible) continue;
        if (classes[i].verdict == VCS_PROOF_VERDICT_FAIL) {
            out->eligible_fail++;
            continue;
        }
        out->eligible_pass++;
        if (!ptr_repeat_signer(classes, i)) out->distinct_pass_signers++;
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

/* Eligible successful builds of one action must agree on the output. */
static bool ptr_outputs_disagree(const struct vcs_proof_ticket_class *classes,
                                 size_t count, uint8_t first[32])
{
    bool have = false;
    for (size_t i = 0; i < count; i++) {
        if (!classes[i].eligible ||
            classes[i].verdict != VCS_PROOF_VERDICT_PASS)
            continue;
        if (!have) {
            memcpy(first, classes[i].artifact_root, 32);
            have = true;
        } else if (memcmp(first, classes[i].artifact_root, 32) != 0) {
            return true;
        }
    }
    return false;
}

static void ptr_set(struct vcs_proof_reuse_decision *out,
                    enum vcs_proof_reuse_outcome outcome, const char *why)
{
    out->outcome = outcome;
    out->reason = why;
}

/* A quorum for a BUILD reuses bytes only after they hash to their root. */
static void ptr_verify_artifact(const struct ptr_local *l,
                                const uint8_t root[32],
                                struct vcs_proof_reuse_decision *out)
{
    const struct vcs_proof_artifact_source *src = l->req->artifacts;
    const uint8_t *bytes = NULL;
    size_t len = 0;
    uint8_t got[VCS_PROOF_ROOT_BYTES];
    if (!src || !src->fetch || !src->fetch(src->ctx, root, &bytes, &len) ||
        (!bytes && len)) {
        ptr_set(out, VCS_PROOF_REUSE_MISS, VCS_PROOF_REUSE_WHY_ARTIFACT_MISSING);
        return;
    }
    if (!vcs_proof_artifact_root(bytes, len, got) ||
        memcmp(got, root, VCS_PROOF_ROOT_BYTES) != 0) {
        out->false_hit_refused = true;
        ptr_set(out, VCS_PROOF_REUSE_MISS,
                VCS_PROOF_REUSE_WHY_ARTIFACT_MISMATCH);
        return;
    }
    memcpy(out->artifact_root, root, VCS_PROOF_ROOT_BYTES);
    ptr_set(out, VCS_PROOF_REUSE_HIT_PASS, VCS_PROOF_REUSE_WHY_HIT);
}

static void ptr_pass(const struct ptr_local *l,
                     const struct vcs_proof_ticket_class *classes,
                     size_t count, struct vcs_proof_reuse_decision *out)
{
    uint8_t artifact[VCS_PROOF_ROOT_BYTES];
    ptr_use_verdict(classes, count, true, false, out);
    if (ptr_outputs_disagree(classes, count, artifact)) {
        ptr_set(out, VCS_PROOF_REUSE_REFUSE, VCS_PROOF_OBSERVATION_CONFLICT);
        return;
    }
    if (l->req->action_class == VCS_PROOF_ACTION_BUILD) {
        ptr_verify_artifact(l, artifact, out);
        return;
    }
    ptr_set(out, VCS_PROOF_REUSE_HIT_PASS, VCS_PROOF_REUSE_WHY_HIT);
}

static void ptr_conclude(const struct ptr_local *l,
                         const struct vcs_proof_ticket_class *classes,
                         size_t count, struct vcs_proof_reuse_decision *out)
{
    ptr_count(classes, count, out);
    if (out->eligible_pass && out->eligible_fail) {
        ptr_set(out, VCS_PROOF_REUSE_REFUSE, VCS_PROOF_OBSERVATION_CONFLICT);
        ptr_use_verdict(classes, count, true, true, out);
    } else if (out->eligible_fail) {
        ptr_set(out, VCS_PROOF_REUSE_HIT_FAIL, VCS_PROOF_REUSE_WHY_KNOWN_FAIL);
        ptr_use_verdict(classes, count, false, true, out);
    } else if (out->distinct_pass_signers >= l->req->policy->quorum) {
        ptr_pass(l, classes, count, out);
    } else {
        ptr_set(out, VCS_PROOF_REUSE_MISS,
                count == 0 ? VCS_PROOF_REUSE_WHY_NONE :
                out->eligible_pass ? VCS_PROOF_REUSE_WHY_QUORUM :
                                     VCS_PROOF_REUSE_WHY_INELIGIBLE);
    }
}

static bool ptr_refuse(struct vcs_proof_reuse_decision *out, const char *why)
{
    ptr_set(out, VCS_PROOF_REUSE_REFUSE, why);
    LOG_RETURN(false, PTR_LOG, "proof reuse refused: %s", why);
}

static const char *ptr_policy_why(const struct vcs_proof_reuse_request *q)
{
    const struct vcs_proof_reuse_policy *p = q->policy;
    if (p->quorum == 0 || (!p->verifiers && p->verifier_count) ||
        (!p->revoked && p->revoked_count))
        return VCS_PROOF_REUSE_WHY_POLICY;
    if (memcmp(q->local->roots[VCS_CPK_POLICY], p->policy_root,
               VCS_PROOF_ROOT_BYTES) != 0)
        return VCS_PROOF_REUSE_WHY_POLICY_ROOT;
    return NULL;
}

static const char *ptr_request_why(const struct vcs_proof_reuse_request *q)
{
    static const uint8_t zero[VCS_PROOF_PUBKEY_BYTES];
    if (!q || !q->domain || !q->policy || !q->local)
        return VCS_PROOF_REUSE_WHY_ARGUMENTS;
    if (q->action_class != VCS_PROOF_ACTION_BUILD &&
        q->action_class != VCS_PROOF_ACTION_CHECK)
        return VCS_PROOF_REUSE_WHY_ARGUMENTS;
    if (!vcs_component_proof_key_valid(q->local))
        return VCS_PROOF_REUSE_WHY_PREIMAGE;
    const char *policy = ptr_policy_why(q);
    if (policy) return policy;
    if (memcmp(q->domain->author_pubkey, zero, sizeof(zero)) == 0 ||
        (!q->domain->extra && q->domain->extra_count))
        return VCS_PROOF_REUSE_WHY_DOMAIN;
    return NULL;
}

static bool ptr_prepare(const struct vcs_proof_receiver *r,
                        const struct vcs_proof_reuse_request *req,
                        struct ptr_local *l,
                        struct vcs_proof_reuse_decision *out)
{
    memset(out, 0, sizeof(*out));
    const char *why = r ? ptr_request_why(req) : VCS_PROOF_REUSE_WHY_ARGUMENTS;
    if (why) return ptr_refuse(out, why);
    l->r = r;
    l->req = req;
    if (!vcs_component_proof_key_derive(req->local, l->input_key) ||
        !vcs_component_proof_key_preimage_root(req->local, l->preimage_root))
        return ptr_refuse(out, VCS_PROOF_REUSE_WHY_PREIMAGE);
    memcpy(out->input_key, l->input_key, VCS_PROOF_ROOT_BYTES);
    return true;
}

bool vcs_proof_reuse_decide(const struct vcs_proof_receiver *r,
                            const struct vcs_proof_reuse_request *req,
                            struct vcs_proof_ticket_class *classes,
                            size_t class_cap,
                            struct vcs_proof_reuse_decision *out)
{
    if (!out) LOG_RETURN(false, PTR_LOG, "proof reuse: no decision buffer");
    struct ptr_local l;
    if (!ptr_prepare(r, req, &l, out)) return false;
    if (class_cap && !classes)
        return ptr_refuse(out, VCS_PROOF_REUSE_WHY_ARGUMENTS);
    size_t n = 0;
    for (size_t i = 0; i < r->count; i++) {
        const struct pr_entry *e = &r->entries[i];
        if (memcmp(e->input_key, l.input_key, VCS_PROOF_ROOT_BYTES) != 0)
            continue;
        if (n >= class_cap || n >= PTR_MAX_TICKETS)
            return ptr_refuse(out, VCS_PROOF_REUSE_WHY_CAPACITY);
        ptr_classify(&l, e, &classes[n++]);
    }
    out->tickets_seen = (uint32_t)n;
    ptr_conclude(&l, classes, n, out);
    return true;
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
