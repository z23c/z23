/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared rig for the proof ticket tests: fixed identities, issuer
 *          logs, one receiver, and an in-memory artifact CAS. */

#include "test/proof_ticket_fixture.h"

#include "crypto/ed25519.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ptf_root(enum vcs_component_proof_field f, const char *text,
              uint8_t out[32])
{
    if (!vcs_component_proof_field_root(f, text, strlen(text), out))
        memset(out, 0, 32);
}

static bool ptf_fetch(void *ctx, const uint8_t root[32],
                      const uint8_t **bytes, size_t *len)
{
    struct ptf *f = ctx;
    for (size_t i = 0; i < f->art_count; i++) {
        if (memcmp(f->arts[i].root, root, 32) != 0) continue;
        *bytes = f->arts[i].bytes;
        *len = f->arts[i].len;
        static const uint8_t any[32];
        bool targeted = memcmp(f->tamper_root, any, 32) != 0;
        if (!f->tamper || (targeted && memcmp(root, f->tamper_root, 32) != 0))
            return true;
        free(f->tamper_buf);
        f->tamper_buf = malloc(f->arts[i].len);
        if (!f->tamper_buf) return false;
        memcpy(f->tamper_buf, f->arts[i].bytes, f->arts[i].len);
        f->tamper_buf[0] ^= 0x01;
        *bytes = f->tamper_buf;
        return true;
    }
    return false;
}

static void ptf_identities(struct ptf *f)
{
    for (int k = 0; k < PTF_KEYS; k++) {
        uint8_t sk[32];
        memset(f->seed[k], 0x11 * (k + 1), 32);
        f->seed[k][0] = (uint8_t)(0xA0 + k);
        zcl_ed25519_keypair(f->pub[k], sk, f->seed[k]);
    }
    memcpy(f->verifiers[0], f->pub[PTF_A], 32);
    memcpy(f->verifiers[1], f->pub[PTF_B], 32);
    memcpy(f->verifiers[2], f->pub[PTF_C], 32);
    memcpy(f->extra[0], f->pub[PTF_EXTRA], 32);
}

bool ptf_init(struct ptf *f)
{
    memset(f, 0, sizeof(*f));
    ptf_identities(f);
    for (int k = 0; k < VCS_CPK_FIELD_COUNT; k++) {
        char text[64];
        snprintf(text, sizeof(text), "base-%s",
                 vcs_component_proof_field_name(
                     (enum vcs_component_proof_field)k));
        ptf_root((enum vcs_component_proof_field)k, text, f->base.roots[k]);
    }
    memcpy(f->domain.author_pubkey, f->pub[PTF_AUTHOR], 32);
    f->domain.has_local_signer = true;
    memcpy(f->domain.local_signer_pubkey, f->pub[PTF_LOCAL], 32);
    f->domain.extra = (const uint8_t (*)[32])f->extra;
    f->domain.extra_count = 1;
    memcpy(f->policy.policy_root, f->base.roots[VCS_CPK_POLICY], 32);
    f->policy.verifiers = (const uint8_t (*)[32])f->verifiers;
    f->policy.verifier_count = 3;
    f->policy.quorum = 2;
    f->source.fetch = ptf_fetch;
    f->source.ctx = f;
    f->rx = vcs_proof_receiver_new();
    bool ok = f->rx != NULL;
    for (int k = 0; ok && k < PTF_KEYS; k++) {
        f->logs[k] = vcs_proof_issuer_log_new(f->seed[k]);
        ok = f->logs[k] != NULL;
    }
    return ok;
}

void ptf_free(struct ptf *f)
{
    for (int k = 0; k < PTF_KEYS; k++) vcs_proof_issuer_log_free(f->logs[k]);
    vcs_proof_receiver_free(f->rx);
    for (size_t i = 0; i < f->art_count; i++) free(f->arts[i].bytes);
    free(f->arts);
    free(f->tamper_buf);
    memset(f, 0, sizeof(*f));
}

struct ptf_spec ptf_pass(void)
{
    return (struct ptf_spec){VCS_PROOF_VERDICT_PASS, VCS_PROOF_BASIS_EXECUTED,
                             VCS_PROOF_ACTION_CHECK, NULL, 0, 0};
}

struct ptf_spec ptf_fail(void)
{
    struct ptf_spec s = ptf_pass();
    s.verdict = VCS_PROOF_VERDICT_FAIL;
    return s;
}

/* Deterministic output bytes of one build action, stored in the CAS. */
static bool ptf_artifact(struct ptf *f, const uint8_t key[32], uint8_t salt,
                         uint8_t root[32])
{
    size_t len = 256;
    uint8_t *bytes = malloc(len);
    if (!bytes) return false;
    for (size_t i = 0; i < len; i++) bytes[i] = (uint8_t)(key[i % 32] ^ i ^ salt);
    if (!vcs_proof_artifact_root(bytes, len, root)) {
        free(bytes);
        return false;
    }
    for (size_t i = 0; i < f->art_count; i++)
        if (memcmp(f->arts[i].root, root, 32) == 0) {
            free(bytes);
            return true;
        }
    if (f->art_count == f->art_cap) {
        size_t cap = f->art_cap ? f->art_cap * 2u : 64u;
        struct ptf_artifact *grown = realloc(f->arts, cap * sizeof(*grown));
        if (!grown) {
            free(bytes);
            return false;
        }
        f->arts = grown;
        f->art_cap = cap;
    }
    f->arts[f->art_count++] = (struct ptf_artifact){{0}, bytes, len};
    memcpy(f->arts[f->art_count - 1].root, root, 32);
    return true;
}

static bool ptf_fill(struct ptf *f, int signer,
                     const struct vcs_component_proof_key_v1 *key,
                     struct ptf_spec spec, struct vcs_proof_ticket_v1 *t)
{
    memset(t, 0, sizeof(*t));
    t->verdict = spec.verdict;
    t->basis = spec.basis;
    t->action_class = spec.action_class;
    if (!vcs_component_proof_key_derive(key, t->input_key) ||
        !vcs_component_proof_key_preimage_root(key, t->key_preimage_root))
        return false;
    memcpy(t->source_root, key->roots[VCS_CPK_SOURCE_CLOSURE], 32);
    memset(t->evidence_root, 0x5e, 32);
    t->evidence_root[0] = (uint8_t)signer;
    if (spec.basis_ref) memcpy(t->basis_ref, spec.basis_ref, 32);
    t->checks_run = 4;
    t->checks_passed = spec.verdict == VCS_PROOF_VERDICT_PASS ? 4u : 3u;
    t->cpu_us = 1000;
    t->wall_us = 1200;
    t->bytes_in = 4096;
    t->bytes_out = 8192;
    t->created_unix = spec.created ? spec.created : 1790000000u;
    if (spec.action_class == VCS_PROOF_ACTION_BUILD &&
        spec.verdict == VCS_PROOF_VERDICT_PASS)
        return ptf_artifact(f, t->input_key, spec.artifact_salt,
                            t->artifact_root);
    return true;
}

bool ptf_emit(struct ptf *f, int signer,
              const struct vcs_component_proof_key_v1 *key,
              struct ptf_spec spec, uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES],
              uint8_t root[32])
{
    struct vcs_proof_ticket_v1 t;
    uint8_t local[VCS_PROOF_TICKET_WIRE_BYTES];
    uint8_t *out = wire ? wire : local;
    if (!ptf_fill(f, signer, key, spec, &t) ||
        !vcs_proof_issuer_log_append(f->logs[signer], &t, out))
        return false;
    return !root || vcs_proof_ticket_observation_root(
                        out, VCS_PROOF_TICKET_WIRE_BYTES, root);
}

bool ptf_sync(struct ptf *f, int signer, uint64_t created,
              struct vcs_proof_sync_report *rep)
{
    struct vcs_proof_issuer_log *log = f->logs[signer];
    uint8_t cp[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
    uint64_t have = vcs_proof_receiver_issuer_leaves(f->rx, f->pub[signer]);
    uint64_t count = vcs_proof_issuer_log_count(log);
    if (count == 0 || count < have ||
        !vcs_proof_issuer_log_checkpoint(log, created ? created : 1790000001u,
                                         cp))
        return false;
    size_t n = (size_t)(count - have);
    const uint8_t **delta = calloc(n + 1u, sizeof(*delta));
    size_t *lens = calloc(n + 1u, sizeof(*lens));
    bool ok = delta && lens;
    for (size_t i = 0; ok && i < n; i++) {
        delta[i] = vcs_proof_issuer_log_ticket(log, have + i);
        lens[i] = VCS_PROOF_TICKET_WIRE_BYTES;
    }
    int64_t t0 = platform_time_monotonic_us();
    ok = ok && vcs_proof_receiver_sync(f->rx, cp, sizeof(cp),
                                       (const uint8_t *const *)delta, lens, n,
                                       rep);
    f->sync_verify_us += (uint64_t)(platform_time_monotonic_us() - t0);
    if (ok) {
        f->sync_bytes += rep->bytes;
        f->sync_checkpoints++;
    }
    free(delta);
    free(lens);
    return ok;
}

bool ptf_decide(struct ptf *f, const struct vcs_component_proof_key_v1 *key,
                enum vcs_proof_action_class action_class,
                const struct vcs_proof_reuse_policy *policy,
                struct vcs_proof_ticket_class *classes, size_t cap,
                struct vcs_proof_reuse_decision *out)
{
    struct vcs_proof_reuse_request req = {
        .local = key,
        .action_class = action_class,
        .domain = &f->domain,
        .policy = policy ? policy : &f->policy,
        .artifacts = &f->source,
    };
    return vcs_proof_reuse_decide(f->rx, &req, classes, cap, out);
}

struct vcs_proof_admission_context ptf_context(struct ptf *f)
{
    return (struct vcs_proof_admission_context){
        .receiver = f->rx,
        .domain = &f->domain,
        .policy = &f->policy,
        .artifacts = &f->source,
    };
}
