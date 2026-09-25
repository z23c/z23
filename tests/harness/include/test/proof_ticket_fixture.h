/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared rig for the proof ticket tests: fixed identities, issuer
 *          logs, one receiver, and an in-memory artifact CAS. */

#ifndef ZCL_TEST_PROOF_TICKET_FIXTURE_H
#define ZCL_TEST_PROOF_TICKET_FIXTURE_H

#include "vcs/proof_reuse.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A, B and C are the receiver's independent verifiers. AUTHOR, LOCAL and
 * EXTRA are the candidate trust domain; STRANGER is trusted by nobody. */
enum { PTF_A = 0, PTF_B, PTF_C, PTF_AUTHOR, PTF_LOCAL, PTF_EXTRA,
       PTF_STRANGER, PTF_KEYS };

struct ptf_artifact {
    uint8_t root[32];
    uint8_t *bytes;
    size_t len;
};

struct ptf {
    uint8_t seed[PTF_KEYS][32];
    uint8_t pub[PTF_KEYS][32];
    uint8_t verifiers[4][32];
    uint8_t extra[1][32];
    struct vcs_component_proof_key_v1 base;
    struct vcs_proof_candidate_domain domain;
    struct vcs_proof_reuse_policy policy;
    struct vcs_proof_issuer_log *logs[PTF_KEYS];
    struct vcs_proof_receiver *rx;
    struct ptf_artifact *arts;
    size_t art_count;
    size_t art_cap;
    /* When set, fetching tamper_root (any root while it is all zero)
     * returns bytes with one bit flipped. */
    bool tamper;
    uint8_t tamper_root[32];
    uint8_t *tamper_buf;
    struct vcs_proof_artifact_source source;
    uint64_t sync_bytes;
    uint64_t sync_checkpoints;
    uint64_t sync_verify_us;        /* receiver-side sync time only */
};

struct ptf_spec {
    enum vcs_proof_verdict verdict;
    enum vcs_proof_basis basis;
    enum vcs_proof_action_class action_class;
    const uint8_t *basis_ref;       /* REUSED only */
    uint64_t created;               /* 0 = fixed default */
    uint8_t artifact_salt;          /* nonzero: a different build output */
};

bool ptf_init(struct ptf *f);
void ptf_free(struct ptf *f);
void ptf_root(enum vcs_component_proof_field f, const char *text,
              uint8_t out[32]);
struct ptf_spec ptf_pass(void);
struct ptf_spec ptf_fail(void);
/* Build, sign and append one ticket to `signer`'s own log; a BUILD PASS
 * also stores deterministic artifact bytes in the CAS. The wire and its
 * observation root are returned when the pointers are non-NULL. */
bool ptf_emit(struct ptf *f, int signer,
              const struct vcs_component_proof_key_v1 *key,
              struct ptf_spec spec, uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES],
              uint8_t root[32]);
/* Checkpoint `signer`'s log and sync the receiver with only the delta. */
bool ptf_sync(struct ptf *f, int signer, uint64_t created,
              struct vcs_proof_sync_report *rep);
bool ptf_decide(struct ptf *f, const struct vcs_component_proof_key_v1 *key,
                enum vcs_proof_action_class action_class,
                const struct vcs_proof_reuse_policy *policy,
                struct vcs_proof_ticket_class *classes, size_t cap,
                struct vcs_proof_reuse_decision *out);

/* Equivocation, artifact and CAS cases (test_proof_ticket_logs.c), run by
 * the proof_ticket_reuse group. Returns the failure count. */
int ptf_log_cases(void);

#endif /* ZCL_TEST_PROOF_TICKET_FIXTURE_H */
