/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Receiver internals shared by the proof ticket sync, decision
 *          and CAS rebuild translation units. Not an API. */

#ifndef ZCL_VCS_PROOF_REUSE_PRIV_H
#define ZCL_VCS_PROOF_REUSE_PRIV_H

#include "vcs/proof_reuse.h"

#include "chain/mmr.h"

/* One retained observation. `covered` is a fact about signed data: this
 * exact observation root is a leaf of its issuer's checkpoint-verified
 * log. It says nothing about whether the issuer is trusted. */
struct pr_entry {
    uint8_t input_key[VCS_PROOF_ROOT_BYTES];
    uint8_t observation_root[VCS_PROOF_ROOT_BYTES];
    uint8_t producer[VCS_PROOF_PUBKEY_BYTES];
    uint64_t issuer_seq;
    bool covered;
    uint8_t wire[VCS_PROOF_TICKET_WIRE_BYTES];
};

/* One signature-valid checkpoint: verified (it extended the prefix) or
 * retained as equivocation evidence. */
struct pr_checkpoint {
    bool verified;
    uint64_t leaf_count;
    uint8_t mmr_root[VCS_PROOF_ROOT_BYTES];
    uint8_t prev[VCS_PROOF_ROOT_BYTES];
    uint8_t root[VCS_PROOF_ROOT_BYTES];
    uint8_t wire[VCS_PROOF_CHECKPOINT_WIRE_BYTES];
};

struct pr_issuer {
    uint8_t pubkey[VCS_PROOF_PUBKEY_BYTES];
    struct mmr mmr;                        /* verified prefix */
    uint8_t last_root[VCS_PROOF_ROOT_BYTES];
    uint32_t verified_count;
    bool equivocating;
    struct pr_checkpoint *cps;
    size_t cp_count;
    size_t cp_cap;
};

struct vcs_proof_receiver {
    struct pr_entry *entries;
    size_t count;
    size_t cap;
    struct pr_issuer *issuers;
    size_t issuer_count;
    size_t issuer_cap;
};

struct pr_entry *pr_entry_find(const struct vcs_proof_receiver *r,
                               const uint8_t root[VCS_PROOF_ROOT_BYTES]);
/* Append (or find) the entry for a decoded ticket; NULL on allocation
 * failure (logged). */
struct pr_entry *pr_entry_put(struct vcs_proof_receiver *r,
                              const uint8_t *wire,
                              const struct vcs_proof_ticket_v1 *t,
                              const uint8_t root[VCS_PROOF_ROOT_BYTES]);
const struct pr_issuer *pr_issuer_find(const struct vcs_proof_receiver *r,
                                       const uint8_t pubkey[32]);

#endif
