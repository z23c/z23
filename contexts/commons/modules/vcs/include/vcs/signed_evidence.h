/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Stateless domain-rooted signatures shared by VCS evidence codecs. */

#ifndef ZCLASSIC23_VCS_SIGNED_EVIDENCE_H
#define ZCLASSIC23_VCS_SIGNED_EVIDENCE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* These primitives define no wire format and own no state.  Domain length is
 * explicit because existing versioned codecs deliberately differ on whether
 * their terminating NUL is committed. */
bool vcs_signed_evidence_root(const char *domain, size_t domain_len,
                              const uint8_t *body, size_t body_len,
                              uint8_t out[32]);

bool vcs_signed_evidence_seal_root(const uint8_t root[32],
                                   const uint8_t secret[32],
                                   const uint8_t pubkey[32],
                                   uint8_t signature[64]);

bool vcs_signed_evidence_verify_root(const uint8_t root[32],
                                     const uint8_t signature[64],
                                     const uint8_t signer_pubkey[32],
                                     const uint8_t expected_signer[32]);

#endif
