/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_verify_policy — the approved-verifier allowlist and the quorum
 * rule for ZCODE external-verifier attestations (slice 6). A release counts
 * as VERIFIED only when >= VCS_VERIFY_QUORUM_REQUIRED (2) APPROVED,
 * INDEPENDENT verifier keys sign MATCHING attestations (same package root,
 * same release id, same recipe root, same result class — the codec's
 * vcs_package_attest_matches tuple). Anonymous peers are not a quorum:
 * approved keys come from EXPLICIT LOCAL CONFIGURATION, never from the
 * network. Self-verification (verifier key == the release's publisher key)
 * is rejected, as is a duplicate signer.
 *
 * Approved-key configuration format (a local text file; the operator-facing
 * path is <datadir>/zcode/approved_verifiers):
 *   - one 66-hex compressed secp256k1 pubkey per line
 *   - blank lines and lines whose first byte is '#' are ignored
 *   - at most VCS_VERIFIER_POLICY_MAX_KEYS keys; a duplicate or malformed
 *     line is a load failure naming the line number
 *
 * This layer parses text and evaluates arrays of parsed attestations; it
 * has no network, wallet, compiler, execution, or node-state authority.
 * Filesystem access is limited to the optional load() helper reading the
 * one named policy file. */

#ifndef ZCL_VCS_PACKAGE_VERIFY_POLICY_H
#define ZCL_VCS_PACKAGE_VERIFY_POLICY_H

#include "vcs/package_attest.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_VERIFIER_POLICY_MAX_KEYS 64u
#define VCS_VERIFY_QUORUM_REQUIRED 2u
/* Rows the report carries; candidates beyond the row cap still evaluate. */
#define VCS_VERIFY_MAX_ROWS 64u
/* Bound on the policy file bytes load() will read (64 keys + comments). */
#define VCS_VERIFIER_POLICY_MAX_FILE_BYTES (64u * 1024u)

enum vcs_verifier_policy_error {
    VCS_VERIFIER_POLICY_OK = 0,
    VCS_VERIFIER_POLICY_ERR_NULL,        /* null argument */
    VCS_VERIFIER_POLICY_ERR_IO,          /* file unreadable/oversize */
    VCS_VERIFIER_POLICY_ERR_KEY_GRAMMAR, /* line not exactly 66 hex */
    VCS_VERIFIER_POLICY_ERR_KEY_OFFCURVE,/* not a compressed curve point */
    VCS_VERIFIER_POLICY_ERR_DUPLICATE,   /* key listed twice */
    VCS_VERIFIER_POLICY_ERR_TOO_MANY,    /* more than MAX_KEYS keys */
};

const char *vcs_verifier_policy_error_string(
    enum vcs_verifier_policy_error error);

struct vcs_verifier_policy {
    uint8_t keys[VCS_VERIFIER_POLICY_MAX_KEYS]
                [VCS_PACKAGE_ATTEST_PUBKEY_BYTES];
    size_t count;
};

void vcs_verifier_policy_init(struct vcs_verifier_policy *policy);

/* Add one compressed pubkey. False with *err_out set on an off-curve point,
 * a duplicate, or a full list. */
bool vcs_verifier_policy_add(struct vcs_verifier_policy *policy,
                             const uint8_t pubkey[33],
                             enum vcs_verifier_policy_error *err_out);

bool vcs_verifier_policy_contains(const struct vcs_verifier_policy *policy,
                                  const uint8_t pubkey[33]);

/* Parse the whole policy text (the format above). False with *err_out set
 * and *line_out naming the 1-based offending line on any rejection; the
 * policy is left with every key parsed before the failure (callers treat
 * ANY parse failure as "no policy"). */
bool vcs_verifier_policy_parse_text(struct vcs_verifier_policy *policy,
                                    const char *text, size_t text_len,
                                    enum vcs_verifier_policy_error *err_out,
                                    size_t *line_out);

/* Load + parse the policy file at `path` (bounded read). False with
 * *err_out set: ERR_IO names a missing/unreadable/oversize file. */
bool vcs_verifier_policy_load(struct vcs_verifier_policy *policy,
                              const char *path,
                              enum vcs_verifier_policy_error *err_out);

/* ── quorum evaluation ──────────────────────────────────────────────── */

/* The named per-attestation outcome. The enum order is frozen: it appears
 * in typed JSON. */
enum vcs_verify_row_rule {
    VCS_VERIFY_ROW_COUNTED = 0,          /* reaches the class cluster */
    VCS_VERIFY_ROW_ATTESTATION_INVALID,  /* parse or signature failure */
    VCS_VERIFY_ROW_PACKAGE_ROOT_MISMATCH,/* names a different package */
    VCS_VERIFY_ROW_RECIPE_ROOT_MISMATCH, /* not the envelope's recipe */
    VCS_VERIFY_ROW_SIGNER_NOT_APPROVED,  /* not on the local allowlist */
    VCS_VERIFY_ROW_SELF_VERIFICATION,    /* signer == release publisher */
    VCS_VERIFY_ROW_DUPLICATE_SIGNER,     /* this signer already counted */
};

const char *vcs_verify_row_rule_string(enum vcs_verify_row_rule rule);

struct vcs_verify_candidate {
    struct vcs_package_attest attestation; /* valid when parsed */
    bool parsed; /* false: the wire did not parse canonically */
};

struct vcs_verify_row {
    uint8_t verifier_pubkey[VCS_PACKAGE_ATTEST_PUBKEY_BYTES];
    bool has_pubkey;      /* false when the wire never parsed */
    uint8_t result_class; /* 0 when unparseable */
    enum vcs_verify_row_rule rule;
};

struct vcs_verify_quorum {
    uint32_t candidates;    /* every candidate evaluated */
    uint32_t counted;       /* rows that reached the class cluster */
    bool quorum_reached;    /* some class has >= QUORUM_REQUIRED signers */
    uint8_t quorum_class;   /* that class (0 when no quorum); the class
                               with the MOST distinct signers wins, ties
                               break to the lowest class byte */
    uint32_t quorum_signers;/* distinct approved signers in quorum_class */
    bool verified;          /* quorum_reached && a PASS class */
    struct vcs_verify_row rows[VCS_VERIFY_MAX_ROWS];
    size_t row_count;
    bool rows_truncated;
};

/* Evaluate the candidates for ONE package: the target package root, the
 * recipe root the release envelope commits, and the envelope's publisher
 * key (the self-verification reference). Candidates are expected verified
 * or not here — signature verification runs INSIDE so the invalid-
 * signature row is named uniformly. Deterministic: rows follow candidate
 * order; the quorum class tie-break is by class byte. */
void vcs_verify_evaluate(const struct vcs_verify_candidate *candidates,
                         size_t candidate_count,
                         const uint8_t package_root[32],
                         const uint8_t recipe_root[32],
                         const uint8_t publisher_pubkey[33],
                         const struct vcs_verifier_policy *policy,
                         struct vcs_verify_quorum *out);

#endif /* ZCL_VCS_PACKAGE_VERIFY_POLICY_H */
