/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_verify_policy — implementation of the approved-verifier
 * allowlist and quorum rule declared in vcs/package_verify_policy.h. Pure
 * evaluation over parsed attestations plus one bounded local-file read;
 * no network, no compiler, no execution. */

#include "vcs/package_verify_policy.h"

#include "base/hex.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <secp256k1.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POLICY_LOG "vcs.verify_policy"

/* Verify-only context for allowlist on-curve checks (the package_release.c
 * pattern: the vendored archive does not export secp256k1_context_static). */
static secp256k1_context *policy_ctx;

__attribute__((constructor))
static void policy_ctx_init(void)
{
    policy_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
}

__attribute__((destructor))
static void policy_ctx_destroy(void)
{
    if (policy_ctx)
        secp256k1_context_destroy(policy_ctx);
}

const char *vcs_verifier_policy_error_string(
    enum vcs_verifier_policy_error error)
{
    switch (error) {
    case VCS_VERIFIER_POLICY_OK: return "ok";
    case VCS_VERIFIER_POLICY_ERR_NULL: return "null-argument";
    case VCS_VERIFIER_POLICY_ERR_IO: return "policy-file-io";
    case VCS_VERIFIER_POLICY_ERR_KEY_GRAMMAR: return "key-not-66-hex";
    case VCS_VERIFIER_POLICY_ERR_KEY_OFFCURVE: return "key-off-curve";
    case VCS_VERIFIER_POLICY_ERR_DUPLICATE: return "duplicate-key";
    case VCS_VERIFIER_POLICY_ERR_TOO_MANY: return "too-many-keys";
    }
    return "unknown-error";
}

const char *vcs_verify_row_rule_string(enum vcs_verify_row_rule rule)
{
    switch (rule) {
    case VCS_VERIFY_ROW_COUNTED: return "counted";
    case VCS_VERIFY_ROW_ATTESTATION_INVALID: return "attestation-invalid";
    case VCS_VERIFY_ROW_PACKAGE_ROOT_MISMATCH:
        return "package-root-mismatch";
    case VCS_VERIFY_ROW_RECIPE_ROOT_MISMATCH:
        return "recipe-root-mismatch";
    case VCS_VERIFY_ROW_SIGNER_NOT_APPROVED: return "signer-not-approved";
    case VCS_VERIFY_ROW_SELF_VERIFICATION: return "self-verification";
    case VCS_VERIFY_ROW_DUPLICATE_SIGNER: return "duplicate-signer";
    }
    return "unknown-rule";
}

/* ── allowlist ──────────────────────────────────────────────────────── */

void vcs_verifier_policy_init(struct vcs_verifier_policy *policy)
{
    memset(policy, 0, sizeof(*policy));
}

bool vcs_verifier_policy_add(struct vcs_verifier_policy *policy,
                             const uint8_t pubkey[33],
                             enum vcs_verifier_policy_error *err_out)
{
    if (!policy || !pubkey) {
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_NULL;
        return false;
    }
    secp256k1_pubkey parsed;
    if (!secp256k1_ec_pubkey_parse(policy_ctx, &parsed, pubkey, 33)) {
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_KEY_OFFCURVE;
        return false;
    }
    if (vcs_verifier_policy_contains(policy, pubkey)) {
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_DUPLICATE;
        return false;
    }
    if (policy->count >= VCS_VERIFIER_POLICY_MAX_KEYS) {
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_TOO_MANY;
        return false;
    }
    memcpy(policy->keys[policy->count++], pubkey, 33);
    return true;
}

bool vcs_verifier_policy_contains(const struct vcs_verifier_policy *policy,
                                  const uint8_t pubkey[33])
{
    if (!policy || !pubkey)
        return false;
    for (size_t i = 0; i < policy->count; i++)
        if (memcmp(policy->keys[i], pubkey, 33) == 0)
            return true;
    return false;
}

bool vcs_verifier_policy_parse_text(struct vcs_verifier_policy *policy,
                                    const char *text, size_t text_len,
                                    enum vcs_verifier_policy_error *err_out,
                                    size_t *line_out)
{
    if (!policy || (!text && text_len > 0)) {
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_NULL;
        return false;
    }
    size_t line = 1;
    size_t i = 0;
    while (i < text_len) {
        size_t start = i;
        while (i < text_len && text[i] != '\n')
            i++;
        size_t len = i - start;
        if (len > 0 && text[start + len - 1] == '\r')
            len--;
        if (i < text_len)
            i++; /* consume the newline */
        if (len == 0 || text[start] == '#') {
            line++;
            continue;
        }
        if (len != 66) {
            if (err_out)
                *err_out = VCS_VERIFIER_POLICY_ERR_KEY_GRAMMAR;
            if (line_out)
                *line_out = line;
            return false;
        }
        uint8_t key[33];
        for (size_t b = 0; b < 33; b++) {
            int hi = zcl_hex_nibble(text[start + 2 * b], true);
            int lo = zcl_hex_nibble(text[start + 2 * b + 1], true);
            if (hi < 0 || lo < 0) {
                if (err_out)
                    *err_out = VCS_VERIFIER_POLICY_ERR_KEY_GRAMMAR;
                if (line_out)
                    *line_out = line;
                return false;
            }
            key[b] = (uint8_t)((hi << 4) | lo);
        }
        enum vcs_verifier_policy_error aerr = VCS_VERIFIER_POLICY_OK;
        if (!vcs_verifier_policy_add(policy, key, &aerr)) {
            if (err_out)
                *err_out = aerr;
            if (line_out)
                *line_out = line;
            return false;
        }
        line++;
    }
    return true;
}

bool vcs_verifier_policy_load(struct vcs_verifier_policy *policy,
                              const char *path,
                              enum vcs_verifier_policy_error *err_out)
{
    if (!policy || !path) {
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_NULL;
        return false;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_IO;
        return false;
    }
    char *text = zcl_malloc(VCS_VERIFIER_POLICY_MAX_FILE_BYTES + 1u,
                            "verifier_policy_text");
    if (!text) {
        fclose(f);
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_IO;
        LOG_FAIL(POLICY_LOG, "alloc policy text for %s", path);
    }
    size_t len = fread(text, 1, VCS_VERIFIER_POLICY_MAX_FILE_BYTES, f);
    bool bad = ferror(f) || !feof(f); /* !feof: longer than the bound */
    fclose(f);
    if (bad) {
        free(text);
        if (err_out)
            *err_out = VCS_VERIFIER_POLICY_ERR_IO;
        return false;
    }
    bool ok = vcs_verifier_policy_parse_text(policy, text, len, err_out,
                                             NULL);
    free(text);
    return ok;
}

/* ── quorum evaluation ──────────────────────────────────────────────── */

static void quorum_row(struct vcs_verify_quorum *out,
                       const struct vcs_verify_row *row)
{
    if (out->row_count < VCS_VERIFY_MAX_ROWS) {
        out->rows[out->row_count++] = *row;
    } else {
        out->rows_truncated = true;
    }
}

void vcs_verify_evaluate(const struct vcs_verify_candidate *candidates,
                         size_t candidate_count,
                         const uint8_t package_root[32],
                         const uint8_t recipe_root[32],
                         const uint8_t publisher_pubkey[33],
                         const struct vcs_verifier_policy *policy,
                         struct vcs_verify_quorum *out)
{
    memset(out, 0, sizeof(*out));
    if (!candidates || !package_root || !recipe_root ||
        !publisher_pubkey || !policy)
        return;
    out->candidates = (uint32_t)candidate_count;

    /* Per-class distinct-signer counts (index = result class byte). The
     * distinct-signer set itself is the shared signer_store below (a key
     * enters it only when COUNTED, so every entry belongs to exactly one
     * class — the per-class count cannot double-count a key). */
    size_t class_counts[6] = { 0 };
    uint8_t(*signer_store)[VCS_PACKAGE_ATTEST_PUBKEY_BYTES] = NULL;
    if (candidate_count > 0) {
        signer_store = zcl_malloc(
            candidate_count * sizeof(*signer_store), "verify_signers");
        if (!signer_store) {
            /* Cannot track distinct signers: no honest quorum is possible,
             * so evaluate nothing (out stays zeroed) rather than risk a
             * duplicate-inflated count. */
            LOG_ERROR(POLICY_LOG, "alloc %zu signer slots", candidate_count);
            return;
        }
    }
    size_t store_used = 0;

    for (size_t i = 0; i < candidate_count; i++) {
        const struct vcs_verify_candidate *cand = &candidates[i];
        struct vcs_verify_row row;
        memset(&row, 0, sizeof(row));
        if (!cand->parsed) {
            row.rule = VCS_VERIFY_ROW_ATTESTATION_INVALID;
            quorum_row(out, &row);
            continue;
        }
        const struct vcs_package_attest *a = &cand->attestation;
        memcpy(row.verifier_pubkey, a->verifier_pubkey, 33);
        row.has_pubkey = true;
        row.result_class = a->result_class;
        if (vcs_package_attest_verify(a) != VCS_PACKAGE_ATTEST_OK) {
            row.rule = VCS_VERIFY_ROW_ATTESTATION_INVALID;
            quorum_row(out, &row);
            continue;
        }
        if (memcmp(a->package_root, package_root, 32) != 0) {
            row.rule = VCS_VERIFY_ROW_PACKAGE_ROOT_MISMATCH;
            quorum_row(out, &row);
            continue;
        }
        if (memcmp(a->recipe_root, recipe_root, 32) != 0) {
            row.rule = VCS_VERIFY_ROW_RECIPE_ROOT_MISMATCH;
            quorum_row(out, &row);
            continue;
        }
        if (memcmp(a->verifier_pubkey, publisher_pubkey, 33) == 0) {
            row.rule = VCS_VERIFY_ROW_SELF_VERIFICATION;
            quorum_row(out, &row);
            continue;
        }
        if (!vcs_verifier_policy_contains(policy, a->verifier_pubkey)) {
            row.rule = VCS_VERIFY_ROW_SIGNER_NOT_APPROVED;
            quorum_row(out, &row);
            continue;
        }
        /* A signer counts at most once TOTAL: the first eligible
         * attestation stands and any later one by the same key is a named
         * duplicate (an equivocating signer cannot fill two class buckets
         * either). */
        bool seen = false;
        for (size_t s = 0; s < store_used; s++)
            if (memcmp(signer_store[s], a->verifier_pubkey, 33) == 0) {
                seen = true;
                break;
            }
        if (seen) {
            row.rule = VCS_VERIFY_ROW_DUPLICATE_SIGNER;
            quorum_row(out, &row);
            continue;
        }
        memcpy(signer_store[store_used++], a->verifier_pubkey, 33);
        class_counts[a->result_class]++;
        row.rule = VCS_VERIFY_ROW_COUNTED;
        out->counted++;
        quorum_row(out, &row);
    }

    /* The class with the most distinct signers wins; ties break low. */
    uint8_t best_class = 0;
    size_t best = 0;
    for (uint8_t cls = VCS_PACKAGE_ATTEST_RESULT_BUILD_PASS;
         cls <= VCS_PACKAGE_ATTEST_RESULT_SANITIZER_FAIL; cls++) {
        if (class_counts[cls] > best) {
            best = class_counts[cls];
            best_class = cls;
        }
    }
    out->quorum_signers = (uint32_t)best;
    out->quorum_reached = best >= VCS_VERIFY_QUORUM_REQUIRED;
    out->quorum_class = out->quorum_reached ? best_class : 0;
    out->verified = out->quorum_reached &&
                    vcs_package_attest_result_is_pass(best_class);
    free(signer_store);
}
