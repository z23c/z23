/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: verify returned foreign proof receipts against independent pins.
 * Synthetic proof claims are signed by real isolated native signer keys.
 * This proves receipt verification/refusal, not placement, ancestry, proof
 * execution, operator authority, or permission to dispatch a queued task. */
#include "test/test_core.h"
#include "base/hex.h"
#include "dev_proof_remote.h"
#include "dev_proof_signer.h"
#include "util/safe_alloc.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if !defined(_WIN32)

#define DPR_LOCAL "1111111111111111111111111111111111111111"
#define DPR_BASE "2222222222222222222222222222222222222222"
#define DPR_OTHER "3333333333333333333333333333333333333333"

struct dpr_fixture {
    char root[4096], requester[4096], workers[3][4096];
    char *saved_xdg;
    bool had_xdg;
    struct zcl_dev_proof_remote_expectation expected;
    uint8_t keys[3][32], host[4][32];
    unsigned captures;
    bool capture_available;
};

#define DPR_CHECK(label, condition) do { \
    bool dpr_ok = (condition); \
    printf("  dev_proof_remote: %s... %s\n", (label), dpr_ok ? "OK" : "FAIL"); \
    if (!dpr_ok) failures++; \
} while (0)

/* This supplies the fixture host's independently configured identity, never
 * roots taken from a returned receipt. Native admission still decides trust
 * and compares every toolchain root; mismatch/capture-failure cases exercise it. */
static bool dpr_capture(void *ctx, uint8_t roots[4][32], char *why, size_t cap)
{
    struct dpr_fixture *f = ctx;
    f->captures++;
    if (!f->capture_available) {
        if (why && cap) (void)snprintf(why, cap, "fixture_capture_failed");
        return false;
    }
    memcpy(roots, f->host, sizeof(f->host));
    return true;
}

static struct zcl_dev_acceptance_receipt_v1 dpr_claim(const struct dpr_fixture *f)
{
    struct zcl_dev_acceptance_receipt_v1 r = {0};
    (void)zcl_dev_proof_oid_decode(DPR_LOCAL, r.local_commit, &r.local_commit_len);
    (void)zcl_dev_proof_oid_decode(DPR_BASE, r.remote_base, &r.remote_base_len);
    memcpy(r.source_root, f->expected.source_root, 32);
    memcpy(r.source_cas_root, f->expected.source_cas_root, 32);
    memcpy(r.changed_set_root, f->expected.changed_set_root, 32);
    memcpy(r.impact_policy_root, f->expected.impact_policy_root, 32);
    memset(r.mutation_root, 0x45, 32);
    memcpy(r.compiler_root, f->host[0], 32);
    memcpy(r.flags_root, f->host[1], 32);
    memcpy(r.environment_root, f->host[2], 32);
    memcpy(r.build_graph_root, f->host[3], 32);
    for (size_t i = 0; i < ZCL_DEV_PROOF_DIMENSIONS; i++) {
        memset(r.dimensions[i].receipt_root, (int)(0x61u + i), 32);
        r.dimensions[i].selected = 1;
        r.dimensions[i].ran = 1;
    }
    r.policy_version = ZCL_DEV_PROOF_POLICY_VERSION;
    r.complete = 1;
    r.created_unix = 1757030400u;
    r.elapsed_ms = 1234;
    return r;
}

static bool dpr_signed(struct dpr_fixture *f,
    struct zcl_dev_acceptance_receipt_v1 *r, unsigned worker,
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES])
{
    if (worker >= 3u || setenv("XDG_STATE_HOME", f->workers[worker], 1) != 0)
        return false;
    bool ok = zcl_dev_proof_receipt_child_set_root(r, r->child_set_root) &&
              zcl_dev_proof_receipt_seal(r) &&
              zcl_dev_proof_receipt_serialize(r, wire);
    if (setenv("XDG_STATE_HOME", f->requester, 1) != 0) ok = false;
    return ok;
}

static bool dpr_allow(struct dpr_fixture *f)
{
    char path[4096], hex[65];
    if (setenv("XDG_STATE_HOME", f->requester, 1) != 0 ||
        !zcl_dev_proof_signer_paths(NULL, 0, path, sizeof(path))) return false;
    FILE *out = fopen(path, "wb");
    if (!out) return false;
    bool ok = true;
    /* Workers A and B are BOTH trusted. C deliberately is not. */
    for (unsigned i = 0; i < 2u; i++) {
        zcl_hex_encode(f->keys[i], 32, hex);
        if (fprintf(out, "%s\n", hex) < 0) ok = false;
    }
    if (fclose(out) != 0) ok = false;
#if !defined(_WIN32)
    if (chmod(path, 0600) != 0) ok = false;
#endif
    return ok;
}

static bool dpr_setup(struct dpr_fixture *f)
{
    memset(f, 0, sizeof(*f));
    const char *prior = getenv("XDG_STATE_HOME");
    f->had_xdg = prior != NULL;
    if (prior) {
        f->saved_xdg = zcl_strdup(prior, "remote proof fixture state");
        if (!f->saved_xdg) return false;
    }
    test_make_tmpdir(f->root, sizeof(f->root), "dev_proof_remote", "receipt");
    int n = snprintf(f->requester, sizeof(f->requester), "%s/requester", f->root);
    if (n < 0 || (size_t)n >= sizeof(f->requester)) return false;
    f->expected.local_commit = DPR_LOCAL;
    f->expected.remote_base = DPR_BASE;
    /* Typed request fixture values are pinned BEFORE any returned wire.
     * They are not derived from that wire or asserted to prove a real tree. */
    memset(f->expected.source_root, 0x11, 32);
    memset(f->expected.source_cas_root, 0x22, 32);
    memset(f->expected.changed_set_root, 0x33, 32);
    memset(f->expected.impact_policy_root, 0x44, 32);
    for (unsigned i = 0; i < 4u; i++) memset(f->host[i], (int)(0x51u + i), 32);
    f->capture_available = true;
    for (unsigned i = 0; i < 3u; i++) {
        n = snprintf(f->workers[i], sizeof(f->workers[i]), "%s/worker-%u", f->root, i);
        if (n < 0 || (size_t)n >= sizeof(f->workers[i])) return false;
        struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
        uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
        if (!dpr_signed(f, &r, i, wire) ||
            setenv("XDG_STATE_HOME", f->workers[i], 1) != 0) return false;
        bool present = false;
        const char *why = NULL;
        if (!zcl_dev_proof_signer_public(f->keys[i], &present, &why) || !present)
            return false;
    }
    if (memcmp(f->keys[0], f->keys[1], 32) == 0) return false;
    memcpy(f->expected.signer_pubkey, f->keys[0], 32);
    return dpr_allow(f);
}

static bool dpr_cleanup(struct dpr_fixture *f)
{
    bool ok = f->had_xdg
        ? f->saved_xdg && setenv("XDG_STATE_HOME", f->saved_xdg, 1) == 0
        : unsetenv("XDG_STATE_HOME") == 0;
    free(f->saved_xdg);
    if (f->root[0] && test_rm_rf_recursive(f->root) != 0) ok = false;
    return ok;
}

static bool dpr_refused(struct dpr_fixture *f, const uint8_t *wire, size_t len,
    const struct zcl_dev_proof_remote_expectation *expected, const char *reason)
{
    struct zcl_dev_acceptance_receipt_v1 out;
    memset(&out, 0xa5, sizeof(out));
    unsigned char before[sizeof(out)];
    memcpy(before, &out, sizeof(out));
    char why[160] = "not set";
    bool accepted = zcl_dev_proof_remote_verify(wire, len, expected,
        dpr_capture, f, &out, why, sizeof(why));
    bool ok = !accepted && strcmp(why, reason) == 0 &&
              memcmp(before, &out, sizeof(out)) == 0;
    if (!ok) printf("    accepted=%d why=%s expected=%s output_unchanged=%d\n",
        accepted, why, reason, memcmp(before, &out, sizeof(out)) == 0);
    return ok;
}

static int dpr_positive(struct dpr_fixture *f)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f), out = {0};
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    char why[160] = "not cleared";
    bool made = dpr_signed(f, &r, 0, wire);
    unsigned before = f->captures;
    bool accepted = made && zcl_dev_proof_remote_verify(wire, sizeof(wire),
        &f->expected, dpr_capture, f, &out, why, sizeof(why));
    DPR_CHECK("trusted foreign receipt reaches native toolchain admission",
        accepted && why[0] == '\0' && f->captures == before + 1u &&
        !zcl_dev_proof_receipt_signer_is_local(&out) &&
        memcmp(out.signer_pubkey, f->expected.signer_pubkey, 32) == 0);
    /* Host-local mutation tokens and arbitrary new TTLs are NOT portable
     * return-receipt requirements. A genuinely signed old claim is reusable. */
    r.mutation_root[0] ^= 1u;
    r.created_unix = 1;
    made = dpr_signed(f, &r, 0, wire);
    DPR_CHECK("no cross-host mutation comparison or added TTL",
        made && zcl_dev_proof_remote_verify(wire, sizeof(wire), &f->expected,
            dpr_capture, f, &out, why, sizeof(why)));
    return failures;
}

static int dpr_pinned_roots(struct dpr_fixture *f)
{
    int failures = 0;
    const struct { size_t offset; const char *why; } fields[] = {
        {offsetof(struct zcl_dev_acceptance_receipt_v1, source_root), "remote_source_root_mismatch"},
        {offsetof(struct zcl_dev_acceptance_receipt_v1, source_cas_root), "remote_source_cas_root_mismatch"},
        {offsetof(struct zcl_dev_acceptance_receipt_v1, changed_set_root), "remote_changed_set_root_mismatch"},
        {offsetof(struct zcl_dev_acceptance_receipt_v1, impact_policy_root), "remote_impact_policy_root_mismatch"},
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
        ((uint8_t *)&r)[fields[i].offset] ^= 1u;
        uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
        bool made = dpr_signed(f, &r, 0, wire);
        DPR_CHECK(fields[i].why, made && dpr_refused(f, wire, sizeof(wire), &f->expected, fields[i].why));
    }
    struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
    memcpy(r.source_root, f->expected.source_cas_root, 32);
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    bool made = dpr_signed(f, &r, 0, wire);
    DPR_CHECK("CAS identity cannot substitute for Git-derived source identity",
        made && dpr_refused(f, wire, sizeof(wire), &f->expected, "remote_source_root_mismatch"));
    return failures;
}

static int dpr_pairs_and_signers(struct dpr_fixture *f)
{
    int failures = 0;
    for (unsigned which = 0; which < 2u; which++) {
        struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
        if (which == 0) (void)zcl_dev_proof_oid_decode(DPR_OTHER, r.local_commit, &r.local_commit_len);
        else (void)zcl_dev_proof_oid_decode(DPR_OTHER, r.remote_base, &r.remote_base_len);
        uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
        bool made = dpr_signed(f, &r, 0, wire);
        DPR_CHECK("correctly signed wrong candidate/base refused",
            made && dpr_refused(f, wire, sizeof(wire), &f->expected, "receipt_commit_or_base_mismatch"));
    }
    struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    bool made = dpr_signed(f, &r, 1, wire);
    char why[160];
    DPR_CHECK("other trusted signer passes native admission first",
        made && zcl_dev_proof_receipt_admit(&r, DPR_LOCAL, DPR_BASE, dpr_capture, f, why, sizeof(why)));
    DPR_CHECK("other TRUSTED signer still differs from pinned expected signer",
        made && dpr_refused(f, wire, sizeof(wire), &f->expected, "remote_signer_mismatch"));
    r = dpr_claim(f);
    made = dpr_signed(f, &r, 2, wire);
    DPR_CHECK("untrusted signer refused by real native allowlist",
        made && dpr_refused(f, wire, sizeof(wire), &f->expected, "signer_unknown"));
    return failures;
}

static int dpr_toolchains(struct dpr_fixture *f)
{
    int failures = 0;
    const struct { size_t offset; const char *name; } fields[] = {
        {offsetof(struct zcl_dev_acceptance_receipt_v1, compiler_root), "compiler_root"},
        {offsetof(struct zcl_dev_acceptance_receipt_v1, flags_root), "flags_root"},
        {offsetof(struct zcl_dev_acceptance_receipt_v1, environment_root), "environment_root"},
        {offsetof(struct zcl_dev_acceptance_receipt_v1, build_graph_root), "build_graph_root"},
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
        ((uint8_t *)&r)[fields[i].offset] ^= 1u;
        uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
        char why[160];
        snprintf(why, sizeof(why), "remote_toolchain_mismatch:%s", fields[i].name);
        bool made = dpr_signed(f, &r, 0, wire);
        DPR_CHECK(why, made && dpr_refused(f, wire, sizeof(wire), &f->expected, why));
    }
    struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    bool made = dpr_signed(f, &r, 0, wire);
    f->capture_available = false;
    bool refused = made && dpr_refused(f, wire, sizeof(wire), &f->expected,
                                      "remote_toolchain_unverifiable:fixture_capture_failed");
    f->capture_available = true;
    DPR_CHECK("unavailable native host capture fails closed", refused);
    return failures;
}

static int dpr_incomplete_and_frames(struct dpr_fixture *f)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES + 1u];
    r.complete = 0;
    bool made = dpr_signed(f, &r, 0, wire);
    DPR_CHECK("signed incomplete proof refused", made && dpr_refused(f, wire,
        ZCL_DEV_PROOF_WIRE_BYTES, &f->expected, "receipt_policy_incomplete"));
    r = dpr_claim(f);
    r.dimensions[ZCL_DEV_PROOF_TEST].selected = 2;
    made = dpr_signed(f, &r, 0, wire);
    DPR_CHECK("signed partially executed proof refused", made && dpr_refused(f, wire,
        ZCL_DEV_PROOF_WIRE_BYTES, &f->expected, "receipt_dimension_incomplete"));
    r = dpr_claim(f);
    r.policy_version--;
    made = dpr_signed(f, &r, 0, wire);
    DPR_CHECK("signed stale policy refused", made && dpr_refused(f, wire,
        ZCL_DEV_PROOF_WIRE_BYTES, &f->expected, "receipt_schema_old"));
    r = dpr_claim(f);
    made = dpr_signed(f, &r, 0, wire);
    const size_t lengths[] = {0, 1, ZCL_DEV_PROOF_WIRE_BYTES - 1u, sizeof(wire)};
    wire[ZCL_DEV_PROOF_WIRE_BYTES] = 0;
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
        DPR_CHECK("truncated or extended physical receipt refused", made && dpr_refused(
            f, wire, lengths[i], &f->expected, "remote_receipt_parse_failed"));
    wire[ZCL_DEV_PROOF_WIRE_BYTES - 1u] ^= 1u;
    DPR_CHECK("corrupted signature refused", made && dpr_refused(f, wire,
        ZCL_DEV_PROOF_WIRE_BYTES, &f->expected, "signature_invalid"));
    return failures;
}

static int dpr_missing_pins(struct dpr_fixture *f)
{
    int failures = 0;
    struct zcl_dev_acceptance_receipt_v1 r = dpr_claim(f);
    uint8_t wire[ZCL_DEV_PROOF_WIRE_BYTES];
    bool made = dpr_signed(f, &r, 0, wire);
    const size_t fields[] = {
        offsetof(struct zcl_dev_proof_remote_expectation, signer_pubkey),
        offsetof(struct zcl_dev_proof_remote_expectation, source_root),
        offsetof(struct zcl_dev_proof_remote_expectation, source_cas_root),
        offsetof(struct zcl_dev_proof_remote_expectation, changed_set_root),
        offsetof(struct zcl_dev_proof_remote_expectation, impact_policy_root),
    };
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct zcl_dev_proof_remote_expectation expected = f->expected;
        memset((uint8_t *)&expected + fields[i], 0, 32);
        DPR_CHECK("missing independent signer/root pin refuses", made &&
            dpr_refused(f, wire, sizeof(wire), &expected, "remote_arguments_invalid"));
    }
    DPR_CHECK("missing returned bytes refuses", made &&
        dpr_refused(f, NULL, sizeof(wire), &f->expected, "remote_arguments_invalid"));
    struct zcl_dev_proof_remote_expectation expected = f->expected;
    expected.remote_base = "not-an-oid";
    DPR_CHECK("invalid pinned base refuses", made &&
        dpr_refused(f, wire, sizeof(wire), &expected, "remote_arguments_invalid"));
    return failures;
}

static int dpr_cases(void)
{
    printf("\n=== dev_proof_remote: returned receipt verification only ===\n");
    int failures = 0;
    struct dpr_fixture *f = zcl_calloc(1, sizeof(*f), "remote proof fixture");
    if (!f) return 1;
    bool ready = dpr_setup(f);
    DPR_CHECK("isolated native foreign signer fixture", ready);
    if (ready) {
        failures += dpr_positive(f);
        failures += dpr_pinned_roots(f);
        failures += dpr_pairs_and_signers(f);
        failures += dpr_toolchains(f);
        failures += dpr_incomplete_and_frames(f);
        failures += dpr_missing_pins(f);
    }
    DPR_CHECK("restore environment and retire only isolated test state", dpr_cleanup(f));
    free(f);
    return failures;
}

#endif

int test_dev_proof_remote(void)
{
#if defined(_WIN32)
    /* Windows resolves a different state-root authority. Never let an XDG
     * override pretend to isolate this fixture's three development keys. */
    printf("dev_proof_remote: SKIP (Windows): foreign signer fixture requires "
           "POSIX XDG_STATE_HOME isolation\n");
    return 0;
#else
    return dpr_cases();
#endif
}
