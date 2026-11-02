/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_dev_proof_coverage — regressions for the per-pair mandatory
 * coverage manifest (tools/dev/dev_proof_coverage.c, canonical lifecycle
 * item 2 in docs/work/FORWARD_PLAN.md).
 *
 * The push proof's test dimension executes a known set of groups; the
 * runner emits one signed verdict-leaf observation per executed group into
 * the pair's durable CAS. The coverage manifest binds those two together:
 * a producer derives and signs it, and a receiver re-verifies it against
 * the receipt's executed-group count and the same store.
 *
 * These cases drive the exact producer and receiver entry points with a
 * fixture CAS and a fixture runner log, and pin the named refusals:
 * incomplete coverage, preserved conflicts, tampered wires, wrong
 * bindings, and a corrupt CAS enumeration. */

#include "test/test_core.h"

#include "dev_proof_coverage.h"
#include "dev_proof_observation.h"
#include "dev_proof_signer.h"

#include "base/hex.h"
#include "platform/directory_compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DPC_LOCAL "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
#define DPC_BASE "cafecafecafecafecafecafecafecafecafecafecafe"
#define DPC_GROUPS 3u

static char g_dpc_state[4096];
static char g_dpc_saved_xdg[4096];
static bool g_dpc_had_xdg;

/* Each case gets a virgin box so signer trust is exercised from the key
 * the fixture itself creates (same pattern as test_dev_proof_signer). */
static void dpc_isolate(const char *tag)
{
    char base[4096 - 64];
    test_make_tmpdir(base, sizeof(base), "dev_proof_coverage", tag);
    (void)snprintf(g_dpc_state, sizeof(g_dpc_state), "%s/state", base);
    if (!g_dpc_had_xdg && getenv("XDG_STATE_HOME")) {
        g_dpc_had_xdg = true;
        (void)snprintf(g_dpc_saved_xdg, sizeof(g_dpc_saved_xdg), "%s",
                       getenv("XDG_STATE_HOME"));
    }
    setenv("XDG_STATE_HOME", g_dpc_state, 1);
}

static void dpc_restore(void)
{
    if (g_dpc_had_xdg)
        setenv("XDG_STATE_HOME", g_dpc_saved_xdg, 1);
    else
        unsetenv("XDG_STATE_HOME");
}

static bool dpc_binding(struct zcl_dev_coverage_binding *binding)
{
    memset(binding, 0, sizeof(*binding));
    if (!zcl_dev_proof_oid_decode(DPC_LOCAL, binding->local_commit,
                                  &binding->local_commit_len) ||
        !zcl_dev_proof_oid_decode(DPC_BASE, binding->remote_base,
                                  &binding->remote_base_len))
        return false;
    for (size_t i = 0; i < ZCL_DEV_PROOF_ROOT_BYTES; i++) {
        binding->child_set_root[i] = (uint8_t)(0xa0 + i);
        binding->impact_policy_root[i] = (uint8_t)(0x50 + i);
    }
    binding->policy_version = ZCL_DEV_PROOF_POLICY_VERSION;
    return true;
}

static void dpc_key(uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES], uint8_t seed)
{
    for (size_t i = 0; i < ZCL_DEV_VERDICT_LEAF_KEY_BYTES; i++)
        key[i] = (uint8_t)(seed * 31u + (uint8_t)i);
}

static bool dpc_record(const char *store, const uint8_t key[32],
                       const char *group,
                       enum zcl_dev_verdict_leaf_verdict verdict,
                       uint64_t elapsed_ms, uint8_t root[32])
{
    char why[96] = {0};
    return zcl_dev_observation_record(store, key, group, verdict, elapsed_ms,
                                      root, why, sizeof(why)) &&
           why[0] == '\0';
}

static bool dpc_log_line(FILE *f, const char *group,
                         const uint8_t key[ZCL_DEV_VERDICT_LEAF_KEY_BYTES],
                         const uint8_t root[ZCL_DEV_PROOF_ROOT_BYTES])
{
    char key_hex[65], root_hex[65];
    zcl_hex_encode(key, ZCL_DEV_VERDICT_LEAF_KEY_BYTES, key_hex);
    zcl_hex_encode(root, ZCL_DEV_PROOF_ROOT_BYTES, root_hex);
    return fprintf(f,
                   "OBSERVATION group=%s verdict=PASS key=%s root=%s "
                   "source=independent_execution\n",
                   group, key_hex, root_hex) > 0;
}

/* A store with DPC_GROUPS groups and a matching log; out-of-order log
 * lines prove the canonical blob sorts its rows. */
static bool dpc_fixture(const char *store, const char *log_path,
                        uint8_t roots[DPC_GROUPS][32])
{
    /* The observation CAS root must exist before the store init; the proof
     * worker pre-creates the per-pair directory the same way. */
    if (!platform_directory_ensure(store, 0700)) return false;
    static const char *const groups[DPC_GROUPS] = {
        "test_coverage_alpha", "test_coverage_beta", "test_coverage_gamma"};
    uint8_t keys[DPC_GROUPS][32];
    for (size_t i = 0; i < DPC_GROUPS; i++) {
        dpc_key(keys[i], (uint8_t)(i + 1));
        if (!dpc_record(store, keys[i], groups[i], ZCL_DEV_VERDICT_LEAF_PASS,
                        i + 1, roots[i]))
            return false;
    }
    FILE *f = fopen(log_path, "w");
    if (!f) return false;
    bool ok = dpc_log_line(f, groups[2], keys[2], roots[2]) &&
              dpc_log_line(f, groups[0], keys[0], roots[0]) &&
              dpc_log_line(f, groups[1], keys[1], roots[1]);
    (void)fclose(f);
    return ok;
}

static bool dpc_derive(const char *store, const char *log,
                       const struct zcl_dev_coverage_binding *binding,
                       uint32_t expected,
                       uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES],
                       uint8_t **blob, size_t *blob_len, char *why,
                       size_t why_len)
{
    return zcl_dev_coverage_manifest_derive(store, log, binding, expected,
                                            envelope, blob, blob_len,
                                            why, why_len);
}

static int test_dpc_round_trip(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "roundtrip");
    dpc_isolate("roundtrip");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: derive signs, verify admits the same pair") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        char why[128] = {0};
        ASSERT(dpc_derive(store, log_path, &binding, DPC_GROUPS, envelope,
                          &blob, &blob_len, why, sizeof(why)));
        ASSERT(why[0] == '\0');
        ASSERT(blob != NULL);
        uint32_t tail = 0;
        ASSERT(zcl_dev_coverage_envelope_blob_len(envelope, sizeof(envelope),
                                                  &tail));
        ASSERT(tail == blob_len);
        /* The on-disk shape is the envelope wire followed by the blob;
         * the hook splits the file exactly this way. */
        uint8_t *file = malloc(sizeof(envelope) + blob_len);
        ASSERT(file != NULL);
        memcpy(file, envelope, sizeof(envelope));
        memcpy(file + sizeof(envelope), blob, blob_len);
        ASSERT(zcl_dev_coverage_manifest_verify(
            store, file, sizeof(envelope), file + sizeof(envelope),
            blob_len, &binding, DPC_GROUPS, why, sizeof(why)));
        free(file);
        free(blob);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpc_zero_rows(void)
{
    int failures = 0;
    char root[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "zero");
    dpc_isolate("zero");
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: a reused test dimension binds empty coverage") {
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 99;
        char why[128] = {0};
        /* No log (NULL) and no observation store: ran == 0 is the cycle
         * reuse path; coverage over the empty mandatory set binds the
         * receipt and verifies. */
        ASSERT(dpc_derive(NULL, NULL, &binding, 0, envelope, &blob, &blob_len,
                          why, sizeof(why)));
        ASSERT(blob_len == 0);
        uint32_t tail = 1;
        ASSERT(zcl_dev_coverage_envelope_blob_len(envelope, sizeof(envelope),
                                                  &tail));
        ASSERT(tail == 0);
        ASSERT(zcl_dev_coverage_manifest_verify(NULL, envelope,
                                                sizeof(envelope), NULL, 0,
                                                &binding, 0, why,
                                                sizeof(why)));
        free(blob);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpc_named_refusals(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "refusals");
    dpc_isolate("refusals");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: count mismatch, refused observation, duplicate") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        char why[160] = {0};
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        /* The log carries one line per executed group; a different ran
         * count means the log is not this receipt's dimension. */
        ASSERT(!dpc_derive(store, log_path, &binding, DPC_GROUPS + 1,
                           envelope, &blob, &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_COUNT_MISMATCH) == 0);

        FILE *f = fopen(log_path, "a");
        ASSERT(f != NULL);
        ASSERT(fputs("OBSERVATION REFUSE group=test_coverage_alpha "
                     "reason=observation_input_closure_incomplete\n", f) >= 0);
        (void)fclose(f);
        why[0] = 0;
        ASSERT(!dpc_derive(store, log_path, &binding, DPC_GROUPS + 1,
                           envelope, &blob, &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_OBSERVATION_REFUSED) == 0);
        /* Rewrite the log with a duplicated group line. */
        uint8_t keys[32];
        dpc_key(keys, 1);
        f = fopen(log_path, "w");
        ASSERT(f != NULL);
        ASSERT(dpc_log_line(f, "test_coverage_alpha", keys, emitted[0]));
        ASSERT(dpc_log_line(f, "test_coverage_alpha", keys, emitted[0]));
        (void)fclose(f);
        why[0] = 0;
        ASSERT(!dpc_derive(store, log_path, &binding, 2, envelope, &blob,
                           &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_LOG_DUPLICATE) == 0);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpc_missing_conflict_and_emitted(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "missing");
    dpc_isolate("missing");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: missing group, preserved conflict, un-emitted root") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        char why[160] = {0};
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;

        /* A mandatory group with no eligible observation in the CAS. */
        FILE *f = fopen(log_path, "w");
        ASSERT(f != NULL);
        uint8_t ghost_key[32], ghost_root[32];
        dpc_key(ghost_key, 9);
        memset(ghost_root, 0x5a, sizeof(ghost_root));
        ASSERT(dpc_log_line(f, "test_coverage_ghost", ghost_key, ghost_root));
        (void)fclose(f);
        ASSERT(!dpc_derive(store, log_path, &binding, 1, envelope, &blob,
                           &blob_len, why, sizeof(why)));
        ASSERT(strncmp(why, ZCL_DEV_COVERAGE_WHY_MISSING,
                       strlen(ZCL_DEV_COVERAGE_WHY_MISSING)) == 0);
        ASSERT(strstr(why, "test_coverage_ghost") != NULL);

        /* A preserved eligible contradiction refuses even when the log
         * row points at the PASS root. */
        uint8_t alpha_key[32];
        dpc_key(alpha_key, 1);
        uint8_t fail_root[32];
        ASSERT(dpc_record(store, alpha_key, "test_coverage_alpha",
                          ZCL_DEV_VERDICT_LEAF_FAIL, 77, fail_root));
        f = fopen(log_path, "w");
        ASSERT(f != NULL);
        ASSERT(dpc_log_line(f, "test_coverage_alpha", alpha_key, emitted[0]));
        (void)fclose(f);
        why[0] = 0;
        ASSERT(!dpc_derive(store, log_path, &binding, 1, envelope, &blob,
                           &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_CONFLICT
                           ":test_coverage_alpha") == 0);

        /* The runner logged a root the store does not hold eligible: the
         * group and key match the store, the emitted root does not. */
        uint8_t not_emitted[32];
        memcpy(not_emitted, emitted[0], sizeof(not_emitted));
        not_emitted[31] ^= 0xff;
        uint8_t beta_key[32];
        dpc_key(beta_key, 2);
        f = fopen(log_path, "w");
        ASSERT(f != NULL);
        ASSERT(dpc_log_line(f, "test_coverage_beta", beta_key, not_emitted));
        (void)fclose(f);
        why[0] = 0;
        ASSERT(!dpc_derive(store, log_path, &binding, 1, envelope, &blob,
                           &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_EMITTED_MISSING) == 0);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpc_verify_refusals(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "verify");
    dpc_isolate("verify");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: tampered blob, wrong binding, bad signature") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        char why[160] = {0};
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        ASSERT(dpc_derive(store, log_path, &binding, DPC_GROUPS, envelope,
                          &blob, &blob_len, why, sizeof(why)));

        blob[0] ^= 0x01;
        ASSERT(!zcl_dev_coverage_manifest_verify(store, envelope,
                                                 sizeof(envelope), blob,
                                                 blob_len, &binding, DPC_GROUPS,
                                                 why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_BLOB_INVALID) == 0);
        blob[0] ^= 0x01;

        struct zcl_dev_coverage_binding other = binding;
        other.child_set_root[0] ^= 0xff;
        why[0] = 0;
        ASSERT(!zcl_dev_coverage_manifest_verify(store, envelope,
                                                 sizeof(envelope), blob,
                                                 blob_len, &other, DPC_GROUPS,
                                                 why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_BINDING) == 0);
        other = binding;
        other.policy_version += 1;
        why[0] = 0;
        ASSERT(!zcl_dev_coverage_manifest_verify(store, envelope,
                                                 sizeof(envelope), blob,
                                                 blob_len, &other, DPC_GROUPS,
                                                 why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_BINDING) == 0);

        envelope[ZCL_DEV_COVERAGE_WIRE_BYTES - 1] ^= 0xff;
        why[0] = 0;
        ASSERT(!zcl_dev_coverage_manifest_verify(store, envelope,
                                                 sizeof(envelope), blob,
                                                 blob_len, &binding, DPC_GROUPS,
                                                 why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_PROOF_SIGNER_WHY_SIGNATURE_INVALID) == 0);
        free(blob);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpc_store_corruption(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096], junk_dir[4096],
        junk_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "corrupt");
    dpc_isolate("corrupt");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: a corrupt CAS object refuses the projection") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        /* One object in the store that is not a well-formed addressed
         * leaf: the enumeration cannot establish completeness. */
        ASSERT(snprintf(junk_dir, sizeof(junk_dir),
                        "%s/.zvcs/objects/ab", store) > 0);
        ASSERT(platform_directory_ensure(junk_dir, 0700));
        ASSERT(snprintf(junk_path, sizeof(junk_path),
                        "%s/cdef", junk_dir) > 0);
        FILE *f = fopen(junk_path, "w");
        ASSERT(f != NULL);
        ASSERT(fputs("not a leaf", f) >= 0);
        (void)fclose(f);

        char why[160] = {0};
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        ASSERT(!dpc_derive(store, log_path, &binding, DPC_GROUPS, envelope,
                           &blob, &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_STORE_INCOMPLETE) == 0);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpc_rerun_reuse(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "reuse");
    dpc_isolate("reuse");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: two eligible PASS roots cover one group") {
        /* A retried group reruns and re-emits: both PASS roots are
         * eligible, neither contradicts, the row binds them sorted. */
        uint8_t key[32], first[32], second[32];
        dpc_key(key, 7);
        ASSERT(platform_directory_ensure(store, 0700));
        ASSERT(dpc_record(store, key, "test_coverage_retry",
                          ZCL_DEV_VERDICT_LEAF_PASS, 1, first));
        ASSERT(dpc_record(store, key, "test_coverage_retry",
                          ZCL_DEV_VERDICT_LEAF_PASS, 2, second));
        ASSERT(memcmp(first, second, 32) != 0);
        FILE *f = fopen(log_path, "w");
        ASSERT(f != NULL);
        ASSERT(dpc_log_line(f, "test_coverage_retry", key, second));
        (void)fclose(f);

        char why[160] = {0};
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        ASSERT(dpc_derive(store, log_path, &binding, 1, envelope, &blob,
                          &blob_len, why, sizeof(why)));
        ASSERT(zcl_dev_coverage_manifest_verify(store, envelope,
                                                sizeof(envelope), blob,
                                                blob_len, &binding, 1, why,
                                                sizeof(why)));
        free(blob);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

/* The test-dimension log is not a clean list of observation lines: it also
 * carries every group's own output and make's multi-kilobyte echoes. Real
 * proof logs on a landing host hold lines of 2.5 KiB and more. */
static int test_dpc_real_log_shape(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "logshape");
    dpc_isolate("logshape");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: long and look-alike foreign lines are not rows") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        FILE *f = fopen(log_path, "a");
        ASSERT(f != NULL);
        /* An over-long foreign line whose tail, read as a continuation
         * chunk, begins exactly like a canonical refusal. */
        for (size_t i = 0; i < 1023; i++) ASSERT(fputc('x', f) != EOF);
        ASSERT(fputs("OBSERVATION REFUSE group=test_coverage_alpha "
                     "reason=not_a_line_start\n", f) >= 0);
        for (size_t i = 0; i < 6000; i++) ASSERT(fputc('y', f) != EOF);
        ASSERT(fputc('\n', f) != EOF);
        /* Group output that merely mentions the words mid-line. */
        ASSERT(fputs("  note: OBSERVATION REFUSE group=test_coverage_beta "
                     "reason=quoted_by_a_test\n", f) >= 0);
        ASSERT(fputs("  note: OBSERVATION group=test_coverage_ghost "
                     "verdict=PASS\n", f) >= 0);
        /* The runner's own summary line is not a group row. */
        ASSERT(fputs("OBSERVATION COVERAGE mode=partial eligible=3 emitted=3 "
                     "unqualified=0 refused=0 complete=1\n", f) >= 0);
        /* A final unterminated foreign line. */
        ASSERT(fputs("trailing output without a newline", f) >= 0);
        (void)fclose(f);

        char why[160] = {0};
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        ASSERT(dpc_derive(store, log_path, &binding, DPC_GROUPS, envelope,
                          &blob, &blob_len, why, sizeof(why)));
        ASSERT(zcl_dev_coverage_manifest_verify(store, envelope,
                                                sizeof(envelope), blob,
                                                blob_len, &binding,
                                                DPC_GROUPS, why,
                                                sizeof(why)));
        free(blob);
        blob = NULL;

        /* A canonical line that is itself cut short is still refused. */
        f = fopen(log_path, "a");
        ASSERT(f != NULL);
        ASSERT(fputs("\nOBSERVATION group=test_coverage_cut verdict=PASS", f)
               >= 0);
        (void)fclose(f);
        why[0] = 0;
        ASSERT(!dpc_derive(store, log_path, &binding, DPC_GROUPS, envelope,
                           &blob, &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_LOG_INVALID) == 0);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpc_nul_record(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "nul");
    dpc_isolate("nul");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    TEST_CASE("dev_proof_coverage: NUL cannot hide the next refusal") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        FILE *f = fopen(log_path, "ab");
        ASSERT(f != NULL);
        static const char tail[] = "x\0\nOBSERVATION REFUSE "
            "group=test_coverage_alpha reason=bad\n";
        ASSERT(fwrite(tail, 1, sizeof(tail) - 1, f) == sizeof(tail) - 1);
        ASSERT(fclose(f) == 0);
        struct zcl_dev_coverage_log_row rows[DPC_GROUPS];
        uint32_t count = 0;
        char why[160] = {0};
        ASSERT(!zcl_dev_coverage_log_rows(log_path, DPC_GROUPS, rows,
                                          DPC_GROUPS, &count, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_LOG_INVALID) == 0);
        f = fopen(log_path, "wb");
        ASSERT(f != NULL);
        ASSERT(fputs("OBSERVATION UNQUALIFIED group=test_coverage_alpha "
                     "reason=external_input_denylist coverage=missing", f) >= 0);
        ASSERT(fclose(f) == 0);
        ASSERT(zcl_dev_coverage_log_rows(log_path, 1, rows, DPC_GROUPS,
                                         &count, why, sizeof(why)));
        ASSERT(count == 1 && rows[0].unqualified);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static bool dpc_unqualified_line(FILE *f, const char *group,
                                 const char *coverage)
{
    return fprintf(f, "OBSERVATION UNQUALIFIED group=%s "
                      "reason=external_input_denylist coverage=%s\n",
                   group, coverage) > 0;
}

/* A group with no exact input key (the external-input denylist) executes
 * and passes without minting a reusable leaf.
 * It is part of the executed set, by name, and never credited with roots. */
static int test_dpc_unqualified_rows(void)
{
    int failures = 0;
    char root[4096], store[4096], empty_store[4096], log_path[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "unqualified");
    dpc_isolate("unqualified");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(empty_store, sizeof(empty_store), "%s/empty", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: unqualified groups count as executed, carry no roots") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        FILE *f = fopen(log_path, "a");
        ASSERT(f != NULL);
        ASSERT(dpc_unqualified_line(f, "test_coverage_external", "missing"));
        (void)fclose(f);

        char why[160] = {0};
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        /* The unqualified group is one of the executed groups: the keyed rows
         * alone do not add up to the receipt's ran count. */
        ASSERT(!dpc_derive(store, log_path, &binding, DPC_GROUPS, envelope,
                           &blob, &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_COUNT_MISMATCH) == 0);
        why[0] = 0;
        ASSERT(dpc_derive(store, log_path, &binding, DPC_GROUPS + 1, envelope,
                          &blob, &blob_len, why, sizeof(why)));
        ASSERT(zcl_dev_coverage_manifest_verify(store, envelope,
                                                sizeof(envelope), blob,
                                                blob_len, &binding,
                                                DPC_GROUPS + 1, why,
                                                sizeof(why)));
        /* The receipt's executed count is part of what is verified: this
         * manifest is not the coverage of a receipt that ran another
         * number of groups. */
        ASSERT(!zcl_dev_coverage_manifest_verify(store, envelope,
                                                 sizeof(envelope), blob,
                                                 blob_len, &binding,
                                                 DPC_GROUPS, why,
                                                 sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_COUNT_MISMATCH) == 0);

        /* A FAIL retained for the unqualified group -- an earlier attempt of
         * this pair -- contradicts the claim, on both sides. */
        uint8_t stale_key[32], fail_root[32];
        dpc_key(stale_key, 11);
        ASSERT(dpc_record(store, stale_key, "test_coverage_external",
                          ZCL_DEV_VERDICT_LEAF_FAIL, 5, fail_root));
        why[0] = 0;
        ASSERT(!zcl_dev_coverage_manifest_verify(store, envelope,
                                                 sizeof(envelope), blob,
                                                 blob_len, &binding,
                                                 DPC_GROUPS + 1, why,
                                                 sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_CONFLICT
                           ":test_coverage_external") == 0);
        free(blob);
        blob = NULL;
        why[0] = 0;
        ASSERT(!dpc_derive(store, log_path, &binding, DPC_GROUPS + 1,
                           envelope, &blob, &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_CONFLICT
                           ":test_coverage_external") == 0);

        /* A proof whose every executed group is unqualified never created an
         * object tree: the store is complete and empty, not incomplete. */
        ASSERT(platform_directory_ensure(empty_store, 0700));
        f = fopen(log_path, "w");
        ASSERT(f != NULL);
        ASSERT(dpc_unqualified_line(f, "test_coverage_external", "missing"));
        ASSERT(dpc_unqualified_line(f, "test_coverage_another", "missing"));
        (void)fclose(f);
        why[0] = 0;
        ASSERT(dpc_derive(empty_store, log_path, &binding, 2, envelope, &blob,
                          &blob_len, why, sizeof(why)));
        ASSERT(zcl_dev_coverage_manifest_verify(empty_store, envelope,
                                                sizeof(envelope), blob,
                                                blob_len, &binding, 2, why,
                                                sizeof(why)));
        /* An empty manifest cannot stand in for it. */
        uint8_t none[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *none_blob = NULL;
        size_t none_len = 0;
        ASSERT(dpc_derive(NULL, NULL, &binding, 0, none, &none_blob,
                          &none_len, why, sizeof(why)));
        ASSERT(!zcl_dev_coverage_manifest_verify(empty_store, none,
                                                 sizeof(none), NULL, 0,
                                                 &binding, 2, why,
                                                 sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_COUNT_MISMATCH) == 0);
        free(none_blob);
        free(blob);
        blob = NULL;

        /* An unqualified line of any other shape is not this runner's. */
        f = fopen(log_path, "w");
        ASSERT(f != NULL);
        ASSERT(dpc_unqualified_line(f, "test_coverage_external", "present"));
        (void)fclose(f);
        why[0] = 0;
        ASSERT(!dpc_derive(empty_store, log_path, &binding, 1, envelope,
                           &blob, &blob_len, why, sizeof(why)));
        ASSERT(strcmp(why, ZCL_DEV_COVERAGE_WHY_LOG_INVALID) == 0);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

static int test_dpc_inspect(void)
{
    int failures = 0;
    char root[4096], store[4096], log_path[4096], empty_store[4096];
    test_make_tmpdir(root, sizeof(root), "dev_proof_coverage", "inspect");
    dpc_isolate("inspect");
    (void)snprintf(store, sizeof(store), "%s/store", root);
    (void)snprintf(empty_store, sizeof(empty_store), "%s/empty", root);
    (void)snprintf(log_path, sizeof(log_path), "%s/test.log", root);
    uint8_t emitted[DPC_GROUPS][32];
    struct zcl_dev_coverage_binding binding;
    (void)dpc_binding(&binding); /* fixed valid fixture OIDs; cannot fail */
    TEST_CASE("dev_proof_coverage: inspect reports coverage, binding and age") {
        ASSERT(dpc_fixture(store, log_path, emitted));
        char why[160] = {0};
        uint8_t envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        ASSERT(dpc_derive(store, log_path, &binding, DPC_GROUPS, envelope,
                          &blob, &blob_len, why, sizeof(why)));

        struct zcl_dev_coverage_inspect report = {0};
        ASSERT(zcl_dev_coverage_inspect(store, envelope, sizeof(envelope),
                                        blob, blob_len, &binding, &report,
                                        why, sizeof(why)));
        ASSERT(report.row_count == DPC_GROUPS);
        ASSERT(report.covered == DPC_GROUPS);
        ASSERT(report.unqualified == 0);
        ASSERT(report.missing == 0 && report.conflicts == 0);
        ASSERT(!report.binding_mismatch);
        ASSERT(report.signer_why[0] == '\0');
        ASSERT(report.observed_total == DPC_GROUPS);
        ASSERT(report.observed_eligible == DPC_GROUPS);
        ASSERT(report.oldest_observed_unix != 0);
        ASSERT(report.newest_observed_unix >= report.oldest_observed_unix);

        /* A wrong binding is reported, not fatal: the rows still
         * classify against what the box actually observed. */
        struct zcl_dev_coverage_binding other = binding;
        other.child_set_root[0] ^= 0xff;
        memset(&report, 0, sizeof(report));
        ASSERT(zcl_dev_coverage_inspect(store, envelope, sizeof(envelope),
                                        blob, blob_len, &other, &report,
                                        why, sizeof(why)));
        ASSERT(report.binding_mismatch);
        ASSERT(report.covered == DPC_GROUPS);

        /* A bad signature names its signer refusal and still reports. */
        envelope[ZCL_DEV_COVERAGE_WIRE_BYTES - 1] ^= 0xff;
        memset(&report, 0, sizeof(report));
        ASSERT(zcl_dev_coverage_inspect(store, envelope, sizeof(envelope),
                                        blob, blob_len, &binding, &report,
                                        why, sizeof(why)));
        ASSERT(strcmp(report.signer_why,
                      ZCL_DEV_PROOF_SIGNER_WHY_SIGNATURE_INVALID) == 0);
        envelope[ZCL_DEV_COVERAGE_WIRE_BYTES - 1] ^= 0xff;

        /* A preserved contradiction lands in the conflicts count. */
        uint8_t alpha_key[32], fail_root[32];
        dpc_key(alpha_key, 1);
        ASSERT(dpc_record(store, alpha_key, "test_coverage_alpha",
                          ZCL_DEV_VERDICT_LEAF_FAIL, 99, fail_root));
        memset(&report, 0, sizeof(report));
        ASSERT(zcl_dev_coverage_inspect(store, envelope, sizeof(envelope),
                                        blob, blob_len, &binding, &report,
                                        why, sizeof(why)));
        ASSERT(report.conflicts == 1);
        ASSERT(report.covered == DPC_GROUPS - 1);

        /* The same manifest against a store that never saw the groups
         * answers "incomplete" with the missing group names. */
        ASSERT(platform_directory_ensure(empty_store, 0700));
        memset(&report, 0, sizeof(report));
        ASSERT(zcl_dev_coverage_inspect(empty_store, envelope,
                                        sizeof(envelope), blob, blob_len,
                                        &binding, &report, why,
                                        sizeof(why)));
        ASSERT(report.row_count == DPC_GROUPS);
        ASSERT(report.missing == DPC_GROUPS && report.covered == 0);
        ASSERT(report.missing_named == DPC_GROUPS);
        ASSERT(report.observed_total == 0);
        free(blob);

        /* One keyed PASS row and one denylisted group that executed
         * without a reusable observation: unqualified, never missing. */
        ASSERT(platform_directory_ensure(store, 0700));
        uint8_t uq_key[32], uq_pass_root[32];
        dpc_key(uq_key, 1);
        ASSERT(dpc_record(store, uq_key, "test_coverage_keyed",
                          ZCL_DEV_VERDICT_LEAF_PASS, 1, uq_pass_root));
        FILE *uq_f = fopen(log_path, "w");
        ASSERT(uq_f != NULL);
        ASSERT(dpc_log_line(uq_f, "test_coverage_keyed", uq_key, uq_pass_root));
        ASSERT(dpc_unqualified_line(uq_f, "test_coverage_external", "missing"));
        (void)fclose(uq_f);

        char uq_why[160] = {0};
        uint8_t uq_envelope[ZCL_DEV_COVERAGE_WIRE_BYTES];
        uint8_t *uq_blob = NULL;
        size_t uq_blob_len = 0;
        ASSERT(dpc_derive(store, log_path, &binding, 2, uq_envelope,
                          &uq_blob, &uq_blob_len, uq_why, sizeof(uq_why)));
        struct zcl_dev_coverage_inspect uq_report = {0};
        ASSERT(zcl_dev_coverage_inspect(store, uq_envelope,
                                        sizeof(uq_envelope), uq_blob,
                                        uq_blob_len, &binding, &uq_report,
                                        uq_why, sizeof(uq_why)));
        ASSERT(uq_report.row_count == 2);
        ASSERT(uq_report.covered == 1 && uq_report.unqualified == 1);
        ASSERT(uq_report.missing == 0 && uq_report.conflicts == 0);

        /* A retained eligible FAIL for the unqualified group is the
         * preserved contradiction verify() refuses: a conflict answer. */
        uint8_t ext_key[32], ext_fail[32];
        dpc_key(ext_key, 2);
        ASSERT(dpc_record(store, ext_key, "test_coverage_external",
                          ZCL_DEV_VERDICT_LEAF_FAIL, 2, ext_fail));
        memset(&uq_report, 0, sizeof(uq_report));
        ASSERT(zcl_dev_coverage_inspect(store, uq_envelope,
                                        sizeof(uq_envelope), uq_blob,
                                        uq_blob_len, &binding, &uq_report,
                                        uq_why, sizeof(uq_why)));
        ASSERT(uq_report.conflicts == 1);
        ASSERT(uq_report.unqualified == 0);
        ASSERT(uq_report.covered == 1);
        free(uq_blob);
    }
    TEST_END
    dpc_restore();
    (void)test_rm_rf_recursive(root);
    return failures;
}

int test_dev_proof_coverage(void)
{
    int failures = 0;
    failures += test_dpc_inspect();
    failures += test_dpc_real_log_shape();
    failures += test_dpc_nul_record();
    failures += test_dpc_unqualified_rows();
    failures += test_dpc_round_trip();
    failures += test_dpc_zero_rows();
    failures += test_dpc_named_refusals();
    failures += test_dpc_missing_conflict_and_emitted();
    failures += test_dpc_verify_refusals();
    failures += test_dpc_store_corruption();
    failures += test_dpc_rerun_reuse();
    return failures;
}
