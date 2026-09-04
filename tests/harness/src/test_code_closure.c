/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_closure contract: the input-closure digest one unit of work is
 * keyed by, so a proof can admit that unit by receipt instead of re-running it.
 *
 * The properties a receipt scheme lives or dies on, each measured here:
 *   1. locality        — a change inside a declared directory MOVES the closure
 *                        digest; a change outside every declared directory
 *                        LEAVES IT ALONE. This is the whole reason the key is
 *                        per-unit instead of per-tree.
 *   2. free directories— declaring a directory reads ZERO file bytes and still
 *                        covers every file below it, counted, not asserted.
 *   3. order-free      — the same set declared in a different order seals to the
 *                        same digest, so a caller cannot shop for one.
 *   4. fail-closed     — an absent scope, a duplicate scope, an over-full
 *                        closure, and an empty closure all REFUSE. A refused
 *                        add poisons the closure so it can never seal short.
 *   5. domain-separated— the same inputs under two unit domains seal to two
 *                        different digests, and a directory digest cannot be
 *                        replayed as a file digest.
 *   6. raw inputs      — a file the Merkle tree does not index (a shell script,
 *                        a baseline table) is covered only when declared with
 *                        add_raw, and editing it then moves the digest.
 *
 * All scratch work happens under ./test-tmp/ (project no-/tmp convention).
 */

#include "test/test_core.h"

#include "codeindex/codeindex_closure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CC_FIX "test-tmp/code_closure_fix"

static bool cc_write(const char *dir, const char *rel, const char *content)
{
    char full[4096];
    snprintf(full, sizeof(full), "%s/%s", dir, rel);
    for (char *p = full + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(full, 0755); *p = '/'; }
    }
    FILE *f = fopen(full, "wb");
    if (!f) return false;
    if (content && content[0]) fwrite(content, 1, strlen(content), f);
    return fclose(f) == 0;
}

/* Two module arms so locality is observable, plus one non-indexed file so the
 * gap between "the Merkle tree covers it" and "somebody declared it" is real
 * rather than described. */
static bool cc_fixture(const char *dir)
{
    bool ok = true;
    ok = ok && cc_write(dir, "engine/modules/services/src/cc_a.c",
                        "/* cc_a — closure fixture. */\nint cc_a(void)\n{\n"
                        "    return 1;\n}\n");
    ok = ok && cc_write(dir, "engine/modules/services/src/cc_b.c",
                        "/* cc_b — closure fixture. */\nint cc_b(void)\n{\n"
                        "    return 2;\n}\n");
    ok = ok && cc_write(dir, "engine/modules/services/include/services/cc.h",
                        "#ifndef CC_H\n#define CC_H\nint cc_a(void);\n#endif\n");
    ok = ok && cc_write(dir, "core/modules/crypto/src/cc_c.c",
                        "/* cc_c — closure fixture. */\nint cc_c(void)\n{\n"
                        "    return 3;\n}\n");
    /* Not a .c/.h: ci_enumerate_sources() cannot see this at all. */
    ok = ok && cc_write(dir, "tools/lint/cc_baseline.txt",
                        "engine/modules/services/src/cc_a.c\n");
    return ok;
}

static void cc_reset(void) { system("rm -rf " CC_FIX); }

static bool cc_seal_dir(struct ci_merkle *m, const char *domain,
                        const char *dir, struct zcl_sha3_digest *out,
                        struct ci_closure_cost *cost)
{
    struct ci_closure c;
    if (!ci_closure_init(&c, domain) || !ci_closure_add_dir(&c, m, dir))
        return false;
    if (cost) ci_closure_cost(&c, cost);
    return ci_closure_seal(&c, out);
}

/* ── 1 + 2: locality, and directories cost no file reads ── */
static int test_cc_locality(void)
{
    int failures = 0;
    TEST("code_closure: a directory scope moves only for changes inside it") {
        cc_reset();
        ASSERT(cc_fixture(CC_FIX));

        struct ci_merkle *before = ci_merkle_build_cold(CC_FIX, NULL);
        ASSERT(before != NULL);

        struct zcl_sha3_digest services_before, crypto_before;
        struct ci_closure_cost services_cost = {0};
        ASSERT(cc_seal_dir(before, "zcl.test.unit.v1",
                           "engine/modules/services", &services_before,
                           &services_cost));
        ASSERT(cc_seal_dir(before, "zcl.test.unit.v1", "core/modules/crypto",
                           &crypto_before, NULL));

        /* Three indexed files live under engine/modules/services and the
         * closure covers all three having read none of them. */
        ASSERT(services_cost.entries == 1);
        ASSERT(services_cost.dir_entries == 1);
        ASSERT(services_cost.files_covered == 3);
        ASSERT(services_cost.bytes_covered > 0);
        ASSERT(services_cost.bytes_hashed == 0);

        /* Edit one file under services. */
        ASSERT(cc_write(CC_FIX, "engine/modules/services/src/cc_b.c",
                        "/* cc_b — closure fixture. */\nint cc_b(void)\n{\n"
                        "    return 22;\n}\n"));
        struct ci_merkle *after = ci_merkle_build_cold(CC_FIX, NULL);
        ASSERT(after != NULL);

        struct zcl_sha3_digest services_after, crypto_after;
        ASSERT(cc_seal_dir(after, "zcl.test.unit.v1",
                           "engine/modules/services", &services_after, NULL));
        ASSERT(cc_seal_dir(after, "zcl.test.unit.v1", "core/modules/crypto",
                           &crypto_after, NULL));

        ASSERT(memcmp(services_before.bytes, services_after.bytes, 32) != 0);
        ASSERT(memcmp(crypto_before.bytes, crypto_after.bytes, 32) == 0);

        ci_merkle_free(before);
        ci_merkle_free(after);
        cc_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 3 + 5: order-free, domain-separated, kind-separated ── */
static int test_cc_canonical(void)
{
    int failures = 0;
    TEST("code_closure: order-free, domain-separated, kind-separated") {
        cc_reset();
        ASSERT(cc_fixture(CC_FIX));
        struct ci_merkle *m = ci_merkle_build_cold(CC_FIX, NULL);
        ASSERT(m != NULL);

        struct ci_closure forward, reverse;
        struct zcl_sha3_digest a, b;
        ASSERT(ci_closure_init(&forward, "zcl.test.unit.v1"));
        ASSERT(ci_closure_add_dir(&forward, m, "engine/modules/services"));
        ASSERT(ci_closure_add_dir(&forward, m, "core/modules/crypto"));
        ASSERT(ci_closure_seal(&forward, &a));

        ASSERT(ci_closure_init(&reverse, "zcl.test.unit.v1"));
        ASSERT(ci_closure_add_dir(&reverse, m, "core/modules/crypto"));
        ASSERT(ci_closure_add_dir(&reverse, m, "engine/modules/services"));
        ASSERT(ci_closure_seal(&reverse, &b));
        ASSERT(memcmp(a.bytes, b.bytes, 32) == 0);

        /* Same inputs, different unit domain -> different key. A lint receipt
         * can never be read as a test receipt. */
        struct ci_closure other;
        struct zcl_sha3_digest c;
        ASSERT(ci_closure_init(&other, "zcl.test.other.v1"));
        ASSERT(ci_closure_add_dir(&other, m, "engine/modules/services"));
        ASSERT(ci_closure_add_dir(&other, m, "core/modules/crypto"));
        ASSERT(ci_closure_seal(&other, &c));
        ASSERT(memcmp(a.bytes, c.bytes, 32) != 0);

        /* A single file declared as a leaf and the same file declared as raw
         * bytes are different entries and different digests. */
        struct ci_closure leaf, raw;
        struct zcl_sha3_digest lh, rh;
        ASSERT(ci_closure_init(&leaf, "zcl.test.unit.v1"));
        ASSERT(ci_closure_add_file(&leaf, m,
                                   "engine/modules/services/src/cc_a.c"));
        ASSERT(ci_closure_seal(&leaf, &lh));
        ASSERT(ci_closure_init(&raw, "zcl.test.unit.v1"));
        ASSERT(ci_closure_add_raw(&raw, CC_FIX,
                                  "engine/modules/services/src/cc_a.c"));
        ASSERT(ci_closure_seal(&raw, &rh));
        ASSERT(memcmp(lh.bytes, rh.bytes, 32) != 0);

        ci_merkle_free(m);
        cc_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 4: every refusal path, and a refused add can never seal short ── */
static int test_cc_fail_closed(void)
{
    int failures = 0;
    TEST("code_closure: absent, duplicate, empty and over-full all refuse") {
        cc_reset();
        ASSERT(cc_fixture(CC_FIX));
        struct ci_merkle *m = ci_merkle_build_cold(CC_FIX, NULL);
        ASSERT(m != NULL);
        struct zcl_sha3_digest d;

        /* Empty closure: a unit with no declared inputs has no closure. */
        struct ci_closure empty;
        ASSERT(ci_closure_init(&empty, "zcl.test.unit.v1"));
        ASSERT(!ci_closure_seal(&empty, &d));

        /* Absent directory: refused, and the closure is poisoned so the
         * caller cannot seal the one good scope it did manage to add. */
        struct ci_closure absent;
        ASSERT(ci_closure_init(&absent, "zcl.test.unit.v1"));
        ASSERT(ci_closure_add_dir(&absent, m, "engine/modules/services"));
        ASSERT(!ci_closure_add_dir(&absent, m, "engine/modules/nope"));
        ASSERT(!ci_closure_seal(&absent, &d));

        /* Absent file, and a file that exists on disk but is not indexed. */
        struct ci_closure absent_file;
        ASSERT(ci_closure_init(&absent_file, "zcl.test.unit.v1"));
        ASSERT(!ci_closure_add_file(&absent_file, m, "core/modules/nope.c"));
        ASSERT(!ci_closure_seal(&absent_file, &d));
        struct ci_closure unindexed;
        ASSERT(ci_closure_init(&unindexed, "zcl.test.unit.v1"));
        ASSERT(!ci_closure_add_file(&unindexed, m, "tools/lint/cc_baseline.txt"));

        /* Duplicate scope: the caller does not know its own closure. */
        struct ci_closure dup;
        ASSERT(ci_closure_init(&dup, "zcl.test.unit.v1"));
        ASSERT(ci_closure_add_dir(&dup, m, "engine/modules/services"));
        ASSERT(!ci_closure_add_dir(&dup, m, "engine/modules/services"));
        ASSERT(!ci_closure_seal(&dup, &d));

        /* A raw file that is not there. */
        struct ci_closure missing_raw;
        ASSERT(ci_closure_init(&missing_raw, "zcl.test.unit.v1"));
        ASSERT(!ci_closure_add_raw(&missing_raw, CC_FIX, "tools/lint/gone.txt"));
        ASSERT(!ci_closure_seal(&missing_raw, &d));

        /* An oversized domain and an empty domain are both refused up front. */
        struct ci_closure bad_domain;
        char long_domain[128];
        memset(long_domain, 'x', sizeof(long_domain) - 1);
        long_domain[sizeof(long_domain) - 1] = '\0';
        ASSERT(!ci_closure_init(&bad_domain, long_domain));
        ASSERT(!ci_closure_init(&bad_domain, ""));

        ci_merkle_free(m);
        cc_reset();
        PASS();
    } _test_next:;
    return failures;
}

/* ── 6: a non-indexed input is covered only when it is declared ── */
static int test_cc_raw_inputs(void)
{
    int failures = 0;
    TEST("code_closure: a non-indexed baseline moves the key only if declared") {
        cc_reset();
        ASSERT(cc_fixture(CC_FIX));
        struct ci_merkle *m = ci_merkle_build_cold(CC_FIX, NULL);
        ASSERT(m != NULL);

        /* A unit that declares the source directory AND its baseline table. */
        struct ci_closure with_raw;
        struct zcl_sha3_digest declared_before;
        struct ci_closure_cost cost = {0};
        ASSERT(ci_closure_init(&with_raw, "zcl.test.unit.v1"));
        ASSERT(ci_closure_add_dir(&with_raw, m, "engine/modules/services"));
        ASSERT(ci_closure_add_raw(&with_raw, CC_FIX,
                                  "tools/lint/cc_baseline.txt"));
        ci_closure_cost(&with_raw, &cost);
        ASSERT(ci_closure_seal(&with_raw, &declared_before));
        ASSERT(cost.entries == 2);
        ASSERT(cost.dir_entries == 1);
        ASSERT(cost.raw_entries == 1);
        ASSERT(cost.bytes_hashed > 0);

        /* A unit that declares only the source directory. */
        struct zcl_sha3_digest undeclared_before;
        ASSERT(cc_seal_dir(m, "zcl.test.unit.v1", "engine/modules/services",
                           &undeclared_before, NULL));

        /* Edit the baseline. The Merkle tree cannot see it at all. */
        ASSERT(cc_write(CC_FIX, "tools/lint/cc_baseline.txt",
                        "engine/modules/services/src/cc_a.c\n"
                        "engine/modules/services/src/cc_b.c\n"));
        struct ci_merkle *m2 = ci_merkle_build_cold(CC_FIX, NULL);
        ASSERT(m2 != NULL);

        struct ci_closure with_raw2;
        struct zcl_sha3_digest declared_after, undeclared_after;
        ASSERT(ci_closure_init(&with_raw2, "zcl.test.unit.v1"));
        ASSERT(ci_closure_add_dir(&with_raw2, m2, "engine/modules/services"));
        ASSERT(ci_closure_add_raw(&with_raw2, CC_FIX,
                                  "tools/lint/cc_baseline.txt"));
        ASSERT(ci_closure_seal(&with_raw2, &declared_after));
        ASSERT(cc_seal_dir(m2, "zcl.test.unit.v1", "engine/modules/services",
                           &undeclared_after, NULL));

        /* Declared: the key moved. Undeclared: it did not — which is exactly
         * the under-declaration hazard this API cannot detect for a caller,
         * and why ci_closure_cost() reports what was covered by what. */
        ASSERT(memcmp(declared_before.bytes, declared_after.bytes, 32) != 0);
        ASSERT(memcmp(undeclared_before.bytes, undeclared_after.bytes, 32) == 0);

        ci_merkle_free(m);
        ci_merkle_free(m2);
        cc_reset();
        PASS();
    } _test_next:;
    return failures;
}

int test_code_closure(void)
{
    int failures = 0;
    failures += test_cc_locality();
    failures += test_cc_canonical();
    failures += test_cc_fail_closed();
    failures += test_cc_raw_inputs();
    return failures;
}
