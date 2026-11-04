/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * test_dev_proof_verdict_mmr -- the append-only signed MMR over accepted-proof
 * verdict leaves and the pure admission, sampling and divergence rules over
 * it (tools/dev/dev_proof_verdict_mmr.c). Every case runs on an isolated
 * state root (its own signer key) and isolated fixture directories; nothing
 * reads or writes a live store. */

#include "test/test_core.h"

#include "dev_proof.h"
#include "dev_proof_verdict_mmr.h"
#include "dev_proof_observation.h"
#include "dev_proof_signer.h"
#include "base/hex.h"
#include "sha3/sha3.h"
#include "platform/directory_compat.h"
#include "vcs/vcs_object.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#define VM_STATE_ENV "ZCL_STATE_ROOT"
#else
#define VM_STATE_ENV "XDG_STATE_HOME"
#endif

struct vm_rig {
    char base[3800];
    char pair[4000], mmr[4000], objects[4040];
};

static bool vm_rig_open(struct vm_rig *r, const char *tag)
{
    char state[4000];
    test_make_tmpdir(r->base, sizeof(r->base), "dev_proof_vmmr", tag);
    (void)snprintf(state, sizeof(state), "%s/state", r->base);
    (void)snprintf(r->pair, sizeof(r->pair), "%s/pair", r->base);
    (void)snprintf(r->mmr, sizeof(r->mmr), "%s/mmr", r->base);
    (void)snprintf(r->objects, sizeof(r->objects), "%s/objects", r->mmr);
    return platform_directory_ensure(state, 0700) &&
           platform_directory_ensure(r->pair, 0700) &&
           platform_directory_ensure(r->mmr, 0700) &&
           setenv(VM_STATE_ENV, state, 1) == 0 &&
           platform_directory_ensure(r->objects, 0700) &&
           vcs_object_store_init(r->objects);
}

static void vm_key(uint8_t key[32], unsigned seed)
{
    for (unsigned i = 0; i < 32; i++) key[i] = (uint8_t)(seed * 31u + i);
}

static bool vm_leaf(const char *store, unsigned seed, const char *group,
                    enum zcl_dev_verdict_leaf_verdict v, uint64_t ms,
                    uint8_t root[32])
{
    uint8_t key[32];
    char why[96];
    vm_key(key, seed);
    return zcl_dev_observation_record(store, key, group, v, ms, root, why,
                                      sizeof(why));
}

static void vm_line(char *out, size_t cap, unsigned seed, const char *group,
                    const uint8_t root[32])
{
    uint8_t key[32];
    char kh[65], rh[65];
    vm_key(key, seed);
    zcl_hex_encode(key, 32, kh);
    zcl_hex_encode(root, 32, rh);
    (void)snprintf(out, cap,
                   "OBSERVATION group=%s verdict=PASS key=%s root=%s "
                   "source=independent_execution\n", group, kh, rh);
}

/* Leaf `seed` flipped in its signature, re-rooted so it is byte-consistent
 * and only its signature is wrong. Stored in `store`. */
static bool vm_forged_leaf(const char *store, unsigned seed,
                           const char *group, uint8_t root[32])
{
    uint8_t good[32], *wire = NULL;
    size_t len = 0;
    struct zcl_dev_verdict_leaf_v1 leaf;
    char why[96];
    bool ok = vm_leaf(store, seed, group, ZCL_DEV_VERDICT_LEAF_PASS, 7, good) &&
              vcs_object_load_raw_bounded(store, good, 328, &wire, &len) == 0;
    if (ok) wire[270] ^= 0x5a;
    ok = ok && zcl_dev_verdict_leaf_parse(wire, len, &leaf, why, sizeof(why)) &&
         zcl_dev_verdict_leaf_root(&leaf, root, why, sizeof(why)) &&
         vcs_object_put_addressed(store, root, wire, len);
    free(wire);
    return ok;
}

static bool vm_copy(const char *from, const char *to, const uint8_t root[32])
{
    uint8_t *wire = NULL;
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(from, root, 328, &wire, &len) == 0 &&
              vcs_object_put_addressed(to, root, wire, len);
    free(wire);
    return ok;
}

/* Fixture verifier list: this box's own key stands in for the separate
 * account's key so the admission mechanics can be exercised. The real list
 * comes only from the strict loader, which refuses a file this uid owns. */
static struct zcl_dev_vmmr_keys vm_verifiers;

static bool vm_set_verifiers(bool include_self)
{
    uint8_t pub[32];
    bool present = false;
    const char *w = NULL;
    char text[80];
    memset(&vm_verifiers, 0, sizeof(vm_verifiers));
    if (!zcl_dev_proof_signer_public(pub, &present, &w) && !present) {
        /* No key yet on this fresh state root: mint one by signing. */
        uint8_t sig[64];
        if (!zcl_dev_proof_signer_sign((const uint8_t *)"x", 1, pub, sig, &w))
            return false;
    }
    if (!include_self) {
        pub[0] ^= 0xff; /* a different, unrelated key */
    }
    zcl_hex_encode(pub, 32, text);
    text[64] = '\n';
    return zcl_dev_vmmr_keys_parse(text, 65, &vm_verifiers) &&
           vm_verifiers.count == 1;
}

static bool vm_open_admit(struct vm_rig *r, unsigned seed, const char *group,
                          enum zcl_dev_observation_verdict *v, uint64_t *ms)
{
    struct zcl_dev_vmmr_chain chain;
    struct zcl_dev_vmmr_index *ix;
    uint8_t key[32];
    char why[96];
    if (!vm_set_verifiers(true) ||
        !zcl_dev_vmmr_load(r->mmr, &chain, why, sizeof(why)))
        return false;
    ix = zcl_dev_vmmr_index_open(r->mmr, &chain, &vm_verifiers, why,
                                 sizeof(why));
    zcl_dev_vmmr_release(&chain);
    if (!ix) return false;
    vm_key(key, seed);
    *v = zcl_dev_vmmr_admit(ix, key, group, ms, why, sizeof(why));
    zcl_dev_vmmr_index_close(ix);
    return true;
}

static int vm_flag_off_checks(void)
{
    int failures = 0;
    TEST("verdict_mmr: flag off, the cold dimension argv is unchanged") {
        const char *argv[8] = {0}, *armed[8] = {0};
        bool no_cache = false, cold_audit = false;
        ASSERT(unsetenv(ZCL_DEV_VMMR_ENV) == 0);
        ASSERT(zcl_dev_vmmr_dir() == NULL);
        ASSERT(setenv(ZCL_DEV_VMMR_ENV, "relative/dir", 1) == 0);
        ASSERT(zcl_dev_vmmr_dir() == NULL);
        ASSERT(setenv(ZCL_DEV_VMMR_ENV, "/some/abs/dir", 1) == 0);
        ASSERT(zcl_dev_vmmr_dir() != NULL);
        ASSERT_EQ(zcl_dev_proof_test_dimension_argv("runner", "--exact=x", argv,
                                                    8), 4u);
        for (int i = 0; argv[i]; i++) {
            no_cache |= strcmp(argv[i], "--no-cache") == 0;
            cold_audit |= strcmp(argv[i], "--cold-audit") == 0;
        }
        ASSERT(no_cache && !cold_audit);
        ASSERT_EQ(zcl_dev_vmmr_test_argv("runner", "--exact=x", armed, 8), 5u);
        ASSERT(strcmp(armed[2], "--cold-audit") == 0);
        ASSERT(strcmp(armed[3], "--collect-observations") == 0);
        PASS();
    }
_test_next:;
    (void)unsetenv(ZCL_DEV_VMMR_ENV);
    return failures;
}

static int vm_chain_checks(void)
{
    int failures = 0;
    struct vm_rig r;
    TEST("verdict_mmr: accepted leaves chain across batches and admit PASS") {
        char *log = calloc(80, 400);
        struct zcl_dev_vmmr_adopt a;
        struct zcl_dev_vmmr_chain c;
        enum zcl_dev_observation_verdict v = ZCL_DEV_OBSERVATION_MISSING;
        uint64_t ms = 0;
        char why[96], name[32];
        size_t at = 0;
        ASSERT(log && vm_rig_open(&r, "chain"));
        for (unsigned i = 1; i <= 70; i++) {
            uint8_t root[32];
            (void)snprintf(name, sizeof(name), "test_vm_g%u", i);
            ASSERT(vm_leaf(r.pair, i, name, ZCL_DEV_VERDICT_LEAF_PASS, 100 + i,
                           root));
            vm_line(log + at, 400, i, name, root);
            at += strlen(log + at);
        }
        ASSERT(zcl_dev_vmmr_adopt_log(r.mmr, r.pair, log, at, &a, why,
                                      sizeof(why)));
        ASSERT(a.seen == 70 && a.adopted == 70 && a.refused == 0);
        ASSERT(a.leaf_count == 70);
        ASSERT(zcl_dev_vmmr_load(r.mmr, &c, why, sizeof(why)));
        ASSERT(c.records == 2 && c.leaf_count == 70);
        zcl_dev_vmmr_release(&c);
        /* A second adoption of the same lines appends nothing. */
        ASSERT(zcl_dev_vmmr_adopt_log(r.mmr, r.pair, log, at, &a, why,
                                      sizeof(why)));
        ASSERT(a.adopted == 0 && a.leaf_count == 70);
        ASSERT(vm_open_admit(&r, 5, "test_vm_g5", &v, &ms));
        ASSERT(v == ZCL_DEV_OBSERVATION_PASS && ms == 105);
        ASSERT(vm_open_admit(&r, 5, "test_vm_other", &v, &ms));
        ASSERT(v == ZCL_DEV_OBSERVATION_MISSING);
        free(log);
        PASS();
    }
_test_next:;
    return failures;
}

static int vm_tamper_check(void)
{
    int failures = 0;
    struct vm_rig r;
    TEST("verdict_mmr: a tampered leaf signature is ineligible, never adopted") {
        uint8_t root[32];
        char line[400], why[96];
        struct zcl_dev_vmmr_adopt a;
        enum zcl_dev_observation_verdict v = ZCL_DEV_OBSERVATION_PASS;
        uint64_t ms = 0;
        ASSERT(vm_rig_open(&r, "tamper"));
        ASSERT(vm_forged_leaf(r.pair, 1, "test_vm_forged", root));
        vm_line(line, sizeof(line), 1, "test_vm_forged", root);
        ASSERT(zcl_dev_vmmr_adopt_log(r.mmr, r.pair, line, strlen(line), &a,
                                      why, sizeof(why)));
        ASSERT(a.seen == 1 && a.adopted == 0 && a.refused == 1);
        /* Force it into the chain anyway: admission still refuses it. */
        ASSERT(vm_copy(r.pair, r.objects, root));
        ASSERT(zcl_dev_vmmr_append(r.mmr, (const uint8_t (*)[32])root, 1, 1000,
                                   NULL, why, sizeof(why)));
        ASSERT(vm_open_admit(&r, 1, "test_vm_forged", &v, &ms));
        ASSERT(v == ZCL_DEV_OBSERVATION_MISSING);
        PASS();
    }
_test_next:;
    return failures;
}

static int vm_conflict_check(void)
{
    int failures = 0;
    struct vm_rig r;
    TEST("verdict_mmr: PASS and FAIL for one key is CONFLICT, not PASS") {
        uint8_t roots[2][32];
        char why[96];
        enum zcl_dev_observation_verdict v = ZCL_DEV_OBSERVATION_PASS;
        uint64_t ms = 0;
        ASSERT(vm_rig_open(&r, "conflict"));
        ASSERT(vm_leaf(r.pair, 2, "test_vm_c", ZCL_DEV_VERDICT_LEAF_PASS, 10,
                       roots[0]));
        ASSERT(vm_leaf(r.pair, 2, "test_vm_c", ZCL_DEV_VERDICT_LEAF_FAIL, 11,
                       roots[1]));
        ASSERT(vm_copy(r.pair, r.objects, roots[0]));
        ASSERT(vm_copy(r.pair, r.objects, roots[1]));
        ASSERT(zcl_dev_vmmr_append(r.mmr, (const uint8_t (*)[32])roots, 2,
                                   1000, NULL, why, sizeof(why)));
        ASSERT(vm_open_admit(&r, 2, "test_vm_c", &v, &ms));
        ASSERT(v == ZCL_DEV_OBSERVATION_CONFLICT);
        PASS();
    }
_test_next:;
    return failures;
}

static int vm_rewrite_check(void)
{
    int failures = 0;
    struct vm_rig r;
    TEST("verdict_mmr: a rewritten MMR history is refused as a whole") {
        uint8_t roots[3][32];
        char path[4100], why[96];
        struct zcl_dev_vmmr_chain c;
        FILE *f;
        ASSERT(vm_rig_open(&r, "rewrite"));
        for (unsigned i = 0; i < 3; i++) {
            ASSERT(vm_leaf(r.pair, 10 + i, "test_vm_r",
                           ZCL_DEV_VERDICT_LEAF_PASS, 1, roots[i]));
            ASSERT(vm_copy(r.pair, r.objects, roots[i]));
            ASSERT(zcl_dev_vmmr_append(r.mmr, (const uint8_t (*)[32])roots[i],
                                       1, 1000 + i, NULL, why, sizeof(why)));
        }
        ASSERT(zcl_dev_vmmr_load(r.mmr, &c, why, sizeof(why)));
        ASSERT(c.records == 3 && c.leaf_count == 3);
        zcl_dev_vmmr_release(&c);
        (void)snprintf(path, sizeof(path), "%s/chain.log", r.mmr);
        f = fopen(path, "r+b");
        ASSERT(f != NULL);
        /* Record 0: count byte, checkpoint wire (1168), then its root. */
        ASSERT(fseek(f, 1 + 1168 + 3, SEEK_SET) == 0);
        ASSERT(fputc(0x77, f) != EOF);
        ASSERT(fclose(f) == 0);
        ASSERT(!zcl_dev_vmmr_load(r.mmr, &c, why, sizeof(why)));
        ASSERT_STR_EQ(why, "verdict_mmr_history_invalid");
        /* Appending onto a rewritten history is refused too. */
        ASSERT(!zcl_dev_vmmr_append(r.mmr, (const uint8_t (*)[32])roots[0], 1,
                                    2000, NULL, why, sizeof(why)));
        PASS();
    }
_test_next:;
    return failures;
}

static int vm_divergence_check(void)
{
    int failures = 0;
    TEST("verdict_mmr: a sample divergence reruns every skipped group") {
        struct zcl_dev_vmmr_item items[5] = {
            {ZCL_DEV_OBSERVATION_PASS, 100, false, false},
            {ZCL_DEV_OBSERVATION_PASS, 200, false, false},
            {ZCL_DEV_OBSERVATION_PASS, 50, true, true},
            {ZCL_DEV_OBSERVATION_MISSING, 0, false, false},
            {ZCL_DEV_OBSERVATION_CONFLICT, 0, false, false},
        };
        bool skip[5];
        struct zcl_dev_vmmr_plan p;
        zcl_dev_vmmr_resolve(items, 5, skip, &p);
        ASSERT(!p.divergence && p.reused == 2 && p.sampled == 1);
        ASSERT(p.saved_ms == 300);
        ASSERT(skip[0] && skip[1] && !skip[2] && !skip[3] && !skip[4]);
        items[2].cold_pass = false;
        zcl_dev_vmmr_resolve(items, 5, skip, &p);
        ASSERT(p.divergence && p.reused == 0 && p.saved_ms == 0);
        for (int i = 0; i < 5; i++) ASSERT(!skip[i]);
        PASS();
    }
_test_next:;
    return failures;
}

static int vm_sample_check(void)
{
    int failures = 0;
    TEST("verdict_mmr: the sample is deterministic, about 1/8, pair-bound") {
        uint8_t key[32];
        unsigned hits = 0, diff = 0;
        for (unsigned i = 0; i < 4096; i++) {
            bool a, b;
            vm_key(key, i);
            a = zcl_dev_vmmr_sampled(key, "pair-a");
            b = zcl_dev_vmmr_sampled(key, "pair-b");
            ASSERT(a == zcl_dev_vmmr_sampled(key, "pair-a"));
            hits += a;
            diff += a != b;
        }
        ASSERT(hits > 4096 / 16 && hits < 4096 / 4);
        ASSERT(diff > 0);
        PASS();
    }
_test_next:;
    return failures;
}

static void vm_closure_key(const char *bytes, uint8_t key[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)"vm.closure", 10);
    sha3_256_write(&sha, (const uint8_t *)bytes, strlen(bytes));
    sha3_256_finalize(&sha, key);
}

/* testcache derives a key from the closure's file bytes (its own group pins
 * that); this case pins the consumer: the key an edited closure produces has
 * no leaf, so the group is not admitted and runs. */
static int vm_closure_checks(void)
{
    int failures = 0;
    struct vm_rig r;
    TEST("verdict_mmr: a changed closure file gets a new key and runs") {
        uint8_t k1[32], k2[32], root[32];
        struct zcl_dev_vmmr_chain c;
        struct zcl_dev_vmmr_index *ix;
        char why[96];
        uint64_t ms;
        ASSERT(vm_rig_open(&r, "closure"));
        ASSERT(vm_set_verifiers(true));
        vm_closure_key("int f(void){return 1;}", k1);
        vm_closure_key("int f(void){return 2;}", k2);
        ASSERT(memcmp(k1, k2, 32) != 0);
        ASSERT(zcl_dev_observation_record(r.pair, k1, "test_vm_closure",
                   ZCL_DEV_VERDICT_LEAF_PASS, 9, root, why, sizeof(why)));
        ASSERT(vm_copy(r.pair, r.objects, root));
        ASSERT(zcl_dev_vmmr_append(r.mmr, (const uint8_t (*)[32])root, 1, 1000,
                                   NULL, why, sizeof(why)));
        ASSERT(zcl_dev_vmmr_load(r.mmr, &c, why, sizeof(why)));
        ix = zcl_dev_vmmr_index_open(r.mmr, &c, &vm_verifiers, why, sizeof(why));
        zcl_dev_vmmr_release(&c);
        ASSERT(ix != NULL);
        ASSERT(zcl_dev_vmmr_admit(ix, k1, "test_vm_closure", &ms, why,
                                  sizeof(why)) == ZCL_DEV_OBSERVATION_PASS);
        ASSERT(zcl_dev_vmmr_admit(ix, k2, "test_vm_closure", &ms, why,
                                  sizeof(why)) == ZCL_DEV_OBSERVATION_MISSING);
        zcl_dev_vmmr_index_close(ix);
        PASS();
    }
_test_next:;
    return failures;
}

static int vm_producer_check(void)
{
    int failures = 0;
    struct vm_rig r;
    TEST("verdict_mmr: a producer-signed leaf is audit only, never admitted") {
        uint8_t root[32], key[32];
        struct zcl_dev_vmmr_chain c;
        struct zcl_dev_vmmr_index *ix;
        struct zcl_dev_vmmr_keys none;
        char why[96], path[4100];
        uint64_t ms = 0;
        FILE *f;
        ASSERT(vm_rig_open(&r, "producer"));
        ASSERT(vm_leaf(r.pair, 3, "test_vm_p", ZCL_DEV_VERDICT_LEAF_PASS, 4,
                       root));
        ASSERT(vm_copy(r.pair, r.objects, root));
        ASSERT(zcl_dev_vmmr_append(r.mmr, (const uint8_t (*)[32])root, 1, 1000,
                                   NULL, why, sizeof(why)));
        vm_key(key, 3);
        ASSERT(zcl_dev_vmmr_load(r.mmr, &c, why, sizeof(why)));
        /* Verifier list does not hold the producer's key: MISSING. */
        ASSERT(vm_set_verifiers(false));
        ix = zcl_dev_vmmr_index_open(r.mmr, &c, &vm_verifiers, why,
                                     sizeof(why));
        ASSERT(ix != NULL);
        ASSERT(zcl_dev_vmmr_admit(ix, key, "test_vm_p", &ms, why,
                                  sizeof(why)) == ZCL_DEV_OBSERVATION_MISSING);
        zcl_dev_vmmr_index_close(ix);
        /* An empty verifier list cannot even open an index. */
        memset(&none, 0, sizeof(none));
        ASSERT(zcl_dev_vmmr_index_open(r.mmr, &c, &none, why, sizeof(why)) ==
               NULL);
        zcl_dev_vmmr_release(&c);
        /* Unset flag: unqualified, exactly as before. */
        ASSERT(unsetenv("ZCL_DEV_PROOF_VERIFIER_KEYS") == 0);
        ASSERT(!zcl_dev_vmmr_keys_load(&none, why, sizeof(why)));
        ASSERT_STR_EQ(why, ZCL_DEV_VMMR_UNQUALIFIED);
        /* A key file this uid owns is candidate-writable: refused. */
        (void)snprintf(path, sizeof(path), "%s/verifiers.keys", r.base);
        f = fopen(path, "w");
        ASSERT(f != NULL);
        ASSERT(fputs("0000000000000000000000000000000000000000000000000000000000000001\n", f) >= 0);
        ASSERT(fclose(f) == 0);
        ASSERT(setenv("ZCL_DEV_PROOF_VERIFIER_KEYS", path, 1) == 0);
        ASSERT(!zcl_dev_vmmr_keys_load(&none, why, sizeof(why)));
        ASSERT_STR_EQ(why, ZCL_DEV_VMMR_UNQUALIFIED);
        PASS();
    }
_test_next:;
    (void)unsetenv("ZCL_DEV_PROOF_VERIFIER_KEYS");
    return failures;
}

int test_dev_proof_verdict_mmr(void)
{
    int failures = 0;
    failures += vm_flag_off_checks();
    failures += vm_chain_checks();
    failures += vm_tamper_check();
    failures += vm_conflict_check();
    failures += vm_rewrite_check();
    failures += vm_divergence_check();
    failures += vm_sample_check();
    failures += vm_closure_checks();
    failures += vm_producer_check();
    return failures;
}
