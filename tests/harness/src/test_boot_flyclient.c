/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_flyclient.h"
#include "models/database.h"
#include "models/utxo.h"
#include "config/boot_internal.h"
#include "controllers/blockchain_controller.h"
#include "chain/mmb.h"
#include "models/mmb_leaf_store.h"
#include "validation/chainstate.h"
#include "test/mmb_chain_fixture.h"
#include "crypto/sha3.h"
#include "net/snapshot_sync_contract.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BFC_CHECK(name, expr) do {                                      \
    printf("boot_flyclient: %s... ", (name));                         \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static bool snapshot_matches_fixture(const char *path, const uint8_t sha3[32])
{
    /* One full chunk followed by the existing empty chunk marker. */
    uint8_t expected[59] = {0};
    expected[0] = 1;
    memset(expected + 4, 0x42, 32);
    expected[40] = 1; /* value */
    expected[48] = 1; /* height */
    expected[53] = 1; /* compact script length */
    expected[54] = 0x51;
    uint8_t actual[60];
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "snapshot fixture could not open %s\n", path);
        return false;
    }
    size_t bytes = fread(actual, 1, sizeof(actual), fp);
    bool read_ok = !ferror(fp);
    int closed = fclose(fp);

    /* Commitment uses script_len before script and height after script. */
    uint8_t commitment_input[54] = {0};
    memset(commitment_input, 0x42, 32);
    commitment_input[36] = 1;
    commitment_input[44] = 1;
    commitment_input[48] = 0x51;
    commitment_input[49] = 1;
    uint8_t commitment[32];
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, commitment_input, sizeof(commitment_input));
    sha3_256_finalize(&ctx, commitment);
    return read_ok && closed == 0 && bytes == sizeof(expected) &&
           memcmp(actual, expected, sizeof(expected)) == 0 &&
           memcmp(sha3, commitment, sizeof(commitment)) == 0;
}

static int snapshot_write_checks(void)
{
    int failures = 0;
    struct node_db ndb;
    struct db_utxo utxo;
    uint8_t script[] = {0x51};
    uint8_t sha3[32];
    char snapshot_path[PATH_MAX];
    bool opened = node_db_open(&ndb, ":memory:");

    memset(&utxo, 0, sizeof(utxo));
    memset(utxo.txid, 0x42, sizeof(utxo.txid));
    utxo.value = 1;
    utxo.script = script;
    utxo.script_len = sizeof(script);
    utxo.script_type = SCRIPT_OTHER;
    utxo.height = 1;

    bool saved = opened && db_utxo_save(&ndb, &utxo);
    int snapshot_fd = test_mkstemp(snapshot_path, sizeof(snapshot_path),
                                   "boot_flyclient_snapshot");
    bool ready = snapshot_fd >= 0;
    if (ready)
        ready = close(snapshot_fd) == 0;
    BFC_CHECK("utxo snapshot serializer writes complete output",
              saved && ready &&
              boot_serialize_utxo_snapshot(&ndb, snapshot_path, 1,
                                           sha3) == 1 &&
              snapshot_matches_fixture(snapshot_path, sha3));
    if (snapshot_fd >= 0)
        BFC_CHECK("snapshot fixture cleanup", unlink(snapshot_path) == 0);

    if (opened)
        node_db_close(&ndb);
    return failures;
}

static int snapshot_output_failure_checks(void)
{
    int failures = 0;
#if defined(__linux__)
    struct node_db ndb;
    bool opened = node_db_open(&ndb, ":memory:");
    uint8_t sha3[32];
    const uint8_t zero[32] = {0};
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("empty snapshot serializer reports close failure",
              opened &&
              boot_serialize_utxo_snapshot(&ndb, "/dev/full", 500, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);

    struct db_utxo utxo = {0};
    uint8_t script[] = {0x51};
    memset(utxo.txid, 0x42, sizeof(utxo.txid));
    utxo.value = 1;
    utxo.script = script;
    utxo.script_len = sizeof(script);
    utxo.script_type = SCRIPT_OTHER;
    utxo.height = 1;
    bool saved = opened && db_utxo_save(&ndb, &utxo);
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("utxo snapshot serializer reports write failure",
              saved &&
              boot_serialize_utxo_snapshot(&ndb, "/dev/full", 1, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);
    if (opened)
        node_db_close(&ndb);
#endif
    return failures;
}

static int snapshot_refusal_checks(void)
{
    int failures = 0;
    uint8_t sha3[32];
    const uint8_t zero[32] = {0};
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("utxo snapshot serializer rejects missing db",
              boot_serialize_utxo_snapshot(NULL, NULL, 500, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("model snapshot serializer clears output before refusal",
              db_utxo_serialize_snapshot(NULL, NULL, 500, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);
    struct node_db ndb;
    bool opened = node_db_open(&ndb, ":memory:");
    char directory[PATH_MAX];
    test_make_tmpdir(directory, sizeof(directory), "boot_snapshot_refusal",
                     "directory");
    memset(sha3, 0xa5, sizeof(sha3));
    BFC_CHECK("utxo snapshot serializer clears output on open failure",
              opened &&
              boot_serialize_utxo_snapshot(&ndb, directory, 500, sha3) == -1 &&
              memcmp(sha3, zero, sizeof(sha3)) == 0);
    BFC_CHECK("snapshot directory cleanup", rmdir(directory) == 0);
    if (opened)
        node_db_close(&ndb);
    return failures;
}

/* ── MMB leaf store reconcile (incremental warm boot) ─────── */

static bool mmb_seed_prefix(struct mmb_leaf_store *s, const char *dir,
                            const char *name, const struct active_chain *chain,
                            int count)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    unlink(path);
    if (!mmb_leaf_store_open(s, path)) return false;
    for (int h = 0; h < count; h++) {
        uint8_t hash[32];
        if (!mmb_leaf_store_hash_at(chain, h, hash) ||
            !mmb_leaf_store_append(s, hash))
            return false;
    }
    return count == 0 || mmb_leaf_store_remap(s);
}

static bool mmb_stores_equal(const struct mmb_leaf_store *a,
                             const struct mmb_leaf_store *b)
{
    return a->num_leaves == b->num_leaves && a->num_leaves > 0 &&
           memcmp(mmb_leaf_store_get(a, 0), mmb_leaf_store_get(b, 0),
                  a->num_leaves * 32u) == 0;
}

static bool mmb_corrupt_leaf(struct mmb_leaf_store *s, uint64_t idx)
{
    uint8_t bad[32];
    memset(bad, 0xee, sizeof(bad));
    return mmb_leaf_store_write_at(s, idx, bad) && mmb_leaf_store_remap(s);
}

static int mmb_reconcile_corrupt_checks(const char *dir,
                                        const struct mmb_chain_fixture *fx,
                                        const struct mmb_leaf_store *ref)
{
    int failures = 0;
    struct mmb_leaf_store s;
    BFC_CHECK("reconcile extends a clean warm prefix by the missing tail",
              mmb_seed_prefix(&s, dir, "warm.bin", &fx->chain, 2500) &&
              boot_reconcile_mmb_leaf_store(&s, &fx->chain, 2600) &&
              mmb_stores_equal(&s, ref));
    mmb_leaf_store_close(&s);

    /* Last, last-1, last-100 and last-2048 of a 2500-leaf store. */
    static const uint64_t bad_idx[] = {2499, 2498, 2399, 451};
    for (size_t i = 0; i < sizeof(bad_idx) / sizeof(bad_idx[0]); i++) {
        char name[64];
        snprintf(name, sizeof(name), "bad%zu.bin", i);
        char label[96];
        snprintf(label, sizeof(label),
                 "reconcile rebuilds when sampled leaf %llu is corrupt",
                 (unsigned long long)bad_idx[i]);
        BFC_CHECK(label,
                  mmb_seed_prefix(&s, dir, name, &fx->chain, 2500) &&
                  mmb_corrupt_leaf(&s, bad_idx[i]) &&
                  boot_reconcile_mmb_leaf_store(&s, &fx->chain, 2600) &&
                  mmb_stores_equal(&s, ref));
        mmb_leaf_store_close(&s);
    }
    return failures;
}

static int mmb_reconcile_shape_checks(const char *dir,
                                      const struct mmb_chain_fixture *fx,
                                      const struct mmb_leaf_store *ref)
{
    int failures = 0;
    struct mmb_leaf_store s;
    BFC_CHECK("reconcile rebuilds an empty store",
              mmb_seed_prefix(&s, dir, "empty.bin", &fx->chain, 0) &&
              boot_reconcile_mmb_leaf_store(&s, &fx->chain, 2600) &&
              mmb_stores_equal(&s, ref));
    mmb_leaf_store_close(&s);

    /* Store longer than the chain: rebuilt down to the chain. */
    BFC_CHECK("reconcile rebuilds a store longer than the chain",
              mmb_seed_prefix(&s, dir, "long.bin", &fx->chain, 2600) &&
              mmb_leaf_store_append(&s, ref->map) &&
              mmb_leaf_store_remap(&s) && s.num_leaves == 2601 &&
              boot_reconcile_mmb_leaf_store(&s, &fx->chain, 2600) &&
              mmb_stores_equal(&s, ref));
    mmb_leaf_store_close(&s);

    /* MMB state 5 ahead of the chain: store follows the chain, then no-op. */
    BFC_CHECK("reconcile with state ahead of chain ends at chain leaves",
              mmb_seed_prefix(&s, dir, "ahead.bin", &fx->chain, 2000) &&
              boot_reconcile_mmb_leaf_store(&s, &fx->chain, 2605) &&
              s.num_leaves == 2600 && mmb_stores_equal(&s, ref));
    struct stat before, after;
    bool stat_ok = stat(s.path, &before) == 0;
    BFC_CHECK("second reconcile appends zero leaves",
              stat_ok && boot_reconcile_mmb_leaf_store(&s, &fx->chain, 2605) &&
              s.num_leaves == 2600 && stat(s.path, &after) == 0 &&
              after.st_size == before.st_size);
    mmb_leaf_store_close(&s);
    return failures;
}

static int mmb_reconcile_guard_checks(const char *dir)
{
    int failures = 0;
    struct mmb_chain_fixture fx;
    struct mmb_leaf_store ref;
    bool ready = mmb_chain_fixture_init(&fx, 2600) &&
                 mmb_seed_prefix(&ref, dir, "ref.bin", &fx.chain, 2600);
    BFC_CHECK("reconcile fixture ready", ready);
    if (!ready) return failures;

    failures += mmb_reconcile_corrupt_checks(dir, &fx, &ref);
    failures += mmb_reconcile_shape_checks(dir, &fx, &ref);
    mmb_leaf_store_close(&ref);
    mmb_chain_fixture_free(&fx);
    return failures;
}

static int mmb_boot_prepare_warm_checks(const char *dir)
{
    int failures = 0;
#if defined(__linux__)
    enum { CHAIN_N = 300 };
    struct mmb_chain_fixture fx;
    struct mmb_leaf_store ref;
    struct main_state *ms = calloc(1, sizeof(*ms));
    bool ready = ms && mmb_chain_fixture_init(&fx, CHAIN_N) &&
                 mmb_seed_prefix(&ref, dir, "bootref.bin", &fx.chain, CHAIN_N);
    BFC_CHECK("boot prepare fixture ready", ready);
    if (!ready) { free(ms); return failures; }

    active_chain_init(&ms->chain_active);
    active_chain_move_window_tip(&ms->chain_active, &fx.bi[CHAIN_N - 1]);
    struct boot_svc_ctx svc = {0};
    svc.state = ms;

    /* g_mmb is process-global: make it at least 5 ahead of the chain. */
    uint64_t have = 0;
    (void)rpc_blockchain_mmb_snapshot(NULL, &have, NULL);
    struct mmb_leaf leaf = {0};
    for (; have < CHAIN_N + 5; have++) rpc_blockchain_mmb_append(&leaf);

    /* Warm store 5 short of the chain, as a node left it. */
    struct mmb_leaf_store seed;
    bool seeded = mmb_seed_prefix(&seed, dir, "mmb_leaves.bin", &fx.chain,
                                  CHAIN_N - 5);
    mmb_leaf_store_close(&seed);
    BFC_CHECK("boot prepare first call extends to the chain",
              seeded && boot_prepare_mmb_leaf_store(&svc, dir, NULL) &&
              g_mmb_leaf_store.num_leaves == CHAIN_N &&
              mmb_stores_equal(&g_mmb_leaf_store, &ref));
    mmb_leaf_store_close(&g_mmb_leaf_store);

    /* Age the file: any write by the second boot would refresh the mtime. */
    char path[512];
    snprintf(path, sizeof(path), "%s/mmb_leaves.bin", dir);
    struct timespec old[2] = {{.tv_sec = 1000000000}, {.tv_sec = 1000000000}};
    struct stat before, after;
    bool aged = utimensat(AT_FDCWD, path, old, 0) == 0 &&
                stat(path, &before) == 0;
    BFC_CHECK("boot prepare second call appends zero leaves",
              aged && boot_prepare_mmb_leaf_store(&svc, dir, NULL) &&
              g_mmb_leaf_store.num_leaves == CHAIN_N &&
              stat(path, &after) == 0 && after.st_size == before.st_size &&
              after.st_mtim.tv_sec == 1000000000 &&
              mmb_stores_equal(&g_mmb_leaf_store, &ref));
    mmb_leaf_store_close(&g_mmb_leaf_store);

    mmb_leaf_store_close(&ref);
    active_chain_free(&ms->chain_active);
    free(ms);
    mmb_chain_fixture_free(&fx);
#else
    (void)dir;
#endif
    return failures;
}

static int mmb_reconcile_checks(void)
{
    int failures = 0;
    char dir[PATH_MAX];
    test_make_tmpdir(dir, sizeof(dir), "boot_mmb_reconcile", "dir");
    failures += mmb_reconcile_guard_checks(dir);
    failures += mmb_boot_prepare_warm_checks(dir);
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ---- mutation-gap cases ------------------------------------------------ */

static int gap_serialize_sentinel(void)
{
    int failures = 0;
    uint8_t buf[33];
    memset(buf, 0xa5, sizeof(buf));
    BFC_CHECK("serializer refusal clears exactly the 32 output bytes",
              boot_serialize_utxo_snapshot(NULL, NULL, 500, buf) == -1 &&
              buf[0] == 0 && buf[31] == 0 && buf[32] == 0xa5);
    return failures;
}

static bool gap_utxo_sha3_matches(struct boot_svc_ctx *svc)
{
    /* Same commitment preimage as snapshot_matches_fixture. */
    uint8_t input[54] = {0}, want[32], got[32] = {0};
    uint64_t count = 0;
    memset(input, 0x42, 32);
    input[36] = 1;
    input[44] = 1;
    input[48] = 0x51;
    input[49] = 1;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, input, sizeof(input));
    sha3_256_finalize(&ctx, want);
    return boot_compute_utxo_sha3(got, &count, svc) && count == 1 &&
           memcmp(got, want, 32) == 0;
}

static int gap_utxo_sha3(void)
{
    int failures = 0;
    struct node_db ndb, closed;
    struct db_utxo utxo = {0};
    uint8_t script[] = {0x51}, out[32];
    uint64_t count = 0;
    memset(&closed, 0, sizeof(closed));
    bool opened = node_db_open(&ndb, ":memory:");
    memset(utxo.txid, 0x42, sizeof(utxo.txid));
    utxo.value = 1;
    utxo.script = script;
    utxo.script_len = sizeof(script);
    utxo.script_type = SCRIPT_OTHER;
    utxo.height = 1;
    struct boot_svc_ctx svc = {0};
    svc.node_db = &ndb;
    BFC_CHECK("utxo sha3 provider commits the stored set",
              opened && db_utxo_save(&ndb, &utxo) && gap_utxo_sha3_matches(&svc));
    BFC_CHECK("utxo sha3 provider rejects a missing output",
              opened && !boot_compute_utxo_sha3(NULL, &count, &svc));
    BFC_CHECK("utxo sha3 provider rejects a missing count",
              opened && !boot_compute_utxo_sha3(out, NULL, &svc));
    struct boot_svc_ctx nodb = {0};
    BFC_CHECK("utxo sha3 provider rejects a missing node db",
              !boot_compute_utxo_sha3(out, &count, &nodb));
    nodb.node_db = &closed;
    BFC_CHECK("utxo sha3 provider rejects a node db with no handle",
              !boot_compute_utxo_sha3(out, &count, &nodb));
    if (opened)
        node_db_close(&ndb);
    return failures;
}

struct gap_range {
    struct mmb_chain_fixture fx;
    struct main_state *ms;
    struct node_db ndb;
    struct boot_svc_ctx svc;
    bool ok;
};

static void gap_range_open(struct gap_range *g)
{
    memset(g, 0, sizeof(*g));
    g->ms = calloc(1, sizeof(*g->ms));
    g->ok = g->ms && mmb_chain_fixture_init(&g->fx, 20) &&
            node_db_open(&g->ndb, ":memory:");
    if (!g->ok)
        return;
    for (int i = 0; i < g->fx.n; i++)
        g->fx.bi[i].nStatus |= BLOCK_HAVE_DATA;
    active_chain_init(&g->ms->chain_active);
    active_chain_move_window_tip(&g->ms->chain_active,
                                 &g->fx.bi[g->fx.n - 1]);
    g->svc.state = g->ms;
    g->svc.node_db = &g->ndb;
}

static void gap_range_close(struct gap_range *g)
{
    if (g->ms)
        active_chain_free(&g->ms->chain_active);
    free(g->ms);
    if (g->fx.bi)
        mmb_chain_fixture_free(&g->fx);
    node_db_close(&g->ndb);
}

static bool gap_hashes_are(const uint8_t (*out)[32],
                           const struct gap_range *g, int first, int n)
{
    for (int i = 0; i < n; i++)
        if (memcmp(out[i], g->fx.hashes[first + i].data, 32) != 0)
            return false;
    return true;
}

static int gap_range_from_chain(struct gap_range *g)
{
    int failures = 0;
    uint8_t out[6][32];
    memset(out, 0xee, sizeof(out));
    BFC_CHECK("range load copies the active-chain hashes",
              boot_load_block_hashes_range(10, 14, out, 5, &g->svc) == 5 &&
              gap_hashes_are(out, g, 10, 5));
    BFC_CHECK("range load writes no row past the count",
              out[5][0] == 0xee && out[5][31] == 0xee);
    memset(out, 0xee, sizeof(out));
    BFC_CHECK("range load of one height from the chain",
              boot_load_block_hashes_range(7, 7, out, 1, &g->svc) == 1 &&
              gap_hashes_are(out, g, 7, 1));
    BFC_CHECK("range load with a too-small buffer does not take the chain",
              boot_load_block_hashes_range(10, 14, out, 4, &g->svc) <= 0);
    BFC_CHECK("range load refuses a zero-size buffer",
              boot_load_block_hashes_range(10, 14, out, 0, &g->svc) == 0);
    return failures;
}

static int gap_range_fallbacks(struct gap_range *g)
{
    int failures = 0;
    uint8_t out[6][32];
    g->fx.bi[7].nStatus = 0;
    BFC_CHECK("range load of one height without a body falls to the db",
              boot_load_block_hashes_range(7, 7, out, 1, &g->svc) <= 0);
    BFC_CHECK("range load across a missing body falls to the db",
              boot_load_block_hashes_range(5, 9, out, 5, &g->svc) <= 0);
    g->fx.bi[7].nStatus = BLOCK_HAVE_DATA;
    struct boot_svc_ctx no_state = g->svc;
    no_state.state = NULL;
    BFC_CHECK("range load without chain state uses the db only",
              boot_load_block_hashes_range(10, 14, out, 5, &no_state) <= 0);
    struct boot_svc_ctx no_db = g->svc;
    no_db.node_db = NULL;
    BFC_CHECK("range load without a node db is refused even with a chain",
              boot_load_block_hashes_range(10, 14, out, 5, &no_db) == 0);
    return failures;
}

static int gap_range_checks(void)
{
    int failures = 0;
    struct gap_range g;
    gap_range_open(&g);
    BFC_CHECK("range fixture ready", g.ok);
    if (g.ok) {
        failures += gap_range_from_chain(&g);
        failures += gap_range_fallbacks(&g);
    }
    gap_range_close(&g);
    return failures;
}

static int gap_reconcile_guards(const char *dir)
{
    int failures = 0;
    struct mmb_chain_fixture fx;
    struct mmb_leaf_store s, closed;
    struct active_chain empty;
    memset(&closed, 0, sizeof(closed));
    bool ready = mmb_chain_fixture_init(&fx, 120);
    BFC_CHECK("reconcile guard fixture", ready);
    if (!ready)
        return failures;
    BFC_CHECK("reconcile refuses a NULL store",
              !boot_reconcile_mmb_leaf_store(NULL, &fx.chain, 120));
    BFC_CHECK("reconcile refuses a closed store",
              !boot_reconcile_mmb_leaf_store(&closed, &fx.chain, 120));
    active_chain_init(&empty);
    BFC_CHECK("reconcile refuses a chain with no tip",
              mmb_seed_prefix(&s, dir, "g_empty_chain.bin", &fx.chain, 3) &&
              !boot_reconcile_mmb_leaf_store(&s, &empty, 3));
    mmb_leaf_store_close(&s);
    active_chain_free(&empty);
    BFC_CHECK("a store already at the MMB state is left alone",
              mmb_seed_prefix(&s, dir, "g_at_state.bin", &fx.chain, 100) &&
              boot_reconcile_mmb_leaf_store(&s, &fx.chain, 100) &&
              s.num_leaves == 100);
    mmb_leaf_store_close(&s);
    mmb_chain_fixture_free(&fx);
    return failures;
}

static int gap_reconcile_one_block(const char *dir)
{
    int failures = 0;
    struct mmb_chain_fixture fx;
    struct mmb_leaf_store s;
    bool ready = mmb_chain_fixture_init(&fx, 1);
    BFC_CHECK("one-block chain fixture", ready);
    if (!ready)
        return failures;
    BFC_CHECK("reconcile accepts a chain whose tip is height 0",
              mmb_seed_prefix(&s, dir, "g_one.bin", &fx.chain, 0) &&
              boot_reconcile_mmb_leaf_store(&s, &fx.chain, 1) &&
              s.num_leaves == 1);
    mmb_leaf_store_close(&s);
    mmb_chain_fixture_free(&fx);
    return failures;
}

static bool gap_proof_challenge(struct fc_challenge *ch,
                                const struct mmb_leaf_store *store)
{
    struct mmb *m = calloc(1, sizeof(*m));
    if (!m)
        return false;
    mmb_init(m);
    for (uint64_t i = 0; i < store->num_leaves; i++)
        mmb_append_hash(m, mmb_leaf_store_get(store, i));
    memset(ch, 0, sizeof(*ch));
    memset(ch->seed, 0x37, sizeof(ch->seed));
    ch->chain_length = store->num_leaves;
    mmb_root(m, ch->mmb_root);
    free(m);
    return true;
}

static int gap_proof_checks(const char *dir)
{
    int failures = 0;
    struct mmb_chain_fixture fx;
    struct fc_challenge ch;
    struct fc_response *resp = calloc(1, sizeof(*resp));
    struct mmb_leaf leaf = {0};
    rpc_blockchain_mmb_append(&leaf);   /* the proof builder needs MMB state */
    bool ready = resp && mmb_chain_fixture_init(&fx, 40) &&
                 mmb_seed_prefix(&g_mmb_leaf_store, dir, "g_proof.bin",
                                 &fx.chain, 40) &&
                 gap_proof_challenge(&ch, &g_mmb_leaf_store);
    BFC_CHECK("proof fixture ready", ready);
    if (ready) {
        BFC_CHECK("proof builder answers an honest challenge",
                  boot_build_flyclient_proof(resp, &ch, &fx.chain, NULL) &&
                  resp->num_samples > 0);
        ch.mmb_root[0] ^= 1;
        BFC_CHECK("proof builder refuses a challenge for another root",
                  !boot_build_flyclient_proof(resp, &ch, &fx.chain, NULL));
        ch.mmb_root[0] ^= 1;
        mmb_leaf_store_close(&g_mmb_leaf_store);
        BFC_CHECK("proof builder refuses without an open leaf store",
                  !boot_build_flyclient_proof(resp, &ch, &fx.chain, NULL));
        mmb_chain_fixture_free(&fx);
    }
    free(resp);
    return failures;
}

static int g_gap_fail_at = -1;

static bool gap_legacy_loader(int height, struct mmb_leaf *leaf)
{
    if (height == g_gap_fail_at)
        return false;
    memset(leaf, 0, sizeof(*leaf));
    leaf->height = (uint32_t)height;
    leaf->timestamp = 7;
    leaf->block_hash[0] = (uint8_t)height;
    leaf->block_hash[1] = (uint8_t)(height >> 8);
    return true;
}

static bool gap_leaf_is_legacy(const struct mmb_leaf_store *s, uint64_t i)
{
    struct mmb_leaf leaf;
    uint8_t want[32];
    gap_legacy_loader((int)i, &leaf);
    mmb_hash_leaf(&leaf, want);
    return memcmp(mmb_leaf_store_get(s, i), want, 32) == 0;
}

static bool gap_leaf_is_chain(const struct mmb_leaf_store *s,
                              const struct mmb_leaf_store *ref, uint64_t i)
{
    return memcmp(mmb_leaf_store_get(s, i), mmb_leaf_store_get(ref, i), 32) == 0;
}

/* Run boot_prepare over a clean `have`-leaf store on a chain of `chain_n`
 * blocks, with the process MMB state clamped at `have` leaves. */
static bool gap_prepare(const char *dir, struct mmb_chain_fixture *fx,
                        struct mmb_leaf_store *ref, int have, int chain_n,
                        boot_mmb_leaf_loader_fn loader)
{
    struct main_state *ms = calloc(1, sizeof(*ms));
    struct mmb_leaf_store seed;
    if (!ms || !mmb_chain_fixture_init(fx, chain_n))
        return false;
    active_chain_init(&ms->chain_active);
    active_chain_move_window_tip(&ms->chain_active, &fx->bi[chain_n - 1]);
    struct boot_svc_ctx svc = {0};
    svc.state = ms;
    bool ok = mmb_seed_prefix(ref, dir, "gref.bin", &fx->chain, chain_n) &&
              mmb_seed_prefix(&seed, dir, "mmb_leaves.bin", &fx->chain, have);
    mmb_leaf_store_close(&seed);
    ok = ok && boot_prepare_mmb_leaf_store(&svc, dir, loader);
    active_chain_free(&ms->chain_active);
    free(ms);
    return ok;
}

static uint64_t gap_mmb_leaves(void)
{
    uint64_t have = 0;
    struct mmb_leaf leaf = {0};
    (void)rpc_blockchain_mmb_snapshot(NULL, &have, NULL);
    while (have < 2100) {
        rpc_blockchain_mmb_append(&leaf);
        have++;
    }
    (void)rpc_blockchain_mmb_snapshot(NULL, &have, NULL);
    return have;
}

static int gap_legacy_catchup(const char *dir)
{
    int failures = 0;
    struct mmb_chain_fixture fx;
    struct mmb_leaf_store ref;
    int have = (int)gap_mmb_leaves();
    g_gap_fail_at = -1;
    bool ok = gap_prepare(dir, &fx, &ref, have, have + 1, gap_legacy_loader);
    BFC_CHECK("legacy catchup: one leaf behind the chain is appended",
              ok && g_mmb_leaf_store.num_leaves == (uint64_t)have + 1 &&
              gap_leaf_is_legacy(&g_mmb_leaf_store, (uint64_t)have));
    BFC_CHECK("legacy repair rewrites the first 2048 leaves only",
              ok && gap_leaf_is_legacy(&g_mmb_leaf_store, 0) &&
              gap_leaf_is_legacy(&g_mmb_leaf_store, 2047) &&
              gap_leaf_is_chain(&g_mmb_leaf_store, &ref, 2048) &&
              gap_leaf_is_chain(&g_mmb_leaf_store, &ref, (uint64_t)have - 1));
    mmb_leaf_store_close(&g_mmb_leaf_store);
    mmb_leaf_store_close(&ref);
    mmb_chain_fixture_free(&fx);
    return failures;
}

static int gap_legacy_stops(const char *dir)
{
    int failures = 0;
    struct mmb_chain_fixture fx;
    struct mmb_leaf_store ref;
    int have = (int)gap_mmb_leaves();
    g_gap_fail_at = have + 1;
    bool ok = gap_prepare(dir, &fx, &ref, have, have + 3, gap_legacy_loader);
    BFC_CHECK("legacy catchup stops where the loader fails",
              ok && g_mmb_leaf_store.num_leaves == (uint64_t)have + 1);
    mmb_leaf_store_close(&g_mmb_leaf_store);
    mmb_leaf_store_close(&ref);
    mmb_chain_fixture_free(&fx);
    g_gap_fail_at = -1;

    have = (int)gap_mmb_leaves();
    ok = gap_prepare(dir, &fx, &ref, have, have, gap_legacy_loader);
    BFC_CHECK("a store already at the chain tip is not repaired from legacy",
              ok && g_mmb_leaf_store.num_leaves == (uint64_t)have &&
              gap_leaf_is_chain(&g_mmb_leaf_store, &ref, 0) &&
              gap_leaf_is_chain(&g_mmb_leaf_store, &ref, (uint64_t)have - 1));
    mmb_leaf_store_close(&g_mmb_leaf_store);
    mmb_leaf_store_close(&ref);
    mmb_chain_fixture_free(&fx);
    return failures;
}

static int boot_flyclient_gap_checks(void)
{
    int failures = 0;
    char dir[PATH_MAX];
    test_make_tmpdir(dir, sizeof(dir), "boot_flyclient_gap", "dir");
    failures += gap_serialize_sentinel();
    failures += gap_utxo_sha3();
    failures += gap_range_checks();
    failures += gap_reconcile_guards(dir);
    failures += gap_reconcile_one_block(dir);
    failures += gap_proof_checks(dir);
    failures += gap_legacy_catchup(dir);
    failures += gap_legacy_stops(dir);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_boot_flyclient(void)
{
    int failures = 0;
    uint8_t hash_out[1][32];
    uint8_t sha3[32];
    uint64_t count = 0;

    BFC_CHECK("proof builder rejects missing args",
              !boot_build_flyclient_proof(NULL, NULL, NULL, NULL));

    BFC_CHECK("block hash loader rejects missing context",
              boot_load_block_hashes_range(0, 1, hash_out, 1, NULL) == 0);

    BFC_CHECK("block hash loader rejects missing output",
              boot_load_block_hashes_range(0, 1, NULL, 1, NULL) == 0);

    BFC_CHECK("utxo sha3 provider rejects missing context",
              !boot_compute_utxo_sha3(sha3, &count, NULL));

    failures += snapshot_write_checks();
    failures += snapshot_output_failure_checks();
    failures += snapshot_refusal_checks();
    failures += mmb_reconcile_checks();
    failures += boot_flyclient_gap_checks();

    BFC_CHECK("mmb leaf store prepare rejects missing service",
              !boot_prepare_mmb_leaf_store(NULL, NULL, NULL));

    return failures;
}
