/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for net/rom_seed_ledger.h — schema/open on a fresh datadir, append
 * + per-artifact rollup, distinct-artifact listing order, and the
 * retention cap (delete-oldest past the cap, mirroring
 * engine/modules/storage/src/peers_projection.c's peer_sessions ledger).
 *
 * One TEST(...) block per function (the ASSERT()/ASSERT_EQ() macros `goto
 * _test_next`, a single hardcoded label — see test/test_core.h — so two
 * TEST blocks sharing one function collide on that label). */

#include "test/test_core.h"
#include "json/json.h"

#include "net/rom_seed_ledger.h"

#include <string.h>

static void fill_ip(uint8_t ip[16], uint8_t tail)
{
    memset(ip, 0, 16);
    ip[10] = 0xff;
    ip[11] = 0xff;
    ip[12] = 203;
    ip[13] = 0;
    ip[14] = 113;
    ip[15] = tail;
}

static void fill_artifact(uint8_t id[ROM_SEED_LEDGER_ARTIFACT_ID_LEN],
                          uint8_t fill)
{
    memset(id, fill, ROM_SEED_LEDGER_ARTIFACT_ID_LEN);
}

static int t_open_empty_is_well_formed(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_ledger", "empty1");

    TEST("open on a fresh datadir succeeds with zero rows") {
        rom_seed_ledger_t *l = rom_seed_ledger_open(dir);
        ASSERT(l != NULL);
        ASSERT_EQ(rom_seed_ledger_row_count(l), (int64_t)0);
        uint8_t ids[4][ROM_SEED_LEDGER_ARTIFACT_ID_LEN];
        ASSERT_EQ(rom_seed_ledger_distinct_artifacts(l, ids, 4), (size_t)0);
        uint8_t artifact[ROM_SEED_LEDGER_ARTIFACT_ID_LEN];
        fill_artifact(artifact, 0xAB);
        struct rom_seed_ledger_artifact_stats st;
        ASSERT(!rom_seed_ledger_artifact_stats(l, artifact, &st));
        ASSERT_EQ(st.sessions, (uint32_t)0);
        rom_seed_ledger_close(l);
        PASS();
    } _test_next:;

    return failures;
}

static int t_open_rejects_null_or_empty_datadir(void)
{
    int failures = 0;

    TEST("open rejects a NULL/empty datadir") {
        ASSERT(rom_seed_ledger_open(NULL) == NULL);
        ASSERT(rom_seed_ledger_open("") == NULL);
        PASS();
    } _test_next:;

    return failures;
}

static int t_append_accumulates_per_artifact_totals(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_ledger", "rollup1");
    rom_seed_ledger_t *l = rom_seed_ledger_open(dir);

    TEST("append accumulates per-artifact totals across peers/sessions") {
        ASSERT(l != NULL);
        uint8_t artifact_a[ROM_SEED_LEDGER_ARTIFACT_ID_LEN];
        fill_artifact(artifact_a, 0x11);
        uint8_t peer1[16], peer2[16];
        fill_ip(peer1, 1);
        fill_ip(peer2, 2);

        ASSERT(rom_seed_ledger_append(l, peer1, 18034, artifact_a, 10,
                                      500000000, 1000, 1010));
        ASSERT(rom_seed_ledger_append(l, peer2, 18034, artifact_a, 5,
                                      250000000, 1020, 1030));
        /* Same peer1 IP+port again — same session count, not a new
         * distinct peer. */
        ASSERT(rom_seed_ledger_append(l, peer1, 18034, artifact_a, 2,
                                      100000000, 1040, 1050));

        struct rom_seed_ledger_artifact_stats st;
        ASSERT(rom_seed_ledger_artifact_stats(l, artifact_a, &st));
        ASSERT_EQ(st.total_chunks_served, (uint64_t)17);
        ASSERT_EQ(st.total_bytes_served, (uint64_t)850000000);
        ASSERT_EQ(st.sessions, (uint32_t)3);
        ASSERT_EQ(st.distinct_peers, (uint32_t)2);
        ASSERT_EQ(st.last_served_unix, (int64_t)1050);
        ASSERT_EQ(rom_seed_ledger_row_count(l), (int64_t)3);
        PASS();
    } _test_next:;

    rom_seed_ledger_close(l);
    return failures;
}

static int t_second_artifact_tracked_independently(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_ledger", "rollup2");
    rom_seed_ledger_t *l = rom_seed_ledger_open(dir);
    if (!l) { failures++; return failures; }

    uint8_t artifact_a[ROM_SEED_LEDGER_ARTIFACT_ID_LEN];
    fill_artifact(artifact_a, 0x11);
    uint8_t peer1[16], peer2[16];
    fill_ip(peer1, 1);
    fill_ip(peer2, 2);
    (void)rom_seed_ledger_append(l, peer1, 18034, artifact_a, 10, 500000000,
                                 1000, 1010);
    (void)rom_seed_ledger_append(l, peer2, 18034, artifact_a, 5, 250000000,
                                 1020, 1030);
    (void)rom_seed_ledger_append(l, peer1, 18034, artifact_a, 2, 100000000,
                                 1040, 1050);

    TEST("a second artifact is tracked independently") {
        uint8_t artifact_b[ROM_SEED_LEDGER_ARTIFACT_ID_LEN];
        fill_artifact(artifact_b, 0x22);
        uint8_t peer3[16];
        fill_ip(peer3, 3);
        ASSERT(rom_seed_ledger_append(l, peer3, 18034, artifact_b, 1,
                                      50000000, 2000, 2005));
        struct rom_seed_ledger_artifact_stats st_a, st_b;
        ASSERT(rom_seed_ledger_artifact_stats(l, artifact_a, &st_a));
        ASSERT(rom_seed_ledger_artifact_stats(l, artifact_b, &st_b));
        ASSERT_EQ(st_a.sessions, (uint32_t)3);
        ASSERT_EQ(st_b.sessions, (uint32_t)1);

        uint8_t ids[8][ROM_SEED_LEDGER_ARTIFACT_ID_LEN];
        size_t n = rom_seed_ledger_distinct_artifacts(l, ids, 8);
        ASSERT_EQ(n, (size_t)2);
        /* Most-recently-served first: artifact_b (last_served=2005) before
         * artifact_a (last_served=1050). */
        ASSERT(memcmp(ids[0], artifact_b, ROM_SEED_LEDGER_ARTIFACT_ID_LEN) == 0);
        ASSERT(memcmp(ids[1], artifact_a, ROM_SEED_LEDGER_ARTIFACT_ID_LEN) == 0);
        PASS();
    } _test_next:;

    rom_seed_ledger_close(l);
    return failures;
}

static int t_retention_caps_to_newest_n_rows(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_ledger", "retention");
    rom_seed_ledger_test_set_retention_cap(5);
    rom_seed_ledger_t *l = rom_seed_ledger_open(dir);

    TEST("retention caps the table to the newest N rows") {
        ASSERT(l != NULL);
        uint8_t artifact[ROM_SEED_LEDGER_ARTIFACT_ID_LEN];
        fill_artifact(artifact, 0x33);
        uint8_t peer[16];
        fill_ip(peer, 9);
        for (int i = 0; i < 12; i++) {
            ASSERT(rom_seed_ledger_append(l, peer, 18034, artifact, 1, 1000,
                                          1000 + i, 1001 + i));
        }
        ASSERT_EQ(rom_seed_ledger_row_count(l), (int64_t)5);
        /* Newest rows survive: the last append's finished_unix is
         * 1001+11=1012, and every retained row's chunks_served/bytes_served
         * still sum correctly for the 5 kept rows (1 chunk / 1000 bytes
         * each). */
        struct rom_seed_ledger_artifact_stats st;
        ASSERT(rom_seed_ledger_artifact_stats(l, artifact, &st));
        ASSERT_EQ(st.sessions, (uint32_t)5);
        ASSERT_EQ(st.total_chunks_served, (uint64_t)5);
        ASSERT_EQ(st.last_served_unix, (int64_t)1012);
        PASS();
    } _test_next:;

    rom_seed_ledger_close(l);
    rom_seed_ledger_test_reset_retention_cap();
    return failures;
}

static int t_dump_state_json(void)
{
    int failures = 0;
    char dir[256];
    test_make_tmpdir(dir, sizeof(dir), "rom_seed_ledger", "dumpstate");
    rom_seed_ledger_test_reset_global();

    TEST("dump_state_json is well-formed even before any global open") {
        struct json_value out;
        json_init(&out);
        ASSERT(rom_seed_ledger_dump_state_json(&out, NULL));
        ASSERT(out.type == JSON_OBJ);
        const struct json_value *rows = json_get(&out, "rows");
        ASSERT(rows != NULL);
        const struct json_value *health = json_get(&out, "_health");
        ASSERT(health && json_get_bool(json_get(health, "ok")));
        json_free(&out);
        PASS();
    } _test_next:;

    (void)dir;
    rom_seed_ledger_test_reset_global();
    return failures;
}

int test_rom_seed_ledger(void)
{
    int failures = 0;
    failures += t_open_empty_is_well_formed();
    failures += t_open_rejects_null_or_empty_datadir();
    failures += t_append_accumulates_per_artifact_totals();
    failures += t_second_artifact_tracked_independently();
    failures += t_retention_caps_to_newest_n_rows();
    failures += t_dump_state_json();
    return failures;
}
