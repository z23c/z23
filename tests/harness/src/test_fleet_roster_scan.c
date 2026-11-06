/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_fleet_roster_scan -- the roster scan's rotating window over unproven
 * lines. A stand-in provider accepts a line spelled "G<n>" and refuses any
 * other, so the page sizes here are the real ones and the seals are not. The
 * stored rows are signed board notes; nothing here reads a clock. */

#include "test/test_core.h"
#include "config/boot_fleet_roster.h"
#include "crypto/ed25519.h"
#include "models/database.h"
#include "models/fleet_board_post.h"
#include "util/fleet_roster_check.h"
#include "util/fleet_role_check.h"

#include <stdio.h>
#include <string.h>

#define FRS_NOW INT64_C(1800000000)
#define FRS_NEWEST (BOOT_FLEET_ROSTER_SCAN_ROWS / 2)

static bool frs_root_cb(uint8_t root[32], bool *present, bool *manager,
                        void *ctx)
{
    (void)ctx;
    memset(root, 0x71, 32);
    *present = true;
    *manager = false;
    return true;
}

/* "G<n>" is sealed and names the key of n; anything else is not sealed. */
static bool frs_verify_cb(const char *line, const uint8_t root[32],
                          enum zcl_fleet_root_state state, bool require,
                          uint8_t signer[32], uint8_t box[32], bool *sealed,
                          const char **why, void *ctx)
{
    (void)root; (void)state; (void)require; (void)ctx;
    *sealed = line[0] == 'G';
    if (!*sealed) {
        *why = "fleetboard.roster_signature_invalid";
        return false;
    }
    memset(signer, atoi(line + 1) & 0xff, 32);
    memset(box, 0xee, 32);
    return true;
}

static void frs_install(void)
{
    static const struct zcl_fleet_roster_provider provider = {
        .root = frs_root_cb, .verify = frs_verify_cb,
        .name = "fleet-roster-scan-test" };
    zcl_fleet_role_checker_install_permissive_for_testing();
    zcl_fleet_roster_provider_install(&provider);
    boot_fleet_roster_test_reset();
}

static void frs_key(int n, uint8_t key[32])
{
    memset(key, n & 0xff, 32);
}

/* One stored roster-shaped row; later calls are newer in the scan's order. */
static bool frs_store(struct node_db *db, int author, const char *text)
{
    uint8_t seed[32] = {0}, pk[32], sk[32];
    struct fleet_board_post p;
    seed[0] = (uint8_t)author;
    seed[31] = (uint8_t)(0xa0 + author);
    ed25519_keypair(pk, sk, seed);
    memcpy(seed, sk, 32);
    memset(&p, 0, sizeof p);
    p.kind = FLEET_BOARD_KIND_NOTE;
    p.created_at = (uint64_t)FRS_NOW;
    p.ttl = FLEET_BOARD_TTL_MAX;
    p.scope = FLEET_BOARD_SCOPE_FLEET;
    (void)snprintf(p.agent, sizeof p.agent, "%s", BOOT_FLEET_ROSTER_AGENT);
    p.text_len = (uint32_t)snprintf(p.text, sizeof p.text, "%s", text);
    bool ok = fleet_board_post_sign(&p, seed, pk) == FLEET_BOARD_OK &&
              db_fleet_board_post_ingest(db, &p, FRS_NOW, NULL) ==
                  FLEET_BOARD_OK;
    boot_fleet_roster_invalidate();
    return ok;
}

static enum boot_fleet_roster_verdict frs_check(struct node_db *db, int n)
{
    uint8_t key[32];
    frs_key(n, key);
    boot_fleet_roster_invalidate();
    return boot_fleet_roster_check(db, key, FRS_NOW + 1000);
}

/* Genuine lines are G<id> with id >= 1; ids stand for members. Lines newest
 * first: `slot[nth]` is the id of the genuine line at that place, 0 for junk. */
static bool frs_fill(struct node_db *db, int total, const int *at,
                     const int *id, size_t n_at)
{
    for (int nth = total - 1; nth >= 0; nth--) {
        char text[24];
        int who = 0;
        for (size_t i = 0; i < n_at; i++)
            if (at[i] == nth)
                who = id[i];
        if (who)
            (void)snprintf(text, sizeof text, "G%d", who);
        else
            (void)snprintf(text, sizeof text, "J%d", nth);
        if (!frs_store(db, 40 + nth / 50, text))
            return false;
    }
    return true;
}

static int test_fleet_roster_scan_offset(void)
{
    int failures = 0;
    struct node_db db;
    bool open = false;
    memset(&db, 0, sizeof db);
    TEST("fleet roster scan: lines a rebuild proves do not move the next "
         "window past a genuine line just beyond it") {
        enum { TOTAL = BOOT_FLEET_ROSTER_SCAN_ROWS + 20, JUST_PAST =
               BOOT_FLEET_ROSTER_SCAN_ROWS };
        /* Three proved among the newest, three in the tail window, and the
         * target the first line the first rebuild does not reach. */
        const int at[] = { 10, 20, 30, FRS_NEWEST + 5, FRS_NEWEST + 50,
                           FRS_NEWEST + 90, JUST_PAST };
        const int id[] = { 1, 2, 3, 4, 5, 6, 7 };
        struct boot_fleet_roster_counts c0, c1;
        ASSERT(node_db_open(&db, ":memory:"));
        open = true;
        frs_install();
        ASSERT(frs_fill(&db, TOTAL, at, id, 7));
        boot_fleet_roster_counts(&c0);
        ASSERT_EQ(frs_check(&db, 1), BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c1);
        ASSERT(c1.verifies - c0.verifies <= BOOT_FLEET_ROSTER_SCAN_ROWS);
        uint8_t late[32];
        frs_key(7, late);
        ASSERT(boot_fleet_roster_check(&db, late, FRS_NOW + 1000) !=
               BOOT_FLEET_ROSTER_MEMBER);
        /* The very next rebuild reaches it. */
        boot_fleet_roster_counts(&c0);
        ASSERT_EQ(frs_check(&db, 7), BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c1);
        ASSERT(c1.verifies - c0.verifies <= BOOT_FLEET_ROSTER_SCAN_ROWS);
        PASS();
    } _test_next:;
    zcl_fleet_roster_provider_install(NULL);
    boot_fleet_roster_test_reset();
    if (open)
        node_db_close(&db);
    return failures;
}

/* A row the walk met that no longer reads back may be the very row that names
 * a member: the scan is unverifiable and keeps what it held. */
static int test_fleet_roster_scan_unreadable(void)
{
    int failures = 0;
    struct node_db db;
    bool open = false;
    memset(&db, 0, sizeof db);
    TEST("fleet roster scan: a pending row that no longer reads back makes "
         "the roster unverifiable and leaves the proven lines as they were") {
        struct boot_fleet_roster_counts c0, c1;
        ASSERT(node_db_open(&db, ":memory:"));
        open = true;
        frs_install();
        ASSERT(frs_store(&db, 1, "G1"));
        ASSERT_EQ(frs_check(&db, 1), BOOT_FLEET_ROSTER_MEMBER);
        ASSERT(frs_store(&db, 2, "G2"));
        ASSERT(node_db_exec(&db, "UPDATE fleet_board_posts SET text='G9' "
                                 "WHERE text='G2'"));
        ASSERT_EQ(frs_check(&db, 1), BOOT_FLEET_ROSTER_UNVERIFIABLE);
        ASSERT_EQ(frs_check(&db, 9), BOOT_FLEET_ROSTER_UNVERIFIABLE);
        /* The row goes: the first line is still proven, with no new verify. */
        ASSERT(node_db_exec(&db, "DELETE FROM fleet_board_posts WHERE "
                                 "text='G9'"));
        boot_fleet_roster_counts(&c0);
        ASSERT_EQ(frs_check(&db, 1), BOOT_FLEET_ROSTER_MEMBER);
        boot_fleet_roster_counts(&c1);
        ASSERT_EQ(c1.verifies, c0.verifies);
        PASS();
    } _test_next:;
    zcl_fleet_roster_provider_install(NULL);
    boot_fleet_roster_test_reset();
    if (open)
        node_db_close(&db);
    return failures;
}

int test_fleet_roster_scan(void)
{
    int failures = 0;
    failures += test_fleet_roster_scan_offset();
    failures += test_fleet_roster_scan_unreadable();
    return failures;
}
