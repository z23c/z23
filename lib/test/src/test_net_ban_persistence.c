/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ban persistence round-trip (lib/net/src/net.c: ban_db_write()/
 * ban_db_read(), and ban_addr()/unban_addr()/clear_banned() auto-
 * persisting to <datadir>/banlist.dat whenever net_manager::datadir is
 * set — see connman_load_addrman()/connman_save_addrman() in connman.c
 * for how that field gets populated at boot).
 *
 * Before this, nm->banned[] was purely in-memory: any restart amnestied
 * every banned attacker. Coverage:
 *   1. ban -> reload in a FRESH net_manager -> still banned.
 *   2. expiry: an already-expired ban is neither persisted live nor
 *      resurrected on reload (lazy prune, both in is_banned() and at
 *      ban_db_write()/ban_db_read() time).
 *   3. unban_addr() persists too — a reload after unban does not
 *      resurrect the address.
 *   4. a missing banlist.dat is a clean cold-start miss (false, not an
 *      error) — matches addr_db_read()'s existing convention.
 *   5. a corrupt banlist.dat is quarantined and treated as "no
 *      persisted bans" rather than crashing boot (bans are advisory
 *      hardening, never fatal to boot).
 *   6. the in-memory table is hard-capped at NET_BAN_TABLE_MAX: an
 *      auto-ban flood driven through the REAL scoring path evicts the
 *      soonest-expiring auto entry instead of growing, and never aborts.
 *   7. a manual ban made before such a flood survives it (manual entries
 *      are never evicted), and the writes the AUTO debounce held back are
 *      flushed by net_manager_free().
 *   8. with only manual entries left, an auto insert is refused and the
 *      table is left unchanged.
 *
 * One TEST()/ASSERT() block per function — this codebase's TEST macro
 * uses a single fixed `_test_next:` goto label per function (see
 * test/test_core.h), so more than one TEST block in the same
 * function is a duplicate-label compile error.
 */

#include "test/test_core.h"
#include "net/net.h"
#include "net/peer_scoring.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct net_addr nbp_addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    struct net_addr addr;
    net_addr_init(&addr);
    unsigned char ip4[4] = {a, b, c, d};
    net_addr_set_ipv4(&addr, ip4);
    return addr;
}

/* Distinct address #i, byte-wise, inside the documentation-only TEST-NET-3
 * range — never routed, and nothing in the ban path cares about
 * routability. */
static struct net_addr nbp_flood_addr(size_t i)
{
    return nbp_addr(203, 0, (uint8_t)(i >> 8), (uint8_t)(i & 0xff));
}

/* Minimal stack peer for the real scoring path, mirroring the fixture
 * idiom in test_peer_scoring.c: peer_misbehaving() reads only the
 * address, the whitelist flag and the atomic score off the node. */
static void nbp_flood_node(struct p2p_node *node, struct net_addr addr)
{
    memset(node, 0, sizeof(*node));
    snprintf(node->addr_name, sizeof(node->addr_name), "ban_flood");
    node->addr.svc.addr = addr;
}

/* The flood must measure THIS code's behaviour, not whatever threshold the
 * operator's environment left behind: default 100 score, one 100-weight
 * offence per fresh node, one auto-ban per call. */
static void nbp_default_scoring(void)
{
    unsetenv("ZCL_PEER_BAN_THRESHOLD");
    unsetenv("ZCL_PEER_BAN_HOURS");
    peer_scoring_init();
}

/* By-value wrappers: nbp_flood_addr() yields an rvalue and the ban APIs
 * take addresses, so these keep every call site to one readable line. */
static void nbp_ban_day(struct net_manager *nm, struct net_addr addr)
{
    ban_addr(nm, &addr, 24 * 60 * 60, false);
}

static bool nbp_banned(struct net_manager *nm, struct net_addr addr)
{
    return is_banned(nm, &addr);
}

static int test_nbp_ban_reload_still_banned(void)
{
    int failures = 0;
    TEST("ban_db: ban -> reload in a fresh net_manager -> still banned") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_ban_persistence", "main");

        struct net_manager nm;
        net_manager_init(&nm);
        nm.datadir = dir;

        struct net_addr addr = nbp_addr(203, 0, 113, 5);
        ban_addr(&nm, &addr, 3600, false);
        ASSERT(is_banned(&nm, &addr));

        struct net_manager nm2;
        net_manager_init(&nm2);
        bool loaded = ban_db_read(&nm2, dir);
        ASSERT(loaded);
        ASSERT(is_banned(&nm2, &addr));

        net_manager_free(&nm);
        net_manager_free(&nm2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_expired_ban_not_resurrected(void)
{
    int failures = 0;
    TEST("ban_db: expired ban is not resurrected — live prune and reload skip") {
        char edir[256];
        test_make_tmpdir(edir, sizeof(edir), "net_ban_persistence", "expiry");
        struct net_manager nm;
        net_manager_init(&nm);
        nm.datadir = edir;

        struct net_addr live = nbp_addr(203, 0, 113, 6);
        struct net_addr expired = nbp_addr(203, 0, 113, 7);
        ban_addr(&nm, &live, 3600, false);
        /* since_epoch=true, ban_offset=1 -> ban_until=1 (1970-01-01),
         * already expired relative to any real wall-clock "now". */
        ban_addr(&nm, &expired, 1, true);

        /* is_banned() lazily prunes expired entries as it scans. */
        ASSERT(!is_banned(&nm, &expired));
        ASSERT(is_banned(&nm, &live));

        struct net_manager nm2;
        net_manager_init(&nm2);
        ASSERT(ban_db_read(&nm2, edir));
        ASSERT(!is_banned(&nm2, &expired));
        ASSERT(is_banned(&nm2, &live));

        net_manager_free(&nm);
        net_manager_free(&nm2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_unban_persists(void)
{
    int failures = 0;
    TEST("ban_db: unban_addr persists — reload does not resurrect") {
        char udir[256];
        test_make_tmpdir(udir, sizeof(udir), "net_ban_persistence", "unban");
        struct net_manager nm;
        net_manager_init(&nm);
        nm.datadir = udir;

        struct net_addr addr = nbp_addr(203, 0, 113, 8);
        ban_addr(&nm, &addr, 3600, false);
        ASSERT(is_banned(&nm, &addr));
        ASSERT(unban_addr(&nm, &addr));
        ASSERT(!is_banned(&nm, &addr));

        struct net_manager nm2;
        net_manager_init(&nm2);
        /* Whether or not a (now-empty) banlist.dat exists on disk, the
         * address must not come back banned. */
        (void)ban_db_read(&nm2, udir);
        ASSERT(!is_banned(&nm2, &addr));

        net_manager_free(&nm);
        net_manager_free(&nm2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_missing_file_clean_miss(void)
{
    int failures = 0;
    TEST("ban_db: missing file is a clean cold-start miss, not an error") {
        char empty_dir[256];
        test_make_tmpdir(empty_dir, sizeof(empty_dir), "net_ban_persistence", "empty");
        struct net_manager nm;
        net_manager_init(&nm);
        ASSERT(!ban_db_read(&nm, empty_dir));
        ASSERT(nm.num_banned == 0);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_corrupt_file_quarantined(void)
{
    int failures = 0;
    TEST("ban_db: corrupt banlist.dat is quarantined, not fatal to boot") {
        char cdir[256];
        test_make_tmpdir(cdir, sizeof(cdir), "net_ban_persistence", "corrupt");
        char path[512];
        snprintf(path, sizeof(path), "%s/banlist.dat", cdir);
        FILE *f = fopen(path, "wb");
        ASSERT(f != NULL);
        const char *garbage = "not a valid banlist.dat body, just junk bytes";
        fwrite(garbage, 1, strlen(garbage), f);
        fclose(f);

        struct net_manager nm;
        net_manager_init(&nm);
        bool loaded = ban_db_read(&nm, cdir);
        ASSERT(!loaded);
        ASSERT(nm.num_banned == 0);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_flood_caps_table(void)
{
    int failures = 0;
    TEST("ban table: an auto-ban flood past the cap evicts the oldest entry, never aborts") {
        nbp_default_scoring();
        struct net_manager nm;
        net_manager_init(&nm); /* no datadir: pure in-memory eviction */

        struct p2p_node node;
        /* Cap + 1 inserts through the real scoring path: one fresh,
         * threshold-crossing peer per call. */
        for (size_t i = 0; i <= NET_BAN_TABLE_MAX; i++) {
            nbp_flood_node(&node, nbp_flood_addr(i));
            peer_scoring_record(&nm, &node,
                                PEER_OFFENCE_INVALID_BLOCK, "flood");
        }

        /* Never grew past the cap, and the flood never aborted. */
        ASSERT_EQ((int)nm.num_banned, NET_BAN_TABLE_MAX);
        /* The oldest auto ban is gone; recent ones still answer. */
        ASSERT(!nbp_banned(&nm, nbp_flood_addr(0)));
        ASSERT(nbp_banned(&nm, nbp_flood_addr(1)));
        ASSERT(nbp_banned(&nm, nbp_flood_addr(NET_BAN_TABLE_MAX / 2)));
        ASSERT(nbp_banned(&nm, nbp_flood_addr(NET_BAN_TABLE_MAX)));

        /* The capped table still accepts work: re-banning the evicted
         * address takes the next-soonest slot instead of failing. */
        nbp_flood_node(&node, nbp_flood_addr(0));
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "flood");
        ASSERT(nbp_banned(&nm, nbp_flood_addr(0)));
        ASSERT_EQ((int)nm.num_banned, NET_BAN_TABLE_MAX);

        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_manual_ban_survives_flood(void)
{
    int failures = 0;
    TEST("ban table: a manual ban survives an auto-ban flood; debounce flushes at destroy") {
        nbp_default_scoring();
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_ban_persistence", "manual_flood");
        struct net_manager nm;
        net_manager_init(&nm);
        nm.datadir = dir;

        struct net_addr manual = nbp_addr(198, 51, 100, 7);
        nbp_ban_day(&nm, manual);
        ASSERT(is_banned(&nm, &manual));
        /* A manual write is never debounced — nothing held back. */
        ASSERT(!nm.ban_db_dirty);

        struct p2p_node node;
        /* The manual entry holds one slot, so this flood evicts exactly
         * one AUTO entry — never the manual one. */
        for (size_t i = 0; i < NET_BAN_TABLE_MAX; i++) {
            nbp_flood_node(&node, nbp_flood_addr(i));
            peer_scoring_record(&nm, &node,
                                PEER_OFFENCE_INVALID_BLOCK, "flood");
        }

        ASSERT_EQ((int)nm.num_banned, NET_BAN_TABLE_MAX);
        ASSERT(is_banned(&nm, &manual));
        ASSERT(nbp_banned(&nm, nbp_flood_addr(NET_BAN_TABLE_MAX - 1)));
        ASSERT(!nbp_banned(&nm, nbp_flood_addr(0)));
        /* Every AUTO write inside the debounce window was held back, not
         * serialized to disk. */
        ASSERT(nm.ban_db_dirty);

        /* Destroy flushes what the debounce held back, so a reload sees
         * the same table — manual entry still on it. */
        net_manager_free(&nm);
        struct net_manager nm2;
        net_manager_init(&nm2);
        ASSERT(ban_db_read(&nm2, dir));
        ASSERT(is_banned(&nm2, &manual));
        ASSERT(nbp_banned(&nm2, nbp_flood_addr(NET_BAN_TABLE_MAX - 1)));
        ASSERT(!nbp_banned(&nm2, nbp_flood_addr(0)));

        net_manager_free(&nm2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_full_manual_table_refuses_auto(void)
{
    int failures = 0;
    TEST("ban table: a full table of manual entries refuses the auto insert, unchanged") {
        nbp_default_scoring();
        struct net_manager nm;
        net_manager_init(&nm); /* no datadir: manual inserts stay in memory */

        /* Fill the table with MANUAL bans (score_at_ban == 0) — these are
         * never eviction candidates. */
        for (size_t i = 0; i < NET_BAN_TABLE_MAX; i++)
            nbp_ban_day(&nm, nbp_flood_addr(i));
        ASSERT_EQ((int)nm.num_banned, NET_BAN_TABLE_MAX);

        /* An attacker provoking one more auto ban must not displace an
         * operator's entry: the insert is refused, table unchanged. */
        struct net_addr refused = nbp_addr(203, 0, 9, 9);
        struct p2p_node node;
        nbp_flood_node(&node, refused);
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "flood");
        ASSERT(!is_banned(&nm, &refused));
        ASSERT_EQ((int)nm.num_banned, NET_BAN_TABLE_MAX);
        /* ...and the operator's bans are all still here. */
        ASSERT(nbp_banned(&nm, nbp_flood_addr(0)));
        ASSERT(nbp_banned(&nm, nbp_flood_addr(NET_BAN_TABLE_MAX - 1)));

        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

int test_net_ban_persistence(void);
int test_net_ban_persistence(void)
{
    int failures = 0;
    failures += test_nbp_ban_reload_still_banned();
    failures += test_nbp_expired_ban_not_resurrected();
    failures += test_nbp_unban_persists();
    failures += test_nbp_missing_file_clean_miss();
    failures += test_nbp_corrupt_file_quarantined();
    failures += test_nbp_flood_caps_table();
    failures += test_nbp_manual_ban_survives_flood();
    failures += test_nbp_full_manual_table_refuses_auto();
    return failures;
}
