/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Ban persistence round-trip (core/modules/net/src/net.c ban_db_write()/
 * ban_db_read(); ban_addr()/unban_addr()/clear_banned() persist to
 * <datadir>/banlist.dat whenever net_manager::datadir is set). Coverage:
 *   1. ban -> reload in a FRESH net_manager -> still banned.
 *   2. an already-expired ban is neither persisted live nor resurrected.
 *   3. unban_addr() persists too.
 *   4. a missing banlist.dat is a clean cold-start miss (false, not an error).
 *   5. a corrupt banlist.dat is quarantined and read as "no persisted bans".
 *   6. the in-memory table is capped at NET_BAN_TABLE_MAX: an auto-ban flood
 *      through the real scoring path evicts the soonest-expiring auto entry
 *      and never aborts.
 *   7. a manual ban survives such a flood; writes the AUTO debounce held back
 *      are flushed by net_manager_free().
 *   8. with only manual entries left, an auto insert is refused.
 *   9. every mutation site moves the generation counter; is_banned()'s lazy
 *      prune does not.
 *  10. a ban landing DURING a banlist.dat write survives that write and a
 *      simulated restart (the dirty flag is not cleared past the snapshot).
 *  11. concurrent writers serialize on the single-flight write mutex and
 *      leave the file equal to the live table.
 *  12. ban_addr_ex(): offset <= 0 means 24h, a positive offset is relative;
 *      a re-ban never shortens a ban and overwrites score and reason.
 *  13. ban_db_read(): NULL arguments refuse; a round trip keeps ban_until,
 *      score_at_ban, reason and prefix_len; rows past the cap are dropped.
 *  14. peer_misbehaving(): NULL and non-positive inputs, trusted peers are
 *      no-ops; the threshold bans a routable peer once for 24h.
 *
 * One TEST()/ASSERT() block per function (TEST uses a fixed `_test_next:`
 * goto label; see test/test_core.h).
 */

#include "test/test_core.h"
#include "net/net.h"
#include "net/peer_scoring.h"
#include "core/utiltime.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

static int test_nbp_generation_contract(void)
{
    int failures = 0;
    TEST("ban_db: every mutation site moves the generation; lazy prune does not") {
        struct net_manager nm;
        net_manager_init(&nm); /* no datadir: this is about the counter */

        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 0);

        struct net_addr a = nbp_addr(203, 0, 113, 20);
        struct net_addr b = nbp_addr(203, 0, 113, 21);

        /* Insert. */
        nbp_ban_day(&nm, a);
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 1);

        /* Extend (re-ban of the same address). */
        nbp_ban_day(&nm, a);
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 2);

        /* An insert of an already-expired ban is still a mutation. */
        ban_addr(&nm, &b, 1, true);
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 3);

        /* is_banned()'s lazy prune drops the expired row — deliberately
         * NOT a bump: it only removes rows the next write would skip, so
         * it must never hold a write back from clearing the dirty flag. */
        ASSERT(!is_banned(&nm, &b));
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 3);
        ASSERT(is_banned(&nm, &a));

        /* Unban swap-remove. */
        ASSERT(unban_addr(&nm, &a));
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 4);

        /* Clear, and the no-op clear of an empty table. */
        nbp_ban_day(&nm, a);
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 5);
        clear_banned(&nm);
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 6);
        ASSERT(nm.num_banned == 0);
        clear_banned(&nm);
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, 6);

        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

/* Writer thread for the lost-update regression: one whole-table write, with
 * the flush state sampled after it returns. Read by main only after
 * pthread_join(), so plain stores are enough. */
static struct ban_db_flush_state g_nbp_race_after;

struct nbp_snapshot_rendezvous {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool reached;
    bool proceed;
};

static void nbp_after_snapshot(void *ctx_)
{
    struct nbp_snapshot_rendezvous *ctx = ctx_;
    pthread_mutex_lock(&ctx->mutex);
    ctx->reached = true;
    pthread_cond_broadcast(&ctx->cond);
    while (!ctx->proceed)
        pthread_cond_wait(&ctx->cond, &ctx->mutex);
    pthread_mutex_unlock(&ctx->mutex);
}

static void *nbp_write_once(void *arg)
{
    struct net_manager *nm = (struct net_manager *)arg;
    ban_db_write(nm, nm->datadir);
    g_nbp_race_after = ban_db_flush_state_read(nm);
    return NULL;
}

static int test_nbp_ban_during_write_survives_restart(void)
{
    int failures = 0;
    TEST("ban_db: a ban landing during a write survives that write and a restart") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_ban_persistence", "race");
        nbp_default_scoring();
        struct net_manager nm;
        net_manager_init(&nm);
        nm.datadir = dir;

        /* Ground truth on disk first: manual bans always write through,
         * leaving the table clean (dirty false) and the debounce clock
         * freshly stamped for the auto ban below. */
        for (size_t i = 0; i < 48; i++)
            nbp_ban_day(&nm, nbp_flood_addr(i));
        ASSERT(!nm.ban_db_dirty);
        const uint64_t gen_before = ban_db_flush_state_read(&nm).generation;

        struct nbp_snapshot_rendezvous rendezvous = {
            .mutex = PTHREAD_MUTEX_INITIALIZER,
            .cond = PTHREAD_COND_INITIALIZER,
            .reached = false,
            .proceed = false,
        };
        nm.ban_db_after_snapshot_test_hook = nbp_after_snapshot;
        nm.ban_db_after_snapshot_test_ctx = &rendezvous;

        /* The writer stops after copying the table but before installing
         * it.  This observes the exact flight window, independent of mutex
         * wake order or scheduler load. */
        pthread_t writer;
        ASSERT(pthread_create(&writer, NULL, nbp_write_once, &nm) == 0);
        pthread_mutex_lock(&rendezvous.mutex);
        while (!rendezvous.reached)
            pthread_cond_wait(&rendezvous.cond, &rendezvous.mutex);
        pthread_mutex_unlock(&rendezvous.mutex);

        /* THE RACE: ban a fresh address as an AUTO ban while the write is
         * in flight. AUTO keeps the debounce from writing it behind our
         * back, so the in-flight file is the only writer racing us. */
        struct net_addr racer = nbp_addr(203, 0, 113, 99);
        struct p2p_node node;
        nbp_flood_node(&node, racer);
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "race");
        const bool racer_banned = is_banned(&nm, &racer);

        pthread_mutex_lock(&rendezvous.mutex);
        rendezvous.proceed = true;
        pthread_cond_broadcast(&rendezvous.cond);
        pthread_mutex_unlock(&rendezvous.mutex);
        pthread_join(writer, NULL);
        nm.ban_db_after_snapshot_test_hook = NULL;
        nm.ban_db_after_snapshot_test_ctx = NULL;
        pthread_cond_destroy(&rendezvous.cond);
        pthread_mutex_destroy(&rendezvous.mutex);
        ASSERT(racer_banned);

        /* Exactly one mutation happened (the racer), and the write
         * serialized the table as it was BEFORE it: the rendezvous observed
         * snapshot completion before the racer was inserted, so the file it
         * installed cannot contain the racer. */
        ASSERT_EQ((int)ban_db_flush_state_read(&nm).generation, (int)gen_before + 1);
        struct net_manager probe;
        net_manager_init(&probe);
        ASSERT(ban_db_read(&probe, dir));
        ASSERT(!is_banned(&probe, &racer));
        net_manager_free(&probe);

        /* The write must NOT report the table clean: the racer moved the
         * generation past the write's snapshot, so the dirty flag is what
         * gets the racer flushed before a restart. */
        ASSERT(g_nbp_race_after.dirty);

        /* Simulated restart: the destroy flush honours the dirty flag, and
         * the reloaded table still bans the racer. */
        net_manager_free(&nm);
        struct net_manager nm2;
        net_manager_init(&nm2);
        ASSERT(ban_db_read(&nm2, dir));
        ASSERT(is_banned(&nm2, &racer));
        net_manager_free(&nm2);
        PASS();
    } _test_next:;
    return failures;
}

static void *nbp_write_loop(void *arg)
{
    struct net_manager *nm = (struct net_manager *)arg;
    for (int i = 0; i < 8; i++)
        ban_db_write(nm, nm->datadir);
    return NULL;
}

static int test_nbp_concurrent_writes_stay_complete(void)
{
    int failures = 0;
    TEST("ban_db: concurrent writers serialize; the file ends equal to the live table") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_ban_persistence", "storm");
        struct net_manager nm;
        net_manager_init(&nm);
        nm.datadir = dir;

        for (size_t i = 0; i < 32; i++)
            nbp_ban_day(&nm, nbp_flood_addr(i));

        /* Four flushers over one table while the main thread keeps
         * mutating: without the single-flight write mutex two writers can
         * install out of order and an older snapshot can land last. */
        pthread_t writers[4];
        for (size_t t = 0; t < 4; t++)
            ASSERT(pthread_create(&writers[t], NULL, nbp_write_loop, &nm) == 0);
        for (size_t i = 32; i < 64; i++)
            nbp_ban_day(&nm, nbp_flood_addr(i));
        for (size_t t = 0; t < 4; t++)
            pthread_join(writers[t], NULL);

        /* The final flush — the same thing the destroy flush does — must
         * leave the file carrying every live ban. */
        ASSERT(ban_db_write(&nm, dir));
        net_manager_free(&nm);

        struct net_manager nm2;
        net_manager_init(&nm2);
        ASSERT(ban_db_read(&nm2, dir));
        ASSERT_EQ((int)nm2.num_banned, 64);
        ASSERT(nbp_banned(&nm2, nbp_flood_addr(0)));
        ASSERT(nbp_banned(&nm2, nbp_flood_addr(63)));
        net_manager_free(&nm2);
        PASS();
    } _test_next:;
    return failures;
}

/* Entry of the table for `addr`, or NULL. */
static const struct ban_entry *nbp_entry(const struct net_manager *nm,
                                         struct net_addr addr)
{
    for (size_t i = 0; i < nm->num_banned; i++)
        if (net_addr_eq(&nm->banned[i].addr, &addr))
            return &nm->banned[i];
    return NULL;
}

static int test_nbp_ban_default_and_relative_expiry(void)
{
    int failures = 0;
    TEST("ban_addr_ex: offset <= 0 means 24h; a positive offset is relative to now") {
        struct net_manager nm;
        net_manager_init(&nm);
        struct net_addr zero = nbp_addr(203, 0, 113, 30);
        struct net_addr rel = nbp_addr(203, 0, 113, 31);

        const int64_t t0 = GetTime();
        ban_addr(&nm, &zero, 0, false);
        ban_addr(&nm, &rel, 3600, false);
        const int64_t t1 = GetTime();

        const struct ban_entry *z = nbp_entry(&nm, zero);
        const struct ban_entry *r = nbp_entry(&nm, rel);
        ASSERT(z != NULL);
        ASSERT(r != NULL);
        ASSERT(z->ban_until >= t0 + 24 * 60 * 60);
        ASSERT(z->ban_until <= t1 + 24 * 60 * 60);
        ASSERT(r->ban_until >= t0 + 3600);
        ASSERT(r->ban_until <= t1 + 3600);
        /* Manual bans: score 0, reason "manual", IPv4 prefix 32. */
        ASSERT_EQ((int)z->score_at_ban, 0);
        ASSERT(strcmp(z->reason, "manual") == 0);
        ASSERT_EQ((int)z->prefix_len, 32);

        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_reban_extends_only_and_overwrites_metadata(void)
{
    int failures = 0;
    TEST("ban_addr_ex: a re-ban never shortens; score and reason are overwritten") {
        nbp_default_scoring();
        struct net_manager nm;
        net_manager_init(&nm); /* no datadir: in-memory only */

        struct net_addr a = nbp_addr(203, 0, 113, 32);
        ban_addr(&nm, &a, 3600, false);
        const int64_t first = nbp_entry(&nm, a)->ban_until;

        /* Shorter window: the existing, longer ban stands. */
        ban_addr(&nm, &a, 60, false);
        ASSERT(nbp_entry(&nm, a)->ban_until == first);
        ASSERT_EQ((int)nm.num_banned, 1);

        /* Longer window: the ban is extended. */
        ban_addr(&nm, &a, 7200, false);
        ASSERT(nbp_entry(&nm, a)->ban_until > first);
        ASSERT_EQ((int)nm.num_banned, 1);

        /* Scored re-ban: score_at_ban and reason are overwritten, the
         * entry count does not grow. */
        struct p2p_node node;
        nbp_flood_node(&node, a);
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "flood");
        const struct ban_entry *e = nbp_entry(&nm, a);
        ASSERT(e != NULL);
        ASSERT_EQ((int)e->score_at_ban, 100);
        ASSERT(strcmp(e->reason, "invalid_block: flood") == 0);
        ASSERT_EQ((int)nm.num_banned, 1);

        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_ban_db_read_null_args(void)
{
    int failures = 0;
    TEST("ban_db_read: NULL manager or NULL datadir refuses without touching state") {
        struct net_manager nm;
        net_manager_init(&nm);
        ASSERT(!ban_db_read(NULL, "/unused"));
        ASSERT(!ban_db_read(&nm, NULL));
        ASSERT_EQ((int)nm.num_banned, 0);
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_ban_db_round_trip_keeps_metadata(void)
{
    int failures = 0;
    TEST("ban_db: round trip keeps ban_until, score_at_ban, reason and prefix") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_ban_persistence", "roundtrip");
        nbp_default_scoring();
        struct net_manager nm;
        net_manager_init(&nm);
        nm.datadir = dir;

        struct net_addr manual = nbp_addr(203, 0, 113, 60);
        struct net_addr scored = nbp_addr(203, 0, 113, 61);
        ban_addr(&nm, &manual, 3600, false);
        struct p2p_node node;
        nbp_flood_node(&node, scored);
        peer_scoring_record(&nm, &node, PEER_OFFENCE_INVALID_BLOCK, "flood");
        const int64_t until_manual = nbp_entry(&nm, manual)->ban_until;
        const int64_t until_scored = nbp_entry(&nm, scored)->ban_until;
        net_manager_free(&nm); /* flushes any debounced auto write */

        struct net_manager nm2;
        net_manager_init(&nm2);
        ASSERT(ban_db_read(&nm2, dir));
        ASSERT_EQ((int)nm2.num_banned, 2);

        const struct ban_entry *m = nbp_entry(&nm2, manual);
        ASSERT(m != NULL);
        ASSERT(m->ban_until == until_manual);
        ASSERT_EQ((int)m->score_at_ban, 0);
        ASSERT(strcmp(m->reason, "manual") == 0);
        ASSERT_EQ((int)m->prefix_len, 32);

        const struct ban_entry *s = nbp_entry(&nm2, scored);
        ASSERT(s != NULL);
        ASSERT(s->ban_until == until_scored);
        ASSERT_EQ((int)s->score_at_ban, 100);
        ASSERT(strcmp(s->reason, "invalid_block: flood") == 0);
        net_manager_free(&nm2);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_ban_db_read_drops_rows_past_cap(void)
{
    int failures = 0;
    TEST("ban_db_read: rows past the in-memory cap are dropped; the load still succeeds") {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "net_ban_persistence", "cap_drop");
        struct net_addr persisted = nbp_addr(203, 0, 113, 50);
        struct net_manager writer;
        net_manager_init(&writer);
        writer.datadir = dir;
        ban_addr(&writer, &persisted, 3600, false);
        net_manager_free(&writer);

        /* Fill a manager to the cap with manual bans (no datadir) so the
         * persisted row has no free slot. */
        struct net_manager nm;
        net_manager_init(&nm);
        for (size_t i = 0; i < NET_BAN_TABLE_MAX; i++)
            nbp_ban_day(&nm, nbp_flood_addr(i));
        ASSERT_EQ((int)nm.num_banned, NET_BAN_TABLE_MAX);

        ASSERT(ban_db_read(&nm, dir));
        ASSERT_EQ((int)nm.num_banned, NET_BAN_TABLE_MAX);
        ASSERT(!nbp_banned(&nm, persisted));
        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

static int test_nbp_peer_misbehaving_branches(void)
{
    int failures = 0;
    TEST("peer_misbehaving: no-op inputs and trusted peers; threshold bans a routable peer once") {
        nbp_default_scoring();
        struct net_manager nm;
        net_manager_init(&nm); /* no datadir */
        const int64_t t0 = GetTime();

        struct net_addr routable = nbp_addr(203, 0, 113, 40);
        struct p2p_node node;
        nbp_flood_node(&node, routable);

        peer_misbehaving(NULL, &node, 100, "null manager");
        peer_misbehaving(&nm, NULL, 100, "null node");
        peer_misbehaving(&nm, &node, 0, "zero");
        peer_misbehaving(&nm, &node, -5, "negative");
        ASSERT_EQ((int)node.misbehavior, 0);
        ASSERT(!node.disconnect);
        ASSERT_EQ((int)nm.num_banned, 0);

        /* Below the threshold: scored, not banned, not disconnected. */
        peer_misbehaving(&nm, &node, 50, "half");
        ASSERT_EQ((int)node.misbehavior, 50);
        ASSERT(!node.disconnect);
        ASSERT_EQ((int)nm.num_banned, 0);

        /* At the threshold: disconnected and address-banned for 24h. */
        peer_misbehaving(&nm, &node, 50, "pinned");
        ASSERT_EQ((int)node.misbehavior, 100);
        ASSERT(node.disconnect);
        ASSERT(nbp_banned(&nm, routable));
        const struct ban_entry *e = nbp_entry(&nm, routable);
        ASSERT(e != NULL);
        ASSERT_EQ((int)e->score_at_ban, 100);
        ASSERT(strcmp(e->reason, "pinned") == 0);
        ASSERT(e->ban_until >= t0 + 24 * 60 * 60);
        ASSERT_EQ((int)nm.num_banned, 1);

        /* A whitelisted peer is never scored. */
        struct net_addr white = nbp_addr(203, 0, 113, 41);
        struct p2p_node trusted;
        nbp_flood_node(&trusted, white);
        trusted.whitelisted = true;
        peer_misbehaving(&nm, &trusted, 100, "whitelisted");
        ASSERT_EQ((int)trusted.misbehavior, 0);
        ASSERT(!trusted.disconnect);
        ASSERT(!nbp_banned(&nm, white));

        /* Loopback is trusted, so it is never scored or banned. */
        struct net_addr lo = nbp_addr(127, 0, 0, 1);
        struct p2p_node local;
        nbp_flood_node(&local, lo);
        peer_misbehaving(&nm, &local, 100, "loopback");
        ASSERT_EQ((int)local.misbehavior, 0);
        ASSERT(!nbp_banned(&nm, lo));

        net_manager_free(&nm);
        PASS();
    } _test_next:;
    return failures;
}

int test_net_ban_persistence(void);
int test_net_ban_persistence(void)
{
    int failures = 0;
    failures += test_nbp_ban_default_and_relative_expiry();
    failures += test_nbp_reban_extends_only_and_overwrites_metadata();
    failures += test_nbp_ban_db_read_null_args();
    failures += test_nbp_ban_db_round_trip_keeps_metadata();
    failures += test_nbp_ban_db_read_drops_rows_past_cap();
    failures += test_nbp_peer_misbehaving_branches();
    failures += test_nbp_ban_reload_still_banned();
    failures += test_nbp_expired_ban_not_resurrected();
    failures += test_nbp_unban_persists();
    failures += test_nbp_missing_file_clean_miss();
    failures += test_nbp_corrupt_file_quarantined();
    failures += test_nbp_flood_caps_table();
    failures += test_nbp_manual_ban_survives_flood();
    failures += test_nbp_full_manual_table_refuses_auto();
    failures += test_nbp_generation_contract();
    failures += test_nbp_ban_during_write_survives_restart();
    failures += test_nbp_concurrent_writes_stay_complete();
    return failures;
}
