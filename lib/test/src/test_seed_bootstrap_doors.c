/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_seed_bootstrap_doors — the doors a cold node can use to reach the
 * network, and the rule that none of them may be a door that cannot open.
 *
 * WHY THIS EXISTS
 * ---------------
 * With DNS seeding deliberately off (nSeeds = 0, and it stays off — this
 * project ships zero DNS names and zero certificate authorities), a stranger's
 * only ways in are the compiled-in seed arrays, the operator's runtime
 * onion-seeds file, and whatever the node has previously learned. Three
 * measured defects made that set much smaller than it counted itself as, and
 * every one of them was INVISIBLE to the assertions that existed:
 * test_net.c's chainparams checks assert only `nFixedSeeds > 0` and
 * `nOnionSeeds > 0`, which is equally true of an array that is entirely dead.
 * Counting doors is not the same as counting doors that open.
 *
 * The three, measured 2026-08-26:
 *
 *   1. Every hardcoded IPv4 seed was added TWICE — once at the mainnet
 *      nDefaultPort and once at :18033. :18033 is testnet/regtest's
 *      nDefaultPort, so those entries were dead BY CONSTRUCTION: a listener
 *      there speaks a different pchMessageStart and could never complete a
 *      mainnet handshake. Half of nFixedSeeds was unusable, and a cold node
 *      spent half its dial budget proving it. All four :18033 probes were
 *      refused, 3/3 attempts each.
 *
 *   2. One hardcoded IPv4 seed (142.54.184.106) was refused on BOTH ports,
 *      3/3 attempts. Its "reachable" comment had gone stale.
 *
 *   3. The onion-seed array's ONE entry answered nothing: 5/5 attempts across
 *      two independent Tor clients returned SOCKS5 reply 4 (no descriptor).
 *      A Tor-only stranger therefore had no working hardcoded door at all,
 *      and paid a 60 s blocking fetch to discover that.
 *
 * WHAT IS ASSERTED HERE
 * ---------------------
 * Reachability itself is NOT asserted — it cannot be, honestly. Whether a host
 * answers depends on the network the test runs on, and a test that grades an
 * offline or Tor-less machine "fail" is measuring the harness, not the code.
 * Reachability is established out-of-band and recorded as evidence next to each
 * entry in core/chainparams/src/chainparams.c.
 *
 * What IS asserted are the structural properties that no probe can establish
 * and that silently regress: that no seed carries a port on which a mainnet
 * handshake is impossible, that no seed is double-booked, that a hostname
 * measured dead is gone, that the onion port field is genuinely per-entry, and
 * that the bootstrap no longer depends on the compiled array alone.
 */

#include "test/test_core.h"
#include "chain/chainparams.h"
#include "net/onion_service.h"
#include "net/onion_peer_merge.h"
#include "util/path_check.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DOOR_CHECK(name, expr) do {                         \
    printf("seed_bootstrap_doors: %s... ", (name));         \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

/* Hostnames and addresses measured DEAD on 2026-08-26 and removed. They are
 * named here so that re-adding one without fresh evidence fails loudly rather
 * than quietly costing the next cold node its bootstrap budget. */
static const char *const kRemovedOnion =
    "zc23kenfdqqkgamthif3m7lbbdsyrotsl2dlw35qrh3iuzopozmpjnad.onion";
static const uint8_t kRemovedIp4[4] = {142, 54, 184, 106};

static bool seed_is_ipv4_mapped(const struct seed_spec6 *s)
{
    for (int i = 0; i < 10; i++)
        if (s->addr[i] != 0) return false;
    return s->addr[10] == 0xFF && s->addr[11] == 0xFF;
}

static bool seed_ip4_equals(const struct seed_spec6 *s, const uint8_t ip[4])
{
    return seed_is_ipv4_mapped(s) && memcmp(s->addr + 12, ip, 4) == 0;
}

/* ── Half 1: the compiled-in arrays ───────────────────────────────── */

static int check_fixed_seed_ports(void)
{
    int failures = 0;

    chain_params_select(CHAIN_MAIN);
    const struct chain_params *main_p = chain_params_get();
    int main_port = main_p->nDefaultPort;

    /* Read the OTHER networks' default ports from the params themselves
     * rather than hardcoding 18033: if a network's port ever moves, this
     * check must move with it instead of silently checking a stale literal. */
    chain_params_select(CHAIN_TESTNET);
    int testnet_port = chain_params_get()->nDefaultPort;
    chain_params_select(CHAIN_REGTEST);
    int regtest_port = chain_params_get()->nDefaultPort;

    chain_params_select(CHAIN_MAIN);
    main_p = chain_params_get();

    DOOR_CHECK("mainnet still has at least one hardcoded IPv4 seed",
               main_p->nFixedSeeds > 0);

    /* (1) No mainnet seed may carry a port on which a mainnet handshake is
     * impossible. This is the assertion the double-add violated. */
    bool all_mainnet_port = true;
    bool none_foreign_port = true;
    for (size_t i = 0; i < main_p->nFixedSeeds; i++) {
        int port = main_p->vFixedSeeds[i].port;
        if (port != main_port) all_mainnet_port = false;
        if (port == testnet_port || port == regtest_port)
            none_foreign_port = false;
    }
    DOOR_CHECK("every mainnet fixed seed uses the mainnet nDefaultPort",
               all_mainnet_port);
    DOOR_CHECK("no mainnet fixed seed uses the testnet/regtest nDefaultPort",
               none_foreign_port);

    /* (2) No double-booking. Each address appears at most once: a duplicate
     * costs a real dial and can never buy a peer the first did not. */
    bool no_dupes = true;
    for (size_t i = 0; i < main_p->nFixedSeeds && no_dupes; i++)
        for (size_t j = i + 1; j < main_p->nFixedSeeds; j++)
            if (memcmp(main_p->vFixedSeeds[i].addr,
                       main_p->vFixedSeeds[j].addr, 16) == 0) {
                no_dupes = false;
                break;
            }
    DOOR_CHECK("no hardcoded IPv4 address is double-booked across ports",
               no_dupes);

    /* (3) The address measured dead is gone and stays gone. */
    bool dead_absent = true;
    for (size_t i = 0; i < main_p->nFixedSeeds; i++)
        if (seed_ip4_equals(&main_p->vFixedSeeds[i], kRemovedIp4))
            dead_absent = false;
    DOOR_CHECK("the IPv4 seed measured refused on both ports is absent",
               dead_absent);

    return failures;
}

static int check_onion_seeds(void)
{
    int failures = 0;

    chain_params_select(CHAIN_MAIN);
    const struct chain_params *p = chain_params_get();

    DOOR_CHECK("mainnet still has at least one hardcoded onion seed",
               p->nOnionSeeds > 0);

    /* Every entry is a well-formed v3 hostname. A malformed one is a
     * guaranteed-wasted 60 s blocking fetch on a cold node. */
    bool all_valid = true;
    bool dead_absent = true;
    bool all_distinct = true;
    for (size_t i = 0; i < p->nOnionSeeds; i++) {
        if (!onion_hostname_valid(p->onionSeeds[i])) all_valid = false;
        if (strcmp(p->onionSeeds[i], kRemovedOnion) == 0) dead_absent = false;
        for (size_t j = i + 1; j < p->nOnionSeeds; j++)
            if (strcmp(p->onionSeeds[i], p->onionSeeds[j]) == 0)
                all_distinct = false;
    }
    DOOR_CHECK("every hardcoded onion seed is a well-formed v3 hostname",
               all_valid);
    DOOR_CHECK("the onion seed measured unreachable 5/5 is absent",
               dead_absent);
    DOOR_CHECK("no hardcoded onion seed is listed twice", all_distinct);

    /* onionSeedPorts[] must stay a genuine PER-ENTRY array. Nothing reads it
     * today (chainparams.c writes it; no other translation unit loads it —
     * the fetch path reaches a seed by hostname over virtual port 80), so the
     * value is documentation for a future direct onion P2P dial. That is
     * exactly why it needs an assertion: a field nothing reads is a field
     * nothing catches. A seed whose P2P port is NOT the mainnet default is
     * present, which is the case a single shared port would get wrong. */
    bool all_ports_set = true;
    bool any_non_default_port = false;
    for (size_t i = 0; i < p->nOnionSeeds; i++) {
        if (p->onionSeedPorts[i] == 0) all_ports_set = false;
        if (p->onionSeedPorts[i] != (uint16_t)p->nDefaultPort)
            any_non_default_port = true;
    }
    DOOR_CHECK("every onion seed carries a non-zero P2P port",
               all_ports_set);
    DOOR_CHECK("onionSeedPorts is per-entry: a seed on a non-default P2P "
               "port is carried correctly",
               any_non_default_port);

    /* No onion seed may claim a port a mainnet peer cannot speak on. */
    chain_params_select(CHAIN_TESTNET);
    uint16_t testnet_port = (uint16_t)chain_params_get()->nDefaultPort;
    chain_params_select(CHAIN_MAIN);
    p = chain_params_get();
    bool none_testnet = true;
    for (size_t i = 0; i < p->nOnionSeeds; i++)
        if (p->onionSeedPorts[i] == testnet_port) none_testnet = false;
    DOOR_CHECK("no onion seed claims the testnet P2P port", none_testnet);

    return failures;
}

/* ── Half 2: the node's own directory as a bootstrap door ─────────── */

/* Insert one peer_directory row directly, so the reader is exercised against
 * the real schema rather than a mock. `source`/`last_success` are what
 * separate a host WE measured from one a stranger merely named. */
static bool door_insert_row(sqlite3 *db, const char *host, int port,
                            int64_t last_seen, int self,
                            const char *source, int64_t last_success,
                            int probe_ok, int dial_success_count)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO peer_directory "
            "(onion_address, port, services, height, first_seen, last_seen,"
            " last_probe, probe_ok, fail_count, version, self,"
            " clearnet_ip, clearnet_port, source, apps) "
            "VALUES (?1, ?2, 0, 0, ?3, ?3, ?3, ?4, 0, 'test', ?5,"
            " '', 0, ?6, '')",
            -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        return false;
    }
    sqlite3_bind_text(s, 1, host, -1, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, port);
    sqlite3_bind_int64(s, 3, last_seen);
    sqlite3_bind_int(s, 4, probe_ok);
    sqlite3_bind_int(s, 5, self);
    sqlite3_bind_text(s, 6, source, -1, SQLITE_STATIC);
    bool ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);

    if (ok && last_success > 0) {
        sqlite3_stmt *u = NULL;
        if (sqlite3_prepare_v2(db,
                "UPDATE peer_directory SET last_success = ?1,"
                " dial_success_count = ?2 WHERE onion_address = ?3",
                -1, &u, NULL) == SQLITE_OK && u) {
            sqlite3_bind_int64(u, 1, last_success);
            sqlite3_bind_int(u, 2, dial_success_count);
            sqlite3_bind_text(u, 3, host, -1, SQLITE_STATIC);
            ok = sqlite3_step(u) == SQLITE_DONE;
        }
        if (u) sqlite3_finalize(u);
    }
    return ok;
}

static int check_directory_is_a_door(void)
{
    int failures = 0;

    /* 56 base32 chars each. The MEASURED host is deliberately named so it
     * sorts LAST alphabetically and its last_seen is not the newest: the
     * ranking assertion below must be provable by the ranking rule and not
     * satisfiable by an incidental hostname or timestamp order. */
    static const char *const kMeasured =
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.onion";
    static const char *const kHearsay =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion";
    static const char *const kStale =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion";
    static const char *const kSelf =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddd.onion";

    char dir[] = "/tmp/zcl_seed_doors_XXXXXX";
    if (!mkdtemp(dir)) {
        printf("seed_bootstrap_doors: cannot create scratch datadir... FAIL\n");
        return 1;
    }

    /* onion_service_start keeps the datadir POINTER, so it must outlive the
     * service (same contract test_onion_directory.c relies on). */
    onion_service_start(dir);

    /* The store is created by the production writer, not by this test:
     * learn() is what a real node calls when a peer's /directory.json names
     * a host, and it is the row shape the reader must cope with. */
    bool learned = onion_service_directory_learn(kHearsay, 8033, 0, 0, "");
    DOOR_CHECK("a hostname heard from a peer is persisted by the real writer",
               learned);

    char db_path[1024];
    zcl_node_db_path(db_path, sizeof(db_path), dir);
    sqlite3 *db = NULL;
    bool opened = sqlite3_open(db_path, &db) == SQLITE_OK && db != NULL;
    DOOR_CHECK("the persisted directory is openable", opened);

    int64_t now = (int64_t)time(NULL);
    bool seeded = opened;
    if (opened) {
        /* One host we MEASURED, one we only heard about (already inserted
         * above by learn()), one too stale to be worth a cold node's
         * seconds, and our own row. */
        seeded = door_insert_row(db, kMeasured, 8055, now - 60, 0, "probe",
                                 now - 60, 1, 5) && seeded;
        seeded = door_insert_row(db, kStale, 8033,
                                 now - (ONION_DIR_STALE_SECS + 3600), 0,
                                 "probe", now - (ONION_DIR_STALE_SECS + 3600),
                                 1, 1) && seeded;
        seeded = door_insert_row(db, kSelf, 8033, now, 1, "self",
                                 now, 1, 9) && seeded;
        sqlite3_close(db);
    }
    DOOR_CHECK("scratch directory rows seeded", seeded);

    struct onion_dial_candidate cand[8];
    memset(cand, 0, sizeof(cand));
    int n = onion_service_directory_dial_candidates(cand, 8);

    /* THE POINT OF THE WHOLE LANE: a host this node learned from a peer is
     * a place it can dial again. Before this reader existed the answer was
     * always zero no matter how many peers the node had met, and the
     * compiled-in array was the only door. */
    DOOR_CHECK("the node's own directory offers dial candidates",
               n > 0);

    bool has_measured = false, has_hearsay = false;
    bool has_stale = false, has_self = false;
    int measured_rank = -1, hearsay_rank = -1;
    for (int i = 0; i < n; i++) {
        if (strcmp(cand[i].hostname, kMeasured) == 0) {
            has_measured = true; measured_rank = i;
        } else if (strcmp(cand[i].hostname, kHearsay) == 0) {
            has_hearsay = true; hearsay_rank = i;
        } else if (strcmp(cand[i].hostname, kStale) == 0) {
            has_stale = true;
        } else if (strcmp(cand[i].hostname, kSelf) == 0) {
            has_self = true;
        }
    }

    DOOR_CHECK("a host we measured ourselves is offered", has_measured);
    DOOR_CHECK("a host a peer told us about is offered too", has_hearsay);
    DOOR_CHECK("a stale host is NOT offered (not worth a cold node's 60s)",
               !has_stale);
    DOOR_CHECK("our own row is NOT offered (dialling ourselves finds nothing)",
               !has_self);

    /* Hearsay may only ADD a place to look; it must never outrank a contact
     * we made ourselves, or a hostile directory could flood the front of the
     * dial list with plausible names. */
    DOOR_CHECK("a measured contact outranks pure hearsay",
               measured_rank >= 0 && hearsay_rank >= 0 &&
               measured_rank < hearsay_rank);

    /* Provenance survives the read, so the caller can tell the two apart. */
    bool provenance_ok =
        measured_rank >= 0 && hearsay_rank >= 0 &&
        cand[measured_rank].contacted && !cand[hearsay_rank].contacted;
    DOOR_CHECK("measured-vs-hearsay provenance survives the read",
               provenance_ok);

    /* The advertised P2P port survives too — the seed we added does NOT run
     * on the mainnet default, so a reader that dropped the port would send a
     * future dialler to the wrong one. */
    DOOR_CHECK("the advertised P2P port survives the read",
               measured_rank >= 0 && cand[measured_rank].port == 8055);

    /* Bounded: the caller's cap is honoured, because every returned host
     * costs a blocking Tor fetch. */
    struct onion_dial_candidate one[1];
    memset(one, 0, sizeof(one));
    int n1 = onion_service_directory_dial_candidates(one, 1);
    DOOR_CHECK("the candidate list honours the caller's bound", n1 <= 1);

    /* Defensive contract. */
    DOOR_CHECK("a NULL out-buffer yields zero candidates, never a crash",
               onion_service_directory_dial_candidates(NULL, 8) == 0);
    DOOR_CHECK("a non-positive bound yields zero candidates",
               onion_service_directory_dial_candidates(cand, 0) == 0);

    onion_service_stop();

    /* A node with no directory at all — the genuine fresh-install state —
     * must report "none known", never an error and never a crash. */
    memset(cand, 0, sizeof(cand));
    DOOR_CHECK("with no datadir published the directory offers nothing",
               onion_service_directory_dial_candidates(cand, 8) == 0);

    return failures;
}

int test_seed_bootstrap_doors(void);
int test_seed_bootstrap_doors(void)
{
    int failures = 0;

    failures += check_fixed_seed_ports();
    failures += check_onion_seeds();
    failures += check_directory_is_a_door();

    /* Leave the params singleton where a sequential full run expects it. */
    chain_params_select(CHAIN_MAIN);

    printf("=== seed bootstrap doors: %d failure(s) ===\n", failures);
    return failures;
}
