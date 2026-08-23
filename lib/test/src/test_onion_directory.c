/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_onion_directory — one group over the ONE onion directory
 * (lib/net/src/onion_directory.c + the transitive half of
 * try_onion_seed_fetch in connman.c). Two teams built a directory at the
 * same path for overlapping purposes; this file is the union of both
 * their test suites, and every assertion from each is kept.
 *
 * FOUR contracts are pinned here.
 *
 *  1. The peer directory used to be written once at boot and never again:
 *     no refresh, no last_seen maintenance, no expiry, and
 *     /directory.json handed out up to 500 rows with nothing on them a
 *     reader could use to tell a minute-old row from a week-old one.
 *     Covered: the pure freshness rule, expiry on a refresh round, census
 *     observations moving (or deliberately NOT moving) last_seen, and the
 *     age/policy fields on every served row.
 *
 *  2. try_onion_seed_fetch string-scanned a fetched /directory.json for
 *     clearnet_ip and threw the "onion" field away, so an onion peer
 *     could never teach this node about another onion peer. Covered: both
 *     parsers for that field (validation, dedupe, self-skip, per-object
 *     field binding, the per-response cap, and that ONE malformed record
 *     cannot hide the honest records that follow it) and the follow
 *     budget that stops one response from dominating the pool.
 *
 *  3. serve_search matched only the raw .onion hostname, so a query for a
 *     registered ZNAM name returned "No results" even with the row
 *     folded. The name join is asserted both ways, and every page that
 *     shows a name is asserted to show the RAW address beside it.
 *
 *  4. ONE v3 hostname predicate. onion_hostname_valid() is the single
 *     definition in the tree; the shape assertions below run against it,
 *     not against a second copy that could drift.
 *
 *  5. Track 2 — the app-service advertisement. Every served row carries
 *     "apps":[...] (the app-catalog Apps the host serves on its onion;
 *     the self row's list comes from the ONE site-route registry), the
 *     harvest normalizes and persists it (junk ids rejected, capped,
 *     deduped; the one column hearsay may refresh on an existing row),
 *     and the seller-discovery read returns only FRESH, non-self rows
 *     with read-time re-validation. Old consumers ignore the unknown key:
 *     the clearnet_ip → clearnet_port adjacency connman's string-scan
 *     relies on is pinned below.
 *
 * The load-bearing property throughout: a directory record is a HINT
 * ABOUT WHERE TO LOOK, never proof of who is there. So every path here
 * may only ever ADD a place to try. The asserts that matter most are the
 * negative ones — hearsay never overwrites a first-hand row, a failed
 * probe never moves last_seen, an observation for an unknown host never
 * inserts, and nothing in this file can remove a peer from any other
 * source's reach.
 */

#include "test/test_core.h"

#include "platform/time_compat.h"
#include "net/onion_discovery.h"
#include "net/onion_service.h"
#include "net/onion_peer_merge.h"
#include "net/onion_ratelimit.h"
#include "util/path_check.h"
#include "znam/znam.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Two well-formed v3 names (56 chars from [a-z2-7] + ".onion") and one
 * that fails the rule in the least obvious way — a '1', which is not in
 * the base32 alphabet. */
#define OD_HOST_A \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad.onion"
#define OD_HOST_B \
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbe.onion"
#define OD_HOST_C \
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccf.onion"
#define OD_HOST_BAD \
    "1111111111111111111111111111111111111111111111111111111a.onion"

/* The second suite's own host set, kept distinct so the two halves never
 * see each other's rows. */
#define HOST_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"
#define HOST_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.onion"
#define HOST_C "cccccccccccccccccccccccccccccccccccccccccccccccccccccccc.onion"
#define HOST_SELF "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.onion"

#define OD_CHECK(label, cond) do { \
    printf("onion_directory: %s... ", (label)); \
    if (cond) { printf("OK\n"); } \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* ── 1. The pure freshness rule ───────────────────────────────────── */

static int od_freshness_rule(void)
{
    int failures = 0;
    const int64_t now = 1800000000;

    OD_CHECK("a row confirmed a minute ago is FRESH",
             onion_directory_freshness(now - 60, now, false) == ONION_DIR_FRESH);
    OD_CHECK("a row one second inside the stale window is still FRESH",
             onion_directory_freshness(now - (ONION_DIR_STALE_SECS - 1), now,
                                       false) == ONION_DIR_FRESH);
    OD_CHECK("a row exactly at the stale threshold is STALE",
             onion_directory_freshness(now - ONION_DIR_STALE_SECS, now,
                                       false) == ONION_DIR_STALE);
    OD_CHECK("a day-old row is STALE, not dropped",
             onion_directory_freshness(now - 86400, now, false) ==
                 ONION_DIR_STALE);
    OD_CHECK("a row past the expiry window is EXPIRED",
             onion_directory_freshness(now - ONION_DIR_EXPIRE_SECS, now,
                                       false) == ONION_DIR_EXPIRED);
    OD_CHECK("a week-old row — the exact bug — is EXPIRED",
             onion_directory_freshness(now - 7 * 86400 - 1, now, false) ==
                 ONION_DIR_EXPIRED);
    OD_CHECK("a row with no stamp at all has no provenance and is EXPIRED",
             onion_directory_freshness(0, now, false) == ONION_DIR_EXPIRED);
    OD_CHECK("a negative stamp is EXPIRED",
             onion_directory_freshness(-5, now, false) == ONION_DIR_EXPIRED);
    /* Our own presence is not hearsay: it is never aged out, whatever the
     * stamp says, because dropping it would stop us advertising ourselves. */
    OD_CHECK("our own row is FRESH even with an ancient stamp",
             onion_directory_freshness(1, now, true) == ONION_DIR_FRESH);
    OD_CHECK("our own row is FRESH even with no stamp",
             onion_directory_freshness(0, now, true) == ONION_DIR_FRESH);
    /* Peer clock skew must never buy a row extra life beyond "now". */
    OD_CHECK("a future stamp is clamped to age 0, never negative",
             onion_directory_age_secs(now + 9999, now) == 0);
    OD_CHECK("a future stamp reads FRESH, not as a wrapped-around expiry",
             onion_directory_freshness(now + 9999, now, false) ==
                 ONION_DIR_FRESH);
    OD_CHECK("age is the plain difference otherwise",
             onion_directory_age_secs(now - 4242, now) == 4242);
    return failures;
}

/* ── 2. Parsing the onion half of a /directory.json ───────────────── */

static int od_parse_relay_hints(void)
{
    int failures = 0;
    struct onion_relay_hint hints[16];

    /* A response shaped exactly like the one this node serves. */
    static const char BODY[] =
        "{\"nodes\":["
        "{\"onion\":\"" OD_HOST_A "\",\"name\":\"\",\"apps\":[\"yardsale\",\"blog\"],"
        "\"port\":8033,\"services\":1029,"
        "\"height\":3196556,\"last_seen\":1799999000,\"version\":\"0.1.0\","
        "\"self\":true,\"clearnet_ip\":\"1.2.3.4\",\"clearnet_port\":8033},"
        "{\"onion\":\"" OD_HOST_B "\",\"name\":\"\",\"apps\":[],"
        "\"port\":9033,\"services\":0,"
        "\"height\":42,\"last_seen\":1799998000,\"version\":\"0.1.0\","
        "\"self\":false,\"clearnet_ip\":\"\",\"clearnet_port\":0}"
        "],\"count\":2}";

    memset(hints, 0, sizeof(hints));
    int n = onion_directory_parse_relay_hints(BODY, NULL, hints, 16);
    OD_CHECK("both advertised onions are parsed (the field used to be dropped)",
             n == 2);
    OD_CHECK("first hostname is carried verbatim",
             n == 2 && strcmp(hints[0].hostname, OD_HOST_A) == 0);
    OD_CHECK("second hostname is carried verbatim",
             n == 2 && strcmp(hints[1].hostname, OD_HOST_B) == 0);
    OD_CHECK("each entry keeps its OWN port, not the next object's",
             n == 2 && hints[0].port == 8033 && hints[1].port == 9033);
    OD_CHECK("each entry keeps its OWN height",
             n == 2 && hints[0].height == 3196556 && hints[1].height == 42);
    OD_CHECK("each entry keeps its OWN last_seen",
             n == 2 && hints[0].last_seen == 1799999000 &&
             hints[1].last_seen == 1799998000);
    OD_CHECK("clearnet_port is not mistaken for port",
             n == 2 && hints[1].port == 9033);
    OD_CHECK("each entry keeps its OWN apps advertisement, as CSV",
             n == 2 && strcmp(hints[0].apps, "yardsale,blog") == 0 &&
             hints[1].apps[0] == '\0');

    /* Junk app ids are dropped, never fatal — the hostname and the honest
     * ids around the junk survive, exactly the hostname scan's posture. */
    static const char JUNKAPPS[] =
        "{\"nodes\":["
        "{\"onion\":\"" OD_HOST_A "\",\"apps\":[\"yardsale\",\"Yardsale\","
        "\"yard sale\",\"\",\"blog\",\"yardsale\"],\"port\":8033},"
        "{\"onion\":\"" OD_HOST_B "\",\"apps\":\"not-an-array\",\"port\":9033}"
        "]}";
    memset(hints, 0, sizeof(hints));
    n = onion_directory_parse_relay_hints(JUNKAPPS, NULL, hints, 16);
    OD_CHECK("junk app ids are rejected, the valid ones kept and deduped",
             n == 2 && strcmp(hints[0].apps, "yardsale,blog") == 0);
    OD_CHECK("a non-array apps field reads as no advertisement",
             n == 2 && hints[1].apps[0] == '\0');

    /* The cap: more ids than ONION_DIR_APPS_MAX keeps exactly the first
     * ONION_DIR_APPS_MAX valid ones. */
    static const char OVERCAP[] =
        "{\"nodes\":[{\"onion\":\"" OD_HOST_A "\",\"apps\":["
        "\"a1\",\"a2\",\"a3\",\"a4\",\"a5\",\"a6\",\"a7\",\"a8\",\"a9\""
        "],\"port\":8033}]}";
    memset(hints, 0, sizeof(hints));
    n = onion_directory_parse_relay_hints(OVERCAP, NULL, hints, 16);
    OD_CHECK("the apps list is capped",
             n == 1 &&
             strcmp(hints[0].apps, "a1,a2,a3,a4,a5,a6,a7,a8") == 0);
    /* An over-long id is rejected, not truncated into a valid one. */
    static const char LONGID[] =
        "{\"nodes\":[{\"onion\":\"" OD_HOST_A "\",\"apps\":["
        "\"abcdefghijabcdefghijabcdefghijabcdefghij\",\"ok\""
        "],\"port\":8033}]}";
    memset(hints, 0, sizeof(hints));
    n = onion_directory_parse_relay_hints(LONGID, NULL, hints, 16);
    OD_CHECK("an over-long app id is rejected, the next one survives",
             n == 1 && strcmp(hints[0].apps, "ok") == 0);

    /* Asking about ourselves must not learn ourselves. */
    memset(hints, 0, sizeof(hints));
    n = onion_directory_parse_relay_hints(BODY, OD_HOST_A, hints, 16);
    OD_CHECK("our own hostname is skipped when the peer advertises it",
             n == 1 && strcmp(hints[0].hostname, OD_HOST_B) == 0);

    /* Every hostname goes through the one v3 rule regardless of source. */
    static const char HOSTILE[] =
        "{\"nodes\":["
        "{\"onion\":\"" OD_HOST_BAD "\",\"port\":8033},"
        "{\"onion\":\"short.onion\",\"port\":8033},"
        "{\"onion\":\"\",\"port\":8033},"
        "{\"onion\":\"" OD_HOST_A "\",\"port\":8033}"
        "]}";
    memset(hints, 0, sizeof(hints));
    n = onion_directory_parse_relay_hints(HOSTILE, NULL, hints, 16);
    OD_CHECK("malformed hostnames are dropped, the valid one survives",
             n == 1 && strcmp(hints[0].hostname, OD_HOST_A) == 0);

    /* A peer repeating one hostname must not consume the whole budget. */
    static const char REPEATED[] =
        "{\"nodes\":["
        "{\"onion\":\"" OD_HOST_A "\",\"port\":1},"
        "{\"onion\":\"" OD_HOST_A "\",\"port\":2},"
        "{\"onion\":\"" OD_HOST_A "\",\"port\":3},"
        "{\"onion\":\"" OD_HOST_B "\",\"port\":4}"
        "]}";
    memset(hints, 0, sizeof(hints));
    n = onion_directory_parse_relay_hints(REPEATED, NULL, hints, 16);
    OD_CHECK("a repeated hostname is deduped within one response", n == 2);

    /* The per-response cap: one node's answer cannot dominate the pool. */
    memset(hints, 0, sizeof(hints));
    n = onion_directory_parse_relay_hints(BODY, NULL, hints, 1);
    OD_CHECK("the caller's cap bounds one response's contribution", n == 1);

    /* Degenerate inputs are a clean zero, never a read past the buffer. */
    memset(hints, 0, sizeof(hints));
    OD_CHECK("a body with no onion field yields nothing",
             onion_directory_parse_relay_hints("{\"nodes\":[]}", NULL,
                                               hints, 16) == 0);
    OD_CHECK("a truncated onion value yields nothing",
             onion_directory_parse_relay_hints("{\"onion\":\"aaaa", NULL,
                                               hints, 16) == 0);
    OD_CHECK("an over-long onion value is rejected, not truncated into a host",
             onion_directory_parse_relay_hints(
                 "{\"onion\":\"" OD_HOST_A OD_HOST_A OD_HOST_A "\"}",
                 NULL, hints, 16) == 0);
    OD_CHECK("NULL body is a clean zero",
             onion_directory_parse_relay_hints(NULL, NULL, hints, 16) == 0);
    OD_CHECK("zero capacity is a clean zero",
             onion_directory_parse_relay_hints(BODY, NULL, hints, 0) == 0);
    return failures;
}

/* ── 2b. The apps normalizers (pure) ──────────────────────────────── */

static int od_apps_pure_helpers(void)
{
    int failures = 0;
    char csv[ONION_DIR_APPS_CSV_MAX + 1];

    /* The one app-id shape rule, deliberately at-or-tighter than the app
     * catalog's own (which also allows interior hyphens): it can only
     * ever withhold an id, never invent one. */
    OD_CHECK("plain lowercase ids are valid",
             onion_directory_app_id_valid("yardsale") &&
             onion_directory_app_id_valid("blog") &&
             onion_directory_app_id_valid("z2"));
    OD_CHECK("NULL and empty ids are refused",
             !onion_directory_app_id_valid(NULL) &&
             !onion_directory_app_id_valid(""));
    OD_CHECK("uppercase, hyphens, and punctuation are refused",
             !onion_directory_app_id_valid("Yardsale") &&
             !onion_directory_app_id_valid("yard-sale") &&
             !onion_directory_app_id_valid("yard<sale") &&
             !onion_directory_app_id_valid("yard sale"));
    OD_CHECK("an id past the length cap is refused",
             !onion_directory_app_id_valid(
                 "abcdefghijabcdefghijabcdefghijabcdefghij") &&
             onion_directory_app_id_valid(
                 "abcdefghijabcdefghijabcdefghijab"));

    /* JSON extraction: absent key, malformed shapes, truncation. */
    OD_CHECK("a segment with no apps key yields nothing",
             onion_directory_apps_from_json("\"port\":8033", csv,
                                            sizeof(csv)) == 0 &&
             csv[0] == '\0');
    OD_CHECK("a NULL segment yields nothing",
             onion_directory_apps_from_json(NULL, csv, sizeof(csv)) == 0);
    OD_CHECK("a scalar apps value yields nothing",
             onion_directory_apps_from_json("\"apps\":\"yardsale\"", csv,
                                            sizeof(csv)) == 0);
    OD_CHECK("an unterminated array keeps the ids already validated",
             onion_directory_apps_from_json(
                 "\"apps\":[\"yardsale\",\"blo", csv, sizeof(csv)) > 0 &&
             strcmp(csv, "yardsale") == 0);

    /* CSV re-normalization: junk tokens out, duplicates out, order kept. */
    OD_CHECK("normalize drops empties, junk, and duplicates",
             onion_directory_apps_normalize("yardsale,,blog,Yard,sale,"
                                            "yardsale", csv,
                                            sizeof(csv)) > 0 &&
             strcmp(csv, "yardsale,blog,sale") == 0);
    OD_CHECK("normalize of NULL/empty is empty",
             onion_directory_apps_normalize(NULL, csv, sizeof(csv)) == 0 &&
             csv[0] == '\0');

    /* Whole-body extraction for the node we just fetched: the match is
     * bound to ITS object, never a neighbour's. */
    static const char TWO[] =
        "{\"nodes\":["
        "{\"onion\":\"" OD_HOST_A "\",\"apps\":[\"yardsale\"]},"
        "{\"onion\":\"" OD_HOST_B "\",\"apps\":[\"blog\"]}"
        "]}";
    OD_CHECK("apps_for_onion reads the named host's own object",
             onion_directory_apps_for_onion(TWO, OD_HOST_B, csv,
                                            sizeof(csv)) > 0 &&
             strcmp(csv, "blog") == 0);
    OD_CHECK("apps_for_onion on an unknown host yields nothing",
             onion_directory_apps_for_onion(TWO, OD_HOST_C, csv,
                                            sizeof(csv)) == 0);
    OD_CHECK("apps_for_onion refuses a malformed hostname",
             onion_directory_apps_for_onion(TWO, "bogus", csv,
                                            sizeof(csv)) == 0);
    return failures;
}

/* ── 3. The follow budget ─────────────────────────────────────────── */

static int od_follow_budget(void)
{
    int failures = 0;
    const int64_t t0 = 1800000000;

    onion_directory_reset_relay_follow();

    OD_CHECK("a malformed hostname can never claim a fetch",
             !onion_directory_claim_relay_follow(OD_HOST_BAD, t0));
    OD_CHECK("NULL hostname can never claim a fetch",
             !onion_directory_claim_relay_follow(NULL, t0));

    OD_CHECK("the first claim on a fresh window succeeds",
             onion_directory_claim_relay_follow(OD_HOST_A, t0));
    OD_CHECK("the same hostname cannot be followed twice in one window",
             !onion_directory_claim_relay_follow(OD_HOST_A, t0));
    OD_CHECK("a different hostname still gets through",
             onion_directory_claim_relay_follow(OD_HOST_B, t0));

    /* Exhaust the rest of the budget with distinct hostnames, then prove
     * the (budget+1)th is refused — this is the cap that stops a
     * directory response from turning into an unbounded crawl. */
    onion_directory_reset_relay_follow();
    int granted = 0;
    for (int i = 0; i < ONION_RELAY_FOLLOW_BUDGET + 8; i++) {
        char host[64];
        snprintf(host, sizeof(host), "%s", OD_HOST_A);
        /* Vary two base32 chars so each name is distinct and still valid. */
        host[0] = (char)('a' + (i % 26));
        host[1] = (char)('a' + ((i / 26) % 26));
        if (!onion_hostname_valid(host)) continue;
        if (onion_directory_claim_relay_follow(host, t0)) granted++;
    }
    OD_CHECK("the follow budget is a hard cap per window",
             granted == ONION_RELAY_FOLLOW_BUDGET);

    /* Rolling the window refills the budget AND clears the dedupe ring,
     * so a host is never locked out for the life of the process. */
    OD_CHECK("an exhausted budget refuses a new host inside the window",
             !onion_directory_claim_relay_follow(OD_HOST_C, t0 + 1));
    OD_CHECK("rolling the window refills the budget",
             onion_directory_claim_relay_follow(
                 OD_HOST_C, t0 + ONION_RELAY_WINDOW_SECS));
    OD_CHECK("a previously-followed host is reachable again next window",
             onion_directory_claim_relay_follow(
                 OD_HOST_A, t0 + ONION_RELAY_WINDOW_SECS));

    onion_directory_reset_relay_follow();
    return failures;
}

/* ── 4. The durable directory: refresh, observe, learn, serve ─────── */

static sqlite3 *od_open_db(const char *datadir)
{
    char path[1024];
    zcl_node_db_path(path, sizeof(path), datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 2000);
    return db;
}

/* Read one integer column for one host. -1 when the row is gone. */
static int64_t od_row_int(sqlite3 *db, const char *host, const char *col)
{
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT %s FROM peer_directory WHERE onion_address = ?", col);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s)
        return -1;
    sqlite3_bind_text(s, 1, host, -1, SQLITE_STATIC);
    int64_t v = -1;
    if (sqlite3_step(s) == SQLITE_ROW)
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

static bool od_row_source(sqlite3 *db, const char *host, char *out, size_t n)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(source,'') FROM peer_directory "
            "WHERE onion_address = ?", -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_text(s, 1, host, -1, SQLITE_STATIC);
    bool found = false;
    if (sqlite3_step(s) == SQLITE_ROW) {
        const char *v = (const char *)sqlite3_column_text(s, 0);
        snprintf(out, n, "%s", v ? v : "");
        found = true;
    }
    sqlite3_finalize(s);
    return found;
}

/* Read one TEXT column for one host. False when the row is gone. */
static bool od_row_text(sqlite3 *db, const char *host, const char *col,
                        char *out, size_t n)
{
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT COALESCE(%s,'') FROM peer_directory "
             "WHERE onion_address = ?", col);
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_text(s, 1, host, -1, SQLITE_STATIC);
    bool found = false;
    if (sqlite3_step(s) == SQLITE_ROW) {
        const char *v = (const char *)sqlite3_column_text(s, 0);
        snprintf(out, n, "%s", v ? v : "");
        found = true;
    }
    sqlite3_finalize(s);
    return found;
}

static void od_insert_row(sqlite3 *db, const char *host, int64_t last_seen,
                          const char *source)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO peer_directory "
            "(onion_address, port, services, height, first_seen, last_seen,"
            " last_probe, probe_ok, fail_count, version, self,"
            " clearnet_ip, clearnet_port, source) "
            "VALUES (?, 8033, 0, 0, ?, ?, 0, 0, 0, 'test', 0, '', 0, ?)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return;
    sqlite3_bind_text(s, 1, host, -1, SQLITE_STATIC);
    sqlite3_bind_int64(s, 2, last_seen);
    sqlite3_bind_int64(s, 3, last_seen);
    sqlite3_bind_text(s, 4, source, -1, SQLITE_STATIC);
    (void)sqlite3_step(s);
    sqlite3_finalize(s);
}

static int od_durable_directory(void)
{
    int failures = 0;

    /* onion_service_start keeps the datadir POINTER, so it must outlive
     * every call below — static, not a stack buffer. */
    static char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "onion_directory", "db");
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);

    onion_service_start(dir);

    sqlite3 *db = od_open_db(dir);
    if (!db) {
        printf("onion_directory: could not open the test node db... FAIL\n");
        onion_service_stop();
        test_cleanup_tmpdir(dir);
        return 1;
    }

    const int64_t now = (int64_t)platform_time_wall_time_t();

    /* ── learn(): hearsay may only ADD ───────────────────────────── */
    OD_CHECK("a malformed relayed hostname is refused",
             !onion_service_directory_learn(OD_HOST_BAD, 8033, 1, now - 60,
                                            NULL));
    OD_CHECK("a valid relayed hostname is recorded",
             onion_service_directory_learn(OD_HOST_A, 8033, 99, now - 60,
                                           NULL));
    { char src[32] = "";
      OD_CHECK("a relayed row is marked as hearsay, not as our own measurement",
               od_row_source(db, OD_HOST_A, src, sizeof(src)) &&
               strcmp(src, "relay") == 0); }
    OD_CHECK("a relayed stamp already past expiry is refused outright",
             !onion_service_directory_learn(OD_HOST_C, 8033, 1,
                                            now - ONION_DIR_EXPIRE_SECS - 1,
                                            NULL));
    OD_CHECK("the refused stale hearsay left no row behind",
             od_row_int(db, OD_HOST_C, "last_seen") == -1);

    /* A first-hand row must survive a peer telling us about it. */
    od_insert_row(db, OD_HOST_B, now - 120, "discovery");
    OD_CHECK("learn() on a host we already know reports success",
             onion_service_directory_learn(OD_HOST_B, 1234, 7, now - 3600,
                                           NULL));
    { char src[32] = "";
      OD_CHECK("hearsay never overwrites a first-hand row",
               od_row_source(db, OD_HOST_B, src, sizeof(src)) &&
               strcmp(src, "discovery") == 0); }
    OD_CHECK("hearsay never rewrites a first-hand last_seen",
             od_row_int(db, OD_HOST_B, "last_seen") == now - 120);

    /* ── learn(): the apps advertisement round-trip ──────────────────
     * The apps list is the ONE field hearsay may refresh on an existing
     * row: a fresher non-empty advertisement replaces it, an empty one
     * never clears it, and junk ids are normalized out before storage. */
    OD_CHECK("an advertisement with apps is stored on the existing row",
             onion_service_directory_learn(OD_HOST_A, 8033, 99, now - 60,
                                           "yardsale,blog"));
    { char apps[320] = "";
      OD_CHECK("the stored apps round-trip as normalized CSV",
               od_row_text(db, OD_HOST_A, "apps", apps, sizeof(apps)) &&
               strcmp(apps, "yardsale,blog") == 0); }
    OD_CHECK("a re-learn with no apps reports success",
             onion_service_directory_learn(OD_HOST_A, 8033, 99, now - 30,
                                           NULL));
    { char apps[320] = "";
      OD_CHECK("an empty advertisement never clears the stored one",
               od_row_text(db, OD_HOST_A, "apps", apps, sizeof(apps)) &&
               strcmp(apps, "yardsale,blog") == 0); }
    OD_CHECK("a fresher advertisement may replace the stored one",
             onion_service_directory_learn(OD_HOST_A, 8033, 99, now - 10,
                                           "blog,<script>,yardsale"));
    { char apps[320] = "";
      OD_CHECK("junk ids are normalized out before storage",
               od_row_text(db, OD_HOST_A, "apps", apps, sizeof(apps)) &&
               strcmp(apps, "blog,yardsale") == 0); }
    OD_CHECK("apps refresh never moves last_seen (INSERT OR IGNORE stands)",
             od_row_int(db, OD_HOST_A, "last_seen") == now - 60);
    { char src[32] = "";
      OD_CHECK("the row is still marked hearsay, not contact",
               od_row_source(db, OD_HOST_A, src, sizeof(src)) &&
               strcmp(src, "relay") == 0); }

    /* ── observe(): the census bridge ────────────────────────────── */
    struct onion_directory_observation obs[3];
    struct onion_directory_refresh_stats st;

    memset(obs, 0, sizeof(obs));
    snprintf(obs[0].hostname, sizeof(obs[0].hostname), "%s", OD_HOST_A);
    obs[0].reachable = true;
    obs[0].observed_unix = now - 5;
    obs[0].best_height = 4242;
    OD_CHECK("a reachable observation is applied",
             onion_service_directory_observe(obs, 1, &st) == 1 &&
             st.refreshed == 1);
    OD_CHECK("a reachable observation moves last_seen forward",
             od_row_int(db, OD_HOST_A, "last_seen") == now - 5);
    OD_CHECK("a reachable observation records probe success",
             od_row_int(db, OD_HOST_A, "probe_ok") == 1);
    OD_CHECK("a reachable observation adopts the higher height",
             od_row_int(db, OD_HOST_A, "height") == 4242);

    /* A failed dial is not evidence of absence — it must NOT move
     * last_seen, only stop being evidence of presence. */
    int64_t before = od_row_int(db, OD_HOST_A, "last_seen");
    memset(obs, 0, sizeof(obs));
    snprintf(obs[0].hostname, sizeof(obs[0].hostname), "%s", OD_HOST_A);
    obs[0].reachable = false;
    obs[0].observed_unix = now;
    obs[0].best_height = -1;
    OD_CHECK("an unreachable observation is applied",
             onion_service_directory_observe(obs, 1, &st) == 1 &&
             st.failed == 1);
    OD_CHECK("an unreachable observation does NOT move last_seen",
             od_row_int(db, OD_HOST_A, "last_seen") == before);
    OD_CHECK("an unreachable observation bumps fail_count",
             od_row_int(db, OD_HOST_A, "fail_count") == 1);
    OD_CHECK("an unreachable observation clears probe_ok",
             od_row_int(db, OD_HOST_A, "probe_ok") == 0);
    OD_CHECK("an unreachable observation never lowers the height",
             od_row_int(db, OD_HOST_A, "height") == 4242);

    /* An observation naming a host we do not have may not INSERT one:
     * a lying census must not be able to add a peer. */
    memset(obs, 0, sizeof(obs));
    snprintf(obs[0].hostname, sizeof(obs[0].hostname), "%s", OD_HOST_C);
    obs[0].reachable = true;
    obs[0].observed_unix = now;
    OD_CHECK("an observation for an unknown host is counted, not applied",
             onion_service_directory_observe(obs, 1, &st) == 0 &&
             st.unknown == 1);
    OD_CHECK("an observation for an unknown host inserts nothing",
             od_row_int(db, OD_HOST_C, "last_seen") == -1);

    memset(obs, 0, sizeof(obs));
    snprintf(obs[0].hostname, sizeof(obs[0].hostname), "%s", OD_HOST_BAD);
    obs[0].reachable = true;
    OD_CHECK("an observation with a malformed hostname is rejected",
             onion_service_directory_observe(obs, 1, &st) == 0 &&
             st.unknown == 1);
    OD_CHECK("an empty observation batch is not an error",
             onion_service_directory_observe(obs, 0, &st) == 0);

    /* ── refresh(): the round that was never running ─────────────── */
    od_insert_row(db, OD_HOST_C, now - ONION_DIR_EXPIRE_SECS - 60, "discovery");
    OD_CHECK("the week-old row exists before the refresh round",
             od_row_int(db, OD_HOST_C, "last_seen") > 0);
    OD_CHECK("a refresh round completes against a writable directory",
             onion_service_directory_refresh(&st));
    OD_CHECK("the refresh round expired exactly the aged-out row",
             st.expired == 1);
    OD_CHECK("the aged-out row is gone",
             od_row_int(db, OD_HOST_C, "last_seen") == -1);
    OD_CHECK("rows still inside the window survive the refresh",
             od_row_int(db, OD_HOST_A, "last_seen") > 0 &&
             od_row_int(db, OD_HOST_B, "last_seen") > 0);

    /* ── serve: every row carries its own age ────────────────────── */
    od_insert_row(db, OD_HOST_C, now - ONION_DIR_EXPIRE_SECS - 60, "discovery");
    static uint8_t resp[262144];
    memset(resp, 0, sizeof(resp));
    size_t rn = onion_service_handle_request("GET", "/directory.json", NULL, 0,
                                             resp, sizeof(resp));
    const char *json = (const char *)resp;
    OD_CHECK("/directory.json still answers", rn > 0 && strstr(json, "200 OK"));
    OD_CHECK("every served row carries its own age",
             strstr(json, "\"age_secs\":") != NULL);
    OD_CHECK("every served row carries a stale flag",
             strstr(json, "\"stale\":") != NULL);
    OD_CHECK("every served row says where it came from",
             strstr(json, "\"source\":") != NULL);
    OD_CHECK("the response states when it was generated",
             strstr(json, "\"generated_at\":") != NULL);
    OD_CHECK("the response states the freshness policy it applied",
             strstr(json, "\"stale_after_secs\":") != NULL &&
             strstr(json, "\"expire_after_secs\":") != NULL);
    OD_CHECK("a row inside the window is served",
             strstr(json, OD_HOST_A) != NULL);
    OD_CHECK("an aged-out row is NOT served as if it were current",
             strstr(json, OD_HOST_C) == NULL);
    OD_CHECK("the response admits how many rows it withheld",
             strstr(json, "\"skipped_expired\":1") != NULL);
    /* Track 2: every row carries its app-service advertisement, right
     * after "name" and never between clearnet_ip and clearnet_port (the
     * connman seed-fetch string-scan reads clearnet_port within 50 chars
     * of clearnet_ip — the adjacency below is the interop pin). */
    OD_CHECK("a row with an advertisement serves it as a JSON array",
             strstr(json, "\"apps\":[\"blog\",\"yardsale\"]") != NULL);
    OD_CHECK("a row with no advertisement serves an empty array",
             strstr(json, "\"apps\":[]") != NULL);
    OD_CHECK("the apps key never splits clearnet_ip from clearnet_port",
             strstr(json, "\"clearnet_ip\":\"1.2.3.4\",\"clearnet_port\":") ||
             strstr(json, "\"clearnet_ip\":\"\",\"clearnet_port\":"));

    sqlite3_close(db);
    onion_service_stop();
    test_cleanup_tmpdir(dir);
    return failures;
}

/* ═══════════════════════════════════════════════════════════════════
 * The second suite: names, the /directory.json scanner, and the
 * observation semantics driven through the SAME lifecycle API above.
 * Its own datadir and its own host set, so neither half can see the
 * other's rows.
 * ═══════════════════════════════════════════════════════════════════ */

/* ── fixture helpers ───────────────────────────────────────────── */

static sqlite3 *od_open(const char *datadir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", datadir);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 5000);
    return db;
}

static bool od_exec(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("[sql: %s] ", err ? err : "?");
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* Single-integer scalar query; returns `missing` when no row. */
static int64_t od_scalar(sqlite3 *db, const char *sql, int64_t missing)
{
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        return missing;
    }
    int64_t v = missing;
    if (sqlite3_step(s) == SQLITE_ROW)     // raw-sql-ok: test fixture readback
        v = sqlite3_column_int64(s, 0);
    sqlite3_finalize(s);
    return v;
}

/* Create the ZNAM projection table the join reads and register one name. */
static bool od_register_name(sqlite3 *db, const char *name,
                             const char *target, int height)
{
    if (!od_exec(db,
        "CREATE TABLE IF NOT EXISTS znam_names ("
        "name TEXT PRIMARY KEY,"
        "owner_address TEXT NOT NULL,"
        "target_type INTEGER NOT NULL,"
        "target_value TEXT NOT NULL,"
        "reg_txid BLOB NOT NULL,"
        "reg_height INTEGER NOT NULL,"
        "last_update_txid BLOB NOT NULL)"))
        return false;

    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO znam_names "
        "(name, owner_address, target_type, target_value, reg_txid,"
        " reg_height, last_update_txid) "
        "VALUES (?1,'t1owner',?2,?3,zeroblob(32),?4,zeroblob(32))",
        -1, &s, NULL) != SQLITE_OK || !s) {
        if (s) sqlite3_finalize(s);
        return false;
    }
    sqlite3_bind_text(s, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int(s, 2, ZNAM_TYPE_ONION);
    sqlite3_bind_text(s, 3, target, -1, SQLITE_STATIC);
    sqlite3_bind_int(s, 4, height);
    bool ok = sqlite3_step(s) == SQLITE_DONE;  // raw-sql-ok: test fixture write
    sqlite3_finalize(s);
    return ok;
}

/* ── 5. the ONE v3 hostname predicate ──────────────────────────── */

/* These used to run against onion_hostname_is_valid_v3, a byte-identical
 * second copy of onion_hostname_valid. The copy is gone; the assertions
 * are not — they now hold the single surviving definition to exactly the
 * same shape rule, which is the point of collapsing the two. */
static int od_test_hostname_shape(void)
{
    int failures = 0;

    OD_CHECK("valid v3 host accepted",
             onion_hostname_valid(HOST_A));
    OD_CHECK("NULL rejected", !onion_hostname_valid(NULL));
    OD_CHECK("empty rejected", !onion_hostname_valid(""));
    OD_CHECK("missing suffix rejected", !onion_hostname_valid(
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    OD_CHECK("v2-length rejected", !onion_hostname_valid(
             "abcdefghij234567.onion"));
    OD_CHECK("uppercase rejected", !onion_hostname_valid(
             "Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"));
    /* '1' and '8' are outside the base32 alphabet [a-z2-7]. */
    OD_CHECK("out-of-alphabet digit rejected", !onion_hostname_valid(
             "1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion"));
    OD_CHECK("trailing garbage rejected", !onion_hostname_valid(
             HOST_A "x"));
    return failures;
}

/* ── 2. /directory.json onion-field scanner ────────────────────── */

static int od_test_scan(void)
{
    int failures = 0;
    char host[64];

    /* A realistic response: two good records around one whose onion field
     * is empty, one over-long, and clearnet fields interleaved. */
    static const char BODY[] =
        "{\"nodes\":["
        "{\"onion\":\"" HOST_A "\",\"clearnet_ip\":\"1.2.3.4\"},"
        "{\"onion\":\"\",\"clearnet_ip\":\"5.6.7.8\"},"
        "{\"onion\":\"" /* 200 chars: over-long, must be skipped not fatal */
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaa\"},"
        "{\"onion\":\"" HOST_B "\",\"clearnet_ip\":\"9.9.9.9\"}"
        "],\"count\":4}";

    const char *cur = BODY;
    bool got_a = onion_directory_scan_next_onion(&cur, host, sizeof(host));
    OD_CHECK("scan finds first onion", got_a && strcmp(host, HOST_A) == 0);

    /* The empty and the over-long records must be SKIPPED, not fatal — a
     * hostile peer cannot hide the honest records that follow its own. */
    bool got_b = onion_directory_scan_next_onion(&cur, host, sizeof(host));
    OD_CHECK("scan survives empty + over-long records",
             got_b && strcmp(host, HOST_B) == 0);

    OD_CHECK("scan terminates at end of body",
             !onion_directory_scan_next_onion(&cur, host, sizeof(host)));

    /* Unterminated field: no crash, no read past the NUL, returns false. */
    static const char TRUNC[] = "{\"nodes\":[{\"onion\":\"aaaa";
    cur = TRUNC;
    OD_CHECK("unterminated field returns false",
             !onion_directory_scan_next_onion(&cur, host, sizeof(host)));

    /* A body with no onion field at all — the pre-change clearnet-only
     * shape — must simply yield nothing. */
    static const char NOONION[] = "{\"nodes\":[{\"clearnet_ip\":\"1.2.3.4\"}]}";
    cur = NOONION;
    OD_CHECK("clearnet-only body yields no onions",
             !onion_directory_scan_next_onion(&cur, host, sizeof(host)));

    /* Defensive arguments. */
    cur = BODY;
    OD_CHECK("NULL out rejected",
             !onion_directory_scan_next_onion(&cur, NULL, sizeof(host)));
    OD_CHECK("zero-length out rejected",
             !onion_directory_scan_next_onion(&cur, host, 0));
    OD_CHECK("NULL cursor rejected",
             !onion_directory_scan_next_onion(NULL, host, sizeof(host)));
    return failures;
}

/* ── 7. observation semantics + freshness columns ──────────────── */

/* Ported onto the surviving lifecycle API. The dropped implementation
 * had three entry points (ensure_table / observe / expire) that
 * duplicated this file's; the SEMANTICS they asserted are what mattered
 * and every one of them is kept here:
 *   ADVERTISED  -> onion_service_directory_learn()   (INSERT OR IGNORE)
 *   REACHED     -> onion_service_directory_observe(reachable = true)
 *   UNREACHABLE -> onion_service_directory_observe(reachable = false)
 * One assertion could not survive verbatim: "observe before node.db
 * exists is a silent no-op" tested that the dropped writer opened
 * READWRITE and never created the file. The surviving writer is gated on
 * the SERVICE, not on the file — it refuses while no datadir is
 * published — so that guard is asserted in its own terms below. */
static int od_test_observe(const char *datadir)
{
    int failures = 0;

    /* Nothing may reach the directory before the service publishes a
     * datadir: a net-layer probe can never race the boot path. */
    OD_CHECK("learn before the service has a datadir is refused",
             !onion_service_directory_learn(HOST_A, 8033, 1234, 0, NULL));

    onion_service_start(datadir);

    /* ADVERTISED creates the row: heard about, never contacted. */
    OD_CHECK("advertised creates a row",
             onion_service_directory_learn(HOST_A, 8033, 1234, 0, NULL));
    sqlite3 *db = od_open(datadir);
    if (!db) { printf("onion_directory: cannot open fixture db\n"); return 1; }

    OD_CHECK("advertised stored exactly one row",
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1) == 1);
    OD_CHECK("advertised sets last_seen",
             od_scalar(db, "SELECT last_seen FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", 0) > 0);
    OD_CHECK("advertised sets first_seen",
             od_scalar(db, "SELECT first_seen FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", 0) > 0);
    OD_CHECK("advertised is NOT contact (last_success stays 0)",
             od_scalar(db, "SELECT last_success FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1) == 0);
    OD_CHECK("advertised records the advertised height",
             od_scalar(db, "SELECT height FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1) == 1234);

    struct onion_directory_observation obs;
    struct onion_directory_refresh_stats st;

    /* UNREACHABLE on an UNKNOWN host must not insert: a failed dial
     * carries no identity. */
    memset(&obs, 0, sizeof(obs));
    snprintf(obs.hostname, sizeof(obs.hostname), "%s", HOST_C);
    obs.reachable = false;
    OD_CHECK("failed dial on unknown host inserts nothing",
             onion_service_directory_observe(&obs, 1, &st) == 0 &&
             st.unknown == 1 &&
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory "
                           "WHERE onion_address='" HOST_C "'", -1) == 0);

    /* UNREACHABLE on a KNOWN host bumps the failure counter only. */
    int64_t seen_before = od_scalar(db, "SELECT last_seen FROM peer_directory "
                                        "WHERE onion_address='" HOST_A "'", 0);
    memset(&obs, 0, sizeof(obs));
    snprintf(obs.hostname, sizeof(obs.hostname), "%s", HOST_A);
    obs.reachable = false;
    OD_CHECK("failed dial is applied to a known row",
             onion_service_directory_observe(&obs, 1, &st) == 1 &&
             st.failed == 1);
    OD_CHECK("failed dial bumps fail_count",
             od_scalar(db, "SELECT fail_count FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1) == 1);
    OD_CHECK("failed dial does NOT refresh last_seen",
             od_scalar(db, "SELECT last_seen FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1)
                 == seen_before);

    /* REACHED is our own contact: both stamps plus the success counter. */
    memset(&obs, 0, sizeof(obs));
    snprintf(obs.hostname, sizeof(obs.hostname), "%s", HOST_A);
    obs.reachable = true;
    obs.best_height = 0;
    OD_CHECK("reached is applied",
             onion_service_directory_observe(&obs, 1, &st) == 1 &&
             st.refreshed == 1);
    OD_CHECK("reached sets last_success",
             od_scalar(db, "SELECT last_success FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", 0) > 0);
    OD_CHECK("reached bumps dial_success_count",
             od_scalar(db, "SELECT dial_success_count FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1) == 1);
    OD_CHECK("reached clears the failure counter",
             od_scalar(db, "SELECT fail_count FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1) == 0);
    OD_CHECK("reached never lowers a known height",
             od_scalar(db, "SELECT height FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1) == 1234);

    /* Malformed hostnames never reach the table. */
    OD_CHECK("malformed host is refused by learn",
             !onion_service_directory_learn("not-an-onion", 8033, 1, 0,
                                            NULL) &&
             !onion_service_directory_learn(NULL, 8033, 1, 0, NULL));
    memset(&obs, 0, sizeof(obs));
    snprintf(obs.hostname, sizeof(obs.hostname), "%s", "not-an-onion");
    obs.reachable = true;
    OD_CHECK("malformed host is refused by observe",
             onion_service_directory_observe(&obs, 1, &st) == 0 &&
             st.unknown == 1);
    OD_CHECK("malformed host is never stored",
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory", -1) == 1);

    sqlite3_close(db);
    return failures;
}

/* ── 8. expiry ─────────────────────────────────────────────────── */

/* The dropped onion_directory_expire(datadir, now, max_age) is gone; the
 * surviving sweep runs inside onion_service_directory_refresh() against
 * ONION_DIR_EXPIRE_SECS. Same three properties asserted: the stale
 * non-self row goes, the SELF row survives however old it is, and a row
 * inside the window is untouched. The two argument-validation assertions
 * on the dropped signature become the equivalent guard on the survivor:
 * a refresh with no published datadir fails rather than silently
 * reporting success. */
static int od_test_expiry(const char *datadir)
{
    int failures = 0;

    sqlite3 *db = od_open(datadir);
    if (!db) { printf("onion_directory: cannot open fixture db\n"); return 1; }

    int64_t now = (int64_t)platform_time_wall_time_t();
    char sql[512];

    /* A stale peer row and a stale SELF row, both older than the cutoff. */
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO peer_directory "
        "(onion_address, port, services, height, last_seen, version, self) "
        "VALUES ('" HOST_B "',8033,0,0,%lld,'test',0)",
        (long long)(now - ONION_DIR_EXPIRE_SECS - 86400));
    OD_CHECK("stale peer row inserted", od_exec(db, sql));

    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO peer_directory "
        "(onion_address, port, services, height, last_seen, version, self) "
        "VALUES ('" HOST_SELF "',8033,0,0,%lld,'test',1)",
        (long long)(now - ONION_DIR_EXPIRE_SECS - 86400));
    OD_CHECK("stale self row inserted", od_exec(db, sql));
    sqlite3_close(db);

    struct onion_directory_refresh_stats st;
    OD_CHECK("the refresh round completes against a writable directory",
             onion_service_directory_refresh(&st));
    OD_CHECK("expire deletes exactly the stale non-self row", st.expired == 1);

    db = od_open(datadir);
    if (!db) { printf("onion_directory: cannot reopen fixture db\n"); return 1; }
    OD_CHECK("stale peer row is gone",
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory "
                           "WHERE onion_address='" HOST_B "'", -1) == 0);
    OD_CHECK("self row survives expiry",
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory "
                           "WHERE onion_address='" HOST_SELF "'", -1) == 1);
    OD_CHECK("fresh row survives expiry",
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory "
                           "WHERE onion_address='" HOST_A "'", -1) == 1);
    sqlite3_close(db);
    return failures;
}

/* ── 8b. the refresh round READS a cache; it never dials ───────── */

/* The round runs on the shared supervisor tick runner (30 s liveness
 * deadline) and used to call peer_strategy_discover_self() — NAT-PMP, then
 * UPnP SSDP + SOAP, then naked IP discovery — every ONION_DIR_REFRESH_SECS.
 * That function's own comment records that it blocks for tens of seconds on
 * a gateway that ignores it. Freezing every other supervised child for that
 * long, every 15 minutes, is the failure class the systemd watchdog has
 * SIGABRT'd this node for. The endpoint is now PUBLISHED by the probe and
 * the round only reads it, which is what these assertions pin: what lands
 * in the self row is exactly what was published, and nothing else. */
static int od_test_self_clearnet(const char *datadir)
{
    int failures = 0;
    static const uint8_t IP[4] = { 203, 0, 113, 7 };

    onion_directory_set_self_clearnet(IP, 8033);
    onion_service_set_address(HOST_SELF);   /* re-publishes our own row */

    sqlite3 *db = od_open(datadir);
    if (!db) { printf("onion_directory: cannot open fixture db\n"); return 1; }
    OD_CHECK("the self row carries the PUBLISHED clearnet endpoint",
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory WHERE "
                           "onion_address='" HOST_SELF "' AND self=1 AND "
                           "clearnet_ip='203.0.113.7' AND clearnet_port=8033",
                       -1) == 1);
    /* Track 2: the self row also advertises the mounted app-catalog Apps,
     * computed from the ONE site-route registry (net/site_routes.def app_id
     * column, def-row order) — blog and yardsale today. */
    OD_CHECK("the self row advertises the mounted app-catalog Apps",
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory WHERE "
                           "onion_address='" HOST_SELF "' AND self=1 AND "
                           "apps='blog,yardsale'", -1) == 1);
    sqlite3_close(db);

    /* Clearing the cache is published too: the next round drops the
     * endpoint rather than dialing to find out whether it still holds. */
    onion_directory_reset_self_clearnet();
    struct onion_directory_refresh_stats st;
    OD_CHECK("a round with no published endpoint still completes",
             onion_service_directory_refresh(&st));

    db = od_open(datadir);
    if (!db) { printf("onion_directory: cannot reopen fixture db\n"); return 1; }
    OD_CHECK("an unpublished endpoint leaves the self row without one",
             od_scalar(db, "SELECT COUNT(*) FROM peer_directory WHERE "
                           "onion_address='" HOST_SELF "' AND self=1 AND "
                           "clearnet_ip='' AND clearnet_port=0", -1) == 1);
    /* Publishing an all-zero address is an absence, not an endpoint. */
    static const uint8_t ZERO[4] = { 0, 0, 0, 0 };
    onion_directory_set_self_clearnet(ZERO, 8033);
    OD_CHECK("an all-zero published address is treated as no endpoint",
             onion_service_directory_refresh(&st) &&
             od_scalar(db, "SELECT clearnet_port FROM peer_directory WHERE "
                           "onion_address='" HOST_SELF "'", -1) == 0);
    sqlite3_close(db);

    onion_directory_reset_self_clearnet();
    onion_service_set_address(NULL);
    return failures;
}

/* ── 5. the ZNAM join ──────────────────────────────────────────── */

static int od_test_name_join(const char *datadir)
{
    int failures = 0;
    char name[80];

    /* No registration yet → nameless, and that is not an error. */
    OD_CHECK("unregistered host resolves to no name",
             !onion_directory_name_for(datadir, HOST_A, name, sizeof(name)) &&
             name[0] == '\0');

    sqlite3 *db = od_open(datadir);
    if (!db) { printf("onion_directory: cannot open fixture db\n"); return 1; }
    /* Stored WITHOUT the ".onion" suffix — the bare-56 form. */
    OD_CHECK("register alice -> HOST_A (bare form)",
             od_register_name(db, "alice",
                              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                              "aaaaaaaaaaaaaaaa", 100));
    /* Stored WITH the suffix — the full form. */
    OD_CHECK("register bob -> HOST_SELF (full form)",
             od_register_name(db, "bob", HOST_SELF, 200));
    sqlite3_close(db);

    OD_CHECK("bare-form registration resolves",
             onion_directory_name_for(datadir, HOST_A, name, sizeof(name)) &&
             strcmp(name, "alice") == 0);
    OD_CHECK("full-form registration resolves",
             onion_directory_name_for(datadir, HOST_SELF, name, sizeof(name)) &&
             strcmp(name, "bob") == 0);
    OD_CHECK("a host with no registration stays nameless",
             !onion_directory_name_for(datadir, HOST_C, name, sizeof(name)));
    OD_CHECK("malformed host resolves to no name",
             !onion_directory_name_for(datadir, "bogus", name, sizeof(name)));
    OD_CHECK("NULL datadir resolves to no name",
             !onion_directory_name_for(NULL, HOST_A, name, sizeof(name)));
    return failures;
}

/* ── 9. seller/app discovery: fresh rows advertising an app ──────────
 *
 * The read side of Track 2: /yardsale's "Known sellers" section queries
 * FRESH, non-self rows whose apps name the app. The assertions that
 * matter are the withholdings: a stale row, the SELF row (we are not our
 * own discovered seller), a hostile hostname, and a junk apps token all
 * stay out, whatever raw SQL put in the table. */
static int od_test_app_peers(const char *datadir)
{
    int failures = 0;
    struct onion_directory_app_peer peers[8];

    int64_t now = (int64_t)platform_time_wall_time_t();

    /* HOST_A already exists (fresh, no apps): the refresh fills them in. */
    OD_CHECK("apps refresh on the existing fresh row",
             onion_service_directory_learn(HOST_A, 8033, 1234, 0,
                                           "yardsale,blog"));

    sqlite3 *db = od_open(datadir);
    if (!db) { printf("onion_directory: cannot open fixture db\n"); return 1; }

    char sql[768];
    /* A STALE seller (last_seen past the fresh window): withheld. */
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO peer_directory "
        "(onion_address, port, services, height, last_seen, version, self,"
        " apps) "
        "VALUES ('" HOST_C "',8033,0,0,%lld,'test',0,'yardsale')",
        (long long)(now - ONION_DIR_STALE_SECS - 60));
    OD_CHECK("stale seller row inserted", od_exec(db, sql));
    /* A hostile hostname row: skipped by the read-time v3 rule. */
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO peer_directory "
        "(onion_address, port, services, height, last_seen, version, self,"
        " apps) "
        "VALUES ('not-an-onion',8033,0,0,%lld,'test',0,'yardsale')",
        (long long)now);
    OD_CHECK("hostile hostname row inserted", od_exec(db, sql));
    /* A junk-apps row, as a pre-validation binary might have stored it:
     * the valid token survives, the hostile one is normalized out. */
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO peer_directory "
        "(onion_address, port, services, height, last_seen, version, self,"
        " apps) "
        "VALUES ('" HOST_B "',8033,0,0,%lld,'test',0,"
        "'yardsale,<img src=x>')",
        (long long)now);
    OD_CHECK("junk-apps row inserted", od_exec(db, sql));

    int n = onion_directory_app_peers_db(db, "yardsale", now, peers, 8);
    OD_CHECK("exactly the fresh non-self yardsale sellers are returned",
             n == 2);
    bool got_a = false, got_b = false;
    for (int i = 0; i < n; i++) {
        if (strcmp(peers[i].onion, HOST_A) == 0)
            got_a = strcmp(peers[i].apps, "yardsale,blog") == 0;
        if (strcmp(peers[i].onion, HOST_B) == 0)
            got_b = strcmp(peers[i].apps, "yardsale") == 0;
    }
    OD_CHECK("the fresh seller carries its full sanitized list", got_a);
    OD_CHECK("the junk token was normalized out of the read", got_b);
    OD_CHECK("the SELF row is never a discovered seller",
             n == 2);   /* HOST_SELF serves blog,yardsale — would be 3rd */

    n = onion_directory_app_peers_db(db, "blog", now, peers, 8);
    OD_CHECK("an app only one peer serves finds exactly that peer",
             n == 1 && strcmp(peers[0].onion, HOST_A) == 0);

    n = onion_directory_app_peers_db(db, "yardsale", now, peers, 1);
    OD_CHECK("the caller's cap bounds the listing", n == 1);

    OD_CHECK("a malformed app id is refused, not matched",
             onion_directory_app_peers_db(db, "Bad", now, peers, 8) == 0);
    OD_CHECK("an app nobody serves is an honest zero",
             onion_directory_app_peers_db(db, "metaverse", now, peers,
                                          8) == 0);
    OD_CHECK("a NULL db is an honest zero",
             onion_directory_app_peers_db(NULL, "yardsale", now, peers,
                                          8) == 0);

    sqlite3_close(db);
    return failures;
}

/* ── 10. end-to-end through the real request handler ───────────── */

static int od_test_served_pages(const char *datadir)
{
    int failures = 0;

    /* Drive the REAL onion request router. onion_service_start only opens
     * the database; no app handler is registered, so nothing dials. */
    onion_service_start(datadir);
    onion_ratelimit_test_reset();

    static uint8_t resp[262144];

    /* SEARCH BY NAME — the case that returned "No results" before. */
    memset(resp, 0, sizeof(resp));
    size_t n = onion_service_handle_request("GET", "/search?q=alice", NULL, 0,
                                            resp, sizeof(resp) - 1);
    resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = 0;
    const char *page = (const char *)resp;
    OD_CHECK("search by name returns a page", n > 0);
    OD_CHECK("search by name finds the registered name",
             strstr(page, "alice") != NULL);
    OD_CHECK("search by name shows the RAW address too",
             strstr(page, HOST_A) != NULL);
    OD_CHECK("search by name reports no 'No results'",
             strstr(page, "No results") == NULL);

    /* SEARCH BY ADDRESS — the pre-existing behaviour, not narrowed. */
    onion_ratelimit_test_reset();
    memset(resp, 0, sizeof(resp));
    n = onion_service_handle_request("GET", "/search?q=aaaaaaaa", NULL, 0,
                                     resp, sizeof(resp) - 1);
    resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = 0;
    OD_CHECK("search by address prefix still works",
             strstr((const char *)resp, HOST_A) != NULL);

    /* A query matching nothing must still say so. */
    onion_ratelimit_test_reset();
    memset(resp, 0, sizeof(resp));
    n = onion_service_handle_request("GET", "/search?q=zzzznomatch", NULL, 0,
                                     resp, sizeof(resp) - 1);
    resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = 0;
    OD_CHECK("non-matching query reports no results",
             strstr((const char *)resp, "No results") != NULL);

    /* DIRECTORY JSON — name beside the address, plus the age fields. */
    onion_ratelimit_test_reset();
    memset(resp, 0, sizeof(resp));
    n = onion_service_handle_request("GET", "/directory.json", NULL, 0,
                                     resp, sizeof(resp) - 1);
    resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = 0;
    const char *js = (const char *)resp;
    OD_CHECK("directory.json served", n > 0);
    OD_CHECK("directory.json carries the on-chain name",
             strstr(js, "\"name\":\"alice\"") != NULL);
    OD_CHECK("directory.json still carries the raw onion",
             strstr(js, "\"onion\":\"" HOST_A "\"") != NULL);
    OD_CHECK("directory.json carries per-row age",
             strstr(js, "\"age_secs\":") != NULL);
    /* The contact record, under the surviving column names: last_success
     * + dial_success_count for contact, fail_count for failures (the
     * dropped table called that one dial_fail_count). */
    OD_CHECK("directory.json carries the contact record",
             strstr(js, "\"last_success\":") != NULL &&
             strstr(js, "\"dial_success_count\":") != NULL &&
             strstr(js, "\"fail_count\":") != NULL);
    OD_CHECK("directory.json declares its freshness policy",
             strstr(js, "\"expire_after_secs\":") != NULL &&
             strstr(js, "\"stale_after_secs\":") != NULL);
    /* Track 2: the self row serves its app advertisement (the mounted
     * app-catalog Apps from the site-route registry). */
    OD_CHECK("directory.json serves the self row's app advertisement",
             strstr(js, "\"apps\":[\"blog\",\"yardsale\"]") != NULL);

    /* DIRECTORY HTML — name as the heading, address still rendered. */
    onion_ratelimit_test_reset();
    memset(resp, 0, sizeof(resp));
    n = onion_service_handle_request("GET", "/directory", NULL, 0,
                                     resp, sizeof(resp) - 1);
    resp[n < sizeof(resp) ? n : sizeof(resp) - 1] = 0;
    const char *html = (const char *)resp;
    OD_CHECK("directory html served", n > 0);
    OD_CHECK("directory html shows the name", strstr(html, "alice") != NULL);
    OD_CHECK("directory html still shows the raw address",
             strstr(html, HOST_A) != NULL);
    OD_CHECK("directory html reports our contact record",
             strstr(html, "Reached") != NULL);

    onion_service_stop();

    /* The guard the dropped expire()'s NULL-datadir assertion tested, in
     * the survivor's terms: with the service stopped there is no
     * directory to refresh, and the round says so instead of reporting a
     * silent success. */
    struct onion_directory_refresh_stats st;
    OD_CHECK("a refresh with no published datadir fails, never silently ok",
             !onion_service_directory_refresh(&st));
    return failures;
}

/* ── Entry point ──────────────────────────────────────────────────── */

int test_onion_directory(void)
{
    int failures = 0;
    printf("\n=== Onion Directory (freshness, names, onion-graph walk) ===\n");

    /* The address singleton is process-global; the sequential runner
     * shares it across groups. Snapshot and restore. */
    const char *prev = onion_service_get_address();
    char saved[128] = "";
    if (prev) snprintf(saved, sizeof(saved), "%s", prev);
    onion_service_set_address(NULL);

    failures += od_freshness_rule();
    failures += od_parse_relay_hints();
    failures += od_apps_pure_helpers();
    failures += od_follow_budget();
    failures += od_durable_directory();

    /* Static: onion_service_start() borrows this pointer for ctx->datadir. */
    static char datadir[256];
    test_make_tmpdir(datadir, sizeof(datadir), "onion_dir", "names");

    failures += od_test_hostname_shape();
    failures += od_test_scan();
    failures += od_test_observe(datadir);
    failures += od_test_expiry(datadir);
    failures += od_test_self_clearnet(datadir);
    failures += od_test_name_join(datadir);
    failures += od_test_app_peers(datadir);
    failures += od_test_served_pages(datadir);

    /* Sub-test in its own file (test_onion_directory_stale_hearsay.c):
     * the freshness boundary from both sides, and the bound on what a
     * flood of expired relayed stamps costs the log. Runs last — it
     * re-points the onion context at its own datadir. */
    { extern int od_stale_hearsay_bound(void);
      failures += od_stale_hearsay_bound(); }

    test_cleanup_tmpdir(datadir);
    onion_service_set_address(saved[0] ? saved : NULL);

    printf("=== Onion Directory: %d failure(s) ===\n", failures);
    return failures;
}
