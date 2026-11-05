/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the fail-loud validation pack check 7 (+ check 5 post-import
 * half) — engine/services/src/seed_integrity_gate.c:
 *
 *   - empty blocks projection: vacuous pass (fresh datadir non-fire);
 *   - healthy linked suffix: pass (cold-import non-fire);
 *   - suffix that ends (snapshot seeds lack deep rows): pass;
 *   - seed-tip pair mismatch (row labeled differently): REFUSED +
 *     PERMANENT seed.linkage_gate blocker, process alive (crash-only);
 *   - linkage break (parent labeled h-7, the splice-at-birth shape):
 *     REFUSED naming the break;
 *   - absent tip row: pass-with-warn (projection backfill ordering);
 *   - memo: re-running the same (height,hash) returns the cached verdict.
 */

#include "test/test_core.h"

#include "base/hex.h"
#include "coins/utxo_commitment.h"
#include "json/json.h"
#include "models/database.h"
#include "services/invariant_sentinel.h"
#include "services/seed_integrity_gate.h"
#include "util/blocker.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#define SIG_CHECK(name, expr) do {                  \
    printf("seed_integrity_gate: %s... ", (name));  \
    if (expr) printf("OK\n");                         \
    else { printf("FAIL\n"); failures++; }            \
} while (0)

static void sig_hash(uint8_t out[32], int h, uint8_t salt)
{
    memset(out, 0, 32);
    out[0] = (uint8_t)(h & 0xFF);
    out[1] = (uint8_t)((h >> 8) & 0xFF);
    out[2] = (uint8_t)((h >> 16) & 0xFF);
    out[3] = salt;
    /* a distinct last byte per height: a walk that drops the final byte
     * of a stored hash must miss the row it names */
    out[31] = (uint8_t)(0x80 | ((h * 5 + salt) & 0x7F));
}

static bool sig_insert(struct node_db *ndb, const uint8_t hash[32],
                       int height, const uint8_t prev[32])
{
    sqlite3_stmt *st = NULL;
    const char *sql =
        "INSERT OR REPLACE INTO blocks"
        "(hash,height,prev_hash,version,merkle_root,time,bits,nonce,"
        " solution,chain_work,status,num_tx)"
        " VALUES(?,?,?,4,?,?,0,?,?,?,3,0)";
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    static const uint8_t zeros[32] = {0};
    static const uint8_t solution[1] = {0};
    sqlite3_bind_blob(st, 1, hash, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 2, height);
    sqlite3_bind_blob(st, 3, prev ? prev : zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 4, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_int64(st, 5, 1700000000 + height);
    sqlite3_bind_blob(st, 6, zeros, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 7, solution, sizeof(solution), SQLITE_STATIC);
    sqlite3_bind_blob(st, 8, zeros, 32, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

/* Build a healthy linked span [lo..hi] with the given salt; out_tip gets
 * the hash at hi. */
static bool sig_build_span(struct node_db *ndb, int lo, int hi,
                           uint8_t salt, uint8_t out_tip[32])
{
    uint8_t prev[32]; memset(prev, 0, 32);
    uint8_t cur[32];
    for (int h = lo; h <= hi; h++) {
        sig_hash(cur, h, salt);
        if (!sig_insert(ndb, cur, h, (h == lo) ? NULL : prev))
            return false;
        memcpy(prev, cur, 32);
    }
    memcpy(out_tip, prev, 32);
    return true;
}


/* ---- mutation-sweep additions ------------------------------------- */

static bool sig_fixture(struct node_db *ndb)
{
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();
    if (!node_db_open(ndb, ":memory:")) {
        printf("seed_integrity_gate: fixture: node_db opens... FAIL\n");
        return false;
    }
    seed_integrity_gate_set_node_db_for_testing(ndb);
    return true;
}

static void sig_teardown(struct node_db *ndb)
{
    seed_integrity_gate_reset_for_testing();
    blocker_reset_for_testing();
    node_db_close(ndb);
}

/* Counter the gate feeds the sentinel: runs only on a fresh evaluation. */
static int64_t sig_stat(const char *key)
{
    struct json_value j;
    json_init(&j);
    int64_t v = -1;
    if (invariant_sentinel_dump_state_json(&j, "seed_gate")) {
        const struct json_value *f = json_get(&j, key);
        if (f)
            v = json_get_int(f);
    }
    json_free(&j);
    return v;
}

static bool sig_reason_has(const char *needle)
{
    struct blocker_snapshot snaps[16];
    int n = blocker_snapshot_all(snaps, 16);
    for (int i = 0; i < n; i++)
        if (strcmp(snaps[i].id, "seed.linkage_gate") == 0)
            return strstr(snaps[i].reason, needle) != NULL;
    return false;
}

static void sig_hex8(const uint8_t h[32], char out[17])
{
    zcl_hex_encode(h, 8, out);
}

static bool sig_gate(int h, const uint8_t hash[32], bool trusted)
{
    return seed_integrity_gate_check(h, hash, trusted);
}

/* Walk edges: a suffix that ends on an ABSENT non-zero parent, the
 * genesis stop, a zero prev that collides with a stored row, and the
 * height-0 / height-1 boundaries. */
static int sig_test_walk_edges(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    uint8_t t[32], p[32];

    sig_hash(t, 400, 0x10); sig_hash(p, 399, 0x10);
    bool built = sig_insert(&ndb, t, 400, p);
    SIG_CHECK("suffix ends on absent non-zero parent: pass",
              built && sig_gate(400, t, false));

    /* seed height 0 with a non-zero prev pointing at a row labeled 5:
     * genesis ends the walk, the parent is never consulted */
    sig_hash(t, 0, 0x11); sig_hash(p, 5, 0x11);
    built = sig_insert(&ndb, p, 5, NULL) && sig_insert(&ndb, t, 0, p);
    SIG_CHECK("height 0 tip stops at genesis: pass",
              built && sig_gate(0, t, false));

    /* the pair check applies at seed height 0 too */
    sig_hash(t, 5, 0x12);
    built = sig_insert(&ndb, t, 5, NULL);
    SIG_CHECK("seed height 0 over a row labeled 5: REFUSED",
              built && !sig_gate(0, t, false));
    blocker_clear("seed.linkage_gate");

    /* height 1: the parent IS consulted (must be labeled 0) */
    sig_hash(t, 1, 0x13); sig_hash(p, 7, 0x13);
    built = sig_insert(&ndb, p, 7, NULL) && sig_insert(&ndb, t, 1, p);
    SIG_CHECK("height 1 over a parent labeled 7: REFUSED",
              built && !sig_gate(1, t, false));
    blocker_clear("seed.linkage_gate");
    sig_hash(t, 1, 0x14); sig_hash(p, 0, 0x14);
    built = sig_insert(&ndb, p, 0, NULL) && sig_insert(&ndb, t, 1, p);
    SIG_CHECK("height 1 over a parent labeled 0: pass",
              built && sig_gate(1, t, false));

    /* an all-zero prev is a chain end even if a row hashed 0x00..00
     * exists and carries some other label */
    uint8_t zero[32] = {0};
    sig_hash(t, 5, 0x15);
    built = sig_insert(&ndb, zero, 999, NULL) && sig_insert(&ndb, t, 5, NULL);
    SIG_CHECK("zero prev ends the walk even beside a zero-hash row",
              built && sig_gate(5, t, false));
    SIG_CHECK("edges: no blocker left by passes",
              !blocker_exists("seed.linkage_gate"));
    sig_teardown(&ndb);
    return failures;
}

/* One tip at height 50 whose parent carries `label`. */
static bool sig_parent_label_gate(struct node_db *ndb, int label,
                                  uint8_t salt)
{
    uint8_t t[32], p[32];
    sig_hash(t, 50, salt); sig_hash(p, 49, salt);
    if (!sig_insert(ndb, p, label, NULL) || !sig_insert(ndb, t, 50, p))
        return true; /* fixture failure reads as "not refused" -> test fails */
    return sig_gate(50, t, false);
}

/* Every parent label other than child-1 refuses, on both sides, and the
 * recorded reason names the break exactly. */
static int sig_test_label_offsets(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    SIG_CHECK("parent labeled child-1: pass",
              sig_parent_label_gate(&ndb, 49, 0x20));
    SIG_CHECK("parent labeled child-2 (-1): REFUSED",
              !sig_parent_label_gate(&ndb, 48, 0x22));
    SIG_CHECK("parent labeled child+1: REFUSED",
              !sig_parent_label_gate(&ndb, 51, 0x23));
    blocker_clear("seed.linkage_gate");

    uint8_t p[32]; char hx[17];
    sig_hash(p, 49, 0x24);
    sig_hex8(p, hx);
    SIG_CHECK("break at depth 0 refused",
              !sig_parent_label_gate(&ndb, 40, 0x24));
    char want[96];
    snprintf(want, sizeof(want), "parent %s is labeled h=40 (expected 49)", hx);
    SIG_CHECK("reason names parent hash prefix, label, expectation",
              sig_reason_has("linkage break at h=50: parent") &&
              sig_reason_has(want));
    SIG_CHECK("reason names the label-splice cause",
              sig_reason_has("label splice at birth"));
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

/* A break two links down: the second step must carry the FULL parent
 * hash (last byte included) or the lookup misses and the break passes. */
static int sig_test_deep_break(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    uint8_t t[32], p1[32], p2[32];
    sig_hash(t, 80, 0x30); sig_hash(p1, 79, 0x30); sig_hash(p2, 78, 0x30);
    bool built = sig_insert(&ndb, p2, 70, NULL) &&
                 sig_insert(&ndb, p1, 79, p2) && sig_insert(&ndb, t, 80, p1);
    SIG_CHECK("break two links down: REFUSED",
              built && !sig_gate(80, t, false));
    char hx[17], want[96];
    sig_hex8(p2, hx);
    snprintf(want, sizeof(want),
             "linkage break at h=79: parent %s is labeled h=70 (expected 78)",
             hx);
    SIG_CHECK("deep reason names h=79, parent, label 70, expected 78",
              sig_reason_has(want));
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

/* A prev hash that is non-zero in ONE byte only (first / last) must still
 * be followed, not mistaken for a genesis-style zero prev. */
static bool sig_one_byte_prev_gate(struct node_db *ndb, int pos, uint8_t salt)
{
    uint8_t t[32], p[32];
    memset(p, 0, 32);
    p[pos] = 1;
    sig_hash(t, 60, salt);
    if (!sig_insert(ndb, p, 10, NULL) || !sig_insert(ndb, t, 60, p))
        return true;
    return sig_gate(60, t, false);
}

static int sig_test_one_byte_prev(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    SIG_CHECK("prev non-zero only in byte 0, parent mislabeled: REFUSED",
              !sig_one_byte_prev_gate(&ndb, 0, 0x40));
    SIG_CHECK("prev non-zero only in byte 31, parent mislabeled: REFUSED",
              !sig_one_byte_prev_gate(&ndb, 31, 0x41));
    SIG_CHECK("prev non-zero only in byte 15, parent mislabeled: REFUSED",
              !sig_one_byte_prev_gate(&ndb, 15, 0x42));
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

/* The pair-mismatch refusal names hash prefix, stored and claimed heights. */
static int sig_test_pair_reason(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    uint8_t t[32]; char hx[17], want[96];
    sig_hash(t, 206, 0x50);
    bool built = sig_insert(&ndb, t, 206, NULL);
    SIG_CHECK("pair mismatch refused", built && !sig_gate(200, t, false));
    sig_hex8(t, hx);
    snprintf(want, sizeof(want), "hash=%s has height=206, seed says 200", hx);
    SIG_CHECK("pair reason names hash prefix and both heights",
              sig_reason_has("seed pair mismatch: blocks row for") &&
              sig_reason_has(want));
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

/* Chain tip_h .. tip_h-break_iter-1 whose parent at link break_iter+1 is
 * mislabeled. Link k is examined at walk iteration k-1. */
static bool sig_build_deep(struct node_db *ndb, int tip_h, int break_iter,
                           uint8_t salt, uint8_t out_tip[32])
{
    uint8_t cur[32], par[32];
    bool ok = true;
    sqlite3_exec(ndb->db, "BEGIN", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    for (int j = 0; ok && j <= break_iter + 1; j++) {
        int h = tip_h - j;
        sig_hash(cur, h, salt);
        sig_hash(par, h - 1, salt);
        ok = sig_insert(ndb, cur, (j == break_iter + 1) ? h - 3 : h, par);
    }
    sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL);  // raw-sql-ok:test-fixture-seeding
    sig_hash(out_tip, tip_h, salt);
    return ok;
}

/* The walk budget is 10000 links: a break at the last examined link is
 * caught, a break one link past it is not reached. */
static int sig_test_walk_budget(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    uint8_t tip[32];
    bool built = sig_build_deep(&ndb, 20000, 9999, 0x60, tip);
    SIG_CHECK("break at link 10000 (last in budget): REFUSED",
              built && !sig_gate(20000, tip, false));
    blocker_clear("seed.linkage_gate");
    built = sig_build_deep(&ndb, 20000, 10000, 0x61, tip);
    SIG_CHECK("break at link 10001 (past budget): not reached, pass",
              built && sig_gate(20000, tip, false));
    sig_teardown(&ndb);
    return failures;
}

/* Memo behaviour, observed through the sentinel's run counter. */
static int sig_test_memo_keys(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    uint8_t a[32], b[32];
    sig_hash(a, 70, 0x70);
    memcpy(b, a, 32);
    b[31] ^= 0x01;                      /* differs in the last byte only */
    bool built = sig_insert(&ndb, a, 70, NULL);  /* b has no row: absent tip passes */
    int64_t r0 = sig_stat("seed_gate_runs");
    int64_t f0 = sig_stat("seed_gate_refusals");
    SIG_CHECK("memo: counters readable", r0 >= 0 && f0 >= 0);

    SIG_CHECK("memo: first (70,a) passes", built && sig_gate(70, a, false));
    SIG_CHECK("memo: first evaluation counted once",
              sig_stat("seed_gate_runs") == r0 + 1);
    SIG_CHECK("memo: pass is not a counted refusal",
              sig_stat("seed_gate_refusals") == f0);
    SIG_CHECK("memo: repeat passes", sig_gate(70, a, false));
    SIG_CHECK("memo: repeat is served from the memo",
              sig_stat("seed_gate_runs") == r0 + 1);

    SIG_CHECK("memo: (70,b) passes", sig_gate(70, b, false));
    SIG_CHECK("memo: hash differing in the last byte re-evaluates",
              sig_stat("seed_gate_runs") == r0 + 2);
    SIG_CHECK("memo: (70,b) repeat passes", sig_gate(70, b, false));
    SIG_CHECK("memo: (70,b) repeat served from memo (last byte stored)",
              sig_stat("seed_gate_runs") == r0 + 2);

    /* same hash, other height: row says 70, seed says 71 -> must refuse */
    SIG_CHECK("memo: stored hash at another height is re-evaluated, REFUSED",
              !sig_gate(71, a, false));
    SIG_CHECK("memo: other height counted as a run and a refusal",
              sig_stat("seed_gate_runs") == r0 + 3 &&
              sig_stat("seed_gate_refusals") == f0 + 1);
    SIG_CHECK("memo: refusal repeats from memo",
              !sig_gate(71, a, false) &&
              sig_stat("seed_gate_runs") == r0 + 3 &&
              sig_stat("seed_gate_refusals") == f0 + 1);
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

/* The test reset hook really drops the memo and the injected db. */
static int sig_test_reset_hook(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    uint8_t t[32];
    sig_hash(t, 90, 0x80);
    bool built = sig_insert(&ndb, t, 90, NULL);
    SIG_CHECK("reset: first pass", built && sig_gate(90, t, false));
    sig_insert(&ndb, t, 91, NULL);      /* now a pair mismatch */
    SIG_CHECK("reset: memo still answers pass", sig_gate(90, t, false));
    seed_integrity_gate_reset_for_testing();
    seed_integrity_gate_set_node_db_for_testing(&ndb);
    SIG_CHECK("reset: memo dropped, fresh evaluation REFUSES",
              !sig_gate(90, t, false));
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

/* Gate argument and wiring guards. */
static int sig_test_args(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    uint8_t t[32];
    sig_hash(t, 5, 0x90);
    SIG_CHECK("negative height: pass (not a gate concern)",
              sig_gate(-1, t, true));
    SIG_CHECK("NULL hash: pass (not a gate concern)",
              seed_integrity_gate_check(5, NULL, true));
    SIG_CHECK("args: rejected args raise no blocker",
              !blocker_exists("seed.linkage_gate"));
    struct node_db closed = {0};
    seed_integrity_gate_set_node_db_for_testing(&closed);
    SIG_CHECK("unwired node_db: gate skipped, pass", sig_gate(5, t, true));
    sig_teardown(&ndb);
    return failures;
}

static bool sig_add_utxo(struct node_db *ndb, uint8_t id, uint32_t vout,
                         int64_t value)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT INTO utxos(txid,vout,value,script,height,is_coinbase)"
            " VALUES(?,?,?,?,7,0)", -1, &st, NULL) != SQLITE_OK)
        return false;
    uint8_t txid[32];
    memset(txid, id, 32);
    static const uint8_t script[3] = {0x76, 0xA9, 0x14};
    sqlite3_bind_blob(st, 1, txid, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, (int)vout);
    sqlite3_bind_int64(st, 3, value);
    sqlite3_bind_blob(st, 4, script, 3, SQLITE_STATIC);
    int rc = sqlite3_step(st);  // raw-sql-ok:test-fixture-seeding
    sqlite3_finalize(st);
    return rc == SQLITE_DONE;
}

/* A single-row healthy chain at height h, hashed by `salt`. */
static bool sig_one_row(struct node_db *ndb, int h, uint8_t salt,
                        uint8_t out[32])
{
    sig_hash(out, h, salt);
    return sig_insert(ndb, out, h, NULL);
}

/* utxo_sha3 commitment gate (trusted seeds only). */
static int sig_test_commitment(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    bool built = sig_add_utxo(&ndb, 0xA1, 0, 5000) &&
                 sig_add_utxo(&ndb, 0xA2, 1, 7000);
    uint8_t root[32], bad[32], t[32];
    uint64_t count = 0;
    utxo_commitment_sha3_compute(ndb.db, root, &count);
    SIG_CHECK("commitment fixture: two utxos hashed", built && count == 2);

    /* no stamp at all */
    built = sig_one_row(&ndb, 100, 0xB0, t);
    SIG_CHECK("trusted, no stamp: pass", built && sig_gate(100, t, true));

    /* matching stamp */
    built = sig_one_row(&ndb, 101, 0xB1, t) &&
            seed_integrity_stamp_utxo_sha3(&ndb, 101, root, count);
    SIG_CHECK("trusted, matching stamp: pass", built && sig_gate(101, t, true));
    SIG_CHECK("matching stamp: no blocker",
              !blocker_exists("seed.linkage_gate"));

    /* stamp at another height is skipped even when its hash is wrong */
    memset(bad, 0xEE, 32);
    built = sig_one_row(&ndb, 102, 0xB2, t) &&
            seed_integrity_stamp_utxo_sha3(&ndb, 999, bad, 77);
    SIG_CHECK("trusted, stamp at other height: gate skipped, pass",
              built && sig_gate(102, t, true));

    /* untrusted seeds never run the commitment check */
    built = sig_one_row(&ndb, 103, 0xB3, t) &&
            seed_integrity_stamp_utxo_sha3(&ndb, 103, bad, 77);
    SIG_CHECK("untrusted, wrong stamp at seed height: pass (not checked)",
              built && sig_gate(103, t, false));
    sig_teardown(&ndb);
    return failures;
}

/* Each way a stamp can disagree with the recomputed set refuses. */
static bool sig_stamped_gate(struct node_db *ndb, int h, uint8_t salt,
                             const uint8_t root[32], uint64_t count)
{
    uint8_t t[32];
    if (!sig_one_row(ndb, h, salt, t) ||
        !seed_integrity_stamp_utxo_sha3(ndb, h, root, count))
        return true;
    return sig_gate(h, t, true);
}

static int sig_test_commitment_refusals(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    bool built = sig_add_utxo(&ndb, 0xA1, 0, 5000) &&
                 sig_add_utxo(&ndb, 0xA2, 1, 7000);
    uint8_t root[32], bad[32];
    uint64_t count = 0;
    utxo_commitment_sha3_compute(ndb.db, root, &count);
    SIG_CHECK("refusal fixture: two utxos hashed", built && count == 2);

    memcpy(bad, root, 32); bad[31] ^= 0x01;
    SIG_CHECK("stamp differs in last hash byte: REFUSED",
              !sig_stamped_gate(&ndb, 110, 0xC0, bad, count));
    SIG_CHECK("last-byte reason carries both counts",
              sig_reason_has("utxo commitment mismatch at seed h=110: "
                             "count_expected=2 count_got=2"));
    blocker_clear("seed.linkage_gate");

    memcpy(bad, root, 32); bad[0] ^= 0x01;
    SIG_CHECK("stamp differs in first hash byte: REFUSED",
              !sig_stamped_gate(&ndb, 111, 0xC1, bad, count));
    blocker_clear("seed.linkage_gate");

    SIG_CHECK("right hash, wrong count: REFUSED",
              !sig_stamped_gate(&ndb, 112, 0xC2, root, 3));
    SIG_CHECK("count reason names expected 3, got 2",
              blocker_exists("seed.linkage_gate") &&
              sig_reason_has("count_expected=3 count_got=2"));
    blocker_clear("seed.linkage_gate");

    /* a broken linkage is not rescued by a clean commitment */
    uint8_t t[32], p[32];
    sig_hash(t, 120, 0xC3); sig_hash(p, 119, 0xC3);
    built = sig_insert(&ndb, p, 100, NULL) && sig_insert(&ndb, t, 120, p) &&
            seed_integrity_stamp_utxo_sha3(&ndb, 120, root, count);
    SIG_CHECK("trusted seed, broken linkage, clean stamp: REFUSED",
              built && !sig_gate(120, t, true));
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

/* seed_integrity_stamp_utxo_sha3 argument guards and round trip. */
static int sig_test_stamp_args(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    uint8_t root[32], got[32];
    memset(root, 0x5A, 32);
    int32_t gh = -1;
    uint64_t gc = 0;

    struct node_db shut = ndb;
    shut.open = false;
    struct node_db nodb = ndb;
    nodb.db = NULL;
    SIG_CHECK("stamp: NULL node_db refused",
              !seed_integrity_stamp_utxo_sha3(NULL, 5, root, 1));
    SIG_CHECK("stamp: closed node_db refused",
              !seed_integrity_stamp_utxo_sha3(&shut, 5, root, 1));
    SIG_CHECK("stamp: node_db without a handle refused",
              !seed_integrity_stamp_utxo_sha3(&nodb, 5, root, 1));
    SIG_CHECK("stamp: negative height refused",
              !seed_integrity_stamp_utxo_sha3(&ndb, -1, root, 1));
    SIG_CHECK("stamp: NULL root refused",
              !seed_integrity_stamp_utxo_sha3(&ndb, 5, NULL, 1));
    SIG_CHECK("stamp: refused calls saved nothing",
              !utxo_commitment_sha3_load(ndb.db, got, &gh, &gc));

    SIG_CHECK("stamp at height 0 accepted",
              seed_integrity_stamp_utxo_sha3(&ndb, 0, root, 9));
    SIG_CHECK("stamp round trip: height 0, count 9, root",
              utxo_commitment_sha3_load(ndb.db, got, &gh, &gc) &&
              gh == 0 && gc == 9 && memcmp(got, root, 32) == 0);
    SIG_CHECK("stamp at height 5 accepted",
              seed_integrity_stamp_utxo_sha3(&ndb, 5, root, 4));
    SIG_CHECK("stamp replaced: height 5, count 4",
              utxo_commitment_sha3_load(ndb.db, got, &gh, &gc) &&
              gh == 5 && gc == 4);
    sig_teardown(&ndb);
    return failures;
}

/* A pass memoized by an untrusted call (linkage walk only) must not be
 * returned to a later trusted call on the same (height, hash): the
 * commitment check never ran for it. */
static int sig_test_trusted_memo(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    bool built = sig_add_utxo(&ndb, 0xA1, 0, 5000);
    uint8_t root[32], bad[32], t[32];
    uint64_t count = 0;
    utxo_commitment_sha3_compute(ndb.db, root, &count);
    memcpy(bad, root, 32);
    bad[0] ^= 0x01;

    built = built && sig_one_row(&ndb, 140, 0xD0, t);
    SIG_CHECK("memo trust: untrusted call passes", built && sig_gate(140, t, false));
    built = built && seed_integrity_stamp_utxo_sha3(&ndb, 140, bad, count);
    SIG_CHECK("memo trust: trusted call after an untrusted pass runs the commitment, REFUSED",
              built && !sig_gate(140, t, true));
    blocker_clear("seed.linkage_gate");

    /* the other way: a trusted pass may satisfy an untrusted repeat */
    built = sig_one_row(&ndb, 141, 0xD1, t) &&
            seed_integrity_stamp_utxo_sha3(&ndb, 141, root, count);
    int64_t r0 = sig_stat("seed_gate_runs");
    SIG_CHECK("memo trust: trusted call passes", built && sig_gate(141, t, true));
    SIG_CHECK("memo trust: untrusted repeat served from the trusted pass",
              sig_gate(141, t, false) && sig_stat("seed_gate_runs") == r0 + 1);
    blocker_clear("seed.linkage_gate");

    /* a trusted refusal stays a refusal: an untrusted repeat must neither walk
     * again nor overwrite it with a linkage-only pass */
    built = sig_one_row(&ndb, 142, 0xD2, t) &&
            seed_integrity_stamp_utxo_sha3(&ndb, 142, bad, count);
    r0 = sig_stat("seed_gate_runs");
    SIG_CHECK("memo trust: trusted call refused", built && !sig_gate(142, t, true));
    SIG_CHECK("memo trust: untrusted repeat keeps the trusted refusal",
              !sig_gate(142, t, false) && sig_stat("seed_gate_runs") == r0 + 1);
    SIG_CHECK("memo trust: the trusted refusal is still stored",
              !sig_gate(142, t, true) && sig_stat("seed_gate_runs") == r0 + 1);
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

/* A stamp written after a trusted check must drop the stored answer: the
 * same (height, hash) re-checked after the stamp reads the new stamp, in
 * both directions (pass -> refusal, refusal -> pass). */
static int sig_test_stamp_drops_memo(void)
{
    int failures = 0;
    struct node_db ndb = {0};
    if (!sig_fixture(&ndb))
        return 1;
    bool built = sig_add_utxo(&ndb, 0xA1, 0, 5000);
    uint8_t root[32], bad[32], t[32];
    uint64_t count = 0;
    utxo_commitment_sha3_compute(ndb.db, root, &count);
    memcpy(bad, root, 32);
    bad[0] ^= 0x01;

    built = built && sig_one_row(&ndb, 150, 0xE0, t);
    SIG_CHECK("stamp memo: trusted, no stamp: pass", built && sig_gate(150, t, true));
    built = built && seed_integrity_stamp_utxo_sha3(&ndb, 150, bad, count);
    SIG_CHECK("stamp memo: wrong stamp after a memoized pass: re-check REFUSED",
              built && !sig_gate(150, t, true));
    blocker_clear("seed.linkage_gate");
    built = built && seed_integrity_stamp_utxo_sha3(&ndb, 150, root, count);
    SIG_CHECK("stamp memo: right stamp after a memoized refusal: re-check passes",
              built && sig_gate(150, t, true));
    blocker_clear("seed.linkage_gate");
    sig_teardown(&ndb);
    return failures;
}

int test_seed_integrity_gate(void)
{
    printf("\n=== seed_integrity_gate tests ===\n");
    int failures = 0;

    blocker_module_init();
    blocker_reset_for_testing();
    seed_integrity_gate_reset_for_testing();

    struct node_db ndb;
    if (!node_db_open(&ndb, ":memory:")) {
        SIG_CHECK("fixture: in-memory node_db opens", false);
        return failures;
    }
    seed_integrity_gate_set_node_db_for_testing(&ndb);

    /* 1. Empty projection: absent tip row -> pass with warn. */
    {
        uint8_t tip[32]; sig_hash(tip, 50, 0x01);
        bool ok = seed_integrity_gate_check(50, tip, false);
        SIG_CHECK("empty projection: pass (absent tip row = warn)", ok);
    }

    /* 2. Healthy linked suffix [0..60]: pass (untrusted seed: linkage
     * walk only). */
    {
        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        uint8_t tip[32];
        bool built = sig_build_span(&ndb, 0, 60, 0x02, tip);
        bool ok = built && seed_integrity_gate_check(60, tip, false);
        SIG_CHECK("healthy linked chain [0..60]: pass", ok);
        SIG_CHECK("healthy: no blocker",
                  !blocker_exists("seed.linkage_gate"));
    }

    /* 3. Suffix ends mid-walk (snapshot shape: rows only above base):
     * pass. */
    {
        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        uint8_t tip[32];
        bool built = sig_build_span(&ndb, 100, 130, 0x03, tip);
        /* parent of row 100 is absent: walk stops cleanly */
        bool ok = built && seed_integrity_gate_check(130, tip, false);
        SIG_CHECK("snapshot suffix (rows only above base): pass", ok);
    }

    /* 4. Seed-tip pair mismatch: row labeled 206 while the seed claims
     * 200 -> refused at birth. */
    {
        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        uint8_t tip[32]; sig_hash(tip, 206, 0x04);
        bool built = sig_insert(&ndb, tip, 206, NULL);
        bool refused = built && !seed_integrity_gate_check(200, tip, false);
        SIG_CHECK("seed pair mismatch (+6 label): REFUSED", refused);
        SIG_CHECK("refusal registered PERMANENT seed.linkage_gate",
                  blocker_exists("seed.linkage_gate") &&
                  blocker_class_for("seed.linkage_gate") ==
                      BLOCKER_PERMANENT);
        blocker_clear("seed.linkage_gate");
    }

    /* 5. Linkage break at birth: chain [300..310] healthy, then the
     * parent of 311 is labeled 304 (the +6 splice boundary). */
    {
        seed_integrity_gate_reset_for_testing();
        seed_integrity_gate_set_node_db_for_testing(&ndb);
        uint8_t base_tip[32];
        bool built = sig_build_span(&ndb, 300, 310, 0x05, base_tip);
        /* mislabel the row at 310: rewrite it with height 304 */
        built = built && sig_insert(&ndb, base_tip, 304, NULL);
        /* child at 311 links to it by hash */
        uint8_t child[32]; sig_hash(child, 311, 0x05);
        built = built && sig_insert(&ndb, child, 311, base_tip);
        bool refused = built && !seed_integrity_gate_check(311, child,
                                                           false);
        SIG_CHECK("linkage break (parent labeled h-7): REFUSED at birth",
                  refused);
        SIG_CHECK("break registered seed.linkage_gate blocker",
                  blocker_exists("seed.linkage_gate"));

        /* 6. Memo: the same (height,hash) re-check returns the cached
         * refusal without re-walking. */
        bool memo_refused = !seed_integrity_gate_check(311, child, false);
        SIG_CHECK("memo: repeat check returns cached refusal",
                  memo_refused);
        blocker_clear("seed.linkage_gate");
    }

    failures += sig_test_walk_edges();
    failures += sig_test_label_offsets();
    failures += sig_test_deep_break();
    failures += sig_test_one_byte_prev();
    failures += sig_test_pair_reason();
    failures += sig_test_walk_budget();
    failures += sig_test_memo_keys();
    failures += sig_test_reset_hook();
    failures += sig_test_args();
    failures += sig_test_commitment();
    failures += sig_test_commitment_refusals();
    failures += sig_test_stamp_args();
    failures += sig_test_trusted_memo();
    failures += sig_test_stamp_drops_memo();

    /* crash-only proof: refusals above were plain false returns;
     * the process (this test) is alive. */
    seed_integrity_gate_reset_for_testing();
    blocker_reset_for_testing();
    node_db_close(&ndb);
    return failures;
}
