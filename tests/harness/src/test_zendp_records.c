/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zendp_records — THE RECEIVING SIDE of signed endpoint records:
 * what a node does at start with the record files an operator has
 * accepted onto disk (engine/composition/src/boot_endpoint_records.c).
 *
 * tests/harness/src/test_zendp.c already proves the library refuses each bad
 * record BY NAME. This file proves the property that actually protects
 * the node, one layer up, on the path a real record travels:
 *
 *   A RECORD THAT DOES NOT VERIFY AGAINST A CHAIN-ANCHORED IDENTITY IS
 *   DISCARDED, NOT FLAGGED.
 *
 * "Discarded" is asserted as an absence, never as a status field: after
 * a refused load the identity is not findable in the directory at all
 * (zendp_directory_find is false) and the discovery projection is empty
 * (zendp_global_records returns 0). There is no entry carrying a "bad"
 * marker that some later reader could mistake for a usable peer hint,
 * because there is no entry.
 *
 * The refusal cases run FIRST and every one of them re-asserts the
 * directory is still empty, so the single installing case at the end
 * cannot be what made the earlier assertions pass.
 *
 * The last case is the one that matters in practice: a directory
 * holding one good record beside three bad ones. Exactly the good one
 * is loaded; a bad neighbour neither blocks it nor rides in with it.
 *
 * WHY THE FILES STAY. A discarded record's file is left on disk on
 * purpose — it is the operator's data, and `zcode endpoint list`
 * reports it as unusable with the named reason. Discarding is about
 * what the node BELIEVES, not about deleting what the operator holds.
 *
 * NOT covered, because it is not true: that the party answering at an
 * advertised address holds the key. A verified record is a hint. */

#include "test/test_core.h"

#include "base/log_level.h"
#include "config/boot_endpoint_records.h"
#include "crypto/ed25519.h"
#include "encoding/utilstrencodings.h"
#include "platform/time_compat.h"
#include "vcs/zendp_swarm.h"
#include "zid/zdesc.h"
#include "zid/zendp.h"
#include "zid/zid.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZR_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zendp_records: %s... OK\n", (name)); }       \
    else { printf("  zendp_records: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* 56 base32 chars + ".onion" — anything else is refused before signing. */
#define ZR_ONION \
    "zclassictwothreesignedendpointrecordgoldenvectorbbbbbbbb.onion"

/* ── the test-owned chain oracle (stands in for db_zid_identity_find) ── */

/* Two modes. `blanket` answers one verdict for every key — enough for
 * the single-record cases. The per-key table is what the mixed-directory
 * case needs: a real chain answers differently for different
 * identities, and a test that cannot express that cannot prove one bad
 * neighbour is dropped while a good one is kept. A key in neither is
 * ABSENT, which is what "never anchored" looks like. */
#define ZR_ORACLE_MAX 4

static struct {
    bool available;
    bool blanket;
    enum zendp_anchor_state state;
    size_t count;
    struct {
        uint8_t pk[32];
        enum zendp_anchor_state state;
    } rows[ZR_ORACLE_MAX];
} g_oracle;

static bool zr_oracle(void *ctx, const uint8_t pubkey[32],
                      struct zendp_anchor *out)
{
    (void)ctx;
    if (!pubkey || !out || !g_oracle.available)
        return false;
    memset(out, 0, sizeof(*out));
    out->anchor_height = 3100000;
    out->updated_height = 3100000;
    if (g_oracle.blanket) {
        out->state = g_oracle.state;
        return true;
    }
    out->state = ZENDP_ANCHOR_ABSENT;
    for (size_t i = 0; i < g_oracle.count; i++) {
        if (memcmp(g_oracle.rows[i].pk, pubkey, 32) == 0) {
            out->state = g_oracle.rows[i].state;
            break;
        }
    }
    return true;
}

static void zr_oracle_set(enum zendp_anchor_state s)
{
    memset(&g_oracle, 0, sizeof(g_oracle));
    g_oracle.available = true;
    g_oracle.blanket = true;
    g_oracle.state = s;
    zendp_set_anchor_lookup(zr_oracle, NULL);
}

static void zr_oracle_table_reset(void)
{
    memset(&g_oracle, 0, sizeof(g_oracle));
    g_oracle.available = true;
    zendp_set_anchor_lookup(zr_oracle, NULL);
}

static void zr_oracle_add(const uint8_t pk[32], enum zendp_anchor_state s)
{
    if (g_oracle.count >= ZR_ORACLE_MAX)
        return;
    memcpy(g_oracle.rows[g_oracle.count].pk, pk, 32);
    g_oracle.rows[g_oracle.count].state = s;
    g_oracle.count++;
}

/* ── fixture ───────────────────────────────────────────────────────── */

/* THE CLOCK IS REAL, AND THAT IS LOAD-BEARING.
 *
 * boot_endpoint_records_load() reads the wall clock itself — it is a
 * boot path, not a pure function, and giving it an injectable clock
 * just to make a test tidy would be a second copy of "what time is it"
 * living in production code for the test's benefit.
 *
 * So the fixture signs records whose window is open NOW. An earlier
 * draft of this file pinned not_before to a fixed 2026-01-01 and every
 * refusal case passed — vacuously, because the window had closed months
 * ago and the record would have been refused whatever the chain said.
 * A discard test that cannot also demonstrate acceptance proves
 * nothing, which is why zr_case_mixed_directory asserts a record IS
 * loaded on the same fixture the refusals use. */
static uint64_t zr_now(void)
{
    return (uint64_t)platform_time_wall_unix();
}

#define ZR_NOW        zr_now()
#define ZR_NOT_BEFORE (zr_now() - 60)
#define ZR_EXPIRY     (zr_now() + 86400)

static void zr_make_endpoint(struct zendp *ep)
{
    memset(ep, 0, sizeof(*ep));
    ep->flags = ZENDP_HAS_ONION;
    snprintf(ep->onion, sizeof(ep->onion), "%s", ZR_ONION);
    ep->onion_port = 8033;
    ep->services = 0x409;
    ep->height = 3196556;
    ep->not_before = ZR_NOT_BEFORE;
}

/* Sign with an explicit not_before, for the window cases. */
static bool zr_sign_window(uint8_t seed_byte, uint64_t seq,
                           uint64_t not_before, uint64_t expiry,
                           uint8_t out_wire[ZID_DOC_MAX], size_t *out_len,
                           uint8_t out_pk[32])
{
    uint8_t seed[32], sk[32];
    memset(seed, seed_byte, sizeof(seed));
    ed25519_keypair(out_pk, sk, seed);

    struct zendp ep;
    zr_make_endpoint(&ep);
    ep.not_before = not_before;
    struct zid_doc doc;
    if (!zendp_sign(&doc, &ep, seq, expiry, seed))
        return false;
    size_t n = zid_doc_encode(out_wire, ZID_DOC_MAX, &doc);
    if (n == 0)
        return false;
    *out_len = n;
    return true;
}

/* Sign a record and hand back the doc wire plus the identity. */
static bool zr_sign(uint8_t seed_byte, uint64_t seq, uint64_t expiry,
                    uint8_t out_wire[ZID_DOC_MAX], size_t *out_len,
                    uint8_t out_pk[32])
{
    uint8_t seed[32], sk[32];
    memset(seed, seed_byte, sizeof(seed));
    ed25519_keypair(out_pk, sk, seed);

    struct zendp ep;
    zr_make_endpoint(&ep);
    struct zid_doc doc;
    if (!zendp_sign(&doc, &ep, seq, expiry, seed))
        return false;
    size_t n = zid_doc_encode(out_wire, ZID_DOC_MAX, &doc);
    if (n == 0)
        return false;
    *out_len = n;
    return true;
}

/* Write raw text as <datadir>/zcode/endpoints/<name>. Creates the tree. */
static bool zr_write_file(const char *datadir, const char *name,
                          const char *text)
{
    char dir[900];
    snprintf(dir, sizeof(dir), "%s/zcode", datadir);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return false;
    snprintf(dir, sizeof(dir), "%s/zcode/endpoints", datadir);
    if (mkdir(dir, 0700) != 0 && errno != EEXIST)
        return false;

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return false;
    size_t len = strlen(text);
    ssize_t w = write(fd, text, len);
    close(fd);
    return w == (ssize_t)len;
}

/* File a signed record under its own blinded record key, the way
 * `zcode endpoint accept` does. */
static bool zr_file_record(const char *datadir, const uint8_t *wire,
                           size_t wire_len, const uint8_t pk[32])
{
    uint8_t key[32];
    char key_hex[65], name[80];
    zendp_record_key(key, pk, zdesc_period_at(ZR_NOW));
    HexStr(key, 32, false, key_hex, sizeof(key_hex));
    snprintf(name, sizeof(name), "%s.zid", key_hex);

    static char doc_hex[ZID_DOC_MAX * 2 + 2];
    HexStr(wire, wire_len, false, doc_hex, sizeof(doc_hex));
    return zr_write_file(datadir, name, doc_hex);
}

/* Is the record file still where the operator put it? */
static bool zr_record_file_exists(const char *datadir, const uint8_t pk[32])
{
    uint8_t key[32];
    char key_hex[65], path[1024];
    zendp_record_key(key, pk, zdesc_period_at(ZR_NOW));
    HexStr(key, 32, false, key_hex, sizeof(key_hex));
    snprintf(path, sizeof(path), "%s/zcode/endpoints/%s.zid", datadir,
             key_hex);
    struct stat st;
    return stat(path, &st) == 0 && st.st_size > 0;
}

/* Nothing is installed and nothing is findable: the shape of "discarded",
 * asserted as an absence rather than as a status field. */
static bool zr_directory_empty(const uint8_t pk[32])
{
    struct zendp_record_view views[ZENDP_DIR_MAX];
    return !zendp_directory_find(zendp_directory_global(), pk, NULL) &&
           zendp_global_records(ZR_NOW, views, ZENDP_DIR_MAX) == 0;
}

/* ── 1: nothing filed is not an error ──────────────────────────────── */

static int zr_case_empty(void)
{
    int failures = 0;
    char dd[512];
    test_make_tmpdir(dd, sizeof(dd), "zendprec", "empty");

    zr_oracle_set(ZENDP_ANCHOR_ACTIVE);
    ZR_CHECK("a datadir with no endpoints directory loads nothing, quietly",
             boot_endpoint_records_load(dd) == 0);
    ZR_CHECK("a NULL datadir is 0, not a crash",
             boot_endpoint_records_load(NULL) == 0);
    ZR_CHECK("an empty endpoints directory loads nothing",
             zr_write_file(dd, ".keep", "") &&
             boot_endpoint_records_load(dd) == 0);

    zendp_set_anchor_lookup(NULL, NULL);
    test_rm_rf(dd);
    return failures;
}

/* ── 2: every chain verdict that is not ACTIVE discards ────────────── */

static int zr_case_chain_refusals(void)
{
    int failures = 0;
    uint8_t wire[ZID_DOC_MAX], pk[32];
    size_t wire_len = 0;
    ZR_CHECK("chain: the fixture record signs",
             zr_sign(0x21, 1, ZR_EXPIRY, wire, &wire_len, pk));
    if (wire_len == 0)
        return failures;

    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    /* THE POINT: the bytes below are perfectly signed and perfectly
     * in-window every single time. Only the chain's answer changes. */
    struct {
        const char *tag;
        const char *what;
        bool registered;
        bool available;
        enum zendp_anchor_state state;
    } cases[] = {
        { "nolookup", "nothing can ask the chain", false, false,
          ZENDP_ANCHOR_UNKNOWN },
        { "unavail", "the chain lookup itself fails", true, false,
          ZENDP_ANCHOR_UNKNOWN },
        { "absent", "the key was never anchored", true, true,
          ZENDP_ANCHOR_ABSENT },
        { "rotated", "the key was rotated away", true, true,
          ZENDP_ANCHOR_ROTATED },
        { "revoked", "the key was revoked", true, true,
          ZENDP_ANCHOR_REVOKED },
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char dd[512];
        test_make_tmpdir(dd, sizeof(dd), "zendprec", cases[i].tag);
        bool filed = zr_file_record(dd, wire, wire_len, pk);

        if (!cases[i].registered) {
            zendp_set_anchor_lookup(NULL, NULL);
        } else if (!cases[i].available) {
            g_oracle.available = false;
            zendp_set_anchor_lookup(zr_oracle, NULL);
        } else {
            zr_oracle_set(cases[i].state);
        }

        int loaded = filed ? boot_endpoint_records_load(dd) : -1;

        char msg[220];
        snprintf(msg, sizeof(msg),
                 "chain: %s -> the record is DISCARDED, not stored",
                 cases[i].what);
        ZR_CHECK(msg, loaded == 0 && zr_directory_empty(pk));

        /* The operator's file is untouched — discarding is about what
         * the node believes, not about deleting what the operator has,
         * and `zcode endpoint list` still reports it with its reason. */
        snprintf(msg, sizeof(msg),
                 "chain: %s -> the operator's file is left on disk",
                 cases[i].what);
        ZR_CHECK(msg, zr_record_file_exists(dd, pk));

        test_rm_rf(dd);
    }

    zcl_log_level_set(saved);
    zendp_set_anchor_lookup(NULL, NULL);
    return failures;
}

/* ── 3: with the chain saying ACTIVE, the crypto still has to hold ── */

static int zr_case_bytes_refusals(void)
{
    int failures = 0;
    uint8_t wire[ZID_DOC_MAX], pk[32];
    size_t wire_len = 0;
    ZR_CHECK("bytes: the fixture record signs",
             zr_sign(0x22, 1, ZR_EXPIRY, wire, &wire_len, pk));
    if (wire_len == 0)
        return failures;

    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);
    zr_oracle_set(ZENDP_ANCHOR_ACTIVE);

    /* A single flipped bit anywhere in the signed document. */
    {
        char dd[512];
        test_make_tmpdir(dd, sizeof(dd), "zendprec", "tamper");
        uint8_t bad[ZID_DOC_MAX];
        memcpy(bad, wire, wire_len);
        bad[wire_len / 2] ^= 0x01;
        ZR_CHECK("bytes: a tampered record is discarded even with an ACTIVE "
                 "anchor",
                 zr_file_record(dd, bad, wire_len, pk) &&
                 boot_endpoint_records_load(dd) == 0 &&
                 zr_directory_empty(pk));
        test_rm_rf(dd);
    }

    /* A record whose own signed window has closed. */
    {
        char dd[512];
        uint8_t exp_wire[ZID_DOC_MAX], exp_pk[32];
        size_t exp_len = 0;
        test_make_tmpdir(dd, sizeof(dd), "zendprec", "expired");
        /* Opened yesterday, closed an hour ago: a real record whose own
         * signed window has simply run out. */
        ZR_CHECK("bytes: the short-window record signs",
                 zr_sign_window(0x23, 1, zr_now() - 86400, zr_now() - 3600,
                                exp_wire, &exp_len, exp_pk));
        ZR_CHECK("bytes: a record whose window has closed is discarded",
                 exp_len > 0 &&
                 zr_file_record(dd, exp_wire, exp_len, exp_pk) &&
                 boot_endpoint_records_load(dd) == 0 &&
                 zr_directory_empty(exp_pk));
        test_rm_rf(dd);
    }

    /* Files that are not records at all. */
    {
        char dd[512];
        test_make_tmpdir(dd, sizeof(dd), "zendprec", "junk");
        char name[80];
        char key_hex[65];
        uint8_t key[32];
        zendp_record_key(key, pk, zdesc_period_at(ZR_NOW));
        HexStr(key, 32, false, key_hex, sizeof(key_hex));

        snprintf(name, sizeof(name), "%s.zid", key_hex);
        ZR_CHECK("bytes: a file that is not hex is discarded",
                 zr_write_file(dd, name, "not hex at all\n") &&
                 boot_endpoint_records_load(dd) == 0 &&
                 zr_directory_empty(pk));

        ZR_CHECK("bytes: odd-length hex is discarded",
                 zr_write_file(dd, name, "abc\n") &&
                 boot_endpoint_records_load(dd) == 0);

        ZR_CHECK("bytes: well-formed hex that is not a zid doc is discarded",
                 zr_write_file(dd, name, "deadbeefdeadbeef\n") &&
                 boot_endpoint_records_load(dd) == 0 &&
                 zr_directory_empty(pk));
        test_rm_rf(dd);
    }

    zcl_log_level_set(saved);
    zendp_set_anchor_lookup(NULL, NULL);
    return failures;
}

/* ── 4: one good record beside three bad ones ──────────────────────── */

/* The case that decides whether any of this is worth having. A bad
 * neighbour must neither block the good record nor ride in with it. */
static int zr_case_mixed_directory(void)
{
    int failures = 0;
    char dd[512];
    test_make_tmpdir(dd, sizeof(dd), "zendprec", "mixed");

    enum zcl_log_level saved = zcl_log_level_get();
    zcl_log_level_set(ZCL_LOG_OFF);

    /* The good one, signed by an identity the chain will call ACTIVE. */
    uint8_t good_wire[ZID_DOC_MAX], good_pk[32];
    size_t good_len = 0;
    ZR_CHECK("mixed: the good record signs",
             zr_sign(0x31, 7, ZR_EXPIRY, good_wire, &good_len, good_pk));

    /* Bad #1: a real signature by an identity the chain never anchored. */
    uint8_t un_wire[ZID_DOC_MAX], un_pk[32];
    size_t un_len = 0;
    ZR_CHECK("mixed: the unanchored record signs",
             zr_sign(0x32, 3, ZR_EXPIRY, un_wire, &un_len, un_pk));

    /* Bad #2: an ACTIVE identity's record with a flipped bit. */
    uint8_t tam_wire[ZID_DOC_MAX], tam_pk[32];
    size_t tam_len = 0;
    ZR_CHECK("mixed: the to-be-tampered record signs",
             zr_sign(0x33, 3, ZR_EXPIRY, tam_wire, &tam_len, tam_pk));
    if (tam_len > 0)
        tam_wire[tam_len - 1] ^= 0x80;

    if (good_len == 0 || un_len == 0 || tam_len == 0) {
        zcl_log_level_set(saved);
        test_rm_rf(dd);
        return failures;
    }

    ZR_CHECK("mixed: all four files are filed",
             zr_file_record(dd, good_wire, good_len, good_pk) &&
             zr_file_record(dd, un_wire, un_len, un_pk) &&
             zr_file_record(dd, tam_wire, tam_len, tam_pk) &&
             zr_write_file(dd,
                           "00000000000000000000000000000000"
                           "00000000000000000000000000000000.zid",
                           "garbage\n"));

    /* A chain that answers differently per identity, which is the only
     * way this case means anything: the good key is ACTIVE, the
     * tampered record's key is ACTIVE too (so its refusal is provably
     * the signature and not the anchor), and the third key is in no
     * table at all — never anchored. */
    zr_oracle_table_reset();
    zr_oracle_add(good_pk, ZENDP_ANCHOR_ACTIVE);
    zr_oracle_add(tam_pk, ZENDP_ANCHOR_ACTIVE);

    int loaded = boot_endpoint_records_load(dd);

    struct zendp_record_view views[ZENDP_DIR_MAX];
    size_t projected = zendp_global_records(ZR_NOW, views, ZENDP_DIR_MAX);

    ZR_CHECK("mixed: exactly one of four files is loaded",
             loaded == 1);
    ZR_CHECK("mixed: the good record is loaded and projected to discovery",
             zendp_directory_find(zendp_directory_global(), good_pk, NULL) &&
             projected == 1 &&
             memcmp(views[0].master_pubkey, good_pk, 32) == 0 &&
             views[0].seq == 7 && views[0].anchor_height == 3100000 &&
             views[0].ep.onion_port == 8033);
    ZR_CHECK("mixed: the tampered identity never entered the directory, "
             "though its key IS anchored",
             !zendp_directory_find(zendp_directory_global(), tam_pk, NULL));
    ZR_CHECK("mixed: the unanchored identity never entered the directory",
             !zendp_directory_find(zendp_directory_global(), un_pk, NULL));

    /* Now retire the good identity on-chain and reload from the SAME
     * files: the bytes did not change, the chain's answer did, and that
     * alone is enough to keep the record out. */
    {
        char dd2[512];
        test_make_tmpdir(dd2, sizeof(dd2), "zendprec", "revoke");
        uint8_t rev_wire[ZID_DOC_MAX], rev_pk[32];
        size_t rev_len = 0;
        ZR_CHECK("mixed: the revocation-test record signs",
                 zr_sign(0x34, 1, ZR_EXPIRY, rev_wire, &rev_len, rev_pk));
        zr_oracle_set(ZENDP_ANCHOR_REVOKED);
        ZR_CHECK("mixed: the same bytes are refused once the chain says "
                 "revoked",
                 rev_len > 0 &&
                 zr_file_record(dd2, rev_wire, rev_len, rev_pk) &&
                 boot_endpoint_records_load(dd2) == 0 &&
                 !zendp_directory_find(zendp_directory_global(), rev_pk,
                                       NULL));
        test_rm_rf(dd2);
    }

    zcl_log_level_set(saved);
    zendp_set_anchor_lookup(NULL, NULL);
    test_rm_rf(dd);
    return failures;
}

int test_zendp_records(void)
{
    int failures = 0;
    printf("\n=== endpoint records: what the node loads at start ===\n");
    failures += zr_case_empty();
    failures += zr_case_chain_refusals();
    failures += zr_case_bytes_refusals();
    failures += zr_case_mixed_directory();
    if (failures == 0)
        printf("  zendp_records: all cases passed\n");
    return failures;
}
