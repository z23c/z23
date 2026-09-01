/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the ZDIR on-chain node directory — the real chain scan that
 * replaces blog_discover_onion_peers' wallet scrape:
 *
 *  1. Codec (contexts/naming/modules/zdir): build->parse round-trips for REGISTER (bound and
 *     unbound) and DEREGISTER, the encoded-size contract, and the whole
 *     rejection surface — wrong lokad, wrong version, the RESERVED command
 *     byte 3 (TRANSFER), every way a hostname can fail the v3 rule, a
 *     mis-sized or all-zero pubkey, a pubkey on DEREGISTER, trailing bytes,
 *     truncation, and NULL/undersized buffers.
 *  2. Schema: the v39 migration lands onion_directory + its index, and the
 *     open db reports NODE_DB_MAX_SCHEMA.
 *  3. Model: save/find round-trip including the NULL-column forms, the
 *     validator's rejections (bad hostname, bad status, present-but-zero
 *     pubkey, negative heights), active-only listing ordered
 *     newest-registration-first, counts, and truncate.
 *  4. Ingestion through the overlay REGISTRY (not a hand-rolled call): a ZDIR
 *     OP_RETURN in a block lands a row; owner authorization holds on
 *     re-register and deregister; seniority (`height`) survives a
 *     re-register; a malformed body is a clean no-op.
 *  5. Rebuildability + purity: truncate the projection, re-walk the same
 *     blocks, get byte-identical rows.
 *  6. Discovery: blog_discover_onion_peers_chain reads the projection out of a
 *     real datadir, and blog_discover_onion_peers merges it ALONGSIDE the
 *     legacy wallet scrape — never fewer peers than the chain source alone,
 *     with the per-source attribution counters populated.
 */

#include "test/test_core.h"
#include "controllers/blog_controller.h"
#include "models/database.h"
#include "models/explorer_index.h"
#include "models/onion_directory.h"
#include "net/onion_peer_merge.h"
#include "overlay/overlay_projection.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "chain/chain.h"
#include "script/standard.h"
#include "zdir/zdir.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

/* ── Helpers ──────────────────────────────────────────────────────── */

static int count_rows(struct node_db *ndb, const char *sql)
{
    sqlite3_stmt *s = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(ndb->db, sql, -1, &s, NULL) == SQLITE_OK && s) {
        if (sqlite3_step(s) == SQLITE_ROW)  // raw-sql-ok:test-readonly-count
            n = sqlite3_column_int(s, 0);
    }
    if (s) sqlite3_finalize(s);
    return n;
}

/* A well-formed v3 onion hostname made of one repeated base32 character. */
static void mk_host(char *out, size_t n, char c)
{
    char body[57];
    memset(body, c, 56);
    body[56] = '\0';
    snprintf(out, n, "%s.onion", body);
}

/* ── (1) codec ────────────────────────────────────────────────────── */

static int zdir_codec_roundtrip(void)
{
    int failures = 0;
    char host[64];
    uint8_t buf[256];
    struct zdir_message m;

    mk_host(host, sizeof(host), 'a');

    printf("zdir: the hostname fixture passes the node's v3 rule... ");
    { bool ok = strlen(host) == ZDIR_HOSTNAME_LEN &&
                onion_hostname_valid(host);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: REGISTER (unbound) round-trips... ");
    { size_t n = zdir_build_register(buf, sizeof(buf), host, NULL);
      bool ok = n > 0 && zdir_parse(buf, n, &m) &&
                m.version == ZDIR_VERSION &&
                m.command == ZDIR_CMD_REGISTER &&
                strcmp(m.hostname, host) == 0 && !m.has_pubkey;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: REGISTER (key-bound) round-trips... ");
    { uint8_t key[ZDIR_PUBKEY_LEN];
      memset(key, 0x5c, sizeof(key));
      size_t n = zdir_build_register(buf, sizeof(buf), host, key);
      bool ok = n > 0 && n <= ZDIR_SCRIPT_MAX && n <= MAX_OP_RETURN_RELAY &&
                zdir_parse(buf, n, &m) &&
                m.command == ZDIR_CMD_REGISTER && m.has_pubkey &&
                memcmp(m.pubkey, key, ZDIR_PUBKEY_LEN) == 0;
      if (ok) printf("OK\n");
      else { printf("FAIL (len=%zu)\n", n); failures++; } }

    printf("zdir: DEREGISTER round-trips and carries no key... ");
    { size_t n = zdir_build_deregister(buf, sizeof(buf), host);
      bool ok = n > 0 && zdir_parse(buf, n, &m) &&
                m.command == ZDIR_CMD_DEREGISTER && !m.has_pubkey;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: command names + validity map... ");
    { bool ok = zdir_command_valid(ZDIR_CMD_REGISTER) &&
                zdir_command_valid(ZDIR_CMD_DEREGISTER) &&
                !zdir_command_valid(ZDIR_CMD_INVALID) &&
                !zdir_command_valid(3) &&      /* RESERVED for TRANSFER */
                !zdir_command_valid(255) &&
                strcmp(zdir_command_name(ZDIR_CMD_REGISTER),
                       "register") == 0 &&
                strcmp(zdir_command_name(ZDIR_CMD_DEREGISTER),
                       "deregister") == 0 &&
                strcmp(zdir_command_name(3), "unknown") == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    return failures;
}

static int zdir_codec_rejections(void)
{
    int failures = 0;
    char host[64];
    uint8_t buf[256];
    struct zdir_message m;

    mk_host(host, sizeof(host), 'a');
    size_t base = zdir_build_register(buf, sizeof(buf), host, NULL);

    printf("zdir: builder refuses every malformed hostname... ");
    { char bad[80];
      uint8_t o[256];
      bool ok = zdir_build_register(o, sizeof(o), NULL, NULL) == 0 &&
                zdir_build_register(o, sizeof(o), "", NULL) == 0 &&
                zdir_build_register(o, sizeof(o), "short.onion", NULL) == 0;
      mk_host(bad, sizeof(bad), 'A');            /* uppercase */
      ok = ok && zdir_build_register(o, sizeof(o), bad, NULL) == 0;
      mk_host(bad, sizeof(bad), '1');            /* not in base32 a-z2-7 */
      ok = ok && zdir_build_register(o, sizeof(o), bad, NULL) == 0;
      mk_host(bad, sizeof(bad), '8');            /* not in base32 a-z2-7 */
      ok = ok && zdir_build_register(o, sizeof(o), bad, NULL) == 0;
      mk_host(bad, sizeof(bad), 'a');
      memcpy(bad + 56, ".union", 6);             /* wrong suffix */
      ok = ok && zdir_build_register(o, sizeof(o), bad, NULL) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: builder refuses an all-zero key and a tiny buffer... ");
    { uint8_t zero[ZDIR_PUBKEY_LEN] = {0};
      uint8_t small[8];
      bool ok = zdir_build_register(buf, sizeof(buf), host, zero) == 0 &&
                zdir_build_register(small, sizeof(small), host, NULL) == 0 &&
                zdir_build_register(NULL, 64, host, NULL) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: parser refuses NULL args and a non-OP_RETURN script... ");
    { uint8_t nots[8] = {0x76, 0x04, 'Z', 'D', 'I', 'R'};
      bool ok = !zdir_parse(buf, base, NULL) &&
                !zdir_parse(NULL, base, &m) &&
                !zdir_parse(buf, 0, &m) &&
                !zdir_parse(nots, sizeof(nots), &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: parser refuses a foreign lokad... ");
    { uint8_t bad[256];
      memcpy(bad, buf, base);
      bad[2] = 'Y';                              /* "YDIR" */
      bool ok = !zdir_parse(bad, base, &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: parser refuses a wrong version byte... ");
    { uint8_t bad[256];
      memcpy(bad, buf, base);
      bad[7] = ZDIR_VERSION + 1;                 /* [0x6a][01 4 lokad][01 v] */
      bool ok = !zdir_parse(bad, base, &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: parser refuses the RESERVED command byte 3 (TRANSFER)... ");
    { uint8_t bad[256];
      memcpy(bad, buf, base);
      bad[9] = 3;
      bool ok = !zdir_parse(bad, base, &m);
      bad[9] = 0;
      ok = ok && !zdir_parse(bad, base, &m);
      bad[9] = 200;
      ok = ok && !zdir_parse(bad, base, &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: parser refuses a hostname that fails the v3 rule... ");
    { uint8_t bad[256];
      memcpy(bad, buf, base);
      bad[11] = 'A';           /* first hostname byte, uppercase */
      bool ok = !zdir_parse(bad, base, &m);
      memcpy(bad, buf, base);
      bad[11] = '1';           /* outside a-z2-7 */
      ok = ok && !zdir_parse(bad, base, &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: parser refuses a truncated script... ");
    { bool ok = true;
      for (size_t cut = 1; cut < base; cut++)
          ok = ok && !zdir_parse(buf, cut, &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: parser refuses trailing bytes... ");
    { uint8_t bad[256];
      memcpy(bad, buf, base);
      bad[base] = 0x00;
      bool ok = !zdir_parse(bad, base + 1, &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    /* `base` ends with the canonical EMPTY key push (one 0x00 byte). Swapping
     * that last byte for a sized push is how these cases are built. */
    printf("zdir: parser refuses a mis-sized / zero key push... ");
    { uint8_t bad[256];
      size_t n = base - 1;
      memcpy(bad, buf, n);
      bad[n++] = 31;                    /* 31 bytes is neither 0 nor 32 */
      memset(bad + n, 0x11, 31);
      n += 31;
      bool ok = !zdir_parse(bad, n, &m);

      n = base - 1;
      memcpy(bad, buf, n);
      bad[n++] = 32;                    /* all-zero 32-byte key is not a key */
      memset(bad + n, 0x00, 32);
      n += 32;
      ok = ok && !zdir_parse(bad, n, &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: parser refuses a key push on DEREGISTER... ");
    { uint8_t d[256], bad[256];
      size_t dn = zdir_build_deregister(d, sizeof(d), host);
      size_t n = dn - 1;
      memcpy(bad, d, n);
      bad[n++] = 32;
      memset(bad + n, 0x42, 32);
      n += 32;
      bool ok = dn > 0 && !zdir_parse(bad, n, &m);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    return failures;
}

/* ── (2)+(3) schema + model ───────────────────────────────────────── */

static void mk_row(struct db_onion_directory *r, char c, int32_t height,
                   const char *status, const char *owner)
{
    memset(r, 0, sizeof(*r));
    mk_host(r->hostname, sizeof(r->hostname), c);
    memset(r->txid, (uint8_t)c, 32);
    r->height = height;
    r->updated_height = height;
    snprintf(r->status, sizeof(r->status), "%s", status);
    if (owner) snprintf(r->owner_address, sizeof(r->owner_address), "%s",
                        owner);
}

static int zdir_schema_and_model(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));

    printf("zdir: open in-memory node.db (schema v%d)... ",
           NODE_DB_MAX_SCHEMA);
    if (node_db_open(&ndb, ":memory:") && ndb.open) printf("OK\n");
    else { printf("FAIL\n"); return 1; }

    printf("zdir: schema_version is %d... ", NODE_DB_MAX_SCHEMA);
    { int v = node_db_schema_version(&ndb);
      if (v == NODE_DB_MAX_SCHEMA) printf("OK\n");
      else { printf("FAIL (got %d)\n", v); failures++; } }

    printf("zdir: v39 created onion_directory + its index... ");
    { int t = count_rows(&ndb,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'"
        " AND name='onion_directory'");
      int i = count_rows(&ndb,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='index'"
        " AND name='idx_onion_directory_status_height'");
      if (t == 1 && i == 1) printf("OK\n");
      else { printf("FAIL (table=%d index=%d)\n", t, i); failures++; } }

    struct db_onion_directory r;
    mk_row(&r, 'b', 900, ONION_DIRECTORY_STATUS_ACTIVE,
           "t1KpuGw6vqrARbCsRWcxNBQGGXpiCDeqZuS");
    memset(r.master_pubkey, 0x7e, 32);
    r.has_pubkey = true;
    r.updated_height = 950;

    printf("zdir: save + find round-trips every field... ");
    { struct db_onion_directory got;
      memset(&got, 0xff, sizeof(got));
      bool ok = db_onion_directory_save(&ndb, &r) &&
                db_onion_directory_find(&ndb, r.hostname, &got) &&
                strcmp(got.hostname, r.hostname) == 0 &&
                memcmp(got.txid, r.txid, 32) == 0 &&
                got.height == 900 && got.updated_height == 950 &&
                strcmp(got.owner_address, r.owner_address) == 0 &&
                got.has_pubkey &&
                memcmp(got.master_pubkey, r.master_pubkey, 32) == 0 &&
                strcmp(got.status, ONION_DIRECTORY_STATUS_ACTIVE) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: the NULL-column form (no owner, no key) round-trips... ");
    { struct db_onion_directory n, got;
      mk_row(&n, 'c', 100, ONION_DIRECTORY_STATUS_ACTIVE, NULL);
      memset(&got, 0xff, sizeof(got));
      bool ok = db_onion_directory_save(&ndb, &n) &&
                db_onion_directory_find(&ndb, n.hostname, &got) &&
                got.owner_address[0] == '\0' && !got.has_pubkey;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: find misses on an unknown hostname... ");
    { struct db_onion_directory got;
      char other[64];
      mk_host(other, sizeof(other), 'd');
      bool ok = !db_onion_directory_find(&ndb, other, &got) &&
                !db_onion_directory_find(&ndb, "", &got) &&
                !db_onion_directory_find(&ndb, NULL, &got);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: validator rejects a bad hostname / status / key / height"
           "... ");
    { int64_t before = db_onion_directory_count(&ndb);
      struct db_onion_directory bad;

      mk_row(&bad, 'e', 10, ONION_DIRECTORY_STATUS_ACTIVE, NULL);
      snprintf(bad.hostname, sizeof(bad.hostname), "nope.onion");
      bool ok = !db_onion_directory_save(&ndb, &bad);

      mk_row(&bad, 'e', 10, "gone", NULL);        /* unknown status */
      ok = ok && !db_onion_directory_save(&ndb, &bad);

      mk_row(&bad, 'e', 10, ONION_DIRECTORY_STATUS_ACTIVE, NULL);
      bad.has_pubkey = true;                      /* present but all-zero */
      ok = ok && !db_onion_directory_save(&ndb, &bad);

      mk_row(&bad, 'e', -1, ONION_DIRECTORY_STATUS_ACTIVE, NULL);
      ok = ok && !db_onion_directory_save(&ndb, &bad);

      ok = ok && !db_onion_directory_save(&ndb, NULL);
      ok = ok && db_onion_directory_count(&ndb) == before;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir: list_active skips retired rows, MOST SENIOR first... ");
    { struct db_onion_directory dead;
      mk_row(&dead, 'f', 5000, ONION_DIRECTORY_STATUS_RETIRED, NULL);
      struct db_onion_directory page[8];
      memset(page, 0, sizeof(page));
      int n = 0;
      bool ok = db_onion_directory_save(&ndb, &dead);
      n = db_onion_directory_list_active(&ndb, page, 8, 0);
      /* 'b' at h=900 and 'c' at h=100 are active; 'f' at h=5000 is not.
       * `height` is the REGISTRATION height, i.e. the seniority signal, so
       * the senior row (h=100) comes first. This used to assert DESC —
       * newest-first — which, on a bounded page the caller intends to dial,
       * let a burst of cheap fresh registrations take every slot and evict
       * every long-standing node. */
      ok = ok && n == 2 && page[0].height == 100 && page[1].height == 900;
      ok = ok && db_onion_directory_list_active(&ndb, page, 1, 0) == 1 &&
                 page[0].height == 100;
      ok = ok && db_onion_directory_list_active(&ndb, page, 8, 1) == 1 &&
                 page[0].height == 900;
      ok = ok && db_onion_directory_list_active(&ndb, page, 0, 0) == 0;
      ok = ok && db_onion_directory_list_active(&ndb, page, 8, -1) == 0;
      ok = ok && db_onion_directory_list_active(&ndb, NULL, 8, 0) == 0;
      if (ok) printf("OK\n");
      else { printf("FAIL (n=%d)\n", n); failures++; } }

    printf("zdir: counts by status, then truncate empties the table... ");
    { bool ok = db_onion_directory_count(&ndb) == 3 &&
                db_onion_directory_count_by_status(
                    &ndb, ONION_DIRECTORY_STATUS_ACTIVE) == 2 &&
                db_onion_directory_count_by_status(
                    &ndb, ONION_DIRECTORY_STATUS_RETIRED) == 1 &&
                db_onion_directory_count_by_status(&ndb, "") == 0 &&
                db_onion_directory_truncate(&ndb) &&
                db_onion_directory_count(&ndb) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* ── (4)+(5) ingestion through the overlay registry ───────────────── */

/* Seed a spendable tx_output owned by `addr20` at outpoint (prevbyte×32, n),
 * so a later tx spending it resolves that address as its signer. */
static void seed_owner_utxo(struct node_db *ndb, uint8_t prevbyte, uint32_t n,
                            const uint8_t addr20[20], int height)
{
    uint8_t txid[32];
    memset(txid, prevbyte, 32);
    db_tx_output_save(ndb, txid, n, 5 * COIN, 0, addr20, height);
}

/* Build a one-tx block spending outpoint (prevbyte×32, 0) whose sole output is
 * `script`, and run the per-block indexer at `height`. */
static bool run_op(struct node_db *ndb, const uint8_t *script, size_t slen,
                   uint8_t prevbyte, int height)
{
    struct transaction tx;
    transaction_init(&tx);
    transaction_alloc(&tx, 1, 1);
    memset(tx.vin[0].prevout.hash.data, prevbyte, 32);
    tx.vin[0].prevout.n = 0;
    tx.vin[0].sequence = 0xFFFFFFFFu;
    tx.vin[0].script_sig.size = 0;
    tx.vout[0].value = 0;
    memcpy(tx.vout[0].script_pub_key.data, script, slen);
    tx.vout[0].script_pub_key.size = slen;
    tx.lock_time = 0;
    transaction_compute_hash(&tx);

    struct block blk;
    block_init(&blk);
    blk.vtx = &tx;
    blk.num_vtx = 1;
    blk.header.nTime = 1700000000u + (uint32_t)height;

    struct uint256 bhash;
    memset(bhash.data, 0x60, 32);
    bhash.data[0] = (uint8_t)height;
    bhash.data[1] = (uint8_t)(height >> 8);
    struct block_index pindex;
    memset(&pindex, 0, sizeof(pindex));
    pindex.nHeight = height;
    pindex.phashBlock = &bhash;

    uint8_t prev_receipt[32] = {0}, out_receipt[32];
    bool ok = explorer_index_block(ndb, &blk, &pindex, prev_receipt,
                                   out_receipt, NULL, NULL);
    blk.vtx = NULL;
    blk.num_vtx = 0;
    transaction_free(&tx);
    return ok;
}

static int zdir_registry_adoption(void)
{
    int failures = 0;
    const struct overlay_registry *reg = explorer_index_overlays();

    printf("zdir: the registry carries ZDIR alongside the others... ");
    { bool ok = reg != NULL &&
                overlay_registry_count(reg) == 5 &&
                overlay_registry_find(reg, ZDIR_LOKAD_BYTES) != NULL;
      if (ok) printf("OK\n");
      else { printf("FAIL (count=%zu)\n",
                    reg ? overlay_registry_count(reg) : (size_t)0);
             failures++; } }
    return failures;
}

static int zdir_ingest(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("zdir ingest: open FAIL\n");
        return 1;
    }

    uint8_t owner[20], stranger[20];
    memset(owner, 0x41, 20);
    memset(stranger, 0x42, 20);
    for (uint8_t i = 0; i < 8; i++)
        seed_owner_utxo(&ndb, (uint8_t)(0xA0 + i), 0, owner, 10);
    for (uint8_t i = 0; i < 4; i++)
        seed_owner_utxo(&ndb, (uint8_t)(0xB0 + i), 0, stranger, 10);

    char host[64];
    mk_host(host, sizeof(host), 'g');
    uint8_t key[ZDIR_PUBKEY_LEN];
    memset(key, 0x33, sizeof(key));

    uint8_t reg_script[256], dereg_script[256];
    size_t reg_len = zdir_build_register(reg_script, sizeof(reg_script),
                                         host, key);
    size_t dereg_len = zdir_build_deregister(dereg_script,
                                             sizeof(dereg_script), host);

    printf("zdir ingest: a ZDIR REGISTER in a block lands one active row... ");
    { run_op(&ndb, reg_script, reg_len, 0xA0, 500);
      struct db_onion_directory got;
      bool ok = db_onion_directory_count(&ndb) == 1 &&
                db_onion_directory_find(&ndb, host, &got) &&
                got.height == 500 && got.updated_height == 500 &&
                got.has_pubkey &&
                memcmp(got.master_pubkey, key, 32) == 0 &&
                got.owner_address[0] != '\0' &&
                strcmp(got.status, ONION_DIRECTORY_STATUS_ACTIVE) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir ingest: a stranger cannot re-register the hostname... ");
    { struct db_onion_directory before, after;
      db_onion_directory_find(&ndb, host, &before);
      run_op(&ndb, reg_script, reg_len, 0xB0, 501);
      bool ok = db_onion_directory_find(&ndb, host, &after) &&
                memcmp(&before, &after, sizeof(before)) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir ingest: a stranger cannot deregister the hostname... ");
    { run_op(&ndb, dereg_script, dereg_len, 0xB1, 502);
      struct db_onion_directory got;
      bool ok = db_onion_directory_find(&ndb, host, &got) &&
                strcmp(got.status, ONION_DIRECTORY_STATUS_ACTIVE) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir ingest: the owner's re-register keeps seniority... ");
    { uint8_t k2[ZDIR_PUBKEY_LEN];
      memset(k2, 0x44, sizeof(k2));
      uint8_t s2[256];
      size_t n2 = zdir_build_register(s2, sizeof(s2), host, k2);
      run_op(&ndb, s2, n2, 0xA1, 600);
      struct db_onion_directory got;
      bool ok = db_onion_directory_find(&ndb, host, &got) &&
                got.height == 500 &&          /* seniority is not resettable */
                got.updated_height == 600 &&
                memcmp(got.master_pubkey, k2, 32) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir ingest: the owner's DEREGISTER retires the row... ");
    { run_op(&ndb, dereg_script, dereg_len, 0xA2, 700);
      struct db_onion_directory got;
      struct db_onion_directory page[4];
      bool ok = db_onion_directory_find(&ndb, host, &got) &&
                strcmp(got.status, ONION_DIRECTORY_STATUS_RETIRED) == 0 &&
                got.updated_height == 700 && got.height == 500 &&
                db_onion_directory_list_active(&ndb, page, 4, 0) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir ingest: DEREGISTER of an unregistered host is a no-op... ");
    { char other[64];
      mk_host(other, sizeof(other), 'h');
      uint8_t s[256];
      size_t n = zdir_build_deregister(s, sizeof(s), other);
      int64_t before = db_onion_directory_count(&ndb);
      struct db_onion_directory sink;
      run_op(&ndb, s, n, 0xA3, 701);
      bool ok = db_onion_directory_count(&ndb) == before &&
                !db_onion_directory_find(&ndb, other, &sink);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir ingest: a ZDIR lokad with a garbage body is a clean"
           " no-op... ");
    { uint8_t garbage[16] = {0x6a, 0x04, 'Z', 'D', 'I', 'R',
                             0x01, 0x01, 0x01, 0x09, 0x02, 'h', 'i'};
      int before_or = count_rows(&ndb, "SELECT COUNT(*) FROM op_returns");
      int64_t before = db_onion_directory_count(&ndb);
      run_op(&ndb, garbage, 13, 0xA4, 702);
      bool ok = db_onion_directory_count(&ndb) == before &&
                count_rows(&ndb, "SELECT COUNT(*) FROM op_returns")
                    == before_or + 1;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* The fold is pure and rebuildable: drop the projection, re-walk the same two
 * blocks, and every column comes back identical. */
static int zdir_rebuildable(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, ":memory:") || !ndb.open) {
        printf("zdir rebuild: open FAIL\n");
        return 1;
    }

    uint8_t owner[20];
    memset(owner, 0x51, 20);
    for (uint8_t i = 0; i < 6; i++)
        seed_owner_utxo(&ndb, (uint8_t)(0xC0 + i), 0, owner, 10);

    char h1[64], h2[64];
    mk_host(h1, sizeof(h1), 'm');
    mk_host(h2, sizeof(h2), 'n');
    uint8_t s1[256], s2[256];
    size_t n1 = zdir_build_register(s1, sizeof(s1), h1, NULL);
    size_t n2 = zdir_build_register(s2, sizeof(s2), h2, NULL);

    run_op(&ndb, s1, n1, 0xC0, 800);
    run_op(&ndb, s2, n2, 0xC1, 801);

    struct db_onion_directory first[4];
    memset(first, 0, sizeof(first));
    int fn = db_onion_directory_list_active(&ndb, first, 4, 0);

    printf("zdir: refolding the same blocks reproduces identical rows... ");
    { bool ok = fn == 2 && db_onion_directory_truncate(&ndb) &&
                db_onion_directory_count(&ndb) == 0;
      run_op(&ndb, s1, n1, 0xC0, 800);
      run_op(&ndb, s2, n2, 0xC1, 801);
      struct db_onion_directory again[4];
      memset(again, 0, sizeof(again));
      int an = db_onion_directory_list_active(&ndb, again, 4, 0);
      ok = ok && an == fn && memcmp(first, again, sizeof(first)) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    node_db_close(&ndb);
    return failures;
}

/* ── (6a) the merge reserves capacity — a source is never STARVED ─── */

/* Both synthetic sources are GREEDY: each fills every slot it is offered,
 * which is exactly what the chain projection does on a node with more
 * registered rows than the slate is wide (it returns up to 64 and connman
 * asks for 64). Distinct alphabets so the merge cannot dedupe them
 * together. */
static int zd_greedy_signed(void *ctx, struct onion_peer *out, size_t max)
{
    (void)ctx;
    for (size_t i = 0; i < max; i++) {
        mk_host(out[i].hostname, sizeof(out[i].hostname),
                (char)('a' + (int)(i % 13)));
        /* Vary one more char so every entry is a DISTINCT valid host. */
        out[i].hostname[0] = (char)('a' + (int)(i % 26));
        out[i].hostname[1] = (char)('a' + (int)((i / 26) % 26));
        out[i].height = 1;
    }
    return (int)max;
}

static int zd_greedy_unsigned(const char *datadir, struct onion_peer *out,
                              size_t max)
{
    (void)datadir;
    for (size_t i = 0; i < max; i++) {
        mk_host(out[i].hostname, sizeof(out[i].hostname), 'n');
        out[i].hostname[0] = (char)('n' + (int)(i % 13));
        out[i].hostname[1] = (char)('n' + (int)((i / 13) % 13));
        out[i].height = 2;
    }
    return (int)max;
}

static int zd_empty_unsigned(const char *datadir, struct onion_peer *out,
                             size_t max)
{
    (void)datadir; (void)out; (void)max;
    return 0;   /* the empty-wallet node: the common case */
}

static int zdir_collect_reservation(void)
{
    int failures = 0;
    struct onion_peer peers[8];
    int rejected = 0;

    /* THE DEFECT: the signed slot used to be handed the full `max`, so a
     * greedy signed source consumed the whole slate and the second source
     * was never invoked at all. "Neither source can remove a candidate the
     * other found" was true literally and false operationally — consuming
     * all the capacity is the same outage. */
    printf("zdir merge: a greedy signed source cannot starve the scrape... ");
    { memset(peers, 0, sizeof(peers));
      int kept = onion_peers_collect(peers, 8, zd_greedy_signed, NULL,
                                     zd_greedy_unsigned, "/nonexistent",
                                     &rejected);
      int from_unsigned = 0;
      for (int i = 0; i < kept; i++)
          if (peers[i].height == 2) from_unsigned++;
      bool ok = kept == 8 && from_unsigned >= 4;
      if (ok) printf("OK\n");
      else { printf("FAIL (kept=%d unsigned=%d)\n", kept, from_unsigned);
             failures++; } }

    /* The reservation must cost nothing when the scrape under-fills it —
     * an empty wallet is the common case, and halving the slate for a
     * source that returns 0 would be a regression of its own. */
    printf("zdir merge: an empty scrape leaves the slate to the signed"
           " source... ");
    { memset(peers, 0, sizeof(peers));
      int kept = onion_peers_collect(peers, 8, zd_greedy_signed, NULL,
                                     zd_empty_unsigned, "/nonexistent",
                                     &rejected);
      bool ok = kept == 8;
      if (ok) printf("OK\n");
      else { printf("FAIL (kept=%d)\n", kept); failures++; } }

    /* With no unsigned source registered there is nothing to reserve for. */
    printf("zdir merge: with no scrape wired the signed source gets"
           " everything... ");
    { memset(peers, 0, sizeof(peers));
      int kept = onion_peers_collect(peers, 8, zd_greedy_signed, NULL,
                                     NULL, NULL, &rejected);
      bool ok = kept == 8;
      if (ok) printf("OK\n");
      else { printf("FAIL (kept=%d)\n", kept); failures++; } }

    /* Degenerate slate: one slot goes to the source that always works. */
    printf("zdir merge: a one-slot slate degrades toward the scrape... ");
    { memset(peers, 0, sizeof(peers));
      int kept = onion_peers_collect(peers, 1, zd_greedy_signed, NULL,
                                     zd_greedy_unsigned, "/nonexistent",
                                     &rejected);
      bool ok = kept == 1 && peers[0].height == 2;
      if (ok) printf("OK\n");
      else { printf("FAIL (kept=%d h=%d)\n", kept, peers[0].height);
             failures++; } }

    return failures;
}

/* ── (6) discovery: the chain source, merged ALONGSIDE the scrape ─── */

static int zdir_discovery(void)
{
    int failures = 0;
    char dir[256];
    char db_path[1024];
    test_make_tmpdir(dir, sizeof(dir), "zdir_disc", "peers");
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    char h1[64], h2[64], h3[64];
    mk_host(h1, sizeof(h1), 'p');
    mk_host(h2, sizeof(h2), 'q');
    mk_host(h3, sizeof(h3), 'r');

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, db_path) || !ndb.open) {
        printf("zdir discovery: open FAIL\n");
        test_cleanup_tmpdir(dir);
        return 1;
    }

    /* mk_row derives the hostname from its char, so these are h1/h2/h3. */
    struct db_onion_directory r;
    mk_row(&r, 'p', 200, ONION_DIRECTORY_STATUS_ACTIVE, "t1owner");
    db_onion_directory_save(&ndb, &r);
    mk_row(&r, 'q', 300, ONION_DIRECTORY_STATUS_ACTIVE, "t1owner");
    db_onion_directory_save(&ndb, &r);
    mk_row(&r, 'r', 400, ONION_DIRECTORY_STATUS_RETIRED, "t1owner");
    db_onion_directory_save(&ndb, &r);
    node_db_close(&ndb);

    printf("zdir discovery: the chain source reads active rows only... ");
    { struct onion_peer peers[8];
      memset(peers, 0, sizeof(peers));
      int n = blog_discover_onion_peers_chain(dir, peers, 8);
      /* Seniority order: h1 registered at 200, h2 at 300. */
      bool ok = n == 2 &&
                strcmp(peers[0].hostname, h1) == 0 && peers[0].height == 200 &&
                strcmp(peers[1].hostname, h2) == 0 && peers[1].height == 300;
      if (ok) printf("OK\n");
      else { printf("FAIL (n=%d)\n", n); failures++; } }

    printf("zdir discovery: the chain source guards its arguments... ");
    { struct onion_peer peers[4];
      bool ok = blog_discover_onion_peers_chain(NULL, peers, 4) == 0 &&
                blog_discover_onion_peers_chain(dir, NULL, 4) == 0 &&
                blog_discover_onion_peers_chain(dir, peers, 0) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    printf("zdir discovery: max clamps the chain source... ");
    { struct onion_peer peers[4];
      memset(peers, 0, sizeof(peers));
      int n = blog_discover_onion_peers_chain(dir, peers, 1);
      bool ok = n == 1 && strcmp(peers[0].hostname, h1) == 0;
      if (ok) printf("OK\n"); else { printf("FAIL (n=%d)\n", n); failures++; } }

    printf("zdir discovery: the merged source ADDS the chain rows, and the"
           " wallet scrape stays wired... ");
    { struct onion_peer peers[8];
      memset(peers, 0, sizeof(peers));
      int chain_only = blog_discover_onion_peers_chain(dir, peers, 8);
      memset(peers, 0, sizeof(peers));
      int merged = blog_discover_onion_peers(dir, peers, 8);
      int chain = -1, wallet = -1, rejected = -1;
      blog_onion_discovery_counts(&chain, &wallet, &rejected);
      /* The merge may only ever GROW the candidate set: a directory can add
       * a peer, never remove one. This empty-wallet datadir also pins the
       * defect being fixed — the wallet scrape contributes 0 here, which is
       * exactly what it contributes on every node with an empty wallet. */
      bool ok = merged >= chain_only && merged == 2 &&
                chain == 2 && wallet == 0 && rejected == 0 &&
                strcmp(peers[0].hostname, h1) == 0 &&
                strcmp(peers[1].hostname, h2) == 0;
      if (ok) printf("OK\n");
      else { printf("FAIL (merged=%d chain=%d wallet=%d rej=%d)\n",
                    merged, chain, wallet, rejected); failures++; } }

    printf("zdir discovery: every hostname handed out passes the v3 rule... ");
    { struct onion_peer peers[8];
      memset(peers, 0, sizeof(peers));
      int n = blog_discover_onion_peers(dir, peers, 8);
      bool ok = n > 0;
      for (int i = 0; i < n; i++)
          ok = ok && onion_hostname_valid(peers[i].hostname);
      if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; } }

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── Entry point ──────────────────────────────────────────────────── */

int test_zdir(void)
{
    int failures = 0;
    printf("\n=== ZDIR On-Chain Node Directory Tests ===\n");
    failures += zdir_codec_roundtrip();
    failures += zdir_codec_rejections();
    failures += zdir_schema_and_model();
    failures += zdir_registry_adoption();
    failures += zdir_ingest();
    failures += zdir_rebuildable();
    failures += zdir_collect_reservation();
    failures += zdir_discovery();
    return failures;
}
