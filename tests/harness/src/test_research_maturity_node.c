/* purpose: Check private coinbase maturity through normal block admission. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "research_freeze_fixture.h"
#include "base/hex.h"
#include <sqlite3.h>

#define RM_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "research_maturity_node:%d: %s\n", __LINE__, #x); return false; \
} } while (0)

static const char rm_input[] = "e46d7568c0973fff0d0bb1daaf9fcb4ff98e2f91d2e253e9e40d772d5a5223b9";
static const char rm_output[] = "2548d464f02d847cceb1379f39cb093e386f7b5097057cbd6584cdfd58536a8b";
static const char rm_input_script[] = "76A91479B000887626B294A914501A4CD226B58B23598388AC";
static const char rm_output_script[] = "76A914424242424242424242424242424242424242424288AC";

/* Fixture lines 1..100 are the canonical prefix; 101/102 are solved
 * candidates with the same signed public v4 spend at heights 100/101. */
static bool rm_block_line(unsigned index, char out[2048])
{
    FILE *f = fopen("tests/fixtures/ironwood/maturity-blocks.hex", "rb");
    if (!f) return false;
    bool ok = true;
    for (unsigned i = 0; i <= index; i++)
        if (!fgets(out, 2048, f)) { ok = false; break; }
    if (ok) {
        size_t n = strlen(out);
        ok = n > 1 && out[n-1] == '\n';
        if (ok) out[n-1] = 0;
    }
    return fclose(f) == 0 && ok;
}

static bool rm_submit(struct rf_fixture *f, unsigned index)
{
    char block[2048], reply[RNF_RAW];
    if (!rm_block_line(index, block)) return false;
    const char *const args[] = {"submitblock", block, NULL};
    return rf_rpc(f, args, reply, sizeof(reply)) == 0 &&
        !strncmp(reply, "null", 4) && strspn(reply + 4, "\r\n") == strlen(reply + 4);
}

static bool rm_replay(struct rf_fixture *f, unsigned count)
{
    for (unsigned i = 0; i < count; i++) if (!rm_submit(f, i)) return false;
    return rf_height(f, (int)count);
}

/* Read only the isolated fixture chainstate, never a wallet or canonical DB. */
static bool rm_coin(struct rf_fixture *f, const char *id, bool present,
                    int64_t value, int height, int coinbase, const char *script)
{
    char path[PATH_MAX + 96]; uint8_t txid[32]; sqlite3 *db = NULL; sqlite3_stmt *st = NULL;
    if (snprintf(path, sizeof(path), "%s/consensus.db", f->network) >= (int)sizeof(path) ||
        !zcl_hex_decode(id, txid, sizeof(txid)) ||
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) goto fail;
    if (sqlite3_prepare_v2(db, "SELECT value,height,is_coinbase,hex(script) FROM coins WHERE txid=? AND vout=0", -1, &st, NULL) != SQLITE_OK ||
        sqlite3_bind_blob(st, 1, txid, sizeof(txid), SQLITE_STATIC) != SQLITE_OK) goto fail;
    int row = sqlite3_step(st);
    bool ok = present ? row == SQLITE_ROW && sqlite3_column_int64(st, 0) == value &&
        sqlite3_column_int(st, 1) == height && sqlite3_column_int(st, 2) == coinbase &&
        sqlite3_column_text(st, 3) && !strcmp((const char *)sqlite3_column_text(st, 3), script) &&
        sqlite3_step(st) == SQLITE_DONE : row == SQLITE_DONE;
    sqlite3_finalize(st); sqlite3_close(db); return ok;
fail:
    sqlite3_finalize(st); if (db) sqlite3_close(db); return false;
}

static bool rm_input_coin(struct rf_fixture *f, bool present)
{
    return rm_coin(f, rm_input, present, 1250000000, 1, 1, rm_input_script);
}

static bool rm_log_contains(struct rf_fixture *f, const char *needle)
{
    char path[PATH_MAX + 32], line[4096];
    if (snprintf(path, sizeof(path), "%s/node.log", f->node.work) >= (int)sizeof(path)) return false;
    FILE *in = fopen(path, "r"); if (!in) return false;
    bool found = false;
    while (fgets(line, sizeof(line), in)) if (strstr(line, needle)) { found = true; break; }
    fclose(in); return found;
}

static bool rm_wait(struct rf_fixture *f, bool mature)
{
    long deadline = rnf_now_ms() + 60000;
    while (rnf_now_ms() < deadline) {
        if (mature ? rf_height(f, 101) : rm_log_contains(f, "status=coinbase_immature kind=bad-txns-premature-spend-of-coinbase")) return true;
        rnf_sleep_ms(200);
    }
    return false;
}

static bool rm_boundary(struct rf_fixture *f, bool mature)
{
    unsigned parent = mature ? 100 : 99;
    RM_CHECK(rm_replay(f, parent));
    RM_CHECK(rm_input_coin(f, true));
    RM_CHECK(rm_submit(f, mature ? 101 : 100));
    RM_CHECK(rm_wait(f, mature));
    RM_CHECK(rf_height(f, mature ? 101 : 99));
    RM_CHECK(rm_input_coin(f, !mature));
    if (mature) RM_CHECK(rm_coin(f, rm_output, true, 1249990000, 101, 0, rm_output_script));
    rnf_node_stop(&f->node);
    RM_CHECK(rf_start(f) && rf_ready(f));
    RM_CHECK(rf_height(f, mature ? 101 : 99));
    RM_CHECK(rm_input_coin(f, !mature));
    if (mature) RM_CHECK(rm_coin(f, rm_output, true, 1249990000, 101, 0, rm_output_script));
    return true;
}

static int rm_run(bool mature)
{
    struct rf_fixture f = { .extra_flag = "-enforce-coinbase-maturity" };
    bool ok = rf_setup(&f) && rm_boundary(&f, mature);
    if (!ok && f.node.work[0]) rnf_log_tail(&f.node);
    rnf_cleanup(&f.node);
    return ok ? 0 : 1;
}

int test_research_maturity_node(void)
{
    /* Other shared fixture helpers are exercised by research_freeze_node. */
    (void)rf_mine; (void)rf_status;
    return rm_run(false) || rm_run(true);
}
