/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Ordinary startup projection stop custody fixture. */
#ifndef Z23_CONSENSUS_STATE_PROJECTION_STOP_TEST_H
#define Z23_CONSENSUS_STATE_PROJECTION_STOP_TEST_H
#include "storage/event_log_payloads.h"
#include "models/wallet_activity.h"
#include "models/wallet_tx.h"
#include "util/ar_step_readonly.h"
#include "../../../engine/modules/storage/src/block_index_projection_internal.h"
#if !defined(_WIN32)
static bool csi_projection_fingerprint(sqlite3 *db, uint8_t out[32])
{
    const char *queries[] = {"SELECT * FROM wallet_keys ORDER BY rowid", "SELECT * FROM wallet_seed ORDER BY rowid", "SELECT * FROM wallet_sapling_keys ORDER BY rowid", "SELECT * FROM wallet_sapling_notes ORDER BY rowid", "SELECT * FROM wallet_transactions ORDER BY rowid"};
    struct sha3_256_ctx h; sha3_256_init(&h);
    for (size_t i = 0; i < sizeof(queries)/sizeof(queries[0]); ++i) {
        sqlite3_stmt *s = NULL;
        if (sqlite3_prepare_v2(db, queries[i], -1, &s, NULL) != SQLITE_OK) return false;
        sha3_256_write(&h, (const uint8_t *)queries[i], strlen(queries[i]) + 1);
        int rc;
        while ((rc = AR_STEP_ROW_READONLY(s)) == SQLITE_ROW) {
            for (int c = 0; c < sqlite3_column_count(s); ++c) {
                int type = sqlite3_column_type(s,c), len = sqlite3_column_bytes(s,c);
                const void *p = sqlite3_column_blob(s,c);
                sha3_256_write(&h, (const uint8_t *)&type, sizeof(type));
                sha3_256_write(&h, (const uint8_t *)&len, sizeof(len));
                if (len && p) sha3_256_write(&h, p, (size_t)len);
                if (len && !p) { sqlite3_finalize(s); return false; }
            }
        }
        bool ok = rc == SQLITE_DONE && sqlite3_finalize(s) == SQLITE_OK;
        if (!ok) return false;
    }
    sha3_256_finalize(&h, out); return true;
}

/* Ordinary startup stops during projection only after a populated wallet loaded. */
static bool csi_projection_stop_seen, csi_projection_wallet_loaded;
static bool csi_projection_error_case;
void boot_test_projection_opened(void (*hook)(struct block_index_projection *));
static bool csi_projection_note_loaded(struct node_db *node)
{
    struct db_wallet_note_fact *notes = NULL;
    int count = db_wallet_note_facts_alloc(node, &notes);
    bool ok = count == 1 && notes && notes[0].value == 200000 && notes[0].txid[0] == 0xaa && notes[0].ivk[0] == 0xbb;
    free(notes);
    return ok;
}
static void csi_projection_event_stop(uint64_t count)
{
    if (count != 1) return;
    struct node_db *node; struct wallet_sqlite *ws; struct wallet *wallet; struct main_state *main;
    boot_wallet_cutover_test_slots(&node, &ws, &wallet, &main);
    csi_projection_wallet_loaded = node && node->open && ws && ws->open && wallet &&
        wallet->keystore.num_keys > 0 && wallet->sapling_keys.num_keys > 0 && wallet->num_wallet_tx > 0 &&
        csi_projection_note_loaded(node);
    csi_projection_stop_seen = true;
    thread_registry_request_shutdown();
}
static void csi_projection_attach(struct block_index_projection *p)
{ p->event_hook = csi_projection_event_stop; }
static bool csi_projection_seed(const char *dir, uint8_t fingerprint[32], uint8_t digest[32], uint64_t *end, bool fault)
{
    char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db node = {0}; struct wallet_sqlite ws = {0};
    wallet_lock_reset_for_test();
    struct privkey key; struct pubkey pub; privkey_init(&key);
    memset(key.vch, 0x4c, 32); key.vch[1] = 0x99; key.fValid = true; key.fCompressed = true;
    bool ok = node_db_open(&node, path) && wallet_sqlite_open_r(&ws, node.db).ok &&
        wallet_lock_unlock(NULL, NULL, "projection-fixture-only").ok &&
        csi_real_sapling_seed(&ws) && privkey_get_pubkey(&key, &pub) && wallet_sqlite_write_key(&ws, &pub, &key);
    struct wallet_tx tx = {0}; transaction_init(&tx.tx); transaction_compute_hash(&tx.tx);
    tx.used = true; tx.time_received = 1713000000;
    struct db_sapling_note note = {0};
    memset(note.txid, 0xaa, 32); memset(note.ivk, 0xbb, 32); memset(note.nullifier, 0xcc, 32);
    memset(note.diversifier, 0xdd, 11); memset(note.pk_d, 0xee, 32);
    memset(note.cm, 0xff, 32); memset(note.rcm, 0x11, 32); note.value = 200000; note.block_height = 500;
    ok = ok && wallet_sqlite_write_tx(&ws, &tx) && db_sapling_note_save(&node, &note) &&
        csi_projection_note_loaded(&node) && csi_projection_fingerprint(node.db, fingerprint);
    transaction_free(&tx.tx); if (ws.open) wallet_sqlite_close(&ws); if (node.open) node_db_close(&node);
    wallet_lock_reset_for_test();
    snprintf(path, sizeof(path), "%s/event_log.dat", dir);
    event_log_t *log = ok ? event_log_open(path) : NULL;
    uint8_t wire[EV_BLOCK_HEADER_FIXED_BYTES]; size_t length = 0;
    struct ev_block_header header = {.height = 1, .nVersion = 4, .nBits = 0x1d00ffff};
    ok = log && ev_block_header_serialize(&header, NULL, wire, sizeof(wire), &length) &&
        event_log_append(log, EV_BLOCK_HEADER, wire, fault ? 1 : length) != UINT64_MAX &&
        event_log_append(log, EV_BLOCK_HEADER, wire, length) != UINT64_MAX && event_log_flush(log);
    if (ok) { *end = event_log_size(log); ok = event_log_prefix_digest(log, *end, digest, NULL, NULL) == 0; }
    if (log) event_log_close(log);
    return ok;
}
static bool csi_projection_reopen(const char *dir, const uint8_t fingerprint[32], const uint8_t digest[32], uint64_t end)
{
    char path[PATH_MAX]; uint8_t after[32]; struct node_db node = {0};
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool ok = node_db_open(&node, path) && csi_projection_fingerprint(node.db, after) && !memcmp(after, fingerprint, 32);
    if (node.open) node_db_close(&node);
    snprintf(path, sizeof(path), "%s/event_log.dat", dir);
    event_log_t *log = ok ? event_log_open(path) : NULL;
    ok = log && event_log_size(log) >= end && event_log_prefix_digest(log, end, after, NULL, NULL) == 0 && !memcmp(after, digest, 32);
    if (log) event_log_close(log);
    return ok;
}
static void csi_projection_boot_child(const char *dir, int proof_fd)
{
    char datadir[PATH_MAX + 32]; snprintf(datadir, sizeof(datadir), "-datadir=%s", dir);
    char *argv[] = {"z23", datadir, "-operator-lane=dev", "-nolegacyimport", "-nolegacyutxoimport", "-no-tor", "-private-listeners", "-observation=0", "-connect=127.0.0.1:1"};
    int argc = (int)(sizeof(argv) / sizeof(argv[0])); struct app_context ctx; app_context_defaults(&ctx);
    ctx.datadir = dir; ParseParameters(argc, (const char *const *)argv); bool metrics = false;
    if (args_parse_node_options(argc, argv, &ctx, &metrics) != -1 || unsetenv("ZCL_DEPLOY_ALLOW_CANONICAL")) _exit(31);
    boot_stage_reset_for_testing(); ecc_verify_destroy(); ecc_stop();
    boot_test_projection_opened(csi_projection_attach);
    bool started = app_init(&ctx); boot_test_projection_opened(NULL);
    if (started || !csi_projection_stop_seen || !csi_projection_wallet_loaded) _exit(32);
    if (csi_projection_error_case) {
        if (boot_projection_stop_cleanup() || write(proof_fd, "E", 1) != 1) _exit(34);
        (void)boot_projection_failure_cleanup();
        _exit(36);
    } else if (boot_error_reported() || boot_projection_failure_cleanup() ||
               !boot_projection_stop_cleanup() || boot_projection_stop_cleanup()) _exit(35);
    if (write(proof_fd, "S", 1) != 1) _exit(37);
    _exit(0);
}
static int csi_projection_populated_stop_case(bool fault)
{
    int failures = 0; char dir[256]; test_make_tmpdir(dir, sizeof(dir), "projection_stop", "populated");
    uint8_t fingerprint[32], digest[32]; uint64_t end = 0;
    bool seeded = csi_projection_seed(dir, fingerprint, digest, &end, fault);
    int proof[2] = {-1, -1}; bool piped = seeded && pipe(proof) == 0;
    uint64_t parent = (uint64_t)getpid(); pid_t child = piped ? fork() : -1;
    if (!child) {
        close(proof[0]); csi_projection_error_case = fault;
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(33);
        alarm(90); csi_projection_boot_child(dir, proof[1]);
    }
    if (proof[1] >= 0) close(proof[1]);
    int status = 0; bool waited = child > 0 && csi_real_wait_child(child, &status);
    char marker = 0; ssize_t n = proof[0] >= 0 ? read(proof[0], &marker, 1) : -1;
    if (proof[0] >= 0) close(proof[0]);
    bool ok = waited && WIFEXITED(status) && WEXITSTATUS(status) == (fault ? 1 : 0) &&
        n == 1 && marker == (fault ? 'E' : 'S') && csi_projection_reopen(dir, fingerprint, digest, end);
    CSI_CHECK(fault ? "projection error takes precedence over stop and preserves wallet" :
              "ordinary projection stop preserves loaded wallet and event prefix", ok);
    test_rm_rf_recursive(dir); return failures;
}
#endif
#endif
