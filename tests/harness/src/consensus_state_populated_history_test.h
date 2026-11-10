/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Prove the fixture's watch-only transactions against its retained history. */
#include "services/block_index_loader.h"
#include "storage/disk_block_io.h"
#include "domain/consensus/check_block.h"

static bool csi_populated_history_cap(struct wallet_history_capability *cap,
    const struct csi_real_paths *p, const struct wallet_cutover_binding *binding)
{
    char parent_path[PATH_MAX]; struct wallet_history_names names;
    int n = snprintf(parent_path, sizeof(parent_path), "%s", p->history);
    if (n < 0 || (size_t)n >= sizeof(parent_path) || !binding->history_identity_present ||
        !wallet_history_capability_names(binding->snapshot_whole_sha3, binding->history_manifest_root, &names).ok) return false;
    char *leaf = strrchr(parent_path, '/');
    if (!leaf || leaf == parent_path || strcmp(leaf + 1, names.root)) return false;
    *leaf = '\0';
    struct platform_directory_transaction parent, root;
    struct platform_directory_lock lease;
    platform_directory_transaction_init(&parent); platform_directory_transaction_init(&root);
    platform_directory_lock_init(&lease);
    bool ok = platform_directory_transaction_open(&parent, parent_path) &&
        platform_directory_lock_acquire(&parent, names.lock, false, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lease) == PLATFORM_DIRECTORY_OK &&
        platform_directory_transaction_open_child(&parent, names.root, false, &root) == PLATFORM_DIRECTORY_OK &&
        wallet_history_capability_acquire(cap, &parent, &root, &lease, names.root, names.lock, 52,
                                          binding->history_manifest_root).ok &&
        wallet_history_capability_matches_path(cap, p->history).ok;
    platform_directory_lock_release(&lease);
    platform_directory_transaction_close(&root);
    platform_directory_transaction_close(&parent);
    return ok;
}

static bool csi_populated_watch_output(const struct transaction *tx)
{
    static const uint8_t script[25] = {0x76, 0xa9, 0x14, [23] = 0x88, [24] = 0xac};
    for (size_t i = 0; i < tx->num_vout; ++i)
        if (tx->vout[i].script_pub_key.size == sizeof(script) &&
            !memcmp(tx->vout[i].script_pub_key.data, script, sizeof(script))) return true;
    return false;
}

static bool csi_populated_block_merkle(struct block *block)
{
    for (size_t i = 0; i < block->num_vtx; ++i) transaction_compute_hash(&block->vtx[i]);
    return domain_consensus_check_block_merkle_root(block, NULL, 0, NULL).ok;
}

static bool csi_populated_block_merkle_negative(struct block *block)
{
    if (!block->num_vtx) return false;
    block->vtx[0].lock_time ^= 1;
    bool refused = !csi_populated_block_merkle(block);
    block->vtx[0].lock_time ^= 1;
    return refused && csi_populated_block_merkle(block);
}

static bool csi_populated_archive_tx(const char *history, struct disk_block_pos *pos,
    const uint8_t block_hash[32], const uint8_t txid[32], const void *raw, int raw_size)
{
    struct block block; block_init(&block);
    bool ok = read_block_from_disk_pread(&block, pos, history); struct uint256 hash;
    if (ok) {
        block_get_hash(&block, &hash);
        ok = !memcmp(hash.data, block_hash, 32) && csi_populated_block_merkle(&block) &&
            csi_populated_block_merkle_negative(&block);
    }
    unsigned matches = 0;
    for (size_t i = 0; ok && i < block.num_vtx; ++i) {
        struct transaction *tx = &block.vtx[i]; transaction_compute_hash(tx);
        if (memcmp(tx->hash.data, txid, 32)) continue;
        struct byte_stream stream; stream_init(&stream, 512);
        bool same = transaction_serialize(tx, &stream) && raw_size >= 0 &&
            stream.size == (size_t)raw_size && !memcmp(stream.data, raw, stream.size) &&
            csi_populated_watch_output(tx);
        stream_free(&stream);
        if (!same) ok = false;
        ++matches;
    }
    block_free(&block);
    return ok && matches == 1;
}

static bool csi_populated_history_columns(sqlite3_stmt *tx, const struct block_index *row)
{
    return sqlite3_column_type(tx, 0) == SQLITE_BLOB &&
        sqlite3_column_type(tx, 1) == SQLITE_BLOB && sqlite3_column_type(tx, 2) == SQLITE_BLOB &&
        sqlite3_column_type(tx, 3) == SQLITE_INTEGER && sqlite3_column_int(tx, 3) == 0 &&
        sqlite3_column_bytes(tx, 0) == 32 && sqlite3_column_bytes(tx, 2) == 32 &&
        sqlite3_column_blob(tx, 0) && sqlite3_column_blob(tx, 1) && sqlite3_column_blob(tx, 2) &&
        !memcmp(sqlite3_column_blob(tx, 2), row->phashBlock->data, 32);
}
static bool csi_populated_history_row(const char *history, sqlite3 *wallet,
    const struct block_index *row, int height, const uint8_t originals[2][32])
{
    if (!row || row->nHeight != height || !row->phashBlock || row->nFile < 0) return false;
    sqlite3_stmt *tx = NULL;
    const char *query = "SELECT txid,raw_tx,block_hash,from_me FROM wallet_transactions "
        "WHERE block_height=?1 AND txid<>?2 AND txid<>?3";
    bool ok = sqlite3_prepare_v2(wallet, query, -1, &tx, NULL) == SQLITE_OK && tx &&
        sqlite3_bind_int(tx, 1, height) == SQLITE_OK &&
        sqlite3_bind_blob(tx, 2, originals[0], 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_blob(tx, 3, originals[1], 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(tx) == SQLITE_ROW && csi_populated_history_columns(tx, row);
    if (ok) {
        struct disk_block_pos pos = {.nFile = row->nFile, .nPos = row->nDataPos};
        ok = csi_populated_archive_tx(history, &pos, row->phashBlock->data,
            sqlite3_column_blob(tx, 0), sqlite3_column_blob(tx, 1), sqlite3_column_bytes(tx, 1)) &&
            sqlite3_step(tx) == SQLITE_DONE;
    }
    if (tx && sqlite3_finalize(tx) != SQLITE_OK) ok = false;
    return ok;
}

static bool csi_populated_history_rows(const char *history, sqlite3 *db,
    struct main_state *archive, const uint8_t originals[2][32])
{
    static const int heights[7] = {820961, 818073, 817627, 817590, 731701, 730740, 730736};
    struct block_index *row = archive->pindex_best_header;
    for (size_t i = 0; i < 7; ++i) {
        while (row && row->nHeight > heights[i]) row = row->pprev;
        if (!csi_populated_history_row(history, db, row, heights[i], originals)) return false;
    }
    return true;
}

static bool csi_populated_history_open_archive(const struct csi_real_paths *p,
    const struct wallet_cutover_binding *binding, struct wallet_history_capability *cap,
    struct main_state *archive, sqlite3 *db, const uint8_t originals[2][32])
{
    return archive && csi_populated_history_cap(cap, p, binding) &&
        block_index_history_archive_open(archive, wallet_history_capability_path(cap), 3500000,
                                         binding->target_height, binding->target_hash, NULL).ok &&
        csi_populated_history_rows(wallet_history_capability_path(cap), db, archive, originals);
}
static bool csi_populated_history_count(sqlite3 *db, sqlite3_stmt **count)
{
    return sqlite3_prepare_v2(db, "SELECT count(*) FROM wallet_transactions", -1, count, NULL) == SQLITE_OK &&
        *count && sqlite3_step(*count) == SQLITE_ROW && sqlite3_column_int(*count, 0) == 9 &&
        sqlite3_step(*count) == SQLITE_DONE;
}
static bool csi_populated_history_proof(const struct csi_real_paths *p,
                                        const struct wallet_cutover_binding *binding)
{
    if (!binding || binding->target_height != 3309900) return false;
    chain_params_select(CHAIN_MAIN);
    struct transaction tx[2]; uint8_t originals[2][32];
    for (unsigned i = 0; i < 2; ++i) {
        transaction_init(&tx[i]); tx[i].lock_time = i + 1; transaction_compute_hash(&tx[i]);
        memcpy(originals[i], tx[i].hash.data, 32); transaction_free(&tx[i]);
    }
    sqlite3 *db = NULL; sqlite3_stmt *count = NULL;
    bool ok = sqlite3_open_v2(p->node, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK &&
        csi_populated_history_count(db, &count);
    if (count && sqlite3_finalize(count) != SQLITE_OK) ok = false;
    struct wallet_history_capability cap; wallet_history_capability_init(&cap);
    struct main_state *archive = calloc(1, sizeof(*archive));
    if (archive) main_state_init(archive);
    ok = ok && csi_populated_history_open_archive(p, binding, &cap, archive, db, originals);
    if (archive) { main_state_free(archive); free(archive); }
    wallet_history_capability_release(&cap);
    if (db && sqlite3_close(db) != SQLITE_OK) ok = false;
    return ok;
}

static bool csi_populated_history_check(const struct csi_real_paths *p,
                                        const struct wallet_cutover_binding *binding)
{
    uint64_t parent = (uint64_t)getpid(); pid_t child = fork();
    if (!child) {
        if (!os_proc_bind_parent_death(SIGKILL, parent)) _exit(120);
        _exit(csi_populated_history_proof(p, binding) ? 0 : 121);
    }
    int status = 0; bool waited = child > 0 && csi_real_wait_child(child, &status);
    bool ok = waited && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    fprintf(stderr, "populated history proof: ok=%d waited=%d exit=%d signal=%d\n", ok, waited,
        WIFEXITED(status) ? WEXITSTATUS(status) : -1, WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    return ok;
}
