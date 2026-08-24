/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit test for block_index_projection_topup_with() — the normal-boot
 * projection top-up that closes defect #10 (task #29: a restart dropped
 * the active chain to the stale flat-file extent because connect-time
 * index state lived only in memory + the projection, and no normal-boot
 * path read the projection back).
 *
 * What it proves
 * --------------
 *   1. RAISE-ONLY MERGE: a header-only in-memory entry (no HAVE_DATA,
 *      nTx=0 — exactly what the stale flat file yields for a window
 *      block) gains HAVE_DATA + nFile/nDataPos + nTx + a raised
 *      BLOCK_VALID level from its projection row.
 *   2. NEVER LOWERS: an entry already carrying nonzero nTx and its own
 *      positions keeps them, whatever the row says.
 *   3. NEVER COPIES FAILED: a row carrying BLOCK_FAILED_VALID applies
 *      its data bits without resurrecting the failure.
 *   4. HEIGHT-CONFLICT REFUSAL: a row whose recorded height disagrees
 *      with the loaded entry's height is refused wholesale.
 *   5. INSERT MISSING: a row the loaders never saw is inserted, pprev
 *      linked via the carried hashPrev, and its nChainWork computed on
 *      top of the parent's.
 *   6. nTx DISK RECOVERY: an entry with a verified on-disk body but
 *      nTx=0 (legacy emit before body persist stamped nTx) recovers
 *      its tx count from the block file, hash-bound.
 *   7. IDEMPOTENT: a second top-up changes nothing.
 *
 * Scratch files live under ./test-tmp/topup_<pid>/ per the project's
 * no-/tmp convention.
 */

#include "test/test_core.h"

#include "services/block_index_loader.h"
#include "util/boot_phase.h"
#include "storage/block_index_projection.h"
#include "storage/disk_block_io.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "core/arith_uint256.h"
#include "primitives/block.h"
#include "core/amount.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TOPUP_CHECK(name, expr) do { \
    printf("block_index_topup: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Synthetic, unique block hash for height `h` (the projection keys rows
 * on the event's explicit hash field; nothing recomputes it here). */
static void topup_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[31] = 0x77;
}

/* Append one EV_BLOCK_HEADER event for the projection to fold. */
static bool topup_emit_row(event_log_t *log, const struct uint256 *hash,
                           const struct uint256 *prev, int height,
                           uint32_t status, int file, uint32_t data_pos,
                           uint32_t ntx)
{
    struct ev_block_header ev;
    memset(&ev, 0, sizeof(ev));
    memcpy(ev.hash, hash->data, 32);
    if (prev)
        memcpy(ev.hashPrev, prev->data, 32);
    ev.height = height;
    ev.nStatus = status;
    ev.nFile = file;
    ev.nDataPos = data_pos;
    ev.nTime = 1700000000u + (uint32_t)height;
    ev.nBits = 0x2000ffffu;
    ev.nVersion = 4;
    ev.nTx = ntx;
    ev.nSolutionSize = 0;

    uint8_t buf[512];
    size_t written = 0;
    if (!ev_block_header_serialize(&ev, NULL, buf, sizeof(buf), &written))
        return false;
    return event_log_append(log, EV_BLOCK_HEADER, buf, written)
           != UINT64_MAX;
}

/* Insert a header-only in-memory entry (the stale-flat-file shape). */
static struct block_index *topup_insert_entry(struct main_state *ms,
                                              const struct uint256 *hash,
                                              int height)
{
    struct block_index *bi = chainstate_insert_block_index(
        (struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->nBits = 0x2000ffffu;
    bi->nTime = 1700000000u + (uint32_t)height;
    bi->nVersion = 4;
    bi->nStatus = BLOCK_VALID_TREE;
    bi->nTx = 0;
    bi->nFile = -1;
    bi->nDataPos = 0;
    return bi;
}

int test_block_index_topup(void)
{
    int failures = 0;

    char dir[256];
    snprintf(dir, sizeof(dir), "./test-tmp/topup_%d", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);
    char blocks_dir[320];
    snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", dir);
    mkdir(blocks_dir, 0755);

    char el_path[320];
    snprintf(el_path, sizeof(el_path), "%s/event_log.dat", dir);
    char bip_path[320];
    snprintf(bip_path, sizeof(bip_path), "%s/bip.db", dir);

    /* Unique hashes for heights 100..105 + disk block. */
    struct uint256 h100, h101, h102, h103, h104, h105;
    topup_hash_for(100, &h100);
    topup_hash_for(101, &h101);
    topup_hash_for(102, &h102);
    topup_hash_for(103, &h103);
    topup_hash_for(104, &h104);
    topup_hash_for(105, &h105);

    struct main_state ms;
    main_state_init(&ms);

    /* e100: the "old extent" — full state the top-up must never lower. */
    struct block_index *e100 = topup_insert_entry(&ms, &h100, 100);
    if (e100) {
        e100->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        e100->nTx = 5;
        e100->nFile = 1;
        e100->nDataPos = 500;
    }
    /* e101/e102/e103: header-only window entries. */
    struct block_index *e101 = topup_insert_entry(&ms, &h101, 101);
    struct block_index *e102 = topup_insert_entry(&ms, &h102, 102);
    struct block_index *e103 = topup_insert_entry(&ms, &h103, 103);
    if (e103) {
        /* Parent work for the inserted-child chainwork assertion. */
        memset(&e103->nChainWork, 0, sizeof(e103->nChainWork));
        e103->nChainWork.pn[0] = 0x1000;
    }
    /* e105: a CONTENTLESS STUB at the wrong height (the corrupt-flat-load
     * shape that births a placeholder tip):
     * height 0, nBits 0, no HAVE_DATA, nTx 0. The projection row below
     * carries the real record at height 105 — the topup must HYDRATE this
     * entry instead of refusing the merge as a label conflict. */
    struct block_index *e105 = topup_insert_entry(&ms, &h105, 0);
    if (e105) {
        e105->nBits = 0;
        e105->nStatus = 0;
        e105->nTx = 0;
    }
    TOPUP_CHECK("setup: entries inserted",
                e100 && e101 && e102 && e103 && e105);

    /* Disk-recovery entry: a REAL block on disk, nTx=0 in the entry. */
    struct block_index *edisk = NULL;
    {
        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = 1700009999u;
        b.header.nBits = 0x2000ffffu;
        b.num_vtx = 3;
        b.vtx = calloc(3, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
        for (int i = 0; i < 3; i++) {
            transaction_init(&b.vtx[i]);
            transaction_alloc(&b.vtx[i], 1, 1);
            b.vtx[i].vin[0].sequence = 0xffffffff;
            b.vtx[i].vout[0].value = (i + 1) * COIN;
        }
        struct uint256 bh;
        block_get_hash(&b, &bh);
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
        bool wrote = write_block_to_disk(&b, &pos, dir, msg_start);
        block_free(&b);
        TOPUP_CHECK("setup: disk block written", wrote);
        if (wrote) {
            edisk = topup_insert_entry(&ms, &bh, 200);
            if (edisk) {
                edisk->nStatus |= BLOCK_HAVE_DATA;
                edisk->nFile = pos.nFile;
                edisk->nDataPos = pos.nPos;
                edisk->nTx = 0;  /* the legacy n_tx=0 emit shape */
            }
        }
        TOPUP_CHECK("setup: disk entry inserted", edisk != NULL);
    }

    /* Projection rows. */
    event_log_t *log = event_log_open(el_path);
    TOPUP_CHECK("setup: event log opens", log != NULL);
    block_index_projection_t *bip =
        log ? block_index_projection_open(bip_path, log) : NULL;
    TOPUP_CHECK("setup: projection opens", bip != NULL);
    if (!log || !bip) {
        if (bip) block_index_projection_close(bip);
        if (log) event_log_close(log);
        main_state_free(&ms);
        return failures + 1;
    }

    bool rows_ok = true;
    /* r101: the canonical merge row. */
    rows_ok &= topup_emit_row(log, &h101, &h100, 101,
                              BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA,
                              2, 1234, 7);
    /* r102: data + a FAILED bit that must NOT be copied. */
    rows_ok &= topup_emit_row(log, &h102, &h101, 102,
                              BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                              BLOCK_FAILED_VALID,
                              2, 2345, 3);
    /* r103: HEIGHT CONFLICT — same hash as e103, recorded height 999. */
    rows_ok &= topup_emit_row(log, &h103, &h102, 999,
                              BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA,
                              2, 3456, 9);
    /* r104: missing from the map → insert, parent = e103. */
    rows_ok &= topup_emit_row(log, &h104, &h103, 104,
                              BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA,
                              2, 4567, 4);
    /* r100: tries to overwrite the full entry — must be a no-op. */
    rows_ok &= topup_emit_row(log, &h100, NULL, 100,
                              BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA,
                              9, 9999, 999);
    /* r105: the real record for the contentless stub e105 — height 105,
     * real nBits (topup_emit_row stamps 0x2000ffff), data-backed. */
    rows_ok &= topup_emit_row(log, &h105, &h104, 105,
                              BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA,
                              2, 5678, 6);
    TOPUP_CHECK("setup: rows emitted", rows_ok);

    /* ── Run the top-up. ─────────────────────────────────────────── */
    uint64_t progress_before = boot_progress_marker();
    bool ran = block_index_projection_topup_with(bip, &ms, dir);
    TOPUP_CHECK("topup returns ok", ran);
    TOPUP_CHECK("topup ticks boot_progress (born-red: silent nTx/iterate)",
                boot_progress_marker() > progress_before);

    /* 1. raise-only merge on e101. */
    TOPUP_CHECK("e101 gained HAVE_DATA",
                e101 && (e101->nStatus & BLOCK_HAVE_DATA));
    TOPUP_CHECK("e101 gained positions",
                e101 && e101->nFile == 2 && e101->nDataPos == 1234);
    TOPUP_CHECK("e101 gained nTx", e101 && e101->nTx == 7);
    TOPUP_CHECK("e101 validity raised to SCRIPTS",
                e101 && (e101->nStatus & BLOCK_VALID_MASK)
                            == BLOCK_VALID_SCRIPTS);

    /* 3. FAILED bit not copied onto e102. */
    TOPUP_CHECK("e102 gained HAVE_DATA",
                e102 && (e102->nStatus & BLOCK_HAVE_DATA));
    TOPUP_CHECK("e102 carries no FAILED bits",
                e102 && !(e102->nStatus & BLOCK_FAILED_MASK));

    /* 4. height conflict refused on e103. */
    TOPUP_CHECK("e103 kept its height", e103 && e103->nHeight == 103);
    TOPUP_CHECK("e103 gained nothing",
                e103 && e103->nTx == 0 &&
                !(e103->nStatus & BLOCK_HAVE_DATA));

    /* 5. insert-missing for h104. */
    struct block_index *e104 = block_map_find(&ms.map_block_index, &h104);
    TOPUP_CHECK("h104 inserted", e104 != NULL);
    TOPUP_CHECK("h104 height + nTx from the row",
                e104 && e104->nHeight == 104 && e104->nTx == 4);
    TOPUP_CHECK("h104 pprev linked to e103",
                e104 && e104->pprev == e103);
    TOPUP_CHECK("h104 chainwork above parent's",
                e104 && e103 &&
                arith_uint256_compare(&e104->nChainWork,
                                      &e103->nChainWork) > 0);

    /* 2. e100 never lowered/overwritten. */
    TOPUP_CHECK("e100 kept nTx", e100 && e100->nTx == 5);
    TOPUP_CHECK("e100 kept positions",
                e100 && e100->nFile == 1 && e100->nDataPos == 500);

    /* 5b. contentless stub HYDRATED from the projection row (the
     * corrupt-flat placeholder-tip class): height re-labelled, header
     * fields + data availability adopted, pprev re-linked, chainwork
     * recomputed above its parent. A REAL entry at a conflicting height
     * (e103, case 4) still refuses — hydration is stub-only. */
    TOPUP_CHECK("e105 stub re-heighted from the row",
                e105 && e105->nHeight == 105);
    TOPUP_CHECK("e105 gained real nBits", e105 && e105->nBits != 0);
    TOPUP_CHECK("e105 gained HAVE_DATA + positions",
                e105 && (e105->nStatus & BLOCK_HAVE_DATA) &&
                e105->nFile == 2 && e105->nDataPos == 5678);
    TOPUP_CHECK("e105 gained nTx", e105 && e105->nTx == 6);
    TOPUP_CHECK("e105 pprev linked to h104",
                e105 && e104 && e105->pprev == e104);
    TOPUP_CHECK("e105 chainwork above parent's",
                e105 && e104 &&
                arith_uint256_compare(&e105->nChainWork,
                                      &e104->nChainWork) > 0);

    /* 6. nTx recovered from disk for the legacy-emit entry. */
    TOPUP_CHECK("edisk nTx recovered from the block file",
                edisk && edisk->nTx == 3);

    /* 7. idempotent second run. */
    bool ran2 = block_index_projection_topup_with(bip, &ms, dir);
    TOPUP_CHECK("second topup returns ok", ran2);
    TOPUP_CHECK("second topup changed nothing",
                e101 && e101->nTx == 7 && e101->nFile == 2 &&
                e100 && e100->nTx == 5 &&
                e103 && e103->nTx == 0 &&
                edisk && edisk->nTx == 3);

    /* NULL projection is a no-op success. */
    TOPUP_CHECK("NULL projection no-op",
                block_index_projection_topup_with(NULL, &ms, dir));

    block_index_projection_close(bip);
    event_log_close(log);
    main_state_free(&ms);
    return failures;
}
