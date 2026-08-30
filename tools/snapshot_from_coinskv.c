/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * snapshot_from_coinskv — write a ZCLUTXO snapshot from an already-seeded
 * coins_kv (the kernel store — consensus.db, or the legacy progress.kv on a
 * pre-flip datadir; progress_store_open() migrates the latter to the former
 * in place) at a given height + block hash. Read-only over the coins set;
 * emits the SAME canonical stream as the -mint-anchor ceremony and the
 * anchor self-mint, so the resulting file is loadable by
 * -load-snapshot-at-own-height (which verifies the body SHA3 and checks that
 * hdr.anchor_block_hash names the in-memory active-chain location at the seed
 * height; that location check does not authenticate the state contents).
 *
 * Usage:
 *   snapshot_from_coinskv <datadir> <height> <blockhash_display_hex> <out_path>
 *     datadir   datadir containing the kernel store (the coins_kv home)
 *     height    seed height to stamp (must match the chain's block at that h)
 *     blockhash big-endian DISPLAY hex (as RPC shows it); reversed internally
 *     out_path  snapshot file to write
 */

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

#include "base/hex.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "storage/snapshot_shielded.h"

/* Provided by the node binary's main.c; this standalone tool defines its own
 * so the shared object set links (shutdown is irrelevant for a one-shot run). */
volatile sig_atomic_t g_shutdown_requested = 0;

int main(int argc, char **argv)
{
    if (argc != 5 && argc != 6) {
        fprintf(stderr,
                "usage: %s <datadir> <height> <blockhash_display_hex> "
                "<out_path> [--shielded]\n", argv[0]);
        return 2;
    }
    /* --shielded: also collect the Sapling+Sprout frontier + nullifier set from
     * the already-folded datadir and emit a section-bearing, body-digest-
     * verified snapshot candidate. This does not independently prove the
     * source datadir or the Sprout/nullifier history. Without it, emit a
     * coins-only snapshot as before. */
    bool want_shielded = (argc == 6 && strcmp(argv[5], "--shielded") == 0);
    if (argc == 6 && !want_shielded) {
        fprintf(stderr, "unknown 5th arg '%s' (expected --shielded)\n", argv[5]);
        return 2;
    }
    const char *datadir = argv[1];
    int32_t height = (int32_t)strtol(argv[2], NULL, 10);
    const char *hexhash = argv[3];
    const char *out_path = argv[4];

    if (strlen(hexhash) != 64) {
        fprintf(stderr, "blockhash must be 64 hex chars (got %zu)\n",
                strlen(hexhash));
        return 2;
    }
    /* Display hex is big-endian; internal hashBlock is little-endian.
     * Reverse byte order so anchor_block_hash matches block_index.hashBlock. */
    uint8_t anchor_hash[32], anchor_hash_be[32];
    if (!zcl_hex_decode(hexhash, anchor_hash_be, 32)) {
        fprintf(stderr, "bad hex in blockhash\n");
        return 2;
    }
    for (int i = 0; i < 32; i++)
        anchor_hash[31 - i] = anchor_hash_be[i];

    if (!progress_store_open(datadir)) {
        fprintf(stderr, "progress_store_open(%s) failed\n", datadir);
        return 1;
    }
    sqlite3 *pdb = progress_store_db();
    if (!pdb) {
        fprintf(stderr, "progress_store_db() returned NULL\n");
        return 1;
    }

    /* Report what coins_kv holds before writing. */
    int64_t num_txs = 0, count = 0, supply = 0;
    if (coins_kv_setinfo(pdb, &num_txs, &count, &supply))
        fprintf(stderr, "coins_kv: count=%lld supply=%lld\n",
                (long long)count, (long long)supply);

    struct snapshot_shielded shielded;
    struct snapshot_shielded *shptr = NULL;
    if (want_shielded) {
        if (!snapshot_shielded_collect_from_db(pdb, height, &shielded)) {
            fprintf(stderr,
                    "snapshot_shielded_collect_from_db FAILED "
                    "(shielded frontier unavailable at h=%d)\n", height);
            return 1;
        }
        shptr = &shielded;
        fprintf(stderr, "collected shielded frontier at h=%d\n", height);
    }

    uint8_t got_sha3[32] = {0};
    uint64_t got_count = 0;
    int64_t got_supply = 0;
    bool ok = coins_kv_snapshot_write(pdb, out_path, height, anchor_hash,
                                      shptr, got_sha3, &got_count, &got_supply);
    if (shptr)
        snapshot_shielded_free_collected(shptr);
    if (!ok) {
        fprintf(stderr, "coins_kv_snapshot_write FAILED\n");
        return 1;
    }

    char sha3hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(sha3hex + i * 2, 3, "%02x", got_sha3[i]);
    fprintf(stderr,
            "WROTE %s height=%d count=%llu supply=%lld sha3=%s\n",
            out_path, height, (unsigned long long)got_count,
            (long long)got_supply, sha3hex);
    return 0;
}
