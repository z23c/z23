// one-result-type-ok:walk-internal-bookkeeping — in-process helpers of the catchup walk; a refused step is logged by the walk and leaves the tree untouched.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling tree bookkeeping for the node.db catchup walk.
 *
 * node_state["sapling_tree"] is a derived copy of the note-commitment
 * frontier, stored with node_state["sapling_tree_rebuild_height"], the
 * height it covers. The catchup walk visits heights from the projection
 * cursor, which can lie far below that height (a seeded node backfilling old
 * block bodies, a re-walk after a cursor reset) or above it (a hole in the
 * bodies). Appending the outputs of a height the tree already covers, or of a
 * height that leaves a gap, corrupts the copy. The walk therefore appends
 * only at height == tree height + 1.
 *
 * A copy whose root differs from the header root at its own height is never
 * used. A copy that lags the walk is moved forward without replaying blocks
 * when its root equals the header root at the previous height, or when the
 * reducer's anchor frontier is newer and matches its own header root. The
 * reducer checks every anchor against the block header, so that frontier is
 * the authoritative source. It is read through an independent read-only
 * connection to the progress store. */

#include "node_db_catchup_internal.h"

#include "chain/chain.h"
#include "core/serialize.h"
#include "models/database.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"

#include <string.h>

/* engine/controllers/src/sync_controller_sapling_tree_persist.c
 * (controllers/sync_controller.h): the atomic tree/height pair writer. Reached
 * by forward declaration so this service file does not include a controller
 * header. */
bool sapling_tree_persist_pair_in_open_tx(struct node_db *ndb,
                                          const void *blob, size_t blob_len,
                                          int64_t height);

static bool header_root_for(const struct active_chain *chain, int64_t h,
                            struct uint256 *root)
{
    static const uint8_t zeros32[32] = {0};
    const struct block_index *bi =
        (chain && h >= 0 && h <= INT32_MAX)
            ? active_chain_at(chain, (int)h) : NULL;
    if (!bi || memcmp(bi->hashFinalSaplingRoot.data, zeros32, 32) == 0)
        return false; // raw-return-ok:absent root is a normal pre-Sapling state
    *root = bi->hashFinalSaplingRoot;
    return true;
}

static const struct uint256 *tree_root(struct catchup_sapling_tree *ct)
{
    if (!ct->root_valid) {
        incremental_tree_root(&ct->tree, &ct->root);
        ct->root_valid = true;
    }
    return &ct->root;
}

static bool root_matches_header(struct catchup_sapling_tree *ct,
                                const struct active_chain *chain, int64_t h)
{
    struct uint256 want;
    if (!header_root_for(chain, h, &want)) // raw-return-ok:no header root to compare with
        return false;
    return memcmp(tree_root(ct)->data, want.data, 32) == 0;
}

/* Latest reducer Sapling frontier whose root equals its header root. */
static bool read_anchor(const struct active_chain *chain, int64_t max_h,
                        struct incremental_merkle_tree *t, int64_t *ah)
{
    sqlite3 *rdb = progress_store_open_reader();
    if (!rdb)
        return false; // raw-return-ok:store not open (fixture or legacy boot)
    *ah = -1;
    enum anchor_kv_lookup_result lr =
        anchor_kv_tree_at_or_below(rdb, ANCHOR_POOL_SAPLING, max_h, t, NULL, ah);
    sqlite3_close(rdb);
    struct catchup_sapling_tree probe = {.tree = *t};
    return lr == ANCHOR_KV_FOUND && root_matches_header(&probe, chain, *ah);
}

/* Replace the copy by the reducer frontier at or below max_h when that is
 * newer. After a miss the reducer is not read again for 4096 heights. */
static bool adopt_anchor(struct catchup_sapling_tree *ct,
                         const struct active_chain *chain, int64_t max_h)
{
    if (max_h < ct->anchor_retry_h)
        return false; // raw-return-ok:recent miss, not read again yet
    ct->anchor_retry_h = max_h > INT64_MAX - 4096 ? INT64_MAX : max_h + 4096;
    struct incremental_merkle_tree t;
    int64_t ah = -1;
    if (!read_anchor(chain, max_h, &t, &ah) || ah <= ct->height)
        return false; // raw-return-ok:no newer verified frontier
    LOG_WARN("catchup", "catchup: Sapling tree (size=%zu h=%lld) replaced by "
             "the verified reducer frontier at h=%lld (size=%zu)",
             incremental_tree_size(&ct->tree), (long long)ct->height,
             (long long)ah, incremental_tree_size(&t));
    ct->tree = t;
    ct->height = ah;
    ct->root_valid = false;
    ct->usable = true;
    ct->dirty = true;
    return true;
}

void catchup_sapling_tree_load(struct node_db *ndb,
                               const struct active_chain *chain,
                               struct catchup_sapling_tree *ct)
{
    memset(ct, 0, sizeof(*ct));
    sapling_tree_init(&ct->tree);
    ct->height = -1;
    uint8_t buf[8192];
    size_t len = 0;
    if (!node_db_state_get(ndb, "sapling_tree", buf, sizeof(buf), &len) ||
        len == 0) {
        ct->usable = true;
        return;
    }
    struct byte_stream ts;
    stream_init_from_data(&ts, buf, len);
    bool parsed = incremental_tree_deserialize(&ct->tree, &ts);
    if (!node_db_state_get_int(ndb, "sapling_tree_rebuild_height",
                               &ct->height))
        ct->height = -1;
    struct uint256 unused;
    if (parsed && ct->height >= 0 &&
        (root_matches_header(ct, chain, ct->height) ||
         (incremental_tree_size(&ct->tree) == 0 &&
          !header_root_for(chain, ct->height, &unused)))) {
        ct->usable = true;
        return;
    }
    LOG_WARN("catchup", "catchup: persisted Sapling tree (size=%zu h=%lld) "
             "disagrees with its header root", incremental_tree_size(&ct->tree),
             (long long)ct->height);
    sapling_tree_init(&ct->tree);
    ct->height = -1;
    ct->root_valid = false;
    bool adopted = adopt_anchor(ct, chain, INT64_MAX);
    ct->anchor_retry_h = 0;
    if (!adopted)
        LOG_WARN("catchup", "catchup: no verified reducer frontier; the walk "
                 "will not append to the persisted tree");
}

bool catchup_sapling_tree_prepare(struct catchup_sapling_tree *ct,
                                  const struct active_chain *chain, int h)
{
    const int64_t prev = (int64_t)h - 1;
    struct uint256 unused;
    if (ct->height >= h)
        return false; // raw-return-ok:tree already covers h
    if (ct->usable) {
        if (ct->height == prev)
            return true;
        if (incremental_tree_size(&ct->tree) == 0 &&
            !header_root_for(chain, prev, &unused))
            return true; /* before Sapling: nothing to append */
        if (root_matches_header(ct, chain, prev)) {
            ct->height = prev;
            return true;
        }
    }
    if (!adopt_anchor(ct, chain, prev))
        return false; // raw-return-ok:no verified way to reach h-1
    if (ct->height != prev && !root_matches_header(ct, chain, prev))
        return false; // raw-return-ok:frontier does not reach h-1
    ct->height = prev;
    return true;
}

void catchup_sapling_tree_note_advanced(struct catchup_sapling_tree *ct, int h)
{
    ct->height = h;
    ct->root_valid = false;
    ct->dirty = false;
}

void catchup_sapling_tree_note_skipped(struct catchup_sapling_tree *ct, int h)
{
    if (ct->skipped++ == 0)
        LOG_WARN("catchup", "catchup: Sapling tree covers h=%lld; not "
                 "appending at h=%d (first skipped height this pass)",
                 (long long)ct->height, h);
}

void catchup_sapling_tree_persist_dirty(struct node_db *ndb,
                                        struct catchup_sapling_tree *ct)
{
    if (!ct->dirty)
        return;
    ct->dirty = false;
    struct byte_stream ts;
    stream_init(&ts, 4096);
    if (!incremental_tree_serialize(&ct->tree, &ts) ||
        !sapling_tree_persist_pair_in_open_tx(ndb, ts.data, ts.size,
                                              ct->height))
        LOG_WARN("catchup", "catchup: could not persist Sapling tree at "
                 "h=%lld", (long long)ct->height);
    stream_free(&ts);
}
