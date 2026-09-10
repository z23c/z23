/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Source-view freshness from a sealed Merkle snapshot vs live stat. */

#include "codeindex_merkle_internal.h"

#include "util/log_macros.h"

#include <string.h>

struct merkle_inventory_match {
    const struct merkle_snapshot *snap;
    uint32_t seen;
    bool mismatch;
};

static bool merkle_inventory_key_cb(const char *relpath,
                                    const struct ci_merkle_stat_key *live,
                                    void *user)
{
    struct merkle_inventory_match *m = user;
    if (m->mismatch)
        return false;
    m->seen++;
    const struct merkle_leaf_rec *prev =
        merkle_find_leaf(m->snap->leaves, m->snap->nleaves, relpath);
    if (!prev || memcmp(&prev->key, live, sizeof(*live)) != 0) {
        m->mismatch = true;
        return false;
    }
    return true;
}

bool ci_merkle_snapshot_inventory_current(const char *root,
                                          bool *have_snapshot,
                                          bool *unchanged,
                                          uint8_t digest_out[32])
{
    if (have_snapshot) *have_snapshot = false;
    if (unchanged) *unchanged = false;
    if (!root || !have_snapshot || !unchanged || !digest_out)
        LOG_FAIL("codeindex", "null arg to snapshot_inventory_current");

    struct merkle_snapshot snap;
    bool found = false;
    if (!merkle_snapshot_load(root, &snap, &found))
        LOG_FAIL("codeindex", "load merkle snapshot for inventory current");
    if (!found)
        return true;

    *have_snapshot = true;
    struct merkle_inventory_match match = {
        .snap = &snap, .seen = 0, .mismatch = false,
    };
    bool enumerated =
        ci_enumerate_merkle_sources(root, merkle_inventory_key_cb, &match);
    if (!enumerated && !match.mismatch) {
        merkle_snapshot_free(&snap);
        LOG_FAIL("codeindex", "enumerate inventory for snapshot current");
    }
    if (match.mismatch || match.seen != snap.nleaves) {
        merkle_snapshot_free(&snap);
        return true;
    }
    const struct merkle_node_rec *root_node =
        merkle_find_node(snap.nodes, snap.nnodes, "");
    if (!root_node) {
        merkle_snapshot_free(&snap);
        LOG_FAIL("codeindex", "snapshot missing root node");
    }
    memcpy(digest_out, root_node->digest.bytes, 32);
    *unchanged = true;
    merkle_snapshot_free(&snap);
    return true;
}
