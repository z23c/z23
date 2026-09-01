/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * chainstate_sapling_anchor -- the borrowed-frontier reader used by the
 * sapling_anchor_frontier_unavailable tier-1b cure.
 *
 * Proves, hermetically (temp LevelDB via dbwrapper; Pedersen hashing over
 * synthetic commitments — no ~/.zcash-params, no live chain), that
 * chainstate_legacy_get_sapling_anchor():
 *   (a) reads back a Sapling anchor tree stored under key ('Z' || root) and
 *       returns FOUND when the stored tree hashes back to that root
 *       (matching-root ACCEPTS);
 *   (b) returns MISSING for a root with no row;
 *   (c) FAIL-CLOSED: when the stored blob is a valid tree but does NOT hash
 *       back to the lookup key, returns ERROR and never hands back an
 *       unverified frontier (mismatched-root REFUSES);
 *   (d) round-trips the exact wire bytes zcashd stores (serialize -> store ->
 *       get), so the reader is compatible with the borrow source's format. */

#include "test/test_core.h"

#include "core/serialize.h"
#include "core/uint256.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/chainstate_legacy_reader.h"
#include "storage/dbwrapper.h"

#include <stdio.h>
#include <string.h>

#define CSA_CHECK(name, expr) do {                                   \
    printf("chainstate_sapling_anchor: %s... ", (name));             \
    if ((expr)) printf("OK\n");                                      \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

static void csa_fill(struct uint256 *h, uint8_t seed, size_t idx)
{
    for (size_t i = 0; i < 32; i++)
        h->data[i] = (uint8_t)(seed ^ (idx + i));
}

/* Build a non-empty Sapling frontier of `n` synthetic commitments. */
static void csa_build_tree(size_t n, struct incremental_merkle_tree *out)
{
    sapling_tree_init(out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm;
        csa_fill(&cm, 0x5A, i);
        incremental_tree_append(out, &cm);
    }
}

/* Write ('Z' || root) -> value(len bytes) into the LevelDB at `dir`. */
static bool csa_store(const char *dir, const struct uint256 *root,
                      const unsigned char *val, size_t vlen)
{
    struct db_wrapper db;
    memset(&db, 0, sizeof(db));
    /* wipe=false: accumulate rows across successive opens (test_make_tmpdir
     * already gave us a clean dir). */
    if (!db_wrapper_open(&db, dir, 1u << 20, false, false))
        return false;
    char key[33];
    key[0] = 'Z';
    memcpy(key + 1, root->data, 32);
    bool ok = db_write(&db, key, sizeof(key), (const char *)val, vlen, true);
    db_wrapper_close(&db);
    return ok;
}

int test_chainstate_sapling_anchor(void);
int test_chainstate_sapling_anchor(void)
{
    int failures = 0;

    char dir[512];
    test_make_tmpdir(dir, sizeof(dir), "chainstate_sapling_anchor", "db");

    /* Build a real Sapling frontier and serialize it exactly as zcashd stores
     * a SaplingMerkleTree (boost::optional wire format). */
    struct incremental_merkle_tree tree;
    csa_build_tree(11, &tree);
    struct uint256 root;
    incremental_tree_root(&tree, &root);

    struct byte_stream ser;
    stream_init(&ser, 256);
    CSA_CHECK("serialize frontier (zcashd SaplingMerkleTree wire format)",
              incremental_tree_serialize(&tree, &ser) && !ser.error);

    /* A bogus root that the tree does NOT hash to (for the fail-closed case). */
    struct uint256 wrong_key;
    csa_fill(&wrong_key, 0xEE, 999);   /* != incremental_tree_root(tree) */

    /* Seed BOTH rows before opening the reader: LevelDB is single-writer, so the
     * reader handle (which holds the dir LOCK) must not overlap a db_write. */
    CSA_CHECK("store anchor row under ('Z' || matching root)",
              csa_store(dir, &root, ser.data, ser.size));
    CSA_CHECK("store the same valid tree under a WRONG-root key",
              csa_store(dir, &wrong_key, ser.data, ser.size));

    void *h = NULL;
    CSA_CHECK("open chainstate copy", chainstate_legacy_open(dir, &h) && h);

    /* (a) matching root ACCEPTS + (d) round-trips. */
    {
        struct incremental_merkle_tree got;
        CSA_CHECK("get_sapling_anchor(matching root) == FOUND",
                  chainstate_legacy_get_sapling_anchor(h, &root, &got) ==
                      CHAINSTATE_ANCHOR_FOUND);
        struct uint256 got_root;
        incremental_tree_root(&got, &got_root);
        CSA_CHECK("recovered tree hashes back to the original root",
                  memcmp(got_root.data, root.data, 32) == 0);
    }

    /* (b) absent root == MISSING. */
    {
        struct uint256 absent;
        csa_fill(&absent, 0xA5, 777);
        struct incremental_merkle_tree got;
        CSA_CHECK("get_sapling_anchor(absent root) == MISSING",
                  chainstate_legacy_get_sapling_anchor(h, &absent, &got) ==
                      CHAINSTATE_ANCHOR_MISSING);
    }

    /* (c) FAIL-CLOSED: a valid tree stored under a bogus key deserializes fine
     * but does not hash back to that key -> ERROR (never handed back). */
    {
        struct incremental_merkle_tree got;
        CSA_CHECK("get_sapling_anchor(root-mismatched blob) == ERROR (refused)",
                  chainstate_legacy_get_sapling_anchor(h, &wrong_key, &got) ==
                      CHAINSTATE_ANCHOR_ERROR);
    }

    chainstate_legacy_close(h);
    stream_free(&ser);
    test_rm_rf_recursive(dir);

    return failures;
}
