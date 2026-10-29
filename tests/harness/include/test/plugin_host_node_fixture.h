/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private node-backed chain fixture shared by resident plugin tests. */
#ifndef Z23_TEST_PLUGIN_HOST_NODE_FIXTURE_H
#define Z23_TEST_PLUGIN_HOST_NODE_FIXTURE_H

#include "test/test_core.h"
#include "models/block.h"
#include "primitives/block.h"
#include "chain/chain.h"
#include "command/native_command.h"
#include "models/database.h"
#include "validation/chainstate.h"
#include "services/plugin_host_handlers.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PRH_TIP_HEIGHT 7

#define PRH_CHAIN_LEN (PRH_TIP_HEIGHT + 1)

struct prh_chain {
    char dir[256];
    struct sqlite3 *sdb;
    struct node_db ndb;
    struct active_chain active;
    bool active_ready;
    bool db_ready;
    struct block_index bi[PRH_CHAIN_LEN];
    uint8_t hash[PRH_CHAIN_LEN][32];
    struct plugin_host_node node;
    struct plugin_hostcall_handlers handlers;
};

static inline bool prh_authority(void *context, int64_t *height, uint8_t hash[32])
{
    const struct prh_chain *c = context;
    *height = PRH_TIP_HEIGHT;
    memcpy(hash, c->hash[PRH_TIP_HEIGHT], 32);
    return true;
}

static const uint8_t prh_sol[8] = {1, 2, 3, 4, 5, 6, 7, 8};

/* One header of the fixture chain: its prev link is the previous block's hash,
 * so every row's id is the real header hash and the links are consistent. */
static inline bool prh_make_row(struct prh_chain *c, struct node_db *rw, int h)
{
    struct block_header b;
    block_header_init(&b);
    if (h > 0)
        memcpy(b.hashPrevBlock.data, c->hash[h - 1], 32);
    memset(b.hashMerkleRoot.data, 0x40 + h, 32);
    b.nTime = 1700000000u + 150u * (uint32_t)h;
    b.nBits = 0x1f07ffff;
    memset(b.nNonce.data, 0x10 + h, 32);
    memcpy(b.nSolution, prh_sol, sizeof(prh_sol));
    b.nSolutionSize = sizeof(prh_sol);
    struct uint256 id;
    block_header_get_hash(&b, &id);
    memcpy(c->hash[h], id.data, 32);
    struct db_block row;
    memset(&row, 0, sizeof(row));
    memcpy(row.hash, id.data, 32);
    memcpy(row.prev_hash, b.hashPrevBlock.data, 32);
    memcpy(row.merkle_root, b.hashMerkleRoot.data, 32);
    memcpy(row.nonce, b.nNonce.data, 32);
    row.height = h;
    row.version = b.nVersion;
    row.time = b.nTime;
    row.bits = b.nBits;
    row.solution = (uint8_t *)prh_sol;
    row.solution_len = sizeof(prh_sol);
    row.status = 3;
    return db_block_save(rw, &row);
}

/* Rows for heights 0..tip, saved on a writable handle that is closed before
 * the read-only connection the handlers use is opened. */
static inline bool prh_save_chain(struct prh_chain *c)
{
    char path[300];
    snprintf(path, sizeof(path), "%s/node.db", c->dir);
    struct node_db rw;
    if (!node_db_open(&rw, path))
        return false;
    bool ok = true;
    for (int h = 0; ok && h < PRH_CHAIN_LEN; h++)
        ok = prh_make_row(c, &rw, h);
    node_db_close(&rw);
    return ok;
}

static inline bool prh_install_active(struct prh_chain *c)
{
    active_chain_init(&c->active);
    c->active_ready = true;
    for (int h = 0; h < PRH_CHAIN_LEN; h++) {
        struct block_index *bi = &c->bi[h];
        block_index_init(bi);
        memcpy(bi->hashBlock.data, c->hash[h], 32);
        bi->phashBlock = &bi->hashBlock;
        bi->nHeight = h;
        if (!active_chain_install_tip_slot(&c->active, bi))
            return false;
    }
    return true;
}

/* The served tip is block 7; its header row is what chain.tip reads the time
 * from. The node is bound to the calling thread, which must also poll the run. */
static inline bool prh_chain_open(struct prh_chain *c)
{
    memset(c, 0, sizeof(*c));
    if (!test_mkdtemp(c->dir, sizeof(c->dir), "prh") || !prh_save_chain(c))
        return false;
    if (zcl_native_node_db_open_readonly(c->dir, &c->sdb, &c->ndb, NULL, 0) != ZCL_NODE_DB_RO_OK)
        return false;
    c->db_ready = true;
    if (!prh_install_active(c) ||
        !plugin_host_node_init(&c->node, &c->ndb, &c->active, "hostcall").ok)
        return false;
    c->node.authority = prh_authority;
    c->node.authority_context = c;
    return plugin_host_node_handlers(&c->handlers, &c->node).ok;
}

static inline void prh_chain_close(struct prh_chain *c)
{
    if (c->db_ready)
        zcl_native_node_db_close_readonly(&c->sdb, &c->ndb);
    if (c->active_ready)
        active_chain_free(&c->active);
    if (!c->dir[0]) return;
    char path[320];
    static const char *const sfx[] = {"", "-wal", "-shm"};
    for (size_t i = 0; i < 3; i++) {
        snprintf(path, sizeof(path), "%s/node.db%s", c->dir, sfx[i]);
        unlink(path);
    }
    rmdir(c->dir);
}


#endif
