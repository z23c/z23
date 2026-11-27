/* purpose: Inspect miner ballots against hash-bound testnet validation evidence. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "blockchain_controller_internal.h"
#include "controllers/strong_params.h"
#include "base/hex.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "domain/consensus/check_block.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "services/miner_signal_round.h"
#include "services/miner_signal_catalog.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* At most 256 synchronous body reads; this bounds local diagnostic I/O. */
#define BALLOT_MAX_WINDOW 256

struct ballot_block {
    struct uint256 hash;
    struct disk_block_pos pos;
    int32_t height;
};
struct ballot_snapshot {
    struct uint256 parent_hash, anchor_hash;
    int32_t parent_height, anchor_height;
    bool has_anchor;
    size_t count;
    struct ballot_block *blocks;
};

static bool ballot_fail(struct json_value *result, const char *message)
{
    json_set_str(result, message);
    return false;
}

static bool ballot_parse_numbers(const struct json_value *params, int64_t n[5])
{
    if (!params || params->type != JSON_ARR || json_size(params) != 6) return false;
    for (size_t i = 0; i < 5; i++) {
        const struct json_value *v = json_at(params, i);
        if (!v || v->type != JSON_INT) return false;
        n[i] = json_get_int(v);
    }
    return true;
}

static bool ballot_numbers_in_range(const int64_t n[5])
{
    return n[0] >= 1 && n[0] <= INT32_MAX && n[1] >= 1 &&
        n[1] <= BALLOT_MAX_WINDOW && n[2] >= 1 && n[2] <= INT32_MAX &&
        n[3] >= 1 && n[3] <= 256 && n[4] >= 0 && n[4] < n[3];
}

static bool ballot_hex(const struct json_value *v, uint8_t out[32]);

static bool ballot_parse(const struct json_value *params,
                         struct miner_signal_schedule *s)
{
    int64_t n[5];
    if (!ballot_parse_numbers(params, n) || !ballot_numbers_in_range(n)) return false;
    const struct json_value *catalog = json_at(params, 5);
    if (!ballot_hex(catalog, s->catalog)) return false; // raw-return-ok:invalid catalog becomes an RPC parameter error
    s->start = (int32_t)n[0]; s->window = (int32_t)n[1];
    s->activation = (int32_t)n[2]; s->slots = (uint16_t)n[3];
    s->slot = (uint16_t)n[4];
    return miner_signal_schedule_valid(s).ok;
}

/* These parsers propagate bad input to the RPC's explanatory error body. */
static bool ballot_hex(const struct json_value *v, uint8_t out[32])
{
    if (!v || v->type != JSON_STR) return false;
    if (!zcl_hex_decode(json_get_str(v), out, 32))
        return false; // raw-return-ok:invalid hex becomes an RPC parameter error
    return true;
}

static bool ballot_integer(const struct json_value *v, int64_t *out)
{
    if (!v || v->type != JSON_INT) return false;
    *out = json_get_int(v);
    return true;
}

static bool ballot_catalog_range(int64_t start, int64_t window, int64_t slot, size_t count)
{
    return start >= 1 && start <= INT32_MAX && window >= 1 &&
           window <= BALLOT_MAX_WINDOW && count >= 1 && count <= 256 &&
           slot >= 0 && (uint64_t)slot < count;
}

static bool ballot_catalog_shape(const struct json_value *params,
                                 struct miner_signal_catalog *catalog,
                                 const struct json_value **rules_out, size_t *slot_out)
{
    if (!params || params->type != JSON_ARR || json_size(params) != 5) return false;
    int64_t start, window, slot;
    if (!ballot_integer(json_at(params, 1), &start) ||
        !ballot_integer(json_at(params, 2), &window) ||
        !ballot_integer(json_at(params, 4), &slot))
        return false; // raw-return-ok:invalid types become an RPC parameter error
    const struct json_value *rules = json_at(params, 3);
    if (!rules || rules->type != JSON_ARR) return false;
    size_t count = json_size(rules);
    if (!ballot_catalog_range(start, window, slot, count))
        return false; // raw-return-ok:invalid ranges become an RPC parameter error
    catalog->start = (int32_t)start;
    catalog->window = (int32_t)window;
    catalog->count = count;
    *rules_out = rules;
    *slot_out = (size_t)slot;
    return true;
}

static bool ballot_catalog_entry(const struct json_value *entry,
                                 struct miner_signal_catalog_entry *out)
{
    if (!entry || entry->type != JSON_ARR || json_size(entry) != 2) return false;
    int64_t height;
    if (!ballot_hex(json_at(entry, 0), out->rule_revision) ||
        !ballot_integer(json_at(entry, 1), &height))
        return false; // raw-return-ok:invalid entry becomes an RPC parameter error
    if (height < 1 || height > INT32_MAX) return false;
    out->activation = (int32_t)height;
    return true;
}

/* The catalog service checks ordering, selected slot and activation grace. */
static bool ballot_parse_catalog(const struct json_value *params,
                                 const struct chain_params *cp,
                                 struct miner_signal_schedule *out)
{
    if (!cp) return false;
    struct miner_signal_catalog_entry entries[256] = {0};
    struct miner_signal_catalog catalog = { .entries = entries };
    const struct json_value *rules;
    size_t slot;
    if (!ballot_catalog_shape(params, &catalog, &rules, &slot) ||
        !ballot_hex(json_at(params, 0), catalog.network_id))
        return false; // raw-return-ok:invalid catalog becomes an RPC parameter error
    memcpy(catalog.genesis, cp->consensus.hashGenesisBlock.data, sizeof(catalog.genesis));
    for (size_t i = 0; i < catalog.count; ++i)
        if (!ballot_catalog_entry(json_at(rules, i), &entries[i]))
            return false; // raw-return-ok:invalid entry becomes an RPC parameter error
    return miner_signal_catalog_select(&catalog, slot, out).ok;
}

static bool ballot_test_network(const struct chain_params *cp)
{
    return cp && (!strcmp(cp->strNetworkID, "test") || !strcmp(cp->strNetworkID, "regtest"));
}

bool rpc_getballotcatalog(const struct json_value *params, bool help,
                          struct json_value *result)
{
    RPC_HELP(help, result,
        "getballotcatalog fork_id_hex start window [[rule_revision_hex,activation],...] slot\n"
        "Derive a network-bound ballot catalog and selected schedule on testnet or regtest.");
    const struct chain_params *cp = chain_params_get();
    if (!ballot_test_network(cp))
        return ballot_fail(result, "Ballot catalog is available only on testnet and regtest");
    struct miner_signal_schedule s = {0};
    if (!ballot_parse_catalog(params, cp, &s))
        return ballot_fail(result, "Invalid catalog, schedule, fork identity, rules, or selected slot");
    char digest[65];
    zcl_hex_encode(s.catalog, sizeof(s.catalog), digest);
    json_set_object(result);
    if (json_push_kv_str(result, "network", cp->strNetworkID) &&
        json_push_kv_str(result, "schedule_source", "supplied_catalog") &&
        json_push_kv_str(result, "catalog", digest) &&
        json_push_kv_int(result, "start", s.start) &&
        json_push_kv_int(result, "window", s.window) &&
        json_push_kv_int(result, "activation", s.activation) &&
        json_push_kv_int(result, "slots", s.slots) &&
        json_push_kv_int(result, "slot", s.slot)) return true;
    return ballot_fail(result, "Out of memory building catalog result");
}

/* Genesis is fixed by the selected network. A finalized row zero can witness
 * block one, so it cannot always supply the pre-window parent for start=1. */
static bool ballot_anchor_hash(sqlite3 *db, int32_t height, struct uint256 *out)
{
    if (height == 0) {
        *out = chain_params_get()->consensus.hashGenesisBlock;
        return true;
    }
    return tip_finalize_stage_block_hash_at(db, height, out->data);
}

/* The progress lock binds the selected hashes and all validation evidence to
 * one reducer-store observation. An anchor witness alone is never a vote. */
static bool ballot_snapshot_evidence(const struct miner_signal_schedule *s,
                                     struct ballot_snapshot *snap)
{
    bool ok = false;
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    int32_t height = reducer_frontier_provable_tip_cached();
    int durable_height = -1;
    uint8_t durable_hash[32];
    if (!db || height < 0 || height == INT32_MAX ||
        !tip_finalize_stage_resolve_durable_tip(db, &durable_height, durable_hash) ||
        durable_height < height ||
        !tip_finalize_stage_block_hash_at(db, height, snap->parent_hash.data)) goto done;
    if (durable_height == height && memcmp(durable_hash, snap->parent_hash.data, 32)) goto done;
    snap->parent_height = height;
    if ((int64_t)height + 1 < s->start) { ok = true; goto done; }
    int32_t end = height;
    int64_t last = (int64_t)s->start + s->window - 1;
    if (end > last) end = (int32_t)last;
    if (!ballot_anchor_hash(db, s->start - 1, &snap->anchor_hash)) goto done;
    snap->anchor_height = s->start - 1;
    snap->has_anchor = true;
    snap->count = (size_t)(end - s->start + 1);
    for (size_t i = 0; i < snap->count; i++) {
        struct ballot_block *b = &snap->blocks[i];
        b->height = s->start + (int32_t)i;
        if (!tip_finalize_stage_block_hash_at(db, b->height, b->hash.data) ||
            tip_finalize_full_evidence_at(db, b->height, &b->hash) != 1) goto done;
    }
    ok = true;
done:
    progress_store_tx_unlock();
    return ok;
}

/* Select positions from the map object identified by the durable hash. */
static bool ballot_snapshot_positions(struct main_state *ms, struct ballot_snapshot *snap)
{
    bool ok = true;
    zcl_mutex_lock(&ms->cs_main);
    for (size_t i = 0; i < snap->count; i++) {
        struct ballot_block *b = &snap->blocks[i];
        struct block_index *entry = block_map_find(&ms->map_block_index, &b->hash);
        if (!entry || !entry->phashBlock || entry->nHeight != b->height ||
            !uint256_eq(entry->phashBlock, &b->hash) || block_has_any_failure(entry) ||
            !block_index_disk_pos_snapshot(entry, &b->pos, NULL)) { ok = false; break; }
    }
    zcl_mutex_unlock(&ms->cs_main);
    return ok;
}

static bool ballot_snapshot_current(struct main_state *ms,
                                    const struct ballot_snapshot *snap)
{
    bool same;
    zcl_mutex_lock(&ms->chain_active.write_lock);
    int32_t height = reducer_frontier_provable_tip_cached();
    struct block_index *tip = height >= 0 ? active_chain_at(&ms->chain_active, height) : NULL;
    same = height == snap->parent_height && tip && tip->phashBlock &&
           tip->nHeight == height && uint256_eq(tip->phashBlock, &snap->parent_hash) &&
           !block_has_any_failure(tip);
    zcl_mutex_unlock(&ms->chain_active.write_lock);
    return same;
}

static bool ballot_authority_parent(sqlite3 *db, const struct ballot_snapshot *snap)
{
    int height = -1;
    uint8_t tip_hash[32], parent_hash[32];
    bool same = db && reducer_frontier_provable_tip_cached() == snap->parent_height &&
        tip_finalize_stage_resolve_durable_tip(db, &height, tip_hash) &&
        height >= snap->parent_height &&
        tip_finalize_stage_block_hash_at(db, snap->parent_height, parent_hash) &&
        !memcmp(parent_hash, snap->parent_hash.data, 32) &&
        (height != snap->parent_height || !memcmp(tip_hash, parent_hash, 32));
    if (same && snap->has_anchor) {
        struct uint256 anchor_hash;
        if (!ballot_anchor_hash(db, snap->anchor_height, &anchor_hash) ||
            !uint256_eq(&anchor_hash, &snap->anchor_hash)) same = false;
    }
    return same;
}

static bool ballot_authority_current(const struct ballot_snapshot *snap)
{
    progress_store_tx_lock();
    sqlite3 *db = progress_store_db();
    bool same = ballot_authority_parent(db, snap);
    for (size_t i = 0; same && i < snap->count; i++) {
        uint8_t block_hash[32];
        const struct ballot_block *b = &snap->blocks[i];
        if (!tip_finalize_stage_block_hash_at(db, b->height, block_hash) ||
            memcmp(block_hash, b->hash.data, 32) ||
            tip_finalize_full_evidence_at(db, b->height, &b->hash) != 1) same = false;
    }
    progress_store_tx_unlock();
    return same;
}

static bool ballot_read_one(const char *datadir, const struct ballot_block *entry,
                            struct miner_signal_tally *tally)
{
    struct block block;
    block_init(&block);
    bool ok = read_block_from_disk_pread(&block, &entry->pos, datadir);
    struct uint256 hash;
    if (ok) {
        block_header_get_hash(&block.header, &hash);
        /* Deserialization computes txids; recheck serialization success since
         * its mutating wrapper does not report allocation failure. */
        ok = uint256_eq(&hash, &entry->hash) && block.num_vtx && block.vtx;
        for (size_t i = 0; ok && i < block.num_vtx; i++)
            ok = transaction_hash_serialized(&block.vtx[i], &block.vtx[i].hash);
        if (ok) ok = domain_consensus_check_block_merkle_root(&block, NULL, 0, NULL).ok;
    }
    if (ok) {
        struct miner_signal_tally next;
        ok = miner_signal_connect(tally, entry->height, &block.header.hashPrevBlock,
                                  &hash, &block.vtx[0], &next).ok;
        if (ok) *tally = next;
    }
    block_free(&block);
    return ok;
}

static const char *ballot_phase_name(enum miner_signal_phase p)
{
    switch (p) {
    case MINER_SIGNAL_VOTING: return "voting";
    case MINER_SIGNAL_EXPIRED: return "expired";
    case MINER_SIGNAL_LOCKED_IN: return "locked_in";
    case MINER_SIGNAL_ACTIVE: return "active";
    }
    return NULL;
}

static bool ballot_tally(const char *datadir, const struct miner_signal_schedule *s,
                         const struct ballot_snapshot *snap,
                         struct miner_signal_tally *tally, const char **phase)
{
    *phase = "scheduled";
    if ((int64_t)snap->parent_height + 1 < s->start) return true;
    if (!miner_signal_begin(s, s->start - 1, &snap->anchor_hash, tally).ok) return false;
    for (size_t i = 0; i < snap->count; i++)
        if (!ballot_read_one(datadir, &snap->blocks[i], tally)) return false;
    enum miner_signal_phase p;
    if (!miner_signal_phase_at(tally, snap->parent_height + 1, &p).ok) return false;
    *phase = ballot_phase_name(p);
    return *phase != NULL;
}

static bool ballot_reply(struct json_value *result, const struct miner_signal_schedule *s,
                         const struct ballot_snapshot *snap, const char *network,
                         const char *source, const char *phase, int32_t votes)
{
    char hash_hex[65], catalog[65];
    zcl_hex_encode(s->catalog, sizeof(s->catalog), catalog);
    uint256_get_hex(&snap->parent_hash, hash_hex);
    json_set_object(result);
    if (json_push_kv_str(result, "network", network) &&
        json_push_kv_str(result, "parent_basis", "durable_provable_tip") &&
        json_push_kv_str(result, "schedule_source", source) &&
        json_push_kv_int(result, "parent_height", snap->parent_height) &&
        json_push_kv_str(result, "parent_hash", hash_hex) &&
        json_push_kv_int(result, "next_height", (int64_t)snap->parent_height + 1) &&
        json_push_kv_str(result, "phase_of_next_block", phase) &&
        json_push_kv_int(result, "votes", votes) &&
        json_push_kv_int(result, "start", s->start) &&
        json_push_kv_int(result, "window", s->window) &&
        json_push_kv_int(result, "activation", s->activation) &&
        json_push_kv_int(result, "slots", s->slots) &&
        json_push_kv_int(result, "slot", s->slot) &&
        json_push_kv_str(result, "catalog", catalog)) return true;
    return ballot_fail(result, "Out of memory building ballot result");
}

static bool ballot_status_snapshot(const struct miner_signal_schedule *s,
                                   const struct chain_params *cp,
                                   const struct blockchain_context *ctx,
                                   const char *source, struct json_value *result)
{
    struct ballot_snapshot snap = {0};
    snap.blocks = zcl_calloc((size_t)s->window, sizeof(*snap.blocks), "ballot status ancestry");
    if (!snap.blocks) return ballot_fail(result, "Out of memory");
    bool ok = ballot_snapshot_evidence(s, &snap);
    if (ok) ok = ballot_snapshot_positions(ctx->main_state, &snap);
    if (ok) ok = ballot_snapshot_current(ctx->main_state, &snap);
    struct miner_signal_tally tally = {0};
    const char *phase = NULL;
    if (ok) ok = ballot_tally(ctx->datadir, s, &snap, &tally, &phase);
    if (ok) ok = ballot_snapshot_current(ctx->main_state, &snap);
    if (ok) ok = ballot_authority_current(&snap);
    if (ok) ok = ballot_reply(result, s, &snap, cp->strNetworkID,
                              source, phase, tally.votes);
    else ballot_fail(result, "Validated ballot history unavailable or chain changed; retry");
    free(snap.blocks);
    return ok;
}


bool rpc_getballotstatus(const struct json_value *params, bool help,
                         struct json_value *result)
{
    RPC_HELP(help, result,
        "getballotstatus fork_id_hex start window rules slot | start window activation slots slot catalog_hex\n"
        "Read testnet ballot history at the durable provable tip. Each counted block requires full validation evidence. Maximum window 256 blocks.");
    const struct chain_params *cp = chain_params_get();
    struct miner_signal_schedule s = {0};
    bool supplied = params && params->type == JSON_ARR && json_size(params) == 5;
    if (!(supplied ? ballot_parse_catalog(params, cp, &s) : ballot_parse(params, &s)))
        return ballot_fail(result, "Invalid integer schedule, slot, 32-byte catalog, or window exceeds 256");
    if (!ballot_test_network(cp))
        return ballot_fail(result, "Ballot status is available only on testnet and regtest");
    struct blockchain_context *ctx = blockchain_ctx();
    if (!ctx->main_state || !ctx->datadir)
        return ballot_fail(result, "Chain state or block storage unavailable");
    return ballot_status_snapshot(&s, cp, ctx, supplied ? "supplied_catalog" : "raw_parameters",
                                  result);
}
