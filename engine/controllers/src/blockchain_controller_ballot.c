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
#include "services/miner_signal_catalog_pin.h"
#include "storage/disk_block_io.h"
#include "storage/progress_store.h"
#include "util/safe_alloc.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* At most 256 synchronous body reads; this bounds local diagnostic I/O. */
#define BALLOT_MAX_WINDOW 256

struct ballot_block {
    const struct block_index *index;
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

/* Parse both the RPC and pinned-file catalog through one typed service. */
static bool ballot_parse_catalog(const struct json_value *params,
                                 const struct chain_params *cp,
                                 struct miner_signal_schedule *out)
{
    if (!params || params->type != JSON_ARR || json_size(params) != 5 || !cp)
        return false;
    const struct json_value *slot_value = json_at(params, 4);
    if (!slot_value || slot_value->type != JSON_INT) return false;
    int64_t slot = json_get_int(slot_value);
    if (slot < 0 || slot >= 256) return false;
    struct miner_signal_catalog_pin pin = {0};
    struct zcl_result r = miner_signal_catalog_pin_parse(
        json_at(params, 0), json_at(params, 1), json_at(params, 2), json_at(params, 3),
        cp->consensus.hashGenesisBlock.data, &pin);
    if (!r.ok) return false; /* invalid catalog becomes the RPC parameter error */
    return miner_signal_catalog_pin_select(&pin, (size_t)slot, out).ok;
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
        b->index = entry;
    }
    zcl_mutex_unlock(&ms->cs_main);
    return ok;
}

/* Compare the durable vote endpoint with the selected window under its writer's
 * lock. Sparse repair can preserve lower slots, so agreement here witnesses
 * the visible selection only. A disagreement always invalidates the tally. */
static bool ballot_endpoint_current(const struct active_chain *chain,
                                    const struct ballot_snapshot *snap)
{
    if (!snap->count)
        return !snap->has_anchor || uint256_eq(&snap->anchor_hash, &snap->parent_hash);
    const struct ballot_block *end = &snap->blocks[snap->count - 1];
    return active_chain_at(chain, end->height) == end->index;
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
           !block_has_any_failure(tip) && ballot_endpoint_current(&ms->chain_active, snap);
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
                            struct miner_signal_tally *tallies, size_t count)
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
    for (size_t i = 0; ok && i < count; i++) {
        struct miner_signal_tally next;
        ok = miner_signal_connect(&tallies[i], entry->height, &block.header.hashPrevBlock,
                                  &hash, &block.vtx[0], &next).ok;
        if (ok) tallies[i] = next;
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
        if (!ballot_read_one(datadir, &snap->blocks[i], tally, 1)) return false;
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

/* One verified pin, one body read per height, and one authority recheck for
 * the entire catalog. The pin owns its entries and is immutable after boot. */
static bool ballot_catalog_tallies(const struct miner_signal_catalog_pin *pin,
                                   const struct miner_signal_schedule *first,
                                   const struct ballot_snapshot *snap, const char *datadir,
                                   struct miner_signal_tally *tallies)
{
    if ((int64_t)snap->parent_height + 1 < first->start) return true;
    for (size_t i = 0; i < pin->count; i++) {
        struct miner_signal_schedule s = *first;
        s.slot = (uint16_t)i;
        s.activation = pin->entries[i].activation;
        if (!miner_signal_begin(&s, s.start - 1, &snap->anchor_hash, &tallies[i]).ok)
            return false; // raw-return-ok:caller reports unavailable ballot history
    }
    for (size_t i = 0; i < snap->count; i++)
        if (!ballot_read_one(datadir, &snap->blocks[i], tallies, pin->count)) return false;
    return true;
}

static bool ballot_catalog_row(struct json_value *array,
                               const struct miner_signal_catalog_pin *pin, size_t i,
                               const struct ballot_snapshot *snap,
                               const struct miner_signal_tally *tally)
{
    const char *phase = "scheduled";
    if ((int64_t)snap->parent_height + 1 >= pin->start) {
        enum miner_signal_phase p;
        if (!miner_signal_phase_at(tally, snap->parent_height + 1, &p).ok ||
            !(phase = ballot_phase_name(p))) return false; // raw-return-ok:caller reports unavailable ballot history
    }
    char revision[65];
    zcl_hex_encode(pin->entries[i].rule_revision, 32, revision);
    struct json_value row = {0};
    json_set_object(&row);
    bool ok = json_push_kv_str(&row, "rule_revision", revision) &&
        json_push_kv_int(&row, "slot", (int64_t)i) &&
        json_push_kv_int(&row, "activation", pin->entries[i].activation) &&
        json_push_kv_int(&row, "votes", tally->votes) &&
        json_push_kv_str(&row, "phase_of_next_block", phase) &&
        json_push_back(array, &row);
    json_free(&row);
    return ok;
}

static bool ballot_catalog_reply(struct json_value *result,
                                 const struct miner_signal_catalog_pin *pin,
                                 const struct ballot_snapshot *snap,
                                 const struct miner_signal_tally *tallies,
                                 const char *network)
{
    char hash[65], digest[65];
    uint256_get_hex(&snap->parent_hash, hash);
    zcl_hex_encode(pin->digest, 32, digest);
    struct json_value rows = {0};
    json_set_array(&rows);
    bool ok = true;
    for (size_t i = 0; ok && i < pin->count; i++)
        ok = ballot_catalog_row(&rows, pin, i, snap, &tallies[i]);
    json_set_object(result);
    ok = ok && json_push_kv_str(result, "network", network) &&
        json_push_kv_str(result, "parent_basis", "durable_provable_tip") &&
        json_push_kv_str(result, "schedule_source", "pinned_catalog") &&
        json_push_kv_str(result, "catalog", digest) &&
        json_push_kv_int(result, "parent_height", snap->parent_height) &&
        json_push_kv_str(result, "parent_hash", hash) &&
        json_push_kv_int(result, "next_height", (int64_t)snap->parent_height + 1) &&
        json_push_kv_int(result, "start", pin->start) &&
        json_push_kv_int(result, "window", pin->window) &&
        json_push_kv(result, "proposals", &rows);
    json_free(&rows);
    return ok;
}

static bool ballot_catalog_status(const struct blockchain_context *ctx,
                                  const struct chain_params *cp, struct json_value *result)
{
    const struct miner_signal_catalog_pin *pin = ctx->ballot_catalog_pin;
    if (!pin) return ballot_fail(result, "No ballot catalog pinned at startup");
    struct miner_signal_schedule first = {0};
    if (pin->count == 0 || pin->count > 256 ||
        memcmp(pin->genesis, cp->consensus.hashGenesisBlock.data, 32) ||
        !miner_signal_catalog_pin_select(pin, 0, &first).ok)
        return ballot_fail(result, "Invalid pinned ballot catalog");
    struct ballot_snapshot snap = {0};
    snap.blocks = zcl_calloc((size_t)first.window, sizeof(*snap.blocks), "ballot status ancestry");
    struct miner_signal_tally *tallies = zcl_calloc(pin->count, sizeof(*tallies), "ballot tallies");
    if (!snap.blocks || !tallies) {
        free(snap.blocks); free(tallies);
        return ballot_fail(result, "Out of memory");
    }
    bool ok = ballot_snapshot_evidence(&first, &snap) &&
        ballot_snapshot_positions(ctx->main_state, &snap) &&
        ballot_snapshot_current(ctx->main_state, &snap) &&
        ballot_catalog_tallies(pin, &first, &snap, ctx->datadir, tallies) &&
        ballot_snapshot_current(ctx->main_state, &snap) && ballot_authority_current(&snap);
    if (ok) ok = ballot_catalog_reply(result, pin, &snap, tallies, cp->strNetworkID);
    if (!ok) ballot_fail(result, "Validated ballot history unavailable or chain changed; retry");
    free(tallies); free(snap.blocks);
    return ok;
}


static bool ballot_status_schedule(const struct json_value *params, const struct chain_params *cp,
                                   const struct blockchain_context *ctx,
                                   struct miner_signal_schedule *s, const char **source,
                                   struct json_value *result)
{
    size_t count = params && params->type == JSON_ARR ? json_size(params) : 0;
    if (count == 1) {
        if (!ballot_test_network(cp))
            return ballot_fail(result, "Pinned ballot status is available only on testnet and regtest");
        if (!ctx->ballot_catalog_pin)
            return ballot_fail(result, "No ballot catalog pinned at startup");
        const struct json_value *v = json_at(params, 0);
        if (!v || v->type != JSON_INT || json_get_int(v) < 0 || json_get_int(v) > 255)
            return ballot_fail(result, "Invalid pinned catalog slot");
        *source = "pinned_catalog";
        if (!miner_signal_catalog_pin_select(ctx->ballot_catalog_pin,
                                             (size_t)json_get_int(v), s).ok)
            return ballot_fail(result, "Slot unavailable in the pinned catalog");
        return true;
    }
    *source = count == 5 ? "supplied_catalog" : "raw_parameters";
    if (count == 5 ? ballot_parse_catalog(params, cp, s) : ballot_parse(params, s))
        return true;
    return ballot_fail(result, "Invalid integer schedule, slot, 32-byte catalog, or window exceeds 256");
}

bool rpc_getballotstatus(const struct json_value *params, bool help,
                         struct json_value *result)
{
    RPC_HELP(help, result,
        "getballotstatus [slot | fork_id_hex start window rules slot | start window activation slots slot catalog_hex]\n"
        "Read testnet ballot history at the durable provable tip. Each counted block requires full validation evidence. Maximum window 256 blocks.");
    const struct chain_params *cp = chain_params_get();
    struct miner_signal_schedule s = {0};
    const char *source;
    struct blockchain_context *ctx = blockchain_ctx();
    if (params && params->type == JSON_ARR && json_size(params) == 0) {
        if (!ballot_test_network(cp))
            return ballot_fail(result, "Pinned ballot status is available only on testnet and regtest");
        if (!ctx->ballot_catalog_pin)
            return ballot_fail(result, "No ballot catalog pinned at startup");
        if (!ctx->main_state || !ctx->datadir)
            return ballot_fail(result, "Chain state or block storage unavailable");
        return ballot_catalog_status(ctx, cp, result);
    }
    if (!ballot_status_schedule(params, cp, ctx, &s, &source, result))
        return false; // raw-return-ok:parameter helper populated the RPC error
    if (!ballot_test_network(cp))
        return ballot_fail(result, "Ballot status is available only on testnet and regtest");
    if (!ctx->main_state || !ctx->datadir)
        return ballot_fail(result, "Chain state or block storage unavailable");
    return ballot_status_snapshot(&s, cp, ctx, source, result);
}
