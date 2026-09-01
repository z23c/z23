/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * property_adapter — the one interface a property kind implements so the
 * catalog can project it. One row per kind, dispatched centrally, exactly
 * the shape engine/services/vault_read.c uses for asset classes and
 * engine/controllers/diagnostics_dumpers.def uses for state dumpers.
 *
 * THE CONTRACT, and the whole reason this file is small: an adapter is a
 * READER. It calls the authoritative subsystem's existing read API and
 * fills a view. It may not write, may not open a handle that mutates the
 * datadir, may not cache between calls, and may not hold state of its own.
 * There is no put/update/transfer hook here on purpose — mutation belongs
 * to the capability engine and to the authority that already owns it.
 *
 * READ MEANS READ. Several node stores mutate on OPEN (a recovery sweep, a
 * staging commit, an orphan GC). An adapter must reach the same bytes by a
 * path that does not, because `metaverse property list` is a read command
 * and a read command that rewrites the operator's datadir is the defect
 * this project has already been bitten by. Adapters therefore take a
 * directory, not a store handle.
 *
 * A kind with no reader yet is still a ROW, carrying
 * `unavailable_reason`. The catalog emits it as an explicit unavailable
 * entry rather than dropping it — a kind that silently vanished from the
 * catalog is indistinguishable from a kind that owns nothing.
 */

#ifndef ZCL_METAVERSE_PROPERTY_ADAPTER_H
#define ZCL_METAVERSE_PROPERTY_ADAPTER_H

#include "metaverse/property_id.h"
#include "metaverse/property_view.h"
#include "metaverse/property_work.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Database-neutral ZNAM facts.  The application layer fills these through
 * the canonical db_znam_* model; contexts/commons/modules/metaverse never sees sqlite or a
 * node_db handle.  The registration transaction is the name's immutable
 * root (property_id.h), while last_update_txid identifies its current
 * descriptor without inventing a numeric revision. */
#define METAVERSE_ZNAM_NAME_MAX 64u
#define METAVERSE_ZNAM_OWNER_MAX 128u
struct metaverse_znam_record {
    char name[METAVERSE_ZNAM_NAME_MAX];
    char owner[METAVERSE_ZNAM_OWNER_MAX];
    uint8_t registration_root[METAVERSE_ROOT_BYTES];
    uint8_t last_update_root[METAVERSE_ROOT_BYTES];
    int64_t registration_height;
    int64_t expiry_height;
};

enum metaverse_source_lookup {
    METAVERSE_SOURCE_ERROR = -1,
    METAVERSE_SOURCE_ABSENT = 0,
    METAVERSE_SOURCE_FOUND = 1,
};

/* A read source supplied by the application layer.  `list` is an atomic
 * answer in the logical sense: true means written/total/truncated are all
 * trustworthy; false means the adapter must emit an honest gap. */
struct metaverse_znam_source {
    void *opaque;
    enum metaverse_source_lookup (*find_registration)(
        void *opaque, const uint8_t registration_root[METAVERSE_ROOT_BYTES],
        struct metaverse_znam_record *out);
    bool (*list)(void *opaque, struct metaverse_znam_record *out,
                 size_t out_cap, size_t *written_out, size_t *total_out,
                 bool *truncated_out);
    const char *unavailable_reason;
};

/* Database-neutral ZSLP GENESIS facts.  Fungible asset definitions do not
 * have one owner: the current model does not index the mint baton and token
 * holders own quantities, not the definition itself.  No owner field is
 * present here so the adapter cannot accidentally promote the genesis
 * recipient into a perpetual controller. */
#define METAVERSE_ZSLP_TICKER_MAX 33u
#define METAVERSE_ZSLP_NAME_MAX 65u
struct metaverse_zslp_record {
    uint8_t genesis_root[METAVERSE_ROOT_BYTES];
    char ticker[METAVERSE_ZSLP_TICKER_MAX];
    char name[METAVERSE_ZSLP_NAME_MAX];
    int64_t genesis_height;
    int decimals;
    int64_t total_minted;
};

struct metaverse_zslp_source {
    void *opaque;
    enum metaverse_source_lookup (*find_genesis)(
        void *opaque, const uint8_t genesis_root[METAVERSE_ROOT_BYTES],
        struct metaverse_zslp_record *out);
    bool (*list)(void *opaque, struct metaverse_zslp_record *out,
                 size_t out_cap, size_t *written_out, size_t *total_out,
                 bool *truncated_out);
    const char *unavailable_reason;
};

/* Everything an adapter is allowed to know about where to read from.
 * Deliberately a directory + a tip, never an open store handle: see
 * "READ MEANS READ" above. */
struct metaverse_adapter_ctx {
    const char *datadir;   /* datadir root; never NULL */
    const char *zcode_dir; /* "<datadir>/zcode"; never NULL */

    /* Chain height for chain-anchored kinds, or -1 when unknown. An
     * adapter over a non-chain authority MUST ignore this: stamping a tip
     * height onto a claim the tip does not commit is a false freshness
     * claim. */
    int64_t chain_height;

    /* The tip's ACCUMULATED WORK, straight from the block index
     * (`bi->nChainWork`), or NULL when unknown. Paired with chain_height
     * and only meaningful together: a proof-of-work-settled adapter passes
     * both, along with its record's anchor height and that block's
     * nChainWork, to metaverse_work_measure(). Nothing here recomputes
     * work — the block index already tracks it per block, and a second
     * derivation would be a second truth.
     *
     * NULL here is not zero work. metaverse_work_measure() leaves the
     * chainwork field explicitly unknown rather than reporting 0, for the
     * same reason chain_height is -1 and not 0. */
    const struct arith_uint256 *chain_work;

    /* Optional canonical-model readers.  NULL means the caller has no safe
     * read path for that authority right now; store_ready reports that as a
     * named unavailability, never as an empty inventory. */
    const struct metaverse_znam_source *znam;
    const struct metaverse_zslp_source *zslp;
};

/* Fill `out` for exactly this id. Returns true when a view was written
 * (determined OR an honest gap — both are answers); false only when the
 * adapter could not even begin (NULL args, wrong kind). A view for an id
 * the authority does not hold is status = ABSENT and determined = true. */
typedef bool (*metaverse_adapter_show_fn)(
    const struct metaverse_adapter_ctx *ctx,
    const struct metaverse_property_id *id,
    struct metaverse_property_view *out);

/* Enumeration has two independent completeness axes: page truncation and
 * source integrity. A corrupt record that was skipped is not pagination and
 * must not disappear behind a plausible total. */
#define METAVERSE_LIST_INTEGRITY_REASON_MAX 192u
struct metaverse_adapter_list_report {
    size_t total;
    bool truncated;
    bool integrity_ok;
    size_t integrity_gap_count;
    char integrity_reason[METAVERSE_LIST_INTEGRITY_REASON_MAX];
};

/* Enumerate this kind's properties into out[0..out_cap). Returns the rows
 * written. report->total receives the TOTAL this kind holds, which may
 * exceed the rows written; report->truncated says the page is partial.
 * report->integrity_ok is false when records could not be read or rendered,
 * with a bounded count and first precise reason — never a silent omission.
 *
 * out_cap == 0 is a legal COUNT-ONLY call: no view is written, and
 * report->total is still the real total. The catalog uses it once its page is
 * full, because "the page filled up" must not silently become "the node
 * owns exactly this many". */
typedef size_t (*metaverse_adapter_list_fn)(
    const struct metaverse_adapter_ctx *ctx,
    struct metaverse_property_view *out, size_t out_cap,
    struct metaverse_adapter_list_report *report);

/* Is this kind's authority READABLE from `ctx` right now, as opposed to
 * merely holding nothing? Optional; NULL means the question cannot arise
 * for this kind.
 *
 * It exists because `list` returns a count and `show` returns "absent",
 * and both of those answers are indistinguishable from "the store is
 * there and could not be opened". An operator told "you own nothing" over
 * a store that threw EACCES has been misinformed, and this project has
 * already paid for exactly that conflation once, on node.db. A row that
 * reads anything unlockable declares this hook; the catalog calls it
 * BEFORE list/show and turns a false into a stated unavailability, never
 * into an empty result. `reason` (never NULL, `reason_cap` > 0) receives
 * the operator-facing explanation on false. */
typedef bool (*metaverse_adapter_ready_fn)(
    const struct metaverse_adapter_ctx *ctx, char *reason,
    size_t reason_cap);

struct metaverse_adapter {
    enum metaverse_kind kind;
    /* NULL when this kind has a reader. Non-NULL names precisely why it
     * does not yet, and `list`/`show` are then NULL. */
    const char *unavailable_reason;
    metaverse_adapter_list_fn list;
    metaverse_adapter_show_fn show;
    /* Optional; see metaverse_adapter_ready_fn. */
    metaverse_adapter_ready_fn store_ready;
};

/* The registry. Exactly one row per kind in METAVERSE_KIND_TABLE order;
 * static_assert'd against METAVERSE_KIND_COUNT in adapter_registry.c. */
size_t metaverse_adapter_count(void);
const struct metaverse_adapter *metaverse_adapter_at(size_t i);
/* NULL only for an invalid kind — a valid kind always has a row, even if
 * that row is an unavailable one. */
const struct metaverse_adapter *metaverse_adapter_for(enum metaverse_kind k);

/* True when the row has a reader wired. */
bool metaverse_adapter_ready(const struct metaverse_adapter *adapter);

#endif /* ZCL_METAVERSE_PROPERTY_ADAPTER_H */
