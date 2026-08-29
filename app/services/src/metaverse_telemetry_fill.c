// one-result-type-ok:telemetry-fill-provider — a telemetry provider's failure
// reason does not travel in its return value, it travels in the SNAPSHOT: each
// leaf carries its own presence plus a static reason token, which is strictly
// more information than one struct zcl_result per call could hold (this file
// can, and does, report "kinds_readable is fine, reader_znam_name could not be
// resolved" in the same answer). The bool is reserved for the one thing that
// is not a per-leaf fact — a NULL snapshot — and the signature itself is fixed
// by the frozen render contract (util/telemetry_render.h) and by the
// `*_dump_state_fill` shape tools/scripts/check_dumper_never_blocks.sh scans.
/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * See services/metaverse_telemetry.h. The provider for the `metaverse`
 * telemetry domain: it fills a typed snapshot and nothing else — it writes no
 * JSON, decides no health, and keeps no state between calls.
 *
 * IT TAKES NO PATH, AND THAT IS THE DESIGN. Every other value this domain
 * could carry (how many properties are held, what a broker recorded) lives in
 * a DIRECTORY, and a collector that picked one would either have to be handed
 * it by the caller on every call or default it — and defaulting it means
 * reading the operator's live node, which this repository has already been
 * bitten by. So this collector reads only what is compiled in: the property
 * kind vocabulary and its adapter rows. Inventory stays where the caller can
 * name its subject: `metaverse property list --datadir=<dir>`.
 *
 * NEVER BLOCKS. Every accessor below resolves against static const data
 * (lib/metaverse/src/adapter_registry.c) — no lock, no allocation, no syscall,
 * and a loop bounded by METAVERSE_KIND_COUNT. Reentrant and safe before boot,
 * which is exactly when an operator asks why the catalog is empty.
 */

#include "services/metaverse_telemetry.h"

#include "metaverse/property_adapter.h"
#include "metaverse/property_id.h"
#include "util/log_macros.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One reader flag per element of METAVERSE_KIND_TABLE. The count is asserted
 * so that adding a kind to the vocabulary without adding its TL_LEAF row and
 * the line below is a BUILD failure — a per-kind flag that quietly stopped
 * being emitted is the same silent-omission defect the adapter registry's own
 * static_assert exists to prevent, one layer up. */
static_assert((int)METAVERSE_KIND_COUNT == 10,
              "a property kind was added or removed: add (or drop) its "
              "reader_<kind> TL_LEAF row in util/telemetry/metaverse_fields.def "
              "and its MV_SET_READER line below, then update this count");

/* A row that cannot be resolved is UNAVAILABLE with a static token, never a
 * `false`: "this kind has no reader" and "this kind has no row at all" are
 * different facts, and the second one is a defect the operator must see. */
#define MV_SET_READER(snap_, member_, kind_)                                  \
    do {                                                                      \
        const struct metaverse_adapter *a_ = metaverse_adapter_for(kind_);    \
        if (a_ && a_->kind == (kind_)) {                                      \
            TELEMETRY_SET_BOOL((snap_), member_,                              \
                               metaverse_adapter_ready(a_),                   \
                               TELEMETRY_SRC_IN_PROCESS);                     \
        } else {                                                              \
            TELEMETRY_UNAVAILABLE_LEAF((snap_), member_,                      \
                                       "adapter_row_unresolved");             \
        }                                                                     \
    } while (0)

bool metaverse_dump_state_fill(struct metaverse_snapshot *snap)
{
    if (!snap)
        LOG_FAIL("metaverse_telemetry", "fill: snapshot is NULL");

    /* The clock can legitimately be unarmed this early. Reporting 0 would be a
     * plausible timestamp for 1970; reporting UNAVAILABLE is the truth. */
    int64_t now = telemetry_now_unix();
    if (now >= 0)
        TELEMETRY_SET_I64(snap, collected_unix, now, TELEMETRY_SRC_IN_PROCESS);
    else
        TELEMETRY_UNAVAILABLE_LEAF(snap, collected_unix,
                                   "wall_clock_unavailable");

    /* One pass over the registry. `complete` is false the moment a kind fails
     * to resolve to a row keyed to itself, which is the only way a kind can
     * disappear from the catalog without the catalog saying so. */
    size_t rows = metaverse_adapter_count();
    int64_t readable = 0;
    int64_t unreadable = 0;
    bool complete = true;
    for (size_t i = 0; i < rows; i++) {
        /* Row i is kind i+1; UNKNOWN (0) owns no row. */
        enum metaverse_kind kind = (enum metaverse_kind)(i + 1u);
        const struct metaverse_adapter *adapter = metaverse_adapter_for(kind);
        if (!adapter || adapter->kind != kind) {
            complete = false;
            continue;
        }
        if (metaverse_adapter_ready(adapter))
            readable++;
        else
            unreadable++;
    }

    TELEMETRY_SET_I64(snap, kinds_declared, (int64_t)rows,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(snap, kinds_readable, readable,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(snap, kinds_unreadable, unreadable,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_BOOL(snap, registry_complete, complete,
                       TELEMETRY_SRC_IN_PROCESS);

    MV_SET_READER(snap, reader_content, METAVERSE_KIND_CONTENT);
    MV_SET_READER(snap, reader_zcode_package, METAVERSE_KIND_ZCODE_PACKAGE);
    MV_SET_READER(snap, reader_znam_name, METAVERSE_KIND_ZNAM_NAME);
    MV_SET_READER(snap, reader_zslp_asset, METAVERSE_KIND_ZSLP_ASSET);
    MV_SET_READER(snap, reader_hosted_service, METAVERSE_KIND_HOSTED_SERVICE);
    MV_SET_READER(snap, reader_endpoint_onion, METAVERSE_KIND_ENDPOINT_ONION);
    MV_SET_READER(snap, reader_storefront_product,
                  METAVERSE_KIND_STOREFRONT_PRODUCT);
    MV_SET_READER(snap, reader_contract_swap, METAVERSE_KIND_CONTRACT_SWAP);
    MV_SET_READER(snap, reader_character_sheet, METAVERSE_KIND_CHARACTER_SHEET);

    return true;
}
