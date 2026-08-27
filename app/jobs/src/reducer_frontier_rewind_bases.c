/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * reducer_frontier_rewind_bases — rolling self-verified rewind-base
 * observability (Pillar 3 of the always-sync spine) AND the programmatic
 * nearest-self-verified base selector the generic recovery driver consumes.
 * Split out of reducer_frontier_dump.c to stay under the E1 file-size ceiling.
 *
 * A rewind base is only valid if it was SELF-DERIVED (folded from real block
 * bodies by THIS node, then cross-checked against its own commitment) — never
 * a borrowed value. Today three kinds exist:
 *
 *   - compiled_checkpoint: the baked SHA3 UTXO checkpoint
 *     (REDUCER_FRONTIER_TRUSTED_ANCHOR). self_derived=true — the self-mint
 *     producer (config/src/boot_mint_anchor.c) folds bodies from genesis and
 *     HARD-ASSERTS its own commitment equals this compiled value before ever
 *     accepting it, so the constant is a proven fold result, not a trusted
 *     literal.
 *   - sealed_coins_sha3: every self-valid slot in the seal_kv 4-slot ring
 *     (storage/seal_kv.h) — each coins_sha3 was computed by
 *     seal_candidate_emit_in_tx scanning THIS node's live, forward-folded
 *     coins_kv (app/services/src/seal_service.c). self_derived=true always;
 *     `ratified` marks whether it has additionally cleared the
 *     finality-depth + input-coverage + active-chain-agreement gates.
 *   - finalized_utxo_sha3: the node_state 'utxo_sha3' commitment
 *     (coins/utxo_commitment.h). self_derived=false — today this is written
 *     ONLY at snapshot-import (seed_integrity_stamp_utxo_sha3), never
 *     re-derived by ongoing forward fold, so it is a borrowed provenance
 *     marker, not yet a self-verified rung (see docs/HANDOFF.md and
 *     docs/work/self-verified-tip-plan.md).
 *
 * NEAREST-BASE SELECTION IS SELF-VERIFIED-FIRST, not height-first: a borrowed
 * finalized_utxo_sha3 can never win over a genuinely self-verified rung, even
 * when it sits at a higher height. See reducer_frontier_nearest_self_verified_
 * base — the borrowed root is last-resort only.
 *
 * READ-ONLY composition over each subsystem's own public dump/read API — no
 * new storage, no mutation, no lock ordering surprises (every call below
 * either takes no lock or acquires the RECURSIVE progress_store_tx_lock
 * itself, the same pattern reducer_frontier_log_frontier already relies on
 * from inside reducer_frontier_dump_state_json). */

#include "reducer_frontier_rewind_bases.h"

#include "jobs/reducer_frontier.h"

#include "chain/checkpoints.h"
#include "coins/utxo_commitment.h"
#include "config/runtime.h"
#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "models/database.h"
#include "storage/seal_kv.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Visitor invoked once per enumerated rewind base. `kind` is a static string
 * literal (safe to store by pointer); `commitment_hex` is transient (points
 * into a caller-owned scratch JSON value that is freed after enumeration), so a
 * visitor that keeps it must COPY. commitment_hex may be NULL/empty when no
 * commitment hash applies. */
typedef void (*rewind_base_visit_fn)(void *ctx, const char *kind,
                                     int32_t height, bool self_derived,
                                     bool ratified, const char *commitment_hex);

/* Enumerate every candidate rewind base once, in cheapest-to-derive order, via
 * `visit`. The single source of truth for WHICH bases exist — both the JSON
 * dump and the nearest-self-verified selector fold over this, so the two can
 * never disagree about the base set. */
static void enumerate_rewind_bases(rewind_base_visit_fn visit, void *ctx)
{
    /* 1) The compiled SHA3 UTXO checkpoint — always available, network gate
     * aside (get_sha3_utxo_checkpoint always returns the mainnet constant;
     * callers on non-mainnet networks already treat REDUCER_FRONTIER_
     * TRUSTED_ANCHOR as inapplicable, same as the other direct-macro call
     * sites in block_index_loader_rebuild.c / header_band_service.c). */
    const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
    int32_t compiled_height = cp ? cp->height : REDUCER_FRONTIER_TRUSTED_ANCHOR;
    char compiled_hex[65] = "";
    if (cp)
        HexStr(cp->sha3_hash, 32, false, compiled_hex, sizeof(compiled_hex));
    visit(ctx, "compiled_checkpoint", compiled_height, true, false,
          compiled_hex);

    /* 2) Every self-valid slot in the seal_kv ring. Reuses seal_kv's OWN
     * public dump (storage/seal_kv.h) rather than duplicating ring-iteration
     * logic here — seal_kv.c is a sibling lane's file. */
    struct json_value seal_state = {0};
    json_init(&seal_state);
    if (seal_kv_dump_state_json(&seal_state, NULL)) {
        const struct json_value *slots = json_get(&seal_state, "slots");
        size_t n = slots ? json_size(slots) : 0;
        for (size_t i = 0; i < n; i++) {
            const struct json_value *item = json_at(slots, i);
            if (!item)
                continue;
            if (!json_get_bool(json_get(item, "self_sha3_valid")))
                continue; /* torn/corrupt slot — not a valid rewind base */
            visit(ctx, "sealed_coins_sha3",
                  (int32_t)json_get_int(json_get(item, "height")), true,
                  json_get_bool(json_get(item, "ratified")),
                  json_get_str(json_get(item, "coins_sha3")));
        }
    }
    json_free(&seal_state);

    /* 3) The finalized 'utxo_sha3' node_state commitment, when a node_db is
     * wired and a stamp exists. Best-effort / optional: absent on a
     * from-genesis-only datadir that has never imported a snapshot. */
    struct node_db *ndb = app_runtime_node_db();
    if (ndb && ndb->open && ndb->db) {
        uint8_t hash[32];
        int32_t stamp_height = -1;
        uint64_t stamp_count = 0;
        if (utxo_commitment_sha3_load(ndb->db, hash, &stamp_height,
                                      &stamp_count) &&
            stamp_height >= 0) {
            char hex[65];
            HexStr(hash, 32, false, hex, sizeof(hex));
            visit(ctx, "finalized_utxo_sha3", stamp_height, false, false, hex);
        }
    }
}

/* ── JSON observability ─────────────────────────────────────────────────── */

struct json_dump_ctx {
    struct json_value *arr;
    int32_t hstar;

    /* Backward-compatible "nearest by height (any provenance)" tracker — the
     * legacy nearest_rewind_base_* keys. */
    int32_t nearest_height;
    const char *nearest_kind;
    bool nearest_self_derived;
    bool nearest_ratified;

    /* Sovereignty-correct "nearest SELF-VERIFIED base" tracker — the driver's
     * actual rewind target. self_derived=true only. */
    int32_t sv_height;
    const char *sv_kind;
    bool sv_ratified;
    char sv_commit[65];
};

static void json_dump_visit(void *vctx, const char *kind, int32_t height,
                            bool self_derived, bool ratified,
                            const char *commitment_hex)
{
    struct json_dump_ctx *c = (struct json_dump_ctx *)vctx;

    struct json_value o = {0};
    json_set_object(&o);
    json_push_kv_str(&o, "kind", kind);
    json_push_kv_int(&o, "height", height);
    json_push_kv_bool(&o, "self_derived", self_derived);
    json_push_kv_bool(&o, "ratified", ratified);
    json_push_kv_int(&o, "distance_from_tip", (int64_t)c->hstar - height);
    json_push_kv_str(&o, "commitment_sha3",
                     commitment_hex ? commitment_hex : "");
    json_push_back(c->arr, &o);
    json_free(&o);

    if (height > c->hstar)
        return; /* above the tip — not a rewind base for this H* */

    /* Legacy: nearest by height, any provenance. */
    if (c->nearest_height < 0 || height > c->nearest_height) {
        c->nearest_height = height;
        c->nearest_kind = kind;
        c->nearest_self_derived = self_derived;
        c->nearest_ratified = ratified;
    }

    /* Sovereignty: nearest among SELF-VERIFIED bases only. */
    if (self_derived && (c->sv_height < 0 || height > c->sv_height)) {
        c->sv_height = height;
        c->sv_kind = kind;
        c->sv_ratified = ratified;
        if (commitment_hex) {
            strncpy(c->sv_commit, commitment_hex, sizeof(c->sv_commit) - 1);
            c->sv_commit[sizeof(c->sv_commit) - 1] = '\0';
        } else {
            c->sv_commit[0] = '\0';
        }
    }
}

void reducer_frontier_push_rewind_bases_json(struct json_value *out,
                                             int32_t hstar)
{
    struct json_value bases = {0};
    json_set_array(&bases);

    struct json_dump_ctx c = {
        .arr = &bases,
        .hstar = hstar,
        .nearest_height = -1,
        .nearest_kind = "",
        .sv_height = -1,
        .sv_kind = "",
    };
    c.sv_commit[0] = '\0';

    enumerate_rewind_bases(json_dump_visit, &c);

    int64_t bases_count = (int64_t)json_size(&bases);
    json_push_kv(out, "rewind_bases", &bases);
    json_free(&bases);

    json_push_kv_int(out, "rewind_bases_count", bases_count);

    /* Legacy keys (nearest by height, any provenance) — UNCHANGED shape. */
    json_push_kv_str(out, "nearest_rewind_base_kind",
                     c.nearest_height >= 0 ? c.nearest_kind : "");
    json_push_kv_int(out, "nearest_rewind_base_height", c.nearest_height);
    json_push_kv_bool(out, "nearest_rewind_base_self_derived",
                      c.nearest_height >= 0 && c.nearest_self_derived);
    json_push_kv_bool(out, "nearest_rewind_base_ratified",
                      c.nearest_height >= 0 && c.nearest_ratified);
    json_push_kv_int(out, "nearest_rewind_distance",
                     c.nearest_height >= 0 ? (int64_t)hstar - c.nearest_height
                                           : -1);

    /* New keys: the SELF-VERIFIED nearest base — the sovereignty-correct rewind
     * target the recovery driver actually uses (borrowed roots excluded). Added
     * alongside the legacy keys; no existing key changes meaning. */
    json_push_kv_str(out, "nearest_self_verified_base_kind",
                     c.sv_height >= 0 ? c.sv_kind : "");
    json_push_kv_int(out, "nearest_self_verified_base_height", c.sv_height);
    json_push_kv_bool(out, "nearest_self_verified_base_ratified",
                      c.sv_height >= 0 && c.sv_ratified);
    json_push_kv_str(out, "nearest_self_verified_base_commitment_sha3",
                     c.sv_height >= 0 ? c.sv_commit : "");
    json_push_kv_int(out, "nearest_self_verified_distance",
                     c.sv_height >= 0 ? (int64_t)hstar - c.sv_height : -1);
}

/* ── Programmatic nearest-self-verified base selector ───────────────────── */

struct select_ctx {
    int32_t at_or_below;
    /* When false, the compiled SHA3 checkpoint (a proven HASH, not loadable
     * STATE) is EXCLUDED from candidacy — its verified snapshot artifact is
     * absent, so it cannot be rewound to. The struct selector leaves this true
     * (the checkpoint is always an O(delta) rewind height for stage_rederive_
     * range, which re-derives from on-disk bodies + the intact delta chain);
     * the gated wrapper passes the real artifact availability. */
    bool compiled_checkpoint_loadable;
    struct reducer_frontier_rewind_base sv;       /* best self_derived=true */
    struct reducer_frontier_rewind_base borrowed; /* best self_derived=false */
    bool have_sv;
    bool have_borrowed;
};

static void select_copy(struct reducer_frontier_rewind_base *dst,
                        const char *kind, int32_t height, bool self_derived,
                        bool ratified, const char *commitment_hex)
{
    dst->height = height;
    dst->self_derived = self_derived;
    dst->ratified = ratified;
    strncpy(dst->kind, kind ? kind : "", sizeof(dst->kind) - 1);
    dst->kind[sizeof(dst->kind) - 1] = '\0';
    if (commitment_hex) {
        size_t commitment_len = strnlen(
            commitment_hex, sizeof(dst->commitment_sha3) - 1);
        memcpy(dst->commitment_sha3, commitment_hex, commitment_len);
        dst->commitment_sha3[commitment_len] = '\0';
    } else {
        dst->commitment_sha3[0] = '\0';
    }
}

static void select_visit(void *vctx, const char *kind, int32_t height,
                         bool self_derived, bool ratified,
                         const char *commitment_hex)
{
    struct select_ctx *c = (struct select_ctx *)vctx;
    if (height > c->at_or_below)
        return; /* above the requested ceiling — not a candidate */

    /* Gate the compiled SHA3 checkpoint on artifact loadability: absent its
     * verified snapshot the checkpoint is a proven hash with no materializable
     * state, so a gated caller must not treat it as a reachable rewind base. */
    if (!c->compiled_checkpoint_loadable &&
        strcmp(kind, "compiled_checkpoint") == 0)
        return;

    if (self_derived) {
        if (!c->have_sv || height > c->sv.height) {
            select_copy(&c->sv, kind, height, self_derived, ratified,
                        commitment_hex);
            c->have_sv = true;
        }
    } else {
        if (!c->have_borrowed || height > c->borrowed.height) {
            select_copy(&c->borrowed, kind, height, self_derived, ratified,
                        commitment_hex);
            c->have_borrowed = true;
        }
    }
}

bool reducer_frontier_nearest_self_verified_base(
    int32_t at_or_below, struct reducer_frontier_rewind_base *out)
{
    if (!out)
        return false; // raw-return-ok:null-out-arg
    memset(out, 0, sizeof(*out));

    struct select_ctx c = {0};
    c.at_or_below = at_or_below;
    /* This selector treats the compiled checkpoint as an always-usable O(delta)
     * rewind HEIGHT: its consumer (stage_rederive_range) re-derives from on-disk
     * bodies + the intact delta chain and never loads the snapshot artifact, so
     * artifact availability is not this selector's concern. Recovery rungs that
     * must RELOAD checkpoint state use the _loadable_ variant below. */
    c.compiled_checkpoint_loadable = true;
    enumerate_rewind_bases(select_visit, &c);

    /* SELF-VERIFIED FIRST: a genuinely self-verified rung always beats a
     * borrowed root, regardless of height. The borrowed finalized_utxo_sha3 is
     * returned only when NO self-verified base exists at or below the ceiling. */
    if (c.have_sv) {
        *out = c.sv;
        return true;
    }
    if (c.have_borrowed) {
        *out = c.borrowed;
        return true;
    }
    return false; // raw-return-ok:no-base-at-or-below-ceiling
}

bool reducer_frontier_nearest_loadable_self_verified_base(
    int32_t at_or_below, bool compiled_checkpoint_loadable,
    int32_t *base_height_out, const char **base_kind_out)
{
    if (base_height_out)
        *base_height_out = -1;
    if (base_kind_out)
        *base_kind_out = "none";

    struct select_ctx c = {0};
    c.at_or_below = at_or_below;
    c.compiled_checkpoint_loadable = compiled_checkpoint_loadable;
    enumerate_rewind_bases(select_visit, &c);

    /* Self-verified ONLY (borrowed roots are never a recovery-rung base) and
     * FAIL-CLOSED: no self-verified base -> false, so a genuinely absent verified
     * base surfaces as a real blocker upstream rather than a faked success. */
    if (!c.have_sv)
        return false; // raw-return-ok:fail-closed-no-self-verified-base
    if (base_height_out)
        *base_height_out = c.sv.height;
    if (base_kind_out)
        /* Map to a static literal (c.sv.kind is stack-local and dies with this
         * frame). Only these two self_derived kinds reach here. */
        *base_kind_out = strcmp(c.sv.kind, "compiled_checkpoint") == 0
                             ? "compiled_checkpoint"
                             : "sealed_coins_sha3";
    return true;
}
