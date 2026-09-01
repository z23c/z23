/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * replay_verify_service — implementation. See services/replay_verify_service.h.
 *
 * Offline integrity / PoW verification sweep over the legacy on-disk block
 * log. Opens the read-only block_log_legacy adapter and walks blocks in
 * active-chain order via block_log_port.iter_from, re-deriving four cheap
 * consensus invariants per block:
 *
 *   1. Equihash solution (height-selected N,K) ─┐
 *   2. difficulty target (nBits)                ├─ delegated to check_block
 *   4. merkle root vs transactions             ┘  (check_pow=1,
 *                                                  check_merkle_root=1)
 *   3. prev-block linkage  ── computed here over the iteration order
 *
 * The crypto is reused, never reimplemented (DEFENSIVE_CODING: do not
 * reinvent consensus primitives). The sweep is read-only and emits a single
 * artifact-style summary line at the end.
 */

#include "services/replay_verify_service.h"

#include "adapters/outbound/persistence/block_log_legacy.h"
#include "ports/block_log_port.h"

#include "chain/chainparams.h"
#include "consensus/validation.h"
#include "core/serialize.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "validation/check_block.h"

#include "util/log_json.h"
#include "util/log_macros.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* State threaded through the block_log iteration callback. */
struct sweep_state {
    struct replay_verify_report *report;
    const struct chain_params   *params;

    bool                         have_prev;      /* prev_hash valid yet?      */
    struct block_hash            prev_hash;      /* hash of last good block   */

    uint64_t                     max_blocks;     /* 0 == unbounded            */
    bool                         deser_failed;   /* operational stop signal   */
    uint32_t                     deser_height;   /* height that failed parse  */
};

/* Record the first observed failure (any class) into the report. Static
 * reason strings only — the report holds a borrowed pointer. */
static void note_first_fail(struct replay_verify_report *r,
                            uint32_t height, const char *reason)
{
    if (r->first_fail_height < 0) {
        r->first_fail_height = (int64_t)height;
        r->first_fail_reason = reason;
    }
}

/* iter_from callback: one block, in active-chain order. Returns true to
 * keep iterating, false to stop. A consensus-level failure does NOT stop
 * the sweep (we want full counts); only an operational parse failure or
 * hitting max_blocks stops it. */
static bool sweep_cb(uint32_t height,
                     const struct block_hash *hash,
                     const uint8_t *bytes,
                     size_t len,
                     void *user_data)
{
    struct sweep_state *st = user_data;
    struct replay_verify_report *r = st->report;

    /* Deserialize the persisted block bytes. A parse failure is an
     * operational error (corrupt/truncated storage), not a consensus
     * verdict — stop the sweep and surface it as a non-OK run result. */
    struct block blk;
    block_init(&blk);

    struct byte_stream s;
    stream_init_from_data(&s, bytes, len);
    bool parsed = block_deserialize(&blk, &s);
    stream_free(&s);

    if (!parsed) {
        block_free(&blk);
        st->deser_failed = true;
        st->deser_height = height;
        return false; /* stop iteration */
    }

    /* (1) equihash solution, (2) difficulty target, (4) merkle root —
     * all via the canonical consensus helper. check_size_limits is left
     * off: we are proving PoW + integrity, not contextual block policy. */
    struct validation_state vstate;
    validation_state_init(&vstate);
    bool block_ok = check_block(&blk, &vstate, st->params,
                                /*check_pow=*/true,
                                /*check_merkle_root=*/true,
                                /*check_size_limits=*/false);

    if (!block_ok) {
        /* check_block folds PoW (equihash + high-hash) and merkle into one
         * verdict. Attribute the failure to the right counter via the
         * reject reason it set. "bad-txnmrklroot" / "bad-txns-duplicate"
         * are merkle; everything else under check_pow ("invalid-solution",
         * "high-hash") is PoW. */
        const char *why = vstate.reject_reason;
        if (strcmp(why, "bad-txnmrklroot") == 0 ||
            strcmp(why, "bad-txns-duplicate") == 0) {
            r->merkle_failures++;
            note_first_fail(r, height, "merkle");
        } else {
            r->pow_failures++;
            note_first_fail(r, height, "pow");
        }
    }

    /* (3) prev-block linkage: each block's hashPrevBlock must equal the
     * hash of the block iterated immediately before it. The genesis block
     * (first block seen) has no predecessor in the window, so it is
     * exempt. uint256 and block_hash are both 32-byte LE; compare raw. */
    if (st->have_prev) {
        if (memcmp(blk.header.hashPrevBlock.data,
                   st->prev_hash.bytes, 32) != 0) {
            r->linkage_failures++;
            note_first_fail(r, height, "linkage");
        }
    }

    /* Advance the linkage cursor to this block's canonical hash. The
     * adapter already computed it; trust the port-supplied hash. */
    memcpy(st->prev_hash.bytes, hash->bytes, 32);
    st->have_prev = true;

    r->blocks_checked++;
    block_free(&blk);

    /* Honour the bounded-run cap. */
    if (st->max_blocks != 0 && r->blocks_checked >= st->max_blocks)
        return false;

    return true;
}

struct zcl_result replay_verify_run_port(struct block_log_port *port,
                                         uint32_t start_height,
                                         uint64_t max_blocks,
                                         struct replay_verify_report *out)
{
    if (!port || !port->iter_from || !port->tip_height)
        return ZCL_ERR(-1, "replay_verify_run_port: port is NULL/incomplete");
    if (!out)
        return ZCL_ERR(-1, "replay_verify_run_port: out report is NULL");

    /* Zero the report and mark "no failure yet". */
    memset(out, 0, sizeof *out);
    out->first_fail_height = -1;
    out->first_fail_reason = NULL;
    out->start_height      = start_height;

    const struct chain_params *params = chain_params_get();
    if (!params)
        return ZCL_ERR(-2, "replay_verify_run_port: chain params not selected");

    uint32_t tip = port->tip_height(port->self);
    out->tip_height = tip;

    if (tip == UINT32_MAX)
        return ZCL_ERR(-4, "replay_verify_run_port: block log is empty");
    if (start_height > tip)
        return ZCL_ERR(-5,
                   "replay_verify_run_port: start_height %u beyond tip %u",
                   start_height, tip);

    /* Derive the intended end height for the report (informational; the
     * callback enforces max_blocks as the hard stop). */
    if (max_blocks == 0) {
        out->end_height = tip;
    } else {
        uint64_t end = (uint64_t)start_height + max_blocks - 1;
        out->end_height = (end > tip) ? tip : (uint32_t)end;
    }

    struct sweep_state st = {
        .report       = out,
        .params       = params,
        .have_prev    = false,
        .max_blocks   = max_blocks,
        .deser_failed = false,
        .deser_height = 0,
    };

    struct zcl_result ri = port->iter_from(port->self, start_height,
                                           sweep_cb, &st);

    if (!ri.ok) {
        LOG_RETURN(ZCL_ERR(-6,
                       "replay_verify_run_port: iter_from(start=%u) failed: "
                       "code=%d %s",
                       start_height, ri.code, ri.message),
                   "replay_verify",
                   "iter_failed start_height=%u code=%d",
                   start_height, ri.code);
    }

    if (st.deser_failed) {
        return ZCL_ERR(-7,
                   "replay_verify_run_port: block deserialize failed at "
                   "height %u (corrupt/truncated storage)",
                   st.deser_height);
    }

    return ZCL_OK;
}

struct zcl_result replay_verify_run(const char *datadir,
                                    uint32_t start_height,
                                    uint64_t max_blocks,
                                    struct replay_verify_report *out)
{
    if (!datadir || !datadir[0])
        return ZCL_ERR(-1, "replay_verify_run: datadir is NULL/empty");
    if (!out)
        return ZCL_ERR(-1, "replay_verify_run: out report is NULL");

    /* Open the read-only legacy block log. */
    struct block_log_legacy *h = NULL;
    struct block_log_port    port = {0};
    struct zcl_result ro = block_log_legacy_open(datadir, &h, &port);
    if (!ro.ok) {
        /* Mirror the open failure into the report so callers that only
         * inspect the report (not the result) still see a sane shape. */
        memset(out, 0, sizeof *out);
        out->first_fail_height = -1;
        out->start_height      = start_height;
        LOG_RETURN(ZCL_ERR(-3,
                       "replay_verify_run: block_log_legacy_open(%s) "
                       "failed: code=%d %s",
                       datadir, ro.code, ro.message),
                   "replay_verify",
                   "open_failed datadir=%s code=%d", datadir, ro.code);
    }

    /* Delegate the whole sweep to the port-driven core. This keeps the
     * canonical consensus logic in exactly one place (sweep_cb +
     * check_block), reusable over ANY block_log_port — including the
     * writable block_log_file fixture the CI teeth test drives. */
    struct zcl_result r = replay_verify_run_port(&port, start_height,
                                                 max_blocks, out);

    block_log_legacy_close(h);

    if (!r.ok)
        return r;

    /* One-line artifact-style summary. fields_fmt is a JSON fragment;
     * the datadir path is JSON-escaped before interpolation. */
    char dd_esc[1100];
    log_json_escape(dd_esc, sizeof dd_esc, datadir);
    log_jsonf(out->first_fail_reason ? LOG_JSON_WARN : LOG_JSON_INFO,
              "replay_verify.summary",
              "\"datadir\":\"%s\","
              "\"start_height\":%u,"
              "\"end_height\":%u,"
              "\"tip_height\":%u,"
              "\"blocks_checked\":%llu,"
              "\"pow_failures\":%llu,"
              "\"linkage_failures\":%llu,"
              "\"merkle_failures\":%llu,"
              "\"first_fail_height\":%lld,"
              "\"first_fail_reason\":\"%s\"",
              dd_esc,
              out->start_height,
              out->end_height,
              out->tip_height,
              (unsigned long long)out->blocks_checked,
              (unsigned long long)out->pow_failures,
              (unsigned long long)out->linkage_failures,
              (unsigned long long)out->merkle_failures,
              (long long)out->first_fail_height,
              out->first_fail_reason ? out->first_fail_reason : "none");

    return ZCL_OK;
}
