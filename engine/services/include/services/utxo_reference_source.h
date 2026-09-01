/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * utxo_reference_source — the pluggable reference-commitment abstraction.
 *
 * The parity service diffs the LOCAL SHA3 UTXO commitment against a
 * REFERENCE commitment obtained through this fn-ptr vtable. Decoupling the
 * reference behind a vtable keeps the comparison algebra (utxo_audit_*)
 * single-sourced while letting the reference be a deterministic fixture
 * (unit tests, no sockets), a co-located zclassicd over JSON-RPC (coarse —
 * height-only), or a future peer/snapshot source (exact — byte-comparable).
 *
 * The `exact` flag is LOAD-BEARING and consensus-relevant:
 *   - exact=true  → commitment_at fills a byte-comparable 64-hex SHA3, so a
 *                   strcmp MATCH/DRIFT is meaningful. A DRIFT here pages.
 *   - exact=false → COARSE. The source cannot prove the UTXO-set bytes
 *                   (e.g. zclassicd has no zclassic23-format commitment). It
 *                   only attests height/count. The comparator NEVER declares
 *                   DRIFT on a coarse source, so it can never false-page.
 *
 * Same-height contract (resolves the apples-to-apples hazard): the local
 * commitment is computed over the LIVE utxos table, which reflects the set
 * as of the live applied-coins height. There is no historical "as-of height"
 * variant of the local commitment. commitment_at therefore MUST return the
 * reference commitment as of the SAME applied height the caller passes in,
 * and report *ref_height back. The comparator declares DRIFT only when the
 * source is exact AND *ref_height equals the local applied height; any height
 * skew is recorded as a non-paging mismatch-of-height, never a byte DRIFT.
 */

#ifndef ZCL_SERVICES_UTXO_REFERENCE_SOURCE_H
#define ZCL_SERVICES_UTXO_REFERENCE_SOURCE_H

#include "util/result.h"

#include <stdbool.h>
#include <stdint.h>

/* RPC transport config for the production zclassicd reference. Defined here
 * (not just forward-declared) because utxo_parity_config embeds it by value;
 * a by-value member needs the full definition. */
struct utxo_parity_rpc_config {
    char host[64];      /* default "127.0.0.1" when empty */
    int  port;          /* default 8232 when 0 */
    char user[64];      /* read from ~/.zclassic/zclassic.conf when empty */
    char password[128]; /* read from ~/.zclassic/zclassic.conf when empty */
};

/* The pluggable reference. The owner of `self` outlives the source. */
struct utxo_reference_source {
    const char *name;   /* short label copied into utxo_audit_result.source */
    bool        exact;  /* see header doc — gates whether a byte DRIFT pages */

    /* Fill `ref_sha3` (lowercase 64-hex, or "" for a coarse source) and
     * `*ref_height` for the given local applied `height`. Return ZCL_OK on
     * success; ZCL_ERR on unreachable/parse-fail (caller treats as a
     * reference error: increments ref_errors, never flags DRIFT). */
    struct zcl_result (*commitment_at)(void *self, int32_t height,
                                       char ref_sha3[65], int32_t *ref_height);
    void *self;
};

/* ── Fixture reference (unit tests, in-process smoke) ──────────────── */

/* Caller-owned backing store the fixture vtable points `self` at. */
struct utxo_reference_source_fixture {
    char    ref_hex[65];
    int32_t ref_height;
};

/* Initialize a fixture source. `fx` is caller-owned and must outlive `src`.
 * exact=true: `ref_hex` is a byte-comparable 64-hex SHA3. exact=false: a
 * coarse fixture (pass ref_hex="" — the comparator asserts height only). */
void utxo_reference_source_fixture_init(struct utxo_reference_source *src,
                                        struct utxo_reference_source_fixture *fx,
                                        const char *name,
                                        const char *ref_hex,
                                        int32_t ref_height,
                                        bool exact);

/* ── zclassicd-RPC reference (production COARSE — height-only) ──────── */

/* Caller-owned backing store for the zclassicd vtable. */
struct utxo_reference_source_zclassicd {
    struct utxo_parity_rpc_config rpc;
};

/* Initialize a zclassicd (coarse) source over `cfg`. `z` is caller-owned and
 * must outlive `src`. Credentials are resolved from cfg or, when absent, from
 * ~/.zclassic/zclassic.conf; returns ZCL_ERR when none are available so the
 * caller can keep the source dormant. exact is always false (gettxoutsetinfo
 * cannot return a zclassic23-format SHA3). */
struct zcl_result utxo_reference_source_zclassicd_init(
    struct utxo_reference_source *src,
    struct utxo_reference_source_zclassicd *z,
    const struct utxo_parity_rpc_config *cfg);

#endif /* ZCL_SERVICES_UTXO_REFERENCE_SOURCE_H */
