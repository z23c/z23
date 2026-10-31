/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Single-pass block-index scan helpers: the per-entry visitor that clears
 * BLOCK_FAILED and tracks the best header, restore fallback, reindex target
 * and body coverage. Moved unchanged out of engine/composition/src/boot.c to
 * keep that file under the size cap; boot_step_scan_block_index stays there. */
#include "config/boot_internal.h"
#include "boot_block_index_scan_internal.h"

/* Track the most-work header, with a height tiebreak when either side's work
 * is zero (a rebuild-from-blocks data gap must not silently cap best_header —
 * same rule as promote_best_header_after_load). */
static void boot_scan_track_best_header(struct boot_index_scan *scan,
                                        struct block_index *sp)
{
    if (!scan->best_header || (arith_uint256_is_zero(&sp->nChainWork) || arith_uint256_is_zero(&scan->best_header->nChainWork)
         ? sp->nHeight > scan->best_header->nHeight
         : arith_uint256_compare(&sp->nChainWork, &scan->best_header->nChainWork) > 0))
        scan->best_header = sp;
}

/* Track the restore fallback and the reindex target. */
static void boot_scan_track_restore_targets(struct boot_index_scan *scan,
                                            struct block_index *sp)
{
    /* Fallback: most work with HAVE_DATA + nChainTx */
    if ((sp->nStatus & BLOCK_HAVE_DATA) && sp->nChainTx > 0) {
        if (!scan->fallback ||
            arith_uint256_compare(&sp->nChainWork,
                                  &scan->fallback->nChainWork) > 0)
            scan->fallback = sp;
    }
    /* Reindex target: highest with pprev + nChainTx */
    if (sp->pprev && sp->nHeight > 0 && sp->nChainTx > 0) {
        if (!scan->reindex_best ||
            sp->nHeight > scan->reindex_best->nHeight)
            scan->reindex_best = sp;
    }
}

/* Max HAVE_DATA height + aggregate body-coverage count (gates the
 * reindex-target decision below; no extra O(chain) pass). */
static void boot_scan_track_body_coverage(struct boot_index_scan *scan,
                                          struct block_index *sp)
{
    if (sp->nStatus & BLOCK_HAVE_DATA) {
        scan->have_data_count++;
        if (sp->nHeight > scan->max_have_data_h)
            scan->max_have_data_h = sp->nHeight;
    }
    if ((sp->nStatus & BLOCK_HAVE_DATA) && sp->nDataPos > 0 &&
        sp->nHeight > 0 &&
        (sp->nVersion == 0 || sp->nTime == 0 || sp->nBits == 0))
        scan->missing_header_data++;
}

/* One entry of the single-pass block-index scan. */
void boot_scan_visit_index_entry(struct boot_index_scan *scan,
                                        struct block_index *sp)
{
    /* Clear BLOCK_FAILED */
    if (sp->nStatus & BLOCK_FAILED_MASK) {
        sp->nStatus &= ~BLOCK_FAILED_MASK;
        scan->cleared_failed++;
    }
    boot_scan_track_best_header(scan, sp);
    boot_scan_track_restore_targets(scan, sp);
    boot_scan_track_body_coverage(scan, sp);
}
