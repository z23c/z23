/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the single-pass block-index scan's private cross-TU contract: the
 * accumulator struct and the one visit entry point. The struct was defined in
 * boot.c and the visit entry point was static there; both moved with the scan
 * helpers into boot_block_index_scan.c unchanged, to keep boot.c under the
 * file-size cap. Only boot.c and boot_block_index_scan.c may include this. */

#ifndef ZCL_CONFIG_BOOT_BLOCK_INDEX_SCAN_INTERNAL_H
#define ZCL_CONFIG_BOOT_BLOCK_INDEX_SCAN_INTERNAL_H

struct block_index;

/* What the single-pass block-index scan learns, so the tip-resolution,
 * coverage and block-file-scan steps below need no further O(chain) pass. */
struct boot_index_scan {
    struct block_index *best_header;   /* most chain work */
    struct block_index *fallback;      /* most work w/ data */
    struct block_index *reindex_best;  /* highest w/ pprev+nChainTx */
    int cleared_failed;
    int max_have_data_h;
    int have_data_count;
    int missing_header_data;
    int contiguous_data_h;
};

/* One entry of the single-pass block-index scan. */
void boot_scan_visit_index_entry(struct boot_index_scan *scan,
                                 struct block_index *sp);

#endif /* ZCL_CONFIG_BOOT_BLOCK_INDEX_SCAN_INTERNAL_H */
