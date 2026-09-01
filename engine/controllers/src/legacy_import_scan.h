#ifndef ZCL_LEGACY_IMPORT_SCAN_H
#define ZCL_LEGACY_IMPORT_SCAN_H

#include "services/scan_util.h"
#include "models/wallet_tx.h"
#include "primitives/block.h"
#include "wallet/wallet.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct legacy_import_scan_file_arg {
    const char *datadir;
    int file_num;
    const struct scan_addr_ht *ht;
    bool result;
};

struct legacy_import_block_pos {
    int file_num;
    size_t offset;      /* offset of magic bytes in file */
    uint32_t blk_size;
    int height;
};

struct legacy_import_filter_file_ctx {
    const char *datadir;
    int file_num;
    int blocks_total;
    int blocks_passed;
    int height_failed;
    struct legacy_import_block_pos *hits;
    int hit_count;
    int hit_cap;
};

struct legacy_import_decrypt_file_ctx {
    const char *datadir;
    struct legacy_import_block_pos *hits;
    int count;
    int file_num;
    struct wallet tw;
    int outputs_seen;
    int notes_found;
    struct db_sapling_note *results;
    int result_count;
    int result_cap;
};

typedef bool (*legacy_import_block_visitor_fn)(const struct block *blk,
                                               int height,
                                               void *ctx);

void *legacy_import_scan_file_thread(void *arg);
int legacy_import_walk_block_file(const uint8_t *fdata,
                                  size_t fsize,
                                  legacy_import_block_visitor_fn visitor,
                                  void *ctx);
void *legacy_import_sapling_filter_thread(void *arg);
void *legacy_import_decrypt_thread(void *arg);

#endif /* ZCL_LEGACY_IMPORT_SCAN_H */
