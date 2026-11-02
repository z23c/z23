/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Source-inclusion witness: when the legacy import's decrypt worker grows its
 * result buffer, the old buffer is zero when it is handed to free(). The bytes
 * are read in the wrapper, before the real free. */
#include "test/test_core.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static const void *growth_watched;
static size_t growth_bytes;
static unsigned growth_frees;
static bool growth_zero;
static void growth_free(void *ptr);

#define free growth_free
#define legacy_import_scan_file_thread growth_legacy_import_scan_file_thread
#define legacy_import_walk_block_file growth_legacy_import_walk_block_file
#define legacy_import_sapling_filter_thread growth_legacy_import_sapling_filter_thread
#define legacy_import_decrypt_thread growth_legacy_import_decrypt_thread
#include "../../../engine/controllers/src/legacy_import_scan.c"
#undef free
#undef legacy_import_scan_file_thread
#undef legacy_import_walk_block_file
#undef legacy_import_sapling_filter_thread
#undef legacy_import_decrypt_thread

static void growth_free(void *ptr)
{
    if (ptr != NULL && ptr == growth_watched) {
        const uint8_t *b = ptr;
        growth_frees++;
        growth_zero = true;
        for (size_t i = 0; i < growth_bytes; i++)
            growth_zero &= b[i] == 0;
    }
    free(ptr);
}

int legacy_import_growth_retirement_cases(void);
int legacy_import_growth_retirement_cases(void)
{
    struct legacy_import_decrypt_file_ctx *c = calloc(1, sizeof(*c));
    struct uint256 txid;
    memset(&txid, 0x11, sizeof(txid));
    bool filled = c != NULL;
    if (filled) {
        c->tw.sapling_notes = calloc(1, sizeof(struct sapling_received_note));
        c->results = calloc(1, sizeof(struct db_sapling_note));
        filled = c->tw.sapling_notes && c->results;
    }
    if (filled) {
        c->tw.num_sapling_notes = 1;
        c->tw.sapling_notes[0].used = true;
        c->tw.sapling_notes[0].txid = txid;
        memset(c->results, 0xa5, sizeof(struct db_sapling_note));
        c->result_cap = 1;
        c->result_count = 1;
        growth_watched = c->results;
        growth_bytes = sizeof(struct db_sapling_note);
        growth_frees = 0;
        growth_zero = false;
        store_notes_matching_txid(c, &txid, 7);
        growth_watched = NULL;
    }
    bool ok = filled && c->result_count == 2 && c->result_cap == 2 &&
              growth_frees == 1u && growth_zero;
    printf("legacy_import_growth_retirement: the old result buffer is zero "
           "when growth frees it... %s\n", ok ? "OK" : "FAIL");
    if (c) {
        free(c->results);
        free(c->tw.sapling_notes);
    }
    free(c);
    return ok ? 0 : 1;
}
