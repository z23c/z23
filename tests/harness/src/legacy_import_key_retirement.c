/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Source-inclusion witness: the key and note buffers the legacy import's
 * decrypt workers hold are zero when they are handed to free(). The bytes are
 * read in the wrapper, before the real free, never after it. */
#include "test/test_core.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct retirement_span {
    const void *ptr;
    size_t offset;
    size_t bytes;
    unsigned frees;
    bool zero;
};

static struct retirement_span retirement_spans[3];
static void retirement_free(void *ptr);

#define free retirement_free
#define legacy_import_service_run retirement_legacy_import_service_run
#include "../../../engine/services/src/legacy_import_service.c"
#undef free
#undef legacy_import_service_run

static void retirement_free(void *ptr)
{
    for (size_t i = 0; ptr != NULL && i < 3; i++) {
        struct retirement_span *s = &retirement_spans[i];
        if (s->ptr != ptr)
            continue;
        const uint8_t *b = (const uint8_t *)ptr + s->offset;
        s->frees++;
        s->zero = true;
        for (size_t j = 0; j < s->bytes; j++)
            s->zero &= b[j] == 0;
    }
    free(ptr);
}

static bool span_ok(size_t i)
{
    return retirement_spans[i].frees == 1u && retirement_spans[i].zero;
}

static int release_path_case(void)
{
    enum { SLOTS = 1 };
    struct legacy_import_decrypt_file_ctx *d = calloc(SLOTS, sizeof(*d));
    bool filled = d != NULL;
    if (filled) {
        d[0].result_cap = 2;
        d[0].results = calloc(2, sizeof(struct db_sapling_note));
        d[0].tw.sapling_notes_cap = 2;
        d[0].tw.sapling_notes =
            calloc(2, sizeof(struct sapling_received_note));
        filled = d[0].results && d[0].tw.sapling_notes;
    }
    if (filled) {
        memset(&d[0].tw.sapling_keys, 0xa5, sizeof(d[0].tw.sapling_keys));
        memset(d[0].results, 0xa5, 2 * sizeof(struct db_sapling_note));
        memset(d[0].tw.sapling_notes, 0xa5,
               2 * sizeof(struct sapling_received_note));
    }
    printf("legacy_import_key_retirement: setup: decrypt contexts hold key "
           "and note copies... %s\n", filled ? "OK" : "FAIL");
    if (!filled)
        return 1;
    memset(retirement_spans, 0, sizeof(retirement_spans));
    retirement_spans[0] = (struct retirement_span){
        .ptr = d[0].results, .bytes = 2 * sizeof(struct db_sapling_note)};
    retirement_spans[1] = (struct retirement_span){
        .ptr = d[0].tw.sapling_notes,
        .bytes = 2 * sizeof(struct sapling_received_note)};
    /* The keystore copy lives inside the context block itself. */
    retirement_spans[2] = (struct retirement_span){
        .ptr = d,
        .offset = offsetof(struct legacy_import_decrypt_file_ctx,
                           tw.sapling_keys),
        .bytes = sizeof(d[0].tw.sapling_keys)};
    legacy_import_release_sapling_contexts(d, NULL, SLOTS);
    printf("legacy_import_key_retirement: the result buffer is zero when "
           "freed... %s\n", span_ok(0) ? "OK" : "FAIL");
    printf("legacy_import_key_retirement: the note buffer is zero when "
           "freed... %s\n", span_ok(1) ? "OK" : "FAIL");
    printf("legacy_import_key_retirement: the keystore copies are zero when "
           "the contexts are freed... %s\n", span_ok(2) ? "OK" : "FAIL");
    return (span_ok(0) ? 0 : 1) + (span_ok(1) ? 0 : 1) + (span_ok(2) ? 0 : 1);
}

/* The save path hands a file's results and note copies to free() after the
 * rows are written; both are zero by then. */
struct save_fixture {
    struct legacy_import_decrypt_file_ctx d[1];
    struct legacy_import_filter_file_ctx fc[1];
    struct node_db ndb;
    bool ready;
};

static void save_fixture_fill(struct save_fixture *x)
{
    struct db_sapling_note *row = &x->d[0].results[0];
    row->txid[0] = 1;
    row->value = 7;
    memset(row->rcm, 0xa5, sizeof(row->rcm));
    memset(row->ivk, 0x11, sizeof(row->ivk));
    memset(row->diversifier, 0x22, sizeof(row->diversifier));
    memset(row->pk_d, 0x33, sizeof(row->pk_d));
    memset(row->cm, 0x44, sizeof(row->cm));
    memset(row->nullifier, 0x55, sizeof(row->nullifier));
    memset(x->d[0].tw.sapling_notes, 0xa5,
           2 * sizeof(struct sapling_received_note));
}

static void save_fixture_open(struct save_fixture *x)
{
    memset(x, 0, sizeof(*x));
    x->d[0].result_cap = 2;
    x->d[0].result_count = 1;
    x->d[0].results = calloc(2, sizeof(struct db_sapling_note));
    x->d[0].tw.sapling_notes_cap = 2;
    x->d[0].tw.sapling_notes =
        calloc(2, sizeof(struct sapling_received_note));
    char dir[1024], path[1100];
    test_make_tmpdir(dir, sizeof(dir), "legacy_import_retire", "save");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    x->ready = x->d[0].results && x->d[0].tw.sapling_notes &&
               node_db_open(&x->ndb, path);
    if (!x->ready)
        return;
    save_fixture_fill(x);
    memset(retirement_spans, 0, sizeof(retirement_spans));
    retirement_spans[0] = (struct retirement_span){
        .ptr = x->d[0].results,
        .bytes = 2 * sizeof(struct db_sapling_note)};
    retirement_spans[1] = (struct retirement_span){
        .ptr = x->d[0].tw.sapling_notes,
        .bytes = 2 * sizeof(struct sapling_received_note)};
}

static bool save_fixture_run(struct save_fixture *x)
{
    int seen = 0, found = 0;
    bool open_tx = false;
    if (!x->ready)
        return false;
    int rc = legacy_import_save_sapling_notes(&x->ndb, x->d, x->fc, 1, &seen,
                                              &found, &open_tx);
    node_db_close(&x->ndb);
    return rc == LEGACY_IMPORT_OK && !open_tx;
}

static int save_path_case(void)
{
    struct save_fixture x;
    save_fixture_open(&x);
    bool saved = save_fixture_run(&x);
    if (!saved) {
        free(x.d[0].results);
        free(x.d[0].tw.sapling_notes);
    }
    bool result_zero = saved && span_ok(0);
    bool notes_zero = saved && span_ok(1);
    printf("legacy_import_key_retirement: the save path commits a file's "
           "rows... %s\n", saved ? "OK" : "FAIL");
    printf("legacy_import_key_retirement: the saved result buffer is zero "
           "when freed... %s\n", result_zero ? "OK" : "FAIL");
    printf("legacy_import_key_retirement: the saved note buffer is zero when "
           "freed... %s\n", notes_zero ? "OK" : "FAIL");
    return (saved ? 0 : 1) + (result_zero ? 0 : 1) + (notes_zero ? 0 : 1);
}

int legacy_import_key_retirement_cases(void);
int legacy_import_key_retirement_cases(void)
{
    return release_path_case() + save_path_case();
}
