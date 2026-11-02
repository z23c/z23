/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Source-inclusion witness: the Sapling keystore copies the legacy import's
 * decrypt workers hold are zero when their block is handed to free(). The
 * bytes are read in the wrapper, before the real free, never after it. */
#include "test/test_core.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const void *retirement_watched;
static int retirement_count;
static unsigned retirement_frees;
static bool retirement_zero;
static void retirement_free(void *ptr);

#define free retirement_free
#define legacy_import_service_run retirement_legacy_import_service_run
#include "../../../engine/services/src/legacy_import_service.c"
#undef free
#undef legacy_import_service_run

static void retirement_free(void *ptr)
{
    if (ptr != NULL && ptr == retirement_watched) {
        const struct legacy_import_decrypt_file_ctx *d = ptr;
        retirement_frees++;
        retirement_zero = true;
        for (int f = 0; f < retirement_count; f++) {
            const uint8_t *b = (const uint8_t *)&d[f].tw.sapling_keys;
            for (size_t i = 0; i < sizeof(d[f].tw.sapling_keys); i++)
                retirement_zero &= b[i] == 0;
        }
    }
    free(ptr);
}

int legacy_import_key_retirement_cases(void);
int legacy_import_key_retirement_cases(void)
{
    enum { SLOTS = 2 };
    int failures = 0;
    struct legacy_import_decrypt_file_ctx *d = calloc(SLOTS, sizeof(*d));
    bool filled = d != NULL;
    for (int f = 0; filled && f < SLOTS; f++) {
        memset(&d[f].tw.sapling_keys, 0xa5, sizeof(d[f].tw.sapling_keys));
        d[f].results = calloc(1, sizeof(struct db_sapling_note));
    }
    printf("legacy_import_key_retirement: setup: decrypt contexts hold key copies... %s\n",
           filled ? "OK" : "FAIL");
    if (!filled)
        return 1;
    retirement_watched = d;
    retirement_count = SLOTS;
    retirement_frees = 0;
    retirement_zero = false;
    legacy_import_release_sapling_contexts(d, NULL, SLOTS);
    retirement_watched = NULL;
    bool ok = retirement_frees == 1u && retirement_zero;
    printf("legacy_import_key_retirement: the keystore copies are zero when the "
           "contexts are freed... %s\n", ok ? "OK" : "FAIL");
    return ok ? failures : failures + 1;
}
