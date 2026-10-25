/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pairing guard: every engine source that resets the nullifier table
 * (nullifier_kv_reset_*) because the coins authority is being replaced must
 * also reset shielded_pool_totals (shielded_pool_kv_reset_in_tx). Rows
 * written under the old authority may describe another chain, and a stale row
 * makes shielded_pool_kv_put's conflict check fatal once the height is
 * recomputed. A future fifth reset site that forgets the pool reset fails
 * here. */

#include "test/shielded_pool_reset_pairing.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SPR_CHECK(name, expr) do {                                      \
    printf("shielded_pool_reset_pairing: %s... ", (name));              \
    if ((expr)) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

#define SPR_NF_RESET "nullifier_kv_reset_"
#define SPR_POOL_RESET "shielded_pool_kv_reset_in_tx("

/* Files that call or define a nullifier reset WITHOUT replacing the coins
 * authority, each with the reason the pool totals must stay. */
static const char *const spr_exempt[] = {
    /* the definitions themselves */
    "engine/modules/storage/src/nullifier_kv.c",
    /* same-chain nullifier backfill generation: the chain does not change,
     * so the per-height pool totals stay valid */
    "engine/services/src/nullifier_backfill_service.c",
};

enum spr_verdict { SPR_NOT_RESET, SPR_PAIRED, SPR_UNPAIRED };

static enum spr_verdict spr_classify(const char *text)
{
    if (!strstr(text, SPR_NF_RESET))
        return SPR_NOT_RESET;
    return strstr(text, SPR_POOL_RESET) ? SPR_PAIRED : SPR_UNPAIRED;
}

static bool spr_is_exempt(const char *path)
{
    for (size_t i = 0; i < sizeof(spr_exempt) / sizeof(spr_exempt[0]); i++)
        if (strcmp(path, spr_exempt[i]) == 0)
            return true;
    return false;
}

static char *spr_read(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    char *buf = NULL;
    long n = -1;
    if (fseek(f, 0, SEEK_END) == 0 && (n = ftell(f)) >= 0 &&
        fseek(f, 0, SEEK_SET) == 0 && (buf = malloc((size_t)n + 1))) {
        if (fread(buf, 1, (size_t)n, f) == (size_t)n)
            buf[n] = '\0';
        else {
            free(buf);
            buf = NULL;
        }
    }
    fclose(f);
    return buf;
}

struct spr_tally {
    int paired;
    int unpaired;
    int scanned;
};

static void spr_file(const char *path, struct spr_tally *t)
{
    size_t n = strlen(path);
    if (n < 3 || strcmp(path + n - 2, ".c") != 0 || spr_is_exempt(path))
        return;
    char *text = spr_read(path);
    if (!text)
        return;
    t->scanned++;
    enum spr_verdict v = spr_classify(text);
    if (v == SPR_PAIRED)
        t->paired++;
    else if (v == SPR_UNPAIRED) {
        t->unpaired++;
        printf("shielded_pool_reset_pairing: UNPAIRED %s\n", path);
    }
    free(text);
}

static void spr_walk(const char *dir, struct spr_tally *t)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        char path[1024];
        if (snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >=
            (int)sizeof(path))
            continue;
        struct stat st;
        if (stat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
            spr_walk(path, t);
        else if (S_ISREG(st.st_mode))
            spr_file(path, t);
    }
    closedir(d);
}

int shielded_pool_reset_pairing_cases(void)
{
    int failures = 0;
    SPR_CHECK("classifier: nullifier reset alone is unpaired",
              spr_classify("x(); nullifier_kv_reset_mark_complete_in_tx(db);")
                  == SPR_UNPAIRED);
    SPR_CHECK("classifier: both resets is paired",
              spr_classify("nullifier_kv_reset_mark_complete_in_tx(db);"
                           "shielded_pool_kv_reset_in_tx(db);") == SPR_PAIRED);
    SPR_CHECK("classifier: no reset is not a reset site",
              spr_classify("nullifier_kv_get(db);") == SPR_NOT_RESET);
    struct spr_tally t = { 0, 0, 0 };
    spr_walk("engine", &t);
    SPR_CHECK("scan reached the engine tree", t.scanned > 100);
    SPR_CHECK("the four authority-replacing sites are all paired",
              t.paired >= 4);
    SPR_CHECK("no engine file resets nullifiers without the pool totals",
              t.unpaired == 0);
    return failures;
}
