/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ldb_reader_api — the leveldb-shaped C entry points of the C23 reader:
 * option handles, open/get, and the explicit refusals for every mutation.
 *
 * The shapes here mirror leveldb/c.h exactly (same argument order, same
 * `char **errptr` convention, same "NULL value means absent" contract for
 * get) so storage/ldb_c_api.h can map one onto the other with nothing but
 * #defines and no call site has to change.
 */

#include "ldb_reader_internal.h"
#include "storage/ldb_reader.h"

#include "util/safe_alloc.h"

#include <stdlib.h>
#include <string.h>

struct ldbr_options {
    bool create_if_missing;
    bool error_if_exists;
    bool paranoid_checks;
    int compression;
};

struct ldbr_readoptions {
    bool verify_checksums;
    bool fill_cache;
    const struct ldbr_snapshot *snapshot;
};

struct ldbr_writeoptions {
    bool sync;
};

/* A read-only view is frozen the moment it is opened, so a snapshot needs
 * no state — but it must still be a distinct, non-NULL handle so callers
 * can tell "snapshot set" from "no snapshot". */
struct ldbr_snapshot {
    int placeholder;
};

struct ldbr_cache {
    size_t capacity;
};

struct ldbr_filterpolicy {
    int bits_per_key;
};

struct ldbr_env {
    int placeholder;
};

struct ldbr_writebatch {
    size_t staged;
};

static void set_err(char **errptr, const char *msg)
{
    if (!errptr)
        return;
    free(*errptr);
    *errptr = ldb_strdup(msg);
}

/* ── database ───────────────────────────────────────────────────────── */

ldbr_t *ldbr_open(const ldbr_options_t *options, const char *name,
                  char **errptr)
{
    if (errptr)
        *errptr = NULL;
    if (!name) {
        set_err(errptr, "ldb: open called with no path");
        return NULL;
    }
    bool allow_missing = options ? options->create_if_missing : true;
    bool verify = true;
    char *err = NULL;
    struct ldbr_db *db = ldbr_db_open_internal(name, verify, allow_missing,
                                               &err);
    if (!db) {
        if (errptr)
            *errptr = err ? err : ldb_strdup("ldb: open failed");
        else
            free(err);
        return NULL;
    }
    return db;
}

void ldbr_close(ldbr_t *db)
{
    ldbr_db_close_internal(db);
}

char *ldbr_get(ldbr_t *db, const ldbr_readoptions_t *options, const char *key,
               size_t keylen, size_t *vallen, char **errptr)
{
    (void)options;
    if (errptr)
        *errptr = NULL;
    if (vallen)
        *vallen = 0;
    if (!db || !key) {
        set_err(errptr, "ldb: get called with no database or key");
        return NULL;
    }
    uint8_t *val = NULL;
    size_t n = 0;
    char *err = NULL;
    if (!ldbr_db_get_internal(db, (const uint8_t *)key, keylen, &val, &n,
                              &err)) {
        if (errptr)
            *errptr = err ? err : ldb_strdup("ldb: get failed");
        else
            free(err);
        return NULL;
    }
    if (vallen)
        *vallen = n;
    return (char *)val;
}

void ldbr_free(void *ptr)
{
    free(ptr);
}

ldbr_iterator_t *ldbr_create_iterator(ldbr_t *db,
                                      const ldbr_readoptions_t *options)
{
    (void)options;
    return ldbr_db_iter_internal(db);
}

const ldbr_snapshot_t *ldbr_create_snapshot(ldbr_t *db)
{
    (void)db;
    static const struct ldbr_snapshot frozen = { .placeholder = 0 };
    return &frozen;
}

void ldbr_release_snapshot(ldbr_t *db, const ldbr_snapshot_t *snapshot)
{
    (void)db;
    (void)snapshot;
}

/* ── refusals ───────────────────────────────────────────────────────── */

#define LDBR_READ_ONLY_MSG \
    "ldb: this build links the read-only C23 LevelDB reader; " \
    "writing to a LevelDB directory is not supported"

void ldbr_put(ldbr_t *db, const ldbr_writeoptions_t *options, const char *key,
              size_t keylen, const char *val, size_t vallen, char **errptr)
{
    (void)db; (void)options; (void)key; (void)keylen; (void)val; (void)vallen;
    set_err(errptr, LDBR_READ_ONLY_MSG);
}

void ldbr_delete(ldbr_t *db, const ldbr_writeoptions_t *options,
                 const char *key, size_t keylen, char **errptr)
{
    (void)db; (void)options; (void)key; (void)keylen;
    set_err(errptr, LDBR_READ_ONLY_MSG);
}

void ldbr_write(ldbr_t *db, const ldbr_writeoptions_t *options,
                ldbr_writebatch_t *batch, char **errptr)
{
    (void)db; (void)options; (void)batch;
    set_err(errptr, LDBR_READ_ONLY_MSG);
}

void ldbr_destroy_db(const ldbr_options_t *options, const char *name,
                     char **errptr)
{
    (void)options; (void)name;
    set_err(errptr, LDBR_READ_ONLY_MSG);
}

void ldbr_compact_range(ldbr_t *db, const char *start_key, size_t start_len,
                        const char *limit_key, size_t limit_len)
{
    /* Compaction is a writer's concern; a read-only view has nothing to
     * reorganize, and leveldb_compact_range has no failure channel. */
    (void)db; (void)start_key; (void)start_len; (void)limit_key;
    (void)limit_len;
}

/* ── options ────────────────────────────────────────────────────────── */

ldbr_options_t *ldbr_options_create(void)
{
    struct ldbr_options *o = zcl_malloc(sizeof(*o), "ldbr_options");
    if (!o)
        return NULL;
    o->create_if_missing = false;
    o->error_if_exists = false;
    o->paranoid_checks = false;
    o->compression = ldbr_snappy_compression;  /* leveldb's default */
    return o;
}

void ldbr_options_destroy(ldbr_options_t *o) { free(o); }

void ldbr_options_set_create_if_missing(ldbr_options_t *o, unsigned char v)
{
    if (o) o->create_if_missing = v != 0;
}

void ldbr_options_set_error_if_exists(ldbr_options_t *o, unsigned char v)
{
    if (o) o->error_if_exists = v != 0;
}

void ldbr_options_set_paranoid_checks(ldbr_options_t *o, unsigned char v)
{
    /* Recorded for symmetry only: this reader always verifies every block
     * and record checksum, which is strictly stronger. */
    if (o) o->paranoid_checks = v != 0;
}

void ldbr_options_set_compression(ldbr_options_t *o, int v)
{
    if (o) o->compression = v;
}

void ldbr_options_set_max_open_files(ldbr_options_t *o, int n)
{
    /* Tables are memory-mapped and their descriptors closed immediately,
     * so there is no open-file budget to spend. */
    (void)o; (void)n;
}

void ldbr_options_set_cache(ldbr_options_t *o, ldbr_cache_t *c)
{
    (void)o; (void)c;
}

void ldbr_options_set_filter_policy(ldbr_options_t *o, ldbr_filterpolicy_t *p)
{
    (void)o; (void)p;
}

void ldbr_options_set_env(ldbr_options_t *o, ldbr_env_t *env)
{
    (void)o; (void)env;
}

ldbr_readoptions_t *ldbr_readoptions_create(void)
{
    struct ldbr_readoptions *o = zcl_malloc(sizeof(*o), "ldbr_readoptions");
    if (!o)
        return NULL;
    o->verify_checksums = true;
    o->fill_cache = true;
    o->snapshot = NULL;
    return o;
}

void ldbr_readoptions_destroy(ldbr_readoptions_t *o) { free(o); }

void ldbr_readoptions_set_verify_checksums(ldbr_readoptions_t *o,
                                           unsigned char v)
{
    /* Honest deviation, in the safe direction: verification is always on
     * here. The escape hatch it mirrors (ZCL_LEVELDB_NO_VERIFY_CHECKSUMS)
     * only ever bought speed at the cost of silently truncating a scan. */
    if (o) o->verify_checksums = v != 0;
}

void ldbr_readoptions_set_fill_cache(ldbr_readoptions_t *o, unsigned char v)
{
    if (o) o->fill_cache = v != 0;
}

void ldbr_readoptions_set_snapshot(ldbr_readoptions_t *o,
                                   const ldbr_snapshot_t *snap)
{
    if (o) o->snapshot = snap;
}

ldbr_writeoptions_t *ldbr_writeoptions_create(void)
{
    struct ldbr_writeoptions *o = zcl_malloc(sizeof(*o), "ldbr_writeoptions");
    if (!o)
        return NULL;
    o->sync = false;
    return o;
}

void ldbr_writeoptions_destroy(ldbr_writeoptions_t *o) { free(o); }

void ldbr_writeoptions_set_sync(ldbr_writeoptions_t *o, unsigned char v)
{
    if (o) o->sync = v != 0;
}

ldbr_writebatch_t *ldbr_writebatch_create(void)
{
    struct ldbr_writebatch *b = zcl_malloc(sizeof(*b), "ldbr_writebatch");
    if (b)
        b->staged = 0;
    return b;
}

void ldbr_writebatch_destroy(ldbr_writebatch_t *b) { free(b); }

void ldbr_writebatch_put(ldbr_writebatch_t *b, const char *key, size_t klen,
                         const char *val, size_t vlen)
{
    (void)key; (void)klen; (void)val; (void)vlen;
    if (b) b->staged++;
}

void ldbr_writebatch_delete(ldbr_writebatch_t *b, const char *key, size_t klen)
{
    (void)key; (void)klen;
    if (b) b->staged++;
}

ldbr_cache_t *ldbr_cache_create_lru(size_t capacity)
{
    struct ldbr_cache *c = zcl_malloc(sizeof(*c), "ldbr_cache");
    if (c)
        c->capacity = capacity;
    return c;
}

void ldbr_cache_destroy(ldbr_cache_t *c) { free(c); }

ldbr_filterpolicy_t *ldbr_filterpolicy_create_bloom(int bits_per_key)
{
    struct ldbr_filterpolicy *p = zcl_malloc(sizeof(*p), "ldbr_filterpolicy");
    if (p)
        p->bits_per_key = bits_per_key;
    return p;
}

void ldbr_filterpolicy_destroy(ldbr_filterpolicy_t *p) { free(p); }

ldbr_env_t *ldbr_create_default_env(void)
{
    struct ldbr_env *e = zcl_malloc(sizeof(*e), "ldbr_env");
    if (e)
        e->placeholder = 0;
    return e;
}

void ldbr_env_destroy(ldbr_env_t *e) { free(e); }
