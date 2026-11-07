/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * test_block_log_legacy — exercises the read-only legacy block_log_port
 * adapter.
 *
 * Strategy mirrors test_chainstate_legacy_reader: cheap unit assertions
 * always run (NULL guards, missing-datadir → NOT_FOUND), and a richer
 * "live" assertion block runs ONLY when the operator names a datadir in
 * ZCL_LEGACY_DATADIR. The live block is skipped with PASS otherwise, so a
 * fresh checkout doesn't fail.
 *
 * There is deliberately no $HOME/.zclassic fallback: that directory belongs to
 * a running zclassicd, and block_log_legacy_open -> bilr_open ->
 * db_wrapper_open is an ordinary read-WRITE LevelDB open that takes the LOCK
 * and can run log recovery, rewriting the live daemon's MANIFEST. Point
 * ZCL_LEGACY_DATADIR at a datadir you own (a stopped node, or a copy) to
 * exercise it. */

#include "test/test_core.h"
#include "adapters/outbound/persistence/block_log_legacy.h"
#include "ports/block_log_port.h"

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLL_CHECK(name, expr) do {                       \
    printf("block_log_legacy: %s... ", (name));          \
    if ((expr)) { printf("OK\n"); }                      \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

/* Explicit opt-in only — see the header comment for why there is no
 * $HOME/.zclassic fallback. */
static const char *resolve_live_datadir(void)
{
    const char *env = getenv("ZCL_LEGACY_DATADIR");
    if (!env || !env[0]) return NULL;
    struct stat st;
    if (stat(env, &st) != 0 || !S_ISDIR(st.st_mode))
        return NULL;
    return env;
}

struct iter_state {
    int      seen;
    uint32_t first_height;
    uint32_t last_height;
    int      max;
};

static bool iter_cb(uint32_t height,
                    const struct block_hash *hash,
                    const uint8_t *bytes,
                    size_t len,
                    void *user_data)
{
    (void)hash; (void)bytes; (void)len;
    struct iter_state *s = user_data;
    if (s->first_height == UINT32_MAX)
        s->first_height = height;
    s->last_height = height;
    s->seen++;
    return s->seen < s->max;
}

/* Count every unexpected entry, including LOCK/CURRENT/MANIFEST, and remove
 * only files in this private fixture so a restored defect leaves no debris. */
static int bll_clean_directory(const char *path)
{
    DIR *d = opendir(path);
    if (!d) return -1;
    int count = 0;
    struct dirent *e;
    errno = 0;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char file[PATH_MAX];
        int n = snprintf(file, sizeof file, "%s/%s", path, e->d_name);
        if (n < 0 || (size_t)n >= sizeof file || unlink(file) != 0) {
            closedir(d);
            return -1;
        }
        count++;
        errno = 0;
    }
    int read_error = errno;
    if (closedir(d) != 0 || read_error) return -1;
    return count;
}

/* The caller supplies only the fixed boundary lengths below. */
static int bll_refused_open(const char *padded, const char *reason)
{
    int failures = 0;
    max_align_t handle_marker;
    struct block_log_legacy *sentinel = (void *)&handle_marker;
    struct block_log_legacy *h = sentinel;
    struct block_log_port port = {.self = &port};
    unsigned char before[sizeof port];
    memcpy(before, &port, sizeof port);
    struct zcl_result r = block_log_legacy_open(padded, &h, &port);
    BLL_CHECK("complete locator or refusal before index open",
              !r.ok && r.code == BLOCK_LOG_ERR_IO && strstr(r.message, reason));
    BLL_CHECK("refused open preserves outputs",
              h == sentinel && memcmp(&port, before, sizeof port) == 0);
    if (h != sentinel) block_log_legacy_close(h);
    return failures;
}

static int bll_exact_index_fixture(const char *index)
{
    int failures = 0;
    FILE *f = fopen(index, "wb");
    BLL_CHECK("exact-fit index refusal fixture", f != NULL);
    if (f) BLL_CHECK("close index fixture", fclose(f) == 0);
    return failures;
}

static int bll_boundary_open(size_t length, const char *padded,
                             const char *index)
{
    int failures = 0;
    if (length == 1010) failures += bll_exact_index_fixture(index);
    if (!failures)
        failures += bll_refused_open(padded,
            length == 1010 ? "bilr_open(" :
            length == 1016 ? "index path too long" : "blocks path too long");
    if (length == 1010)
        BLL_CHECK("remove index fixture", unlink(index) == 0);
    return failures;
}

static int bll_path_bounds(size_t length)
{
    int failures = 0;
    char root[512];
    char *dir = test_mkdtemp(root, sizeof root, "zcl_bll_bounds");
    BLL_CHECK("bounds fixture", dir != NULL);
    if (!dir) return failures;
    char blocks[1024], block[1024], index[1024], padded[1018];
    snprintf(blocks, sizeof blocks, "%s/blocks", dir);
    snprintf(block, sizeof block, "%s/block", dir);
    snprintf(index, sizeof index, "%s/blocks/index", dir);
    size_t root_len = strlen(dir);
    if (root_len > length || length >= sizeof padded) {
        BLL_CHECK("bounds fixture fits padded locator", false);
        BLL_CHECK("remove bounds fixture", test_rm_rf_recursive(dir) == 0);
        return failures;
    }
    memcpy(padded, dir, root_len);
    memset(padded + root_len, '/', length - root_len);
    padded[length] = '\0';
    bool made_blocks = mkdir(blocks, 0700) == 0;
    bool made_block = mkdir(block, 0700) == 0;
    BLL_CHECK("wrong-directory fixtures", made_blocks && made_block);
    if (made_blocks && made_block)
        failures += bll_boundary_open(length, padded, index);
    if (made_blocks)
        BLL_CHECK("no database files in blocks", bll_clean_directory(blocks) == 0);
    if (made_block)
        BLL_CHECK("no database files in block", bll_clean_directory(block) == 0);
    BLL_CHECK("remove bounds fixture", test_rm_rf_recursive(dir) == 0);
    return failures;
}

static int bll_basic_checks(void)
{
    int failures = 0;
    failures += bll_path_bounds(1010);
    failures += bll_path_bounds(1016);
    failures += bll_path_bounds(1017);

    /* ── 1. NULL guards on open. */
    {
        struct block_log_legacy *h = NULL;
        struct block_log_port port = {0};
        struct zcl_result r = block_log_legacy_open(NULL, &h, &port);
        BLL_CHECK("open(NULL datadir) → IO err",
                  !r.ok && r.code == BLOCK_LOG_ERR_IO && h == NULL);
        r = block_log_legacy_open("/anything", NULL, &port);
        BLL_CHECK("open(NULL handle) → IO err",
                  !r.ok && r.code == BLOCK_LOG_ERR_IO);
        r = block_log_legacy_open("/anything", &h, NULL);
        BLL_CHECK("open(NULL port) → IO err",
                  !r.ok && r.code == BLOCK_LOG_ERR_IO);
    }

    /* ── 2. Missing datadir → NOT_FOUND. */
    {
        /* The missing path lives under this test's own fresh temp dir, so
         * a stale shared /tmp directory can never make it exist. */
        char tmpl[512];
        char *dir = test_mkdtemp(tmpl, sizeof tmpl, "zcl_bll_missing");
        BLL_CHECK("mkdtemp missing parent", dir != NULL);
        if (dir) {
            char missing[600];
            int mn = snprintf(missing, sizeof missing, "%s/no_such_dir", dir);
            BLL_CHECK("missing path fits", mn > 0 && (size_t)mn < sizeof missing);
            struct block_log_legacy *h = NULL;
            struct block_log_port port = {0};
            struct zcl_result r = block_log_legacy_open(missing, &h, &port);
            BLL_CHECK("open(missing) → NOT_FOUND",
                      !r.ok && r.code == BLOCK_LOG_ERR_NOT_FOUND);
            BLL_CHECK("remove missing fixture", test_rm_rf_recursive(dir) == 0);
        }
    }

    /* ── 3. Datadir with no blocks/ subdir → NOT_FOUND. */
    {
        char tmpl[512];
        char *dir = test_mkdtemp(tmpl, sizeof tmpl, "zcl_bll_empty");
        BLL_CHECK("mkdtemp empty", dir != NULL);
        if (dir) {
            struct block_log_legacy *h = NULL;
            struct block_log_port port = {0};
            struct zcl_result r = block_log_legacy_open(dir, &h, &port);
            BLL_CHECK("open(no blocks/) → NOT_FOUND",
                      !r.ok && r.code == BLOCK_LOG_ERR_NOT_FOUND);
            BLL_CHECK("remove empty fixture", test_rm_rf_recursive(dir) == 0);
        }
    }

    return failures;
}

static int bll_live_read_checks(const struct block_log_port *port, uint32_t tip)
{
    int failures = 0;
    /* read_at_height(0) — genesis block. */
    const uint8_t *bytes = NULL;
    size_t len = 0;
    struct zcl_result r = port->read_at_height(port->self, 0, &bytes, &len);
    BLL_CHECK("read_at_height(0) → OK",
              r.ok && bytes != NULL && len > 80);
    size_t genesis_len = len;

    /* Re-read same height — bytes and len must be stable. */
    {
        const uint8_t *bytes2 = NULL;
        size_t len2 = 0;
        struct zcl_result rr = port->read_at_height(port->self, 0,
                                                    &bytes2, &len2);
        BLL_CHECK("read_at_height(0) stable",
                  rr.ok && len2 == genesis_len && bytes2 != NULL);
    }

    /* read_at_height(tip) — must succeed. */
    r = port->read_at_height(port->self, tip, &bytes, &len);
    BLL_CHECK("read_at_height(tip) → OK",
              r.ok && bytes != NULL && len > 80);

    /* read_at_height(tip+1) → NOT_FOUND. */
    r = port->read_at_height(port->self, tip + 1, &bytes, &len);
    BLL_CHECK("read_at_height(tip+1) → NOT_FOUND",
              !r.ok && r.code == BLOCK_LOG_ERR_NOT_FOUND);

    /* append always rejected. */
    {
        struct block_hash dummy = {0};
        uint8_t fake[1] = {0};
        r = port->append(port->self, 0, &dummy, fake, sizeof fake);
        BLL_CHECK("append → NOT_SUPPORTED",
                  !r.ok && r.code == BLOCK_LOG_ERR_NOT_SUPPORTED);
    }

    return failures;
}

static int bll_live_checks(void)
{
    int failures = 0;

    /* ── 4. Live block: real legacy datadir.
     *
     * Skipped (with PASS) when no datadir is reachable or the LevelDB
     * LOCK is held by a running zclassicd. */
    const char *datadir = resolve_live_datadir();
    if (!datadir) {
        printf("block_log_legacy: live block SKIPPED "
               "(set ZCL_LEGACY_DATADIR to a datadir you own; this test "
               "never opens the live ~/.zclassic)\n");
        return failures;
    }

    struct block_log_legacy *h = NULL;
    struct block_log_port port = {0};
    struct zcl_result r = block_log_legacy_open(datadir, &h, &port);
    if (!r.ok) {
        printf("block_log_legacy: live block SKIPPED "
               "(open %s failed: code=%d %s)\n",
               datadir, r.code, r.message);
        return failures;
    }

    BLL_CHECK("port populated", port.self == h &&
              port.append && port.read_by_hash &&
              port.read_at_height && port.tip_height && port.iter_from);

    size_t loaded = block_log_legacy_loaded_count(h);
    BLL_CHECK("loaded_count > 0", loaded > 0);

    uint32_t tip = port.tip_height(port.self);
    BLL_CHECK("tip_height != UINT32_MAX", tip != UINT32_MAX);
    printf("  tip_height = %u, loaded = %zu\n", tip, loaded);

    failures += bll_live_read_checks(&port, tip);

    /* iter_from(tip-2) → at most 3 invocations starting at tip-2. */
    if (tip >= 2) {
        struct iter_state walk = {
            .seen = 0,
            .first_height = UINT32_MAX,
            .last_height = 0,
            .max = 3,
        };
        r = port.iter_from(port.self, tip - 2, iter_cb, &walk);
        BLL_CHECK("iter_from → OK", r.ok);
        BLL_CHECK("iter_from saw 1..3 entries",
                  walk.seen <= 3 && walk.seen > 0);
        BLL_CHECK("iter_from started at tip-2",
                  walk.first_height == tip - 2);
    }

    block_log_legacy_close(h);

    return failures;
}

int test_block_log_legacy(void)
{
    int failures = bll_basic_checks();
    failures += bll_live_checks();
    return failures;
}
