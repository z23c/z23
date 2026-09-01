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
 * There is deliberately no $HOME/.zclassic fallback. That directory belongs
 * to a running zclassicd, and block_log_legacy_open → bilr_open →
 * db_wrapper_open is an ordinary read-WRITE LevelDB open: it takes the LOCK
 * and can run log recovery, rewriting the MANIFEST of a live daemon's block
 * index. It happened to be harmless only because the daemon held the LOCK
 * and the open failed — which also made every assertion below silently
 * vanish, and made the result depend on whether a service was running.
 * Point ZCL_LEGACY_DATADIR at a datadir you own (a stopped node, or a copy)
 * to exercise it. */

#include "test/test_core.h"
#include "adapters/outbound/persistence/block_log_legacy.h"
#include "ports/block_log_port.h"

#include <stdio.h>
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

int test_block_log_legacy(void)
{
    int failures = 0;

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
        struct block_log_legacy *h = NULL;
        struct block_log_port port = {0};
        struct zcl_result r = block_log_legacy_open(
                "/tmp/zcl_no_such_legacy_dir_42424242", &h, &port);
        BLL_CHECK("open(missing) → NOT_FOUND",
                  !r.ok && r.code == BLOCK_LOG_ERR_NOT_FOUND);
    }

    /* ── 3. Datadir with no blocks/ subdir → NOT_FOUND. */
    {
        char tmpl[] = "/tmp/zcl_bll_emptyXXXXXX";
        char *dir = mkdtemp(tmpl);
        BLL_CHECK("mkdtemp empty", dir != NULL);
        if (dir) {
            struct block_log_legacy *h = NULL;
            struct block_log_port port = {0};
            struct zcl_result r = block_log_legacy_open(dir, &h, &port);
            BLL_CHECK("open(no blocks/) → NOT_FOUND",
                      !r.ok && r.code == BLOCK_LOG_ERR_NOT_FOUND);
            rmdir(dir);
        }
    }

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

    /* read_at_height(0) — genesis block. */
    const uint8_t *bytes = NULL;
    size_t len = 0;
    r = port.read_at_height(port.self, 0, &bytes, &len);
    BLL_CHECK("read_at_height(0) → OK",
              r.ok && bytes != NULL && len > 80);
    size_t genesis_len = len;

    /* Re-read same height — bytes and len must be stable. */
    {
        const uint8_t *bytes2 = NULL;
        size_t len2 = 0;
        struct zcl_result rr = port.read_at_height(port.self, 0,
                                                    &bytes2, &len2);
        BLL_CHECK("read_at_height(0) stable",
                  rr.ok && len2 == genesis_len && bytes2 != NULL);
    }

    /* read_at_height(tip) — must succeed. */
    r = port.read_at_height(port.self, tip, &bytes, &len);
    BLL_CHECK("read_at_height(tip) → OK",
              r.ok && bytes != NULL && len > 80);

    /* read_at_height(tip+1) → NOT_FOUND. */
    r = port.read_at_height(port.self, tip + 1, &bytes, &len);
    BLL_CHECK("read_at_height(tip+1) → NOT_FOUND",
              !r.ok && r.code == BLOCK_LOG_ERR_NOT_FOUND);

    /* append always rejected. */
    {
        struct block_hash dummy = {0};
        uint8_t fake[1] = {0};
        r = port.append(port.self, 0, &dummy, fake, sizeof fake);
        BLL_CHECK("append → NOT_SUPPORTED",
                  !r.ok && r.code == BLOCK_LOG_ERR_NOT_SUPPORTED);
    }

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
