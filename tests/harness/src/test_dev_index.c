/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.index.* (native_dev_index_{catalog,ingest,search,
 * command}.c).
 *
 * Exercises the catalog/ingest/search modules directly against a fixture
 * root, never the real checkout's state: ZCL_INDEX_STATE_DIR redirects the
 * zclassic23-rooted sources (board/experiments/logs) and XDG_STATE_HOME
 * redirects platform_state_root() (the landing source's root) to a
 * per-test temp directory. index.db itself lands under that same
 * ZCL_INDEX_STATE_DIR/index/index.db, so a fixture never touches the
 * operator's real ~/.local/state/zclassic23/index/index.db.
 */

#include "test/test_core.h"

#include "command/native_dev_index_catalog.h"
#include "command/native_dev_index_ingest.h"
#include "command/native_dev_index_search.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── fixture plumbing ────────────────────────────────────────────────── */

static bool dvi_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

static bool dvi_append(const char *path, const char *text)
{
    FILE *f = fopen(path, "ab");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool wrote = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && wrote;
}

/* platform_directory_ensure() creates exactly one level; fixtures here
 * need multi-level paths ("<parent>/xdg/z23/dev/land"), so walk and
 * create each segment, same as platform/state_root.c's ensure_parent(). */
static bool dvi_mkdir(const char *path)
{
    char copy[768];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(copy))
        return false;
    memcpy(copy, path, len + 1);
    for (char *p = copy + (copy[0] == '/' ? 1 : 0);; p++) {
        if (*p != '/' && *p != '\0')
            continue;
        char saved = *p;
        *p = '\0';
        if (copy[0] && !platform_directory_ensure(copy, 0700))
            return false;
        *p = saved;
        if (!saved)
            break;
    }
    return true;
}

/* Injected clock — see tests/harness/src/test_clock.c for the same idiom. */
struct dvi_fake_clock {
    _Atomic int64_t mono_ns;
    _Atomic int64_t wall_ms;
};
static int64_t dvi_fake_mono(void *self)
{
    return atomic_load(&((struct dvi_fake_clock *)self)->mono_ns);
}
static int64_t dvi_fake_wall(void *self)
{
    return atomic_load(&((struct dvi_fake_clock *)self)->wall_ms);
}

int test_dev_index(void);
int test_dev_index(void)
{
    int failures = 0;
    char parent[512];
    test_make_tmpdir(parent, sizeof(parent), "dev_index", "fixture");

    char zclassic23[600], xdg[600], board_dir[700], exp_dir[700];
    (void)snprintf(zclassic23, sizeof(zclassic23), "%s/zclassic23", parent);
    (void)snprintf(xdg, sizeof(xdg), "%s/xdg", parent);
    (void)snprintf(board_dir, sizeof(board_dir), "%s/board", zclassic23);
    (void)snprintf(exp_dir, sizeof(exp_dir), "%s/experiments", zclassic23);
    ASSERT(dvi_mkdir(zclassic23));
    ASSERT(dvi_mkdir(xdg));
    ASSERT(dvi_mkdir(board_dir));
    ASSERT(dvi_mkdir(exp_dir));
    (void)setenv("ZCL_INDEX_STATE_DIR", zclassic23, 1);
    (void)setenv("XDG_STATE_HOME", xdg, 1);

    char board_file[800], exp_file[800], land_dir[800], land_file[800];
    (void)snprintf(board_file, sizeof(board_file), "%s/node1.jsonl", board_dir);
    (void)snprintf(exp_file, sizeof(exp_file), "%s/rows.tsv", exp_dir);
    (void)snprintf(land_dir, sizeof(land_dir), "%s/z23/dev/land", xdg);
    (void)snprintf(land_file, sizeof(land_file), "%s/outcomes.jsonl",
                  land_dir);
    ASSERT(dvi_mkdir(land_dir));

    ASSERT(dvi_write(
        board_file,
        "{\"ts\":\"2026-09-01T00:00:00Z\",\"id\":\"a1\",\"host\":\"node1\","
        "\"agent\":\"claude\",\"kind\":\"problem\",\"ref\":\"\","
        "\"text\":\"first\"}\n"));
    ASSERT(dvi_write(
        exp_file,
        "ts\tkind\tbox\ttask_id\ttask_class\tstory\texecutor\tharness\tmodel\t"
        "effort\ttokens_in\ttokens_out\ttokens_cache\ttokens_reasoning\t"
        "tool_uses\tturns\twall_s\toutcome\tlines_added\tlines_removed\t"
        "defects\tnote\n"
        "2026-09-01T00:00:00Z\tresult\tnode1\tt1\tunit_docs\ts1\tclaude-"
        "sonnet\tagent-tool\tsonnet\tmedium\t1\t2\t3\t4\t5\t6\t7\tLAND\t0\t0\t"
        "0\tfirst\n"));
    ASSERT(dvi_write(
        land_file,
        "{\"seq\":1,\"ts\":\"2026-09-01T00:00:00Z\",\"tip\":\"deadbeef\","
        "\"worktree\":\"/w1\",\"note\":\"train1\",\"state\":\"landed\","
        "\"phase\":\"\"}\n"));

    sqlite3 *db = NULL;
    char err[256];
    /* dev_index_db_open's schema includes `CREATE VIRTUAL TABLE rows_fts
     * USING fts5(...)`. If this vendored sqlite build lacked FTS5, that
     * DDL — and therefore this open — would fail with "no such module:
     * fts5", and the assert below names it rather than the test silently
     * skipping the feature. */
    if (!dev_index_db_open(&db, err, sizeof(err))) {
        printf("dev_index_db_open failed (FTS5 missing from this build?): "
              "%s\n", err);
    }
    ASSERT(db != NULL);

    const struct dev_index_source *board_src = dev_index_source_find("board");
    const struct dev_index_source *exp_src =
        dev_index_source_find("experiments");
    const struct dev_index_source *land_src =
        dev_index_source_find("landing");
    const struct dev_index_source *log_src = dev_index_source_find("logs");
    ASSERT(board_src && exp_src && land_src && log_src);

    TEST("index: first ingest picks up every fixture row") {
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 1);
        ASSERT(dev_index_ingest_source(db, exp_src, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 1);
        ASSERT(dev_index_ingest_source(db, land_src, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 1);
        PASS();
    }

    TEST("index: ingesting again with no new bytes adds zero rows") {
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 0);
        ASSERT(dev_index_ingest_source(db, exp_src, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 0);
        PASS();
    }

    TEST("index: appending a line ingests only the appended row") {
        ASSERT(dvi_append(
            board_file,
            "{\"ts\":\"2026-09-01T01:00:00Z\",\"id\":\"a2\","
            "\"host\":\"node1\",\"agent\":\"claude\",\"kind\":\"result\","
            "\"ref\":\"a1\",\"text\":\"second\"}\n"));
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 1);
        PASS();
    }

    TEST("index: truncating a file restarts ingest from byte 0") {
        ASSERT(dvi_write(
            board_file,
            "{\"ts\":\"2026-09-01T02:00:00Z\",\"id\":\"a3\","
            "\"host\":\"node1\",\"agent\":\"claude\",\"kind\":\"note\","
            "\"ref\":\"\",\"text\":\"rewritten\"}\n"));
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 1);
        PASS();
    }

    TEST("index: search hits a bare word") {
        struct dev_index_search_result res;
        ASSERT(dev_index_search(db, "rewritten", NULL, 10, &res, err,
                                sizeof(err)));
        ASSERT(res.count >= 1);
        ASSERT(strstr(res.hits[0].text, "rewritten") != NULL);
        PASS();
    }

    TEST("index: search hits a key:value term") {
        struct dev_index_search_result res;
        ASSERT(dev_index_search(db, "kind:result", NULL, 10, &res, err,
                                sizeof(err)));
        bool found = false;
        for (size_t i = 0; i < res.count; i++)
            if (strstr(res.hits[i].text, "second"))
                found = true;
        ASSERT(found);
        PASS();
    }

    TEST("index: search scoped to one source ignores the rest") {
        struct dev_index_search_result res;
        ASSERT(dev_index_search(db, "state:landed", "landing", 10, &res, err,
                                sizeof(err)));
        ASSERT(res.count == 1);
        ASSERT_STR_EQ(res.hits[0].source_id, "landing");
        PASS();
    }

    TEST("index: status numbers are exact under the injected clock") {
        struct dvi_fake_clock fc;
        atomic_store(&fc.mono_ns, (int64_t)0);
        atomic_store(&fc.wall_ms, (int64_t)1788300000000LL); /* 2026-09-01
                                                              * ~00:20:00Z */
        const clock_iface_t iface = {.now_monotonic_ns = dvi_fake_mono,
                                     .now_wall_ms = dvi_fake_wall,
                                     .self = &fc};
        clock_set_default(&iface);
        struct dev_index_source_status st;
        int64_t now_ms = clock_now_wall_ms();
        ASSERT(dev_index_source_status(db, exp_src, now_ms, &st, err,
                                       sizeof(err)));
        clock_reset_default();
        ASSERT(st.rows == 1);
        ASSERT(st.has_rows);
        ASSERT_STR_EQ(st.newest_ts, "2026-09-01T00:00:00Z");
        ASSERT(st.seconds_since_newest > 0);
        ASSERT(st.bytes_behind == 0);
        PASS();
    }

    TEST("index: an unknown source id is refused by dev_index_source_find") {
        ASSERT(dev_index_source_find("not-a-real-source") == NULL);
        PASS();
    }

    (void)log_src;
_test_next:;
    dev_index_db_close(db);
    (void)unsetenv("ZCL_INDEX_STATE_DIR");
    (void)unsetenv("XDG_STATE_HOME");
    (void)test_rm_rf_recursive(parent);
    return failures;
}
