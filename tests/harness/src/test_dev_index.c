/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.index.* (native_dev_index_{catalog,ingest,identity,
 * parse,search,command}.c).
 *
 * Exercises the catalog/ingest/search modules directly against a fixture
 * root, never the real checkout's state: every call passes an explicit
 * state_root_override (and, for dev_index_db_open, an explicit index_override
 * too) pointing at a per-test temp directory — no environment variable is
 * read anywhere in this path, so a fixture can never touch the operator's
 * real ~/.local/state/zclassic23/index/index.db or sources.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_index_catalog.h"
#include "command/native_dev_index_ingest.h"
#include "command/native_dev_index_search.h"
#include "json/json.h"
#include "kernel/command_registry.h"
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
 * need multi-level paths ("<parent>/root/land"), so walk and create each
 * segment, same as platform/state_root.c's ensure_parent(). */
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

/* Drives one dev.index.* handler with a hand-built request whose input JSON
 * carries the DOCUMENTED CLI spelling of the two overrides ("index" and
 * "state-root", hyphenated) — the same keys the CLI flag parser
 * (nc_split_flag in native_command.c does no hyphen/underscore translation)
 * hands the handler after splitting "--index=..." / "--state-root=...".
 * Calling the handler directly (rather than through the catalog dispatcher)
 * avoids needing a ZCL_DEV_BUILD-wired handler table in the test binary,
 * while still exercising the exact json_get(request->input, "state-root")
 * lookup the bug was in. */
static bool dvi_dispatch(const char *leaf, const char *index_val,
                         const char *state_root_val,
                         struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (index_val)
        (void)json_push_kv_str(&input, "index", index_val);
    if (state_root_val)
        (void)json_push_kv_str(&input, "state-root", state_root_val);
    struct zcl_command_request request = {
        .input = &input,
        .view = "normal",
    };
    zcl_command_reply_init(reply, "");
    if (strcmp(leaf, "dev.index.ingest") == 0)
        zcl_native_handle_dev_index_ingest(&request, reply);
    else if (strcmp(leaf, "dev.index.status") == 0)
        zcl_native_handle_dev_index_status(&request, reply);
    else
        return false;
    json_free(&input);
    return true;
}

int test_dev_index(void);
int test_dev_index(void)
{
    int failures = 0;
    char parent[512];
    test_make_tmpdir(parent, sizeof(parent), "dev_index", "fixture");

    /* One fixture root serves every source: --state-root=<root> applies to
     * board/experiments/logs (normally zclassic23-rooted) AND landing
     * (normally the native dev-state root) alike — see
     * dev_index_source_resolve_root's doc comment. */
    char root[600], board_dir[700], exp_dir[700], land_dir[700];
    (void)snprintf(root, sizeof(root), "%s/root", parent);
    (void)snprintf(board_dir, sizeof(board_dir), "%s/board", root);
    (void)snprintf(exp_dir, sizeof(exp_dir), "%s/experiments", root);
    (void)snprintf(land_dir, sizeof(land_dir), "%s/land", root);
    ASSERT(dvi_mkdir(board_dir));
    ASSERT(dvi_mkdir(exp_dir));
    ASSERT(dvi_mkdir(land_dir));

    char board_file[800], exp_file[800], land_file[800], board_tmp[800];
    (void)snprintf(board_file, sizeof(board_file), "%s/node1.jsonl", board_dir);
    (void)snprintf(board_tmp, sizeof(board_tmp), "%s/node1.jsonl.tmp",
                  board_dir);
    (void)snprintf(exp_file, sizeof(exp_file), "%s/rows.tsv", exp_dir);
    (void)snprintf(land_file, sizeof(land_file), "%s/outcomes.jsonl",
                  land_dir);

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

    char err[256];

    TEST("index: status on a never-ingested root reports no index, "
        "and creates nothing") {
        sqlite3 *db = NULL;
        bool missing = false;
        ASSERT(dev_index_db_open(false, NULL, root, &db, &missing, err,
                                 sizeof(err)));
        ASSERT(missing);
        ASSERT(db == NULL);
        char index_dir[700];
        (void)snprintf(index_dir, sizeof(index_dir), "%s/index", root);
        struct platform_directory_list dummy_dirs, dummy_files;
        memset(&dummy_dirs, 0, sizeof(dummy_dirs));
        memset(&dummy_files, 0, sizeof(dummy_files));
        ASSERT(!platform_directory_list_children_sorted(
            index_dir, &dummy_dirs, &dummy_files));
        PASS();
    }

    sqlite3 *db = NULL;
    /* dev_index_db_open's schema includes `CREATE VIRTUAL TABLE rows_fts
     * USING fts5(...)`. If this vendored sqlite build lacked FTS5, that
     * DDL — and therefore this open — would fail with "no such module:
     * fts5", and the assert below names it rather than the test silently
     * skipping the feature. */
    if (!dev_index_db_open(true, NULL, root, &db, NULL, err, sizeof(err))) {
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
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1);
        ASSERT(r.rows_skipped == 0);
        ASSERT(dev_index_ingest_source(db, exp_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1);
        ASSERT(dev_index_ingest_source(db, land_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1);
        PASS();
    }

    TEST("index: ingesting again with no new bytes adds zero rows") {
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 0);
        ASSERT(dev_index_ingest_source(db, exp_src, root, &r, err,
                                       sizeof(err)));
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
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1);
        PASS();
    }

    TEST("index: a malformed line is counted in rows_skipped, not silently "
        "lost") {
        ASSERT(dvi_append(board_file, "not valid json at all\n"));
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 0);
        ASSERT(r.rows_skipped == 1);
        PASS();
    }

    TEST("index: truncating a file restarts ingest from byte 0") {
        ASSERT(dvi_write(
            board_file,
            "{\"ts\":\"2026-09-01T02:00:00Z\",\"id\":\"a3\","
            "\"host\":\"node1\",\"agent\":\"claude\",\"kind\":\"note\","
            "\"ref\":\"\",\"text\":\"third\"}\n"));
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1);
        PASS();
    }

    TEST("index: mv onto identical bytes ingests 0 new rows (rename "
        "changes inode, not content)") {
        char current[512];
        FILE *f = fopen(board_file, "rb");
        ASSERT(f != NULL);
        size_t n = fread(current, 1, sizeof(current) - 1, f);
        fclose(f);
        current[n] = '\0';
        ASSERT(dvi_write(board_tmp, current));
        ASSERT(rename(board_tmp, board_file) == 0);
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 0);
        PASS();
    }

    TEST("index: append-then-mv ingests exactly the appended row") {
        char current[512];
        FILE *f = fopen(board_file, "rb");
        ASSERT(f != NULL);
        size_t n = fread(current, 1, sizeof(current) - 1, f);
        fclose(f);
        current[n] = '\0';
        char grown[900];
        (void)snprintf(grown, sizeof(grown), "%s"
                      "{\"ts\":\"2026-09-01T01:30:00Z\",\"id\":\"a4\","
                      "\"host\":\"node1\",\"agent\":\"claude\","
                      "\"kind\":\"result\",\"ref\":\"a3\","
                      "\"text\":\"fourth\"}\n",
                      current);
        ASSERT(dvi_write(board_tmp, grown));
        ASSERT(rename(board_tmp, board_file) == 0);
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1);
        PASS();
    }

    TEST("index: a same-size in-place rewrite is re-ingested exactly "
        "once, not missed and not duplicated") {
        char current[900];
        FILE *f = fopen(board_file, "rb");
        ASSERT(f != NULL);
        size_t n = fread(current, 1, sizeof(current) - 1, f);
        fclose(f);
        current[n] = '\0';
        /* "fourth" -> "fifth ": same byte length, same file size, same
         * inode (an ordinary open/write/close, no rename) — the case an
         * inode-or-size check alone would miss. */
        char *hit = strstr(current, "fourth");
        ASSERT(hit != NULL);
        memcpy(hit, "fifth ", 6);
        ASSERT(dvi_write(board_file, current));

        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1); /* the rewritten line only */

        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 0); /* re-ingesting adds it exactly once */
        PASS();
    }

    TEST("index: search hits a bare word") {
        struct dev_index_search_result res;
        ASSERT(dev_index_search(db, "fifth", NULL, 10, &res, err,
                                sizeof(err)));
        ASSERT(res.count >= 1);
        ASSERT(strstr(res.hits[0].text, "fifth") != NULL);
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
        ASSERT(dev_index_source_status(db, exp_src, root, now_ms, &st, err,
                                       sizeof(err)));
        clock_reset_default();
        ASSERT(st.rows == 1);
        ASSERT(st.has_rows);
        ASSERT_STR_EQ(st.newest_ts, "2026-09-01T00:00:00Z");
        ASSERT(st.seconds_since_newest > 0);
        ASSERT(st.bytes_behind == 0);
        /* 1, not 0: the TSV header line is a deliberate never-indexed line
         * (dev_index_parse_experiment), and rows_skipped counts every line
         * that produced no row this run — header included, not just
         * genuinely malformed content. */
        ASSERT(st.rows_skipped == 1);
        PASS();
    }

    TEST("index: status rows_skipped reflects the earlier malformed line") {
        struct dev_index_source_status st;
        ASSERT(dev_index_source_status(db, board_src, root, 0, &st, err,
                                       sizeof(err)));
        ASSERT(st.rows_skipped == 1);
        PASS();
    }

    TEST("index: an unknown source id is refused by dev_index_source_find") {
        ASSERT(dev_index_source_find("not-a-real-source") == NULL);
        PASS();
    }

    TEST("index: dispatch accepts the documented --index/--state-root "
        "spelling (hyphenated), not the underscored form") {
        char disp_parent[512];
        test_make_tmpdir(disp_parent, sizeof(disp_parent), "dev_index",
                         "dispatch");
        char disp_root[600], disp_board[700], disp_index[700];
        (void)snprintf(disp_root, sizeof(disp_root), "%s/root", disp_parent);
        (void)snprintf(disp_board, sizeof(disp_board), "%s/board", disp_root);
        (void)snprintf(disp_index, sizeof(disp_index), "%s/index.db",
                      disp_parent);
        ASSERT(dvi_mkdir(disp_board));
        char disp_file[800];
        (void)snprintf(disp_file, sizeof(disp_file), "%s/node1.jsonl",
                      disp_board);
        ASSERT(dvi_write(
            disp_file,
            "{\"ts\":\"2026-09-01T00:00:00Z\",\"id\":\"d1\",\"host\":"
            "\"node1\",\"agent\":\"claude\",\"kind\":\"problem\",\"ref\":\"\","
            "\"text\":\"dispatch\"}\n"));

        struct zcl_command_reply ingest_reply;
        ASSERT(dvi_dispatch("dev.index.ingest", disp_index, disp_root,
                            &ingest_reply));
        ASSERT(ingest_reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_int(json_get(&ingest_reply.data, "rows_added")) == 1);
        zcl_command_reply_free(&ingest_reply);

        struct zcl_command_reply status_reply;
        ASSERT(dvi_dispatch("dev.index.status", disp_index, disp_root,
                            &status_reply));
        ASSERT(status_reply.status == ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_int(json_get(&status_reply.data, "index_exists"))
              != 0);
        zcl_command_reply_free(&status_reply);

        (void)test_rm_rf_recursive(disp_parent);
        PASS();
    }

    (void)log_src;
_test_next:;
    dev_index_db_close(db);
    (void)test_rm_rf_recursive(parent);
    return failures;
}
