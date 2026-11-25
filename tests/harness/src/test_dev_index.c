/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ACCEPTANCE BAR for dev.index.* (native_dev_index_{catalog,ingest,identity,
 * parse,search,command}.c).
 *
 * Exercises the catalog/ingest/search modules against a fixture root: every
 * call passes an explicit state_root_override (and index_override for
 * dev_index_db_open), and no environment variable is read, so a fixture never
 * touches the operator's real index.db or sources.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_dev_index_catalog.h"
#include "command/native_dev_index_ingest.h"
#include "command/native_dev_mail_projection.h"
#include <sqlite3.h>
#include "command/native_dev_index_parse.h"
#include "command/native_dev_index_search.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#include <unistd.h>
#endif

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

/* One log line longer than the ingest buffer, then one short line. The
 * long line's first token sits inside the buffer so a truncated store
 * would still make it searchable. */
static bool dvi_write_overlong_log(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fputs("overlongprefix ", f) >= 0;
    for (size_t i = 0; ok && i < DEV_INDEX_LINE_MAX; i++)
        ok = fputc('x', f) != EOF;
    ok = ok && fputs(" tailtoken\nkeptshortline\n", f) >= 0;
    return fclose(f) == 0 && ok;
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

/* Validate declared input keys before invoking the isolated real handler. */
static bool dvi_dispatch(const char *leaf, const char *index_val,
                         const char *state_root_val,
                         struct zcl_command_reply *reply)
{
    zcl_command_reply_init(reply, "");
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    if (index_val)
        (void)json_push_kv_str(&input, "index", index_val);
    if (state_root_val)
        (void)json_push_kv_str(&input, "state-root", state_root_val);
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), leaf, NULL);
    char why[192];
    if (!zcl_command_registry_input_validate(spec, &input, why, sizeof(why))) {
        json_free(&input);
        return false;
    }
    struct zcl_command_request request = {
        .spec = spec,
        .input = &input,
        .view = "normal",
    };
    if (strcmp(leaf, "dev.index.ingest") == 0)
        zcl_native_handle_dev_index_ingest(&request, reply);
    else if (strcmp(leaf, "dev.index.status") == 0)
        zcl_native_handle_dev_index_status(&request, reply);
    else {
        json_free(&input);
        zcl_command_reply_free(reply);
        return false;
    }
    json_free(&input);
    return true;
}

static bool dvi_refuses_underscored_root(const char *leaf, const char *root)
{
    const struct zcl_command_spec *spec =
        zcl_command_registry_find(zcl_command_catalog(), leaf, NULL);
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "state_root", root);
    char why[192];
    bool accepted =
        zcl_command_registry_input_validate(spec, &input, why, sizeof(why));
    json_free(&input);
    return !accepted && strcmp(why, "unknown input key 'state_root'") == 0;
}

static int dvi_mail_projection_checks(void)
{
    int failures = 0;
    TEST("derived mail projection preserves offsets and refuses incomplete state") {
        sqlite3 *db = NULL;
        ASSERT_EQ(sqlite3_open(":memory:", &db), SQLITE_OK);
        struct dev_mail_tuple t = {.boot="12345678-1234-1234-1234-123456789abc", .dev=1, .inode=2,
            .size=20, .mtime_ns=3, .ctime_ns=4, .frontier=20};
        struct dev_mail_locator rows[2] = {
            {.offset=0,.end=10,.seq=1,.sha3="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.ref="same"},
            {.offset=10,.end=20,.seq=1,.sha3="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.ref="same"}};
        struct dev_mail_locator got[2]; size_t n = 99;
        ASSERT(dev_mail_projection_rebuild(db,"outbox.jsonl",&t,rows,2));
        char boundary[DEV_MAIL_STREAM_MAX+1]; memset(boundary,'s',DEV_MAIL_STREAM_MAX); boundary[DEV_MAIL_STREAM_MAX]=0;
        ASSERT(dev_mail_projection_rebuild(db,boundary,&t,rows,2));
        struct dev_mail_tuple stored;
        ASSERT(dev_mail_projection_get(db,"outbox.jsonl",&stored));
        ASSERT_EQ(stored.frontier,20);
        struct dev_mail_rebuild *tx=dev_mail_projection_begin(db,"outbox.jsonl",&t);
        ASSERT(tx != NULL);
        ASSERT(dev_mail_projection_add(tx,&rows[0]));
        ASSERT(!dev_mail_projection_add(tx,&rows[0]));
        ASSERT(!dev_mail_projection_commit(tx));
        ASSERT(sqlite3_next_stmt(db,NULL)==NULL);
        tx=dev_mail_projection_begin(db,"outbox.jsonl",&t); ASSERT(tx != NULL);
        ASSERT(dev_mail_projection_add(tx,&rows[0])); ASSERT(dev_mail_projection_add(tx,&rows[1]));
        struct dev_mail_tuple changed=t; changed.ctime_ns++;
        ASSERT(!dev_mail_projection_commit_scanned(tx,&changed));
        ASSERT(sqlite3_next_stmt(db,NULL)==NULL);
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"same",got,2,&n)); ASSERT_EQ(n,2);
        tx=dev_mail_projection_begin(db,"outbox.jsonl",&t); ASSERT(tx != NULL);
        ASSERT(dev_mail_projection_add(tx,&rows[0])); ASSERT(dev_mail_projection_add(tx,&rows[1]));
        changed=t; changed.skipped=7;
        ASSERT(dev_mail_projection_commit_scanned(tx,&changed)); t=changed;
        ASSERT(sqlite3_next_stmt(db,NULL)==NULL);
        ASSERT(dev_mail_projection_get(db,"outbox.jsonl",&stored)); ASSERT_EQ(stored.skipped,7);
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"same",got,2,&n));
        ASSERT_EQ(n,2); ASSERT_EQ(got[0].offset,0); ASSERT_EQ(got[1].offset,10);
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"absent",got,2,&n)); ASSERT_EQ(n,0);
        ASSERT(!dev_mail_projection_find(db,"outbox.jsonl",&t,"same",got,1,&n)); ASSERT_EQ(n,0);
        ASSERT_EQ(dev_mail_projection_probe(db,"outbox.jsonl",&t,"same",1),DEV_MAIL_PROBE_UNKNOWN);
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"same",got,2,&n)); ASSERT_EQ(n,2);
        struct dev_mail_tuple wrong = t; wrong.boot[0] = 'f';
        ASSERT(!dev_mail_projection_find(db,"outbox.jsonl",&wrong,"same",got,2,&n));
        wrong=t; wrong.source_sha3[0]=1;
        ASSERT(!dev_mail_projection_find(db,"outbox.jsonl",&wrong,"same",got,2,&n));
        wrong = t; wrong.partial = true;
        ASSERT(!dev_mail_projection_rebuild(db,"outbox.jsonl",&wrong,rows,2));
        struct dev_mail_tuple post = t; post.size = post.frontier = 30;
        struct dev_mail_locator bad = rows[0]; bad.offset=10; bad.end=15;
        ASSERT(!dev_mail_projection_append(db,"outbox.jsonl",&t,&post,&bad,1));
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"same",got,2,&n)); ASSERT_EQ(n,2);
        bad.offset=20; bad.end=30;
        ASSERT(!dev_mail_projection_append(db,"outbox.jsonl",&wrong,&post,&bad,1));
        tx=dev_mail_projection_begin_append(db,"outbox.jsonl",&t,&post); ASSERT(tx!=NULL);
        ASSERT(dev_mail_projection_add(tx,&bad)); ASSERT(!dev_mail_projection_add(tx,&bad));
        ASSERT(!dev_mail_projection_commit(tx));
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"same",got,2,&n)); ASSERT_EQ(n,2);
        tx=dev_mail_projection_begin_append(db,"outbox.jsonl",&t,&post); ASSERT(tx!=NULL);
        ASSERT(dev_mail_projection_add(tx,&bad)); ASSERT(dev_mail_projection_commit_scanned(tx,&post));
        struct dev_mail_tuple boundary_tuple=t; boundary_tuple.skipped=0;
        ASSERT(dev_mail_projection_find(db,boundary,&boundary_tuple,"same",got,2,&n)); ASSERT_EQ(n,2);
        ASSERT(!dev_mail_projection_find(db,"outbox.jsonl",&t,"same",got,2,&n));
        ASSERT_EQ(sqlite3_exec(db,"DELETE FROM mail_projection_nodes",NULL,NULL,NULL),SQLITE_OK);
        ASSERT(!dev_mail_projection_find(db,"outbox.jsonl",&post,"same",got,2,&n)); ASSERT_EQ(n,0);
        ASSERT_EQ(dev_mail_projection_probe(db,"outbox.jsonl",&post,"same",2),DEV_MAIL_PROBE_CORRUPT);
        ASSERT_EQ(sqlite3_exec(db,"UPDATE mail_projection_streams SET partial=4294967296",NULL,NULL,NULL),SQLITE_OK);
        ASSERT(!dev_mail_projection_get(db,"outbox.jsonl",&stored));
        ASSERT_EQ(sqlite3_exec(db,"UPDATE mail_projection_streams SET ino='invalid'",NULL,NULL,NULL),SQLITE_OK);
        ASSERT(!dev_mail_projection_get(db,"outbox.jsonl",&stored));
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static int dvi_mail_busy_checks(void)
{
    int failures = 0;
    TEST("mail projection refuses busy and unsupported cache version") {
        char dir[512], path[600];
        test_make_tmpdir(dir, sizeof(dir), "dev_index", "mail_busy");
        (void)snprintf(path,sizeof(path),"%s/cache.db",dir);
        sqlite3 *a = NULL, *b = NULL;
        ASSERT_EQ(sqlite3_open(path,&a),SQLITE_OK);
        ASSERT_EQ(sqlite3_open(path,&b),SQLITE_OK);
        struct dev_mail_tuple t = {.boot="12345678-1234-1234-1234-123456789abc",.dev=1,.inode=2};
        ASSERT(dev_mail_projection_rebuild(a,"outbox.jsonl",&t,NULL,0));
        ASSERT_EQ(sqlite3_exec(a,"BEGIN IMMEDIATE",NULL,NULL,NULL),SQLITE_OK);
        ASSERT(!dev_mail_projection_rebuild(b,"outbox.jsonl",&t,NULL,0));
        ASSERT_EQ(sqlite3_exec(a,"ROLLBACK",NULL,NULL,NULL),SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(a,"BEGIN EXCLUSIVE",NULL,NULL,NULL),SQLITE_OK);
        ASSERT_EQ(dev_mail_projection_probe(b,"outbox.jsonl",&t,"x",1),DEV_MAIL_PROBE_UNKNOWN);
        ASSERT_EQ(sqlite3_exec(a,"ROLLBACK",NULL,NULL,NULL),SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(a,"UPDATE mail_projection_meta SET version=5",NULL,NULL,NULL),SQLITE_OK);
        size_t n=9;
        ASSERT(!dev_mail_projection_find(b,"outbox.jsonl",&t,"x",NULL,0,&n)); ASSERT_EQ(n,0);
        ASSERT(!dev_mail_projection_rebuild(b,"outbox.jsonl",&t,NULL,0));
        struct dev_mail_tuple stored;
        ASSERT(!dev_mail_projection_get(b,"outbox.jsonl",&stored));
        ASSERT_EQ(sqlite3_exec(a,"UPDATE mail_projection_meta SET version=1",NULL,NULL,NULL),SQLITE_OK);
        ASSERT(!dev_mail_projection_get(b,"outbox.jsonl",&stored));
        sqlite3_close(a); sqlite3_close(b);
        test_rm_rf_recursive(dir);
        PASS();
    } _test_next:;
    return failures;
}

static int dvi_mail_crash_checks(void)
{
    int failures=0;
#if !defined(_WIN32)
    TEST("mail projection rolls back an interrupted process transaction") {
        char dir[512],path[600]; test_make_tmpdir(dir,sizeof(dir),"dev_index","mail_crash");
        (void)snprintf(path,sizeof(path),"%s/cache.db",dir);
        sqlite3 *db=NULL; ASSERT_EQ(sqlite3_open(path,&db),SQLITE_OK);
        ASSERT(dev_mail_projection_index_prepare(db,true));
        sqlite3_stmt *policy=NULL;
        ASSERT_EQ(sqlite3_prepare_v2(db,"PRAGMA synchronous",-1,&policy,NULL),SQLITE_OK);
        ASSERT_EQ(sqlite3_step(policy),SQLITE_ROW); ASSERT_EQ(sqlite3_column_int(policy,0),1);
        ASSERT_EQ(sqlite3_finalize(policy),SQLITE_OK);
        struct dev_mail_tuple t={.boot="12345678-1234-1234-1234-123456789abc",.dev=1,.inode=2,.size=10,.frontier=10};
        struct dev_mail_locator row={.offset=0,.end=10,.seq=1,.sha3="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.ref="old"};
        ASSERT(dev_mail_projection_rebuild(db,"outbox.jsonl",&t,&row,1)); ASSERT_EQ(sqlite3_close(db),SQLITE_OK);
        pid_t child=fork(); ASSERT(child>=0);
        if (child==0) {
            sqlite3 *c=NULL; if (sqlite3_open(path,&c)!=SQLITE_OK) _exit(2);
            if (!dev_mail_projection_index_prepare(c,false)) _exit(4);
            struct dev_mail_tuple proposed=t; proposed.size=proposed.frontier=20;
            struct dev_mail_locator uncommitted=row; uncommitted.seq=9;
            (void)snprintf(uncommitted.ref,sizeof(uncommitted.ref),"uncommitted");
            struct dev_mail_rebuild *tx=dev_mail_projection_begin(c,"outbox.jsonl",&proposed);
            if (!tx || !dev_mail_projection_add(tx,&uncommitted)) _exit(3);
            _exit(0);
        }
        int status=0; ASSERT_EQ(waitpid(child,&status,0),child); ASSERT(WIFEXITED(status)); ASSERT_EQ(WEXITSTATUS(status),0);
        ASSERT_EQ(sqlite3_open(path,&db),SQLITE_OK);
        ASSERT(dev_mail_projection_index_prepare(db,false));
        ASSERT_EQ(sqlite3_prepare_v2(db,"PRAGMA synchronous",-1,&policy,NULL),SQLITE_OK);
        ASSERT_EQ(sqlite3_step(policy),SQLITE_ROW); ASSERT_EQ(sqlite3_column_int(policy,0),1);
        ASSERT_EQ(sqlite3_finalize(policy),SQLITE_OK);
        struct dev_mail_tuple saved; struct dev_mail_locator got[2]; size_t count=0;
        ASSERT(dev_mail_projection_get(db,"outbox.jsonl",&saved)); ASSERT_EQ(saved.frontier,10);
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"old",got,2,&count)); ASSERT_EQ(count,1);
        ASSERT_EQ(got[0].offset,0); ASSERT_EQ(got[0].end,10); ASSERT_EQ(got[0].seq,1);
        ASSERT(!strcmp(got[0].sha3,row.sha3)); ASSERT(!strcmp(got[0].ref,row.ref));
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"uncommitted",got,2,&count)); ASSERT_EQ(count,0);
        struct dev_mail_tuple after=t; after.size=after.frontier=20;
        struct dev_mail_locator next=row; next.offset=10; next.end=20; next.seq=2;
        ASSERT(dev_mail_projection_append(db,"outbox.jsonl",&t,&after,&next,1));
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&after,"old",got,2,&count)); ASSERT_EQ(count,2);
        ASSERT_EQ(sqlite3_close(db),SQLITE_OK); test_rm_rf_recursive(dir); PASS();
    } _test_next:;
#endif
    return failures;
}

static int dvi_mail_radix_checks(void)
{
    int failures=0;
    TEST("mail radix verifies mixed keys, postings and node corruption") {
        sqlite3 *db=NULL;
        ASSERT_EQ(sqlite3_open(":memory:",&db),SQLITE_OK);
        struct dev_mail_tuple t={.boot="12345678-1234-1234-1234-123456789abc",.dev=1,.inode=2,.size=40,.frontier=40};
        struct dev_mail_locator r[4]={
            {.offset=0,.end=10,.seq=1,.sha3="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.ref="alpha"},
            {.offset=10,.end=20,.seq=2,.sha3="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",.ref="beta"},
            {.offset=20,.end=30,.seq=3,.sha3="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.ref="alpha"},
            {.offset=30,.end=40,.seq=4,.sha3="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",.ref="gamma"}};
        struct dev_mail_rebuild *tx=dev_mail_projection_begin(db,"outbox.jsonl",&t);
        ASSERT(tx != NULL);
        for (size_t i=0;i<4;i++) ASSERT(dev_mail_projection_add(tx,&r[i]));
        ASSERT(dev_mail_projection_commit(tx));
        struct dev_mail_locator got[4]; size_t n=0;
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"alpha",got,4,&n));
        ASSERT_EQ(n,2); ASSERT_EQ(got[0].offset,0); ASSERT_EQ(got[1].offset,20);
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"beta",got,4,&n)); ASSERT_EQ(n,1); ASSERT_EQ(got[0].offset,10);
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&t,"missing",got,4,&n)); ASSERT_EQ(n,0);
        struct dev_mail_tuple post=t; post.size=post.frontier=50;
        struct dev_mail_locator delta={.offset=40,.end=50,.seq=5,.sha3="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",.ref="delta"};
        ASSERT(dev_mail_projection_append(db,"outbox.jsonl",&t,&post,&delta,1));
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&post,"delta",got,4,&n)); ASSERT_EQ(n,1); ASSERT_EQ(got[0].offset,40);
        ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&post,"alpha",got,4,&n)); ASSERT_EQ(n,2);
        ASSERT_EQ(sqlite3_exec(db,"UPDATE mail_projection_nodes SET body=x'00'",NULL,NULL,NULL),SQLITE_OK);
        ASSERT(!dev_mail_projection_find(db,"outbox.jsonl",&post,"alpha",got,4,&n)); ASSERT_EQ(n,0);
        sqlite3_close(db);
        PASS();
    } _test_next:;
    return failures;
}

static bool dvi_mail_node_metrics(sqlite3 *db, const char *phase)
{
    sqlite3_stmt *st=NULL;
    if (sqlite3_prepare_v2(db,"SELECT count(*),coalesce(sum(length(body)),0) FROM mail_projection_nodes",-1,&st,NULL)!=SQLITE_OK) return false;
    bool ok=sqlite3_step(st)==SQLITE_ROW;
    if (ok) printf("mail radix %s: nodes=%lld bytes=%lld\n",phase,
        (long long)sqlite3_column_int64(st,0),(long long)sqlite3_column_int64(st,1));
    sqlite3_finalize(st); return ok;
}

static int64_t dvi_mail_node_count(sqlite3 *db)
{
    sqlite3_stmt *st=NULL; int64_t count=-1;
    if (sqlite3_prepare_v2(db,"SELECT count(*) FROM mail_projection_nodes",-1,&st,NULL)==SQLITE_OK &&
        sqlite3_step(st)==SQLITE_ROW) count=sqlite3_column_int64(st,0);
    sqlite3_finalize(st); return count;
}

static int dvi_mail_radix_oracle(void)
{
    int failures=0;
    TEST("mail radix matches an interleaved locator oracle") {
        sqlite3 *db=NULL;
        ASSERT_EQ(sqlite3_open(":memory:",&db),SQLITE_OK);
        struct dev_mail_tuple before={.boot="12345678-1234-1234-1234-123456789abc",.dev=1,.inode=2,.size=320,.frontier=320};
        struct dev_mail_tuple after=before; after.size=after.frontier=640;
        struct dev_mail_locator rows[64]; memset(rows,0,sizeof(rows));
        for (size_t i=0;i<64;i++) {
            rows[i].offset=(int64_t)i*10; rows[i].end=rows[i].offset+10; rows[i].seq=(int64_t)i+1;
            memset(rows[i].sha3,'a'+(int)(i%6),64); rows[i].sha3[64]=0;
            (void)snprintf(rows[i].ref,sizeof(rows[i].ref),"ref-%zu",i%9);
        }
        struct dev_mail_rebuild *tx=dev_mail_projection_begin(db,"outbox.jsonl",&before);
        ASSERT(tx!=NULL);
        for (size_t i=0;i<32;i++) ASSERT(dev_mail_projection_add(tx,&rows[i]));
        ASSERT(dev_mail_projection_commit(tx));
        ASSERT(dvi_mail_node_metrics(db,"rebuild32"));
        ASSERT(dev_mail_projection_append(db,"outbox.jsonl",&before,&after,rows+32,32));
        ASSERT(dvi_mail_node_metrics(db,"append32"));
        int64_t node_count=dvi_mail_node_count(db);
        ASSERT(node_count>0);
        for (int i=0;i<3;i++) {
            ASSERT(dev_mail_projection_rebuild(db,"outbox.jsonl",&after,rows,64));
            ASSERT_EQ(dvi_mail_node_count(db),node_count);
        }
        for (size_t key=0;key<10;key++) {
            char ref[32]; (void)snprintf(ref,sizeof(ref),"ref-%zu",key);
            struct dev_mail_locator got[64]; size_t count=0, expected=0;
            ASSERT(dev_mail_projection_find(db,"outbox.jsonl",&after,ref,got,64,&count));
            for (size_t i=0;i<64;i++) if (!strcmp(rows[i].ref,ref)) {
                ASSERT(expected<count); ASSERT_EQ(got[expected].offset,rows[i].offset);
                ASSERT_EQ(got[expected].end,rows[i].end); ASSERT_EQ(got[expected].seq,rows[i].seq);
                ASSERT_STR_EQ(got[expected].sha3,rows[i].sha3); expected++;
            }
            ASSERT_EQ(count,expected);
        }
        ASSERT_EQ(sqlite3_exec(db,"DELETE FROM mail_projection_nodes WHERE substr(body,1,1)=x'50'",NULL,NULL,NULL),SQLITE_OK);
        struct dev_mail_locator got[64]; size_t count=99;
        ASSERT(!dev_mail_projection_find(db,"outbox.jsonl",&after,"ref-0",got,64,&count)); ASSERT_EQ(count,0);
        sqlite3_close(db); PASS();
    } _test_next:;
    return failures;
}

static int dvi_mail_refcount_checks(void)
{
    int failures=0;
    TEST("mail radix refuses corrupt node ownership") {
        sqlite3 *db=NULL; ASSERT_EQ(sqlite3_open(":memory:",&db),SQLITE_OK);
        struct dev_mail_tuple t={.boot="12345678-1234-1234-1234-123456789abc",.dev=1,.inode=2,.size=10,.frontier=10};
        struct dev_mail_locator r={.offset=0,.end=10,.seq=1,.sha3="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.ref="x"};
        ASSERT(dev_mail_projection_rebuild(db,"outbox.jsonl",&t,&r,1));
        ASSERT_EQ(sqlite3_exec(db,"UPDATE mail_projection_nodes SET refs=0",NULL,NULL,NULL),SQLITE_OK);
        struct dev_mail_locator got; size_t n=99;
        ASSERT(!dev_mail_projection_find(db,"outbox.jsonl",&t,"x",&got,1,&n)); ASSERT_EQ(n,0);
        ASSERT(!dev_mail_projection_rebuild(db,"outbox.jsonl",&t,&r,1));
        sqlite3_close(db); PASS();
    } _test_next:;
    return failures;
}

static int dvi_mail_reset_checks(void)
{
    int failures=0;
    TEST("mail cache reset preserves generic index tables") {
        sqlite3 *db=NULL; ASSERT_EQ(sqlite3_open(":memory:",&db),SQLITE_OK);
        ASSERT_EQ(sqlite3_exec(db,"CREATE TABLE rows(x); INSERT INTO rows VALUES(42); CREATE TABLE cursors(x); INSERT INTO cursors VALUES(9)",NULL,NULL,NULL),SQLITE_OK);
        struct dev_mail_tuple t={.boot="12345678-1234-1234-1234-123456789abc",.dev=1,.inode=2};
        ASSERT(dev_mail_projection_rebuild(db,"outbox.jsonl",&t,NULL,0));
        ASSERT(dev_mail_projection_reset(db));
        struct dev_mail_tuple stored; ASSERT(!dev_mail_projection_get(db,"outbox.jsonl",&stored));
        sqlite3_stmt *st=NULL;
        ASSERT_EQ(sqlite3_prepare_v2(db,"SELECT (SELECT x FROM rows),(SELECT x FROM cursors)",-1,&st,NULL),SQLITE_OK);
        ASSERT_EQ(sqlite3_step(st),SQLITE_ROW); ASSERT_EQ(sqlite3_column_int(st,0),42); ASSERT_EQ(sqlite3_column_int(st,1),9);
        sqlite3_finalize(st); sqlite3_close(db); PASS();
    } _test_next:;
    return failures;
}

int test_dev_index(void);
int test_dev_index(void)
{
    int failures = 0;
    failures += dvi_mail_projection_checks();
    failures += dvi_mail_busy_checks();
    failures += dvi_mail_crash_checks();
    failures += dvi_mail_radix_checks();
    failures += dvi_mail_radix_oracle();
    failures += dvi_mail_refcount_checks();
    failures += dvi_mail_reset_checks();
    sqlite3 *db = NULL;
    char parent[512];
    test_make_tmpdir(parent, sizeof(parent), "dev_index", "fixture");

    /* One fixture root serves every source: --state-root=<root> applies to
     * board/experiments/logs and landing alike (see
     * dev_index_source_resolve_root). */
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

    /* dev_index_db_open's schema uses `CREATE VIRTUAL TABLE ... USING fts5`;
     * a sqlite build without FTS5 fails this open and the assert names it. */
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
        /* "fourth" -> "fifth ": same length, size and inode (no rename),
         * which an inode-or-size check alone would miss. */
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
        ASSERT(dvi_append(
            board_file,
            "{\"ts\":\"2026-09-01T03:00:00Z\",\"id\":\"scope-other\","
            "\"host\":\"node1\",\"agent\":\"fixture\",\"kind\":\"note\","
            "\"ref\":\"\",\"text\":\"state:landed\"}\n"));
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1);
        struct dev_index_search_result res;
        ASSERT(dev_index_search(db, "state:landed", NULL, 10, &res, err,
                                sizeof(err)));
        ASSERT(res.count == 2);
        ASSERT_STR_EQ(res.hits[0].source_id, "board");
        ASSERT_STR_EQ(res.hits[1].source_id, "landing");
        ASSERT(dev_index_search(db, "state:landed", "landing", 10, &res, err,
                                sizeof(err)));
        ASSERT(res.count == 1);
        ASSERT_STR_EQ(res.hits[0].source_id, "landing");
        PASS();
    }

    TEST("index: status numbers are exact under the injected clock") {
        struct dvi_fake_clock fc;
        atomic_store(&fc.mono_ns, (int64_t)0);
        atomic_store(&fc.wall_ms, (int64_t)1788300000000LL); /* 2026-09-01T22:00:00Z */
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
        ASSERT(st.seconds_since_newest == 79200);
        ASSERT(st.bytes_behind == 0);
        /* 1, not 0: the TSV header line is deliberately never indexed and
         * rows_skipped counts every line that produced no row. */
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

        ASSERT(dvi_refuses_underscored_root("dev.index.ingest", disp_root));
        ASSERT(dvi_refuses_underscored_root("dev.index.status", disp_root));

        (void)test_rm_rf_recursive(disp_parent);
        PASS();
    }

    TEST("index: a line past the import bound is skipped, not stored "
        "truncated") {
        char log_file[800];
        (void)snprintf(log_file, sizeof(log_file), "%s/note.log", root);
        ASSERT(dvi_write_overlong_log(log_file));
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, log_src, root, &r, err,
                                       sizeof(err)));
        ASSERT(r.rows_added == 1);
        ASSERT(r.rows_skipped == 1);
        struct dev_index_search_result res;
        ASSERT(dev_index_search(db, "overlongprefix", "logs", 10, &res, err,
                                sizeof(err)));
        ASSERT(res.count == 0);
        ASSERT(dev_index_search(db, "keptshortline", "logs", 10, &res, err,
                                sizeof(err)));
        ASSERT(res.count == 1);
        ASSERT(strstr(res.hits[0].text, "keptshortline") != NULL);
        PASS();
    }

    TEST("index: byte framing skips NUL and oversized prefixes, keeps next row") {
        char path[800];
        (void)snprintf(path, sizeof(path), "%s/framing.jsonl", board_dir);
        const char a[] = "{\"id\":\"framing-a\",\"text\":\"framinghidden\"}";
        const char b[] = "{\"id\":\"framing-b\",\"text\":\"framingkept\"}\n";
        FILE *fp = fopen(path, "wb");
        ASSERT(fp != NULL);
        ASSERT(fwrite(a, 1, sizeof(a) - 1, fp) == sizeof(a) - 1);
        ASSERT(fwrite("\0junk\n", 1, 6, fp) == 6);
        ASSERT(fputs(b, fp) >= 0);
        ASSERT(fclose(fp) == 0);
        struct dev_index_ingest_result r;
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 1 && r.rows_skipped == 1);
        struct dev_index_search_result res;
        ASSERT(dev_index_search(db, "framinghidden", "board", 10, &res,
                                err, sizeof(err)));
        ASSERT(res.count == 0);
        ASSERT(dev_index_search(db, "framingkept", "board", 10, &res,
                                err, sizeof(err)));
        ASSERT(res.count == 1);
        struct dev_index_source_status st;
        ASSERT(dev_index_source_status(db, board_src, root, 0, &st,
                                       err, sizeof(err)));
        ASSERT(st.bytes_behind == 0);
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 0 && r.rows_skipped == 0);
        fp = fopen(path, "ab");
        ASSERT(fp != NULL);
        ASSERT(fputs(a, fp) >= 0);
        for (size_t i = sizeof(a) - 1; i < DEV_INDEX_LINE_MAX - 1; i++)
            ASSERT(fputc(' ', fp) != EOF);
        ASSERT(fputs("junk\n{\"id\":\"framing-partial\"", fp) >= 0);
        ASSERT(fclose(fp) == 0);
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 0 && r.rows_skipped == 1);
        ASSERT(dev_index_source_status(db, board_src, root, 0, &st,
                                       err, sizeof(err)));
        ASSERT(st.bytes_behind == (int64_t)strlen("{\"id\":\"framing-partial\""));
        ASSERT(dvi_append(path, ",\"text\":\"framingcompleted\"}\n"));
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 1 && r.rows_skipped == 0);
        ASSERT(dvi_append(path, "{\"id\":\"framing-positive-a\"}\n"
                                "{\"id\":\"framing-positive-b\"}\n"));
        ASSERT(dev_index_ingest_source(db, board_src, root, &r, err, sizeof(err)));
        ASSERT(r.rows_added == 2 && r.rows_skipped == 0);
        PASS();
    }

_test_next:;
    dev_index_db_close(db);
    (void)test_rm_rf_recursive(parent);
    return failures;
}
