/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_dev_port_table: proof for the dev.vcs.ports leaf. A throwaway
 * repository carries a base that moved after a contributor branch forked and
* a five-commit branch that lands in each of the four classes:
 *
 *   add "d" file      APPLIES   (also edits a generated doc: not counted)
 *   touch two         CONFLICT  (the base rewrote the same line)
 *   already on base   ON_BASE   (the base already carries the change)
 *   tweak nine        APPLIES   (plain apply rejects it, the 3-way fallback places it)
 *   docs only         EMPTY     (only docs/dev/CODEBASE_MAP.md)
 *
 * The handler is called directly with GIT_DIR/GIT_INDEX_FILE poisoned in the
 * process environment: the leaf must ignore them, must leave refs, the real
 * index and the working tree untouched, and must remove its temp directory.
 * The repository sets its identity locally, never signs, and runs with hooks
 * disabled, so it does not depend on the host's git configuration. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PTT_SHA 80
#define E_ROOT "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n"
#define E_TOPIC "1\n2\n3\n4\n5\n6\n7\n8\nnine\n10\n11\n12\n"
#define E_BASE "1\n2\n3\n4\n5\nsix\n7\n8\n9\n10\n11\n12\n"

/* Run `git -C dir <args>` with this test's own isolation: routing variables
 * stripped, no global/system config, local identity, no signing, no hooks. */
static int ptt_git(const char *dir, const char *const *args, char *out,
                   size_t cap)
{
    const char *argv[48];
    size_t n = 0;
    char sink[2];
    static const char *const head[] = {
        "env", "-u", "GIT_DIR", "-u", "GIT_WORK_TREE", "-u", "GIT_INDEX_FILE",
        "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
        "GIT_OPTIONAL_LOCKS=0", "git", "-C"};
    for (size_t i = 0; i < sizeof(head) / sizeof(head[0]); i++)
        argv[n++] = head[i];
    argv[n++] = dir;
    argv[n++] = "-c";
    argv[n++] = "user.name=Port Table";
    argv[n++] = "-c";
    argv[n++] = "user.email=port-table@example.invalid";
    argv[n++] = "-c";
    argv[n++] = "commit.gpgsign=false";
    argv[n++] = "-c";
    argv[n++] = "core.hooksPath=/dev/null";
    for (size_t i = 0; args[i]; i++) {
        if (n + 2 > sizeof(argv) / sizeof(argv[0]))
            return -1;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    if (out && cap)
        out[0] = '\0';
    return zcl_spawn_capture(argv, out ? out : sink, out ? cap : sizeof(sink),
                             60000);
}

#define PTT_G(dir, ...) \
    (ptt_git((dir), (const char *const[]){__VA_ARGS__, NULL}, NULL, 0) == 0)

static bool ptt_write(const char *dir, const char *name, const char *text)
{
    char path[PATH_MAX];
    FILE *f;
    int n = snprintf(path, sizeof(path), "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool ptt_commit(const char *dir, const char *subject)
{
    return PTT_G(dir, "add", "-A") &&
           PTT_G(dir, "commit", "-q", "--no-verify", "-m", subject);
}

static bool ptt_rev(const char *dir, const char *rev, char out[PTT_SHA])
{
    const char *args[] = {"rev-parse", "--verify", rev, NULL};
    size_t n;
    if (ptt_git(dir, args, out, PTT_SHA) != 0)
        return false;
    n = strlen(out);
    while (n && (out[n - 1] == '\n' || out[n - 1] == ' '))
        out[--n] = '\0';
    return n > 0;
}

static bool ptt_rig_topic(const char *dir)
{
    char path[PATH_MAX];
    (void)snprintf(path, sizeof(path), "%s/docs", dir);
    if (mkdir(path, 0700) != 0)
        return false;
    (void)snprintf(path, sizeof(path), "%s/docs/dev", dir);
    if (mkdir(path, 0700) != 0 || !PTT_G(dir, "checkout", "-q", "-b", "topic"))
        return false;
    return ptt_write(dir, "d.txt", "d\n") &&
           ptt_write(dir, "docs/CAPABILITY_INVENTORY.jsonl", "{}\n") &&
           ptt_commit(dir, "add \"d\" file") &&
           ptt_write(dir, "a.txt", "one\nTWO\nthree\n") &&
           ptt_commit(dir, "touch two") &&
           ptt_write(dir, "c.txt", "y\n") &&
           ptt_commit(dir, "already on base") &&
           ptt_write(dir, "e.txt", E_TOPIC) &&
           ptt_commit(dir, "tweak nine") &&
           ptt_write(dir, "docs/dev/CODEBASE_MAP.md", "map\n") &&
           ptt_commit(dir, "docs only");
}

static bool ptt_rig_base_moves(const char *dir)
{
    return PTT_G(dir, "checkout", "-q", "main") &&
           ptt_write(dir, "a.txt", "one\ndeux\nthree\n") &&
           ptt_write(dir, "c.txt", "y\n") &&
           ptt_write(dir, "e.txt", E_BASE) && ptt_commit(dir, "base moves");
}

static bool ptt_rig_orphan(const char *dir)
{
    return PTT_G(dir, "checkout", "-q", "--orphan", "orphan") &&
           PTT_G(dir, "rm", "-rfq", ".") && ptt_write(dir, "o.txt", "o\n") &&
           ptt_commit(dir, "orphan root") && PTT_G(dir, "checkout", "-q", "main");
}

static bool ptt_rig(const char *dir)
{
    return PTT_G(dir, "init", "-q", "-b", "main") &&
           ptt_write(dir, "a.txt", "one\ntwo\nthree\n") &&
           ptt_write(dir, "c.txt", "x\n") && ptt_write(dir, "e.txt", E_ROOT) &&
           ptt_commit(dir, "root") && ptt_rig_topic(dir) &&
           ptt_rig_base_moves(dir) && ptt_rig_orphan(dir);
}

/* Call the leaf with a poisoned git environment; returns false on a
 * harness-level failure (the reply still carries the verdict). */
static bool ptt_call(const char *dir, const char *tmproot, const char *input,
                     struct zcl_command_reply *reply)
{
    struct json_value in;
    struct zcl_command_request req;
    bool ok;
    json_init(&in);
    ok = json_read(&in, input, strlen(input));
    memset(&req, 0, sizeof(req));
    req.input = &in;
    zcl_command_reply_init(reply, "zcl.dev_port_table.v1");
    (void)tmproot;
    (void)setenv("ZCL_DEV_SOURCE_ROOT", dir, 1);
    (void)setenv("GIT_INDEX_FILE", "/nonexistent/poison-index", 1);
    (void)setenv("GIT_DIR", "/nonexistent/poison-gitdir", 1);
    if (ok)
        zcl_native_handle_dev_port_table(&req, reply);
    (void)unsetenv("GIT_INDEX_FILE");
    (void)unsetenv("GIT_DIR");
    (void)unsetenv("ZCL_DEV_SOURCE_ROOT");
    json_free(&in);
    return ok;
}

static const char *ptt_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = json_get(obj, key);
    const char *s = v ? json_get_str(v) : NULL;
    return s ? s : "";
}

static int64_t ptt_count(const struct json_value *data, const char *klass)
{
    const struct json_value *counts = json_get(data, "counts");
    const struct json_value *v = counts ? json_get(counts, klass) : NULL;
    return v ? json_get_int(v) : -1;
}

static bool ptt_row_is(const struct json_value *data, size_t i,
                       const char *klass, const char *subject, int64_t files)
{
    const struct json_value *rows = json_get(data, "rows");
    const struct json_value *row = rows ? json_at(rows, i) : NULL;
    const struct json_value *f = row ? json_get(row, "files_changed") : NULL;
    return row && strcmp(ptt_str(row, "class"), klass) == 0 &&
           strcmp(ptt_str(row, "subject"), subject) == 0 && f &&
           json_get_int(f) == files && strlen(ptt_str(row, "sha")) >= 40;
}

static bool ptt_full_table_ok(const struct json_value *d)
{
    return ptt_count(d, "APPLIES") == 2 && ptt_count(d, "ON_BASE") == 1 &&
           ptt_count(d, "CONFLICT") == 1 && ptt_count(d, "EMPTY") == 1 &&
           json_get_int(json_get(d, "total")) == 5 &&
           !json_get_bool(json_get(d, "truncated")) &&
           ptt_row_is(d, 0, "APPLIES", "add \"d\" file", 1) &&
           ptt_row_is(d, 1, "CONFLICT", "touch two", 1) &&
           ptt_row_is(d, 2, "ON_BASE", "already on base", 1) &&
           ptt_row_is(d, 3, "APPLIES", "tweak nine", 1) &&
           ptt_row_is(d, 4, "EMPTY", "docs only", 0);
}

static bool ptt_refused(struct zcl_command_reply *r, const char *code)
{
    return r->status == ZCL_COMMAND_STATUS_FAILED &&
           r->exit_code == ZCL_COMMAND_EXIT_INVALID &&
           strcmp(r->error.code, code) == 0;
}

static bool ptt_refusal_case(const char *dir, const char *tmp,
                             const char *input, const char *code)
{
    struct zcl_command_reply r;
    bool ok = ptt_call(dir, tmp, input, &r) && ptt_refused(&r, code);
    zcl_command_reply_free(&r);
    return ok;
}

static bool ptt_refusals_ok(const char *dir, const char *tmp)
{
    return ptt_refusal_case(dir, tmp, "{\"base\":\"-x\",\"tip\":\"topic\"}",
                            "INVALID_REV") &&
           ptt_refusal_case(dir, tmp,
                            "{\"base\":\"main\",\"tip\":\"to pic;\"}",
                            "INVALID_REV") &&
           ptt_refusal_case(dir, tmp,
                            "{\"base\":\"main\",\"tip\":\"topic\","
                            "\"limit\":257}",
                            "LIMIT_TOO_LARGE") &&
           ptt_refusal_case(dir, tmp, "{\"tip\":\"topic\"}", "MISSING_BASE") &&
           ptt_refusal_case(dir, tmp, "{\"base\":\"main\"}", "MISSING_TIP") &&
           ptt_refusal_case(dir, tmp,
                            "{\"base\":\"main\",\"tip\":\"no-such-rev\"}",
                            "UNRESOLVABLE_REV") &&
           ptt_refusal_case(dir, tmp,
                            "{\"base\":\"main\",\"tip\":\"orphan\"}",
                            "NO_MERGE_BASE");
}

/* Refs, the real index and the working tree must be exactly as rigged. */
static bool ptt_untouched(const char *dir, const char *main_sha,
                          const char *topic_sha)
{
    char now[PTT_SHA];
    char out[256];
    const char *status[] = {"status", "--porcelain", NULL};
    const char *cached[] = {"diff", "--cached", "--name-only", NULL};
    return ptt_rev(dir, "main", now) && strcmp(now, main_sha) == 0 &&
           ptt_rev(dir, "topic", now) && strcmp(now, topic_sha) == 0 &&
           ptt_git(dir, status, out, sizeof(out)) == 0 && out[0] == '\0' &&
           ptt_git(dir, cached, out, sizeof(out)) == 0 && out[0] == '\0';
}

static bool ptt_table_case(const char *dir, const char *tmp)
{
    struct zcl_command_reply r;
    char mb[PTT_SHA], tip[PTT_SHA], base[PTT_SHA];
    bool ok = ptt_call(dir, tmp,
                       "{\"base\":\"main\",\"tip\":\"topic\"}", &r) &&
              r.status == ZCL_COMMAND_STATUS_PASSED && ptt_full_table_ok(&r.data) &&
              ptt_rev(dir, "main", base) && ptt_rev(dir, "topic", tip) &&
              ptt_rev(dir, "main~1", mb) &&
              strcmp(ptt_str(&r.data, "base"), base) == 0 &&
              strcmp(ptt_str(&r.data, "tip"), tip) == 0 &&
              strcmp(ptt_str(&r.data, "merge_base"), mb) == 0;
    zcl_command_reply_free(&r);
    return ok;
}

static bool ptt_limit_case(const char *dir, const char *tmp)
{
    struct zcl_command_reply r;
    const struct json_value *rows;
    bool ok = ptt_call(dir, tmp,
                       "{\"base\":\"main\",\"tip\":\"topic\",\"limit\":2}",
                       &r) &&
              r.status == ZCL_COMMAND_STATUS_PASSED;
    rows = ok ? json_get(&r.data, "rows") : NULL;
    ok = ok && rows && json_size(rows) == 2 &&
         json_get_int(json_get(&r.data, "total")) == 5 &&
         json_get_bool(json_get(&r.data, "truncated")) &&
         ptt_count(&r.data, "APPLIES") == 1 &&
         ptt_count(&r.data, "CONFLICT") == 1 &&
         ptt_count(&r.data, "ON_BASE") == 0;
    zcl_command_reply_free(&r);
    return ok;
}

struct ptt_fix {
    char dir[PATH_MAX];
    char tmp[PATH_MAX + 8];
    char main_sha[PTT_SHA];
    char topic_sha[PTT_SHA];
};

static int ptt_t_rig(struct ptt_fix *fx)
{
    int failures = 0;
    TEST_CASE("dev_port_table: rigging the throwaway repository") {
        ASSERT(test_mkdtemp(fx->dir, sizeof(fx->dir), "dev_port_table") != NULL);
        ASSERT(snprintf(fx->tmp, sizeof(fx->tmp), "%s/tmpd", fx->dir) > 0);
        ASSERT(ptt_rig(fx->dir));
        /* Scratch parent for the leaf's own mkdtemp; created after the last
         * commit and empty, so git never reports it. */
        ASSERT(mkdir(fx->tmp, 0700) == 0);
        ASSERT(ptt_rev(fx->dir, "main", fx->main_sha));
        ASSERT(ptt_rev(fx->dir, "topic", fx->topic_sha));
    } TEST_END
    return failures;
}

static int ptt_t_table(const struct ptt_fix *fx)
{
    int failures = 0;
    TEST_CASE("dev_port_table: four commits land in four classes") {
        ASSERT(ptt_table_case(fx->dir, fx->tmp));
    } TEST_END
    return failures;
}

static int ptt_t_limit(const struct ptt_fix *fx)
{
    int failures = 0;
    TEST_CASE("dev_port_table: limit truncates oldest-first and says so") {
        ASSERT(ptt_limit_case(fx->dir, fx->tmp));
    } TEST_END
    return failures;
}

static int ptt_t_refusals(const struct ptt_fix *fx)
{
    int failures = 0;
    TEST_CASE("dev_port_table: refusals are typed") {
        ASSERT(ptt_refusals_ok(fx->dir, fx->tmp));
    } TEST_END
    return failures;
}

/* True when no z23-port-table-* leftover sits in <dir>/.git. */
static bool ptt_gitdir_clean(const char *dir)
{
    char path[PATH_MAX];
    struct dirent *e;
    DIR *d;
    bool clean = true;
    if (snprintf(path, sizeof(path), "%s/.git", dir) <= 0)
        return false;
    d = opendir(path);
    if (!d)
        return false;
    while ((e = readdir(d)) != NULL)
        if (strncmp(e->d_name, "z23-port-table-", 15) == 0)
            clean = false;
    (void)closedir(d);
    return clean;
}

static int ptt_t_readonly(const struct ptt_fix *fx)
{
    int failures = 0;
    TEST_CASE("dev_port_table: read-only; temp dir removed") {
        /* Every earlier call must have removed its own mkdtemp child of the
         * git directory. */
        ASSERT(ptt_gitdir_clean(fx->dir));
        ASSERT(ptt_untouched(fx->dir, fx->main_sha, fx->topic_sha));
    } TEST_END
    return failures;
}

int test_dev_port_table(void)
{
    int failures = 0;
    struct ptt_fix fx;
    memset(&fx, 0, sizeof(fx));
    failures += ptt_t_rig(&fx);
    failures += ptt_t_table(&fx);
    failures += ptt_t_limit(&fx);
    failures += ptt_t_refusals(&fx);
    failures += ptt_t_readonly(&fx);
    if (fx.dir[0] != '\0')
        (void)test_rm_rf_recursive(fx.dir);
    return failures;
}
