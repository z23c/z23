/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.batch.slim, the C form of the lab bridge slim-stacks.sh. It
 *          deletes the regenerable build/ and test-tmp/ of FINISHED stack
 *          worktrees (11-01: 58 finished stacks held ~3 GB of build each and
 *          took the host to 27 GB free). A stack is finished when no running
 *          user unit names it, no process has its cwd inside it, and its
 *          build/ is older than two hours. At most --max (default 4) stacks
 *          are slimmed per call, in version order (z23-stacks10 before 100).
 *
 * Reads, all under --home (default $HOME): development/z23/z23-stacks*; the
 * running units from `systemctl --user` (--systemctl names the program); the
 * cwd of every process from --proc-dir (default /proc).
 *
 * SHADOW STEP. slim-stacks.sh keeps acting. --dry-run lists what would be
 * slimmed and deletes nothing; it is the mode run against a live host. */

#include "command/native_dev_batch.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#if !defined(_WIN32)
#include <sys/statvfs.h>
#endif

#define SL_FRESH_S (120 * 60)
#define SL_MAX_DEFAULT 4
#define SL_DEPTH 64

/* A set of stack numbers kept as "\n12\n345\n" so membership is one strstr. */
struct sl_set {
    char *p;
    size_t n;
};

static bool sl_set_add(struct sl_set *s, const char *digits, size_t len)
{
    char *grown = zcl_realloc(s->p, s->n + len + 3, "sl_set");
    if (!grown)
        return false;
    s->p = grown;
    if (s->n == 0)
        s->p[s->n++] = '\n';
    memcpy(s->p + s->n, digits, len);
    s->n += len;
    s->p[s->n++] = '\n';
    s->p[s->n] = '\0';
    return true;
}

static bool sl_set_has(const struct sl_set *s, const char *k)
{
    char needle[64];
    if (!s->p || snprintf(needle, sizeof(needle), "\n%s\n", k) >= (int)sizeof(needle))
        return false;
    return strstr(s->p, needle) != NULL;
}

/* grep -o 'stacks\?-\?s\?[0-9][0-9]*': the digits after "stack", an optional
 * s, an optional hyphen and an optional s. */
static bool sl_units_numbers(struct sl_set *running, const char *text)
{
    const char *at = text;
    while ((at = strstr(at, "stack")) != NULL) {
        const char *p = at + 5, *d;
        at = p;
        if (*p == 's')
            p++;
        if (*p == '-')
            p++;
        if (*p == 's')
            p++;
        for (d = p; isdigit((unsigned char)*d); d++)
            ;
        if (d > p && !sl_set_add(running, p, (size_t)(d - p)))
            return false;
    }
    return true;
}

/* The number in the last "/z23-stacks<digits>" of a path, as sed's greedy
 * ".*" reads it. */
static bool sl_path_number(struct sl_set *busy, const char *path)
{
    static const char tag[] = "/z23-stacks";
    const char *at = path, *last = NULL, *d;
    while ((at = strstr(at, tag)) != NULL) {
        if (isdigit((unsigned char)at[sizeof(tag) - 1]))
            last = at + sizeof(tag) - 1;
        at += sizeof(tag) - 1;
    }
    if (!last)
        return true;
    for (d = last; isdigit((unsigned char)*d); d++)
        ;
    return sl_set_add(busy, last, (size_t)(d - last));
}

static bool sl_busy_numbers(struct sl_set *busy, const char *proc_dir)
{
    DIR *dir = opendir(proc_dir);
    struct dirent *ent;
    char link[DB_PATH + 64], target[DB_PATH];
    bool ok = true;
    if (!dir)
        return true;
    while (ok && (ent = readdir(dir)) != NULL) {
        ssize_t n;
        if (!isdigit((unsigned char)ent->d_name[0]))
            continue;
        if (snprintf(link, sizeof(link), "%s/%s/cwd", proc_dir,
                     ent->d_name) >= (int)sizeof(link))
            continue;
        n = readlink(link, target, sizeof(target) - 1);
        if (n <= 0)
            continue;
        target[n] = '\0';
        ok = sl_path_number(busy, target);
    }
    (void)closedir(dir);
    return ok;
}

/* ── deleting ──────────────────────────────────────────────────────────── */

/* rm -rf that never follows a symlink and stops at SL_DEPTH. */
static bool sl_rm_rf(const char *path, int depth)
{
    struct stat st;
    DIR *dir;
    struct dirent *ent;
    bool ok = true;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    if (depth >= SL_DEPTH || !(dir = opendir(path)))
        return false;
    while ((ent = readdir(dir)) != NULL) {
        char child[DB_PATH + 280];
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;
        if (snprintf(child, sizeof(child), "%s/%s", path, ent->d_name) >=
                (int)sizeof(child) ||
            !sl_rm_rf(child, depth + 1))
            ok = false;
    }
    (void)closedir(dir);
    return rmdir(path) == 0 && ok;
}

static long sl_free_gb(void)
{
#if !defined(_WIN32)
    struct statvfs sv;
    if (statvfs("/", &sv) == 0) {
        unsigned long long b = (unsigned long long)sv.f_bavail * sv.f_frsize;
        return (long)((b + (1ull << 30) - 1) >> 30);
    }
#endif
    return -1;
}

/* ── the stacks ────────────────────────────────────────────────────────── */

static int sl_vercmp(const void *a, const void *b)
{
    const char *x = *(const char *const *)a, *y = *(const char *const *)b;
    const char *xs = x + strlen("z23-stacks"), *ys = y + strlen("z23-stacks");
    unsigned long nx = strtoul(xs, NULL, 10), ny = strtoul(ys, NULL, 10);
    if (nx != ny)
        return nx < ny ? -1 : 1;
    return strcmp(x, y);
}

static char **sl_list_stacks(const char *root, size_t *count)
{
    DIR *dir = opendir(root);
    struct dirent *ent;
    char **v = NULL;
    size_t n = 0, cap = 0;
    *count = 0;
    if (!dir)
        return NULL;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "z23-stacks", 10) != 0)
            continue;
        if (n == cap) {
            char **g = zcl_realloc(v, (cap ? cap * 2 : 64) * sizeof(*v),
                                   "sl_stacks");
            if (!g)
                break;
            v = g;
            cap = cap ? cap * 2 : 64;
        }
        v[n] = zcl_strdup(ent->d_name, "sl_stack_name");
        if (v[n])
            n++;
    }
    (void)closedir(dir);
    if (n > 1)
        qsort(v, n, sizeof(*v), sl_vercmp);
    *count = n;
    return v;
}

static bool sl_isdir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool sl_build_fresh(const char *build)
{
    struct stat st;
    return stat(build, &st) == 0 &&
           platform_time_wall_time_t() - st.st_mtime < SL_FRESH_S;
}

struct sl_ctx {
    struct sl_set running, busy;
    char root[DB_PATH];
    int max;
    bool dry;
    size_t slimmed;
    struct json_value done, skipped, lines;
};

static void sl_note_skip(struct sl_ctx *c, const char *name, const char *why)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "stack", name);
    (void)json_push_kv_str(&row, "reason", why);
    (void)json_push_back(&c->skipped, &row);
    json_free(&row);
}

/* Why a stack is not finished, or NULL when it is. */
static const char *sl_unfinished(const struct sl_ctx *c, const char *name,
                                 const char *build)
{
    const char *k = name + strlen("z23-stacks");
    if (sl_set_has(&c->running, k))
        return "unit running";
    if (sl_set_has(&c->busy, k))
        return "process cwd inside";
    if (sl_build_fresh(build))
        return "build younger than 2h";
    return NULL;
}

static void sl_slim_one(struct sl_ctx *c, const char *name, const char *dir,
                        const char *build, const char *tmp)
{
    char line[DB_PATH + 128];
    struct json_value row;
    bool ok = c->dry || ((!sl_isdir(build) || sl_rm_rf(build, 0)) &&
                         (!sl_isdir(tmp) || sl_rm_rf(tmp, 0)));
    if (!ok) {
        sl_note_skip(c, name, "delete failed");
        return;
    }
    (void)snprintf(line, sizeof(line), "slim-stacks: %s %s (%ldG free)",
                   c->dry ? "would slim" : "slimmed", name, sl_free_gb());
    db_push_str(&c->lines, line);
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "stack", name);
    (void)json_push_kv_str(&row, "path", dir);
    (void)json_push_back(&c->done, &row);
    json_free(&row);
    c->slimmed++;
}

/* One stack, in the bridge's order: no build/test-tmp, running, busy and
 * fresh skips first, then the per-call cap. Returns false at the cap. */
static bool sl_visit(struct sl_ctx *c, const char *name)
{
    char dir[DB_PATH + 280], build[DB_PATH + 300], tmp[DB_PATH + 300];
    const char *why;
    if (!db_join(dir, sizeof(dir), c->root, name) ||
        !db_join(build, sizeof(build), dir, "build") ||
        !db_join(tmp, sizeof(tmp), dir, "test-tmp"))
        return true;
    if (!sl_isdir(build) && !sl_isdir(tmp))
        return true;
    why = sl_unfinished(c, name, build);
    if (why) {
        sl_note_skip(c, name, why);
        return true;
    }
    if (c->slimmed >= (size_t)c->max)
        return false;
    sl_slim_one(c, name, dir, build, tmp);
    return true;
}

static bool sl_collect(const struct json_value *in, struct sl_ctx *c,
                       const char *home)
{
    const char *sysctl = db_opt_str(in, "systemctl");
    const char *proc = db_opt_str(in, "proc_dir");
    const char *argv[] = {sysctl[0] ? sysctl : "systemctl", "--user",
                          "list-units", "--no-pager", "--plain",
                          "--state=running", NULL};
    char *text = zcl_malloc(1u << 20, "sl_units");
    bool ok;
    (void)home;
    if (!text)
        return false;
    if (zcl_spawn_capture(argv, text, 1u << 20, 60 * 1000) < 0)
        text[0] = '\0';
    ok = sl_units_numbers(&c->running, text) &&
         sl_busy_numbers(&c->busy, proc[0] ? proc : "/proc");
    free(text);
    return ok;
}

static void sl_free(struct sl_ctx *c)
{
    free(c->running.p);
    free(c->busy.p);
    json_free(&c->done);
    json_free(&c->skipped);
    json_free(&c->lines);
}

static int sl_max(const struct json_value *in)
{
    const char *m = db_opt_str(in, "max");
    long v = m[0] ? strtol(m, NULL, 10) : SL_MAX_DEFAULT;
    if (!m[0]) {
        const struct json_value *j = json_get(in, "max");
        if (j && j->type == JSON_INT)
            v = (long)json_get_int(j);
    }
    return v < 0 ? 0 : (v > 1000 ? 1000 : (int)v);
}

static void sl_run(struct sl_ctx *c)
{
    size_t n = 0, i;
    char **names = sl_list_stacks(c->root, &n);
    bool more = true;
    for (i = 0; i < n; i++) {
        if (more)
            more = sl_visit(c, names[i]);
        free(names[i]);
    }
    free(names);
}

void zcl_native_handle_dev_batch_slim(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    const struct json_value *in;
    struct db_paths p;
    struct sl_ctx c;
    if (!reply)
        return;
    in = request ? request->input : NULL;
    if (!in) {
        db_refuse(reply, "BAD_INPUT", "input", "dev.batch.slim needs input");
        return;
    }
    if (!db_paths_init(in, &p, reply))
        return;
    memset(&c, 0, sizeof(c));
    json_init(&c.done);
    json_set_array(&c.done);
    json_init(&c.skipped);
    json_set_array(&c.skipped);
    json_init(&c.lines);
    json_set_array(&c.lines);
    c.max = sl_max(in);
    c.dry = db_opt_flag(in, "dry_run");
    if (!db_join(c.root, sizeof(c.root), p.home, "development/z23") ||
        !sl_collect(in, &c, p.home)) {
        db_refuse(reply, "BAD_INPUT", "paths", "slim: cannot read the host");
        sl_free(&c);
        return;
    }
    sl_run(&c);
    (void)json_push_kv_str(&reply->data, "leaf", "dev.batch.slim");
    (void)json_push_kv_bool(&reply->data, "dry_run", c.dry);
    (void)json_push_kv(&reply->data, "slimmed", &c.done);
    (void)json_push_kv(&reply->data, "skipped", &c.skipped);
    (void)json_push_kv(&reply->data, "lines", &c.lines);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)c.slimmed);
    sl_free(&c);
}
