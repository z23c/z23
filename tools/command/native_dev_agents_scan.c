/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Find every agent workspace on this box and say what is happening
 *          in it — the `running` and `units` sections of
 *          `z23-dev fleet agents`.
 *
 * WHAT AN AGENT WORKSPACE IS. A directory under one of four well-known
 * places: `lanes/` (a Claude subagent's own worktree), `units/` (a single
 * scoped unit), `trains/` (a landing train), and the native landing
 * worktree. The root is one option so the tests drive the whole scan against
 * a fixture tree rather than against this machine.
 *
 * WHAT "RUNNING" MEANS HERE, EXACTLY. A live process whose working directory
 * is inside the tree. That is evidence of ACTIVITY and never of a result —
 * the same rule dev.fleet.start states about systemd units, for the same
 * reason: a busy process and a correct one are different facts, and only
 * receipts carry the second. Nothing in this file produces a verdict.
 *
 * WHY THE WHOLE SURVEY IS NOT PRICED THE SAME. This box carries roughly two
 * hundred workspaces. Asking Git the state of each costs one process per
 * workspace, and walking each source tree costs thousands of metadata reads,
 * so pricing every workspace at that rate would make the command too slow to
 * run casually — and a dashboard nobody runs reports nothing. The scan
 * therefore prices EVERY workspace at two metadata reads (its Git admin
 * HEAD and index, which any commit, checkout or `add` touches) and spends
 * the expensive reads only on the ones that are actually live: a workspace
 * with a process in it, or one whose Git state moved inside the window. The
 * counts of what was scanned and what was skipped are reported, so the
 * cheaper answer is never mistaken for a complete one.
 */

#include "command/native_dev_agents.h"

#include "base/safe_alloc.h"
#include "command/native_dev_fleet_internal.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/file_metadata.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SC_MAX_WORKSPACES 1024u
#define SC_MAX_PROCS 8192u
#define SC_MAX_UNITS 64u
#define SC_CAPTURE_BYTES 262144u
/* Entries one source-tree walk may visit before it reports a partial answer.
 * Measured on this checkout: a full Z23 worktree holds about 7,000 admitted
 * files, so this is a whole tree with room, not a truncation in practice. */
#define SC_WALK_ENTRY_MAX 12000u
#define SC_WALK_DEPTH_MAX 8u
/* Wall the expensive per-workspace reads share. Past it, the remaining rows
 * carry -1 (unmeasured) rather than a number nobody waited for. */
#define SC_WALL_MS 600
#define SC_WINDOW_HOURS 12
#define SC_NAME_MAX 96u
#define SC_UNMEASURED (-1)

struct sc_proc {
    long pid;
    char exe[64];
    char cwd[ZCL_AGENTS_PATH_MAX];
};

struct sc_workspace {
    char name[SC_NAME_MAX];
    char kind[16];
    char path[ZCL_AGENTS_PATH_MAX];
    int64_t git_mtime;
    bool live;
    bool has_process;
    bool moved;
};

struct sc_ctx {
    struct sc_proc *procs;
    size_t proc_count;
    bool process_observed;
    char *capture;
    int64_t deadline_ms;
};

static void sc_join(char *out, size_t cap, const char *a, const char *b)
{
    (void)snprintf(out, cap, "%s/%s", a, b);
}

static int64_t sc_mtime(const char *path)
{
    struct platform_file_metadata meta;
    if (platform_file_metadata_read(path, &meta) != PLATFORM_FILE_METADATA_OK)
        return 0;
    return meta.modified_seconds;
}

/* Where Git keeps this workspace's own HEAD and index. A linked worktree
 * carries a `.git` FILE naming an admin directory in the common dir; a
 * standalone clone carries a `.git` directory. Both are two reads. */
static int64_t sc_git_mtime(const char *path)
{
    char dot[ZCL_AGENTS_PATH_MAX], admin[ZCL_AGENTS_PATH_MAX];
    char probe[ZCL_AGENTS_PATH_MAX];
    int64_t newest = 0, t;
    FILE *f;
    sc_join(dot, sizeof(dot), path, ".git");
    (void)snprintf(admin, sizeof(admin), "%s", dot);
    f = fopen(dot, "rb");
    if (f) {
        char line[ZCL_AGENTS_PATH_MAX];
        if (fgets(line, sizeof(line), f) &&
            strncmp(line, "gitdir: ", 8) == 0) {
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                line[--n] = 0;
            (void)snprintf(admin, sizeof(admin), "%s", line + 8);
        }
        (void)fclose(f);
    }
    sc_join(probe, sizeof(probe), admin, "HEAD");
    t = sc_mtime(probe);
    if (t > newest) newest = t;
    sc_join(probe, sizeof(probe), admin, "index");
    t = sc_mtime(probe);
    if (t > newest) newest = t;
    return newest;
}

/* Newest modification time anywhere in the workspace's own source, with
 * `build/`, `.git/` and `vendor/` left out: those three are machine output
 * and vendored input, and counting them would report the last compile as if
 * it were the agent's last edit. */
static int64_t sc_source_mtime(const char *dir, size_t depth, size_t *budget)
{
    struct platform_directory_list dirs, files;
    int64_t newest = 0;
    if (depth > SC_WALK_DEPTH_MAX || *budget == 0) return 0;
    if (!platform_directory_list_children_sorted(dir, &dirs, &files))
        return 0;
    for (size_t i = 0; i < files.count && *budget; i++) {
        (*budget)--;
        if (files.entries[i].snapshot_valid &&
            files.entries[i].modified_seconds > newest)
            newest = files.entries[i].modified_seconds;
    }
    for (size_t i = 0; i < dirs.count && *budget; i++) {
        const char *name = dirs.entries[i].name;
        char child[ZCL_AGENTS_PATH_MAX];
        int64_t t;
        if (!name || strcmp(name, "build") == 0 || strcmp(name, ".git") == 0 ||
            strcmp(name, "vendor") == 0)
            continue;
        (*budget)--;
        sc_join(child, sizeof(child), dir, name);
        t = sc_source_mtime(child, depth + 1, budget);
        if (t > newest) newest = t;
    }
    platform_directory_list_free(&dirs);
    platform_directory_list_free(&files);
    return newest;
}

/* Every live process, with the directory it is working in.
 *
 * This reads /proc directly rather than through the platform directory seam,
 * and the reason is the whole point of the section: /proc is the one
 * directory on this machine whose entries disappear WHILE it is being read.
 * The seam treats a failed metadata read as a failed listing and discards the
 * whole result, which is exactly right for a source tree and exactly wrong
 * here — measured, it returned nothing at all, so the dashboard reported zero
 * running agents on a box with dozens. A process that exits mid-scan is
 * skipped and the scan continues. A process whose links this user may not
 * read simply does not appear, which is the honest answer for a process this
 * box will not show us. Counts describe only the observable subset. An absent
 * process backend is reported separately from a scan that observed no match.
 */
static void sc_collect_procs(struct sc_ctx *ctx, const char *process_root)
{
#if defined(_WIN32)
    /* Windows has no /proc process-cwd observation backend. */
    (void)ctx;
    (void)process_root;
#else
    const char *root = process_root ? process_root : "/proc";
    DIR *dir = opendir(root);
    struct dirent *entry;
    if (!dir) return;
    ctx->process_observed = true;
    while ((entry = readdir(dir)) != NULL &&
           ctx->proc_count < SC_MAX_PROCS) {
        const char *name = entry->d_name;
        char link[ZCL_AGENTS_PATH_MAX];
        char target[ZCL_AGENTS_PATH_MAX];
        ssize_t n;
        struct sc_proc *p;
        if (name[0] < '1' || name[0] > '9') continue;
        if (snprintf(link, sizeof(link), "%s/%s/cwd", root, name) >=
            (int)sizeof(link)) continue;
        n = readlink(link, target, sizeof(target) - 1);
        if (n <= 0) continue;
        target[n] = 0;
        p = &ctx->procs[ctx->proc_count++];
        p->pid = strtol(name, NULL, 10);
        (void)snprintf(p->cwd, sizeof(p->cwd), "%s", target);
        if (snprintf(link, sizeof(link), "%s/%s/exe", root, name) >=
            (int)sizeof(link)) continue;
        n = readlink(link, target, sizeof(target) - 1);
        if (n > 0) {
            const char *slash;
            target[n] = 0;
            slash = strrchr(target, '/');
            (void)snprintf(p->exe, sizeof(p->exe), "%s",
                           slash ? slash + 1 : target);
        } else {
            (void)snprintf(p->exe, sizeof(p->exe), "%s", "(unreadable)");
        }
    }
    (void)closedir(dir);
#endif
}

/* True when `cwd` is the tree itself or anything inside it. The separator
 * test matters: without it `/x/lanes/ab` would claim `/x/lanes/abc`. */
static bool sc_inside(const char *cwd, const char *root)
{
    size_t n = strlen(root);
    return strncmp(cwd, root, n) == 0 && (cwd[n] == 0 || cwd[n] == '/');
}

static size_t sc_add_kind(struct sc_workspace *list, size_t count,
                          const char *parent, const char *kind)
{
    struct platform_directory_list dirs, files;
    if (!platform_directory_list_children_sorted(parent, &dirs, &files))
        return count;
    for (size_t i = 0; i < dirs.count && count < SC_MAX_WORKSPACES; i++) {
        struct sc_workspace *w = &list[count];
        if (!dirs.entries[i].name) continue;
        (void)snprintf(w->name, sizeof(w->name), "%s", dirs.entries[i].name);
        (void)snprintf(w->kind, sizeof(w->kind), "%s", kind);
        sc_join(w->path, sizeof(w->path), parent, dirs.entries[i].name);
        count++;
    }
    platform_directory_list_free(&dirs);
    platform_directory_list_free(&files);
    return count;
}

static int sc_compare(const void *left, const void *right)
{
    const struct sc_workspace *a = left, *b = right;
    if (a->live != b->live) return a->live ? -1 : 1;
    if (a->git_mtime != b->git_mtime)
        return a->git_mtime < b->git_mtime ? 1 : -1;
    return strcmp(a->name, b->name);
}

static void sc_push_processes(struct sc_ctx *ctx, const struct sc_workspace *w,
                              struct json_value *row)
{
    struct json_value arr, item;
    size_t shown = 0, total = 0;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < ctx->proc_count; i++) {
        if (!sc_inside(ctx->procs[i].cwd, w->path)) continue;
        total++;
        if (shown >= ZCL_AGENTS_MAX_PROCESS_ROWS) continue;
        json_init(&item);
        json_set_object(&item);
        (void)json_push_kv_str(&item, "exe", ctx->procs[i].exe);
        (void)json_push_kv_int(&item, "pid", (int64_t)ctx->procs[i].pid);
        (void)json_push_back(&arr, &item);
        json_free(&item);
        shown++;
    }
    (void)json_push_kv_int(row, "process_count", (int64_t)total);
    (void)json_push_kv(row, "processes", &arr);
    json_free(&arr);
}

/* The lane's own completion marker: the tip sha an executor writes when it
 * believes its work is ready. Reported verbatim and never interpreted. */
static void sc_push_ready(const char *ready_dir, const char *name,
                          struct json_value *row)
{
    char path[ZCL_AGENTS_PATH_MAX];
    char line[128] = "";
    FILE *f;
    (void)snprintf(path, sizeof(path), "%s/%s/READY", ready_dir, name);
    f = fopen(path, "rb");
    if (f) {
        if (fgets(line, sizeof(line), f)) {
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                line[--n] = 0;
        }
        (void)fclose(f);
    }
    (void)json_push_kv_str(row, "ready", line);
}

/* HEAD and the dirty count in ONE process. `status --porcelain=v2 --branch`
 * prints `# branch.oid <sha>` followed by one line per changed path, so the
 * two facts this row needs cost one spawn instead of two — and on a box with
 * two hundred workspaces the spawn count IS the latency. */
static void sc_push_git(struct sc_ctx *ctx, const struct sc_workspace *w,
                        struct json_value *row)
{
    static const char *const args[] = {"status", "--porcelain=v2", "--branch",
                                       NULL};
    char head[16] = "";
    int64_t dirty = SC_UNMEASURED;
    bool truncated = false;
    if (zcl_dev_fleet_git_capture(w->path, args, ctx->capture,
                                  SC_CAPTURE_BYTES, &truncated) == 0 &&
        !truncated) {
        dirty = 0;
        for (char *line = ctx->capture;;) {
            char *end = strchr(line, '\n');
            if (end) *end = 0;
            if (strncmp(line, "# branch.oid ", 13) == 0)
                (void)snprintf(head, sizeof(head), "%.9s", line + 13);
            else if (line[0] && line[0] != '#')
                dirty++;
            if (!end) break;
            line = end + 1;
            if (!*line) break;
        }
    }
    (void)json_push_kv_str(row, "head", head);
    (void)json_push_kv_int(row, "dirty", dirty);
}

static void sc_collect_units(struct json_value *out)
{
    static const char *const argv[] = {"systemctl", "--user",  "list-units",
                                       "--plain",   "--no-legend", "z23-*",
                                       NULL};
    static char text[65536];
    struct json_value rows;
    size_t count = 0, total = 0;

    json_init(&rows);
    json_set_array(&rows);
    json_set_object(out);
    text[0] = 0;
    if (zcl_spawn_capture(argv, text, sizeof(text), 5000) != 0) {
        (void)json_push_kv_str(out, "state", "unobserved");
        (void)json_push_kv_str(out, "note", "units: not collected");
        (void)json_push_kv_int(out, "count", 0);
        (void)json_push_kv_int(out, "total", 0);
        (void)json_push_kv(out, "rows", &rows);
        json_free(&rows);
        return;
    }
    for (char *line = text;;) {
        char *end = strchr(line, '\n');
        char *space;
        if (end) *end = 0;
        while (*line == ' ') line++;
        space = strchr(line, ' ');
        if (space) *space = 0;
        if (strncmp(line, "z23-", 4) == 0) {
            total++;
            if (count < ZCL_AGENTS_MAX_UNIT_ROWS) {
                struct json_value row;
                json_init(&row);
                json_set_object(&row);
                (void)json_push_kv_str(&row, "name", line);
                (void)json_push_kv_str(&row, "sub",
                                       space && space[1] ? space + 1 : "");
                (void)json_push_back(&rows, &row);
                json_free(&row);
                count++;
            }
        }
        if (!end) break;
        line = end + 1;
        if (!*line) break;
    }
    (void)json_push_kv_str(out, "state", "observed");
    (void)json_push_kv_int(out, "count", (int64_t)count);
    (void)json_push_kv_int(out, "total", (int64_t)total);
    (void)json_push_kv(out, "rows", &rows);
    json_free(&rows);
}

/* This user's home, or the working directory when the environment has none.
 * Every default path below is built from exactly this one answer. */
static const char *sc_home(void)
{
    const char *home = getenv("HOME");
    return home && home[0] ? home : ".";
}

/* Where the workspaces live and where their READY markers are written. A
 * caller-supplied root moves BOTH, so a test drives the whole scan against a
 * fixture tree without touching this machine. */
static void sc_resolve_roots(const struct zcl_agents_options *options,
                             char *root, size_t root_cap, char *ready_dir,
                             size_t ready_cap)
{
    if (options->root && options->root[0]) {
        (void)snprintf(root, root_cap, "%s", options->root);
        sc_join(ready_dir, ready_cap, root, "scratch");
        return;
    }
    (void)snprintf(root, root_cap, "%s/.z23", sc_home());
    (void)snprintf(ready_dir, ready_cap, "%s/.local/state/zclassic23/scratch",
                   sc_home());
}

/* The four places an agent works. The landing worktree is the odd one: it
 * lives outside ~/.z23 on a real box and inside the fixture root in a test. */
static size_t sc_enumerate(const struct zcl_agents_options *options,
                           const char *root, struct sc_workspace *list)
{
    char child[ZCL_AGENTS_PATH_MAX];
    size_t count = 0;
    sc_join(child, sizeof(child), root, "lanes");
    count = sc_add_kind(list, count, child, "lane");
    sc_join(child, sizeof(child), root, "units");
    count = sc_add_kind(list, count, child, "unit");
    sc_join(child, sizeof(child), root, "trains");
    count = sc_add_kind(list, count, child, "train");
    if (options->root && options->root[0])
        sc_join(child, sizeof(child), root, "land");
    else
        (void)snprintf(child, sizeof(child), "%s/.local/state/z23/dev/land",
                       sc_home());
    return sc_add_kind(list, count, child, "landing");
}

/* Decide which workspaces are worth the expensive reads.
 *
 * "Running now" is a fixed, short window on purpose. It is not the ledger's
 * `since`: a workspace whose Git state last moved half a week ago is a real
 * part of the grade history and is not running now, and folding the two
 * windows together would put two hundred idle worktrees under a heading that
 * says RUNNING. */
static void sc_classify(const struct sc_ctx *ctx,
                        const struct zcl_agents_options *options,
                        struct sc_workspace *list, size_t count,
                        size_t *with_process, size_t *live)
{
    int64_t window = SC_WINDOW_HOURS * 3600;
    for (size_t i = 0; i < count; i++) {
        struct sc_workspace *w = &list[i];
        w->git_mtime = sc_git_mtime(w->path);
        w->has_process = false;
        for (size_t p = 0; p < ctx->proc_count && !w->has_process; p++)
            if (sc_inside(ctx->procs[p].cwd, w->path)) w->has_process = true;
        w->moved = w->git_mtime > 0 &&
                   options->now_unix - w->git_mtime <= window;
        w->live = w->has_process || w->moved;
        if (w->has_process) (*with_process)++;
        if (w->live) (*live)++;
    }
}

/* Ages are reported only when the reader has both ends of them. A -1 means
 * "not measured", which is a different fact from zero. */
static int64_t sc_age(int64_t now_unix, int64_t stamp)
{
    if (stamp <= 0 || now_unix < stamp) return SC_UNMEASURED;
    return now_unix - stamp;
}

/* One workspace row. Past the shared wall the Git read and the source walk
 * are skipped and the row says so, rather than reporting a number nobody
 * waited for. */
static void sc_emit_row(struct sc_ctx *ctx,
                        const struct zcl_agents_options *options,
                        const struct sc_workspace *w, const char *ready_dir,
                        struct json_value *rows)
{
    struct json_value row;
    size_t budget = SC_WALK_ENTRY_MAX;
    int64_t newest = 0;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "name", w->name);
    (void)json_push_kv_str(&row, "kind", w->kind);
    (void)json_push_kv_str(&row, "path", w->path);
    if (platform_time_monotonic_ms() < ctx->deadline_ms) {
        sc_push_git(ctx, w, &row);
        newest = sc_source_mtime(w->path, 0, &budget);
    } else {
        (void)json_push_kv_str(&row, "head", "");
        (void)json_push_kv_int(&row, "dirty", SC_UNMEASURED);
    }
    (void)json_push_kv_int(&row, "newest_source_age_s",
                           sc_age(options->now_unix, newest));
    (void)json_push_kv_int(&row, "git_age_s",
                           sc_age(options->now_unix, w->git_mtime));
    sc_push_processes(ctx, w, &row);
    sc_push_ready(ready_dir, w->name, &row);
    (void)json_push_back(rows, &row);
    json_free(&row);
}

/* The scan could not even take its own buffers. Reported as a section that
 * observed nothing, never as a section that found nothing. */
static void sc_refuse(struct json_value *out, struct json_value *rows)
{
    (void)json_push_kv_str(out, "state", "unavailable");
    (void)json_push_kv_str(out, "note",
                           "cannot allocate the workspace scan buffers");
    (void)json_push_kv_int(out, "count", 0);
    (void)json_push_kv(out, "rows", rows);
}

void zcl_agents_running_json(const struct zcl_agents_options *options,
                             struct json_value *out)
{
    struct sc_ctx ctx;
    struct sc_workspace *list = NULL;
    struct json_value rows, units;
    char root[ZCL_AGENTS_PATH_MAX], ready_dir[ZCL_AGENTS_PATH_MAX];
    size_t count = 0, emitted = 0, live_count = 0, process_count = 0;

    if (!out) return;
    json_set_object(out);
    json_init(&rows);
    json_set_array(&rows);
    memset(&ctx, 0, sizeof(ctx));
    sc_resolve_roots(options, root, sizeof(root), ready_dir,
                     sizeof(ready_dir));

    list = zcl_calloc(SC_MAX_WORKSPACES, sizeof(*list), "agents_workspaces");
    ctx.procs = zcl_calloc(SC_MAX_PROCS, sizeof(*ctx.procs), "agents_procs");
    ctx.capture = zcl_malloc(SC_CAPTURE_BYTES, "agents_git_capture");
    if (!list || !ctx.procs || !ctx.capture) {
        free(list); free(ctx.procs); free(ctx.capture);
        sc_refuse(out, &rows);
        json_free(&rows);
        return;
    }

    count = sc_enumerate(options, root, list);
    sc_collect_procs(&ctx, options->process_root);
    sc_classify(&ctx, options, list, count, &process_count, &live_count);
    qsort(list, count, sizeof(*list), sc_compare);

    ctx.deadline_ms = platform_time_monotonic_ms() + SC_WALL_MS;
    while (emitted < count && list[emitted].live &&
           emitted < ZCL_AGENTS_MAX_WORKSPACE_ROWS) {
        sc_emit_row(&ctx, options, &list[emitted], ready_dir, &rows);
        emitted++;
    }

    (void)json_push_kv_str(out, "state", count ? "observed" : "unavailable");
    (void)json_push_kv_str(out, "root", root);
    (void)json_push_kv_int(out, "scanned", (int64_t)count);
    (void)json_push_kv_int(out, "with_process", (int64_t)process_count);
    (void)json_push_kv_str(out, "process_observation",
                         ctx.process_observed ? "partial" : "unavailable");
    (void)json_push_kv_int(out, "active", (int64_t)live_count);
    (void)json_push_kv_int(out, "idle", (int64_t)(count - live_count));
    (void)json_push_kv_int(out, "window_hours", SC_WINDOW_HOURS);
    (void)json_push_kv_int(out, "count", (int64_t)emitted);
    (void)json_push_kv_int(out, "total", (int64_t)live_count);
    (void)json_push_kv_bool(out, "truncated", emitted < live_count);
    (void)json_push_kv(out, "rows", &rows);

    if (options->collect_units) {
        json_init(&units);
        sc_collect_units(&units);
        (void)json_push_kv(out, "units", &units);
        json_free(&units);
    }

    json_free(&rows);
    free(list); free(ctx.procs); free(ctx.capture);
}
