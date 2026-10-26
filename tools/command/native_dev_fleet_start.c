/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.fleet.start — the whole opening read for an ORCHESTRATOR in
 *          one bounded packet: this checkout, the mission, every linked
 *          worktree, the running executor units, each fleet host, the
 *          unanswered board rows, main, and what to do first.
 *
 * ── CONTRACT (this file is the whole implementation) ──────────────────────
 *
 * WHY. dev.agent.start answers the opening question for ONE LANE. Nothing
 * answered it for the session that DISPATCHES lanes: that session opened its
 * day with roughly twenty shell reads over Git, ~190 worktrees, systemd, the
 * board and four documents before its first decision. Every one of those
 * facts is local, cheap, and already on this disk. One call returns them
 * inside a byte budget the caller sets, so orienting costs a fixed, known
 * number of tokens instead of a variable pile of scrollback.
 *
 * INPUT (zcl.fleet_start_input.v1) — all keys optional
 *   since          opaque cursor STRING a previous call returned as `cursor`.
 *                  Malformed → refusal code `cursor_invalid`.
 *   budget_bytes   INT, default 6144, min 1024, max 15360. Out of range →
 *                  refusal code `budget_out_of_range`.
 *   board_dir      STRING. Default: $HOME/.local/state/zclassic23/board.
 *   cwd            STRING. Directory to run Git in. Default: the process
 *                  working directory. The checkout is whatever
 *                  `git rev-parse --show-toplevel` names there.
 *   include_units  BOOL, default true. False, or no `systemctl`, makes the
 *                  units section `unobserved`. The key is NOT called `units`:
 *                  the transport validator already owns `units` as a ZSLP
 *                  token amount (positive integer), so a bool named `units`
 *                  is refused before this handler ever runs.
 *
 * OUTPUT (zcl.fleet_start.v1). Every section is an object carrying `state`
 * (observed|unobserved|unavailable), `count`, `total`, `truncated`, and —
 * where it has rows — `rows`. Sections, in assembly order:
 *   checkout   worktree (with $HOME rendered as ~), branch, head,
 *              origin_main, behind, ahead, dirty, hooks_armed, stale
 *   mission    forward_plan path + its first H2 title; lifecycle path and
 *              whether it exists. Pointers only; no prose is copied.
 *   worktrees  every linked worktree sharing this checkout's git common dir:
 *              name, path, branch, head, ahead, behind, dirty, mtime.
 *              Newest first. With `since`, only those changed after it.
 *   units      running `--user` units whose names start with z23-, glm-,
 *              muse-, oc_, eu-: name, minutes. BRIDGE: a running unit is
 *              evidence of ACTIVITY, never of a result. Verdicts come from
 *              receipts in a later increment, never from a scratch .out file.
 *   hosts      one row per <host>.jsonl in the board dir: host, the last
 *              `offer` row's text and ts, and the last ts posted by any agent
 *              other than the two automated ones.
 *   board      unanswered rows: every `need` or `problem` whose `id` is not
 *              the `ref` of a LATER `claim`/`result`, newest first, `text`
 *              cut to 160 bytes on a UTF-8 boundary, automated agents
 *              excluded. With `since`, only rows newer than it.
 *   main       origin/main short head, subject, age in hours, and the red
 *              lint gates this checkout's own receipt chain reports (read
 *              through zcl_dev_fleet_receipts_json — the same reader
 *              dev.fleet.truth uses).
 *   next       ordered {action, reason, command} derived from the facts.
 *
 * Then `cursor` (opaque: newest board id, origin/main head, unix seconds),
 * `bytes` (this data object's own serialized size), `elapsed_ms`,
 * `latency_budget_ms`, `budget_exceeded`, `budget_bytes`, and `facts` —
 * one line naming how many verified fact rows this checkout carries and
 * how to query them, from the compiled table in engine/composition/facts/.
 *
 * BUDGET. Sections are assembled in the order above and rows stop being
 * added when the packet would exceed `budget_bytes`. A section that was cut
 * says `truncated=true` and reports its `total`. The packet NEVER exceeds
 * the budget and NEVER drops a row silently.
 *
 * SCOPE RULE. No fetch, no network, no RPC, no datadir, nothing written.
 * Git is the only authority for refs and worktrees; the board dir is the
 * only authority for fleet posts and it is read through ONE function
 * (fs_board_read) so the signed, gossiped native board can replace the
 * source without touching a single section.
 *
 * PROCESS RULE. Git runs only through zcl_dev_fleet_git_capture() — the same
 * bounded, shell-free rail dev.fleet.truth uses. `systemctl` runs through
 * zcl_spawn_capture(). popen(), system() and a shell command string are
 * forbidden and gated.
 *
 * Implement this file only; the test tests/harness/src/test_dev_fleet_start.c
 * is the acceptance bar.
 */

#include "command/native_dev_fleet.h"
#include "command/native_dev_fleet_internal.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/file_metadata.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FS_LEAF "dev.fleet.start"
#define FS_SCHEMA "zcl.fleet_start.v1"

#define FS_BUDGET_DEFAULT 6144
#define FS_BUDGET_MIN 1024
/* The real ceiling is the TRANSPORT, not the catalog. The native CLI hands
 * the dispatcher one ZCL_COMMAND_EXTENDED_LIST_BUDGET buffer (16 KiB) for
 * every leaf however large that leaf declares its own response budget, and
 * the result ENVELOPE (schema, command, request_id, authority, timings,
 * next[]) is charged against the same buffer. Measured: a packet asked for
 * at 24576 came back only as RESPONSE_BUDGET_EXCEEDED. Deriving the maximum
 * from the transport constant means a maximum this leaf can always actually
 * deliver, and one that follows the transport if it ever widens. */
#define FS_ENVELOPE_ALLOWANCE 1024
#define FS_BUDGET_MAX \
    ((int64_t)ZCL_COMMAND_EXTENDED_LIST_BUDGET - FS_ENVELOPE_ALLOWANCE)

/* Measured on the maintainer host with 276 worktrees: eight fixed Git spawns
 * at ~20 ms each plus one `status --porcelain` per EMITTED row, and the
 * default budget emits ~27 rows — 420 ms. That is why the .def declares
 * LATENCY_FOREGROUND (750 ms) and not the FAST (250 ms) its five-spawn
 * sibling dev.agent.start declares: a class this leaf could not hold would
 * be a false promise on every fleet-sized checkout. The constant is DERIVED
 * from the declared class so the two cannot drift. */
#define FS_LATENCY_BUDGET_MS ZCL_COMMAND_LATENCY_BUDGET_FOREGROUND_MS
/* Wall the per-worktree `status` spawns share. Past it, remaining rows carry
 * dirty=-1 (unmeasured) and the section says truncated. */
#define FS_WORKTREE_WALL_MS 550

#define FS_CAPTURE_BYTES (1024u * 1024u)
#define FS_MAX_WORKTREES 1024u
#define FS_MAX_BOARD_ROWS 8192u
#define FS_MAX_HOSTS 64u
#define FS_MAX_UNITS 64u
#define FS_TEXT_CUT 160u
/* Room the tail (cursor, elapsed_ms, latency_budget_ms, budget_exceeded,
 * budget_bytes, bytes) is always guaranteed. */
#define FS_TAIL_RESERVE 260u
#define FS_CURSOR_TAG "z23fs1"

/* The board is the fleet's shared append log. This is the same
 * $HOME-relative location every other dev-state reader in this tree uses
 * (dev.train's land queue, the node-verify scratch). It is NOT
 * platform_state_root(): that resolver CREATES its directories, and a leaf
 * whose whole contract is "nothing is written except the result" must not
 * mkdir on a read. */
#define FS_BOARD_REL "/.local/state/zclassic23/board"

#define FS_UNMEASURED (-1)

/* ── small shared helpers ────────────────────────────────────────────────── */

static void fs_strip(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = 0;
}

/* Render an absolute path under $HOME as ~/... . The tree has a gate against
 * operator paths reaching a committed file; a packet an agent pastes into a
 * commit message or a document is exactly how one gets there. */
static void fs_tilde(const char *path, char *out, size_t cap)
{
    const char *home = getenv("HOME");
    size_t hl = home ? strlen(home) : 0;
    if (home && hl && strncmp(path, home, hl) == 0 &&
        (path[hl] == 0 || path[hl] == '/'))
        (void)snprintf(out, cap, "~%s", path + hl);
    else
        (void)snprintf(out, cap, "%s", path);
}

static const char *fs_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash && slash[1] ? slash + 1 : path;
}

/* Twelve hex is the abbreviation this packet quotes everywhere: unambiguous
 * for a repository of this size, and 28 bytes cheaper per row than the full
 * object name — which is several more worktree rows inside the same budget. */
static void fs_short(const char *oid, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%.12s", oid ? oid : "");
}

/* Copy at most `cut` BYTES of `in`, never splitting a UTF-8 sequence. */
static void fs_cut_utf8(const char *in, size_t cut, char *out, size_t cap)
{
    size_t len = strlen(in);
    if (len > cut) len = cut;
    while (len > 0 && ((unsigned char)in[len] & 0xc0u) == 0x80u) len--;
    if (len >= cap) len = cap ? cap - 1 : 0;
    if (len) memcpy(out, in, len);
    out[len] = 0;
}

static size_t fs_count_lines(const char *text)
{
    size_t n = 0;
    for (const char *p = text; *p;) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len) n++;
        if (!nl) break;
        p = nl + 1;
    }
    return n;
}

/* ── the Git rail (the same one dev.fleet.truth uses) ────────────────────── */

struct fs_ctx {
    char root[ZCL_FLEET_PATH_MAX];
    char common[ZCL_FLEET_PATH_MAX];
    char *capture;
    int64_t started_ms;
    int64_t now_wall;
    int64_t budget;
    /* Bytes still owed to sections that have NOT been assembled yet. Without
     * it the first big section wins the whole budget: measured on this host,
     * `worktrees` alone took 32 rows and every section after it — units,
     * hosts, board, main and next — arrived as "cut by budget_bytes". An
     * opening packet that cannot say what to do first is not an opening
     * packet, so each later section holds a floor the earlier ones cannot
     * spend. The floors are FRACTIONS of the caller's budget, so a small
     * budget shrinks every section instead of starving the tail. */
    int64_t reserve;
    char scratch[FS_BUDGET_MAX + 4096];
};

/* Floors, as a divisor of budget_bytes, for each section that is assembled
 * after `worktrees`. Order matches assembly order. */
static const int FS_FLOOR_DIVISOR[] = {32, 8, 6, 16, 12};
enum {
    FS_FLOOR_UNITS = 0, FS_FLOOR_HOSTS, FS_FLOOR_BOARD, FS_FLOOR_MAIN,
    FS_FLOOR_NEXT, FS_FLOOR_COUNT
};

static int64_t fs_floor_total(int64_t budget, size_t from)
{
    int64_t sum = 0;
    for (size_t i = from; i < FS_FLOOR_COUNT; i++)
        sum += budget / FS_FLOOR_DIVISOR[i];
    return sum;
}

static bool fs_git(struct fs_ctx *ctx, const char *dir,
                   const char *const args[])
{
    bool truncated = false;
    int rc = zcl_dev_fleet_git_capture(dir, args, ctx->capture,
                                       FS_CAPTURE_BYTES, &truncated);
    return rc == 0 && !truncated;
}

static int64_t fs_elapsed(const struct fs_ctx *ctx)
{
    return platform_time_monotonic_ms() - ctx->started_ms;
}

/* ── JSON size accounting ────────────────────────────────────────────────
 * Pushing one member into an object grows its serialization by exactly
 * strlen(key) + 2 quotes + 1 colon + len(value) + 1 comma (the first member
 * pays no comma, so +4 is an exact upper bound). Pushing one item into an
 * array grows it by len(item) + 1. Both identities let the packet decide
 * whether a row FITS before it commits to it, without re-serializing the
 * whole document per candidate. */

static size_t fs_len(struct fs_ctx *ctx, const struct json_value *v)
{
    return json_write(v, ctx->scratch, sizeof(ctx->scratch));
}

static size_t fs_member_cost(const char *key, size_t value_len)
{
    return strlen(key) + 4u + value_len;
}

/* ── section frames ──────────────────────────────────────────────────────── */

static void fs_head(struct json_value *sec, const char *state, long long count,
                    long long total, bool truncated)
{
    json_set_object(sec);
    (void)json_push_kv_str(sec, "state", state);
    (void)json_push_kv_int(sec, "count", count);
    (void)json_push_kv_int(sec, "total", total);
    (void)json_push_kv_bool(sec, "truncated", truncated);
}

/* Push one finished section if the whole packet still fits, and say whether
 * it went in. A section that does not fit is replaced by its own unobserved
 * frame so the reader is never left guessing why a name is missing. */
static bool fs_commit(struct fs_ctx *ctx, struct json_value *data,
                      const char *key, struct json_value *sec, long long total)
{
    size_t used = fs_len(ctx, data);
    size_t cost = fs_member_cost(key, fs_len(ctx, sec));
    if (used + cost + FS_TAIL_RESERVE + (size_t)ctx->reserve <=
        (size_t)ctx->budget) {
        (void)json_push_kv(data, key, sec);
        return true;
    }
    struct json_value cut;
    json_init(&cut);
    fs_head(&cut, "unobserved", 0, total, true);
    (void)json_push_kv_str(&cut, "reason", "cut by budget_bytes");
    /* The cut frame is small, but six of them are not: at the 1024-byte
     * minimum they filled the packet to the brim and the tail then pushed
     * it to 1189 bytes — over a budget this leaf promises never to exceed.
     * The frame owes the tail its room exactly as a real section does. */
    size_t cut_cost = fs_member_cost(key, fs_len(ctx, &cut));
    if (used + cut_cost + FS_TAIL_RESERVE <= (size_t)ctx->budget)
        (void)json_push_kv(data, key, &cut);
    json_free(&cut);
    return false;
}

/* Would `sec` (head fields + `rows` holding `rows_len` bytes) still fit? */
static bool fs_row_fits(struct fs_ctx *ctx, const struct json_value *data,
                        const char *key, size_t head_len, size_t rows_len)
{
    /* `"rows":` is 7 bytes, its comma 1; 8 more absorb the count/total
     * digits that grow as rows are added. */
    size_t sec_len = head_len + 8u + 8u + rows_len;
    return fs_len(ctx, data) + fs_member_cost(key, sec_len) +
               FS_TAIL_RESERVE + (size_t)ctx->reserve <= (size_t)ctx->budget;
}

/* ── refusals ────────────────────────────────────────────────────────────── */

static void fs_refuse(struct zcl_command_reply *reply, const char *code,
                      const char *message, const char *evidence,
                      const char *next)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_INVALID, code, "validate", false,
                           false, message, evidence);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                   "%s", next);
}

/* ── the cursor ──────────────────────────────────────────────────────────
 * Opaque to the caller, and deliberately readable to a maintainer:
 *   z23fs1.<newest board id seen>.<origin/main head>.<unix seconds>
 * A caller only ever round-trips it. */

struct fs_cursor {
    bool present;
    char board_id[96];
    char origin_main[ZCL_FLEET_OID_MAX];
    long long unix_seconds;
};

static bool fs_cursor_parse(const char *text, struct fs_cursor *out)
{
    char buf[256];
    char *field[4] = {0};
    size_t n = 0;
    if (!text || strlen(text) >= sizeof(buf)) return false;
    (void)snprintf(buf, sizeof(buf), "%s", text);
    for (char *p = buf;;) {
        char *dot = strchr(p, '.');
        if (n >= 4) return false;
        field[n++] = p;
        if (!dot) break;
        *dot = 0;
        p = dot + 1;
    }
    if (n != 4 || strcmp(field[0], FS_CURSOR_TAG) != 0) return false;
    if (!field[2][0] || !field[3][0]) return false;
    for (const char *p = field[3]; *p; p++)
        if (*p < '0' || *p > '9') return false;
    if (strlen(field[1]) >= sizeof(out->board_id) ||
        strlen(field[2]) >= sizeof(out->origin_main))
        return false;
    out->present = true;
    (void)snprintf(out->board_id, sizeof(out->board_id), "%s", field[1]);
    (void)snprintf(out->origin_main, sizeof(out->origin_main), "%s", field[2]);
    out->unix_seconds = strtoll(field[3], NULL, 10);
    return true;
}

/* ── THE BOARD SEAM ──────────────────────────────────────────────────────
 * Everything this packet knows about the fleet's message board enters
 * through fs_board_read() and through nothing else. The board is a
 * directory of <host>.jsonl append logs today; when it becomes a signed,
 * gossiped native surface, replace this function's body and the hosts,
 * board and next sections keep working unchanged.
 *
 * Row text is written by other agents. It is DATA: it is cut to a byte
 * bound and emitted as a JSON string, never interpreted. */

struct fs_board_row {
    char ts[40];
    char id[96];
    char fhost[80];
    char agent[80];
    char kind[16];
    char ref[96];
    char text[512];
};

static bool fs_board_automated(const char *agent)
{
    return strcmp(agent, "board-cpu") == 0 ||
           strcmp(agent, "z23 front page") == 0;
}

static void fs_board_field(const struct json_value *row, const char *key,
                           char *out, size_t cap)
{
    const struct json_value *v = json_get(row, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    (void)snprintf(out, cap, "%s", s ? s : "");
}

static int fs_board_compare(const void *left, const void *right)
{
    const struct fs_board_row *a = left, *b = right;
    return strcmp(a->id, b->id);
}

static bool fs_board_read(const char *dir, struct fs_board_row *rows,
                          size_t cap, size_t *count, char *why, size_t whycap)
{
    struct platform_directory_list files = {0};
    *count = 0;
    if (!platform_directory_list_regular_sorted(dir, &files)) {
        (void)snprintf(why, whycap, "board directory is not readable");
        return false;
    }
    for (size_t i = 0; i < files.count; i++) {
        const char *name = files.entries[i].name;
        size_t len = strlen(name);
        char path[ZCL_FLEET_PATH_MAX];
        FILE *f;
        if (len <= 6 || strcmp(name + len - 6, ".jsonl") != 0) continue;
        if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
            (int)sizeof(path))
            continue;
        f = fopen(path, "rb");
        if (!f) continue;
        for (;;) {
            static char line[8192];
            struct json_value row;
            struct fs_board_row *out;
            if (!fgets(line, sizeof(line), f)) break;
            fs_strip(line);
            if (!line[0] || *count >= cap) continue;
            json_init(&row);
            if (!json_read(&row, line, strlen(line)) ||
                row.type != JSON_OBJ) {
                json_free(&row);
                continue;
            }
            out = &rows[*count];
            memset(out, 0, sizeof(*out));
            fs_board_field(&row, "ts", out->ts, sizeof(out->ts));
            fs_board_field(&row, "id", out->id, sizeof(out->id));
            fs_board_field(&row, "agent", out->agent, sizeof(out->agent));
            fs_board_field(&row, "kind", out->kind, sizeof(out->kind));
            fs_board_field(&row, "ref", out->ref, sizeof(out->ref));
            fs_board_field(&row, "text", out->text, sizeof(out->text));
            (void)snprintf(out->fhost, sizeof(out->fhost), "%.*s",
                           (int)(len - 6), name);
            json_free(&row);
            if (out->id[0]) (*count)++;
        }
        (void)fclose(f);
    }
    platform_directory_list_free(&files);
    if (*count > 1)
        qsort(rows, *count, sizeof(*rows), fs_board_compare);
    return true;
}

/* ── worktrees ───────────────────────────────────────────────────────────── */

struct fs_wt {
    char path[ZCL_FLEET_PATH_MAX];
    char branch[192];
    char head[ZCL_FLEET_OID_MAX];
    long long ahead;
    long long behind;
    long long dirty;
    int64_t mtime;
};

static int fs_wt_compare(const void *left, const void *right)
{
    const struct fs_wt *a = left, *b = right;
    if (a->mtime != b->mtime) return a->mtime < b->mtime ? 1 : -1;
    return strcmp(a->path, b->path);
}

static int64_t fs_mtime(const char *path)
{
    struct platform_file_metadata meta;
    if (platform_file_metadata_read(path, &meta) != PLATFORM_FILE_METADATA_OK)
        return 0;
    return meta.modified_seconds;
}

/* Newest of a worktree admin directory's HEAD and index. Both live in the
 * git common dir, never on the worktree's own disk, so enumerating 273 of
 * them costs one directory read and two metadata probes each. */
static int64_t fs_admin_mtime(const char *admin_dir)
{
    char path[ZCL_FLEET_PATH_MAX];
    int64_t newest = 0, t;
    (void)snprintf(path, sizeof(path), "%s/HEAD", admin_dir);
    t = fs_mtime(path);
    if (t > newest) newest = t;
    (void)snprintf(path, sizeof(path), "%s/index", admin_dir);
    t = fs_mtime(path);
    if (t > newest) newest = t;
    return newest;
}

/* Read `<admin>/gitdir`, which holds "<worktree>/.git". */
static bool fs_admin_worktree(const char *admin_dir, char *out, size_t cap)
{
    char path[ZCL_FLEET_PATH_MAX];
    char line[ZCL_FLEET_PATH_MAX];
    FILE *f;
    size_t len;
    (void)snprintf(path, sizeof(path), "%s/gitdir", admin_dir);
    f = fopen(path, "rb");
    if (!f) return false;
    if (!fgets(line, sizeof(line), f)) { (void)fclose(f); return false; }
    (void)fclose(f);
    fs_strip(line);
    len = strlen(line);
    if (len > 5 && strcmp(line + len - 5, "/.git") == 0) line[len - 5] = 0;
    if (!line[0] || strlen(line) >= cap) return false;
    (void)snprintf(out, cap, "%s", line);
    return true;
}

static size_t fs_wt_parse_list(struct fs_ctx *ctx, struct fs_wt *wts,
                               size_t cap)
{
    size_t count = 0;
    char path[ZCL_FLEET_PATH_MAX] = "", head[ZCL_FLEET_OID_MAX] = "";
    char branch[192] = "";

    for (char *line = ctx->capture;;) {
        char *end = strchr(line, '\n');
        if (end) *end = 0;
        if (strncmp(line, "worktree ", 9) == 0) {
            (void)snprintf(path, sizeof(path), "%s", line + 9);
            head[0] = 0;
            branch[0] = 0;
        } else if (strncmp(line, "HEAD ", 5) == 0) {
            (void)snprintf(head, sizeof(head), "%s", line + 5);
        } else if (strncmp(line, "branch refs/heads/", 18) == 0) {
            (void)snprintf(branch, sizeof(branch), "%s", line + 18);
        }
        if ((!end || !end[1] || end[1] == '\n') && path[0] && count < cap) {
            struct fs_wt *w = &wts[count++];
            memset(w, 0, sizeof(*w));
            (void)snprintf(w->path, sizeof(w->path), "%s", path);
            (void)snprintf(w->head, sizeof(w->head), "%s", head);
            (void)snprintf(w->branch, sizeof(w->branch), "%s", branch);
            w->ahead = FS_UNMEASURED;
            w->behind = FS_UNMEASURED;
            w->dirty = FS_UNMEASURED;
            path[0] = 0;
        }
        if (!end) break;
        line = end + 1;
        if (!*line) break;
    }
    return count;
}

static void fs_wt_stamp_mtimes(struct fs_ctx *ctx, struct fs_wt *wts,
                               size_t count)
{
    /* mtimes: the main worktree from the common dir itself, every linked one
     * from its admin directory under <common>/worktrees/<name>. */
    for (size_t i = 0; i < count; i++)
        if (strcmp(wts[i].path, ctx->root) == 0 || i == 0)
            wts[i].mtime = fs_admin_mtime(ctx->common);
    {
        char admin_root[ZCL_FLEET_PATH_MAX];
        struct platform_directory_list dirs = {0}, plain = {0};
        (void)snprintf(admin_root, sizeof(admin_root), "%s/worktrees",
                       ctx->common);
        if (platform_directory_list_children_sorted(admin_root, &dirs,
                                                    &plain)) {
            for (size_t i = 0; i < dirs.count; i++) {
                char admin[ZCL_FLEET_PATH_MAX], wt_path[ZCL_FLEET_PATH_MAX];
                int64_t mtime;
                if (snprintf(admin, sizeof(admin), "%s/%s", admin_root,
                             dirs.entries[i].name) >= (int)sizeof(admin))
                    continue;
                if (!fs_admin_worktree(admin, wt_path, sizeof(wt_path)))
                    continue;
                mtime = fs_admin_mtime(admin);
                for (size_t j = 0; j < count; j++)
                    if (strcmp(wts[j].path, wt_path) == 0) {
                        wts[j].mtime = mtime;
                        break;
                    }
            }
            platform_directory_list_free(&dirs);
            platform_directory_list_free(&plain);
        }
    }
}

static void fs_wt_branch_ahead_behind(struct fs_ctx *ctx, struct fs_wt *wts,
                                      size_t count)
{
    /* One `for-each-ref` answers ahead/behind for every named branch at
     * once — 273 worktrees would otherwise be 273 rev-list spawns. */
    static const char *const ab_args[] = {
        "for-each-ref",
        "--format=%(refname:short) %(ahead-behind:refs/remotes/origin/main)",
        "refs/heads", NULL};
    if (fs_git(ctx, ctx->root, ab_args)) {
        for (char *line = ctx->capture;;) {
            char *end = strchr(line, '\n');
            char *sp;
            if (end) *end = 0;
            sp = strchr(line, ' ');
            if (sp) {
                long long ahead = 0, behind = 0;
                *sp = 0;
                if (sscanf(sp + 1, "%lld %lld", &ahead, &behind) == 2)
                    for (size_t j = 0; j < count; j++)
                        if (wts[j].branch[0] &&
                            strcmp(wts[j].branch, line) == 0) {
                            wts[j].ahead = ahead;
                            wts[j].behind = behind;
                            break;
                        }
            }
            if (!end) break;
            line = end + 1;
            if (!*line) break;
        }
    }
}

static size_t fs_collect_worktrees(struct fs_ctx *ctx, struct fs_wt *wts,
                                   size_t cap)
{
    static const char *const list_args[] = {"worktree", "list", "--porcelain",
                                            NULL};
    size_t count = 0;

    if (!fs_git(ctx, ctx->root, list_args)) return 0;
    count = fs_wt_parse_list(ctx, wts, cap);
    fs_wt_stamp_mtimes(ctx, wts, count);
    fs_wt_branch_ahead_behind(ctx, wts, count);

    if (count > 1) qsort(wts, count, sizeof(*wts), fs_wt_compare);
    return count;
}

/* Ahead/behind for a worktree `for-each-ref` could not name (a detached
 * stack worktree), measured only for rows the packet actually emits. */
static void fs_wt_ahead_behind(struct fs_ctx *ctx, struct fs_wt *w)
{
    static const char *const args[] = {"rev-list", "--left-right", "--count",
                                       "refs/remotes/origin/main...HEAD",
                                       NULL};
    long long behind = 0, ahead = 0;
    if (!fs_git(ctx, w->path, args)) return;
    if (sscanf(ctx->capture, "%lld %lld", &behind, &ahead) == 2) {
        w->behind = behind;
        w->ahead = ahead;
    }
}

/* `--no-optional-locks` is load-bearing, not decoration. A plain
 * `git status` REWRITES the index whenever a stat cache entry moved, and the
 * index mtime is exactly the signal this packet uses to decide what changed
 * since the caller's cursor. Measured: the first call statused every emitted
 * worktree, stamped each index with "now", and the next call with that call's
 * own cursor reported worktrees as changed that nobody had touched. A read
 * that perturbs its own change signal reports noise forever. */
static void fs_wt_dirty(struct fs_ctx *ctx, struct fs_wt *w)
{
    static const char *const args[] = {"--no-optional-locks", "status",
                                       "--porcelain", NULL};
    if (!fs_git(ctx, w->path, args)) return;
    w->dirty = (long long)fs_count_lines(ctx->capture);
}

/* ── units ───────────────────────────────────────────────────────────────── */

struct fs_unit {
    char name[128];
    long long minutes;
};

static bool fs_unit_interesting(const char *name)
{
    static const char *const prefixes[] = {"z23-", "glm-", "muse-", "oc_",
                                           "eu-", NULL};
    for (size_t i = 0; prefixes[i]; i++)
        if (strncmp(name, prefixes[i], strlen(prefixes[i])) == 0) return true;
    return false;
}

static size_t fs_unit_parse_list(char *out, struct fs_unit *units, size_t cap)
{
    size_t count = 0;

    for (char *line = out;;) {
        char *end = strchr(line, '\n');
        char *sp;
        if (end) *end = 0;
        while (*line == ' ') line++;
        sp = strchr(line, ' ');
        if (sp) *sp = 0;
        if (line[0] && fs_unit_interesting(line) && count < cap) {
            (void)snprintf(units[count].name, sizeof(units[count].name), "%s",
                           line);
            units[count].minutes = FS_UNMEASURED;
            count++;
        }
        if (!end) break;
        line = end + 1;
        if (!*line) break;
    }
    return count;
}

static void fs_unit_show_argv(const char *show_argv[], size_t slots,
                              const struct fs_unit *units, size_t count)
{
    size_t n = 0;

    show_argv[n++] = "systemctl";
    show_argv[n++] = "--user";
    show_argv[n++] = "show";
    show_argv[n++] = "-p";
    show_argv[n++] = "Id";
    show_argv[n++] = "-p";
    show_argv[n++] = "ActiveEnterTimestampMonotonic";
    for (size_t i = 0; i < count && n + 1 < slots; i++)
        show_argv[n++] = units[i].name;
    show_argv[n] = NULL;
}

static void fs_unit_stamp_minutes(char *out, struct fs_unit *units,
                                  size_t count)
{
    int64_t now_us;

    /* systemd's monotonic stamps and platform_time_monotonic_ms() both read
     * CLOCK_MONOTONIC, so the difference is the unit's real age. */
    now_us = platform_time_monotonic_ms() * 1000;
    {
        char id[128] = "";
        for (char *line = out;;) {
            char *end = strchr(line, '\n');
            if (end) *end = 0;
            if (strncmp(line, "Id=", 3) == 0)
                (void)snprintf(id, sizeof(id), "%s", line + 3);
            else if (strncmp(line, "ActiveEnterTimestampMonotonic=", 30) == 0) {
                long long started = strtoll(line + 30, NULL, 10);
                for (size_t i = 0; i < count; i++)
                    if (strcmp(units[i].name, id) == 0) {
                        units[i].minutes = started > 0 && now_us > started
                                               ? (now_us - started) / 60000000
                                               : 0;
                        break;
                    }
            }
            if (!end) break;
            line = end + 1;
            if (!*line) break;
        }
    }
}

/* `systemctl --user list-units` names what is RUNNING; `show` dates it. Two
 * spawns total, never one per unit. */
static size_t fs_collect_units(struct fs_unit *units, size_t cap, bool *have)
{
    static const char *const list_argv[] = {
        "systemctl", "--user", "list-units", "--type=service",
        "--state=running", "--no-legend", "--plain", NULL};
    static char out[65536];
    const char *show_argv[8 + FS_MAX_UNITS];
    size_t count = 0;

    *have = false;
    out[0] = 0;
    if (zcl_spawn_capture(list_argv, out, sizeof(out), 5000) != 0) return 0;
    *have = true;

    count = fs_unit_parse_list(out, units, cap);
    if (!count) return 0;

    fs_unit_show_argv(show_argv, sizeof(show_argv) / sizeof(*show_argv),
                      units, count);
    out[0] = 0;
    if (zcl_spawn_capture(show_argv, out, sizeof(out), 5000) != 0)
        return count;
    fs_unit_stamp_minutes(out, units, count);
    return count;
}

/* ── next actions ────────────────────────────────────────────────────────── */

static void fs_next_row(struct json_value *rows, const char *action,
                        const char *reason, const char *command)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "action", action);
    (void)json_push_kv_str(&row, "reason", reason);
    (void)json_push_kv_str(&row, "command", command);
    (void)json_push_back(rows, &row);
    json_free(&row);
}

/* ── the handler ─────────────────────────────────────────────────────────── */

struct fs_checkout {
    char head[ZCL_FLEET_OID_MAX];
    char branch[192];
    char toplevel[ZCL_FLEET_PATH_MAX];
    char shown[ZCL_FLEET_PATH_MAX];
    bool hooks_armed;
};

struct fs_start {
    struct fs_ctx ctx;
    struct json_value *data;
    struct fs_cursor since;
    struct fs_wt *wts;
    struct fs_board_row *board;
    struct fs_unit units[FS_MAX_UNITS];
    struct fs_checkout co;
    char board_dir[ZCL_FLEET_PATH_MAX];
    char origin_main[ZCL_FLEET_OID_MAX];
    char self_head[ZCL_FLEET_OID_MAX];
    char self_branch[192];
    const char *start_dir;
    char newest_board_id[96];
    char board_why[128];
    bool board_ok;
    bool want_units;
    bool stale;
    long long checkout_behind;
    long long checkout_ahead;
    long long checkout_dirty;
    size_t wt_count;
    size_t board_count;
    size_t unit_count;
    size_t unanswered_total;
    size_t ahead_worktrees;
    size_t dirty_worktrees;
};

static void fs_start_init(struct fs_start *st, struct zcl_command_reply *reply)
{
    memset(st, 0, sizeof(*st));
    st->ctx.started_ms = platform_time_monotonic_ms();
    st->ctx.now_wall = (int64_t)platform_time_wall_time_t();
    st->ctx.budget = FS_BUDGET_DEFAULT;
    st->data = &reply->data;
    st->start_dir = ".";
    st->want_units = true;
    st->checkout_behind = FS_UNMEASURED;
    st->checkout_ahead = FS_UNMEASURED;
    st->checkout_dirty = FS_UNMEASURED;
}

static bool fs_input_budget(const struct json_value *input,
                            struct zcl_command_reply *reply,
                            struct fs_ctx *ctx)
{
    const struct json_value *v;
    v = json_get(input, "budget_bytes");
    if (v) {
        long long want = v->type == JSON_INT ? json_get_int(v) : -1;
        if (want < FS_BUDGET_MIN || want > FS_BUDGET_MAX) {
            fs_refuse(reply, "budget_out_of_range",
                      "budget_bytes is an integer between 1024 and 15360",
                      "input.budget_bytes is outside the declared range",
                      "rerun with budget_bytes between 1024 and 15360");
            return false;
        }
        ctx->budget = want;
    }
    return true;
}

static bool fs_input_since(const struct json_value *input,
                           struct zcl_command_reply *reply,
                           struct fs_cursor *since)
{
    const struct json_value *v;
    v = json_get(input, "since");
    if (v && v->type == JSON_STR) {
        if (!fs_cursor_parse(json_get_str(v), since)) {
            fs_refuse(reply, "cursor_invalid",
                      "since is a cursor this leaf issued",
                      "input.since is not a " FS_CURSOR_TAG " cursor",
                      "rerun without since, then reuse the cursor it "
                      "returns");
            return false;
        }
    }
    return true;
}

static void fs_input_options(const struct json_value *input,
                             struct fs_start *st)
{
    const struct json_value *v;
    v = json_get(input, "board_dir");
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        (void)snprintf(st->board_dir, sizeof(st->board_dir), "%s",
                       json_get_str(v));
    v = json_get(input, "include_units");
    if (v && v->type == JSON_BOOL) st->want_units = json_get_bool(v);
    v = json_get(input, "cwd");
    if (v && v->type == JSON_STR && json_get_str(v) && json_get_str(v)[0])
        st->start_dir = json_get_str(v);
}

static bool fs_alloc_buffers(struct fs_start *st,
                             struct zcl_command_reply *reply)
{
    st->ctx.capture = zcl_malloc(FS_CAPTURE_BYTES, "fleet_start_capture");
    st->wts = zcl_calloc(FS_MAX_WORKTREES, sizeof(*st->wts),
                         "fleet_start_worktrees");
    st->board = zcl_calloc(FS_MAX_BOARD_ROWS, sizeof(*st->board),
                           "fleet_start_board");
    if (!st->ctx.capture || !st->wts || !st->board) {
        free(st->ctx.capture); free(st->wts); free(st->board);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "OUT_OF_MEMORY",
                               "allocate", true, false,
                               "cannot allocate the fleet packet buffers",
                               "dev.fleet.start bounds every buffer up front");
        return false;
    }
    return true;
}

static bool fs_resolve_root(struct fs_start *st,
                            struct zcl_command_reply *reply)
{
    /* Git itself names the checkout. The marker walk dev.agent.* uses would
     * be wrong here: it climbs PAST a repository that carries no Z23 marker
     * into whatever ancestor does, so a caller pointed at one checkout would
     * silently be answered about another. This leaf reads Git, the board and
     * systemd — none of which need a Z23 marker to be true. */
    static const char *const args[] = {"rev-parse", "--show-toplevel", NULL};
    if (!fs_git(&st->ctx, st->start_dir, args)) {
        free(st->ctx.capture); free(st->wts); free(st->board);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                               ZCL_COMMAND_EXIT_BLOCKED,
                               "NOT_IN_A_CHECKOUT", "resolve", false,
                               false,
                               "no Git checkout exists at or above the "
                               "requested directory",
                               "dev.fleet.start reads only local Git, the "
                               "board directory, and systemd user units");
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action),
                       "cd into a checkout (or pass cwd), then rerun: "
                       "z23 dev fleet start");
        return false;
    }
    fs_strip(st->ctx.capture);
    (void)snprintf(st->ctx.root, sizeof(st->ctx.root), "%s",
                   st->ctx.capture);
    return true;
}

static void fs_resolve_common_dir(struct fs_start *st)
{
    static const char *const args[] = {"rev-parse", "--git-common-dir",
                                       NULL};
    if (fs_git(&st->ctx, st->ctx.root, args)) {
        fs_strip(st->ctx.capture);
        if (st->ctx.capture[0] == '/')
            (void)snprintf(st->ctx.common, sizeof(st->ctx.common), "%s",
                           st->ctx.capture);
        else
            (void)snprintf(st->ctx.common, sizeof(st->ctx.common), "%s/%s",
                           st->ctx.root, st->ctx.capture);
    }
}

static void fs_default_board_dir(struct fs_start *st)
{
    if (!st->board_dir[0]) {
        const char *home = getenv("HOME");
        if (home && home[0])
            (void)snprintf(st->board_dir, sizeof(st->board_dir), "%s%s",
                           home, FS_BOARD_REL);
    }
}

static void fs_checkout_identity(struct fs_start *st)
{
    /* One spawn answers head, branch and toplevel. `--short` is NOT
     * used here: it makes the following `--abbrev-ref HEAD` ambiguous
     * and git refuses the whole invocation ("Needed a single
     * revision"), which is how this leaf first reported an empty head
     * and branch. Abbreviate in C instead. */
    static const char *const args[] = {"rev-parse", "HEAD",
                                       "--abbrev-ref", "HEAD",
                                       "--show-toplevel", NULL};
    if (fs_git(&st->ctx, st->ctx.root, args)) {
        char *line = st->ctx.capture, *end;
        for (size_t i = 0; line && i < 3; i++) {
            end = strchr(line, '\n');
            if (end) *end = 0;
            if (i == 0)
                (void)snprintf(st->self_head, sizeof(st->self_head), "%s",
                               line);
            else if (i == 1)
                (void)snprintf(st->co.branch, sizeof(st->co.branch), "%s",
                               line);
            else
                (void)snprintf(st->co.toplevel, sizeof(st->co.toplevel),
                               "%s", line);
            line = end ? end + 1 : NULL;
        }
    }
    fs_short(st->self_head, st->co.head, sizeof(st->co.head));
    (void)snprintf(st->self_branch, sizeof(st->self_branch), "%s",
                   st->co.branch);
}

static void fs_checkout_origin(struct fs_start *st)
{
    {
        static const char *const args[] = {"rev-parse",
                                           "refs/remotes/origin/main",
                                           NULL};
        if (fs_git(&st->ctx, st->ctx.root, args)) {
            fs_strip(st->ctx.capture);
            fs_short(st->ctx.capture, st->origin_main,
                     sizeof(st->origin_main));
        }
    }
    if (st->origin_main[0]) {
        static const char *const args[] = {
            "rev-list", "--left-right", "--count",
            "refs/remotes/origin/main...HEAD", NULL};
        if (fs_git(&st->ctx, st->ctx.root, args))
            (void)sscanf(st->ctx.capture, "%lld %lld",
                         &st->checkout_behind, &st->checkout_ahead);
    }
}

static void fs_checkout_dirty_and_hooks(struct fs_start *st)
{
    {
        static const char *const args[] = {"--no-optional-locks", "status",
                                           "--porcelain", NULL};
        if (fs_git(&st->ctx, st->ctx.root, args))
            st->checkout_dirty = (long long)fs_count_lines(st->ctx.capture);
    }
    {
        static const char *const args[] = {"config", "core.hooksPath",
                                           NULL};
        if (fs_git(&st->ctx, st->ctx.root, args)) {
            fs_strip(st->ctx.capture);
            st->co.hooks_armed = st->ctx.capture[0] != 0;
        }
    }
}

static void fs_section_checkout(struct fs_start *st)
{
    struct json_value sec;

    fs_checkout_identity(st);
    fs_checkout_origin(st);
    fs_checkout_dirty_and_hooks(st);
    st->stale = st->checkout_behind > 0;
    fs_tilde(st->co.toplevel[0] ? st->co.toplevel : st->ctx.root,
             st->co.shown, sizeof(st->co.shown));

    json_init(&sec);
    fs_head(&sec, "observed", 1, 1, false);
    (void)json_push_kv_str(&sec, "worktree", st->co.shown);
    (void)json_push_kv_str(&sec, "branch",
                           strcmp(st->co.branch, "HEAD") == 0 ? ""
                                                              : st->co.branch);
    (void)json_push_kv_str(&sec, "head", st->co.head);
    (void)json_push_kv_str(&sec, "origin_main", st->origin_main);
    (void)json_push_kv_int(&sec, "behind", st->checkout_behind);
    (void)json_push_kv_int(&sec, "ahead", st->checkout_ahead);
    (void)json_push_kv_int(&sec, "dirty", st->checkout_dirty);
    (void)json_push_kv_bool(&sec, "hooks_armed", st->co.hooks_armed);
    (void)json_push_kv_bool(&sec, "stale", st->stale);
    (void)fs_commit(&st->ctx, st->data, "checkout", &sec, 1);
    json_free(&sec);
}

static void fs_section_mission(struct fs_start *st)
{
    struct json_value sec;
    const char *plan = "docs/work/FORWARD_PLAN.md";
    const char *lifecycle = "docs/node/CANONICAL_LIFECYCLE.md";
    char path[ZCL_FLEET_PATH_MAX], title[256] = "";
    struct platform_file_metadata meta;
    bool lifecycle_present;
    FILE *f;

    st->ctx.reserve = fs_floor_total(st->ctx.budget, 0);
    (void)snprintf(path, sizeof(path), "%s/%s", st->ctx.root, plan);
    f = fopen(path, "rb");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            fs_strip(line);
            if (strncmp(line, "## ", 3) == 0) {
                (void)snprintf(title, sizeof(title), "%s", line + 3);
                break;
            }
        }
        (void)fclose(f);
    }
    (void)snprintf(path, sizeof(path), "%s/%s", st->ctx.root, lifecycle);
    lifecycle_present =
        platform_file_metadata_read(path, &meta) ==
        PLATFORM_FILE_METADATA_OK;

    json_init(&sec);
    fs_head(&sec, title[0] ? "observed" : "unavailable", 1, 1, false);
    (void)json_push_kv_str(&sec, "forward_plan", plan);
    (void)json_push_kv_str(&sec, "forward_plan_title", title);
    (void)json_push_kv_str(&sec, "lifecycle", lifecycle);
    (void)json_push_kv_bool(&sec, "lifecycle_present", lifecycle_present);
    (void)fs_commit(&st->ctx, st->data, "mission", &sec, 1);
    json_free(&sec);
}

static size_t fs_wt_count_eligible(const struct fs_cursor *since,
                                   const struct fs_wt *wts, size_t count)
{
    size_t eligible = 0;

    /* The cursor second is INCLUSIVE. A file mtime has one-second
     * granularity, so a worktree touched later in the same second the
     * previous call started would be invisible forever under a strict
     * comparison. Repeating at most one second of rows is the failure
     * an orchestrator can absorb; never seeing a lane move is not. */
    for (size_t i = 0; i < count; i++)
        if (!since->present || wts[i].mtime >= since->unix_seconds)
            eligible++;
    return eligible;
}

static void fs_wt_measure(struct fs_ctx *ctx, struct fs_wt *w, int64_t wall)
{
    if (platform_time_monotonic_ms() < wall) {
        if (w->ahead == FS_UNMEASURED) fs_wt_ahead_behind(ctx, w);
        fs_wt_dirty(ctx, w);
    }
}

static void fs_wt_json_row(const struct fs_wt *w, struct json_value *row)
{
    char shown[ZCL_FLEET_PATH_MAX];
    fs_tilde(w->path, shown, sizeof(shown));
    json_init(row);
    json_set_object(row);
    (void)json_push_kv_str(row, "name", fs_basename(w->path));
    (void)json_push_kv_str(row, "path", shown);
    (void)json_push_kv_str(row, "branch", w->branch);
    {
        char short_head[16];
        fs_short(w->head, short_head, sizeof(short_head));
        (void)json_push_kv_str(row, "head", short_head);
    }
    (void)json_push_kv_int(row, "ahead", w->ahead);
    (void)json_push_kv_int(row, "behind", w->behind);
    (void)json_push_kv_int(row, "dirty", w->dirty);
    (void)json_push_kv_int(row, "mtime", w->mtime);
}

static void fs_section_worktrees(struct fs_start *st)
{
    struct json_value sec, rows, head_probe;
    size_t eligible, emitted = 0, head_len, rows_len;
    int64_t wall;

    st->wt_count = fs_collect_worktrees(&st->ctx, st->wts, FS_MAX_WORKTREES);
    wall = st->ctx.started_ms + FS_WORKTREE_WALL_MS;
    eligible = fs_wt_count_eligible(&st->since, st->wts, st->wt_count);

    json_init(&head_probe);
    fs_head(&head_probe, "observed", (long long)eligible,
            (long long)eligible, false);
    head_len = fs_len(&st->ctx, &head_probe);
    json_free(&head_probe);

    json_init(&rows);
    json_set_array(&rows);
    rows_len = fs_len(&st->ctx, &rows);

    for (size_t i = 0; i < st->wt_count; i++) {
        struct fs_wt *w = &st->wts[i];
        struct json_value row;
        size_t next_len;
        if (st->since.present && w->mtime < st->since.unix_seconds) continue;

        fs_wt_measure(&st->ctx, w, wall);
        fs_wt_json_row(w, &row);
        next_len = rows_len + fs_len(&st->ctx, &row) + 1u;
        /* A fleet checkout has hundreds of worktrees and only one of
         * them is the reader's. Left alone this section spends the whole
         * packet on rows nobody asked for, so it may never take more
         * than half the budget however many worktrees exist; `total`
         * still names every one and `truncated` still says it was cut. */
        if (next_len + head_len > (size_t)(st->ctx.budget / 2) ||
            !fs_row_fits(&st->ctx, st->data, "worktrees", head_len,
                         next_len)) {
            json_free(&row);
            break;
        }
        (void)json_push_back(&rows, &row);
        json_free(&row);
        rows_len = fs_len(&st->ctx, &rows);
        emitted++;
        if (w->ahead > 0) st->ahead_worktrees++;
        if (w->dirty > 0) st->dirty_worktrees++;
    }

    json_init(&sec);
    fs_head(&sec, st->wt_count ? "observed" : "unavailable",
            (long long)emitted, (long long)eligible, emitted < eligible);
    (void)json_push_kv(&sec, "rows", &rows);
    (void)fs_commit(&st->ctx, st->data, "worktrees", &sec,
                    (long long)eligible);
    json_free(&rows);
    json_free(&sec);
}

static size_t fs_unit_emit_rows(struct fs_start *st, bool have,
                                struct json_value *rows, size_t head_len)
{
    size_t emitted = 0, rows_len = fs_len(&st->ctx, rows);

    for (size_t i = 0; st->want_units && have && i < st->unit_count; i++) {
        struct json_value row;
        size_t next_len;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "name", st->units[i].name);
        (void)json_push_kv_int(&row, "minutes", st->units[i].minutes);
        next_len = rows_len + fs_len(&st->ctx, &row) + 1u;
        if (!fs_row_fits(&st->ctx, st->data, "units", head_len, next_len)) {
            json_free(&row);
            break;
        }
        (void)json_push_back(rows, &row);
        json_free(&row);
        rows_len = fs_len(&st->ctx, rows);
        emitted++;
    }
    return emitted;
}

static void fs_section_units(struct fs_start *st)
{
    struct json_value sec, rows, head_probe;
    bool have = false;
    size_t emitted, head_len;

    st->ctx.reserve = fs_floor_total(st->ctx.budget, FS_FLOOR_HOSTS);
    if (st->want_units)
        st->unit_count = fs_collect_units(st->units, FS_MAX_UNITS, &have);

    /* The probe must carry the SAME extra keys the finished section
     * will, and its widest values: a head estimate that omits them lets
     * rows pass fs_row_fits and then loses the whole section at
     * fs_commit — which is exactly how `hosts` reported zero of four
     * rows while a thousand bytes went unused. */
    json_init(&head_probe);
    fs_head(&head_probe, "observed", (long long)st->unit_count,
            (long long)st->unit_count, false);
    (void)json_push_kv_str(&head_probe, "means", "activity, not a verdict");
    (void)json_push_kv_str(&head_probe, "reason",
                           "no systemctl --user here");
    head_len = fs_len(&st->ctx, &head_probe);
    json_free(&head_probe);

    json_init(&rows);
    json_set_array(&rows);
    emitted = fs_unit_emit_rows(st, have, &rows, head_len);

    json_init(&sec);
    fs_head(&sec, st->want_units && have ? "observed" : "unobserved",
            (long long)emitted,
            (long long)(st->want_units && have ? st->unit_count : 0),
            st->want_units && have && emitted < st->unit_count);
    /* A running unit is ACTIVITY. It is not a result, and this packet
     * never reads a scratch .out file to pretend otherwise: verdicts
     * arrive as receipts in a later increment. */
    (void)json_push_kv_str(&sec, "means", "activity, not a verdict");
    if (!st->want_units)
        (void)json_push_kv_str(&sec, "reason", "include_units=false");
    else if (!have)
        (void)json_push_kv_str(&sec, "reason", "no systemctl --user here");
    (void)json_push_kv(&sec, "rows", &rows);
    (void)fs_commit(&st->ctx, st->data, "units", &sec,
                    (long long)st->unit_count);
    json_free(&rows);
    json_free(&sec);
}

static void fs_board_load(struct fs_start *st)
{
    st->board_ok = st->board_dir[0] &&
                   fs_board_read(st->board_dir, st->board, FS_MAX_BOARD_ROWS,
                                 &st->board_count, st->board_why,
                                 sizeof(st->board_why));
    if (!st->board_dir[0])
        (void)snprintf(st->board_why, sizeof(st->board_why),
                       "no board directory could be resolved");
    if (st->board_ok && st->board_count)
        (void)snprintf(st->newest_board_id, sizeof(st->newest_board_id),
                       "%s", st->board[st->board_count - 1].id);
}

static size_t fs_host_collect(const struct fs_start *st, char hosts[][80])
{
    size_t host_count = 0;

    for (size_t i = 0; st->board_ok && i < st->board_count; i++) {
        bool seen = false;
        for (size_t j = 0; j < host_count; j++)
            if (strcmp(hosts[j], st->board[i].fhost) == 0) {
                seen = true;
                break;
            }
        if (!seen && host_count < FS_MAX_HOSTS)
            (void)snprintf(hosts[host_count++], sizeof(hosts[0]), "%s",
                           st->board[i].fhost);
    }
    return host_count;
}

static size_t fs_host_rows(struct fs_start *st, char hosts[][80],
                           size_t host_count, struct json_value *rows,
                           size_t head_len)
{
    size_t emitted = 0, rows_len = fs_len(&st->ctx, rows);

    for (size_t h = 0; h < host_count; h++) {
        struct json_value row;
        const char *offer_text = "", *offer_ts = "", *last_human_ts = "";
        char cut[FS_TEXT_CUT + 8];
        size_t next_len;
        for (size_t i = 0; i < st->board_count; i++) {
            if (strcmp(st->board[i].fhost, hosts[h]) != 0) continue;
            if (strcmp(st->board[i].kind, "offer") == 0) {
                offer_text = st->board[i].text;
                offer_ts = st->board[i].ts;
            }
            if (!fs_board_automated(st->board[i].agent))
                last_human_ts = st->board[i].ts;
        }
        fs_cut_utf8(offer_text, FS_TEXT_CUT, cut, sizeof(cut));
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "host", hosts[h]);
        (void)json_push_kv_str(&row, "offer", cut);
        (void)json_push_kv_str(&row, "offer_ts", offer_ts);
        (void)json_push_kv_str(&row, "last_agent_ts", last_human_ts);
        next_len = rows_len + fs_len(&st->ctx, &row) + 1u;
        if (!fs_row_fits(&st->ctx, st->data, "hosts", head_len, next_len)) {
            json_free(&row);
            break;
        }
        (void)json_push_back(rows, &row);
        json_free(&row);
        rows_len = fs_len(&st->ctx, rows);
        emitted++;
    }
    return emitted;
}

static void fs_section_hosts(struct fs_start *st)
{
    struct json_value sec, rows, head_probe;
    char hosts[FS_MAX_HOSTS][80];
    size_t host_count, emitted, head_len;
    char shown_dir[ZCL_FLEET_PATH_MAX];

    st->ctx.reserve = fs_floor_total(st->ctx.budget, FS_FLOOR_BOARD);
    host_count = fs_host_collect(st, hosts);

    fs_tilde(st->board_dir, shown_dir, sizeof(shown_dir));
    json_init(&head_probe);
    fs_head(&head_probe, "observed", (long long)host_count,
            (long long)host_count, false);
    (void)json_push_kv_str(&head_probe, "board_dir", shown_dir);
    (void)json_push_kv_str(&head_probe, "reason", st->board_why);
    head_len = fs_len(&st->ctx, &head_probe);
    json_free(&head_probe);

    json_init(&rows);
    json_set_array(&rows);
    emitted = fs_host_rows(st, hosts, host_count, &rows, head_len);

    json_init(&sec);
    fs_head(&sec, st->board_ok ? "observed" : "unavailable",
            (long long)emitted, (long long)host_count,
            emitted < host_count);
    (void)json_push_kv_str(&sec, "board_dir", shown_dir);
    if (!st->board_ok) (void)json_push_kv_str(&sec, "reason", st->board_why);
    (void)json_push_kv(&sec, "rows", &rows);
    (void)fs_commit(&st->ctx, st->data, "hosts", &sec,
                    (long long)host_count);
    json_free(&rows);
    json_free(&sec);
}

static void fs_board_tally_unanswered(struct fs_start *st)
{
    for (size_t i = 0; st->board_ok && i < st->board_count; i++) {
        if (strcmp(st->board[i].kind, "need") != 0 &&
            strcmp(st->board[i].kind, "problem") != 0) continue;
        if (fs_board_automated(st->board[i].agent)) continue;
        if (st->since.present &&
            strcmp(st->board[i].id, st->since.board_id) <= 0)
            continue;
        st->unanswered_total++;
    }
}

static bool fs_board_answered(const struct fs_start *st,
                              const struct fs_board_row *r)
{
    bool answered = false;
    for (size_t j = 0; j < st->board_count; j++) {
        if (strcmp(st->board[j].ref, r->id) != 0) continue;
        if (strcmp(st->board[j].kind, "claim") != 0 &&
            strcmp(st->board[j].kind, "result") != 0) continue;
        if (strcmp(st->board[j].id, r->id) <= 0) continue;
        answered = true;
        break;
    }
    return answered;
}

static size_t fs_board_rows(struct fs_start *st, struct json_value *rows,
                            size_t head_len)
{
    size_t emitted = 0, rows_len = fs_len(&st->ctx, rows);

    /* Newest first: the rows are sorted oldest-first by id, so walk back. */
    for (size_t k = st->board_ok ? st->board_count : 0; k > 0; k--) {
        struct fs_board_row *r = &st->board[k - 1];
        struct json_value row;
        char cut[FS_TEXT_CUT + 8];
        bool answered = false;
        size_t next_len;
        if (strcmp(r->kind, "need") != 0 && strcmp(r->kind, "problem") != 0)
            continue;
        if (fs_board_automated(r->agent)) continue;
        if (st->since.present && strcmp(r->id, st->since.board_id) <= 0)
            continue;
        answered = fs_board_answered(st, r);
        if (answered) { st->unanswered_total--; continue; }
        fs_cut_utf8(r->text, FS_TEXT_CUT, cut, sizeof(cut));
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "id", r->id);
        (void)json_push_kv_str(&row, "ts", r->ts);
        (void)json_push_kv_str(&row, "host", r->fhost);
        (void)json_push_kv_str(&row, "agent", r->agent);
        (void)json_push_kv_str(&row, "kind", r->kind);
        (void)json_push_kv_str(&row, "text", cut);
        next_len = rows_len + fs_len(&st->ctx, &row) + 1u;
        if (!fs_row_fits(&st->ctx, st->data, "board", head_len, next_len)) {
            json_free(&row);
            break;
        }
        (void)json_push_back(rows, &row);
        json_free(&row);
        rows_len = fs_len(&st->ctx, rows);
        emitted++;
    }
    return emitted;
}

static void fs_section_board(struct fs_start *st)
{
    struct json_value sec, rows, head_probe;
    size_t emitted, head_len;

    st->ctx.reserve = fs_floor_total(st->ctx.budget, FS_FLOOR_MAIN);
    fs_board_tally_unanswered(st);

    json_init(&head_probe);
    fs_head(&head_probe, "observed", (long long)st->unanswered_total,
            (long long)st->board_count, false);
    (void)json_push_kv_int(&head_probe, "unanswered",
                           (long long)st->unanswered_total);
    (void)json_push_kv_str(&head_probe, "reason", st->board_why);
    head_len = fs_len(&st->ctx, &head_probe);
    json_free(&head_probe);

    json_init(&rows);
    json_set_array(&rows);
    emitted = fs_board_rows(st, &rows, head_len);

    json_init(&sec);
    fs_head(&sec, st->board_ok ? "observed" : "unavailable",
            (long long)emitted, (long long)st->board_count,
            emitted < st->unanswered_total);
    (void)json_push_kv_int(&sec, "unanswered",
                           (long long)st->unanswered_total);
    if (!st->board_ok) (void)json_push_kv_str(&sec, "reason", st->board_why);
    (void)json_push_kv(&sec, "rows", &rows);
    (void)fs_commit(&st->ctx, st->data, "board", &sec,
                    (long long)st->board_count);
    json_free(&rows);
    json_free(&sec);
}

static void fs_section_main(struct fs_start *st)
{
    struct json_value sec;
    char subject[256] = "";
    long long age_hours = FS_UNMEASURED;
    size_t owner_red = 0;
    char why[256] = "";
    struct zcl_fleet_worktree self = {0};

    st->ctx.reserve = fs_floor_total(st->ctx.budget, FS_FLOOR_NEXT);
    if (st->origin_main[0]) {
        static const char *const args[] = {
            "log", "-1", "--format=%s%n%ct", "refs/remotes/origin/main",
            NULL};
        if (fs_git(&st->ctx, st->ctx.root, args)) {
            char *nl = strchr(st->ctx.capture, '\n');
            if (nl) {
                *nl = 0;
                (void)snprintf(subject, sizeof(subject), "%s",
                               st->ctx.capture);
                age_hours =
                    (st->ctx.now_wall - strtoll(nl + 1, NULL, 10)) / 3600;
                if (age_hours < 0) age_hours = 0;
            }
        }
    }

    json_init(&sec);
    fs_head(&sec, st->origin_main[0] ? "observed" : "unavailable", 1, 1,
            false);
    (void)json_push_kv_str(&sec, "origin_main", st->origin_main);
    (void)json_push_kv_str(&sec, "subject", subject);
    (void)json_push_kv_int(&sec, "age_hours", age_hours);

    /* Red gates for THIS checkout, through the same self-sealed receipt
     * reader dev.fleet.truth uses — never a second evidence path. */
    self.present = true;
    (void)snprintf(self.head, sizeof(self.head), "%s", st->self_head);
    (void)snprintf(self.branch, sizeof(self.branch), "%s", st->self_branch);
    (void)snprintf(self.path, sizeof(self.path), "%s", st->ctx.root);
    if (!zcl_dev_fleet_receipts_json(&self, &sec, &owner_red, why,
                                     sizeof(why)))
        (void)json_push_kv_str(&sec, "lint_status", "unobserved");
    (void)fs_commit(&st->ctx, st->data, "main", &sec, 1);
    json_free(&sec);
}

static void fs_section_next(struct fs_start *st)
{
    struct json_value sec, rows;
    char command[512];

    st->ctx.reserve = 0;
    json_init(&rows);
    json_set_array(&rows);

    if (st->stale) {
        char reason[128];
        (void)snprintf(reason, sizeof(reason),
                       "this checkout is %lld commits behind origin/main",
                       st->checkout_behind);
        fs_next_row(&rows, "rebase this checkout onto origin/main", reason,
                    "git fetch origin main && git rebase origin/main");
    }
    if (st->unanswered_total > 0) {
        char reason[128];
        (void)snprintf(reason, sizeof(reason),
                       "%zu board needs or problems have no later claim "
                       "or result", st->unanswered_total);
        fs_next_row(&rows, "answer the newest unanswered board row",
                    reason,
                    "z23 dev agent mail post --kind=result --ref=<id> "
                    "--body='<what you did>'");
    }
    if (st->dirty_worktrees > 0 || st->ahead_worktrees > 0) {
        char reason[128];
        (void)snprintf(reason, sizeof(reason),
                       "%zu worktrees are dirty and %zu are ahead of "
                       "origin/main", st->dirty_worktrees,
                       st->ahead_worktrees);
        fs_next_row(&rows, "triage the worktrees that carry work", reason,
                    "z23 dev agent triage");
    }
    if (st->unit_count == 0 && st->ahead_worktrees > 0) {
        (void)snprintf(command, sizeof(command),
                       "z23 dev train build --name land --source <path>");
        fs_next_row(&rows, "land the worktrees that are ahead",
                    "no executor unit is running and work is unlanded",
                    command);
    }
    if (json_size(&rows) == 0)
        fs_next_row(&rows,
                    "pick the first open lifecycle lane in "
                    "docs/node/CANONICAL_LIFECYCLE.md section 7",
                    "main is quiet: nothing is stale, unanswered, dirty, "
                    "or ahead",
                    "z23 dev agent start");

    json_init(&sec);
    fs_head(&sec, "observed", (long long)json_size(&rows),
            (long long)json_size(&rows), false);
    (void)json_push_kv(&sec, "rows", &rows);
    (void)fs_commit(&st->ctx, st->data, "next", &sec,
                    (long long)json_size(&rows));
    json_free(&rows);
    json_free(&sec);
}

static void fs_section_tail(struct fs_start *st)
{
    char cursor[256];
    int64_t elapsed;
    size_t without_bytes;
    long long reported = 0;

    (void)snprintf(cursor, sizeof(cursor), "%s.%s.%s.%lld", FS_CURSOR_TAG,
                   st->newest_board_id[0] ? st->newest_board_id : "none",
                   st->origin_main[0] ? st->origin_main : "none",
                   (long long)st->ctx.now_wall);
    (void)json_push_kv_str(st->data, "cursor", cursor);
    elapsed = fs_elapsed(&st->ctx);
    (void)json_push_kv_int(st->data, "elapsed_ms", elapsed);
    (void)json_push_kv_int(st->data, "latency_budget_ms",
                           FS_LATENCY_BUDGET_MS);
    (void)json_push_kv_bool(st->data, "budget_exceeded",
                            elapsed > FS_LATENCY_BUDGET_MS);
    (void)json_push_kv_int(st->data, "budget_bytes", st->ctx.budget);

    /* Orientation is one line, not a discovery process. The fact table
     * is the cheapest read in the checkout and the one an orienting
     * session most needs to know exists; the count comes from the
     * compiled rows, so it is never a number somebody typed. Pushed
     * before `bytes` so it is inside the size this packet reports. */
    {
        char facts_line[192];
        zcl_dev_orient_banner(facts_line, sizeof(facts_line));
        (void)json_push_kv_str(st->data, "facts", facts_line);
    }

    /* `bytes` reports the size of the document it is itself inside, so
     * solve for it: adding the member costs 9 bytes plus its digits, and
     * exactly one digit width is consistent. */
    without_bytes = fs_len(&st->ctx, st->data);
    for (long long digits = 1; digits <= 8; digits++) {
        long long candidate = (long long)without_bytes + 9 + digits;
        long long width = 0;
        for (long long t = candidate; t > 0; t /= 10) width++;
        if (width == digits) { reported = candidate; break; }
    }
    (void)json_push_kv_int(st->data, "bytes", reported);
}

void zcl_native_handle_dev_fleet_start(const struct zcl_command_request *request,
                                       struct zcl_command_reply *reply)
{
    struct fs_start st;

    if (!reply) return;
    fs_start_init(&st, reply);

    /* ── input ── */
    if (request && request->input) {
        if (!fs_input_budget(request->input, reply, &st.ctx)) return;
        if (!fs_input_since(request->input, reply, &st.since)) return;
        fs_input_options(request->input, &st);
    }
    if (!fs_alloc_buffers(&st, reply)) return;
    if (!fs_resolve_root(&st, reply)) return;
    fs_resolve_common_dir(&st);
    fs_default_board_dir(&st);

    /* `checkout` is the one section that is never negotiable — every other
     * answer is relative to it — so it reserves nothing for anybody. From
     * `mission` on, each section holds the later ones their floor. */
    st.ctx.reserve = 0;
    (void)json_push_kv_str(st.data, "leaf", FS_LEAF);
    (void)json_push_kv_str(st.data, "data_schema", FS_SCHEMA);

    /* ── 1. checkout ── */
    fs_section_checkout(&st);

    /* ── 2. mission (pointers only) ── */
    fs_section_mission(&st);

    /* ── 3. worktrees ── */
    fs_section_worktrees(&st);

    /* ── 4. units ── */
    fs_section_units(&st);

    /* ── the board, read once for sections 5 and 6 ── */
    fs_board_load(&st);

    /* ── 5. hosts ── */
    fs_section_hosts(&st);

    /* ── 6. board: what nobody answered ── */
    fs_section_board(&st);

    /* ── 7. main ── */
    fs_section_main(&st);

    /* ── 8. next ── */
    fs_section_next(&st);

    /* ── the tail: cursor, size, time ── */
    fs_section_tail(&st);

    free(st.ctx.capture);
    free(st.wts);
    free(st.board);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}
