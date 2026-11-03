/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.batch.restack, the C form of the lab bridge restack-failed.sh.
 *          It returns the lanes of a batch whose land row failed or
 *          conflicted, or whose gate failed before it submitted, to
 *          stack-pending (at most twice per lane head). 10-26 15:40: 13
 *          batches holding 130+ reviewed LAND lanes failed a transient
 *          check-kpi-floor race at land; the stacked.tsv ledger then kept every
 *          one of them out of later batches and nothing retried them.
 *
 * What the decision reads, all of it under --home (default $HOME):
 *   <state>/stacked.tsv        LANE<TAB>HEAD<TAB>sN, one row per batched lane
 *   <state>/stack-pending.txt  LANE<TAB>NOTE
 *   <state>/restacked.tsv      LANE<TAB>HEAD<TAB>sN<TAB>UTC time
 *   .local/state/z23/dev/land/outcomes.jsonl   the last row per stack worktree
 *   .cache/development-scratch/z23/gate-submit/z23-stacksN/{run.log,lint.log,
 *       fast.log,av-fail.txt}     the gate's own logs (run.log ends in rc=N)
 *   development/z23/main       origin/main and its complexity baseline
 *   `dev land status` (--dev-bin) names the stacks still live; `systemctl
 *   --user` (--systemctl) names the gates still running.
 *
 * A stack is stranded when its last land row is failed or conflict, or when it
 * has no land row and its gate log ends in rc=N with N not 0. A gate failure
 * with no land row names its culprit files (10-26 s119 "LEGACY FILE GREW:
 * .../codeindex_merkle.c"); those lanes stay out for triage. Compiler command
 * lines, devbuild and gen_templates lines and tab-led wrapped lines name
 * every file, so they are ignored (10-31 s357: an agent-verify stop read the
 * PASSING lint.log). Lanes moved since review (tree compare), already on main
 * (git cherry) and cx-* lanes whose files lost every baseline row are skipped.
 *
 * SHADOW STEP. restack-failed.sh keeps acting. --dry-run is the mode run
 * against live state: it writes nothing (the bridge's DRY=1 touches its stamp
 * and three scratch files in the state directory; this does not), ignores the
 * ten-minute spacing and returns the decision plus the bridge's exact message
 * lines. Without --dry-run it rewrites the ledger and appends pending and
 * restacked rows. It does NOT take .stack-tick.lock: the batch tick calls the
 * bridge while already holding that lock, and a second flock(2) on the same
 * file from a child would deadlock. A caller that is not the tick must hold
 * the lock itself (dev.batch.requeue takes it). */

#include "command/native_dev_batch.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define RS_BUF (4u * 1024u * 1024u)
#define RS_SPACING_S 600

struct rs_take {
    char lane[DB_PATH];
    char head[84];
    char stack[24];
};

struct rs_ctx {
    struct db_paths p;
    char main[DB_PATH];
    char gate_dir[DB_PATH];
    char stacks[DB_PATH];
    struct db_text ledger, pending, done, outcomes, baseline;
    char *land;    /* `dev land status` output */
    char *units;   /* running gate units */
    char *scratch; /* one git answer at a time */
    struct rs_take *take;
    size_t ntake, captake;
    struct json_value lines;
};

enum rs_verdict { RS_SILENT, RS_SAID, RS_TAKE };

static void rs_say(struct rs_ctx *c, const char *fmt, ...)
{
    char msg[DB_PATH + 256];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    db_push_str(&c->lines, msg);
}

/* basename(1): trailing slashes do not count (the ledger holds lane paths
 * written with one). The result lives until the next call. */
static const char *rs_base(const char *path)
{
    static char buf[256];
    size_t n = strlen(path);
    const char *b;
    while (n > 1 && path[n - 1] == '/')
        n--;
    b = path + n;
    while (b > path && b[-1] != '/')
        b--;
    (void)snprintf(buf, sizeof(buf), "%.*s", (int)(path + n - b), b);
    return buf;
}

/* ── the live picture: land status, running gate units ─────────────────── */

static char *rs_spawn_text(const char *const argv[])
{
    char *buf = zcl_malloc(RS_BUF, "rs_spawn");
    if (!buf)
        return NULL;
    if (zcl_spawn_capture(argv, buf, RS_BUF, 120 * 1000) < 0)
        buf[0] = '\0';
    return buf;
}

static bool rs_land_live(const struct rs_ctx *c, const char *n)
{
    char needle[48];
    (void)snprintf(needle, sizeof(needle), "z23-stacks%s:", n);
    return strstr(c->land, needle) != NULL;
}

static bool rs_gate_running(const struct rs_ctx *c, const char *s)
{
    char needle[64];
    const char *at = c->units;
    size_t len;
    (void)snprintf(needle, sizeof(needle), "z23-gate-stack-%s", s);
    len = strlen(needle);
    while ((at = strstr(at, needle)) != NULL) {
        if (!isdigit((unsigned char)at[len]))
            return true;
        at += len;
    }
    return false;
}

/* The state of the last outcomes row naming this stack's worktree, "" when
 * there is none (or its state is not lower-case letters). */
static void rs_outcome_state(const struct rs_ctx *c, const char *n,
                             char *out, size_t cap)
{
    char needle[DB_PATH + 64];
    const char *line, *last = NULL, *at;
    size_t pos = 0, len, last_len = 0;
    out[0] = '\0';
    (void)snprintf(needle, sizeof(needle), "\"worktree\":\"%s/z23-stacks%s\"",
                   c->stacks, n);
    while (db_next_line(&c->outcomes, &pos, &line, &len)) {
        size_t nl = strlen(needle), i;
        for (i = 0; i + nl <= len; i++) {
            if (memcmp(line + i, needle, nl) == 0) {
                last = line;
                last_len = len;
                break;
            }
        }
    }
    if (!last)
        return;
    for (at = last; at + 9 < last + last_len; at++) {
        size_t k = 0;
        if (strncmp(at, "\"state\":\"", 9) != 0)
            continue;
        while (at + 9 + k < last + last_len && islower((unsigned char)at[9 + k]))
            k++;
        if (at + 9 + k < last + last_len && at[9 + k] == '"' && k + 1 < cap) {
            memcpy(out, at + 9, k);
            out[k] = '\0';
            return;
        }
    }
}

/* The last line of a gate's run.log: rc=0 passed, rc=N failed, else unknown. */
static int rs_run_rc(const struct rs_ctx *c, const char *dir)
{
    char path[DB_PATH + 64];
    struct db_text t;
    size_t n;
    const char *start;
    int rc = 0; /* 0 unknown or passed, 1 failed */
    if (!db_join(path, sizeof(path), dir, "run.log") || !db_text_load(path, &t))
        return 0;
    n = t.n;
    if (n > 0 && t.p[n - 1] == '\n')
        n--;
    for (start = t.p + n; start > t.p && start[-1] != '\n'; start--)
        ;
    if (strncmp(start, "rc=", 3) == 0 && (size_t)(t.p + n - start) > 0)
        rc = ((size_t)(t.p + n - start) == 4 && start[3] == '0') ? 0 : 1;
    db_text_free(&t);
    (void)c;
    return rc;
}

/* True when the stack's last land row failed or conflicted, or its gate failed
 * without submitting; *no_outcome is true for the second kind. */
static bool rs_stranded(const struct rs_ctx *c, const char *s, bool *no_outcome)
{
    char state[24], dir[DB_PATH + 64];
    const char *n = s + 1;
    *no_outcome = false;
    if (rs_land_live(c, n) || rs_gate_running(c, s))
        return false;
    rs_outcome_state(c, n, state, sizeof(state));
    if (!strcmp(state, "failed") || !strcmp(state, "conflict"))
        return true;
    if (state[0])
        return false;
    (void)snprintf(dir, sizeof(dir), "%s/z23-stacks%s", c->gate_dir, n);
    *no_outcome = true;
    return rs_run_rc(c, dir) != 0;
}

/* ── naming the culprit files of a gate failure ────────────────────────── */

static bool rs_buf_add(struct db_text *t, const char *s, size_t n)
{
    char *grown = zcl_realloc(t->p, t->n + n + 2, "rs_names");
    if (!grown)
        return false;
    t->p = grown;
    memcpy(t->p + t->n, s, n);
    t->n += n;
    t->p[t->n++] = '\n';
    t->p[t->n] = '\0';
    return true;
}

static bool rs_line_ignored(const char *line, size_t len)
{
    static const char *const words[] = {"zcc ", "clang ", "gcc "};
    size_t i, k;
    if (len == 0 || line[0] == '\t')
        return true;
    if (len >= 9 && !memcmp(line, "devbuild:", 9))
        return true;
    if (len >= 13 && !memcmp(line, "gen_templates", 13))
        return true;
    for (k = 0; k < 3; k++) {
        size_t wl = strlen(words[k]);
        for (i = 0; i + wl <= len; i++)
            if (!memcmp(line + i, words[k], wl))
                return true;
    }
    return false;
}

static bool rs_isword(int ch) { return isalnum(ch) || ch == '_'; }

static bool rs_isclass(int ch)
{
    return isalnum(ch) || ch == '_' || ch == '.' || ch == '/' || ch == '-';
}

/* grep -o '[a-z][A-Za-z0-9_./-]*\.[ch]\b': the leftmost-longest match at or
 * after *pos; false when there is none. */
static bool rs_next_name(const char *s, size_t len, size_t *pos, size_t *from,
                         size_t *to)
{
    size_t i, run, e;
    for (i = *pos; i < len; i++) {
        if (!islower((unsigned char)s[i]))
            continue;
        for (run = i + 1; run < len && rs_isclass((unsigned char)s[run]); run++)
            ;
        for (e = run; e >= i + 3; e--) {
            if (s[e - 2] == '.' && (s[e - 1] == 'c' || s[e - 1] == 'h') &&
                (e == len || !rs_isword((unsigned char)s[e]))) {
                *from = i;
                *to = e;
                *pos = e;
                return true;
            }
        }
    }
    return false;
}

static bool rs_names_from_line(struct db_text *names, const char *line,
                               size_t len)
{
    size_t pos = 0, from, to;
    while (rs_next_name(line, len, &pos, &from, &to))
        if (!rs_buf_add(names, line + from, to - from))
            return false;
    return true;
}

static void rs_log_choice(const struct rs_ctx *c, const char *dir, char *out,
                          size_t cap)
{
    char run[DB_PATH + 64];
    struct db_text t;
    const char *name = "lint.log";
    (void)c;
    if (db_join(run, sizeof(run), dir, "run.log") && db_text_load(run, &t)) {
        if (strstr(t.p, "STOP: fast"))
            name = "fast.log";
        if (strstr(t.p, "STOP: agent-verify"))
            name = "av-fail.txt";
        db_text_free(&t);
    }
    (void)db_join(out, cap, dir, name);
}

/* The files a no-outcome gate failure names, one per line. */
static bool rs_collect_names(const struct rs_ctx *c, const char *n,
                             struct db_text *names)
{
    char dir[DB_PATH + 64], log[DB_PATH + 96];
    struct db_text t;
    size_t pos = 0, len;
    const char *line;
    bool ok = true;
    (void)snprintf(dir, sizeof(dir), "%s/z23-stacks%s", c->gate_dir, n);
    rs_log_choice(c, dir, log, sizeof(log));
    if (!db_text_load(log, &t))
        return true;
    while (ok && db_next_line(&t, &pos, &line, &len))
        if (!rs_line_ignored(line, len))
            ok = rs_names_from_line(names, line, len);
    db_text_free(&t);
    return ok;
}

/* grep -q -x -F -f names: some diff line equals some name line. */
static bool rs_lines_meet(const char *diff, const struct db_text *names)
{
    struct db_text d = {(char *)diff, strlen(diff)};
    size_t dp = 0, dl, np, nl;
    const char *dline, *nline;
    while (db_next_line(&d, &dp, &dline, &dl)) {
        np = 0;
        while (db_next_line(names, &np, &nline, &nl))
            if (dl == nl && dl > 0 && !memcmp(dline, nline, dl))
                return true;
    }
    return false;
}

/* ── the per-lane checks, in the bridge's order ────────────────────────── */

static bool rs_hex_ok(const char *h)
{
    size_t n = strlen(h), i;
    if (n != 40 && n != 64)
        return false;
    for (i = 0; i < n; i++)
        if (!isxdigit((unsigned char)h[i]))
            return false;
    return true;
}

static size_t rs_done_count(const struct rs_ctx *c, const char *lane,
                            const char *head)
{
    size_t pos = 0, len, n = 0;
    const char *line;
    while (db_next_line(&c->done, &pos, &line, &len))
        if (db_field_is(line, len, 0, lane) && db_field_is(line, len, 1, head))
            n++;
    return n;
}

/* Same tree = not moved: gate-submit's author re-stamp changes the sha only. */
static bool rs_same_tree(const struct rs_ctx *c, const char *lane,
                         const char *head)
{
    const char *now_args[] = {"rev-parse", "HEAD^{tree}", NULL};
    const char *old_args[] = {"rev-parse", NULL, NULL};
    char now[128] = "", old[128] = "", spec[128];
    if (!rs_hex_ok(head))
        return false;
    (void)snprintf(spec, sizeof(spec), "%s^{tree}", head);
    old_args[1] = spec;
    (void)db_git_line(lane, now_args, now, sizeof(now));
    (void)db_git_line(lane, old_args, old, sizeof(old));
    (void)c;
    return strcmp(now, old) == 0;
}

static bool rs_taken(const struct rs_ctx *c, const char *lane)
{
    size_t i;
    for (i = 0; i < c->ntake; i++)
        if (!strcmp(c->take[i].lane, lane))
            return true;
    return false;
}

/* On main in substance: no commit of the lane is missing from origin/main. */
static bool rs_has_new_commits(struct rs_ctx *c, const char *lane)
{
    const char *args[] = {"cherry", "origin/main", "HEAD", NULL};
    size_t pos = 0, len;
    struct db_text t;
    const char *line;
    if (db_git(lane, args, c->scratch, RS_BUF) != 0)
        return false;
    t.p = c->scratch;
    t.n = strlen(c->scratch);
    while (db_next_line(&t, &pos, &line, &len))
        if (len > 0 && line[0] == '+')
            return true;
    return false;
}

static bool rs_baseline_has(const struct rs_ctx *c, const char *file)
{
    size_t pos = 0, len, fl = strlen(file);
    const char *line;
    while (db_next_line(&c->baseline, &pos, &line, &len))
        if (len > fl && !memcmp(line, file, fl) && line[fl] == ':')
            return true;
    return false;
}

/* A complexity lane whose files lost every baseline row has landed in
 * substance (the land rebase can change patch ids). */
static bool rs_cx_left(struct rs_ctx *c, const char *lane)
{
    const char *args[] = {"diff", "--name-only", "origin/main...HEAD", "--",
                          "*.c", "*.h", NULL};
    struct db_text t;
    size_t pos = 0, len;
    const char *line;
    char file[DB_PATH];
    if (db_git(lane, args, c->scratch, RS_BUF) != 0)
        return false;
    t.p = c->scratch;
    t.n = strlen(c->scratch);
    while (db_next_line(&t, &pos, &line, &len))
        if (len < sizeof(file)) {
            memcpy(file, line, len);
            file[len] = '\0';
            if (rs_baseline_has(c, file))
                return true;
        }
    return false;
}

static bool rs_named_hit(struct rs_ctx *c, const char *lane,
                         const struct db_text *names)
{
    const char *args[] = {"diff", "--name-only", "origin/main...HEAD", NULL};
    if (names->n == 0 || db_git(lane, args, c->scratch, RS_BUF) != 0)
        return false;
    return rs_lines_meet(c->scratch, names);
}

static enum rs_verdict rs_lane(struct rs_ctx *c, const char *lane,
                               const char *head, const char *s,
                               const struct db_text *names)
{
    struct stat st;
    if (stat(lane, &st) != 0 || !S_ISDIR(st.st_mode))
        return RS_SILENT;
    if (rs_named_hit(c, lane, names)) {
        rs_say(c, "restack-failed: %s is named in %s's gate failure; left for "
                  "triage", rs_base(lane), s);
        return RS_SAID;
    }
    if (rs_done_count(c, lane, head) >= 2) {
        rs_say(c, "restack-failed: %s failed twice after restacking; left for "
                  "triage", rs_base(lane));
        return RS_SAID;
    }
    if (!rs_same_tree(c, lane, head)) {
        rs_say(c, "restack-failed: %s moved since review; skipped",
               rs_base(lane));
        return RS_SAID;
    }
    if (db_has_first_field(&c->pending, lane) || rs_taken(c, lane) ||
        !rs_has_new_commits(c, lane))
        return RS_SILENT;
    if (!strncmp(rs_base(lane), "cx-", 3) && !rs_cx_left(c, lane))
        return RS_SILENT;
    return RS_TAKE;
}

/* ── one pass ──────────────────────────────────────────────────────────── */

static bool rs_take_add(struct rs_ctx *c, const char *lane, const char *head,
                        const char *s)
{
    struct rs_take *t;
    if (c->ntake == c->captake) {
        size_t cap = c->captake ? c->captake * 2 : 16;
        struct rs_take *grown = zcl_realloc(c->take, cap * sizeof(*grown),
                                            "rs_take");
        if (!grown)
            return false;
        c->take = grown;
        c->captake = cap;
    }
    t = &c->take[c->ntake++];
    (void)snprintf(t->lane, sizeof(t->lane), "%s", lane);
    (void)snprintf(t->head, sizeof(t->head), "%s", head);
    (void)snprintf(t->stack, sizeof(t->stack), "%s", s);
    return true;
}

static bool rs_stack_lanes(struct rs_ctx *c, const char *s,
                           const struct db_text *names)
{
    size_t pos = 0, len;
    const char *line;
    char lane[DB_PATH], head[84];
    while (db_next_line(&c->ledger, &pos, &line, &len)) {
        if (!db_field_is(line, len, 2, s) ||
            !db_field_copy(line, len, 0, lane, sizeof(lane)) ||
            !db_field_copy(line, len, 1, head, sizeof(head)))
            continue;
        if (rs_lane(c, lane, head, s, names) == RS_TAKE &&
            !rs_take_add(c, lane, head, s))
            return false;
    }
    return true;
}

static bool rs_stack(struct rs_ctx *c, const char *s)
{
    struct db_text names = {NULL, 0};
    bool none = false, ok;
    if (!rs_stranded(c, s, &none))
        return true;
    if (none && !rs_collect_names(c, s + 1, &names)) {
        db_text_free(&names);
        return false;
    }
    if (!names.p)
        names.p = zcl_calloc(1, 1, "rs_names_empty");
    ok = names.p != NULL && rs_stack_lanes(c, s, &names);
    db_text_free(&names);
    return ok;
}

static int rs_vercmp(const void *a, const void *b)
{
    const char *x = a, *y = b;
    unsigned long nx = strtoul(x + 1, NULL, 10), ny = strtoul(y + 1, NULL, 10);
    if (nx != ny)
        return nx < ny ? -1 : 1;
    return strcmp(x, y);
}

/* Every distinct stack id in the ledger, in version order (s10 before s100). */
static char (*rs_stack_ids(const struct rs_ctx *c, size_t *count))[24]
{
    size_t pos = 0, len, n = 0, i, uniq = 0;
    const char *line;
    char s[24];
    char (*ids)[24] = zcl_malloc(24 * (c->ledger.n / 4 + 2), "rs_ids");
    *count = 0;
    if (!ids)
        return NULL;
    while (db_next_line(&c->ledger, &pos, &line, &len))
        if (db_field_copy(line, len, 2, s, sizeof(s)) && s[0] == 's')
            (void)snprintf(ids[n++], 24, "%s", s);
    qsort(ids, n, 24, rs_vercmp);
    for (i = 0; i < n; i++)
        if (uniq == 0 || strcmp(ids[uniq - 1], ids[i]) != 0)
            memmove(ids[uniq++], ids[i], 24);
    *count = uniq;
    return ids;
}

/* ── the write path ────────────────────────────────────────────────────── */

static bool rs_take_has_pair(const struct rs_ctx *c, const char *line,
                             size_t len)
{
    size_t i;
    for (i = 0; i < c->ntake; i++)
        if (db_field_is(line, len, 0, c->take[i].lane) &&
            db_field_is(line, len, 1, c->take[i].head))
            return true;
    return false;
}

/* Drop the taken rows first, or the tick would refuse each lane as batched. */
static bool rs_ledger_drop(const struct rs_ctx *c)
{
    size_t pos = 0, len, used = 0;
    const char *line;
    char *out = zcl_malloc(c->ledger.n + 2, "rs_ledger_out");
    bool ok;
    if (!out)
        return false;
    while (db_next_line(&c->ledger, &pos, &line, &len)) {
        if (rs_take_has_pair(c, line, len))
            continue;
        memcpy(out + used, line, len);
        out[used + len] = '\n';
        used += len + 1;
    }
    ok = db_text_save(c->p.ledger, out, used);
    free(out);
    return ok;
}

static void rs_utc_now(char out[32])
{
    struct tm tm_utc;
    time_t now = platform_time_wall_time_t();
    (void)gmtime_r(&now, &tm_utc);
    (void)strftime(out, 32, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

static bool rs_record_one(const struct rs_ctx *c, const struct rs_take *t,
                          const char *when)
{
    char row[DB_PATH + 512];
    int n = snprintf(row, sizeof(row),
                     "%s\t%s: restacked after %s failed (reviewed LAND at "
                     "%.12s)\n",
                     t->lane, rs_base(t->lane), t->stack, t->head);
    if (n <= 0 || (size_t)n >= sizeof(row) ||
        !db_append(c->p.pending, row, (size_t)n))
        return false;
    n = snprintf(row, sizeof(row), "%s\t%s\t%s\t%s\n", t->lane, t->head,
                 t->stack, when);
    return n > 0 && (size_t)n < sizeof(row) &&
           db_append(c->p.restacked, row, (size_t)n);
}

static bool rs_apply(const struct rs_ctx *c)
{
    char when[32];
    size_t i;
    rs_utc_now(when);
    if (!rs_ledger_drop(c))
        return false;
    for (i = 0; i < c->ntake; i++)
        if (!rs_record_one(c, &c->take[i], when))
            return false;
    return true;
}

/* ── setup, teardown, report ───────────────────────────────────────────── */

static bool rs_spaced(const struct rs_ctx *c)
{
    char stamp[DB_PATH + 64];
    struct stat st;
    if (!db_join(stamp, sizeof(stamp), c->p.state, ".restack-failed.stamp"))
        return false;
    return stat(stamp, &st) == 0 &&
           platform_time_wall_time_t() - st.st_mtime < RS_SPACING_S;
}

static void rs_touch_stamp(const struct rs_ctx *c)
{
    char stamp[DB_PATH + 64];
    int fd;
    if (!db_join(stamp, sizeof(stamp), c->p.state, ".restack-failed.stamp"))
        return;
    fd = open(stamp, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
    if (fd >= 0) {
        (void)futimens(fd, NULL);
        (void)close(fd);
    }
}

static void rs_free(struct rs_ctx *c)
{
    db_text_free(&c->ledger);
    db_text_free(&c->pending);
    db_text_free(&c->done);
    db_text_free(&c->outcomes);
    db_text_free(&c->baseline);
    free(c->land);
    free(c->units);
    free(c->scratch);
    free(c->take);
    json_free(&c->lines);
}

static bool rs_derive(const struct json_value *in, struct rs_ctx *c,
                      struct zcl_command_reply *reply)
{
    if (!db_paths_init(in, &c->p, reply))
        return false;
    if (!db_join(c->main, sizeof(c->main), c->p.home, "development/z23/main") ||
        !db_join(c->stacks, sizeof(c->stacks), c->p.home, "development/z23") ||
        !db_join(c->gate_dir, sizeof(c->gate_dir), c->p.home,
                 ".cache/development-scratch/z23/gate-submit")) {
        db_refuse(reply, "BAD_HOME", "paths", "home path too long");
        return false;
    }
    return true;
}

static bool rs_load_files(struct rs_ctx *c)
{
    char outcomes[DB_PATH + 64];
    const char *show[] = {"show",
                          "origin/main:tools/lint/"
                          "cyclomatic_complexity_baseline.txt",
                          NULL};
    if (!db_join(outcomes, sizeof(outcomes), c->p.home,
                 ".local/state/z23/dev/land/outcomes.jsonl"))
        return false;
    c->scratch = zcl_malloc(RS_BUF, "rs_scratch");
    if (!c->scratch || !db_text_load(c->p.ledger, &c->ledger) ||
        !db_text_load(c->p.pending, &c->pending) ||
        !db_text_load(c->p.restacked, &c->done) ||
        !db_text_load(outcomes, &c->outcomes))
        return false;
    if (db_git(c->main, show, c->scratch, RS_BUF) != 0)
        return false;
    c->baseline.n = strlen(c->scratch);
    c->baseline.p = zcl_malloc(c->baseline.n + 1, "rs_baseline");
    if (!c->baseline.p)
        return false;
    memcpy(c->baseline.p, c->scratch, c->baseline.n + 1);
    return true;
}

static bool rs_live_picture(const struct json_value *in, struct rs_ctx *c)
{
    const char *dev = db_opt_str(in, "dev_bin");
    const char *sysctl = db_opt_str(in, "systemctl");
    char devpath[DB_PATH + 32];
    const char *land_argv[] = {NULL, "dev", "land", "status", NULL};
    const char *unit_argv[] = {NULL, "--user", "list-units", "--no-pager",
                               "--plain", "--state=running",
                               "z23-gate-stack-*", NULL};
    if (!dev[0]) {
        if (!db_join(devpath, sizeof(devpath), c->main, "build/bin/z23-dev"))
            return false;
        dev = devpath;
    }
    land_argv[0] = dev;
    unit_argv[0] = sysctl[0] ? sysctl : "systemctl";
    c->land = rs_spawn_text(land_argv);
    c->units = rs_spawn_text(unit_argv);
    return c->land && c->units;
}

static void rs_publish(struct zcl_command_reply *reply, const struct rs_ctx *c,
                       bool dry)
{
    struct json_value list;
    size_t i;
    json_init(&list);
    json_set_array(&list);
    for (i = 0; i < c->ntake; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "lane", c->take[i].lane);
        (void)json_push_kv_str(&row, "head", c->take[i].head);
        (void)json_push_kv_str(&row, "stack", c->take[i].stack);
        (void)json_push_back(&list, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "restack", &list);
    json_free(&list);
    (void)json_push_kv(&reply->data, "lines", &c->lines);
    (void)json_push_kv_bool(&reply->data, "dry_run", dry);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)c->ntake);
}

static bool rs_pass(const struct json_value *in, struct rs_ctx *c, bool dry,
                    struct zcl_command_reply *reply)
{
    size_t count = 0, i;
    char (*ids)[24];
    bool ok = true;
    if (!rs_load_files(c)) {
        db_refuse(reply, "STATE_UNREADABLE", "load",
                  "restack: a ledger file, the baseline or a buffer could "
                  "not be read");
        return false;
    }
    if (!rs_live_picture(in, c) || !strstr(c->land, "\"ok\":true")) {
        rs_say(c, "restack-failed: land status unreadable; nothing restacked");
        return true;
    }
    ids = rs_stack_ids(c, &count);
    if (!ids) {
        db_refuse(reply, "NO_MEMORY", "load", "restack: out of memory");
        return false;
    }
    for (i = 0; ok && i < count; i++)
        ok = rs_stack(c, ids[i]);
    free(ids);
    if (!ok) {
        db_refuse(reply, "NO_MEMORY", "decide", "restack: out of memory");
        return false;
    }
    if (c->ntake == 0)
        return true;
    if (dry) {
        rs_say(c, "restack-failed: %zu lanes would go back (dry run)", c->ntake);
        return true;
    }
    if (!rs_apply(c)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "LEDGER_WRITE_FAILED",
                               "write", false, true,
                               "restack: a ledger file could not be written",
                               c->p.state);
        return false;
    }
    rs_say(c, "restack-failed: %zu reviewed lanes back in stack-pending",
           c->ntake);
    return true;
}

/* Create the three ledgers the bridge touches before it reads them. */
static bool rs_touch_ledgers(const struct rs_ctx *c)
{
    return db_append(c->p.ledger, "", 0) && db_append(c->p.pending, "", 0) &&
           db_append(c->p.restacked, "", 0);
}

void zcl_native_handle_dev_batch_restack(const struct zcl_command_request *request,
                                         struct zcl_command_reply *reply)
{
    const struct json_value *in;
    struct rs_ctx c;
    bool dry, now, ok;
    if (!reply)
        return;
    in = request ? request->input : NULL;
    if (!in) {
        db_refuse(reply, "BAD_INPUT", "input", "dev.batch.restack needs input");
        return;
    }
    memset(&c, 0, sizeof(c));
    json_init(&c.lines);
    json_set_array(&c.lines);
    dry = db_opt_flag(in, "dry_run");
    now = db_opt_flag(in, "now");
    if (!rs_derive(in, &c, reply))
        goto done;
    (void)json_push_kv_str(&reply->data, "leaf", "dev.batch.restack");
    if (!dry && !now && rs_spaced(&c)) {
        (void)json_push_kv_bool(&reply->data, "spaced", true);
        goto done;
    }
    if (!dry && !rs_touch_ledgers(&c)) {
        db_refuse(reply, "STATE_UNWRITABLE", "load",
                  "restack: the state directory is not writable");
        goto done;
    }
    if (!dry)
        rs_touch_stamp(&c);
    ok = rs_pass(in, &c, dry, reply);
    if (ok)
        rs_publish(reply, &c, dry);
done:
    rs_free(&c);
}
