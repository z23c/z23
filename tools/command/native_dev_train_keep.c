/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.train.keep — the unattended train keeper. One bounded pass
 *          over one train's state machine, safe to run from a timer with no
 *          agent session alive: it assembles the LAND-verdict queue onto the
 *          base, gates it, writes READY, and hands the landing to the
 *          existing land_pre.sh/land_unit.sh contract.
 *
 * WHY A STATE MACHINE ON DISK. Agents die overnight; the box reboots; the
 * timer fires every five minutes regardless. Every pass therefore starts by
 * reading <train dir>/KEEP.json and does only the one step that state
 * allows, then returns. There is no loop, no sleep and no wait anywhere in
 * this file — the timer is the loop.
 *
 *   idle -> picking -> gating -> ready -> landing -> landed
 *                \          \        \         \
 *                 `---------->`------->`-------->  blocked
 *
 * A crash inside `picking` leaves a half-assembled worktree that only a
 * human can judge, so it resolves to `blocked`. A crash inside `gating`
 * leaves a fully assembled worktree whose gates simply have not been run,
 * so it resumes by running them again. `blocked` never retries on its own:
 * it prints why and returns, because a keeper that retried the same failing
 * assembly every five minutes forever is a keeper that burns a box down
 * while telling nobody. A human or another agent clears a block by fixing
 * the queue and deleting KEEP.json's block, which is one file edit.
 *
 * PROCESS RULE, inherited from native_dev_train_command.c: git runs only
 * through zcl_dev_train_git() (util/spawn.h), make and the two landing shell
 * helpers run only through zcl_devloop_process_run() (tools/dev/devloop.h).
 * No popen(), no system(), no shell command string appears in this file —
 * land_pre.sh and land_unit.sh are exec'd as the executables they are.
 */

#include "command/native_command.h"
#include "command/native_dev_train_command.h"

#include "devloop.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/directory_compat.h"
#include "platform/process_lock.h"
#include "platform/time_compat.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DTK_LEAF "dev.train.keep"

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)

/* A train number names a directory, a worktree and a systemd unit. Keep it
 * small and positive so none of those three can be surprised by it. */
#define DTK_TRAIN_MIN 1
#define DTK_TRAIN_MAX 9999
#define DTK_MAX_PICKS 64
#define DTK_PATH 1024
#define DTK_LINE 1024
#define DTK_GIT_TIMEOUT_MS 60000
#define DTK_FETCH_TIMEOUT_MS 180000
/* One gate is a whole `make lint` in a cold worktree. This is the ceiling on
 * a single child, not a budget the keeper spends: it returns as soon as the
 * child does. */
#define DTK_GATE_TIMEOUT_MS 3600000
#define DTK_HELPER_TIMEOUT_MS 600000

struct dtk_paths {
    char scratch[DTK_PATH];   /* <scratch root> */
    char dir[DTK_PATH];       /* <scratch root>/train<N> */
    char queue[DTK_PATH];     /* .../late_picks.txt */
    char picks[DTK_PATH];     /* .../picks.txt */
    char ready[DTK_PATH];     /* .../READY */
    char base[DTK_PATH];      /* .../BASE */
    char state[DTK_PATH];     /* .../KEEP.json */
    char log[DTK_PATH];       /* .../keep.log */
    char lock[DTK_PATH];      /* .../keep.lock */
    char board[DTK_PATH];     /* .../board_post.txt */
    char wt[DTK_PATH];        /* <trains root>/train<N> */
    char land_pre[DTK_PATH];  /* <helper dir>/land_pre.sh */
    char land_unit[DTK_PATH]; /* <helper dir>/land_unit.sh */
    char outcomes[DTK_PATH];  /* <state root>/land/outcomes.jsonl */
    char name[32];            /* "train<N>" */
    int train;
};

struct dtk_pick {
    char name[64];
    char sha[41];
};

struct dtk_state {
    char state[32];
    char base[41];
    char tip[41];
    char reason[256];
    int64_t picks;
};

/* ── tiny file and string helpers ──────────────────────────────────────── */

static bool dtk_join(const char *dir, const char *leaf, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", dir, leaf);
    return n > 0 && (size_t)n < cap;
}

static bool dtk_is_hex40(const char *s)
{
    if (!s || strlen(s) != 40)
        return false;
    for (size_t i = 0; i < 40; i++) {
        char c = s[i];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex)
            return false;
    }
    return true;
}

/* Only [A-Za-z0-9_.-], 1..47 bytes, no leading '-': a queue row's name is
 * concatenated into `refs/review/<name>` and printed into a board line, so
 * it must never be able to name a ref outside that namespace. */
static bool dtk_name_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
}

static bool dtk_valid_name(const char *s)
{
    size_t len = s ? strlen(s) : 0;
    if (len == 0 || len > 47 || s[0] == '-' || strstr(s, "..") != NULL)
        return false;
    for (size_t i = 0; i < len; i++)
        if (!dtk_name_char(s[i]))
            return false;
    return true;
}

static bool dtk_read_first_line(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    bool ok = fgets(out, (int)cap, f) != NULL;
    (void)fclose(f);
    if (ok)
        zcl_dev_train_strip(out);
    return ok;
}

/* Write `text` to `path` through a sibling temp file plus rename, so a
 * keeper killed mid-write never leaves a half-parsed state file behind. */
static bool dtk_write_atomic(const char *path, const char *text)
{
    char tmp[DTK_PATH + 8];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
        return false;
    FILE *f = fopen(tmp, "wb");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    ok = (fclose(f) == 0) && ok;
    if (!ok || rename(tmp, path) != 0) {
        (void)remove(tmp);
        return false;
    }
    return true;
}

static void dtk_now_iso(char out[64])
{
    const char *injected = getenv("ZCL_TRAIN_KEEP_NOW");
    if (injected && injected[0]) {
        (void)snprintf(out, 64, "%s", injected);
        return;
    }
    time_t now = platform_time_wall_time_t();
    struct tm tm_utc;
    memset(&tm_utc, 0, sizeof(tm_utc));
#if defined(_WIN32)
    (void)gmtime_s(&tm_utc, &now);
#else
    (void)gmtime_r(&now, &tm_utc);
#endif
    (void)strftime(out, 64, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

/* Every step's transcript lands in <train dir>/keep.log. An unattended run
 * that left no trace of what it did would be worse than no run at all. */
static void dtk_log(const struct dtk_paths *p, const char *label,
                    const char *body)
{
    FILE *f = fopen(p->log, "ab");
    if (!f)
        return;
    char now[64];
    dtk_now_iso(now);
    (void)fprintf(f, "%s %s: %s\n", now, label, body ? body : "");
    (void)fclose(f);
}

/* ── paths ─────────────────────────────────────────────────────────────── */

/* `env` when non-empty, else $HOME + `suffix`. The caller passes the getenv()
 * itself so the three overrides are readable as literals at their one call
 * site: they exist only so the acceptance test can point a whole keeper at a
 * scratch tree, and a real run never sets them. */
static bool dtk_root(const char *env, const char *suffix, char *out,
                     size_t cap)
{
    if (env && env[0])
        return snprintf(out, cap, "%s", env) < (int)cap;
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return false;
    return snprintf(out, cap, "%s%s", home, suffix) < (int)cap;
}

/* The seven files the keeper reads and writes inside <scratch>/train<N>. */
static bool dtk_paths_files(struct dtk_paths *p)
{
    return dtk_join(p->dir, "late_picks.txt", p->queue, sizeof(p->queue)) &&
           dtk_join(p->dir, "picks.txt", p->picks, sizeof(p->picks)) &&
           dtk_join(p->dir, "READY", p->ready, sizeof(p->ready)) &&
           dtk_join(p->dir, "BASE", p->base, sizeof(p->base)) &&
           dtk_join(p->dir, "KEEP.json", p->state, sizeof(p->state)) &&
           dtk_join(p->dir, "keep.log", p->log, sizeof(p->log)) &&
           dtk_join(p->dir, "keep.lock", p->lock, sizeof(p->lock)) &&
           dtk_join(p->dir, "board_post.txt", p->board, sizeof(p->board));
}

static bool dtk_paths_init(int train, struct dtk_paths *p, bool dry_run)
{
    char trains[DTK_PATH], helpers[DTK_PATH], land[PATH_MAX];
    memset(p, 0, sizeof(*p));
    p->train = train;
    if (snprintf(p->name, sizeof(p->name), "train%d", train) >=
        (int)sizeof(p->name))
        return false;
    if (!dtk_root(getenv("ZCL_TRAIN_SCRATCH_ROOT"),
                  "/.local/state/zclassic23/scratch", p->scratch,
                  sizeof(p->scratch)) ||
        !dtk_root(getenv("ZCL_TRAIN_WORKTREE_ROOT"), "/.z23/trains", trains,
                  sizeof(trains)) ||
        !dtk_root(getenv("ZCL_TRAIN_HELPER_DIR"),
                  "/.local/state/zclassic23/scratch/northstar", helpers,
                  sizeof(helpers)))
        return false;
    bool land_resolved = dry_run
        ? zcl_dev_train_land_dir_existing(land, sizeof(land))
        : zcl_dev_train_land_dir(land, sizeof(land));
    if (!land_resolved)
        return false;
    return dtk_join(p->scratch, p->name, p->dir, sizeof(p->dir)) &&
           dtk_join(trains, p->name, p->wt, sizeof(p->wt)) &&
           dtk_join(helpers, "land_pre.sh", p->land_pre, sizeof(p->land_pre)) &&
           dtk_join(helpers, "land_unit.sh", p->land_unit,
                    sizeof(p->land_unit)) &&
           dtk_join(land, "outcomes.jsonl", p->outcomes, sizeof(p->outcomes)) &&
           dtk_paths_files(p);
}

/* ── persisted state ───────────────────────────────────────────────────── */

static void dtk_state_str(const struct json_value *obj, const char *key,
                          char *out, size_t cap)
{
    const char *s = json_get_str(json_get(obj, key));
    (void)snprintf(out, cap, "%s", s ? s : "");
}

/* A missing state file is a genuinely idle train — the normal case before
 * any pass has ever run. A PRESENT but unparseable state file is a
 * different fact entirely: something wrote (or partially wrote, or
 * corrupted) KEEP.json outside the atomic temp+rename path this leaf always
 * uses, and this leaf cannot tell what step that file was trying to record.
 * Treating that ambiguity as "idle" would make a keeper that starts a fresh
 * assembly over whatever the previous, unreadable pass was doing — exactly
 * the silent-restart failure mode the state machine exists to rule out. So
 * "file present but unreadable" resolves to `blocked`, the same as any
 * other state this leaf does not recognize. */
static void dtk_state_load(const struct dtk_paths *p, struct dtk_state *st)
{
    char raw[4096];
    memset(st, 0, sizeof(*st));
    (void)snprintf(st->state, sizeof(st->state), "idle");
    FILE *f = fopen(p->state, "rb");
    if (!f)
        return;
    size_t n = fread(raw, 1, sizeof(raw) - 1, f);
    bool read_err = ferror(f) != 0;
    (void)fclose(f);
    raw[n] = '\0';
    struct json_value v;
    json_init(&v);
    if (!read_err && json_read(&v, raw, n) && v.type == JSON_OBJ) {
        dtk_state_str(&v, "state", st->state, sizeof(st->state));
        dtk_state_str(&v, "base", st->base, sizeof(st->base));
        dtk_state_str(&v, "tip", st->tip, sizeof(st->tip));
        dtk_state_str(&v, "reason", st->reason, sizeof(st->reason));
        st->picks = json_get_int(json_get(&v, "picks"));
        if (!st->state[0])
            (void)snprintf(st->state, sizeof(st->state), "idle");
    } else {
        (void)snprintf(st->state, sizeof(st->state), "blocked");
        (void)snprintf(st->reason, sizeof(st->reason),
                      "KEEP.json is present but unreadable or not valid JSON; a "
                      "previous keeper may have died mid-write outside the "
                      "atomic path — inspect and repair or remove it");
    }
    json_free(&v);
}

static bool dtk_state_save(const struct dtk_paths *p,
                           const struct dtk_state *st)
{
    char now[64], buf[4096];
    dtk_now_iso(now);
    struct json_value v;
    json_init(&v);
    json_set_object(&v);
    (void)json_push_kv_int(&v, "train", p->train);
    (void)json_push_kv_str(&v, "state", st->state);
    (void)json_push_kv_str(&v, "base", st->base);
    (void)json_push_kv_str(&v, "tip", st->tip);
    (void)json_push_kv_str(&v, "reason", st->reason);
    (void)json_push_kv_int(&v, "picks", st->picks);
    (void)json_push_kv_str(&v, "updated", now);
    size_t need = json_write(&v, buf, sizeof(buf) - 2);
    json_free(&v);
    if (need >= sizeof(buf) - 2)
        return false;
    (void)strcat(buf, "\n");
    return dtk_write_atomic(p->state, buf);
}

static void dtk_set(struct dtk_state *st, const char *state, const char *why)
{
    (void)snprintf(st->state, sizeof(st->state), "%s", state);
    (void)snprintf(st->reason, sizeof(st->reason), "%s", why ? why : "");
}

/* ── the verdict queue ─────────────────────────────────────────────────── */

/* One `<name> <sha|PENDING> <verdict-file>` row. The verdict file is the
 * authority: its first line must read `LAND <full-sha>`, and when the row
 * carries a real sha of its own the two must agree. A row whose sha column
 * still reads PENDING is accepted at the verdict's sha — the verdict IS the
 * confirmation the column is waiting for — but a row that names a DIFFERENT
 * sha than the verdict is a queue that disagrees with itself and is skipped,
 * never guessed at. */
static bool dtk_queue_row(char *line, struct dtk_pick *out, char *why,
                          size_t why_cap)
{
    char *save = NULL;
    const char *name = strtok_r(line, " \t", &save);
    const char *sha = strtok_r(NULL, " \t", &save);
    const char *verdict = strtok_r(NULL, " \t", &save);
    char first[DTK_LINE];
    if (!name || !sha || !verdict) {
        (void)snprintf(why, why_cap, "malformed row");
        return false;
    }
    if (!dtk_valid_name(name)) {
        (void)snprintf(why, why_cap, "invalid lane name");
        return false;
    }
    if (!dtk_read_first_line(verdict, first, sizeof(first))) {
        (void)snprintf(why, why_cap, "verdict file unreadable");
        return false;
    }
    if (strncmp(first, "LAND ", 5) != 0 || !dtk_is_hex40(first + 5)) {
        (void)snprintf(why, why_cap, "no LAND verdict");
        return false;
    }
    if (strcmp(sha, "PENDING") != 0 && strcmp(sha, first + 5) != 0) {
        (void)snprintf(why, why_cap, "queue sha disagrees with the verdict");
        return false;
    }
    (void)snprintf(out->name, sizeof(out->name), "%s", name);
    (void)snprintf(out->sha, sizeof(out->sha), "%s", first + 5);
    return true;
}

static size_t dtk_queue_load(const struct dtk_paths *p, struct dtk_pick *picks,
                             struct json_value *skipped)
{
    FILE *f = fopen(p->queue, "rb");
    size_t n = 0;
    char line[DTK_LINE];
    if (!f)
        return 0;
    while (n < DTK_MAX_PICKS && fgets(line, sizeof(line), f)) {
        char why[128], copy[DTK_LINE];
        zcl_dev_train_strip(line);
        if (!line[0] || line[0] == '#')
            continue;
        (void)snprintf(copy, sizeof(copy), "%s", line);
        if (dtk_queue_row(copy, &picks[n], why, sizeof(why))) {
            n++;
            continue;
        }
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        (void)json_push_kv_str(&item, "row", line);
        (void)json_push_kv_str(&item, "reason", why);
        (void)json_push_back(skipped, &item);
        json_free(&item);
    }
    (void)fclose(f);
    return n;
}

/* ── git questions ─────────────────────────────────────────────────────── */

static bool dtk_rev_parse(const char *dir, const char *rev, char out[41])
{
    const char *args[] = {"rev-parse", "--verify", rev, NULL};
    char buf[128];
    if (zcl_dev_train_git(dir, args, buf, sizeof(buf), DTK_GIT_TIMEOUT_MS) != 0)
        return false;
    zcl_dev_train_strip(buf);
    if (!dtk_is_hex40(buf))
        return false;
    (void)snprintf(out, 41, "%s", buf);
    return true;
}

/* The base this queue was assembled against: the BASE file when the operator
 * pinned one, else today's origin/main. */
static bool dtk_queue_base(const struct dtk_paths *p, const char *root,
                           char out[41])
{
    char line[DTK_LINE];
    if (dtk_read_first_line(p->base, line, sizeof(line)) &&
        dtk_is_hex40(line)) {
        (void)snprintf(out, 41, "%s", line);
        return true;
    }
    return dtk_rev_parse(root, "origin/main", out);
}

/* ── assembly ──────────────────────────────────────────────────────────── */

/* Cherry-pick one lane's own commits: merge-base(base, sha)..sha, oldest
 * first, `-x -S`, skipping the regen/pin subjects zcl_dev_train_skip_subject()
 * owns. A conflict STOPS: this function never resolves one. */
static bool dtk_pick_one(const struct dtk_paths *p, const char *base,
                         const struct dtk_pick *pick, char *why, size_t cap)
{
    char mb[41], range[128], log_out[ZCL_DEVLOOP_OUTPUT_MAX];
    const char *mb_args[] = {"merge-base", base, pick->sha, NULL};
    if (zcl_dev_train_git(p->wt, mb_args, mb, sizeof(mb),
                          DTK_GIT_TIMEOUT_MS) != 0) {
        (void)snprintf(why, cap, "no merge-base for %s", pick->name);
        return false;
    }
    zcl_dev_train_strip(mb);
    (void)snprintf(range, sizeof(range), "%s..%s", mb, pick->sha);
    const char *log_args[] = {"log", "--reverse", "--format=%H%x1f%s", range,
                              NULL};
    if (zcl_dev_train_git(p->wt, log_args, log_out, sizeof(log_out),
                          DTK_GIT_TIMEOUT_MS) != 0) {
        (void)snprintf(why, cap, "cannot list %s for %s", range, pick->name);
        return false;
    }
    char *save = NULL;
    for (char *line = strtok_r(log_out, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *sep = strchr(line, '\x1f');
        if (!sep)
            continue;
        *sep = '\0';
        if (zcl_dev_train_skip_subject(sep + 1))
            continue;
        const char *pick_args[] = {"cherry-pick", "-x", "-S", line, NULL};
        if (zcl_dev_train_git(p->wt, pick_args, NULL, 0,
                              DTK_GIT_TIMEOUT_MS) != 0) {
            (void)snprintf(why, cap, "cherry-pick conflict on %s (%s)", line,
                          pick->name);
            return false;
        }
    }
    return true;
}

static bool dtk_worktree_open(const struct dtk_paths *p, const char *root,
                              const char *base, char *why, size_t cap)
{
    const char *args[] = {"worktree", "add", "--detach", p->wt, base, NULL};
    if (zcl_dev_train_is_dir(p->wt)) {
        (void)snprintf(why, cap, "train worktree already exists at %s", p->wt);
        return false;
    }
    if (zcl_dev_train_git(root, args, NULL, 0, DTK_FETCH_TIMEOUT_MS) != 0) {
        (void)snprintf(why, cap, "git worktree add failed at %s", p->wt);
        return false;
    }
    return true;
}

/* ── gates and regen ───────────────────────────────────────────────────── */

static bool dtk_make(const struct dtk_paths *p, const char *const argv[],
                     const char *label)
{
    struct zcl_devloop_process_result r;
    bool ran = zcl_devloop_process_run(p->wt, argv, DTK_GATE_TIMEOUT_MS, &r);
    bool ok = ran && r.exit_code == 0 && !r.timed_out;
    dtk_log(p, label, ok ? "ok" : (ran ? r.output : "could not execute"));
    return ok;
}

/* The gates a train must pass before anything is offered to dev.land.
 *
 * check-cyclomatic-complexity runs as the plain CHECK, never with
 * --write-baseline: rewriting a baseline is how a keeper would quietly raise
 * one at 03:00 with nobody reading. A train that needs a re-pinned baseline
 * is a train a human re-pins. */
static bool dtk_gates(const struct dtk_paths *p, char *why, size_t cap)
{
    static const char *const dev_bin[] = {"make", "-s", "-j8",
                                          "--no-print-directory", "dev-bin",
                                          NULL};
    static const char *const complexity[] = {
        "make", "-s", "--no-print-directory", "check-cyclomatic-complexity",
        NULL};
    static const char *const lint_gates[] = {
        "make", "--no-print-directory", "t-fast", "ONLY=make_lint_gates", NULL};
    static const char *const lint[] = {"make", "--no-print-directory", "lint",
                                       NULL};
    struct {
        const char *const *argv;
        const char *label;
    } steps[] = {
        {dev_bin, "gate dev-bin"},
        {complexity, "gate check-cyclomatic-complexity"},
        {lint_gates, "gate t-fast ONLY=make_lint_gates"},
        {lint, "gate lint"},
    };
    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        if (!dtk_make(p, steps[i].argv, steps[i].label)) {
            (void)snprintf(why, cap, "%s failed; see %s", steps[i].label,
                          p->log);
            return false;
        }
    }
    return true;
}

static bool dtk_regen(const struct dtk_paths *p, char *why, size_t cap)
{
    static const char *const inventory[] = {
        "make", "-s", "-B", "--no-print-directory", "docs-capability-inventory",
        NULL};
    static const char *const routing[] = {
        "make", "-s", "--no-print-directory", "docs-executor-routing", NULL};
    static const char *const counts[] = {"make", "-s", "--no-print-directory",
                                         "fix-doc-counts", NULL};
    static const char *const api[] = {"make", "-s", "--no-print-directory",
                                      "docs-api-reference", NULL};
    const char *const *steps[] = {inventory, routing, counts, api};
    static const char *const labels[] = {"regen docs-capability-inventory",
                                         "regen docs-executor-routing",
                                         "regen fix-doc-counts",
                                         "regen docs-api-reference"};
    for (size_t i = 0; i < 4; i++) {
        if (!dtk_make(p, steps[i], labels[i])) {
            (void)snprintf(why, cap, "%s failed; see %s", labels[i], p->log);
            return false;
        }
    }
    static const char *const add[] = {"add", "-A", "--", "docs/", NULL};
    static const char *const staged[] = {"diff", "--cached", "--quiet", NULL};
    static const char *const commit[] = {
        "commit", "-q", "-S", "-m", "Regenerate the generated docs for the train",
        NULL};
    (void)zcl_dev_train_git(p->wt, add, NULL, 0, DTK_GIT_TIMEOUT_MS);
    if (zcl_dev_train_git(p->wt, staged, NULL, 0, DTK_GIT_TIMEOUT_MS) != 0 &&
        zcl_dev_train_git(p->wt, commit, NULL, 0, DTK_GIT_TIMEOUT_MS) != 0) {
        (void)snprintf(why, cap, "the regen commit failed; see %s", p->log);
        return false;
    }
    return true;
}

/* ── the landing hand-off ──────────────────────────────────────────────── */

/* land_pre.sh is read-only and prints exactly one verdict line. Only the
 * literal `PRECHECK: OK` launches anything; any other output, a non-zero
 * exit, or a missing helper refuses. */
static bool dtk_precheck(const struct dtk_paths *p, const char *base,
                         char *why, size_t cap)
{
    const char *argv[] = {p->land_pre, p->name, base, NULL};
    struct zcl_devloop_process_result r;
    if (!zcl_devloop_process_run(p->scratch, argv, DTK_HELPER_TIMEOUT_MS, &r)) {
        (void)snprintf(why, cap, "could not run land_pre.sh at %.180s%s",
                      p->land_pre, strlen(p->land_pre) > 180 ? "..." : "");
        return false;
    }
    dtk_log(p, "land_pre.sh", r.output);
    if (r.exit_code != 0 || !strstr(r.output, "PRECHECK: OK")) {
        (void)snprintf(why, cap, "land_pre.sh refused; see %s", p->log);
        return false;
    }
    return true;
}

static bool dtk_launch(const struct dtk_paths *p, char *why, size_t cap)
{
    const char *argv[] = {p->land_unit, p->name, NULL};
    struct zcl_devloop_process_result r;
    if (!zcl_devloop_process_run(p->scratch, argv, DTK_HELPER_TIMEOUT_MS, &r) ||
        r.exit_code != 0) {
        (void)snprintf(why, cap, "land_unit.sh failed; see %s", p->log);
        dtk_log(p, "land_unit.sh", r.output);
        return false;
    }
    dtk_log(p, "land_unit.sh", r.output);
    return true;
}

/* ── advancing a train that is already landing ─────────────────────────── */

/* The last state dev.land recorded for `tip` in its outcome ledger. Empty
 * when the tip is not there yet — which is the normal answer while a landing
 * is still stepping. */
static void dtk_outcome_state(const struct dtk_paths *p, const char *tip,
                              char *out, size_t cap)
{
    FILE *f = fopen(p->outcomes, "rb");
    char line[4096], needle[64];
    out[0] = '\0';
    if (!f)
        return;
    (void)snprintf(needle, sizeof(needle), "\"tip\":\"%s\"", tip);
    while (fgets(line, sizeof(line), f)) {
        const char *hit = strstr(line, needle) ? strstr(line, "\"state\":\"")
                                               : NULL;
        if (!hit)
            continue;
        hit += strlen("\"state\":\"");
        size_t n = strcspn(hit, "\"");
        if (n < cap)
            (void)snprintf(out, n + 1, "%s", hit);
    }
    (void)fclose(f);
}

/* A landed train: retire the review refs it consumed (only those named in
 * picks.txt — never a wildcard), open the next train's queue file, and leave
 * the board line for whoever posts it. */
static void dtk_finish_landed(const struct dtk_paths *p, const char *root,
                              const char *tip)
{
    FILE *f = fopen(p->picks, "rb");
    char line[DTK_LINE];
    while (f && fgets(line, sizeof(line), f)) {
        char *save = NULL;
        zcl_dev_train_strip(line);
        const char *name = strtok_r(line, " \t", &save);
        char ref[128];
        if (!name || !dtk_valid_name(name))
            continue;
        (void)snprintf(ref, sizeof(ref), "refs/review/%s", name);
        const char *args[] = {"update-ref", "-d", ref, NULL};
        (void)zcl_dev_train_git(root, args, NULL, 0, DTK_GIT_TIMEOUT_MS);
    }
    if (f)
        (void)fclose(f);

    char next_dir[DTK_PATH], next_queue[DTK_PATH], next_name[32], post[512];
    (void)snprintf(next_name, sizeof(next_name), "train%d", p->train + 1);
    if (dtk_join(p->scratch, next_name, next_dir, sizeof(next_dir)) &&
        platform_directory_ensure(next_dir, 0700) &&
        dtk_join(next_dir, "late_picks.txt", next_queue, sizeof(next_queue)) &&
        !dtk_read_first_line(next_queue, post, sizeof(post)))
        (void)dtk_write_atomic(next_queue,
                              "# <name> <sha|PENDING> <verdict-file>\n");
    (void)snprintf(post, sizeof(post),
                  "[result] %s LANDED via native dev.land: %s", p->name, tip);
    (void)dtk_write_atomic(p->board, post);
    dtk_log(p, "landed", post);
}

/* ── reply helpers ─────────────────────────────────────────────────────── */

static void dtk_refuse(struct zcl_command_reply *reply, const char *code,
                       const char *phase, const char *reason)
{
    char message[512];
    (void)snprintf(message, sizeof(message), "keep: refused: %s", reason);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, code, phase, false, false,
                           message, "");
}

static void dtk_publish(struct zcl_command_reply *reply,
                        const struct dtk_paths *p, const struct dtk_state *st)
{
    (void)json_push_kv_str(&reply->data, "state", st->state);
    (void)json_push_kv_str(&reply->data, "base", st->base);
    (void)json_push_kv_str(&reply->data, "tip", st->tip);
    (void)json_push_kv_str(&reply->data, "reason", st->reason);
    (void)json_push_kv_int(&reply->data, "picks", st->picks);
    (void)json_push_kv_str(&reply->data, "log", p->log);
}

/* ── the passes ────────────────────────────────────────────────────────── */

static void dtk_pass_landing(const struct dtk_paths *p, const char *root,
                             struct dtk_state *st,
                             struct zcl_command_reply *reply, bool dry_run)
{
    char outcome[64];
    dtk_outcome_state(p, st->tip, outcome, sizeof(outcome));
    if (dry_run) {
        const char *would_state = "landing";
        if (strcmp(outcome, "landed") == 0)
            would_state = "landed";
        else if (outcome[0] && strcmp(outcome, "queued") != 0 &&
                 strcmp(outcome, "running") != 0)
            would_state = "blocked";
        dtk_publish(reply, p, st);
        (void)json_push_kv_str(&reply->data, "observed_outcome", outcome);
        (void)json_push_kv_str(&reply->data, "would_state", would_state);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
        return;
    }
    if (strcmp(outcome, "landed") == 0) {
        dtk_finish_landed(p, root, st->tip);
        dtk_set(st, "landed", "");
    } else if (outcome[0] && strcmp(outcome, "queued") != 0 &&
               strcmp(outcome, "running") != 0) {
        char why[256];
        (void)snprintf(why, sizeof(why), "dev.land reported %s for %s",
                      outcome, st->tip);
        dtk_set(st, "blocked", why);
        dtk_log(p, "blocked", why);
    } else {
        dtk_set(st, "landing", "dev.land has not finished this tip yet");
    }
    (void)dtk_state_save(p, st);
    dtk_publish(reply, p, st);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}

/* Everything the keeper would do, without doing any of it. --dry-run exists
 * because "trust me, it will do the right thing at 03:00" is not a claim a
 * keeper gets to make. */
static void dtk_pass_dry(const struct dtk_paths *p, const struct dtk_pick *picks,
                         size_t n, const char *base, const char *origin,
                         const char *state, struct zcl_command_reply *reply)
{
    struct json_value plan;
    json_init(&plan);
    json_set_array(&plan);
    for (size_t i = 0; i < n; i++) {
        struct json_value item;
        json_init(&item);
        json_set_object(&item);
        (void)json_push_kv_str(&item, "name", picks[i].name);
        (void)json_push_kv_str(&item, "sha", picks[i].sha);
        (void)json_push_back(&plan, &item);
        json_free(&item);
    }
    (void)json_push_kv(&reply->data, "plan", &plan);
    json_free(&plan);
    (void)json_push_kv_str(&reply->data, "base", base);
    (void)json_push_kv_str(&reply->data, "origin_main", origin);
    (void)json_push_kv_str(&reply->data, "origin_main_source",
                          "local_tracking_ref");
    (void)json_push_kv_str(&reply->data, "worktree", p->wt);
    (void)json_push_kv_str(&reply->data, "land_pre", p->land_pre);
    (void)json_push_kv_str(&reply->data, "land_unit", p->land_unit);
    (void)json_push_kv_str(&reply->data, "state", state);
    (void)json_push_kv_int(&reply->data, "picks", (int64_t)n);
    (void)json_push_kv_str(&reply->data, "next",
                          "dev train keep --train=<N> --once");
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}

static bool dtk_assemble(const struct dtk_paths *p, const char *root,
                         const char *base, const struct dtk_pick *picks,
                         size_t n, char *why, size_t cap)
{
    char tip[41];
    FILE *f;
    if (!dtk_worktree_open(p, root, base, why, cap))
        return false;
    for (size_t i = 0; i < n; i++) {
        if (!dtk_pick_one(p, base, &picks[i], why, cap))
            return false;
        dtk_log(p, "picked", picks[i].name);
    }
    f = fopen(p->picks, "wb");
    if (!f) {
        (void)snprintf(why, cap, "cannot write picks.txt in the train directory");
        return false;
    }
    for (size_t i = 0; i < n; i++)
        (void)fprintf(f, "%s %s\n", picks[i].name, picks[i].sha);
    (void)fclose(f);
    return dtk_rev_parse(p->wt, "HEAD", tip);
}

/* Re-fetch, then insist origin/main is still exactly the base this queue was
 * assembled against. A keeper that assembled onto a moved main would produce
 * a train whose every commit is a surprise to the tree it lands on; the fix
 * is a human rebase, so this only ever refuses. */
static bool dtk_agree_on_base(const struct dtk_paths *p, const char *root,
                              char base[41], char origin[41],
                              struct zcl_command_reply *reply, bool dry_run)
{
    static const char *const fetch[] = {"fetch", "-q", "origin", NULL};
    char why[256];
    if (!dry_run &&
        zcl_dev_train_git(root, fetch, NULL, 0, DTK_FETCH_TIMEOUT_MS) != 0) {
        dtk_refuse(reply, "FETCH_FAILED", "base",
                   "cannot refresh origin/main; the queue was not assembled");
        return false;
    }
    if (!dtk_queue_base(p, root, base) ||
        !dtk_rev_parse(root, "origin/main", origin)) {
        dtk_refuse(reply, "NO_BASE", "base",
                   "cannot resolve the queue base or origin/main");
        return false;
    }
    if (strcmp(base, origin) != 0) {
        (void)snprintf(why, sizeof(why),
                      "origin/main moved to %s; the queue base is %s", origin,
                      base);
        dtk_refuse(reply, "BASE_MOVED", "base", why);
        return false;
    }
    return true;
}

static void dtk_pass_cycle(const struct dtk_paths *p, const char *root,
                           struct dtk_state *st,
                           struct zcl_command_reply *reply, bool dry_run)
{
    struct dtk_pick picks[DTK_MAX_PICKS];
    struct json_value skipped;
    char base[41], origin[41], why[256], tip[41];
    size_t n;

    json_init(&skipped);
    json_set_array(&skipped);
    n = dtk_queue_load(p, picks, &skipped);
    (void)json_push_kv(&reply->data, "skipped", &skipped);
    json_free(&skipped);

    if (n == 0) {
        dtk_refuse(reply, "NO_PICKS", "queue",
                   "no LAND verdicts in the queue");
        return;
    }
    if (!dtk_agree_on_base(p, root, base, origin, reply, dry_run))
        return;
    if (dry_run) {
        dtk_pass_dry(p, picks, n, base, origin, st->state, reply);
        return;
    }

    (void)snprintf(st->base, sizeof(st->base), "%s", base);
    st->picks = (int64_t)n;
    dtk_set(st, "picking", "");
    (void)dtk_state_save(p, st);
    if (!dtk_assemble(p, root, base, picks, n, why, sizeof(why)) ||
        !dtk_rev_parse(p->wt, "HEAD", tip)) {
        dtk_set(st, "blocked", why);
        (void)dtk_state_save(p, st);
        dtk_log(p, "blocked", why);
        dtk_refuse(reply, "ASSEMBLY_BLOCKED", "assemble", why);
        dtk_publish(reply, p, st);
        return;
    }
    dtk_set(st, "gating", "");
    (void)dtk_state_save(p, st);
    if (!dtk_gates(p, why, sizeof(why)) || !dtk_regen(p, why, sizeof(why)) ||
        !dtk_rev_parse(p->wt, "HEAD", tip)) {
        dtk_set(st, "blocked", why);
        (void)dtk_state_save(p, st);
        dtk_refuse(reply, "GATE_BLOCKED", "gate", why);
        dtk_publish(reply, p, st);
        return;
    }

    char ready[64];
    (void)snprintf(ready, sizeof(ready), "%s\n", tip);
    (void)snprintf(st->tip, sizeof(st->tip), "%s", tip);
    dtk_set(st, "ready", "");
    (void)dtk_write_atomic(p->ready, ready);
    (void)dtk_state_save(p, st);

    if (!dtk_precheck(p, base, why, sizeof(why)) ||
        !dtk_launch(p, why, sizeof(why))) {
        dtk_refuse(reply, "PRECHECK_REFUSED", "land", why);
        dtk_publish(reply, p, st);
        return;
    }
    dtk_set(st, "landing", "");
    (void)dtk_state_save(p, st);
    dtk_publish(reply, p, st);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
}

/* `gating` is the only crash state that resumes on its own: the worktree is
 * fully assembled and the gates are pure re-runs. `picking` is not — a
 * half-assembled worktree is a judgement call, and this keeper does not make
 * judgement calls unattended. */
static bool dtk_resume_is_safe(const char *state)
{
    return strcmp(state, "idle") == 0 || strcmp(state, "gating") == 0 ||
           strcmp(state, "ready") == 0;
}

/* Resolve paths without creating files. Preview never acquires a write lock. */
static bool dtk_open(const struct json_value *input,
                    struct zcl_command_reply *reply, struct dtk_paths *p,
                    bool dry_run)
{
    /* The train number arrives as the string the shell typed. It is parsed
     * and range-checked HERE rather than by a new integer rule in the
     * command registry: that validator is one 300-branch chain already, and
     * a leaf that owns a bound should state the bound itself. */
    const char *text = input ? json_get_str(json_get(input, "train")) : NULL;
    char *end = NULL;
    long train = text ? strtol(text, &end, 10) : 0;
    if (!text || !text[0] || !end || *end || train < DTK_TRAIN_MIN ||
        train > DTK_TRAIN_MAX) {
        dtk_refuse(reply, "INVALID_TRAIN", "validate",
                   "--train=<N> must be a whole number 1..9999");
        return false;
    }
    (void)json_push_kv_int(&reply->data, "train", (int64_t)train);
    if (!dtk_paths_init((int)train, p, dry_run)) {
        dtk_refuse(reply, "NO_STATE_ROOT", "validate",
                   "cannot resolve the keeper's state paths");
        return false;
    }
    (void)json_push_kv_str(&reply->data, "train_dir", p->dir);
    if (!zcl_dev_train_is_dir(p->dir)) {
        dtk_refuse(reply, "NO_TRAIN_DIR", "validate", "no such train directory");
        return false;
    }
    return true;
}

/* One pass, dispatched on the persisted state. Nothing here loops. */
static void dtk_dispatch(const struct dtk_paths *p, const char *root,
                         struct zcl_command_reply *reply, bool dry_run)
{
    struct dtk_state st;
    dtk_state_load(p, &st);
    if (strcmp(st.state, "blocked") == 0 || strcmp(st.state, "landed") == 0) {
        dtk_publish(reply, p, &st);
        reply->status = ZCL_COMMAND_STATUS_PASSED;
    } else if (strcmp(st.state, "landing") == 0) {
        dtk_pass_landing(p, root, &st, reply, dry_run);
    } else if (dtk_resume_is_safe(st.state)) {
        dtk_pass_cycle(p, root, &st, reply, dry_run);
    } else {
        char why[256];
        (void)snprintf(why, sizeof(why),
                      "a previous keeper died in state %.31s; inspect %.170s%s",
                      st.state, p->wt, strlen(p->wt) > 170 ? "..." : "");
        if (!dry_run) {
            dtk_set(&st, "blocked", why);
            (void)dtk_state_save(p, &st);
        }
        dtk_refuse(reply, "KEEPER_CRASHED", "resume", why);
        dtk_publish(reply, p, &st);
    }
}

#endif /* ZCL_DEV_BUILD || ZCL_TESTING */

void zcl_native_handle_dev_train_keep(const struct zcl_command_request *request,
                                      struct zcl_command_reply *reply)
{
    if (!reply)
        return;
#if !defined(ZCL_DEV_BUILD) && !defined(ZCL_TESTING)
    (void)request;
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                           ZCL_COMMAND_EXIT_BLOCKED, "DEV_BUILD_REQUIRED",
                           "dispatch", false, false,
                           "the unattended train keeper requires a dev build",
                           "make dev-bin, or z23-dev dev train keep");
#else
    const struct json_value *input = request ? request->input : NULL;
    const struct json_value *dry = input ? json_get(input, "dry_run") : NULL;
    bool dry_run = dry && dry->type == JSON_BOOL && json_get_bool(dry);
    struct dtk_paths p;
    (void)json_push_kv_str(&reply->data, "leaf", DTK_LEAF);
    if (!dtk_open(input, reply, &p, dry_run))
        return;
    (void)json_push_kv_bool(&reply->data, "dry_run", dry_run);
    if (dry_run) {
        dtk_dispatch(&p, zcl_dev_train_source_root(request), reply, true);
        return;
    }
    struct platform_process_lock lock;
    platform_process_lock_init(&lock);
    if (!platform_process_lock_try_acquire(&lock, p.lock, true)) {
        dtk_refuse(reply, "KEEPER_BUSY", "lock",
                   "cannot acquire this train's private lock; it may be busy");
        return;
    }
    dtk_dispatch(&p, zcl_dev_train_source_root(request), reply, false);
    platform_process_lock_release(&lock);
#endif
}
