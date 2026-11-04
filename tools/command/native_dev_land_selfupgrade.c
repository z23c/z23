/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land driver self-upgrade -- a content-addressed slot per
 *          commit, a decision compare beside the current driver, and an
 *          atomic pointer switch with rollback. Default OFF.
 *
 * DESIGN
 *
 * Problem. The land queue's driver is a z23-dev build an operator pinned by
 * hand (a systemd drop-in names the binary). A landed fix to the driver's own
 * logic (rebase, train, push) does not run until someone upgrades it, and an
 * old driver once missed a landed fix and failed rows on .merge_file_* temps.
 *
 * Shape. Everything lives under one root the caller names (the state root's
 * land directory):
 *     slots/<40-hex sha>/z23-dev   immutable build of that commit's main
 *     current                      symlink to the binary the unit execs
 *     upgrade.state                candidate, agree count, previous, trial
 * A slot path holds the commit sha, so a path names exactly one build. An
 * existing slot is never rewritten. A slot appears by rename.
 *
 * Trigger. After a landing, the caller asks touches_driver() of the landed
 * diff's path list; only a diff of tools/command/native_dev_land*.c or
 * tools/dev/dev_land* starts a candidate. The caller builds the new main's
 * z23-dev (devbuild) and slot_install()s it. Building is not done here.
 *
 * Compare. On the next row, observe() runs the current binary and the
 * candidate on the same read-only decision args ("what would you do": the
 * rebase plan, the train membership, the verdict routing) and compares exit
 * status and stdout byte for byte. Neither run mutates a queue, a worktree
 * or a remote: the decision mode the args select must be read-only, and the
 * driver keeps acting through the current binary alone. A launch failure, a
 * nonzero exit, an empty output or a difference is a DISAGREE and resets the
 * agree count to zero (fail closed: no evidence is never agreement). A change
 * of candidate sha also resets it.
 *
 * Switch. After need_rows consecutive agreeing rows the pointer is replaced
 * with symlink-at-temp-name then rename(2), which is atomic: an exec sees the
 * old target or the new one, never neither. The previous target is recorded
 * and the candidate becomes the "trial".
 *
 * Rollback. row_result() is told how the first row under the switched
 * pointer ended. A failed row restores the previous target (or removes the
 * pointer when none existed, so the unit's pinned binary runs); a good row
 * confirms the switch. Either way the trial ends.
 *
 * Off. zcl_land_selfupgrade_enabled() is true only for
 * ZCL_LAND_SELFUPGRADE=1. With it unset the land path calls none of this, so
 * how rows are proven and pushed is unchanged.
 *
 * Not here (follow-up): the read-only decision verb on dev land itself, the
 * post-landing hook that builds and installs the slot, and the unit exec'ing
 * <root>/current.
 */

#include "command/native_dev_land_selfupgrade.h"

#include "util/path_util.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>

#define SU_OUT_MAX 8192
#define SU_TIMEOUT_MS 20000
#define SU_SHA_LEN 40

struct su_state {
    char candidate[SU_SHA_LEN + 1];
    int matches;
    char previous[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    char trial[SU_SHA_LEN + 1];
};

bool zcl_land_selfupgrade_enabled(void)
{
    const char *v = getenv(ZCL_LAND_SELFUPGRADE_ENV);
    return v && strcmp(v, "1") == 0;
}

bool zcl_land_selfupgrade_touches_driver(const char *paths)
{
    static const char *const pre[] = {"tools/command/native_dev_land",
                                      "tools/dev/dev_land"};
    const char *p = paths;
    while (p && *p) {
        for (size_t i = 0; i < sizeof(pre) / sizeof(pre[0]); i++)
            if (strncmp(p, pre[i], strlen(pre[i])) == 0)
                return true;
        p = strchr(p, '\n');
        if (p)
            p++;
    }
    return false;
}

static bool su_sha_ok(const char *sha)
{
    return zcl_is_lower_hex(sha, SU_SHA_LEN);
}

bool zcl_land_selfupgrade_slot_path(const char *root, const char *sha,
                                    char *out, size_t cap)
{
    if (!root || !root[0] || !su_sha_ok(sha))
        return false;
    int n = snprintf(out, cap, "%s/slots/%s/z23-dev", root, sha);
    return n > 0 && (size_t)n < cap;
}

static bool su_copy(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    FILE *out = in ? fopen(dst, "wb") : NULL;
    char buf[8192];
    size_t n;
    bool ok = in && out;
    while (ok && (n = fread(buf, 1, sizeof(buf), in)) > 0)
        ok = fwrite(buf, 1, n, out) == n;
    ok = ok && !ferror(in);
    if (in)
        fclose(in);
    if (out) {
        ok = ok && fflush(out) == 0 && fsync(fileno(out)) == 0;
        ok = (fclose(out) == 0) && ok;
    }
    return ok && chmod(dst, 0755) == 0;
}

static bool su_same(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    char x[4096], y[4096];
    bool same = fa && fb;
    while (same) {
        size_t nx = fread(x, 1, sizeof(x), fa);
        size_t ny = fread(y, 1, sizeof(y), fb);
        same = nx == ny && memcmp(x, y, nx) == 0 && !ferror(fa) && !ferror(fb);
        if (nx == 0 || !same)
            break;
    }
    if (fa)
        fclose(fa);
    if (fb)
        fclose(fb);
    return same;
}

bool zcl_land_selfupgrade_slot_install(const char *root, const char *sha,
                                       const char *src)
{
    char slot[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    char dir[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    char tmp[ZCL_LAND_SELFUPGRADE_PATH_MAX + 32];
    if (!src || !zcl_land_selfupgrade_slot_path(root, sha, slot, sizeof(slot)))
        return false;
    if (access(slot, F_OK) == 0) {
        /* Never trust an existing slot on its mode bits: it must be
         * byte-identical to src. An empty one is a torn install and is
         * replaced; a different non-empty one is refused (fail closed). */
        struct stat st;
        if (stat(slot, &st) == 0 && st.st_size > 0)
            return su_same(src, slot) && access(slot, X_OK) == 0;
    }
    (void)mkdir(root, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/slots", root);
    (void)mkdir(dir, 0700);
    (void)snprintf(dir, sizeof(dir), "%s/slots/%s", root, sha);
    (void)mkdir(dir, 0700);
    (void)snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", slot, (long)getpid());
    if (!su_copy(src, tmp) || rename(tmp, slot) != 0) {
        (void)unlink(tmp);
        return false;
    }
    return true;
}

bool zcl_land_selfupgrade_pointer_read(const char *root, char *out, size_t cap)
{
    char link[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    ssize_t n;
    if (!zcl_path_join(link, sizeof(link), root, "current"))
        return false;
    n = readlink(link, out, cap - 1);
    if (n <= 0)
        return false;
    out[n] = '\0';
    return true;
}

/* Atomic: a symlink at a temp name, then rename over <root>/current. */
static bool su_pointer_set(const char *root, const char *target)
{
    char link[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    char tmp[ZCL_LAND_SELFUPGRADE_PATH_MAX + 16];
    if (target[0] != '/' || access(target, X_OK) != 0 ||
        !zcl_path_join(link, sizeof(link), root, "current"))
        return false;
    (void)snprintf(tmp, sizeof(tmp), "%s.tmp", link);
    (void)unlink(tmp);
    if (symlink(target, tmp) != 0)
        return false;
    if (rename(tmp, link) != 0) {
        (void)unlink(tmp);
        return false;
    }
    return true;
}

static void su_state_read(const char *root, struct su_state *s)
{
    char path[ZCL_LAND_SELFUPGRADE_PATH_MAX], line[2048];
    FILE *f;
    memset(s, 0, sizeof(*s));
    if (!zcl_path_join(path, sizeof(path), root, "upgrade.state"))
        return;
    f = fopen(path, "r");
    if (!f)
        return;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "candidate=", 10) == 0 && su_sha_ok(line + 10))
            (void)snprintf(s->candidate, sizeof(s->candidate), "%s", line + 10);
        else if (strncmp(line, "matches=", 8) == 0)
            s->matches = atoi(line + 8);
        else if (strncmp(line, "previous=", 9) == 0)
            (void)snprintf(s->previous, sizeof(s->previous), "%s", line + 9);
        else if (strncmp(line, "trial=", 6) == 0 && su_sha_ok(line + 6))
            (void)snprintf(s->trial, sizeof(s->trial), "%s", line + 6);
    }
    fclose(f);
}

static bool su_state_write(const char *root, const struct su_state *s)
{
    char path[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    char tmp[ZCL_LAND_SELFUPGRADE_PATH_MAX + 8];
    FILE *f;
    bool ok;
    if (!zcl_path_join(path, sizeof(path), root, "upgrade.state"))
        return false;
    (void)snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f)
        return false;
    ok = fprintf(f, "candidate=%s\nmatches=%d\nprevious=%s\ntrial=%s\n",
                 s->candidate, s->matches, s->previous, s->trial) > 0;
    ok = (fclose(f) == 0) && ok;
    if (!ok || rename(tmp, path) != 0) {
        (void)unlink(tmp);
        return false;
    }
    return true;
}

/* One decision run. False on a launch failure, nonzero exit or no output. */
static bool su_decide(const char *bin, const char *const *args, char *out,
                      size_t cap, int *status)
{
    const char *argv[ZCL_LAND_SELFUPGRADE_ARGS_MAX + 2];
    size_t n = 0;
    argv[n++] = bin;
    while (args && args[n - 1] && n <= ZCL_LAND_SELFUPGRADE_ARGS_MAX) {
        argv[n] = args[n - 1];
        n++;
    }
    argv[n] = NULL;
    *status = zcl_spawn_capture(argv, out, cap, SU_TIMEOUT_MS);
    return *status == 0 && out[0] != '\0';
}

static bool su_agree(const char *current_bin, const char *cand_bin,
                     const char *const *args)
{
    char a[SU_OUT_MAX], b[SU_OUT_MAX];
    int sa, sb;
    if (!su_decide(current_bin, args, a, sizeof(a), &sa) ||
        !su_decide(cand_bin, args, b, sizeof(b), &sb))
        return false;
    return strcmp(a, b) == 0;
}

static enum zcl_land_selfupgrade_verdict
su_count(const char *root, struct su_state *s, bool agree, int need_rows,
         const char *sha, const char *cand_bin)
{
    char prev[ZCL_LAND_SELFUPGRADE_PATH_MAX] = "";
    struct su_state saved;
    s->matches = agree ? s->matches + 1 : 0;
    if (!agree || s->matches < need_rows) {
        if (!su_state_write(root, s))
            return ZCL_LAND_SU_ERROR;
        return agree ? ZCL_LAND_SU_AGREE : ZCL_LAND_SU_DISAGREE;
    }
    /* Durable first, then the pointer: trial+previous reach disk before the
     * pointer moves, so a crash between the two is recoverable (observe sees
     * a trial the pointer never took) and ERROR leaves nothing changed. */
    (void)zcl_land_selfupgrade_pointer_read(root, prev, sizeof(prev));
    saved = *s;
    snprintf(s->previous, sizeof(s->previous), "%s", prev);
    snprintf(s->trial, sizeof(s->trial), "%s", sha);
    s->candidate[0] = '\0';
    s->matches = 0;
    if (!su_state_write(root, s)) {
        *s = saved;
        return ZCL_LAND_SU_ERROR;
    }
    if (!su_pointer_set(root, cand_bin)) {
        saved.trial[0] = '\0';
        saved.previous[0] = '\0';
        (void)su_state_write(root, &saved);
        return ZCL_LAND_SU_ERROR;
    }
    return ZCL_LAND_SU_SWITCHED;
}

/* Crash recovery. A trial whose slot the pointer does not name never took
 * effect (the crash fell between the state write and the pointer rename), so
 * the pointer still holds the real old target: drop the trial and carry on.
 * False (and the trial kept) when the pointer does name it or the state
 * cannot be cleared. */
static bool su_trial_lapsed(const char *root, struct su_state *s)
{
    char slot[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    char ptr[ZCL_LAND_SELFUPGRADE_PATH_MAX] = "";
    if (!zcl_land_selfupgrade_slot_path(root, s->trial, slot, sizeof(slot)))
        return false;
    (void)zcl_land_selfupgrade_pointer_read(root, ptr, sizeof(ptr));
    if (strcmp(ptr, slot) == 0)
        return false;
    s->trial[0] = '\0';
    s->previous[0] = '\0';
    s->matches = 0;
    return su_state_write(root, s);
}

enum zcl_land_selfupgrade_verdict
zcl_land_selfupgrade_observe(const char *root, const char *current_bin,
                             const char *sha, const char *const *args,
                             int need_rows)
{
    char cand_bin[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    struct su_state s;
    if (!current_bin || need_rows < 1 ||
        !zcl_land_selfupgrade_slot_path(root, sha, cand_bin, sizeof(cand_bin)) ||
        access(cand_bin, X_OK) != 0)
        return ZCL_LAND_SU_ERROR;
    su_state_read(root, &s);
    if (s.trial[0] && !su_trial_lapsed(root, &s))
        return ZCL_LAND_SU_ERROR; /* a switch is still awaiting its row */
    if (strcmp(s.candidate, sha) != 0) {
        snprintf(s.candidate, sizeof(s.candidate), "%s", sha);
        s.matches = 0;
    }
    return su_count(root, &s, su_agree(current_bin, cand_bin, args), need_rows,
                    sha, cand_bin);
}

bool zcl_land_selfupgrade_row_result(const char *root, bool row_ok)
{
    char link[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    struct su_state s;
    bool restored = false;
    su_state_read(root, &s);
    if (!s.trial[0])
        return false;
    if (!row_ok) {
        if (s.previous[0])
            restored = su_pointer_set(root, s.previous);
        else if (zcl_path_join(link, sizeof(link), root, "current"))
            restored = unlink(link) == 0;
        if (!restored)
            return false; /* keep the trial recorded; the caller may retry */
    }
    s.trial[0] = '\0';
    s.previous[0] = '\0';
    s.matches = 0;
    (void)su_state_write(root, &s);
    return restored;
}

#else /* _WIN32: the lander is not run there; every call refuses. */

bool zcl_land_selfupgrade_enabled(void) { return false; }
bool zcl_land_selfupgrade_touches_driver(const char *p) { (void)p; return false; }
bool zcl_land_selfupgrade_slot_path(const char *r, const char *s, char *o,
                                    size_t c)
{
    (void)r; (void)s; (void)o; (void)c;
    return false;
}
bool zcl_land_selfupgrade_slot_install(const char *r, const char *s,
                                       const char *src)
{
    (void)r; (void)s; (void)src;
    return false;
}
bool zcl_land_selfupgrade_pointer_read(const char *r, char *o, size_t c)
{
    (void)r; (void)o; (void)c;
    return false;
}
enum zcl_land_selfupgrade_verdict
zcl_land_selfupgrade_observe(const char *r, const char *c, const char *s,
                             const char *const *a, int n)
{
    (void)r; (void)c; (void)s; (void)a; (void)n;
    return ZCL_LAND_SU_ERROR;
}
bool zcl_land_selfupgrade_row_result(const char *r, bool ok)
{
    (void)r; (void)ok;
    return false;
}
#endif
