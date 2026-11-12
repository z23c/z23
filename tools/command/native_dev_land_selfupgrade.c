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
 *     upgrade.state                candidate, agree count, last row, previous, trial
 * A slot path holds the commit sha, so a path names exactly one build. An
 * existing slot is never rewritten. A slot appears by rename.
 *
 * Trigger. After a landing, the caller asks touches_driver() of the landed
 * diff's path list; only a diff of tools/command/native_dev_land*.c or
 * tools/dev/dev_land* starts a candidate. The caller builds the new main's
 * z23-dev (devbuild) and slot_install()s it. Building is not done here.
 *
 * Compare. On the next row, observe() runs the current binary and the
 * candidate on the same read-only decision args and compares typed stable
 * decision fields and the full row digest. Neither run mutates a queue, a worktree
 * or a remote: the decision mode the args select must be read-only, and the
 * driver keeps acting through the current binary alone. A launch failure, a
 * nonzero exit, an empty output or a difference is a DISAGREE and resets the
 * agree count to zero (fail closed: no evidence is never agreement). A change
 * of candidate sha also resets it. A sequence counts only once and must
 * exceed the candidate's previous high-water mark.
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
 * Not here (follow-up): the post-landing hook that builds and installs the
 * slot, and the unit exec'ing
 * <root>/current.
 */

#include "command/native_dev_land_selfupgrade.h"

#include "json/json.h"
#include "util/path_util.h"
#include "util/spawn.h"

#include <errno.h>
#include <limits.h>
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
    long long last_seq;
    char previous[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    char trial[SU_SHA_LEN + 1];
};
#endif

bool zcl_land_selfupgrade_enabled(void)
{
#if defined(_WIN32)
    return false;
#else
    const char *v = getenv(ZCL_LAND_SELFUPGRADE_ENV);
    return v && strcmp(v, "1") == 0;
#endif
}

bool zcl_land_selfupgrade_touches_driver(const char *paths)
{
#if defined(_WIN32)
    (void)paths;
    return false;
#else
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
#endif
}

#if !defined(_WIN32)
static bool su_sha_ok(const char *sha)
{
    return zcl_is_lower_hex(sha, SU_SHA_LEN);
}
#endif

bool zcl_land_selfupgrade_slot_path(const char *root, const char *sha,
                                    char *out, size_t cap)
{
#if defined(_WIN32)
    (void)root; (void)sha; (void)out; (void)cap;
    return false;
#else
    if (!root || !root[0] || !su_sha_ok(sha))
        return false;
    int n = snprintf(out, cap, "%s/slots/%s/z23-dev", root, sha);
    return n > 0 && (size_t)n < cap;
#endif
}

#if !defined(_WIN32)
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
#endif

bool zcl_land_selfupgrade_slot_install(const char *root, const char *sha,
                                       const char *src)
{
#if defined(_WIN32)
    (void)root; (void)sha; (void)src;
    return false;
#else
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
#endif
}

bool zcl_land_selfupgrade_pointer_read(const char *root, char *out, size_t cap)
{
#if defined(_WIN32)
    (void)root; (void)out; (void)cap;
    return false;
#else
    char link[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    ssize_t n;
    if (!zcl_path_join(link, sizeof(link), root, "current"))
        return false;
    n = readlink(link, out, cap - 1);
    if (n <= 0)
        return false;
    out[n] = '\0';
    return true;
#endif
}

#if !defined(_WIN32)
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

/* Only the read-only, explicitly scoped decision verb may be executed. */
static bool su_decimal(const char *s, long long *out)
{
    unsigned long long n = 0;
    if (!s || !*s) return false;
    for (; *s; ++s) {
        unsigned d;
        if (*s < '0' || *s > '9') return false;
        d = (unsigned)(*s - '0');
        if (n > ((unsigned long long)LLONG_MAX - d) / 10) return false;
        n = n * 10 + d;
    }
    if (!n) return false;
    *out = (long long)n;
    return true;
}

static bool su_args(const char *const *a, long long *seq)
{
    if (!a || !a[0] || strcmp(a[0], "dev") || !a[1] || strcmp(a[1], "land") ||
        !a[2] || strcmp(a[2], "decision") || !a[3] || strncmp(a[3], "--seq=", 6) ||
        !su_decimal(a[3] + 6, seq)) return false;
    return !a[4] || (!strcmp(a[4], "--json") && !a[5]);
}

/* Reject ambiguous members at every depth before calling json_get. */
static bool su_unique(const struct json_value *v)
{
    if (v->type == JSON_OBJ) {
        for (size_t i = 0; i < v->num_children; i++)
            for (size_t j = i + 1; j < v->num_children; j++)
                if (!strcmp(v->keys[i], v->keys[j])) return false;
    }
    for (size_t i = 0; i < v->num_children; i++)
        if (!su_unique(&v->children[i])) return false;
    return true;
}

static bool su_text_is(const struct json_value *v, const char *key, const char *want)
{
    const struct json_value *p = json_get(v, key);
    return p && p->type == JSON_STR && p->val.s && !strcmp(p->val.s, want);
}

static bool su_row_sequence(const struct json_value *d, long long seq)
{
    const struct json_value *p = json_get(d, "seq"), *priority = json_get(d, "priority_seq");
    return d && d->type == JSON_OBJ && p && p->type == JSON_INT && p->val.i == seq &&
        priority && priority->type == JSON_INT && priority->val.i >= 1 && priority->val.i <= seq;
}

static bool su_row_identity(const struct json_value *d, long long seq)
{
    const struct json_value *hash = json_get(d, "row_sha3");
    if (!su_row_sequence(d, seq) || !hash || hash->type != JSON_STR ||
        !zcl_is_lower_hex(hash->val.s, 64) ||
        !su_text_is(d, "scope", "observed_next_dispatch_only") ||
        !su_text_is(d, "row_schema", "zcl.land.decision.row.v1")) return false;
    if (!su_text_is(d, "dispatch", "prepare") && !su_text_is(d, "dispatch", "resume")) return false;
    return true;
}

static bool su_row_phase(const struct json_value *d)
{
    return su_text_is(d, "phase", "") || su_text_is(d, "phase", "rebase") ||
        su_text_is(d, "phase", "regen") || su_text_is(d, "phase", "prebuild") ||
        su_text_is(d, "phase", "prove") || su_text_is(d, "phase", "push");
}

static bool su_decision_fields(const struct json_value *d, long long seq)
{
    static const char *const names[] = {"state", "phase", "tip", "base", "local"};
    const struct json_value *p;
    if (!su_row_identity(d, seq)) return false;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        p = json_get(d, names[i]);
        if (!p || p->type != JSON_STR || !p->val.s) return false;
    }
    if (!su_text_is(d, "state", "queued") && !su_text_is(d, "state", "inflight")) return false;
    if (!su_row_phase(d)) return false;
    p = json_get(d, "tip");
    if (!zcl_is_lower_hex(p->val.s, 40)) return false;
    for (size_t i = 3; i < 5; i++) {
        p = json_get(d, names[i]);
        if (p->val.s[0] && !zcl_is_lower_hex(p->val.s, 40)) return false;
    }
    return true;
}

static bool su_read_decision(const char *s, long long seq, struct json_value *v)
{
    const struct json_value *ok;
    /* Conservatively refuse even a literal escaped backslash before u0000. */
    if (strstr(s, "\\u0000") || !json_read(v, s, strlen(s)) || v->type != JSON_OBJ || !su_unique(v)) return false;
    ok = json_get(v, "ok");
    return ok && ok->type == JSON_BOOL && ok->val.b &&
        su_text_is(v, "schema", "zcl.result.v1") && su_text_is(v, "command", "dev.land.decision") &&
        su_text_is(v, "status", "passed") && su_text_is(v, "data_schema", "zcl.land.v1") &&
        su_decision_fields(json_get(v, "data"), seq);
}

static bool su_same_field(const struct json_value *a, const struct json_value *b, const char *name)
{
    const struct json_value *x = json_get(a, name), *y = json_get(b, name);
    if (!x || !y || x->type != y->type) return false;
    if (x->type == JSON_INT) return x->val.i == y->val.i;
    return x->type == JSON_STR && x->val.s && y->val.s && !strcmp(x->val.s, y->val.s);
}

static bool su_same_decision(const struct json_value *a, const struct json_value *b)
{
    static const char *const names[] = {"seq", "priority_seq", "state", "phase", "tip", "base", "local", "dispatch", "scope", "row_schema", "row_sha3"};
    a = json_get(a, "data"); b = json_get(b, "data");
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (!su_same_field(a, b, names[i])) return false;
    return true;
}

struct su_read_counts { int matches, seq, candidate, previous, trial; bool valid; };

static bool su_state_number(const char *value, long long *out)
{
    *out = 0;
    return !strcmp(value, "0") || su_decimal(value, out);
}

static void su_state_metadata(struct su_state *s, struct su_read_counts *c, const char *line)
{
    if (!strncmp(line, "candidate=", 10)) {
        if (++c->candidate != 1 || (line[10] && !su_sha_ok(line + 10))) c->valid = false;
        else (void)snprintf(s->candidate, sizeof s->candidate, "%s", line + 10);
    } else if (!strncmp(line, "previous=", 9)) {
        if (++c->previous != 1 || strlen(line + 9) >= sizeof s->previous) c->valid = false;
        else (void)snprintf(s->previous, sizeof s->previous, "%s", line + 9);
    } else if (!strncmp(line, "trial=", 6)) {
        if (++c->trial != 1 || (line[6] && !su_sha_ok(line + 6))) c->valid = false;
        else (void)snprintf(s->trial, sizeof s->trial, "%s", line + 6);
    } else c->valid = false;
}

static void su_state_line(struct su_state *s, struct su_read_counts *c, char *line)
{
    long long n;
    line[strcspn(line, "\r\n")] = '\0';
    if (strncmp(line, "matches=", 8) == 0) {
        if (++c->matches != 1 || !su_state_number(line + 8, &n) || n > INT_MAX) c->valid = false;
        else s->matches = (int)n;
    } else if (strncmp(line, "last_seq=", 9) == 0) {
        if (++c->seq != 1 || !su_state_number(line + 9, &n)) c->valid = false;
        else s->last_seq = n;
    } else su_state_metadata(s, c, line);
}

static bool su_state_read(const char *root, struct su_state *s)
{
    char path[ZCL_LAND_SELFUPGRADE_PATH_MAX], line[2048];
    FILE *f;
    struct su_read_counts c = { .valid = true };
    memset(s, 0, sizeof(*s));
    if (!zcl_path_join(path, sizeof(path), root, "upgrade.state"))
        return false;
    f = fopen(path, "r");
    if (!f) return errno == ENOENT;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'), *cr = strchr(line, '\r');
        if (!nl || (cr && cr + 1 != nl)) { c.valid = false; break; }
        su_state_line(s, &c, line);
    }
    if (ferror(f)) c.valid = false;
    fclose(f);
    if (!c.valid || c.candidate != 1 || c.previous != 1 || c.trial != 1 || c.matches != 1) return false;
    if (!c.seq) { s->matches = 0; s->last_seq = 0; return true; }
    return c.seq == 1 && s->matches <= s->last_seq;
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
    ok = fprintf(f, "candidate=%s\nmatches=%d\nlast_seq=%lld\nprevious=%s\ntrial=%s\n",
                 s->candidate, s->matches, s->last_seq, s->previous, s->trial) > 0;
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
    struct zcl_spawn_evidence evidence;
    size_t n = 0;
    argv[n++] = bin;
    while (args && args[n - 1] && n <= ZCL_LAND_SELFUPGRADE_ARGS_MAX) {
        argv[n] = args[n - 1];
        n++;
    }
    argv[n] = NULL;
    *status = zcl_spawn_capture_evidence(argv, out, cap, SU_TIMEOUT_MS,
                                         &evidence);
    return *status == 0 && evidence.exit_observed && evidence.exit_code == 0 &&
           !evidence.timed_out && evidence.stdout_complete &&
           !evidence.stdout_truncated && evidence.stdout_observed > 0 &&
           strlen(out) == evidence.stdout_observed;
}

static bool su_agree(const char *current_bin, const char *cand_bin,
                     const char *const *args, long long seq)
{
    char a[SU_OUT_MAX], b[SU_OUT_MAX];
    struct json_value ja = {0}, jb = {0};
    int sa, sb; bool same = false;
    if (su_decide(current_bin, args, a, sizeof(a), &sa) &&
        su_decide(cand_bin, args, b, sizeof(b), &sb) &&
        su_read_decision(a, seq, &ja) && su_read_decision(b, seq, &jb))
        same = su_same_decision(&ja, &jb);
    json_free(&ja); json_free(&jb);
    return same;
}

static enum zcl_land_selfupgrade_verdict
su_count(const char *root, struct su_state *s, bool agree, int need_rows,
         const char *sha, const char *cand_bin)
{
    char prev[ZCL_LAND_SELFUPGRADE_PATH_MAX] = "";
    struct su_state saved;
    if (agree && s->matches < INT_MAX) s->matches++;
    else if (!agree) s->matches = 0;
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
#endif

enum zcl_land_selfupgrade_verdict
zcl_land_selfupgrade_observe(const char *root, const char *current_bin,
                             const char *sha, const char *const *args,
                             int need_rows)
{
#if defined(_WIN32)
    (void)root; (void)current_bin; (void)sha; (void)args; (void)need_rows;
    return ZCL_LAND_SU_ERROR;
#else
    char cand_bin[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    struct su_state s;
    long long seq;
    if (!su_args(args, &seq) || !current_bin || need_rows < 1 ||
        !zcl_land_selfupgrade_slot_path(root, sha, cand_bin, sizeof(cand_bin)) ||
        access(cand_bin, X_OK) != 0)
        return ZCL_LAND_SU_ERROR;
    if (!su_state_read(root, &s)) return ZCL_LAND_SU_ERROR;
    if (s.trial[0] && !su_trial_lapsed(root, &s))
        return ZCL_LAND_SU_ERROR; /* a switch is still awaiting its row */
    if (strcmp(s.candidate, sha) != 0) {
        snprintf(s.candidate, sizeof(s.candidate), "%s", sha);
        s.matches = 0;
        s.last_seq = 0;
    }
    bool fresh = seq > s.last_seq;
    if (fresh) s.last_seq = seq;
    return su_count(root, &s, fresh && su_agree(current_bin, cand_bin, args, seq), need_rows,
                    sha, cand_bin);
#endif
}

bool zcl_land_selfupgrade_row_result(const char *root, bool row_ok)
{
#if defined(_WIN32)
    (void)root; (void)row_ok;
    return false;
#else
    char link[ZCL_LAND_SELFUPGRADE_PATH_MAX];
    struct su_state s;
    bool restored = false;
    if (!su_state_read(root, &s)) return false;
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
#endif
}
