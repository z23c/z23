/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the "shadow" subcommand of z23-lab-peer: the port of the shadow
 * bridge lab-shadow.sh. It offers each FINISHED gate-submit stack to the lab
 * room, collects the peer's receipts and logs r1-vs-peer verdicts. Never
 * submits, never touches the land queue, nodes, datadirs, wallets or keys.
 *
 *   z23-lab-peer shadow --state=DIR [--gates=DIR] [--stacks-root=DIR]
 *       [--handoff-dir=DIR] [--bin=PATH] [--z23=P] [--z23dev=P] [--room=lab]
 *       [--check=gate] [--xdg-state=DIR] [--max=N] [--max-age=SECS] [--dry-run]
 *
 * The offered sha is the FINAL gated tip, not the stack's first commit. r1's
 * gate may commit an automatic lint fix after it starts; a peer that verifies
 * the first commit then fails full lint on bytes r1 itself corrected. A stack
 * is therefore offered only once its run.log ends with an rc= line, rc is 0 and
 * a "submitted as #N" line exists; the sha is the "tip" of submit.json (the
 * stack worktree HEAD when submit.json names none). A tip that is several
 * commits beyond origin/main is SEND_NOT_SINGLE for dev land send, so it is
 * offered as ONE synthesized commit carrying the tip's tree on the stack's
 * merge base: the exact gated bytes. The ledger (shadow-offered.tsv) records
 * the tip; its fifth column is the rc= line count BEFORE the final verdict, so
 * the compare phase sees the verdict at once.
 *
 * Files kept byte-compatible with the bridge, all under --state:
 *   shadow-offered.tsv  id name commit ts rc0
 *   shadow-compare.tsv  id name commit r1 r2 agree
 *   lane-offered.tsv    id name head commit ts     lane-verdict.tsv id name head verdict ts
 * collect runs with the same --check as the peer's verifier (default gate).
 * XDG_STATE_HOME is set only from --xdg-state (the bridge exported one); with
 * none the inherited value stays, and the output says so.
 *
 * --dry-run reads the ledgers and git and prints what WOULD be offered; it
 * writes nothing, takes no lock and starts no offer or collect child.
 * Every child goes through zcl_spawn_capture* by argv (no shell).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#include "lab_peer_shadow.h"
#include "platform/clock.h"
#include "platform/os_proc.h"
#include "util/spawn.h"

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum { LS_P = 1024, LS_BUF = 1 << 20, LS_OUT = 1 << 18, LS_STACKS = 512, LS_QUICK_S = 120, LS_OFFER_S = 2700 };

struct ls_ctx {
    int argc;
    char **argv;
    bool dry;
    int max, max_age;
    int64_t now;
    char state[LS_P], gates[LS_P], root[LS_P], handoff[LS_P], bin[LS_P];
    const char *z23, *z23dev, *room, *check, *xdg;
    int offered; /* offers made or planned this run */
};

struct ls_gate {
    int rcs;      /* number of exact rc=N lines */
    int last_rc;  /* the last one, -1 when none */
    bool submitted;
    char tip[41]; /* submit.json "tip", empty when absent */
};

struct ls_dec {
    char name[48], dir[LS_P], tip[41], commit[41], tree[41], base[41], bridge[41];
    bool synth;
    int rc0;
};

static char g_log[LS_BUF], g_sj[LS_BUF], g_tmp[LS_BUF], g_out[LS_BUF], g_ref[LS_BUF];
static char g_doc[LS_OUT];
static size_t g_doc_len;

/* ── helpers ───────────────────────────────────────────────────────────── */

static bool ls_fmt(char *dst, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    return n >= 0 && (size_t)n < cap;
}

static bool ls_hex(const char *s, size_t n)
{
    if (!s || strlen(s) != n)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i]))
            return false;
    return true;
}

static bool ls_read(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        buf[0] = '\0';
        return false;
    }
    const size_t n = fread(buf, 1, cap - 1, f);
    (void)fclose(f);
    buf[n] = '\0';
    return true;
}

static bool ls_append(const char *path, const char *line)
{
    FILE *f = fopen(path, "ab");
    if (!f)
        return false;
    bool ok = fputs(line, f) >= 0 && fflush(f) == 0;
    ok = (fclose(f) == 0) && ok;
    return ok;
}

static void ls_say(const struct ls_ctx *c, const char *fmt, ...)
{
    char msg[600], path[LS_P + 16], line[700];
    va_list ap;
    if (c->dry)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    char ts[32];
    const time_t t = (time_t)c->now;
    struct tm tmv;
    if (!gmtime_r(&t, &tmv) || strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tmv) == 0)
        (void)snprintf(ts, sizeof(ts), "%lld", (long long)c->now);
    if (ls_fmt(path, sizeof(path), "%s/shadow.log", c->state) &&
        ls_fmt(line, sizeof(line), "%s %s\n", ts, msg))
        (void)ls_append(path, line);
}

/* Runs argv (no shell); the exit status, or -1 on a timeout or launch failure. */
static int ls_run(const char *const argv[], const char *cwd, int timeout_s, char *out, size_t cap)
{
    bool to = false;
    const int rc = zcl_spawn_capture_in_dir_observed(argv, cwd, out, cap, timeout_s * 1000, &to);
    return to ? -1 : rc;
}

/* git -C dir A [B [C [D]]]; stdout trimmed to its first line in out. */
static bool ls_git(const char *dir, char *out, size_t cap, const char *a, const char *b,
                   const char *cc, const char *d)
{
    const char *const argv[] = {"git", "-C", dir, a, b, cc, d, NULL};
    char *nl;
    if (ls_run(argv, NULL, LS_QUICK_S, out, cap) != 0)
        return false;
    nl = strchr(out, '\n');
    if (nl)
        *nl = '\0';
    return out[0] != '\0';
}

/* Splits one line in place at tabs; returns the field count (at most max). */
static int ls_fields(char *line, char *f[], int max)
{
    int n = 0;
    char *p = line;
    while (n < max) {
        f[n++] = p;
        p = strchr(p, '\t');
        if (!p)
            break;
        *p++ = '\0';
    }
    return n;
}

/* True when a ledger line has field ia == a and, if b is set, field ib == b. */
static bool ls_ledger_has(const char *path, int ia, const char *a, int ib, const char *b)
{
    char *sp = NULL, line[1024], *f[8];
    if (!ls_read(path, g_tmp, sizeof(g_tmp)))
        return false;
    for (char *l = strtok_r(g_tmp, "\n", &sp); l; l = strtok_r(NULL, "\n", &sp)) {
        (void)snprintf(line, sizeof(line), "%s", l);
        const int n = ls_fields(line, f, 8);
        if (n > ia && n > ib && strcmp(f[ia], a) == 0 && (!b || strcmp(f[ib], b) == 0))
            return true;
    }
    return false;
}

/* The last sha the bridge or an earlier run recorded for a stack. */
static void ls_ledger_last(const char *path, const char *name, char out[41])
{
    char *sp = NULL, line[1024], *f[8];
    out[0] = '\0';
    if (!ls_read(path, g_tmp, sizeof(g_tmp)))
        return;
    for (char *l = strtok_r(g_tmp, "\n", &sp); l; l = strtok_r(NULL, "\n", &sp)) {
        (void)snprintf(line, sizeof(line), "%s", l);
        if (ls_fields(line, f, 8) > 2 && strcmp(f[1], name) == 0 && ls_hex(f[2], 40))
            (void)snprintf(out, 41, "%s", f[2]);
    }
}

/* ── the result document ───────────────────────────────────────────────── */

static void ls_doc(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(g_doc + g_doc_len, sizeof(g_doc) - g_doc_len, fmt, ap);
    va_end(ap);
    if (n > 0 && g_doc_len + (size_t)n < sizeof(g_doc))
        g_doc_len += (size_t)n;
}

static void ls_item(const char *kind, const char *name, const char *action, const char *code,
                    const char *sha, const char *bridge)
{
    ls_doc("%s{\"kind\":\"%s\",\"name\":\"%s\",\"action\":\"%s\",\"code\":\"%s\","
           "\"sha\":\"%s\",\"bridge\":\"%s\"}",
           g_doc_len > 0 && g_doc[g_doc_len - 1] != '[' ? "," : "", kind, name, action,
           code ? code : "", sha ? sha : "", bridge ? bridge : "");
}

/* ── the gate's own record ─────────────────────────────────────────────── */

/* The bridge's '^rc=[0-9]*$' with at least one digit. */
static bool ls_rc_line(const char *l)
{
    if (strncmp(l, "rc=", 3) != 0 || !isdigit((unsigned char)l[3]))
        return false;
    for (const char *p = l + 3; *p; p++)
        if (!isdigit((unsigned char)*p))
            return false;
    return true;
}

static void ls_gate_log(const char *text, struct ls_gate *g)
{
    char *sp = NULL;
    static char copy[LS_BUF];
    (void)snprintf(copy, sizeof(copy), "%s", text);
    for (char *l = strtok_r(copy, "\n", &sp); l; l = strtok_r(NULL, "\n", &sp)) {
        if (ls_rc_line(l)) {
            g->rcs++;
            g->last_rc = atoi(l + 3);
        } else if (strstr(l, "submitted as #") != NULL) {
            g->submitted = true;
        }
    }
}

static void ls_gate_tip(const char *json, struct ls_gate *g)
{
    const char *p = strstr(json, "\"tip\":\"");
    g->tip[0] = '\0';
    if (!p)
        return;
    p += 7;
    char t[41] = "";
    (void)snprintf(t, sizeof(t), "%.40s", p);
    if (ls_hex(t, 40) && p[40] == '"')
        (void)snprintf(g->tip, sizeof(g->tip), "%s", t);
}

/* False when there is no run.log. mtime goes to *mtime. */
static bool ls_gate_read(const struct ls_ctx *c, const char *name, struct ls_gate *g, int64_t *mtime)
{
    char path[LS_P + 64];
    struct stat st;
    g->rcs = 0;
    g->last_rc = -1;
    g->submitted = false;
    g->tip[0] = '\0';
    if (!ls_fmt(path, sizeof(path), "%s/%s/run.log", c->gates, name) || stat(path, &st) != 0 ||
        !ls_read(path, g_log, sizeof(g_log)))
        return false;
    *mtime = (int64_t)st.st_mtime;
    ls_gate_log(g_log, g);
    if (ls_fmt(path, sizeof(path), "%s/%s/submit.json", c->gates, name) &&
        ls_read(path, g_sj, sizeof(g_sj)))
        ls_gate_tip(g_sj, g);
    return true;
}

/* ── (a) offer ─────────────────────────────────────────────────────────── */

/* The offer child's id when its reply is items[0] status ok; else its code. */
static bool ls_offer_id(const char *out, char id[65], char code[48])
{
    const char *p = strstr(out, "\"items\":[{\"id\":\"");
    code[0] = '\0';
    id[0] = '\0';
    if (p) {
        p += 16;
        char t[65] = "";
        (void)snprintf(t, sizeof(t), "%.64s", p);
        if (ls_hex(t, 64) && strncmp(p + 64, "\",\"status\":\"ok\"", 14) == 0) {
            (void)snprintf(id, 65, "%s", t);
            return true;
        }
    }
    p = strstr(out, "\"code\":\"");
    for (size_t i = 0; p && i < 47 && (isupper((unsigned char)p[8 + i]) || p[8 + i] == '_'); i++) {
        code[i] = p[8 + i];
        code[i + 1] = '\0';
    }
    return false;
}

static bool ls_peer_offer(const struct ls_ctx *c, const char *lane, const char *commit,
                          char id[65], char code[48])
{
    char a_lane[LS_P + 16], a_commit[64], a_state[LS_P + 16], a_room[80], a_dev[LS_P + 16];
    if (!ls_fmt(a_lane, sizeof(a_lane), "--lane=%s", lane) ||
        !ls_fmt(a_commit, sizeof(a_commit), "--commit=%s", commit) ||
        !ls_fmt(a_state, sizeof(a_state), "--state=%s", c->state) ||
        !ls_fmt(a_room, sizeof(a_room), "--room=%s", c->room) ||
        !ls_fmt(a_dev, sizeof(a_dev), "--z23dev=%s", c->z23dev)) {
        (void)snprintf(code, 48, "SHADOW_PATH_TOO_LONG");
        return false;
    }
    const char *const argv[] = {c->bin, "offer", a_lane, a_commit, a_state, a_room, a_dev, NULL};
    (void)ls_run(argv, NULL, LS_OFFER_S, g_out, sizeof(g_out));
    return ls_offer_id(g_out, id, code);
}

/* The commit to offer for tip: tip itself when one commit beyond origin/main,
 * else a synthesized single commit with the tip's tree on the merge base. */
static const char *ls_plan_commit(const struct ls_ctx *c, struct ls_dec *d)
{
    char n[32], range[64];
    (void)snprintf(range, sizeof(range), "origin/main..%s", d->tip);
    if (!ls_git(d->dir, n, sizeof(n), "rev-list", "--count", range, NULL))
        return "STACK_RANGE_UNKNOWN";
    if (atoi(n) < 1)
        return "STACK_EMPTY";
    if (atoi(n) == 1) {
        (void)snprintf(d->commit, sizeof(d->commit), "%s", d->tip);
        return NULL;
    }
    char rev[64];
    (void)snprintf(rev, sizeof(rev), "%s^{tree}", d->tip);
    if (!ls_git(d->dir, d->tree, sizeof(d->tree), "rev-parse", rev, NULL, NULL) ||
        !ls_git(d->dir, d->base, sizeof(d->base), "merge-base", "origin/main", d->tip, NULL))
        return "STACK_TREE_UNKNOWN";
    d->synth = true;
    (void)c;
    return NULL;
}

static const char *ls_make_synth(struct ls_dec *d)
{
    char msg[160];
    (void)snprintf(msg, sizeof(msg), "lab offer: %s %s", d->name, d->tip);
    const char *const argv[] = {"git", "-C", d->dir, "-c", "user.name=lab-shadow", "-c",
                                "user.email=lab-shadow@localhost", "commit-tree", d->tree, "-p",
                                d->base, "-m", msg, NULL};
    char out[128];
    char *nl;
    if (ls_run(argv, NULL, LS_QUICK_S, out, sizeof(out)) != 0)
        return NULL;
    nl = strchr(out, '\n');
    if (nl)
        *nl = '\0';
    if (!ls_hex(out, 40))
        return NULL;
    (void)snprintf(d->commit, sizeof(d->commit), "%.40s", out);
    return d->commit;
}

/* Which stack to offer: NULL and d filled, or a skip code. */
static const char *ls_decide(const struct ls_ctx *c, const char *name, struct ls_dec *d)
{
    struct ls_gate g;
    int64_t mt = 0;
    char head[41], rev[64];
    memset(d, 0, sizeof(*d));
    (void)snprintf(d->name, sizeof(d->name), "%s", name);
    if (!ls_fmt(d->dir, sizeof(d->dir), "%s/%s", c->root, name))
        return "SHADOW_PATH_TOO_LONG";
    if (!ls_gate_read(c, name, &g, &mt))
        return "NO_RUN_LOG";
    if (g.last_rc < 0)
        return "GATE_RUNNING";
    if (g.last_rc != 0)
        return "GATE_FAILED";
    if (!g.submitted)
        return "NOT_SUBMITTED";
    d->rc0 = g.rcs - 1;
    if (!ls_git(d->dir, head, sizeof(head), "rev-parse", "HEAD", NULL, NULL))
        return "STACK_GONE";
    (void)snprintf(d->tip, sizeof(d->tip), "%s", g.tip[0] ? g.tip : head);
    (void)snprintf(rev, sizeof(rev), "%s^{commit}", d->tip);
    if (!ls_git(d->dir, head, sizeof(head), "rev-parse", rev, NULL, NULL))
        return "TIP_MISSING";
    return ls_plan_commit(c, d);
}

static int ls_stack_num(const char *n)
{
    if (strncmp(n, "z23-stacks", 10) != 0 || !isdigit((unsigned char)n[10]))
        return -1;
    for (const char *p = n + 10; *p; p++)
        if (!isdigit((unsigned char)*p))
            return -1;
    return atoi(n + 10);
}

static int ls_cmp_int(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}

/* The stack numbers with a run.log in the gates dir, ascending. */
static int ls_stack_list(const struct ls_ctx *c, int *nums, int cap)
{
    int n = 0;
    DIR *dp = opendir(c->gates);
    if (!dp)
        return 0;
    for (struct dirent *e = readdir(dp); e && n < cap; e = readdir(dp)) {
        const int v = ls_stack_num(e->d_name);
        if (v >= 0)
            nums[n++] = v;
    }
    (void)closedir(dp);
    qsort(nums, (size_t)n, sizeof(nums[0]), ls_cmp_int);
    return n;
}

/* One finished stack: record the decision, make the offer unless --dry-run. */
static void ls_offer_stack(struct ls_ctx *c, const char *name, struct ls_dec *d, const char *skip)
{
    char id[65], code[48], offp[LS_P + 32], row[400];
    if (skip) {
        ls_item("stack", name, "skip", skip, "", d->bridge);
        return;
    }
    (void)ls_fmt(offp, sizeof(offp), "%s/shadow-offered.tsv", c->state);
    if (ls_ledger_has(offp, 1, name, 2, d->tip)) {
        ls_item("stack", name, "skip", "ALREADY_OFFERED", d->tip, d->bridge);
        return;
    }
    if (c->dry) {
        ls_item("stack", name, "would_offer", d->synth ? "SYNTH_SINGLE" : "SINGLE", d->tip, d->bridge);
        c->offered++;
        return;
    }
    if (d->synth && !ls_make_synth(d)) {
        ls_item("stack", name, "failed", "SYNTH_FAILED", d->tip, d->bridge);
        return;
    }
    if (ls_peer_offer(c, d->dir, d->commit, id, code) &&
        ls_fmt(row, sizeof(row), "%s\t%s\t%s\t%lld\t%d\n", id, name, d->tip, (long long)c->now, d->rc0)) {
        (void)ls_append(offp, row);
        ls_say(c, "offered %s %s %s", name, d->tip, id);
        ls_item("stack", name, "offered", "", d->tip, d->bridge);
        c->offered++;
    } else {
        ls_say(c, "offer %s %s failed: %s", name, d->tip, code);
        ls_item("stack", name, "failed", code, d->tip, d->bridge);
    }
}

static void ls_phase_offer(struct ls_ctx *c)
{
    static int nums[LS_STACKS];
    char name[48], offp[LS_P + 32];
    struct ls_gate g;
    struct ls_dec d;
    int64_t mt;
    const int n = ls_stack_list(c, nums, LS_STACKS);
    (void)ls_fmt(offp, sizeof(offp), "%s/shadow-offered.tsv", c->state);
    for (int i = n - 1; i >= 0 && c->offered < c->max; i--) {
        (void)snprintf(name, sizeof(name), "z23-stacks%d", nums[i]);
        if (!ls_gate_read(c, name, &g, &mt) || c->now - mt > c->max_age)
            continue;
        const char *skip = ls_decide(c, name, &d);
        ls_ledger_last(offp, name, d.bridge);
        ls_offer_stack(c, name, &d, skip);
    }
}

/* ── (a2) per-lane pre-check ───────────────────────────────────────────── */

static const char *ls_lane_commit(struct ls_dec *d, const char *head)
{
    char tree[160];
    if (!ls_git(d->dir, tree, sizeof(tree), "merge-tree", "--write-tree", "origin/main", head))
        return "LANE_CONFLICTS";
    (void)snprintf(d->tree, sizeof(d->tree), "%.40s", tree);
    if (!ls_git(d->dir, d->base, sizeof(d->base), "rev-parse", "origin/main", NULL, NULL))
        return "LANE_BASE_UNKNOWN";
    return ls_make_synth(d) ? NULL : "LANE_COMMIT_FAILED";
}

static void ls_one_lane(struct ls_ctx *c, const char *dir)
{
    struct ls_dec d;
    char head[41], id[65], code[48], lo[LS_P + 32], row[400];
    const char *name = strrchr(dir, '/');
    name = name ? name + 1 : dir;
    memset(&d, 0, sizeof(d));
    (void)snprintf(d.dir, sizeof(d.dir), "%s", dir);
    (void)snprintf(d.name, sizeof(d.name), "%s", name);
    (void)ls_fmt(lo, sizeof(lo), "%s/lane-offered.tsv", c->state);
    if (!ls_git(dir, head, sizeof(head), "rev-parse", "HEAD", NULL, NULL) || !ls_hex(head, 40))
        return;
    if (ls_ledger_has(lo, 1, d.name, 2, head))
        return;
    if (c->dry) {
        ls_item("lane", d.name, "would_offer", "LANE_SYNTH", head, "");
        return;
    }
    const char *bad = ls_lane_commit(&d, head);
    if (bad) {
        ls_say(c, "lane %s %s: %s", d.name, head, bad);
    } else if (ls_peer_offer(c, dir, d.commit, id, code) &&
               ls_fmt(row, sizeof(row), "%s\t%s\t%s\t%s\t%lld\n", id, d.name, head, d.commit,
                      (long long)c->now)) {
        (void)ls_append(lo, row);
        ls_say(c, "lane-offered %s %s %s", d.name, head, id);
    } else {
        ls_say(c, "lane offer %s %s failed: %s", d.name, head, code);
    }
}

static void ls_phase_lanes(struct ls_ctx *c)
{
    char path[LS_P + 32], *sp = NULL;
    static char pend[LS_BUF];
    if (!ls_fmt(path, sizeof(path), "%s/stack-pending.txt", c->handoff) ||
        !ls_read(path, pend, sizeof(pend)))
        return;
    for (char *l = strtok_r(pend, "\n", &sp); l; l = strtok_r(NULL, "\n", &sp)) {
        char *tab = strchr(l, '\t');
        struct stat st;
        if (tab)
            *tab = '\0';
        if (l[0] == '/' && stat(l, &st) == 0 && S_ISDIR(st.st_mode))
            ls_one_lane(c, l);
    }
}

/* ── (b) collect and (c) compare ───────────────────────────────────────── */

/* The status and code the collect reply gives offer id; false when absent. */
static bool ls_item_code(const char *reply, const char *id, char code[48])
{
    char needle[96];
    code[0] = '\0';
    if (!ls_fmt(needle, sizeof(needle), "\"id\":\"%s\",\"status\":\"", id))
        return false;
    const char *p = strstr(reply, needle);
    if (!p)
        return false;
    p = strstr(p, "\",\"code\":\"");
    if (!p)
        return false;
    p += 10;
    for (size_t i = 0; i < 47 && (isalnum((unsigned char)p[i]) || p[i] == '_'); i++) {
        code[i] = p[i];
        code[i + 1] = '\0';
    }
    return true;
}

/* "refused:<CODE>" when the board's result list shows a refusal for id. */
static bool ls_refusal(const char *id, char out[64])
{
    char needle[96];
    if (!ls_fmt(needle, sizeof(needle), "offer=%s verdict=refused code=", id))
        return false;
    const char *p = strstr(g_ref, needle);
    if (!p)
        return false;
    p += strlen(needle);
    size_t n = 0;
    while (n < 40 && (isupper((unsigned char)p[n]) || p[n] == '_'))
        n++;
    return n > 0 && ls_fmt(out, 64, "refused:%.*s", (int)n, p);
}

/* The peer verdict word for an offer: pass, refused:C, fail:C; false when none yet. */
static bool ls_peer_verdict(const char *reply, const char *id, char v[64])
{
    char code[48];
    const bool have = ls_item_code(reply, id, code);
    if (have && strcmp(code, "ready") == 0) {
        (void)snprintf(v, 64, "pass");
        return true;
    }
    if (!have || code[0] == '\0' || strcmp(code, "NO_RECEIPTS") == 0)
        return ls_refusal(id, v);
    return ls_fmt(v, 64, "fail:%s", code);
}

static const char *ls_agree(const char *r1, const char *r2)
{
    if (strcmp(r2, "pass") == 0)
        return strcmp(r1, "pass") == 0 ? "yes" : "no";
    if (strncmp(r2, "refused:", 8) == 0)
        return "n/a";
    return strcmp(r1, "fail") == 0 ? "yes" : "no";
}

static void ls_compare_row(struct ls_ctx *c, const char *reply, char *line)
{
    char *f[8], cmp[LS_P + 32], row[500], v[64];
    struct ls_gate g;
    int64_t mt;
    if (ls_fields(line, f, 8) < 5 || !ls_hex(f[0], 64))
        return;
    (void)ls_fmt(cmp, sizeof(cmp), "%s/shadow-compare.tsv", c->state);
    if (ls_ledger_has(cmp, 0, f[0], 0, NULL) || !ls_gate_read(c, f[1], &g, &mt) ||
        g.rcs <= atoi(f[4]) || g.last_rc < 0 || !ls_peer_verdict(reply, f[0], v))
        return;
    const char *r1 = g.last_rc == 0 ? "pass" : "fail";
    if (ls_fmt(row, sizeof(row), "%s\t%s\t%s\t%s\t%s\t%s\n", f[0], f[1], f[2], r1, v, ls_agree(r1, v)))
        (void)ls_append(cmp, row);
}

static void ls_phase_compare(struct ls_ctx *c, const char *reply)
{
    static char offs[LS_BUF];
    char path[LS_P + 32], *sp = NULL, line[1024];
    if (!ls_fmt(path, sizeof(path), "%s/shadow-offered.tsv", c->state) ||
        !ls_read(path, offs, sizeof(offs)))
        return;
    for (char *l = strtok_r(offs, "\n", &sp); l; l = strtok_r(NULL, "\n", &sp)) {
        (void)snprintf(line, sizeof(line), "%s", l);
        ls_compare_row(c, reply, line);
    }
}

/* (c2) the per-lane peer verdicts. */
static void ls_phase_lane_verdicts(struct ls_ctx *c, const char *reply)
{
    static char lanes[LS_BUF];
    char path[LS_P + 32], lv[LS_P + 32], *sp = NULL, line[1024], *f[8], v[64], row[500];
    if (!ls_fmt(path, sizeof(path), "%s/lane-offered.tsv", c->state) ||
        !ls_fmt(lv, sizeof(lv), "%s/lane-verdict.tsv", c->state) ||
        !ls_read(path, lanes, sizeof(lanes)))
        return;
    for (char *l = strtok_r(lanes, "\n", &sp); l; l = strtok_r(NULL, "\n", &sp)) {
        (void)snprintf(line, sizeof(line), "%s", l);
        if (ls_fields(line, f, 8) < 4 || !ls_hex(f[0], 64) || ls_ledger_has(lv, 0, f[0], 0, NULL) ||
            !ls_peer_verdict(reply, f[0], v))
            continue;
        if (ls_fmt(row, sizeof(row), "%s\t%s\t%s\t%s\t%lld\n", f[0], f[1], f[2], v, (long long)c->now)) {
            (void)ls_append(lv, row);
            ls_say(c, "lane-verdict %s %s %s", f[1], f[2], v);
        }
    }
}

static void ls_phase_collect(struct ls_ctx *c)
{
    char a_check[40], a_state[LS_P + 16], a_room[80], a_dev[LS_P + 16];
    static char reply[LS_BUF];
    if (!ls_fmt(a_check, sizeof(a_check), "--check=%s", c->check) ||
        !ls_fmt(a_state, sizeof(a_state), "--state=%s", c->state) ||
        !ls_fmt(a_room, sizeof(a_room), "--room=%s", c->room) ||
        !ls_fmt(a_dev, sizeof(a_dev), "--z23dev=%s", c->z23dev))
        return;
    const char *const col[] = {c->bin, "collect", a_check, a_state, a_room, a_dev, NULL};
    (void)ls_run(col, NULL, LS_OFFER_S, reply, sizeof(reply));
    ls_say(c, "collect: %.200s", reply);
    const char *const lst[] = {c->z23, "fleet", "board", "list", a_room, "--kind=result", NULL};
    g_ref[0] = '\0';
    (void)ls_run(lst, NULL, LS_QUICK_S, g_ref, sizeof(g_ref));
    ls_phase_compare(c, reply);
    ls_phase_lane_verdicts(c, reply);
}

/* ── options and main ──────────────────────────────────────────────────── */

static const char *ls_opt(const struct ls_ctx *c, const char *name, const char *dflt)
{
    size_t k = strlen(name);
    for (int i = 2; i < c->argc; i++)
        if (strncmp(c->argv[i], "--", 2) == 0 && strncmp(c->argv[i] + 2, name, k) == 0 &&
            c->argv[i][2 + k] == '=' && c->argv[i][3 + k])
            return c->argv[i] + 3 + k;
    return dflt;
}

static bool ls_path_opt(const struct ls_ctx *c, char *dst, const char *name, const char *home_tail)
{
    const char *v = ls_opt(c, name, NULL);
    const char *home = getenv("HOME");
    if (v)
        return ls_fmt(dst, LS_P, "%s", v);
    return home && home[0] == '/' && home_tail && ls_fmt(dst, LS_P, "%s/%s", home, home_tail);
}

static bool ls_known(const char *a)
{
    static const char *const k[] = {"state", "gates", "stacks-root", "handoff-dir", "bin", "z23",
                                    "z23dev", "room", "check", "xdg-state", "max", "max-age"};
    if (strcmp(a, "--dry-run") == 0)
        return true;
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        const size_t n = strlen(k[i]);
        if (strncmp(a, "--", 2) == 0 && strncmp(a + 2, k[i], n) == 0 && a[2 + n] == '=' && a[3 + n])
            return true;
    }
    return false;
}

static bool ls_self(struct ls_ctx *c)
{
    const char *b = ls_opt(c, "bin", NULL);
    if (b)
        return ls_fmt(c->bin, sizeof(c->bin), "%s", b);
    if (os_proc_exe_path(c->bin, sizeof(c->bin)))
        return true;
    return ls_fmt(c->bin, sizeof(c->bin), "%s", c->argv[0]);
}

static bool ls_valid(const struct ls_ctx *c)
{
    const bool check_ok = strcmp(c->check, "gate") == 0 || strcmp(c->check, "verify") == 0 ||
                          strcmp(c->check, "cx") == 0;
    return c->max >= 1 && c->max_age >= 1 && check_ok && ls_opt(c, "state", NULL) != NULL;
}

static bool ls_setup(struct ls_ctx *c)
{
    for (int i = 2; i < c->argc; i++) {
        if (!ls_known(c->argv[i]))
            return false;
        c->dry = c->dry || strcmp(c->argv[i], "--dry-run") == 0;
    }
    c->z23 = ls_opt(c, "z23", "z23");
    c->z23dev = ls_opt(c, "z23dev", "z23-dev");
    c->room = ls_opt(c, "room", "lab");
    c->check = ls_opt(c, "check", "gate");
    c->xdg = ls_opt(c, "xdg-state", NULL);
    c->max = atoi(ls_opt(c, "max", "5"));
    c->max_age = atoi(ls_opt(c, "max-age", "86400"));
    c->now = clock_now_wall_ms() / 1000;
    if (!ls_valid(c))
        return false;
    return ls_path_opt(c, c->state, "state", NULL) &&
           ls_path_opt(c, c->gates, "gates", ".cache/development-scratch/z23/gate-submit") &&
           ls_path_opt(c, c->root, "stacks-root", "development/z23") &&
           ls_path_opt(c, c->handoff, "handoff-dir", "development/z23/handoff/handoff-20261025") &&
           ls_self(c);
}

/* The exclusive run lock (the bridge's shadow.lock); false when held. */
static bool ls_lock(const struct ls_ctx *c)
{
    char path[LS_P + 32];
    if (!ls_fmt(path, sizeof(path), "%s/shadow.lock", c->state))
        return false;
    const int fd = open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    return fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0; /* held to exit */
}

int lab_peer_shadow_main(int argc, char **argv)
{
    static struct ls_ctx c;
    c.argc = argc;
    c.argv = argv;
    if (!ls_setup(&c)) {
        (void)fputs("usage: z23-lab-peer shadow --state=DIR [--gates=DIR] [--stacks-root=DIR] "
                    "[--handoff-dir=DIR] [--bin=PATH] [--z23=P] [--z23dev=P] [--room=lab] "
                    "[--check=gate|verify|cx] [--xdg-state=DIR] [--max=N] [--max-age=SECS] "
                    "[--dry-run]\n", stderr);
        return 2;
    }
    if (c.xdg && setenv("XDG_STATE_HOME", c.xdg, 1) != 0)
        return 1;
    if (!c.dry && !ls_lock(&c))
        return 0; /* another run holds the lock, as the bridge's flock -n */
    ls_doc("[");
    ls_phase_offer(&c);
    ls_phase_lanes(&c);
    if (!c.dry)
        ls_phase_collect(&c);
    (void)printf("{\"schema\":\"zcl.lab_peer.v1\",\"command\":\"shadow\",\"ok\":true,\"dry_run\":%s,"
                 "\"check\":\"%s\",\"xdg_state\":\"%s\",\"items\":%s]}\n",
                 c.dry ? "true" : "false", c.check, c.xdg ? "set" : "inherited", g_doc);
    return 0;
}
