/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: predicate evaluation for check-doc-claims (gate_doc_claims.c).
 * eval_claim answers 0 hold / 1 stale / 2 malformed and fills a human
 * reason; gate_rc resolves an oracle gate through the driver's recorded
 * verdict (ZCL_LINT_GATES_DIR_X) or by running it via fork+execvp of
 * "timeout N bash -c" — never system() or popen(). Subprocess capture is
 * dc_run_capture. Ported from the eval_claim / gate_rc / symbol_hit
 * functions of tools/lint/check_doc_claims.sh.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include "platform/clock.h"
#include "lintc.h"
#include "gate_doc_claims_priv.h"

static const char k_dc_self_gate[] = "check-doc-claims";

struct dc_memo_ent {
    char name[DC_MEMO_NAME];
    int rc;
    int set;
};
static struct dc_memo_ent dc_memo[DC_MEMO];

/* ── small helpers ─────────────────────────────────────────────────── */

static void dc_setr(char *reason, size_t cap, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(reason, cap, fmt, ap);
    va_end(ap);
    if (ovf(n, cap)) {
        memcpy(reason, "reason text too long", 20);
        reason[20] = '\0';
    }
}

static void dc_strip_note(const char *body, char *out, size_t cap)
{
    const char *h = strchr(body, '#');
    size_t n = h ? (size_t)(h - body) : strlen(body);
    if (n >= cap)
        n = cap - 1;
    memcpy(out, body, n);
    out[n] = '\0';
}

/* Splits on blanks; returns 1 when a token was truncated. */
static int dc_tok_split(const char *b, char tok[][DC_TOK], int max, int *nt)
{
    int n = 0, ov = 0;
    const char *p = b;
    while (*p) {
        while (*p == ' ' || *p == '\t')
            p++;
        if (!*p)
            break;
        const char *s = p;
        while (*p && *p != ' ' && *p != '\t')
            p++;
        if (n < max) {
            size_t l = (size_t)(p - s);
            if (l >= DC_TOK) {
                l = DC_TOK - 1;
                ov = 1;
            }
            memcpy(tok[n], s, l);
            tok[n][l] = '\0';
        }
        n++;
    }
    *nt = n;
    return ov;
}

int dc_claim_owned(const char *body)
{
    if (dc_claim_part == DC_PART_ALL)
        return 1;
    char b[DC_LINE], tok[DC_TOKS][DC_TOK];
    int nt;
    dc_strip_note(body, b, sizeof b);
    (void)dc_tok_split(b, tok, DC_TOKS, &nt);
    int oracle = nt >= 1 && (!strcmp(tok[0], "gate-passes") ||
                             !strcmp(tok[0], "gate-fails"));
    if (dc_claim_part == DC_PART_GATE)
        return oracle;
    return !oracle;
}

/* ── subprocess plumbing (fork + execvp only) ──────────────────────── */

int dc_run_capture(char *const argv[], char *out, size_t cap, size_t *len,
                   int *rc)
{
    int fds[2];
    if (pipe(fds))
        return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        close(fds[0]);
        dup2(fds[1], 1);
        close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    size_t got = 0;
    char b[4096];
    ssize_t r;
    int over = 0;
    while ((r = read(fds[0], b, sizeof b)) > 0) {
        if (got + (size_t)r >= cap)
            over = 1;
        else {
            memcpy(out + got, b, (size_t)r);
            got += (size_t)r;
        }
    }
    close(fds[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    *rc = WIFSIGNALED(st) ? 128 + WTERMSIG(st) : WEXITSTATUS(st);
    out[got] = '\0';
    *len = got;
    if (over && got + 1 > cap)
        return -2;
    return over ? -2 : 0;
}

/* Runs "timeout N bash -c cd ROOT && ZCL_LINT_PRODUCTION_SCAN=1 cmd". */
static int dc_run_gate(const char *cmd)
{
    char full[DC_CMD + DC_PATH + 64], ts[16];
    if (ovf(snprintf(full, sizeof full, "cd '%s' && "
                     "ZCL_LINT_PRODUCTION_SCAN=1 %s", dc_root, cmd),
            sizeof full))
        return 2;
    if (ovf(snprintf(ts, sizeof ts, "%d", dc_gate_timeout), sizeof ts))
        return 2;
    char *av[] = { "timeout", ts, "bash", "-c", full, NULL };
    int fds[2];
    if (pipe(fds))
        return 2;
    pid_t pid = fork();
    if (pid < 0) {
        close(fds[0]);
        close(fds[1]);
        return 2;
    }
    if (pid == 0) {
        close(fds[0]);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) {
            dup2(dn, 1);
            dup2(dn, 2);
        }
        close(fds[1]);
        execvp("timeout", av);
        _exit(127);
    }
    close(fds[0]);
    close(fds[1]);
    int st = 0;
    waitpid(pid, &st, 0);
    return WIFSIGNALED(st) ? 128 + WTERMSIG(st) : WEXITSTATUS(st);
}

/* ── oracle gate resolution ─────────────────────────────────────────── */

static int dc_memo_find(const char *g)
{
    for (int i = 0; i < DC_MEMO; i++)
        if (dc_memo[i].set && !strcmp(dc_memo[i].name, g))
            return i;
    return -1;
}

static void dc_memo_put(const char *g, int rc)
{
    int i = dc_memo_find(g);
    if (i < 0) {
        if (strlen(g) >= DC_MEMO_NAME || dc_memo[DC_MEMO - 1].set)
            return;
        for (i = 0; i < DC_MEMO; i++)
            if (!dc_memo[i].set)
                break;
        strcpy(dc_memo[i].name, g);
        dc_memo[i].set = 1;
    }
    dc_memo[i].rc = rc;
}

void dc_memo_forget(const char *g)
{
    int i = dc_memo_find(g);
    if (i >= 0)
        dc_memo[i].set = 0;
}

void dc_memo_clear(void)
{
    for (int i = 0; i < DC_MEMO; i++)
        dc_memo[i].set = 0;
}

/* Extracts the recipe from a run_lint.sh-style table line: NAME) echo '...'
 * ;;. Returns 0 when out holds the command. */
static int dc_table_lookup(const char *path, const char *g, char *out,
                           size_t cap)
{
    char pat[DC_MEMO_NAME + 64];
    if (ovf(snprintf(pat, sizeof pat,
                     "^[[:space:]]*%s\\)[[:space:]]*echo '(.*)'"
                     "[[:space:]]*;;", g), sizeof pat))
        return 1;
    regex_t re;
    if (regcomp(&re, pat, REG_EXTENDED) != 0)
        return 1;
    FILE *f = fopen(path, "r");
    if (!f) {
        regfree(&re);
        return 1;
    }
    char line[DC_LINE];
    regmatch_t m[2];
    int found = 0;
    while (!found && fgets(line, sizeof line, f)) {
        if (regexec(&re, line, 2, m, 0) == 0) {
            size_t n = (size_t)(m[1].rm_eo - m[1].rm_so);
            if (n < cap) {
                memcpy(out, line + m[1].rm_so, n);
                out[n] = '\0';
                found = 1;
            }
        }
    }
    fclose(f);
    regfree(&re);
    return found ? 0 : 1;
}

static int dc_gate_cmd_for(const char *g, char *out, size_t cap)
{
    const char *tbl = dc_table_override ? dc_table_path
                                        : "tools/lint/run_lint.sh";
    if (dc_table_lookup(tbl, g, out, cap) == 0)
        return 0;
    return lint_gate_command(g, out, cap) == 0 ? 0 : 1;
}

/* 1 when requested.list exists and omits g (never wait for it). */
static int dc_requested_omits(const char *dir, const char *g)
{
    char path[DC_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/requested.list", dir),
            sizeof path))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[DC_LINE];
    int found = 0;
    while (!found && fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        if (n && line[n - 1] == '\n')
            line[n - 1] = '\0';
        if (!strcmp(line, g))
            found = 1;
    }
    fclose(f);
    return found ? 0 : 1;
}

/* Polls dir/<g>.rc up to dc_gate_timeout seconds. 1 when a valid numeric
 * verdict was read into *rc; 0 means fall through and run the gate. */
static int dc_wait_verdict(const char *dir, const char *g, int *rc)
{
    char path[DC_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s.rc", dir, g), sizeof path))
        return 0;
    int64_t start = clock_now_monotonic_ns();
    struct timespec nap = { 0, 200 * 1000 * 1000 };
    while (clock_now_monotonic_ns() - start < (int64_t)dc_gate_timeout * 1000000000LL) {
        FILE *f = fopen(path, "r");
        if (f) {
            char buf[64];
            int ok = 0;
            if (fgets(buf, sizeof buf, f) && buf[0]) {
                ok = 1;
                for (char *p = buf; *p; p++) {
                    if (*p == '\n') {
                        *p = '\0';
                        break;
                    }
                    if (*p < '0' || *p > '9')
                        ok = 0;
                }
            }
            fclose(f);
            if (ok && buf[0]) {
                *rc = atoi(buf);
                return 1;
            }
            return 0;
        }
        nanosleep(&nap, NULL);
    }
    return 0;
}

int dc_gate_rc(const char *gate)
{
    int i = dc_memo_find(gate);
    if (i >= 0)
        return dc_memo[i].rc;
    if (!strcmp(gate, k_dc_self_gate) || !strcmp(gate, "check-core-seal"))
        return -1;
    char cmd[DC_CMD];
    if (dc_gate_cmd_for(gate, cmd, sizeof cmd) != 0)
        return -1;
    const char *vdir = getenv("ZCL_LINT_GATES_DIR_X");
    struct stat vst;
    if (vdir && *vdir && (stat(vdir, &vst) != 0 || !S_ISDIR(vst.st_mode)))
        vdir = NULL;
    if (vdir && *vdir && dc_requested_omits(vdir, gate))
        vdir = NULL;
    int rc;
    if (vdir && *vdir && dc_wait_verdict(vdir, gate, &rc)) {
        dc_memo_put(gate, rc);
        return rc;
    }
    rc = dc_run_gate(cmd);
    dc_memo_put(gate, rc);
    return rc;
}

/* ── predicates ────────────────────────────────────────────────────── */

static int dc_symbol_hit(const char *sym, const char *spec)
{
    char out[4096];
    size_t len;
    int rc;
    char *av[] = { "git", "-C", dc_root, "grep", "-lwF", "--", (char *)sym,
                   "--", (char *)spec, NULL };
    if (dc_run_capture(av, out, sizeof out, &len, &rc))
        return 2;
    if (rc >= 2)
        return 2;
    return rc == 0 ? 0 : 1;
}

static int dc_eval_file(const char *pred, int nt, char tok[][DC_TOK],
                        char *reason, size_t cap)
{
    if (nt != 2) {
        dc_setr(reason, cap,
                "'%s' takes exactly 1 argument (a path); got %d", pred,
                nt - 1);
        return 2;
    }
    const char *p = tok[1];
    if (p[0] == '/' || strstr(p, "..")) {
        dc_setr(reason, cap,
                "'%s' path must be repo-relative and free of '..': %s", pred,
                p);
        return 2;
    }
    char full[DC_PATH * 2];
    if (ovf(snprintf(full, sizeof full, "%s/%s", dc_root, p), sizeof full))
        return 2;
    struct stat st;
    int ex = stat(full, &st) == 0;
    if (!strcmp(pred, "file-present")) {
        if (ex)
            return 0;
        dc_setr(reason, cap, "%s does NOT exist in the tree", p);
        return 1;
    }
    if (!ex)
        return 0;
    dc_setr(reason, cap, "%s EXISTS in the tree", p);
    return 1;
}

static int dc_eval_symbol(const char *pred, int nt, char tok[][DC_TOK],
                          char *reason, size_t cap)
{
    if (nt != 3) {
        dc_setr(reason, cap,
                "'%s' takes exactly 2 arguments (<symbol> <pathspec>); "
                "got %d", pred, nt - 1);
        return 2;
    }
    int hit = dc_symbol_hit(tok[1], tok[2]);
    if (hit >= 2) {
        dc_setr(reason, cap, "git grep failed for '%s' over pathspec '%s'",
                tok[1], tok[2]);
        return 2;
    }
    if (!strcmp(pred, "symbol-present")) {
        if (hit == 0)
            return 0;
        dc_setr(reason, cap, "'%s' is NOT referenced anywhere under '%s'",
                tok[1], tok[2]);
        return 1;
    }
    if (hit == 1)
        return 0;
    dc_setr(reason, cap, "'%s' IS still referenced under '%s'", tok[1],
            tok[2]);
    return 1;
}

static int dc_gate_name_ok(const char *g)
{
    if (strncmp(g, "check-", 6) != 0)
        return 0;
    const char *p = g + 6;
    if (!*p)
        return 0;
    int alnum = 0;
    for (; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9')) {
            alnum = 1;
            continue;
        }
        if (*p == '-' && alnum && p[1] && p[1] != '-') {
            alnum = 0;
            continue;
        }
        return 0;
    }
    return alnum;
}

static int dc_eval_gate(const char *pred, int nt, const char *g,
                        char *reason, size_t cap)
{
    if (nt != 2) {
        dc_setr(reason, cap,
                "'%s' takes exactly 1 argument (a check-* gate name); "
                "got %d", pred, nt - 1);
        return 2;
    }
    if (!dc_gate_name_ok(g)) {
        dc_setr(reason, cap, "'%s' is not a well-formed check-* gate name",
                g);
        return 2;
    }
    int rc = dc_gate_rc(g);
    if (rc < 0) {
        dc_setr(reason, cap,
                "gate '%s' has no entry in gate_command() in %s (or is not "
                "runnable as an oracle)", g,
                dc_table_override ? dc_table_path : "tools/lint/run_lint.sh");
        return 2;
    }
    if (rc == 0) {
        if (!strcmp(pred, "gate-passes"))
            return 0;
        dc_setr(reason, cap, "oracle gate '%s' now PASSES — the work this "
                "item calls outstanding is DONE", g);
        return 1;
    }
    if (!strcmp(pred, "gate-fails"))
        return 0;
    dc_setr(reason, cap, "oracle gate '%s' now FAILS (exit %d) — the state "
            "this item relies on is gone", g, rc);
    return 1;
}

int dc_eval_claim(const char *body, char *reason, size_t cap)
{
    char b[DC_LINE], tok[DC_TOKS][DC_TOK];
    int nt, ov;
    dc_strip_note(body, b, sizeof b);
    ov = dc_tok_split(b, tok, DC_TOKS, &nt);
    if (nt == 0) {
        dc_setr(reason, cap, "empty claim body");
        return 2;
    }
    if (ov) {
        dc_setr(reason, cap, "claim token exceeds %d bytes", DC_TOK);
        return 2;
    }
    if (!strcmp(tok[0], "file-present") || !strcmp(tok[0], "file-absent"))
        return dc_eval_file(tok[0], nt, tok, reason, cap);
    if (!strcmp(tok[0], "symbol-present") || !strcmp(tok[0], "symbol-absent"))
        return dc_eval_symbol(tok[0], nt, tok, reason, cap);
    if (!strcmp(tok[0], "gate-passes") || !strcmp(tok[0], "gate-fails"))
        return dc_eval_gate(tok[0], nt, tok[1], reason, cap);
    dc_setr(reason, cap, "unknown predicate '%s' (want: file-present|"
            "file-absent|symbol-present|symbol-absent|gate-passes|"
            "gate-fails)", tok[0]);
    return 2;
}
