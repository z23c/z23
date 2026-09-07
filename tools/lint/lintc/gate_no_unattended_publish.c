/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-no-unattended-publish of the C23 lint
 * runtime, replacing tools/lint/check_no_unattended_publish.sh. HARD gate,
 * closed allowlist: no tracked shell script/systemd unit, and no native
 * leaf under tools/command/ or tools/dev/ (a .c file there), may reach
 * `git push` or
 * `git commit-tree` unless the path is named in the allowlist below with a
 * reviewed reason. Default (unoverridden) scan set: git-tracked files
 * matching the pathspecs 'tools/ (any depth)', 'deploy/ (any depth)' and
 * any path ending .sh — read from the
 * native git index in a production scan (ZCL_LINT_PRODUCTION_SCAN=1, what
 * `make check-no-unattended-publish` sets) and via a plain filesystem walk
 * otherwise, so the gate still finds its scan set from the make_lint_gates
 * sandbox lane's hardlink clone, which deliberately carries no .git.
 * ZCL_UNATTENDED_PUBLISH_SCAN_FILES overrides the scan set with a literal
 * newline-separated file list (used by --selftest, sandboxed).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum {
    NUP_MAXF = 4096, NUP_PATH = 512, NUP_HITBUF = 4096, NUP_MAXV = 64,
    NUP_LINE = 8192
};

/* Closed allowlist: path, reason. A file not named here may not publish. */
static const struct { const char *path; const char *reason; } k_nup_allow[] = {
    { "tools/ship.sh",
      "the operator-run deploy path; a person invokes it and it verifies "
      "the running daemon's source id" },
    { "tools/githooks/pre-push",
      "prints advice text naming the override command; performs no push "
      "of its own" },
    { "tools/githooks/pre-commit",
      "prints advice text naming the override command; performs no "
      "commit of its own" },
    { "tools/scripts/hooks_status.sh",
      "read-only `make hooks-status` reporter; prints the same override "
      "advice text as tools/githooks/pre-push, performs no push of its "
      "own" },
    { "tools/lint/check_stable_publish_containment.sh",
      "lint fixture: the forbidden string is the input it tests" },
    { "tools/scripts/check_stable_publish_containment.sh",
      "lint fixture: the forbidden string is the input it tests" },
    { "tools/lint/check_no_unattended_publish.sh",
      "this gate; a gate exempt from itself is a place to hide, so it is "
      "listed rather than skipped" },
    { "tools/command/native_dev_land.c",
      "the landing service pushes only a tip whose exact proof receipt "
      "was admitted; see docs/agent/TRAIN_PROTOCOL.md" },
};
#define NUP_NALLOW ((int)(sizeof k_nup_allow / sizeof k_nup_allow[0]))

static const char k_nup_gate[] = "check-no-unattended-publish";
static const char k_nup_publish_re[] =
    "(^|[^[:alnum:]_-])git([[:space:]]+(-C|-c|--git-dir|--work-tree|"
    "--namespace|--config-env)[[:space:]]+[^[:space:]]+|[[:space:]]+--"
    "(git-dir|work-tree|namespace|config-env|exec-path)=[^[:space:]]+|"
    "[[:space:]]+(-p|-P|--paginate|--no-pager|--no-replace-objects|"
    "--bare))*[[:space:]]+(push|commit-tree)([^[:alnum:]_-]|$)";
static const char k_nup_push_lit[] = "\"push\"";
static const char k_nup_spawn_re[] = "zcl_spawn(_capture)?\\(";
static const char k_nup_report_re[] = "\"push\"|\"origin\"";

struct nup_violation { char path[NUP_PATH]; char hits[NUP_HITBUF]; };
struct nup_ctx { int scanned; struct nup_violation v[NUP_MAXV]; int nv; };
struct nup_regs {
    const regex_t *publish, *push_lit, *spawn, *report;
};

static int nup_ends_with(const char *s, const char *suf)
{
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && strcmp(s + ls - lf, suf) == 0;
}

static int nup_starts_with(const char *s, const char *pre)
{ return strncmp(s, pre, strlen(pre)) == 0; }

static const char *nup_allow_reason(const char *p)
{
    for (int i = 0; i < NUP_NALLOW; i++)
        if (strcmp(k_nup_allow[i].path, p) == 0)
            return k_nup_allow[i].reason;
    return NULL;
}

static int nup_is_shell_kind(const char *p)
{
    const char *base = strrchr(p, '/');
    base = base ? base + 1 : p;
    return nup_ends_with(p, ".sh") || strcmp(base, "pre-push") == 0
        || strcmp(base, "pre-commit") == 0 || nup_ends_with(p, ".service")
        || nup_ends_with(p, ".timer");
}

static int nup_is_native_kind(const char *p)
{
    if (!nup_ends_with(p, ".c"))
        return 0;
    return nup_starts_with(p, "tools/command/") || strstr(p, "/tools/command/")
        || nup_starts_with(p, "tools/dev/") || strstr(p, "/tools/dev/");
}

/* Default-enumeration scope only: mirrors `git ls-files -- <pathspecs
 * tools/ANY, deploy/ANY, ANY.sh>` (plain, unmagicked git pathspecs — the
 * glob crosses '/', so the tools/ pathspec matches anything anywhere
 * under tools/, and the .sh pathspec matches any path ending .sh at any
 * depth). Never applied to an explicit ZCL_UNATTENDED_PUBLISH_SCAN_FILES
 * override, exactly like the shell. */
static int nup_in_scope(const char *p)
{
    return nup_starts_with(p, "tools/") || nup_starts_with(p, "deploy/")
        || nup_ends_with(p, ".sh");
}

static int nup_line_is_comment(const char *line)
{
    while (*line == ' ' || *line == '\t')
        line++;
    return *line == '#';
}

static int nup_hits_append(char *buf, size_t cap, size_t *used, int lineno,
                           const char *line)
{
    int n = snprintf(buf + *used, cap - *used, "%d:%s\n", lineno, line);
    if (n < 0 || (size_t)n >= cap - *used)
        return die("z23-lint: hit buffer overflow\n", "");
    *used += (size_t)n;
    return 0;
}

/* Read one line into `line` (stripped of its trailing newline); sets *eof
 * when the file is exhausted. Split out of nup_scan_lines so the loop that
 * owns it stays under the complexity cap. */
static int nup_read_line(FILE *f, const char *path, char *line, size_t cap,
                         int *eof)
{
    size_t n;
    if (!fgets(line, (int)cap, f)) {
        *eof = 1;
        return 0;
    }
    *eof = 0;
    n = strlen(line);
    if (n + 1 >= cap && (n == 0 || line[n - 1] != '\n'))
        return die("z23-lint: source line too long: %s\n", path);
    if (n && line[n - 1] == '\n')
        line[--n] = '\0';
    return 0;
}

/* Test one already-read line against `re`, recording a hit when it matches
 * and (unless skip_comments says otherwise) is not a comment line. */
static int nup_test_line(const char *line, const regex_t *re,
                         int skip_comments, int lineno, int *matched,
                         char *hitbuf, size_t hitcap, size_t *used)
{
    if (skip_comments && nup_line_is_comment(line))
        return 0;
    if (regexec(re, line, 0, NULL, 0) != 0)
        return 0;
    *matched = 1;
    return nup_hits_append(hitbuf, hitcap, used, lineno, line);
}

/* Scan one file line by line against `re`; every matching line becomes a
 * hit (lineno:text). When `skip_comments` is set, a line whose first
 * non-blank byte is '#' is never tested — documentation naming the
 * forbidden command is not a publish. */
static int nup_scan_lines(const char *path, const regex_t *re,
                          int skip_comments, int *matched, char *hitbuf,
                          size_t hitcap)
{
    FILE *f = fopen(path, "r");
    char line[NUP_LINE];
    int rc = 0, lineno = 0, eof = 0;
    size_t used = 0;
    *matched = 0;
    hitbuf[0] = '\0';
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (rc == 0) {
        rc = nup_read_line(f, path, line, sizeof line, &eof);
        if (rc || eof)
            break;
        lineno++;
        rc = nup_test_line(line, re, skip_comments, lineno, matched, hitbuf,
                           hitcap, &used);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int nup_record_violation(struct nup_ctx *c, const char *path,
                                const char *hits)
{
    if (c->nv >= NUP_MAXV)
        return die("z23-lint: violation-set overflow\n", "");
    if (ovf(snprintf(c->v[c->nv].path, NUP_PATH, "%s", path), NUP_PATH))
        return 2;
    if (ovf(snprintf(c->v[c->nv].hits, NUP_HITBUF, "%s", hits), NUP_HITBUF))
        return 2;
    c->nv++;
    return 0;
}

static int nup_process_native(const char *path, const struct nup_regs *re,
                              int *is_violation, char *hitbuf, size_t cap)
{
    int has_push = 0, has_spawn = 0, rc;
    *is_violation = 0;
    rc = nup_scan_lines(path, re->push_lit, 0, &has_push, hitbuf, cap);
    if (rc || !has_push)
        return rc;
    rc = nup_scan_lines(path, re->spawn, 0, &has_spawn, hitbuf, cap);
    if (rc || !has_spawn)
        return rc;
    rc = nup_scan_lines(path, re->report, 0, is_violation, hitbuf, cap);
    if (rc)
        return rc;
    *is_violation = 1; /* push+spawn together is the violation shape */
    return 0;
}

static int nup_process_file(const char *path, const struct nup_regs *re,
                            struct nup_ctx *c)
{
    int native = nup_is_native_kind(path);
    int shell = !native && nup_is_shell_kind(path);
    char hitbuf[NUP_HITBUF];
    int matched = 0, rc;
    if (!native && !shell)
        return 0;
    c->scanned++;
    if (shell) {
        rc = nup_scan_lines(path, re->publish, 1, &matched, hitbuf,
                            sizeof hitbuf);
        if (rc || !matched)
            return rc;
    } else {
        rc = nup_process_native(path, re, &matched, hitbuf, sizeof hitbuf);
        if (rc || !matched)
            return rc;
    }
    if (nup_allow_reason(path))
        return 0;
    return nup_record_violation(c, path, hitbuf);
}

static int nup_split_lines(const char *s, char out[][NUP_PATH], int max,
                           int *n)
{
    const char *p = s;
    *n = 0;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0) {
            if (*n >= max)
                return die("z23-lint: scan-set overflow\n", "");
            if (len >= NUP_PATH)
                return die("z23-lint: path too long in scan-files list\n", "");
            memcpy(out[*n], p, len);
            out[*n][len] = '\0';
            (*n)++;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int nup_add_scoped(char out[][NUP_PATH], int max, int *n,
                          const char *p)
{
    size_t len;
    if (!nup_in_scope(p))
        return 0;
    if (*n >= max)
        return die("z23-lint: scan-set overflow\n", "");
    len = strlen(p);
    if (len >= NUP_PATH)
        return die("z23-lint: path too long: %s\n", p);
    memcpy(out[*n], p, len + 1);
    (*n)++;
    return 0;
}

struct nup_collect_ctx { char (*files)[NUP_PATH]; int max; int *n; };

static int nup_on_index(const char *path, int stage, void *ctx)
{
    struct nup_collect_ctx *c = ctx;
    if (stage != 0)
        return 0;
    return nup_add_scoped(c->files, c->max, c->n, path);
}

static int nup_from_index(char out[][NUP_PATH], int max, int *n)
{
    char badext[5] = "";
    struct nup_collect_ctx cc = { out, max, n };
    int rc = lint_git_index_foreach(nup_on_index, &cc, badext);
    if (badext[0]) {
        fprintf(stderr,
                "z23-lint: UNPROVEN — the git index carries a mandatory\n"
                "  extension ('%s') this native reader does not interpret;\n"
                "  reading past it could silently yield a PARTIAL file\n"
                "  list. Refusing to grade. Re-create the index without\n"
                "  split-index/sparse extensions, or teach\n"
                "  lint_git_index_foreach the extension first.\n", badext);
        return 2;
    }
    return rc;
}

static const char *const k_nup_skip_dirs[] = {
    ".git", "build", "vendor", "node_modules", "test-tmp", ".claude"
};

static int nup_skip_dir(const char *nm)
{
    for (size_t i = 0; i < sizeof k_nup_skip_dirs / sizeof k_nup_skip_dirs[0]; i++)
        if (strcmp(nm, k_nup_skip_dirs[i]) == 0)
            return 1;
    return 0;
}

static int nup_walk(const char *dir, char out[][NUP_PATH], int max, int *n);

static int nup_walk_entry(const char *dir, const char *nm,
                          char out[][NUP_PATH], int max, int *n)
{
    char path[4096];
    struct stat st;
    int k;
    if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0 || nup_skip_dir(nm))
        return 0;
    k = snprintf(path, sizeof path, "%s/%s", dir, nm);
    if (k < 0 || (size_t)k >= sizeof path)
        return die("z23-lint: path too long: %s\n", dir);
    if (lstat(path, &st) != 0)
        return die("z23-lint: cannot stat %s\n", path);
    if (S_ISDIR(st.st_mode))
        return nup_walk(path, out, max, n);
    if (S_ISREG(st.st_mode)) {
        const char *rel = (path[0] == '.' && path[1] == '/') ? path + 2 : path;
        return nup_add_scoped(out, max, n, rel);
    }
    return 0;
}

static int nup_walk(const char *dir, char out[][NUP_PATH], int max, int *n)
{
    struct dirent **names = NULL;
    int cnt = scandir(dir, &names, NULL, alphasort);
    int rc = 0, i;
    if (cnt < 0)
        return errno == ENOENT ? 0 : die("z23-lint: cannot scan %s\n", dir);
    for (i = 0; i < cnt; i++) {
        if (rc == 0)
            rc = nup_walk_entry(dir, names[i]->d_name, out, max, n);
        free(names[i]);
    }
    free(names);
    return rc;
}

static int nup_collect_default(char out[][NUP_PATH], int max, int *n)
{
    *n = 0;
    if (lint_prod_scan())
        return nup_from_index(out, max, n);
    return nup_walk(".", out, max, n);
}

static int nup_report(const struct nup_ctx *c)
{
    fprintf(stderr,
            "[%s] a script may not write to the shared remote:\n", k_nup_gate);
    for (int i = 0; i < c->nv; i++) {
        const char *p = c->v[i].hits;
        fprintf(stderr, "  %s\n", c->v[i].path);
        while (*p) {
            const char *nl = strchr(p, '\n');
            size_t len = nl ? (size_t)(nl - p) : strlen(p);
            fprintf(stderr, "      %.*s\n", (int)len, p);
            if (!nl)
                break;
            p = nl + 1;
        }
    }
    fputs("\n"
          "Publishing is a deliberate act a person performs, not a side "
          "effect of a\nbackground loop. A timer that can move `main` "
          "moves it for every checkout\nthat fast-forwards from it, with "
          "nobody reviewing what went out.\n\n"
          "If this file genuinely must publish, add it to ALLOW_PATHS in "
          "this gate with\na reason a reviewer can weigh. If it is "
          "recording what a machine observed,\nwrite that to the "
          "operator's own state directory instead — see the header of\n"
          "tools/scripts/fleet_sync.sh for the shape.\n", stderr);
    return 1;
}

static int nup_compile(regex_t *publish, regex_t *push_lit, regex_t *spawn,
                       regex_t *report, const char *pub_pat)
{
    int rc = reg_fail(publish, regcomp(publish, pub_pat, REG_EXTENDED));
    if (rc)
        return rc;
    rc = reg_fail(push_lit, regcomp(push_lit, k_nup_push_lit, REG_EXTENDED));
    if (rc) { regfree(publish); return rc; }
    rc = reg_fail(spawn, regcomp(spawn, k_nup_spawn_re, REG_EXTENDED));
    if (rc) { regfree(publish); regfree(push_lit); return rc; }
    rc = reg_fail(report, regcomp(report, k_nup_report_re, REG_EXTENDED));
    if (rc) { regfree(publish); regfree(push_lit); regfree(spawn); return rc; }
    return 0;
}

/* Resolve the scan set: an explicit override (its own file list, verbatim)
 * or the default (git index in a production scan, filesystem walk
 * otherwise). Split out of check_no_unattended_publish_run so the
 * top-level driver stays under the complexity cap. */
static int nup_gather(char files[][NUP_PATH], int max, int *nf, int *override)
{
    const char *ovr = getenv("ZCL_UNATTENDED_PUBLISH_SCAN_FILES");
    if (ovr && ovr[0]) {
        *override = 1;
        return nup_split_lines(ovr, files, max, nf);
    }
    *override = 0;
    return nup_collect_default(files, max, nf);
}

/* Compile the four detector regexes and scan every candidate file with
 * them, freeing the regexes on every exit path. */
static int nup_scan_all(char files[][NUP_PATH], int nf, int override,
                        struct nup_ctx *c)
{
    const char *pub_pat = k_nup_publish_re;
    regex_t publish, push_lit, spawn, report;
    struct nup_regs re;
    int rc;
    if (override) {
        const char *tr = getenv("ZCL_UNATTENDED_PUBLISH_TEST_REGEX");
        if (tr && tr[0])
            pub_pat = tr;
    }
    rc = nup_compile(&publish, &push_lit, &spawn, &report, pub_pat);
    if (rc)
        return rc;
    re.publish = &publish;
    re.push_lit = &push_lit;
    re.spawn = &spawn;
    re.report = &report;
    for (int i = 0; rc == 0 && i < nf; i++)
        rc = nup_process_file(files[i], &re, c);
    regfree(&publish);
    regfree(&push_lit);
    regfree(&spawn);
    regfree(&report);
    return rc;
}

int check_no_unattended_publish_run(int argc, char **argv)
{
    static char files[NUP_MAXF][NUP_PATH];
    static struct nup_ctx c;
    int nf = 0, override = 0, rc;
    (void)argc;
    (void)argv;
    c.scanned = 0;
    c.nv = 0;
    rc = nup_gather(files, NUP_MAXF, &nf, &override);
    if (rc)
        return rc;
    rc = nup_scan_all(files, nf, override, &c);
    if (rc)
        return rc;
    if (!override) {
        rc = gate_require_scanned(c.scanned, 50, k_nup_gate,
                                  "expected the tracked tools/ and deploy/ "
                                  "script set");
        if (rc)
            return rc;
    }
    if (c.nv > 0)
        return nup_report(&c);
    printf("[%s] PASS (%d tracked script(s)/unit(s) scanned; %d "
           "allowlisted, each with a reason)\n", k_nup_gate, c.scanned,
           NUP_NALLOW);
    return 0;
}

static int nup_plant(const char *root, const char *rel, const char *text,
                     char *out, size_t outcap)
{
    if (ovf(snprintf(out, outcap, "%s/%s", root, rel), outcap))
        return 2;
    return csr_write(out, text);
}

static int nup_st_case(int want, const char *label, const char *file)
{
    static char sink[65536];
    int code = 0;
    int rc;
    if (setenv("ZCL_UNATTENDED_PUBLISH_SCAN_FILES", file, 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    rc = cic_invoke(k_nup_gate, 1, sink, sizeof sink, &code);
    if (rc)
        return rc;
    if (code != want) {
        fprintf(stderr,
                "[%s] SELFTEST FAIL: %s expected rc=%d, got rc=%d\n",
                k_nup_gate, label, want, code);
        return 1;
    }
    return 0;
}

/* Plant one fixture file and grade the resulting scan in one step. Split
 * out so each selftest case below costs the top-level driver a single
 * branch instead of a plant-then-grade pair. */
static int nup_st_pc(const char *root, const char *rel, const char *body,
                     int want, const char *msg, char *p, int *fails)
{
    int rc = nup_plant(root, rel, body, p, 4096);
    if (rc)
        return rc;
    *fails |= nup_st_case(want, msg, p);
    return 0;
}

/* Case 5 needs a regex override held only for the duration of its own
 * grading — the one case that cannot go through nup_st_pc verbatim. */
static int nup_st_grep_error_case(const char *root, char *p, int *fails)
{
    int rc = nup_plant(root, "grep_error.sh", "#!/bin/sh\necho clean\n", p, 4096);
    if (rc)
        return rc;
    if (setenv("ZCL_UNATTENDED_PUBLISH_TEST_REGEX", "[", 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    *fails |= nup_st_case(2, "a scan error fails loud", p);
    unsetenv("ZCL_UNATTENDED_PUBLISH_TEST_REGEX");
    return 0;
}

/* Cases 1-8: the shell-kind fixtures (plain PUBLISH_RE matching, plus the
 * comment exemption and the fatal-regex case). */
static int nup_st_shell_cases(const char *root, char *p, int *fails)
{
    int rc = nup_st_pc(root, "clean.sh",
        "#!/bin/sh\nprintf \"%s\\n\" up > \"$STATE_DIR/box.sync\"\n", 0,
        "a script that records its state locally", p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "push.sh", "#!/bin/sh\ngit push origin main --quiet\n",
                       1, "a script that pushes to the shared remote", p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "push_cwd.sh", "#!/bin/sh\ngit -C \"$repo\" push origin main\n",
                       1, "git -C cannot hide a push", p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "push_config.sh",
            "#!/bin/sh\ngit -c core.hooksPath=/dev/null push origin main\n", 1,
            "git -c cannot hide a push", p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "tree_gitdir.sh",
            "#!/bin/sh\ngit --git-dir=\"$repo/.git\" commit-tree \"$t\"\n", 1,
            "a long global option cannot hide commit-tree", p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "tree.sh",
            "#!/bin/sh\nc=$(git commit-tree \"$t\" -p \"$b\" -m heartbeat)\n", 1,
            "a script that builds a commit object out of band", p, fails);
    if (rc == 0)
        rc = nup_st_grep_error_case(root, p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "comment.sh",
            "#!/bin/sh\n# there is no git push path here any more\necho ok\n", 0,
            "a comment that names the forbidden command", p, fails);
    return rc;
}

/* Cases 9-12: the native-kind fixtures under tools/command/ and tools/dev/
 * (the push+spawn shape, the URL-remote shape, and the prose non-match). */
static int nup_st_native_cases(const char *root, char *p, int *fails)
{
    int rc = nup_st_pc(root, "tools/command/native_push.c",
        "static void go(void) {\n"
        "    const char *argv[] = { \"git\", \"push\", \"origin\", \"HEAD:main\", NULL };\n"
        "    zcl_spawn_capture(argv, buf, sizeof(buf), 1000);\n}\n", 1,
        "a native leaf under tools/command/ that pushes via spawn", p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "tools/dev/native_push.c",
            "static void go(void) {\n"
            "    const char *argv[] = { \"git\", \"push\", \"origin\", \"HEAD:main\", NULL };\n"
            "    zcl_spawn(argv);\n}\n", 1,
            "a native leaf under tools/dev/ that pushes via spawn", p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "tools/command/native_push_url.c",
            "static void go(void) {\n"
            "    const char *argv[] = { \"git\", \"push\", \"https://host/r.git\",\n"
            "                           \"HEAD:main\", NULL };\n"
            "    zcl_spawn(argv);\n}\n", 1,
            "a native leaf that pushes to a URL remote, not \"origin\"", p, fails);
    if (rc == 0)
        rc = nup_st_pc(root, "tools/command/native_prose.c",
            "/* purpose: explains that \"push\" to \"origin\" is the landing "
            "service's job,\n * not this leaf's. This file never calls a "
            "spawn function. */\nstatic void go(void) { return; }\n", 0,
            "push/origin prose with no spawn call is not a violation", p, fails);
    return rc;
}

int check_no_unattended_publish_selftest(void)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096], p[4096];
    char *root;
    int fails = 0, rc;
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-nup-XXXXXX", td),
            sizeof tmpl))
        return 2;
    root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    unsetenv("ZCL_UNATTENDED_PUBLISH_TEST_REGEX");

    rc = nup_st_shell_cases(root, p, &fails);
    if (rc == 0)
        rc = nup_st_native_cases(root, p, &fails);
    if (rc == 0)
        rc = rap_rm_rf(root);
    if (rc)
        return rc;
    if (fails) {
        fprintf(stderr, "[%s] selftest: FAIL\n", k_nup_gate);
        return 1;
    }
    printf("[%s] selftest: PASS\n", k_nup_gate);
    return 0;
}
