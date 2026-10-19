/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of check-cookbook. Proves the registry parser and field
 * splitter against the rules of the awk and read pipeline they replace, then
 * drives the gate against a throwaway repository root whose z23-dev is a
 * shell fixture: clean runs, every failure class with its exit status,
 * --fix, and SIGINT (once and twice), SIGTERM and SIGHUP delivered after a
 * readiness handshake over a pipe, which must stop the fixture group,
 * including one that ignores the signal, and re-raise the signal.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "gate_cookbook_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

enum { CKS_BUF = 16384, CKS_GRACE_MS = 300 };

struct cks_fx {
    char base[CK_PATH];
    char root[CK_PATH + 16];
    char out[CK_PATH + 16];
};

struct cks_case {
    const char *name;
    const char *def;     /* registry text, NULL removes the registry */
    int fix;
    const char *floor;
    int want;
    const char *needle;  /* must appear in the output, or NULL */
    const char *needle2;
};

static const char k_cks_def[] =
    "/* header comment */\n"
    "SECTION(\"Fixture\")\n"
    "RECIPE_RUN(\"run-it\", \"How?\",\n"
    "           Z23_DEV, \"code have retrieval\",\n"
    "           \"answer: code have\")\n"
    "RECIPE_ASK(\"ask-it\", \"Which?\", \"code.general\", \"describe code.general\")\n"
    "RECIPE_READ(\"read-it\", \"Where?\", \"Makefile\", \"all:\")\n";

static const char k_cks_dev[] =
    "#!/bin/sh\n"
    "case \"$CKS_MODE\" in\n"
    "hold) echo \"$$\" >&\"$CKS_READY_FD\"; exec sleep 30;;\n"
    "stubborn) trap '' INT TERM HUP; echo \"$$\" >&\"$CKS_READY_FD\"\n"
    "  while :; do sleep 1; done;;\n"
    "orphan) ( trap '' INT TERM HUP; echo \"$$\" >&\"$CKS_READY_FD\"; while :; do sleep 1; done ) &\n"
    "  wait;;\n"
    "esac\n"
    "echo \"answer: $*\"\n";

static int cks_fail(const char *what)
{
    fprintf(stderr, "check_cookbook selftest: FAIL - %s\n", what);
    return 1;
}

static int cks_str_eq(const char *got, const char *want, const char *what)
{
    if (strcmp(got, want) == 0)
        return 0;
    fprintf(stderr, "check_cookbook selftest: FAIL - %s\n  got:  %s\n  want: %s\n", what, got, want);
    return 1;
}

static void cks_flat(const struct ck_recs *r, char *out, size_t cap)
{
    size_t n = 0;
    for (size_t i = 0; i < r->n; i++) {
        if (i && n + 1 < cap)
            out[n++] = '\n';
        for (const char *p = r->line[i]; *p && n + 1 < cap; p++)
            out[n++] = *p == '\t' ? '|' : *p;
    }
    out[n] = '\0';
}

static int cks_parse_one(const char *text, const char *want, const char *what)
{
    struct ck_recs r;
    char got[CKS_BUF];
    if (ck_parse(text, &r) != 0)
        return cks_fail(what);
    cks_flat(&r, got, sizeof got);
    ck_recs_free(&r);
    return cks_str_eq(got, want, what);
}

static int cks_parser(void)
{
    return cks_parse_one("SECTION(\"A heading\")\nRECIPE_READ(\"a-row\", \"A question?\", \"Makefile\", \"all\")\n",
                         "SECTION|A heading\nRECIPE_READ|a-row|A question?|Makefile|all",
                         "parser output changed")
        || cks_parse_one(k_cks_def,
                         "SECTION|Fixture\nRECIPE_RUN|run-it|How?|code have retrieval|answer: code have|Z23_DEV\n"
                         "RECIPE_ASK|ask-it|Which?|code.general|describe code.general\n"
                         "RECIPE_READ|read-it|Where?|Makefile|all:",
                         "multi-line records or the tool token")
        || cks_parse_one("RECIPE_ASK(\"a\", \"say \\\"x\\\"\", \"p\", \"e\")  \n",
                         "RECIPE_ASK|a|say \\\"x\\\"|p|e", "escaped quote or trailing blanks")
        || cks_parse_one("RECIPE_ASK(\"lost\",\nSECTION(\"kept\")\n", "SECTION|kept",
                         "a new record start must discard an unfinished one")
        || cks_parse_one("RECIPE_ASK(\"never closed\"\n", "", "an unterminated record must not be emitted")
        || cks_parse_one(" SECTION(\"indented\")\n", "", "a record must start in column one");
}

static int cks_split_one(const char *line, const char *want, const char *what)
{
    char copy[256], got[512] = "", *f[CK_FIELDS];
    snprintf(copy, sizeof copy, "%s", line);
    ck_split(copy, f);
    for (int i = 0; i < CK_FIELDS; i++) {
        strcat(got, i ? "|" : "");
        strcat(got, f[i]);
    }
    return cks_str_eq(got, want, what);
}

static int cks_splitter(void)
{
    return cks_split_one("K\ta\tb\tc\td\te", "K|a|b|c|d|e", "six fields")
        || cks_split_one("K\ta\t\tc\td", "K|a|c|d||", "an empty field collapses like IFS whitespace")
        || cks_split_one("K\ta\tb\tc\td\te\tf\t", "K|a|b|c|d|e\tf", "the last field takes the remainder")
        || cks_split_one("K", "K|||||", "missing fields are empty");
}

static int cks_args(void)
{
    if (!ck_args_safe("code have retrieval") || !ck_args_safe("a-b_c.d/e=f"))
        return cks_fail("safe arguments refused");
    if (ck_args_safe("") || ck_args_safe("code have; rm -rf /") || ck_args_safe("a$b")
        || ck_args_safe("a\tb") || ck_args_safe("a'b"))
        return cks_fail("an empty or metacharacter argument was accepted");
    return 0;
}

static int cks_put(const struct cks_fx *fx, const char *rel, const char *text, mode_t mode)
{
    char path[CK_PATH * 2];
    if (snprintf(path, sizeof path, "%s/%s", fx->root, rel) >= (int)sizeof path
        || csr_write(path, text) != 0)
        return -1;
    return chmod(path, mode);
}

static int cks_scratch_parent(char *out, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    char root[CK_PATH], probe[CK_PATH + 32];
    if (tmp && tmp[0] == '/')
        return snprintf(out, cap, "%s", tmp) >= (int)cap ? -1 : 0;
    if (cic_repo_root(root, sizeof root)
        || snprintf(probe, sizeof probe, "%s/test-tmp/x", root) >= (int)sizeof probe
        || csr_mkdirs(probe) != 0)
        return -1;
    return snprintf(out, cap, "%s/test-tmp", root) >= (int)cap ? -1 : 0;
}

static int cks_git(const char *root)
{
    char cmd[CK_PATH * 3], q[CK_PATH * 2], out[CKS_BUF];
    int code = 0;
    if (sh_single_quote(root, q, sizeof q)
        || snprintf(cmd, sizeof cmd,
                    "cd %s && env -u GIT_DIR -u GIT_INDEX_FILE -u GIT_WORK_TREE "
                    "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null "
                    "sh -c 'git init -q . && git add Makefile' 2>&1", q) >= (int)sizeof cmd)
        return -1;
    return capture_cmd(cmd, out, sizeof out, &code) == 0 && code == 0 ? 0 : -1;
}

static int cks_build(struct cks_fx *fx)
{
    char parent[CK_PATH];
    if (cks_scratch_parent(parent, sizeof parent) != 0
        || snprintf(fx->base, sizeof fx->base, "%s/cookbook-selftest.XXXXXX", parent) >= (int)sizeof fx->base
        || !mkdtemp(fx->base))
        return -1;
    snprintf(fx->root, sizeof fx->root, "%s/root", fx->base);
    snprintf(fx->out, sizeof fx->out, "%s/out.txt", fx->base);
    char docs[CK_PATH + 32];
    snprintf(docs, sizeof docs, "%s/docs/dev", fx->root);
    if (cks_put(fx, "build/bin/z23-dev", k_cks_dev, 0700) || cks_put(fx, "Makefile", "all:\n\ttrue\n", 0600)
        || csr_mkdirs(docs) != 0)
        return -1;
    return cks_git(fx->root);
}

static struct ck_cfg cks_cfg(const struct cks_fx *fx, int fix, const char *floor, int grace)
{
    return (struct ck_cfg){ .root = fx->root, .def = "engine/composition/cookbook.def",
                            .doc = "docs/dev/COOKBOOK.md", .bin_dir = "build/bin", .floor = floor,
                            .timeout = "20", .fix = fix, .grace_ms = grace };
}

static pid_t cks_fork(const struct cks_fx *fx, const struct ck_cfg *cfg, const char *mode, int ready[2])
{
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    char fd[16];
    snprintf(fd, sizeof fd, "%d", ready ? ready[1] : -1);
    if (freopen(fx->out, "w", stdout) == NULL)
        _exit(125);
    unsetenv("GIT_DIR");
    unsetenv("GIT_INDEX_FILE");
    unsetenv("GIT_WORK_TREE");
    setenv("CKS_MODE", mode, 1);
    setenv("CKS_READY_FD", fd, 1);
    if (ready)
        close(ready[0]);
    _exit(ck_gate(cfg));
}

static int cks_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, cap - 1, f) : 0;
    if (f)
        fclose(f);
    buf[n] = '\0';
    return f ? 0 : -1;
}

static int cks_case(const struct cks_fx *fx, const struct cks_case *c)
{
    char path[CK_PATH * 2], out[CKS_BUF], what[CKS_BUF + 256];
    int st = 0;
    snprintf(path, sizeof path, "%s/engine/composition/cookbook.def", fx->root);
    if (c->def ? cks_put(fx, "engine/composition/cookbook.def", c->def, 0600) != 0
               : unlink(path) != 0 && errno != ENOENT)
        return cks_fail("cannot write the registry fixture");
    struct ck_cfg cfg = cks_cfg(fx, c->fix, c->floor, CKS_GRACE_MS);
    pid_t pid = cks_fork(fx, &cfg, "ok", NULL);
    if (pid < 0 || waitpid(pid, &st, 0) != pid || cks_slurp(fx->out, out, sizeof out) != 0)
        return cks_fail("the gate child did not finish");
    snprintf(what, sizeof what, "%s (exit %d, want %d)\n%s", c->name, WIFEXITED(st) ? WEXITSTATUS(st) : -1,
             c->want, out);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != c->want || (c->needle && !strstr(out, c->needle))
        || (c->needle2 && !strstr(out, c->needle2)))
        return cks_fail(what);
    return 0;
}

static int cks_cases(const struct cks_fx *fx)
{
    char path[CK_PATH * 2], doc[CKS_BUF], drifted[CKS_BUF + 8];
    const struct cks_case fix = { "--fix writes the document", k_cks_def, 1, "1", 0,
                                  "fixed: docs/dev/COOKBOOK.md regenerated", NULL };
    const struct cks_case clean = { "a matching document is clean", k_cks_def, 0, "1", 0,
                                    "check_cookbook: clean — 1 run, 1 ask, 1 read recipe(s)", NULL };
    const struct cks_case drift = { "a drifted document fails", k_cks_def, 0, "1", 1,
                                    "has drifted from", "check_cookbook: FAILED" };
    const struct cks_case again = { "--fix repairs a drifted document", k_cks_def, 1, "1", 0, "fixed:", NULL };
    const struct cks_case none = { "a missing document fails", k_cks_def, 0, "1", 1, "does not exist; run", NULL };
    snprintf(path, sizeof path, "%s/docs/dev/COOKBOOK.md", fx->root);
    if (cks_case(fx, &fix) || cks_case(fx, &clean))
        return 1;
    if (cks_slurp(path, doc, sizeof doc) != 0 || !strstr(doc, "### How?\n\n    z23 code have retrieval\n\n")
        || !strstr(doc, "(`ask-it`, ASK)") || !strstr(doc, "Worked example: `Makefile`, look for `all:`."))
        return cks_fail("the generated document lacks a recipe");
    snprintf(drifted, sizeof drifted, "%sdrift\n", doc);
    if (csr_write(path, drifted) != 0 || cks_case(fx, &drift) || cks_case(fx, &again))
        return cks_fail("document drift cases");
    return unlink(path) != 0 || cks_case(fx, &none);
}

#define CKS_RUN(tool, args, token) "RECIPE_RUN(\"r\", \"q\", " tool ", \"" args "\", \"" token "\")\n"
#define CKS_READ(id, file, sym) "RECIPE_READ(\"" id "\", \"q\", \"" file "\", \"" sym "\")\n"

static int cks_failures(const struct cks_fx *fx)
{
    const struct cks_case cases[] = {
        { "a stale RUN token", CKS_RUN("Z23_DEV", "code have", "nothing like this"), 0, "1", 1,
          "recipe 'r': 'z23 code have' no longer prints 'nothing like this'",
          "observed (first 2048 bytes): answer: code have" },
        { "an unsafe argument", CKS_RUN("Z23_DEV", "code; true", "x"), 0, "1", 1,
          "recipe 'r' has unsafe or empty arguments: 'code; true'", NULL },
        { "an unknown tool", CKS_RUN("Z23_SH", "code have", "answer"), 0, "1", 1,
          "recipe 'r' names an unknown tool", NULL },
        { "a stale ASK command", "RECIPE_ASK(\"a\", \"q\", \"code.general\", \"never\")\n", 0, "1", 1,
          "recipe 'a': command 'code.general' is no longer 'never'", NULL },
        { "a symbol that left the file", CKS_READ("g", "Makefile", "no such symbol"), 0, "1", 1,
          "recipe 'g' cites 'Makefile' for 'no such symbol', which is no longer in it", NULL },
        { "an untracked file", CKS_READ("g", "README.none", "x"), 0, "1", 1,
          "recipe 'g' cites 'README.none', which is not a tracked file", NULL },
        { "a recipe id that is not kebab-case", CKS_READ("Not_Kebab", "Makefile", "all:"), 0, "1", 1,
          "recipe id 'Not_Kebab' is not kebab-case", NULL },
        { "a duplicate recipe id", CKS_READ("x", "Makefile", "all:") CKS_READ("x", "Makefile", "all:"), 0, "1", 1,
          "duplicate recipe id 'x'", NULL },
        { "an empty section title", "SECTION(\"\")\n", 0, "1", 1, "an empty SECTION title", NULL },
        { "rows below the floor", k_cks_def, 0, "99", 2, "parsed only 4 row(s)", "floor is 99." },
        { "an empty registry", "", 0, "1", 2, "parsed only 0 row(s)", NULL },
        { "a missing registry", NULL, 0, "1", 2, "is missing", NULL },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        if (cks_case(fx, &cases[i]))
            return 1;
    }
    return 0;
}

static int cks_read_ready(int rfd)
{
    char line[64];
    size_t used = 0;
    while (used + 1 < sizeof line) {
        ssize_t n = read(rfd, line + used, 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0 || line[used] == '\n')
            break;
        used++;
    }
    line[used] = '\0';
    return atoi(line) > 0 ? 0 : -1;
}

/* True once every holder of the pipe's write end, the fixture group, is gone. */
static int cks_group_gone(int rfd)
{
    for (int tries = 0; tries < 100; tries++) {
        fd_set rd;
        struct timeval tv = { 0, 100000 };
        char c;
        FD_ZERO(&rd);
        FD_SET(rfd, &rd);
        if (select(rfd + 1, &rd, NULL, NULL, &tv) > 0 && read(rfd, &c, 1) == 0)
            return 1;
    }
    return 0;
}

static int cks_signal(const struct cks_fx *fx, const char *mode, int sig, int times)
{
    int ready[2], st = 0;
    struct ck_cfg cfg = cks_cfg(fx, 0, "1", CKS_GRACE_MS);
    if (cks_put(fx, "engine/composition/cookbook.def", k_cks_def, 0600) != 0 || pipe(ready) != 0)
        return cks_fail("cannot prepare the signal case");
    pid_t gate = cks_fork(fx, &cfg, mode, ready);
    close(ready[1]);
    int up = gate > 0 ? cks_read_ready(ready[0]) : -1;
    for (int i = 0; up == 0 && i < times; i++)
        kill(gate, sig);
    if (gate < 0 || waitpid(gate, &st, 0) != gate || up != 0) {
        close(ready[0]);
        return cks_fail("the gate never reached the fixture command");
    }
    int gone = cks_group_gone(ready[0]);
    close(ready[0]);
    if (!WIFSIGNALED(st) || WTERMSIG(st) != sig)
        return cks_fail("the gate did not re-raise the signal");
    return gone ? 0 : cks_fail("the fixture command outlived the gate");
}

static int cks_signals(const struct cks_fx *fx)
{
    return cks_signal(fx, "hold", SIGINT, 1) || cks_signal(fx, "hold", SIGINT, 2)
        || cks_signal(fx, "hold", SIGTERM, 1) || cks_signal(fx, "hold", SIGHUP, 1)
        || cks_signal(fx, "stubborn", SIGTERM, 1) || cks_signal(fx, "orphan", SIGTERM, 1);
}

/* A recipe with thousands of arguments must reach the command whole; --fix
 * makes the exit status 0 only when the last argument came back as the token. */
static int cks_long_args(const struct cks_fx *fx)
{
    static char def[65536];
    size_t n = (size_t)snprintf(def, sizeof def, "RECIPE_RUN(\"long\", \"q\", Z23_DEV, \"code");
    for (int i = 0; i < 3000 && n + 16 < sizeof def; i++)
        n += (size_t)snprintf(def + n, sizeof def - n, " w%d", i);
    snprintf(def + n, sizeof def - n, "\", \"w2999\")\n");
    const struct cks_case c = { "a recipe with 3000 arguments", def, 1, "1", 0, "fixed:", NULL };
    return cks_case(fx, &c);
}

/* Output beyond LCP_CAP is drained, not left to break the child's pipe, and
 * the run is flagged truncated. */
static int cks_runner_cap(void)
{
    char *argv[] = { (char *)"sh", (char *)"-c", (char *)"head -c 70000000 /dev/zero | tr '\\0' a", NULL };
    struct lcp_spec s = { argv, NULL, NULL, LCP_OUT, CKS_GRACE_MS, NULL };
    struct lcp_buf out = { 0 };
    int code = -1, rc;
    if (lsc_install() != 0)
        return cks_fail("cannot install the signal handlers");
    rc = lcp_run(&s, &out, &code);
    lsc_unblock();
    int ok = rc == 0 && code == 0 && out.lost == LCP_LOST_TRUNCATED && out.len == LCP_CAP;
    lcp_buf_free(&out);
    return ok ? 0 : cks_fail("output over the capture limit must be flagged and the child must finish");
}

static int cks_unknown_arg(void)
{
    char *argv[] = { (char *)"--bogus" };
    int saved = dup(2), null = open("/dev/null", O_WRONLY), rc;
    if (saved < 0 || null < 0 || dup2(null, 2) < 0)
        return cks_fail("cannot silence stderr");
    rc = check_cookbook_run(1, argv);
    dup2(saved, 2);
    close(saved);
    close(null);
    return rc == 2 ? 0 : cks_fail("an unknown argument must exit 2");
}

int check_cookbook_selftest(void)
{
    struct cks_fx fx = { { 0 }, { 0 }, { 0 } };
    int rc = cks_parser() || cks_splitter() || cks_args() || cks_unknown_arg() || cks_runner_cap();
    if (rc == 0 && cks_build(&fx) != 0)
        rc = cks_fail("cannot build the fixture root");
    if (rc == 0)
        rc = cks_cases(&fx) || cks_failures(&fx) || cks_long_args(&fx) || cks_signals(&fx);
    if (fx.base[0] && access(fx.base, F_OK) == 0)
        rap_rm_rf(fx.base);
    if (rc == 0)
        puts("check_cookbook: selftest OK (parser, field split, argument safety, "
             "failure classes, long arguments, output cap, --fix, signal cleanup)");
    return rc;
}
