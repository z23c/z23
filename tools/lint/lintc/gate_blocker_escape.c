/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — blocker escape-action totality
 * (check-blocker-escape-registered). Tracked files via lint_git_index_foreach;
 * filesystem walk when .git is absent.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

enum { BER_MAX = 8192, BER_NAME = 96, BER_LINE = 8192, BER_HIT = 256 };

struct ber_files { char p[BER_MAX][RS_PATH]; int n; };
struct ber_names { char n[BER_MAX][BER_NAME]; int c; };

static const char *const k_ber_roots[] = {
    "core", "engine", "contexts", "cognition", "platform"
};

static int ber_add(struct ber_files *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= BER_MAX || n >= RS_PATH)
        return die("z23-lint: blocker-escape overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int ber_under(const char *path)
{
    int i, n = (int)(sizeof k_ber_roots / sizeof k_ber_roots[0]);
    for (i = 0; i < n; i++) {
        size_t k = strlen(k_ber_roots[i]);
        if (strncmp(path, k_ber_roots[i], k) == 0
            && (path[k] == '/' || path[k] == '\0'))
            return 1;
    }
    return 0;
}

static int ber_want(const char *path)
{
    size_t n = strlen(path);
    if (!ber_under(path) || lint_path_is_excluded(path))
        return 0;
    if (strstr(path, "/test/") || strncmp(path, "tests/", 6) == 0)
        return 0;
    if (strcmp(path, "platform/modules/util/src/blocker.c") == 0)
        return 0;
    if (strcmp(path, "platform/modules/util/include/util/blocker.h") == 0)
        return 0;
    if (n >= 2 && path[n - 2] == '.' && (path[n - 1] == 'c' || path[n - 1] == 'h'))
        return 1;
    return n >= 4 && memcmp(path + n - 4, ".def", 4) == 0;
}

static int ber_on_idx(const char *path, int stage, void *ctx)
{
    (void)stage;
    return ber_want(path) ? ber_add(ctx, path) : 0;
}

static int ber_on_walk(const char *path, void *ctx)
{
    return ber_want(path) ? ber_add(ctx, path) : 0;
}

static int ber_walk_roots(struct ber_files *s)
{
    int rc = 0, i, nr = (int)(sizeof k_ber_roots / sizeof k_ber_roots[0]);
    for (i = 0; rc == 0 && i < nr; i++) {
        rc = walk_src(k_ber_roots[i], 1, ber_on_walk, s);
        if (rc == 0)
            rc = walk_src(k_ber_roots[i], 2, ber_on_walk, s);
    }
    return rc;
}

static int ber_collect(struct ber_files *s)
{
    struct stat st;
    char bad[8] = {0};
    int rc;
    s->n = 0;
    if (stat(".git", &st) == 0) {
        rc = lint_git_index_foreach(ber_on_idx, s, bad);
        if (rc)
            fprintf(stderr, "check_blocker_escape_registered: UNPROVEN — git "
                            "index%s%s\n", bad[0] ? " extension " : "", bad);
        return rc;
    }
    return ber_walk_roots(s);
}

static int ber_nadd(struct ber_names *s, const char *name)
{
    size_t n;
    int i;
    if (!name[0])
        return 0;
    for (i = 0; i < s->c; i++)
        if (strcmp(s->n[i], name) == 0)
            return 0;
    n = strlen(name);
    if (s->c >= BER_MAX || n >= BER_NAME)
        return die("z23-lint: blocker-escape overflow\n", "");
    memcpy(s->n[s->c++], name, n + 1);
    return 0;
}

static int ber_nhas(const struct ber_names *s, const char *name)
{
    int i;
    for (i = 0; i < s->c; i++)
        if (strcmp(s->n[i], name) == 0)
            return 1;
    return 0;
}

static int ber_qstr(const char *buf, char *out, size_t cap)
{
    const char *p = strchr(buf, '"');
    size_t n = 0;
    if (!p)
        return 0;
    p++;
    while (*p && *p != '"' && n + 1 < cap) {
        if (*p == '\\' && p[1]) {
            out[n++] = p[1];
            p += 2;
        } else {
            out[n++] = *p++;
        }
    }
    if (*p != '"')
        return 0;
    out[n] = '\0';
    return 1;
}

static int ber_unreadable(const char *path)
{
    fprintf(stderr, "check_blocker_escape_registered: UNPROVEN — cannot read "
                    "%s\n", path);
    return 2;
}

static int ber_stmt(FILE *f, char *buf, size_t cap, int *lineno, const char *first)
{
    size_t n;
    if (ovf(snprintf(buf, cap, "%s", first), cap))
        return 2;
    n = strlen(buf);
    while (!strchr(buf, ';')) {
        char line[BER_LINE];
        if (!fgets(line, (int)sizeof line, f))
            break;
        (*lineno)++;
        if (n + strlen(line) + 1 >= cap)
            return die("z23-lint: blocker-escape overflow\n", "");
        memcpy(buf + n, line, strlen(line) + 1);
        n += strlen(line);
    }
    return 0;
}

static int ber_is_ident(unsigned char c)
{
    return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || (c >= '0' && c <= '9');
}

static int ber_on_register(FILE *f, int *lineno, const char *first,
                           struct ber_names *reg)
{
    char stmt[BER_LINE * 2], q[BER_NAME];
    int rc = ber_stmt(f, stmt, sizeof stmt, lineno, first);
    if (rc)
        return rc;
    if (ber_qstr(stmt, q, sizeof q))
        return ber_nadd(reg, q);
    return 0;
}

static int ber_on_condition(const char *line, struct ber_names *cond)
{
    const char *p = strstr(line, "ZCL_CONDITION(");
    char id[BER_NAME];
    int n = 0;
    if (!p)
        return 0;
    p += 14;
    while (ber_is_ident((unsigned char)*p)) {
        if (n + 1 < BER_NAME)
            id[n++] = *p;
        p++;
    }
    id[n] = '\0';
    if (*p == ')')
        return ber_nadd(cond, id);
    return 0;
}

static int ber_on_cond_name(const char *line, struct ber_names *cond)
{
    char q[BER_NAME];
    if (!strstr(line, "_COND_NAME") || !strstr(line, "#define"))
        return 0;
    if (ber_qstr(line, q, sizeof q))
        return ber_nadd(cond, q);
    return 0;
}

static int ber_record_lit(const char *path, int start, const char *q,
                          const struct ber_names *reg,
                          const struct ber_names *cond,
                          struct ber_names *lits, char viol[][RS_PATH], int *nv)
{
    int rc = ber_nadd(lits, q);
    if (rc || ber_nhas(reg, q) || ber_nhas(cond, q) || strpbrk(q, " \t"))
        return rc;
    if (*nv < BER_HIT
        && !ovf(snprintf(viol[*nv], RS_PATH, "%s:%d: \"%s\"", path, start, q),
                RS_PATH))
        (*nv)++;
    return 0;
}

static int ber_on_escape_lit(FILE *f, const char *path, const char *first,
                             int *lineno, int start,
                             const struct ber_names *reg,
                             const struct ber_names *cond,
                             struct ber_names *lits, char viol[][RS_PATH],
                             int *nv)
{
    char stmt[BER_LINE * 2], q[BER_NAME];
    int rc;
    if (!strstr(first, "snprintf(") || !strstr(first, "escape_action"))
        return 0;
    rc = ber_stmt(f, stmt, sizeof stmt, lineno, first);
    if (rc || !ber_qstr(stmt, q, sizeof q) || !q[0] || strchr(q, '%'))
        return rc;
    return ber_record_lit(path, start, q, reg, cond, lits, viol, nv);
}

static int ber_scan_line(FILE *f, const char *path, const char *line,
                         int *lineno, struct ber_names *reg,
                         struct ber_names *cond, struct ber_names *lits,
                         char viol[][RS_PATH], int *nv)
{
    int start = *lineno, rc;
    if (strstr(line, "blocker_register_escape("))
        return ber_on_register(f, lineno, line, reg);
    rc = ber_on_condition(line, cond);
    if (rc)
        return rc;
    rc = ber_on_cond_name(line, cond);
    if (rc)
        return rc;
    return ber_on_escape_lit(f, path, line, lineno, start, reg, cond, lits,
                             viol, nv);
}

static int ber_scan_file(const char *path, struct ber_names *reg,
                         struct ber_names *cond, struct ber_names *lits,
                         char viol[][RS_PATH], int *nv)
{
    FILE *f = fopen(path, "r");
    char line[BER_LINE];
    int lineno = 0, rc = 0;
    if (!f)
        return ber_unreadable(path);
    while (rc == 0 && fgets(line, (int)sizeof line, f)) {
        lineno++;
        rc = ber_scan_line(f, path, line, &lineno, reg, cond, lits, viol, nv);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static int ber_load_list(const char *text, struct ber_files *s)
{
    char buf[8192], *p;
    s->n = 0;
    if (ovf(snprintf(buf, sizeof buf, "%s", text), sizeof buf))
        return 2;
    p = buf;
    while (*p) {
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        if (*p && ber_add(s, p))
            return 2;
        if (!nl)
            break;
        p = nl + 1;
    }
    return 0;
}

static int ber_report(int nv, char viol[][RS_PATH], int nreg, int ncond)
{
    int i;
    if (!nv) {
        printf("check_blocker_escape_registered: clean — %d registered "
               "escape(s), %d condition name(s), all escape_action literals "
               "resolve\n", nreg, ncond);
        return 0;
    }
    printf("\ncheck_blocker_escape_registered: %d escape_action literal(s) "
           "matching no registered escape function and no registered "
           "condition name\n\n", nv);
    for (i = 0; i < nv; i++)
        printf("  %s\n", viol[i]);
    fputs("\nFix options:\n"
          "  1. Register the escape: blocker_register_escape(\"<same string>\", "
          "<fn>)\n"
          "     at the owning subsystem's init (see\n"
          "     engine/services/src/chain_activation_service.c for the "
          "pattern).\n"
          "  2. If the string names the condition-engine healer that actually\n"
          "     drives the fix (e.g. \"reducer_frontier_reconcile_light\"), "
          "add a\n"
          "     ZCL_CONDITION(<name>) entry to\n"
          "     engine/conditions/include/conditions/condition_registry.def "
          "(or a\n"
          "     matching <X>_COND_NAME #define) so the gate recognizes it.\n"
          "  3. If it's operator guidance rather than a dispatch key, phrase "
          "it as\n"
          "     a sentence (e.g. \"re-run script_validate for selected block\n"
          "     hash\") — any literal containing whitespace is exempt as a\n"
          "     human-readable remedy description.\n"
          "  4. If the blocker never sets escape_deadline_secs (no auto-escape "
          "is\n"
          "     intended — it is dispatched some other way, e.g. its own\n"
          "     condition cadence, and there's no useful remedy text to add),\n"
          "     empty the string instead: it then falls under the\n"
          "     blocker_stall_meta_detector.c empty-escape backstop rather "
          "than\n"
          "     silently dead-ending an unregistered name.\n", stdout);
    return 1;
}

static int ber_scan_set(const struct ber_files *assign,
                        const struct ber_files *regf, int *nreg, int *ncond,
                        char viol[][RS_PATH], int *nv)
{
    static struct ber_names reg, cond, lits;
    int rc = 0, i;
    reg.c = cond.c = lits.c = 0;
    *nv = 0;
    for (i = 0; rc == 0 && i < regf->n; i++)
        rc = ber_scan_file(regf->p[i], &reg, &cond, &lits, viol, nv);
    *nv = 0;
    lits.c = 0;
    for (i = 0; rc == 0 && i < assign->n; i++)
        rc = ber_scan_file(assign->p[i], &reg, &cond, &lits, viol, nv);
    *nreg = reg.c;
    *ncond = cond.c;
    return rc;
}

static int ber_run(void)
{
    static struct ber_files assign, registry;
    static char viol[BER_HIT][RS_PATH];
    const char *ov = env_or("ZCL_BLOCKER_ESCAPE_SCAN_FILES", "");
    int nv = 0, nreg = 0, ncond = 0, rc;
    rc = ber_collect(&registry);
    if (rc)
        return rc;
    if (ov[0])
        rc = ber_load_list(ov, &assign);
    else
        assign = registry;
    if (rc)
        return rc;
    if (assign.n == 0) {
        fputs("check_blocker_escape_registered: no files to scan\n", stderr);
        return 1;
    }
    rc = ber_scan_set(&assign, &registry, &nreg, &ncond, viol, &nv);
    if (rc)
        return rc;
    return ber_report(nv, viol, nreg, ncond);
}

static int ber_quiet(void)
{
    int nfd, oldo, olde, rc;
    fflush(stdout);
    fflush(stderr);
    nfd = open("/dev/null", O_WRONLY);
    if (nfd < 0)
        return 2;
    oldo = dup(1);
    olde = dup(2);
    dup2(nfd, 1);
    dup2(nfd, 2);
    close(nfd);
    rc = ber_run();
    fflush(stdout);
    fflush(stderr);
    dup2(oldo, 1);
    dup2(olde, 2);
    close(oldo);
    close(olde);
    return rc;
}

int check_blocker_escape_registered_selftest(void)
{
    char tmp[] = "/tmp/zcl-ber-XXXXXX";
    char plant[4096];
    int rc, bad = 0;
    if (!mkdtemp(tmp))
        return die("z23-lint: mkdtemp failed\n", "");
    if (ovf(snprintf(plant, sizeof plant, "%s/plant.c", tmp), sizeof plant)
        || csr_write(plant,
                     "void f(void) {\n"
                     "    snprintf(b.escape_action, 64, \"not_a_registered_escape_xyz\");\n"
                     "}\n")) {
        rap_rm_rf(tmp);
        return 2;
    }
    if (setenv("ZCL_BLOCKER_ESCAPE_SCAN_FILES", plant, 1)) {
        rap_rm_rf(tmp);
        return 2;
    }
    rc = ber_quiet();
    if (rc != 1) {
        fprintf(stderr, "check_blocker_escape_registered selftest: FAIL — "
                        "planted unregistered literal rc=%d want=1\n", rc);
        bad = 1;
    }
    if (csr_write(plant,
                  "void f(void) {\n"
                  "    snprintf(b.escape_action, 64, "
                  "\"re-run script_validate for selected block hash\");\n"
                  "}\n")) {
        unsetenv("ZCL_BLOCKER_ESCAPE_SCAN_FILES");
        rap_rm_rf(tmp);
        return 2;
    }
    rc = ber_quiet();
    if (rc != 0) {
        fprintf(stderr, "check_blocker_escape_registered selftest: FAIL — "
                        "whitespace remedy rc=%d want=0\n", rc);
        bad = 1;
    }
    unsetenv("ZCL_BLOCKER_ESCAPE_SCAN_FILES");
    rap_rm_rf(tmp);
    rc = ber_quiet();
    if (rc != 0) {
        fprintf(stderr, "check_blocker_escape_registered selftest: FAIL — "
                        "real tree rc=%d want=0\n", rc);
        bad = 1;
    }
    if (bad)
        return 1;
    fputs("check_blocker_escape_registered selftest: PASS — planted "
          "unregistered identifier is named, a whitespace remedy is clean, "
          "the real tree resolves\n", stdout);
    return 0;
}

int check_blocker_escape_registered_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return ber_run();
}
