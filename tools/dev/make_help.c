/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Curated make help. Names no durations; --self-test proves every
 *          target it names still heads a Makefile rule. */

#include "make_help.h"

#include <stdio.h>
#include <string.h>

#define MH_DASH "\xe2\x80\x94"
#define MH_LINE 16384

struct mh_entry {
    const char *group;
    const char *target;
    const char *desc;
};

static const struct mh_entry k_entries[] = {
    {"first", "doctor-env",
     "C23 compiler, git, vendor/tor, stack: what this machine is missing"},
    {"first", "doctor",
     "what this host is still missing, with the exact install line"},
    {"first", "setup",
     "arm the git hooks and generate compile_commands.json (idempotent)"},
    {"first", "z23",
     "build the public node (bare make does the same; vendor setup is automatic)"},
    {"loop", "all",
     "build the node plus the monolithic test harness and auxiliary tools"},
    {"loop", "new-app",
     "scaffold a GUI app from zhello: make new-app NAME=myapp, then make myapp"},
    {"loop", "game",
     "link the Sky Combat binary at build/bin/z23-skycombat (opt-in; needs X11/GL)"},
    {"loop", "game-check",
     "compile apps/skycombat and vendor/raylib to objects only, no window needed"},
    {"loop", "build-only",
     "compile every translation unit, no link " MH_DASH " genuinely parallel under -j"},
    {"loop", "syntax-check",
     "whole-tree no-link syntax pass in one compiler invocation"},
    {"loop", "dev-bin",
     "non-LTO local node binary at build/bin/zclassic23-dev"},
    {"loop", "t-fast", "one test group: make t-fast ONLY=<group>"},
    {"loop", "lint-fast", "the highest-signal subset of the lint gates"},
    {"loop", "agent-verify",
     "one trip for an edit: make -j28 agent-verify ONLY=<group,group>"},
    {"gate", "lint-ready",
     "hooks, generated docs, untracked-file check before lint; never commits"},
    {"gate", "lint",
     "the full lint umbrella " MH_DASH " every gate, run in parallel"},
    {"gate", "test-parallel", "every test group, each in its own process"},
    {"gate", "pr-check",
     "lint plus a whole-tree syntax pass; needs nothing built first"},
    {"gate", "ci",
     "the umbrella a push must survive: lint, then the isolated test runner"},
    {"gate", "fuzz-ci", "build the fuzz harnesses and smoke-run each one"},
    {"agent", "timings",
     "where wall time actually went ON THIS HOST (reads measured artifacts)"},
    {"agent", "first-build-timing",
     "time a fresh clone through the full suite and record it for make timings"},
    {"agent", "build-bench",
     "measure the build and test loop scenario by scenario (ARGS=--quick for the subset)"},
    {"agent", "compdb", "regenerate compile_commands.json for clangd / LSP"},
    {"agent", "doctor-build",
     "which build accelerators (ccache, mold, clang) this host has"},
};

#define MH_N (sizeof k_entries / sizeof k_entries[0])

static const char *k_groups[] = {"first", "loop", "gate", "agent"};

static int mh_fail(const char *msg)
{
    fprintf(stderr, "make_help selftest: FAIL " MH_DASH " %s\n", msg);
    return 1;
}

static int mh_word(char c, int wide)
{
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '/' || c == '-')
        return 1;
    if (wide && (c == '$' || c == '(' || c == ')'))
        return 1;
    return 0;
}

static const char *mh_skip_name(const char *p, int wide)
{
    if (p == NULL || !mh_word(*p, wide))
        return NULL;
    while (mh_word(*p, wide))
        p++;
    return p;
}

static void mh_note(const char *b, const char *e, const char *want, int *found)
{
    size_t n;
    if (want == NULL || found == NULL || *found)
        return;
    n = (size_t)(e - b);
    if (strlen(want) == n && memcmp(b, want, n) == 0)
        *found = 1;
}

static const char *mh_more_names(const char *p, const char *want, int *found)
{
    for (;;) {
        const char *s = p;
        const char *end;
        while (*s == ' ' || *s == '\t')
            s++;
        if (s == p || !mh_word(*s, 1))
            return s;
        end = mh_skip_name(s, 1);
        if (end == NULL)
            return s;
        mh_note(s, end, want, found);
        p = end;
    }
}

static int mh_rule(const char *line, const char *want, int *found)
{
    const char *end;
    const char *p;
    if (found != NULL)
        *found = 0;
    if (line[0] == '\0' || line[0] == ' ' || line[0] == '\t')
        return 0;
    end = mh_skip_name(line, 0);
    if (end == NULL)
        return 0;
    mh_note(line, end, want, found);
    p = mh_more_names(end, want, found);
    if (p == NULL || *p != ':')
        return 0;
    if (p[1] == '=')
        return 0;
    return 1;
}

static int mh_line(FILE *fp, char *buf, size_t cap)
{
    size_t n;
    int ch;
    if (fgets(buf, (int)cap, fp) == NULL)
        return 0;
    n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n') {
        buf[n - 1] = '\0';
        if (n > 1 && buf[n - 2] == '\r')
            buf[n - 2] = '\0';
        return 1;
    }
    while ((ch = fgetc(fp)) != EOF && ch != '\n')
        ;
    return 1;
}

static int mh_scan_file(const char *path, const char *want, int *found)
{
    FILE *fp = fopen(path, "r");
    char buf[MH_LINE];
    if (fp == NULL)
        return 0;
    while (mh_line(fp, buf, sizeof buf)) {
        int one = 0;
        if (mh_rule(buf, want, &one) && one)
            *found = 1;
    }
    fclose(fp);
    return 0;
}

/* Literal `include path` lines only. Variable includes are not files we can
 * name, and the printed rule count stays the top Makefile alone. */
static int mh_include_rel(const char *line, char *out, size_t cap)
{
    const char *p = line;
    size_t n = 0;
    if (strncmp(p, "include ", 8) == 0)
        p += 8;
    else if (strncmp(p, "-include ", 9) == 0)
        p += 9;
    else
        return 0;
    while (*p == ' ' || *p == '\t')
        p++;
    if (*p == '\0' || *p == '$')
        return 0;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '#') {
        if (*p == '$' || n + 1 >= cap)
            return 0;
        out[n++] = *p++;
    }
    if (n == 0)
        return 0;
    out[n] = '\0';
    return 1;
}

static int mh_known(const char *repo, const char *makefile, const char *want,
                    int *found)
{
    FILE *fp;
    char buf[MH_LINE];
    char rel[256];
    char inc[32][512];
    int ninc = 0;
    int i;
    *found = 0;
    fp = fopen(makefile, "r");
    if (fp == NULL)
        return 0;
    while (mh_line(fp, buf, sizeof buf)) {
        int one = 0;
        if (mh_rule(buf, want, &one) && one)
            *found = 1;
        if (ninc < 32 && mh_include_rel(buf, rel, sizeof rel)) {
            int nw = snprintf(inc[ninc], sizeof inc[ninc], "%s/%s", repo, rel);
            if (nw > 0 && (size_t)nw < sizeof inc[ninc])
                ninc++;
        }
    }
    fclose(fp);
    for (i = 0; i < ninc && !*found; i++)
        mh_scan_file(inc[i], want, found);
    return 0;
}

static int mh_count(const char *path, int *out)
{
    FILE *fp = fopen(path, "r");
    char buf[MH_LINE];
    int n = 0;
    if (fp == NULL)
        return -1;
    while (mh_line(fp, buf, sizeof buf)) {
        if (mh_rule(buf, NULL, NULL))
            n++;
    }
    fclose(fp);
    *out = n;
    return 0;
}

static int mh_boundary(char c)
{
    if (c == '\0')
        return 1;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '_')
        return 0;
    return 1;
}

static int mh_prefix(const char *p, const char *lit)
{
    size_t n = strlen(lit);
    size_t i;
    for (i = 0; i < n; i++) {
        char c = p[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (c != lit[i])
            return 0;
    }
    return mh_boundary(p[n]);
}

static int mh_unit_at(const char *p)
{
    static const char *units[] = {
        "seconds", "second", "secs", "sec", "minutes", "minute", "mins", "min",
        "hours", "hour", "mss", "ms", "ss", "s", NULL};
    size_t i;
    for (i = 0; units[i] != NULL; i++) {
        if (mh_prefix(p, units[i]))
            return 1;
    }
    return 0;
}

static int mh_duration(const char *s)
{
    const char *p = s;
    while (*p != '\0') {
        if (*p >= '0' && *p <= '9') {
            while (*p >= '0' && *p <= '9')
                p++;
            while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
                p++;
            if (mh_unit_at(p))
                return 1;
            continue;
        }
        p++;
    }
    return 0;
}

static int mh_table_duration(void)
{
    char line[1024];
    size_t i;
    for (i = 0; i < MH_N; i++) {
        int nw = snprintf(line, sizeof line, "%s\t%s\t%s", k_entries[i].group,
                          k_entries[i].target, k_entries[i].desc);
        if (nw < 0)
            return 1;
        if (mh_duration(line))
            return 1;
    }
    return 0;
}

static int mh_makefile(const char *repo, char *path, size_t cap)
{
    int nw = snprintf(path, cap, "%s/Makefile", repo);
    if (nw < 0)
        return -1;
    if ((size_t)nw >= cap)
        return -1;
    return 0;
}

static int mh_missing(const char names[][64], size_t n)
{
    size_t i;
    fprintf(stderr,
            "make_help selftest: FAIL " MH_DASH
            " help names targets the Makefile does not define:\n");
    for (i = 0; i < n; i++)
        fprintf(stderr, "    %s\n", names[i]);
    return 1;
}

static int mh_self_test(const char *repo)
{
    char path[4096];
    char missing[MH_N][64];
    size_t nmiss = 0;
    size_t i;
    int found = 0;
    if (mh_makefile(repo, path, sizeof path) != 0)
        return mh_fail("repo path is too long");
    for (i = 0; i < MH_N; i++) {
        found = 0;
        mh_known(repo, path, k_entries[i].target, &found);
        if (!found) {
            snprintf(missing[nmiss], sizeof missing[nmiss], "%s",
                     k_entries[i].target);
            nmiss++;
        }
    }
    if (nmiss > 0)
        return mh_missing(missing, nmiss);
    found = 0;
    mh_known(repo, path, "zcl-target-that-cannot-exist", &found);
    if (found)
        return mh_fail("detector accepts a nonexistent target");
    if (mh_table_duration())
        return mh_fail("a duration leaked into the help text; point at 'make timings'");
    printf("make_help selftest: PASS " MH_DASH " %zu documented targets all exist\n",
           MH_N);
    return 0;
}

static const char *mh_title(const char *group)
{
    if (strcmp(group, "first") == 0)
        return "First run, in this order";
    if (strcmp(group, "loop") == 0)
        return "Inner loop " MH_DASH " while you are editing";
    if (strcmp(group, "gate") == 0)
        return "Gates " MH_DASH " what a change must survive";
    if (strcmp(group, "agent") == 0)
        return "Agent and operator surface";
    return "";
}

static void mh_print_group(const char *group)
{
    size_t i;
    printf("%s\n", mh_title(group));
    for (i = 0; i < MH_N; i++) {
        if (strcmp(k_entries[i].group, group) != 0)
            continue;
        printf("  make %-16s %s\n", k_entries[i].target, k_entries[i].desc);
    }
    printf("\n");
}

static int mh_print(const char *repo)
{
    char path[4096];
    char total[32];
    int n = 0;
    size_t g;
    total[0] = '\0';
    if (mh_makefile(repo, path, sizeof path) == 0 && mh_count(path, &n) == 0)
        snprintf(total, sizeof total, "%d", n);
    printf("zclassic23 " MH_DASH
           " one C23 binary: full node, wallet, explorer, onion service.\n\n");
    for (g = 0; g < sizeof k_groups / sizeof k_groups[0]; g++)
        mh_print_group(k_groups[g]);
    printf("How long does any of this take? Ask the host, not this page:\n"
           "  make timings          reads the measured artifacts, and says NOT MEASURED\n"
           "                        rather than quoting a number from another machine.\n"
           "\n"
           "This page is a curated subset. The Makefile defines %s rule targets;\n"
           "list them all with:\n"
           "  grep -E '^[A-Za-z0-9_.-]+:' Makefile\n"
           "\n"
           "Deeper reading:\n"
           "  AGENTS.md                          model-neutral mission and authority rules\n"
           "  CLAUDE.md                          thin Claude compatibility adapter\n"
           "  docs/node/HOW_THE_NODE_WORKS.md         the node as a state machine, in one page\n"
           "  docs/DEFENSIVE_CODING.md           the coding laws and every lint gate\n"
           "  .claude/skills/z23-dev/     the developer operating manual\n",
           total);
    return 0;
}

int zcl_make_help(const char *repo, int argc, char **argv)
{
    if (repo == NULL || repo[0] == '\0') {
        fprintf(stderr, "make_help: repo is required\n");
        return 2;
    }
    if (argc > 0 && argv != NULL && argv[0] != NULL &&
        strcmp(argv[0], "--self-test") == 0)
        return mh_self_test(repo);
    return mh_print(repo);
}
