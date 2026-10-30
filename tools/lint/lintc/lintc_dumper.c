/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the one C resolution of the dumpstate descriptor set, the twin of
 * dumper_def_files in tools/lint/dumper_defs.sh. The set is the diagnostics
 * aggregator followed by each per-domain .def it #includes, in include order,
 * every include resolved to exactly one git-tracked owner across the
 * feature-first controller rooms. A consumer that resolves fewer than the
 * floor of per-domain files fails loudly instead of reporting a confident
 * zero (check-sandbox-wired and check-doc-counts both read it).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "lintc_text.h"

static const char k_ld_agg[] =
    "engine/controllers/include/controllers/diagnostics_dumpers.def";

/* Anti-hollowness floor, shrink-only, as DUMPER_DEF_MIN_INCLUDES. */
enum { LD_MIN_INCLUDES = 8 };

struct ld_owners { char *out; size_t cap; int count; };

int lint_dumper_include_re(regex_t *re)
{
    int err = regcomp(re,
        "^[[:space:]]*#include[[:space:]]+\"controllers/(diagnostics_dumpers_"
        "[A-Za-z0-9_]+\\.def)\"", REG_EXTENDED);
    return err ? reg_fail(re, err) : 0;
}

static int ld_owner_path(const char *path, void *ctx)
{
    struct ld_owners *owners = ctx;
    if (owners->count == 0) {
        size_t n = strlen(path);
        if (n >= owners->cap)
            return die("z23-lint: git ls-files path overflow: %s\n", path);
        memcpy(owners->out, path, n + 1);
    }
    owners->count++;
    return 0;
}

int lint_dumper_owners_command(const char *cmd, char *out, size_t cap)
{
    struct ld_owners owners = { .out = out, .cap = cap };
    out[0] = '\0';
    return each_zpath(cmd, ld_owner_path, &owners) ? -1 : owners.count;
}

/* git ls-files -z over the three controller rooms for one include: number of
 * tracked owners; when exactly one, its path is copied to out. A failed
 * producer or read returns -1, never a partial count. git's own stderr passes
 * through, as in the shell original. */
static int ld_git_owners(const char *rel, char *out, size_t cap)
{
    char cmd[4096];
    if (ovf(snprintf(cmd, sizeof cmd,
                     "git ls-files -z -- 'engine/controllers/include/controllers/%s' "
                     "'cognition/controllers/include/controllers/%s' "
                     "'contexts/*/controllers/include/controllers/%s'",
                     rel, rel, rel), sizeof cmd))
        return -1;
    return lint_dumper_owners_command(cmd, out, cap);
}

/* One aggregator line: when it is a per-domain include, resolve its owner
 * into out[*nout]. Returns 0 to continue, 1 or 2 to stop with that rc. */
static int ld_take_line(const regex_t *incl, const char *line,
                        char out[][LINT_DUMPER_PATH], int max, int *nout)
{
    regmatch_t m[2];
    if (regexec(incl, line, 2, m, 0) != 0)
        return 0;
    char rel[128];
    size_t rl = (size_t)(m[1].rm_eo - m[1].rm_so);
    if (rl >= sizeof rel || *nout >= max)
        return die("z23-lint: dumper include overflow\n", "");
    memcpy(rel, line + m[1].rm_so, rl);
    rel[rl] = '\0';
    int owners = ld_git_owners(rel, out[*nout], LINT_DUMPER_PATH);
    if (owners < 0)
        return 2;
    if (owners != 1) {
        fprintf(stderr, "dumper_defs: %s includes '%s' but the "
                "feature-first controller rooms resolve %d owners\n",
                k_ld_agg, rel, owners);
        return 1;
    }
    (*nout)++;
    return 0;
}

static int ld_floor(int domains)
{
    if (domains >= LD_MIN_INCLUDES)
        return 0;
    fprintf(stderr, "dumper_defs: resolved only %d per-domain .def "
            "include(s) from %s, expected at least %d — the include "
            "pattern moved and every consumer of this set has gone blind\n",
            domains, k_ld_agg, LD_MIN_INCLUDES);
    return 1;
}

int lint_dumper_def_files(char out[][LINT_DUMPER_PATH], int max, int *nout)
{
    *nout = 0;
    if (!lct_readable(k_ld_agg) || lintc_is_dir(k_ld_agg)) {
        fprintf(stderr, "dumper_defs: missing %s (run from repo root)\n",
                k_ld_agg);
        return 1;
    }
    memcpy(out[0], k_ld_agg, sizeof k_ld_agg);
    *nout = 1;
    regex_t incl;
    int rc = lint_dumper_include_re(&incl);
    if (rc)
        return rc;
    FILE *f = fopen(k_ld_agg, "r");
    if (!f) {
        regfree(&incl);
        return die("z23-lint: cannot open %s\n", k_ld_agg);
    }
    char *line = NULL;
    size_t cap = 0;
    while (rc == 0 && getline(&line, &cap, f) >= 0)
        rc = ld_take_line(&incl, line, out, max, nout);
    free(line);
    fclose(f);
    regfree(&incl);
    return rc ? rc : ld_floor(*nout - 1);
}
