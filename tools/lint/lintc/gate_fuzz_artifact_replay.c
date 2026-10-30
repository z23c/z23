/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check_fuzz_artifact_replay — a saved fuzz finding that
 * still reproduces fails the build. Ported from
 * tools/lint/check_fuzz_artifact_replay.sh (deleted). Entry point, arg/env
 * parsing and the shared report/note/verdict-vocabulary helpers. Structural
 * checks live in gate_fuzz_artifact_replay_struct.c, the replay half in
 * gate_fuzz_artifact_replay_replay.c, selftest in
 * gate_fuzz_artifact_replay_selftest.c.
 *
 * Modes: --ledger-only (text and git only, what make lint runs), default
 * (actually replays every artifact, what make fuzz-replay runs), --selftest
 * (plant/trip/recover). Mode WARN|FAIL via ZCL_LINT_MODE, default FAIL.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_fuzz_artifact_replay_priv.h"

const char k_far_gate[] = "check_fuzz_artifact_replay";
const char k_far_seed_root[] = "tests/harness/fuzz_seeds";
const char k_far_ledger[] = "tests/harness/fuzz_seeds/ARTIFACT_VERDICTS.txt";

/* One finding = one violation, however many lines it takes. */
int far_report(struct far_ctx *c, const char *fmt, ...)
{
    va_list ap;
    c->violations++;
    fputs("    ", c->err);
    va_start(ap, fmt);
    vfprintf(c->err, fmt, ap);
    va_end(ap);
    fputc('\n', c->err);
    return 0;
}

void far_note(struct far_ctx *c, const char *fmt, ...)
{
    va_list ap;
    fputs("      ", c->err);
    va_start(ap, fmt);
    vfprintf(c->err, fmt, ap);
    va_end(ap);
    fputc('\n', c->err);
}

/* gate_require_scanned: abort LOUD when the scan set is below a floor. */
int far_floor(struct far_ctx *c, int count, int flr, const char *hint)
{
    if (count >= flr)
        return 0;
    fprintf(c->err, "%s: FATAL — scan set is '%d' (< floor %d).\n", k_far_gate,
            count, flr);
    fputs("  The scan producer (find/glob/grep) returned too little; a\n", c->err);
    fputs("  scanned dir/file was likely renamed, moved, or deleted.\n", c->err);
    fputs("  Refusing to report 'clean' off a hollow (empty) scan.\n", c->err);
    fprintf(c->err, "  %s\n", hint);
    return 2;
}

int far_ledger_find(const struct far_ctx *c, const char *rel)
{
    for (int i = 0; i < c->n_ledger; i++)
        if (!strcmp(c->ledger[i].file, rel))
            return i;
    return -1;
}

int far_kind_has(const struct far_ctx *c, const char *k)
{
    for (int i = 0; i < c->n_kinds; i++)
        if (!strcmp(c->kinds[i], k))
            return 1;
    return 0;
}

/* case-insensitive substring, as tr+[[:upper:]] lowercasing + case match */
int far_has_ci(const char *hay, const char *needle)
{
    char buf[FAR_REASON];
    size_t n = strlen(hay);
    if (n >= sizeof buf)
        n = sizeof buf - 1;
    for (size_t i = 0; i < n; i++)
        buf[i] = (char)tolower((unsigned char)hay[i]);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

/* Port of tools/scripts/fuzz_verdict_lib.sh. */
int far_reason_named_fix(const char *r)
{
    return far_has_ci(r, "fixed by") || far_has_ci(r, "root cause:");
}

int far_reason_pattern_init(const char *r)
{
    return far_has_ci(r, "pattern-init") || far_has_ci(r, "pattern_init") ||
           far_has_ci(r, "auto-var-init=pattern");
}

int far_kind_needs_pi(const char *kind)
{
    return !strcmp(kind, "crash") || !strcmp(kind, "leak");
}

int far_regression_sufficient(const char *kind, const char *r)
{
    if (!far_kind_needs_pi(kind))
        return 1;
    return far_reason_named_fix(r) || far_reason_pattern_init(r);
}

void far_today_utc(char *dst, size_t cap)
{
    time_t t = time(NULL); // platform-ok: z23-lint links no platform library; UTC date for the verdict-age check only
    struct tm tm;
    if (!gmtime_r(&t, &tm)) {
        dst[0] = '\0';
        return;
    }
    if (!strftime(dst, cap, "%Y-%m-%d", &tm))
        dst[0] = '\0';
}

static int far_env_int(const char *v, int dflt)
{
    char *end;
    long n;
    if (!v || !*v)
        return dflt;
    n = strtol(v, &end, 10);
    while (*end == ' ' || *end == '\t')
        end++;
    if (end == v || *end)
        return dflt;
    return (int)n;
}

static int far_ctx_env(struct far_ctx *c)
{
    c->mode = env_or("ZCL_LINT_MODE", "FAIL");
    c->replay_timeout = far_env_int(env_or("ZCL_FUZZ_REPLAY_TIMEOUT", ""), 5);
    c->confirm_timeout = far_env_int(env_or("ZCL_FUZZ_REPLAY_CONFIRM_TIMEOUT", ""), 15);
    c->jobs = far_env_int(env_or("ZCL_FUZZ_REPLAY_JOBS", ""), 6);
    if (ovf(snprintf(c->bin_dir, sizeof c->bin_dir, "%s",
                     env_or("ZCL_LINT_BIN_DIR", "build/bin")), sizeof c->bin_dir))
        return 2;
    if (ovf(snprintf(c->pi_bin_dir, sizeof c->pi_bin_dir, "%s",
                     env_or("ZCL_LINT_PATTERNINIT_BIN_DIR",
                            "build/fuzz-patterninit/bin")),
            sizeof c->pi_bin_dir))
        return 2;
    c->ledger_only = far_env_int(env_or("ZCL_FUZZ_REPLAY_LEDGER_ONLY", ""), 0) != 0;
    c->selftest = far_env_int(env_or("ZCL_FUZZ_REPLAY_SELFTEST", ""), 0) != 0;
    return 0;
}

/* Returns 0 continue, 1 exit 0 now (--help), 2 error. */
static int far_ctx_args(struct far_ctx *c, int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--ledger-only")) {
            c->ledger_only = 1;
        } else if (!strcmp(a, "--selftest")) {
            c->selftest = 1;
        } else if (!strncmp(a, "--corpus=", 9)) {
            if (ovf(snprintf(c->only_corpora, sizeof c->only_corpora, "%s",
                             a + 9), sizeof c->only_corpora))
                return 2;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            fprintf(c->out, "usage: check_fuzz_artifact_replay.sh "
                            "[--ledger-only] [--selftest] [--corpus=a,b]\n");
            return 1;
        } else {
            fprintf(c->err, "%s: unknown arg '%s'\n", k_far_gate, a);
            return 2;
        }
    }
    return 0;
}

int far_check(struct far_ctx *c)
{
    if (far_load_kinds(c))
        return 2;
    if (far_load_ledger(c))
        return 2;
    if (far_enumerate(c))
        return 2;
    fprintf(c->out, "[%s] %d saved artifact(s); %d ledger line(s); "
                    "%d fuzz target(s)\n", k_far_gate, c->n_artifacts,
            c->n_ledger, c->n_kinds);
    if (far_structural(c))
        return 2;
    if (c->ledger_only) {
        fprintf(c->out, "[%s] ledger-only: structure checked, no artifact "
                        "replayed\n", k_far_gate);
        fprintf(c->out, "[%s] the replay itself is 'make fuzz-replay' (in "
                        "make ci) — this half\n", k_far_gate);
        fprintf(c->out, "[%s] only proves every finding has a live binary "
                        "and a written verdict.\n", k_far_gate);
        fprintf(c->out, "[%s] %d violation(s) found (mode: %s)\n", k_far_gate,
                c->violations, c->mode);
        if (c->violations > 0 && !strcmp(c->mode, "FAIL"))
            return 1;
        return 0;
    }
    return far_replay_phase(c);
}

int far_main(int argc, char **argv, FILE *out, FILE *err)
{
    struct far_ctx c;
    int rc;
    memset(&c, 0, sizeof c);
    c.out = out;
    c.err = err;
    if (!getcwd(c.root, sizeof c.root)) {
        fprintf(err, "%s: cannot determine working directory\n", k_far_gate);
        return 2;
    }
    rc = far_ctx_env(&c);
    if (!rc)
        rc = far_ctx_args(&c, argc, argv);
    if (rc)
        return rc == 1 ? 0 : 2;
    if (c.selftest)
        return check_fuzz_artifact_replay_selftest();
    return far_check(&c);
}

int check_fuzz_artifact_replay_run(int argc, char **argv)
{
    return far_main(argc, argv, stdout, stderr);
}
