/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-sandbox-wired
 * Boot-wiring lint gates of the C23 lint runtime: gates that prove a
 * subsystem is actually entered, noted, and observable after boot, not
 * merely compiled in. Default landing spot for a FUTURE gate port of the
 * same shape (fixed boot/wiring files asserted by anchored patterns);
 * anything else follows the landing policy in the older family headers.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

/* check-sandbox-wired — port of tools/lint/check_sandbox_wired.sh (now a
 * shim). The os_sandbox steady-state profile is only a defense if boot
 * actually ENTERS it: boot.c must register a SYSINIT boundary record named
 * "sandbox" on the SERVICES_RUNNING boundary, call os_sandbox_enter(), and
 * note the request via os_sandbox_note_requested(); os_sandbox_linux.c must
 * install the seccomp filter with SECCOMP_FILTER_FLAG_TSYNC through the
 * seccomp(2) syscall (all-thread coverage, not just the boot thread); the
 * witness must never live-probe Landlock (a probe from a confined process is
 * SECCOMP_RET_KILL_PROCESS); and a "confinement" dumpstate row must exist in
 * the resolved descriptor set (aggregator + per-domain includes, resolved
 * like tools/lint/dumper_defs.sh: includes parsed from the aggregator, each
 * resolved to exactly one git-tracked owner via git ls-files over the
 * feature-first controller rooms, floor 8 so a moved include pattern fails
 * loudly). All FAIL lines go to stderr and accumulate; a missing boot.c or
 * os_sandbox_linux.c is FATAL rc 2.
 * Parity notes: grep -Eq is a per-line ERE predicate; the shell's \b word
 * boundary has no POSIX regex form (glibc regcomp rejects [[:<:]]), so the
 * three \bIDENT( predicates are matched by sw_ident_call() instead; git's
 * stderr passes through both implementations untouched; the confinement-row
 * FAIL reports the resolved domain count, so the dumper set must resolve
 * fully before that message can print. */

#define SW_MAX_DEFS 128
#define SW_PATH 512

static const char k_sw_boot[] = "engine/composition/src/boot.c";
static const char k_sw_linux[] =
    "platform/modules/platform/src/os_sandbox_linux.c";
static const char k_sw_witness[] =
    "platform/modules/platform/src/os_sandbox_witness.c";
static const char k_sw_agg[] =
    "engine/controllers/include/controllers/diagnostics_dumpers.def";

struct sw_re {
    regex_t name, stage, nrsec, conf, incl;
};

static void sw_free(struct sw_re *r, int n)
{
    regex_t *re[] = { &r->name, &r->stage, &r->nrsec, &r->conf, &r->incl };
    for (int i = 0; i < n && i < 5; i++)
        regfree(re[i]);
}

static int sw_compile(struct sw_re *r)
{
    static const char *const pat[] = {
        "\\.name[[:space:]]*=[[:space:]]*\"sand" "box\"",
        "\\.stage[[:space:]]*=[[:space:]]*BOOT_STAGE_" "SERVICES_RUNNING"
            ".*\"sand" "box\"|\"sand" "box\".*BOOT_STAGE_" "SERVICES_RUNNING",
        "syscall[[:space:]]*\\([[:space:]]*__NR_" "seccomp",
        "\"confine" "ment\"[[:space:]]*,[[:space:]]*confine"
            "ment_dump_state_json",
        "^[[:space:]]*#include[[:space:]]+\"controllers/(diagnostics_dumpers_"
            "[A-Za-z0-9_]+\\.def)\"",
    };
    regex_t *re[] = { &r->name, &r->stage, &r->nrsec, &r->conf, &r->incl };
    for (int i = 0; i < 5; i++) {
        int err = regcomp(re[i], pat[i], REG_EXTENDED);
        if (err) {
            sw_free(r, i);
            return reg_fail(re[i], err);
        }
    }
    return 0;
}

static int sw_is_reg(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* grep -Eq: does any line of the file match? */
static int sw_file_has(const char *path, regex_t *re)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (getline(&line, &cap, f) >= 0) {
        if (regexec(re, line, 0, NULL, 0) == 0) {
            found = 1;
            break;
        }
    }
    free(line);
    fclose(f);
    return found;
}

/* grep -Eq with a metachar-free pattern (SECCOMP_FILTER_FLAG_TSYNC). */
static int sw_file_has_lit(const char *path, const char *lit)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (getline(&line, &cap, f) >= 0) {
        if (strstr(line, lit) != NULL) {
            found = 1;
            break;
        }
    }
    free(line);
    fclose(f);
    return found;
}

/* grep -Eq '\bIDENT[[:space:]]*\(': an occurrence of IDENT whose left neighbor
 * is not a word character (or is line start), followed by optional whitespace
 * and '('. The right side needs no boundary: callers pass idents long enough
 * that any longer identifier continues with '_' or another word character,
 * which is exactly what the \b form also accepts. */
static int sw_ident_call(const char *line, const char *ident)
{
    size_t il = strlen(ident);
    for (const char *p = line; (p = strstr(p, ident)) != NULL; p += il) {
        int left = p == line
            || !(isalnum((unsigned char)p[-1]) || p[-1] == '_');
        const char *q = p + il;
        while (*q && isspace((unsigned char)*q))
            q++;
        if (left && *q == '(')
            return 1;
    }
    return 0;
}

static int sw_file_has_ident(const char *path, const char *ident)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char *line = NULL;
    size_t cap = 0;
    int found = 0;
    while (getline(&line, &cap, f) >= 0) {
        if (sw_ident_call(line, ident)) {
            found = 1;
            break;
        }
    }
    free(line);
    fclose(f);
    return found;
}

/* git ls-files -- <engine path> <cognition path> <contexts glob>: number of
 * tracked owners for one per-domain include; when exactly one, the path is
 * copied to out. git's own stderr passes through, as in the shell original. */
static int sw_git_owners(const char *rel, char *out, size_t cap)
{
    char cmd[4096];
    if (ovf(snprintf(cmd, sizeof cmd,
                     "git ls-files -- 'engine/controllers/include/controllers/%s' "
                     "'cognition/controllers/include/controllers/%s' "
                     "'contexts/*/controllers/include/controllers/%s'",
                     rel, rel, rel), sizeof cmd))
        return -1;
    FILE *p = popen(cmd, "r");
    if (!p)
        return die("z23-lint: popen failed (%s)\n", cmd);
    char *line = NULL;
    size_t lcap = 0;
    ssize_t n;
    int count = 0;
    while ((n = getline(&line, &lcap, p)) >= 0) {
        if (count == 0) {
            while (n > 0 && (line[n - 1] == '\n'))
                line[--n] = '\0';
            if ((size_t)n >= cap) {
                free(line);
                pclose(p);
                return die("z23-lint: git ls-files path overflow\n", "");
            }
            memcpy(out, line, (size_t)n + 1);
        }
        count++;
    }
    free(line);
    pclose(p);
    return count;
}

/* dumper_def_files twin: aggregator first, then each parsed include's single
 * resolved owner, in include order. Returns 1 (explaining on stderr) when the
 * aggregator is missing, an include resolves to != 1 owners, or the set comes
 * back under the anti-hollowness floor. */
static int sw_dumper_files(regex_t *incl, char out[][SW_PATH], int *nout)
{
    *nout = 0;
    if (!sw_is_reg(k_sw_agg)) {
        fprintf(stderr, "dumper_defs: missing %s (run from repo root)\n",
                k_sw_agg);
        return 1;
    }
    memcpy(out[0], k_sw_agg, sizeof k_sw_agg);
    *nout = 1;
    FILE *f = fopen(k_sw_agg, "r");
    if (!f)
        return die("z23-lint: cannot open %s\n", k_sw_agg);
    char *line = NULL;
    size_t cap = 0;
    int rc = 0;
    while (getline(&line, &cap, f) >= 0 && rc == 0) {
        regmatch_t m[2];
        if (regexec(incl, line, 2, m, 0) != 0)
            continue;
        char rel[128];
        size_t rl = (size_t)(m[1].rm_eo - m[1].rm_so);
        if (rl >= sizeof rel || *nout >= SW_MAX_DEFS) {
            rc = die("z23-lint: dumper include overflow\n", "");
            break;
        }
        memcpy(rel, line + m[1].rm_so, rl);
        rel[rl] = '\0';
        int owners = sw_git_owners(rel, out[*nout], SW_PATH);
        if (owners < 0) {
            rc = 2;
            break;
        }
        if (owners != 1) {
            fprintf(stderr, "dumper_defs: %s includes '%s' but the "
                    "feature-first controller rooms resolve %d owners\n",
                    k_sw_agg, rel, owners);
            rc = 1;
            break;
        }
        (*nout)++;
    }
    free(line);
    fclose(f);
    if (rc)
        return rc;
    int domains = *nout - 1;
    if (domains < 8) {
        fprintf(stderr, "dumper_defs: resolved only %d per-domain .def "
                "include(s) from %s, expected at least 8 — the include "
                "pattern moved and every consumer of this set has gone blind\n",
                domains, k_sw_agg);
        return 1;
    }
    return 0;
}

int check_sandbox_wired_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    struct sw_re r;
    int rc = sw_compile(&r);
    if (rc)
        return rc;
    int fail = 0;
    if (!sw_is_reg(k_sw_boot)) {
        fprintf(stderr, "check_sandbox_wired: FATAL — missing %s\n", k_sw_boot);
        sw_free(&r, 5);
        return 2;
    }
    if (!sw_is_reg(k_sw_linux)) {
        fprintf(stderr, "check_sandbox_wired: FATAL — missing %s\n", k_sw_linux);
        sw_free(&r, 5);
        return 2;
    }
    if (!sw_file_has(k_sw_boot, &r.name)) {
        fprintf(stderr, "check_sandbox_wired: FAIL — no SYSINIT record named \"sand"
                "box\" in %s\n", k_sw_boot);
        fail = 1;
    }
    if (!sw_file_has(k_sw_boot, &r.stage)) {
        fprintf(stderr, "check_sandbox_wired: FAIL — the sand"
                "box record is not on the SERVICES_RUNNING boundary in %s\n",
                k_sw_boot);
        fail = 1;
    }
    if (!sw_file_has_ident(k_sw_boot, "os_sandbox_" "enter")) {
        fprintf(stderr, "check_sandbox_wired: FAIL — boot never calls os_sand"
                "box_enter() in %s\n", k_sw_boot);
        fail = 1;
    }
    if (!sw_file_has_lit(k_sw_linux, "SECCOMP_FILTER_" "FLAG_TSYNC")) {
        fprintf(stderr, "check_sandbox_wired: FAIL — %s does not use SECCOMP_FILTER_"
                "FLAG_TSYNC (seccomp would confine only the boot thread)\n",
                k_sw_linux);
        fail = 1;
    }
    if (!sw_file_has(k_sw_linux, &r.nrsec)) {
        fprintf(stderr, "check_sandbox_wired: FAIL — %s never installs via the "
                "seccomp(2) syscall (__NR_" "seccomp) for the TSYNC path\n",
                k_sw_linux);
        fail = 1;
    }
    if (!sw_file_has_ident(k_sw_boot, "os_sandbox_" "note_requested")) {
        fprintf(stderr, "check_sandbox_wired: FAIL — boot never calls os_sand"
                "box_note_requested() in %s (a failed apply would be "
                "indistinguishable from 'never requested')\n", k_sw_boot);
        fail = 1;
    }
    if (!sw_is_reg(k_sw_witness)) {
        fprintf(stderr, "check_sandbox_wired: FAIL — missing %s (the confine"
                "ment witness)\n", k_sw_witness);
        fail = 1;
    } else if (sw_file_has_ident(k_sw_witness, "os_sandbox_" "landlock_abi")) {
        fprintf(stderr, "check_sandbox_wired: FAIL — %s live-probes Landlock; use "
                "os_sandbox_" "landlock_abi_cached() (a probe from a confined "
                "process is KILL_PROCESS)\n", k_sw_witness);
        fail = 1;
    }
    static char defs[SW_MAX_DEFS][SW_PATH];
    int ndef = 0;
    if (sw_dumper_files(&r.incl, defs, &ndef)) {
        fputs("check_sandbox_wired: FAIL — could not resolve the dumpstate "
              "descriptor set\n", stderr);
        fail = 1;
    } else {
        int found = 0;
        for (int i = 0; i < ndef && !found; i++)
            found = sw_file_has(defs[i], &r.conf);
        if (!found) {
            fprintf(stderr, "check_sandbox_wired: FAIL — no \"confine"
                    "ment\" dumpstate row in %s or the %d per-domain files it "
                    "includes (the UNCONFINED verdict would be unreachable via "
                    "ops state)\n", k_sw_agg, ndef - 1);
            fail = 1;
        }
    }
    sw_free(&r, 5);
    if (fail) {
        fputs("check_sandbox_wired: the -sand"
              "box=steady confinement wiring is missing or moved.\n", stderr);
        return 1;
    }
    fputs("[check_sandbox_wired] OK — boot registers the sand"
          "box record, enters os_sand"
          "box, notes the request, exposes the `confine"
          "ment` witness (no live Landlock re-probe), and the seccomp filter "
          "installs with TSYNC (all-thread coverage)\n", stdout);
    return 0;
}

static int sw_want(const char *tag, regex_t *re, const char *s, int w)
{
    if ((regexec(re, s, 0, NULL, 0) == 0) != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

static int sw_want_ident(const char *tag, const char *ident, const char *s,
                         int w)
{
    if (sw_ident_call(s, ident) != w) {
        fprintf(stderr, "%s selftest: want %d: %s\n", tag, w, s);
        return 1;
    }
    return 0;
}

int check_sandbox_wired_selftest(void)
{
    const char *t = "check_sandbox_wired";
    struct sw_re r;
    int cr = sw_compile(&r);
    if (cr)
        return cr;
    regmatch_t m[2];
    int bad = sw_want(t, &r.name, ".name = \"sand" "box\"", 1)
        | sw_want(t, &r.name, ".name=\"sand" "box\"", 1)
        | sw_want(t, &r.name, ".namex = \"sand" "box\"", 0)
        | sw_want(t, &r.stage,
                  ".stage = BOOT_STAGE_" "SERVICES_RUNNING, .name = \"sand"
                  "box\"", 1)
        | sw_want(t, &r.stage,
                  ".name = \"sand" "box\"", 0)
        | sw_want(t, &r.stage,
                  ".stage = BOOT_STAGE_" "BOOT, .name = \"sand" "box\"", 0)
        | sw_want_ident(t, "os_sandbox_" "enter",
                        "    os_sandbox_" "enter();", 1)
        | sw_want_ident(t, "os_sandbox_" "enter",
                        "    my_os_sandbox_" "enter();", 0)
        | sw_want_ident(t, "os_sandbox_" "enter",
                        "    os_sandbox_" "enter  ( );", 1)
        | sw_want(t, &r.nrsec, "syscall(__NR_" "seccomp, ...)", 1)
        | sw_want(t, &r.nrsec, "syscall  (  __NR_" "seccomp, ...)", 1)
        | sw_want(t, &r.nrsec, "prctl(__NR_" "seccomp", 0)
        | sw_want_ident(t, "os_sandbox_" "note_requested",
                        "    os_sandbox_" "note_requested();", 1)
        | sw_want_ident(t, "os_sandbox_" "note_requested",
                        "    xos_sandbox_" "note_requested();", 0)
        | sw_want_ident(t, "os_sandbox_" "landlock_abi",
                        "os_sandbox_" "landlock_abi();", 1)
        | sw_want_ident(t, "os_sandbox_" "landlock_abi",
                        "os_sandbox_" "landlock_abi_cached();", 0)
        | sw_want(t, &r.conf,
                  "DIAG_SERVICE(\"confine" "ment\", confine"
                  "ment_dump_state_json,", 1)
        | sw_want(t, &r.conf,
                  "DIAG_SERVICE(\"confine" "ment\", other_fn,", 0);
    /* the include parse keeps exactly the captured file name */
    const char *inc = "\t#include \"controllers/diagnostics_dumpers_"
        "runtime.def\" /* trailing */";
    char cap[64];
    size_t cl = regexec(&r.incl, inc, 2, m, 0) == 0
        ? (size_t)(m[1].rm_eo - m[1].rm_so) : 0;
    if (cl == 0 || cl >= sizeof cap) {
        fprintf(stderr, "%s selftest: include parse failed: %s\n", t, inc);
        bad = 1;
    } else {
        memcpy(cap, inc + m[1].rm_so, cl);
        cap[cl] = '\0';
        if (strcmp(cap, "diagnostics_dumpers_" "runtime.def") != 0) {
            fprintf(stderr, "%s selftest: include captured '%s'\n", t, cap);
            bad = 1;
        }
    }
    bad |= sw_want(t, &r.incl, "# include \"controllers/diagnostics_dumpers_"
                   "x.def\"", 0)
        | sw_want(t, &r.incl, "#include \"controllers/other.def\"", 0)
        | sw_want(t, &r.incl, "x #include \"controllers/diagnostics_dumpers_"
                  "x.def\"", 0);
    sw_free(&r, 5);
    return st_ok(bad, "check_sandbox_wired selftest: OK\n");
}

