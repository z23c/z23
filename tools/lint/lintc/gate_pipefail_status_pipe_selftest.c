/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-pipefail-status-pipe
 * (gate_pipefail_status_pipe.c). Plants each fixture shape from the
 * original shell self-test in a sandbox scan glob with an empty baseline,
 * ceiling 0 and floor 1, and asserts the gate's verdict: clean passes; a
 * stale baseline row for a clean file fails; plain, reindented and
 * one-line printf|grep -q fail; plain and reindented cmd|grep -q fail; a
 * value pipeline (grep -o), a no-pipefail script and cmd|grep -q without
 * pipefail pass. Hollowness guards check the fixtures really carry the
 * shapes they claim.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_pipefail_status_pipe_priv.h"

#define PSPS_GATE "check_pipefail_status_pipe"

enum { PSPS_PATH = 1024 };

static const char k_psps_plain[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nexport LC_ALL=C\n"
    "out=\"$(some_producer)\"\nif printf '%s\\n' \"$out\" | grep -q "
    "'needle'; then\n    echo \"found\"\nfi\n";
static const char k_psps_reindented[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nexport LC_ALL=C\n"
    "out=\"$(some_producer)\"\n      if      printf '%s\\n' \"$out\"    |\n"
    "                    grep     -q    'needle'\n      then\n"
    "                    echo \"found\"\n      fi\n";
static const char k_psps_oneline[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nexport LC_ALL=C\n"
    "probe() { out=\"$(some_producer)\"; printf '%s' \"$out\" | grep -qE "
    "'need|le' && return 0; return 1; }\n";
static const char k_psps_clean[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nexport LC_ALL=C\n"
    ". tools/scripts/sh_str.sh\nout=\"$(some_producer)\"\n"
    "first=\"$(printf '%s\\n' \"$out\" | head -n1)\"\n"
    "name=\"$(printf '%s\\n' \"$out\" | sed -n 's/^name=//p')\"\n"
    "hit=\"$(printf '%s\\n' \"$out\" | grep '^FATAL' || true)\"\n"
    "extracted=\"$(arbitrary_cmd | grep -o 'needle' || true)\"\n"
    "if [ -n \"$hit\" ]; then echo \"found\"; fi\n"
    "if [ -n \"$extracted\" ]; then echo \"found\"; fi\n"
    "if str_contains \"$out\" 'needle'; then echo \"found\"; fi\n"
    "# if printf '%s\\n' \"$out\" | grep -q 'needle'; then echo "
    "\"commented out\"; fi\n"
    "echo \"a # b\" | wc -c   # a '#' inside quotes is not a comment\n";
static const char k_psps_no_pf[] =
    "#!/usr/bin/env bash\nset -eu\nout=\"$(some_producer)\"\n"
    "if printf '%s\\n' \"$out\" | grep -q 'needle'; then\n"
    "    echo \"found\"\nfi\n";
static const char k_psps_cmd_quiet[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nexport LC_ALL=C\n"
    "if arbitrary_cmd | grep -q 'needle'; then\n    echo \"found\"\nfi\n";
static const char k_psps_cmd_reind[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nexport LC_ALL=C\n"
    "      if      arbitrary_cmd    |\n"
    "                    grep     -q    'needle'\n      then\n"
    "                    echo \"found\"\n      fi\n";
static const char k_psps_cmd_value[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nexport LC_ALL=C\n"
    "hit=\"$(arbitrary_cmd | grep -o 'needle' || true)\"\n"
    "if [ -n \"$hit\" ]; then echo \"found\"; fi\n";
static const char k_psps_cmd_no_pf[] =
    "#!/usr/bin/env bash\nset -eu\nif arbitrary_cmd | grep -q 'needle'; "
    "then\n    echo \"found\"\nfi\n";

/* `#` inside a double quote opened on the previous line is not a comment */
static const char k_psps_multiline_q[] =
    "#!/usr/bin/env bash\nset -euo pipefail\nexport LC_ALL=C\n"
    "x=$(printf \"foo\na # \"b\" | grep -q x)\n";

/* fixtures too large for a literal, built by psps_build() */
static char k_psps_longline[9000];
static char k_psps_longstage[12000];

static void psps_build(void)
{
    static const char head[] = "#!/usr/bin/env bash\n";
    static const char pf[] = "set -euo pipefail\n";
    static const char viol[] = "echo hi | grep -q x\n";
    size_t o = 0;
    /* a first line over the line cap, then pipefail, then a violation */
    o += (size_t)snprintf(k_psps_longline, sizeof k_psps_longline, "#");
    memset(k_psps_longline + o, 'a', 8200);
    o += 8200;
    snprintf(k_psps_longline + o, sizeof k_psps_longline - o, "\n%s%s%s",
             head, pf, viol);
    /* a grep -q stage longer than the stage cap, joined by continuations */
    o = (size_t)snprintf(k_psps_longstage, sizeof k_psps_longstage,
                         "%s%secho hi | grep -q x ", head, pf);
    for (int k = 0; k < 2; k++) {
        memset(k_psps_longstage + o, 'a', 5000);
        o += 5000;
        o += (size_t)snprintf(k_psps_longstage + o,
                              sizeof k_psps_longstage - o,
                              k ? "\n" : " \\\n");
    }
}

struct psps_case {
    const char *name;
    const char *body;
    int want_fail;
};

static const struct psps_case k_psps_cases[] = {
    { "quote state carries across lines", k_psps_multiline_q, 1 },
    { "over-long line fails closed", k_psps_longline, 1 },
    { "over-long stage fails closed", k_psps_longstage, 1 },
    { "clean passes", k_psps_clean, 0 },
    { "plain printf|grep -q fails", k_psps_plain, 1 },
    { "clean again after removal", k_psps_clean, 0 },
    { "reindented violation fails", k_psps_reindented, 1 },
    { "one-line violation fails", k_psps_oneline, 1 },
    { "no-pipefail script passes", k_psps_no_pf, 0 },
    { "cmd|grep -q fails", k_psps_cmd_quiet, 1 },
    { "reindented cmd|grep -q fails", k_psps_cmd_reind, 1 },
    { "cmd|grep -o value pipeline passes", k_psps_cmd_value, 0 },
    { "cmd|grep -q without pipefail passes", k_psps_cmd_no_pf, 0 },
};

static int psps_strstr(const char *h, const char *n)
{
    return strstr(h, n) != NULL;
}

/* hollowness guards: each fixture really carries its claimed shape */
static int psps_guards(void)
{
    if (strcmp(k_psps_reindented, k_psps_plain) == 0 ||
        strcmp(k_psps_cmd_reind, k_psps_cmd_quiet) == 0) {
        fputs(PSPS_GATE ": SELFTEST FAILED — a reindented fixture is "
              "byte-identical to its plain twin\n", stderr);
        return 2;
    }
    if (!psps_strstr(k_psps_reindented, "\"$out\"    |") ||
        !psps_strstr(k_psps_cmd_reind, "arbitrary_cmd    |")) {
        fputs(PSPS_GATE ": SELFTEST FAILED — a reindent fixture no longer "
              "ends a line on the pipe\n", stderr);
        return 2;
    }
    if (!psps_strstr(k_psps_cmd_quiet, "arbitrary_cmd | grep -q") ||
        !psps_strstr(k_psps_cmd_no_pf, "arbitrary_cmd | grep -q")) {
        fputs(PSPS_GATE ": SELFTEST FAILED — a cmd fixture no longer "
              "carries 'arbitrary_cmd | grep -q'\n", stderr);
        return 2;
    }
    if (!psps_strstr(k_psps_cmd_value, "grep -o") ||
        psps_strstr(k_psps_cmd_value, "-q") ||
        !psps_strstr(k_psps_cmd_value, "pipefail")) {
        fputs(PSPS_GATE ": SELFTEST FAILED — the cmd_value fixture cannot "
              "prove the value-pipeline exemption\n", stderr);
        return 2;
    }
    if (psps_strstr(k_psps_no_pf, "pipefail") ||
        psps_strstr(k_psps_cmd_no_pf, "pipefail")) {
        fputs(PSPS_GATE ": SELFTEST FAILED — a no-pipefail fixture mentions "
              "pipefail\n", stderr);
        return 2;
    }
    if (!psps_strstr(k_psps_clean, "grep -o") ||
        !psps_strstr(k_psps_clean, "# if printf")) {
        fputs(PSPS_GATE ": SELFTEST FAILED — the clean fixture no longer "
              "carries its exemption shapes\n", stderr);
        return 2;
    }
    return 0;
}

static int psps_set_env(const char *root, const char *base, const char *ceil,
                        const char *floor)
{
    char glob[PSPS_PATH];
    if (ovf(snprintf(glob, sizeof glob, "%s/sh/*.sh", root), sizeof glob))
        return 2;
    setenv("ZCL_PIPEFAIL_GATE_SCAN_GLOB", glob, 1);
    setenv("ZCL_PIPEFAIL_GATE_BASELINE", base, 1);
    setenv("ZCL_PIPEFAIL_GATE_CEILING", ceil, 1);
    setenv("ZCL_PIPEFAIL_GATE_FILE_FLOOR", floor, 1);
    setenv("ZCL_LINT_MODE", "FAIL", 1);
    return 0;
}

static int psps_run(const char *root, const char *body, const char *base,
                    const char *ceil)
{
    char probe[PSPS_PATH], dir[PSPS_PATH];
    if (ovf(snprintf(dir, sizeof dir, "%s/sh", root), sizeof dir))
        return 2;
    if (csr_mkdirs(dir))
        return 2;
    if (ovf(snprintf(probe, sizeof probe, "%s/sandbox_probe.sh", dir),
             sizeof probe))
        return 2;
    int rc = csr_write(probe, body);
    if (rc)
        return rc;
    if (psps_set_env(root, base, ceil, "1"))
        return 2;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    rc = psp_main(sink, sink);
    fclose(sink);
    return rc;
}

/* a stale baseline row for a clean file must be rejected; 1 = bad, 2 = error */
static int psps_stale_case(const char *root, const char *stale)
{
    int bad = 0;
    char row[PSPS_PATH + 32];
    if (ovf(snprintf(row, sizeof row, "%s/sh/sandbox_probe.sh 1\n", root),
             sizeof row))
        return 2;
    if (csr_write(stale, row))
        return die("z23-lint: cannot write stale baseline\n", "");
    int got = psps_run(root, k_psps_clean, stale, "1");
    if (got == 0) {
        fputs(PSPS_GATE " selftest: a stale baseline row for a clean file "
              "was accepted\n", stderr);
        bad = 1;
    }
    return bad;
}

static int psps_baseline_cases(const char *root)
{
    int bad = 0;
    /* a missing baseline file is an empty baseline, like the empty case */
    char gone[PSPS_PATH + 16];
    if (ovf(snprintf(gone, sizeof gone, "%s/absent_baseline.txt", root),
             sizeof gone))
        return 2;
    int m1 = psps_run(root, k_psps_clean, gone, "0");
    int m2 = psps_run(root, k_psps_plain, gone, "0");
    if (m1 != 0 || m2 == 0) {
        fprintf(stderr, PSPS_GATE " selftest: missing baseline: clean "
                "rc=%d plain rc=%d\n", m1, m2);
        bad = 1;
    }
    /* an overlong baseline line must exit 2 */
    static char big[2100];
    memset(big, 'a', sizeof big - 2);
    big[sizeof big - 2] = '\n';
    big[sizeof big - 1] = '\0';
    char longb[PSPS_PATH];
    if (ovf(snprintf(longb, sizeof longb, "%s/long_baseline.txt", root),
             sizeof longb))
        return 2;
    if (csr_write(longb, big))
        return die("z23-lint: cannot write long baseline\n", "");
    int lg = psps_run(root, k_psps_clean, longb, "0");
    if (lg != 2) {
        fprintf(stderr, PSPS_GATE " selftest: overlong baseline line: "
                "want rc=2 got rc=%d\n", lg);
        bad = 1;
    }
    return bad;
}

int check_pipefail_status_pipe_selftest(void)
{
    int rc = psps_guards();
    if (rc)
        return rc;
    psps_build();
    char root[PSPS_PATH], empty[PSPS_PATH], stale[PSPS_PATH];
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(root, sizeof root, "%s/z23-lint-pipefail.XXXXXX", td),
             sizeof root))
        return 2;
    if (!mkdtemp(root))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    if (ovf(snprintf(empty, sizeof empty, "%s/empty_baseline.txt", root),
             sizeof empty))
        return 2;
    if (ovf(snprintf(stale, sizeof stale, "%s/stale_baseline.txt", root),
             sizeof stale))
        return 2;
    if (csr_write(empty, "") || csr_write(stale, ""))
        return die("z23-lint: cannot create selftest baselines\n", "");
    int bad = 0;
    for (size_t i = 0; i < sizeof k_psps_cases / sizeof k_psps_cases[0];
         i++) {
        int got = psps_run(root, k_psps_cases[i].body, empty, "0");
        int ok = k_psps_cases[i].want_fail ? (got != 0) : (got == 0);
        if (!ok) {
            fprintf(stderr, PSPS_GATE " selftest: %s: want %s got rc=%d\n",
                    k_psps_cases[i].name,
                    k_psps_cases[i].want_fail ? "fail" : "pass", got);
            bad = 1;
        }
    }
    int sc = psps_stale_case(root, stale);
    if (sc == 2)
        return 2;
    bad |= sc;
    int bc = psps_baseline_cases(root);
    if (bc == 2)
        return 2;
    bad |= bc;
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: " PSPS_GATE " selftest\n", stderr);
    return st_ok(bad, "[" PSPS_GATE "] SELFTEST PASS (clean passes; stale "
                 "baseline rows and plain, REINDENTED and one-line "
                 "printf|grep -q plus plain and REINDENTED cmd|grep -q all "
                 "fail; a value pipeline (grep -o / head / sed), a converted "
                 "site, a commented-out violation do not count; cmd|grep -q "
                 "and printf|grep -q without pipefail are exempt; this gate "
                 "and sh_str.sh are clean)\n");
}
