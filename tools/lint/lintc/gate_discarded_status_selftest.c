/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check_discarded_status (gate_discarded_status.c).
 * Ports every fixture and hollowness guard of the shell selftest: the clean
 * fixture carries every legitimate spelling of the same syntax, so a gate
 * that failed unconditionally could not pass; the plain and REINDENTED bare
 * negation, the pipefail-less make pipe, the no-errexit and the pipefail
 * scripts each assert one verdict. The gate-is-clean check now scans the
 * two ported C sources (the shell script was deleted with the port).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_discarded_status_priv.h"

static const char k_cdss_gate[] = "check_discarded_status";

static const char k_cdss_bare[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "a=\"$(compute a)\"\n"
    "b=\"$(compute b)\"\n"
    "verify_epoch \"$a\" \"$a\" \"$a\"\n"
    "! verify_epoch \"$a\" \"$b\" \"$a\" >/dev/null 2>&1\n"
    "echo \"selftest PASS\"\n";

static const char k_cdss_reshaped[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "if [ -n \"$mode\" ]; then     ! verify_epoch \"$a\" \"$b\" \"$a\"   ; fi\n"
    "echo \"selftest PASS\"\n";

static const char k_cdss_make_pipe[] =
    "#!/usr/bin/env bash\n"
    "set -eu\n"
    "echo \"building\"\n"
    "make dev-bin 2>&1 | tail -20\n"
    "echo \"built\"\n";

static const char k_cdss_clean[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "refute() { if \"$@\"; then echo \"expected non-zero from: $*\" >&2; exit 1; fi; }\n"
    "refute verify_epoch \"$a\" \"$b\" \"$a\"\n"
    "if ! verify_epoch \"$a\" \"$b\" \"$a\"; then echo \"good\"; fi\n"
    "while ! ready; do sleep 1; done\n"
    "until ! draining; do sleep 1; done\n"
    "! verify_epoch \"$a\" \"$b\" \"$a\" || die \"epoch check inverted\"\n"
    "! verify_epoch \"$a\" \"$b\" \"$a\" && echo \"correctly rejected\"\n"
    "if [ \"$x\" != \"$y\" ] && \\\n"
    "   ! verify_epoch \"$a\" \"$b\" \"$a\"; then\n"
    "    echo \"multi-line condition\"\n"
    "fi\n"
    "make dev-bin > build.log 2>&1 || { tail -20 build.log; exit 1; }\n"
    "version=\"$(make --version | head -n1)\"\n"
    "# ! verify_epoch \"$a\" \"$b\" \"$a\"    <- a commented-out one is not a violation\n";

static const char k_cdss_pipefail[] =
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n"
    "make dev-bin 2>&1 | tail -20\n";

static const char k_cdss_no_errexit[] =
    "#!/usr/bin/env bash\n"
    "set -u\n"
    "! verify_epoch \"$a\" \"$b\" \"$a\"\n"
    "echo \"done\"\n";

struct cdss_case {
    const char *name;
    const char *body;
    int want_fail;
};

static const struct cdss_case k_cdss_cases[] = {
    { "the clean fixture — refute(), 'if !', 'while !', 'until !', "
      "'! .. ||', '! .. &&', a multi-line condition, a redirected make and "
      "a value pipeline — was reported as a violation",
      k_cdss_clean, 0 },
    { "a bare '! cmd' statement under set -e did not fail the gate; that "
      "assertion can never fire",
      k_cdss_bare, 1 },
    { "removing the planted bare negation did not clear it", k_cdss_clean,
      0 },
    { "the SAME bare negation reindented after a 'then' on one line did not "
      "fail the gate; the reshape dodge is not closed",
      k_cdss_reshaped, 1 },
    { "removing the reshaped negation did not clear it", k_cdss_clean, 0 },
    { "a bare '! cmd' in a script with no set -e was counted; without "
      "errexit it discards no decision",
      k_cdss_no_errexit, 0 },
    { "'make ... | tail' in a script with no pipefail did not fail the gate; "
      "a failed build reports 0 there",
      k_cdss_make_pipe, 1 },
    { "the same 'make | tail' in a script that sets pipefail was counted; "
      "the status survives",
      k_cdss_pipefail, 0 },
};

/* ── hollowness guards on the fixtures themselves ──────────────────── */

static int cdss_fail(const char *msg)
{
    fprintf(stderr, "%s: SELFTEST FAILED — %s\n", k_cdss_gate, msg);
    return 2;
}

static int cdss_guards_neg(void)
{
    if (strcmp(k_cdss_bare, k_cdss_reshaped) == 0)
        return cdss_fail("the reshaped fixture is byte-identical to the "
                         "plain one; the reindent-dodge assertion is hollow");
    if (!strstr(k_cdss_bare, "! verify_epoch"))
        return cdss_fail("the bare_negation fixture no longer carries a bare "
                         "'! cmd'; it cannot prove anything");
    if (!strstr(k_cdss_reshaped, "! verify_epoch"))
        return cdss_fail("the bare_negation_reshaped fixture no longer "
                         "carries a bare '! cmd'; it cannot prove anything");
    if (!strstr(k_cdss_no_errexit, "! verify_epoch"))
        return cdss_fail("the negation_no_errexit fixture no longer carries "
                         "a bare '! cmd'; it cannot prove anything");
    return 0;
}

static int cdss_guards_make(void)
{
    if (!strstr(k_cdss_make_pipe, "make dev-bin 2>&1 | tail"))
        return cdss_fail("the make_pipe fixture no longer pipes make into "
                         "tail; the assertion is hollow");
    if (!strstr(k_cdss_pipefail, "make dev-bin 2>&1 | tail"))
        return cdss_fail("the make_pipe_pipefail fixture no longer pipes "
                         "make into tail; the assertion is hollow");
    if (strstr(k_cdss_make_pipe, "pipefail"))
        return cdss_fail("the make_pipe fixture sets pipefail; the status "
                         "would survive and the assertion inverts");
    return 0;
}

static int cdss_guards_clean(void)
{
    if (!strstr(k_cdss_no_errexit, "set -u"))
        return cdss_fail("the no-errexit fixture's set line changed; it may "
                         "now set -e and the assertion would invert");
    if (strstr(k_cdss_no_errexit, "set -e") ||
        strstr(k_cdss_no_errexit, "errexit"))
        return cdss_fail("the no-errexit fixture sets errexit; it cannot "
                         "test the exemption");
    if (!strstr(k_cdss_clean, "# ! verify_epoch"))
        return cdss_fail("the clean fixture no longer carries a commented-"
                         "out negation; the comment-stripping assertion is "
                         "hollow");
    if (!strstr(k_cdss_clean, "refute verify_epoch"))
        return cdss_fail("the clean fixture no longer shows the refute() fix "
                         "the gate points at");
    return 0;
}

static int cdss_guards(void)
{
    int rc = cdss_guards_neg();
    if (rc)
        return rc;
    rc = cdss_guards_make();
    if (rc)
        return rc;
    return cdss_guards_clean();
}

/* ── fixture tree and case runner ──────────────────────────────────── */

static int cdss_scratch(char *out, size_t cap)
{
    const char *td = env_or("TMPDIR", "test-tmp");
    if (ovf(snprintf(out, cap, "%s/z23-lint-discarded-status.XXXXXX", td),
            cap))
        return 2;
    (void)mkdir(td, 0700);
    if (!mkdtemp(out)) {
        fprintf(stderr, "%s: mkdtemp failed for selftest scratch\n",
                k_cdss_gate);
        return 2;
    }
    return 0;
}

static int cdss_case(const char *root, const struct cdss_case *c)
{
    char dir[CDS_PATH], path[CDS_PATH];
    char files[1][CDS_PATH];
    static struct cds_rows rows;
    int rc, viol;
    if (ovf(snprintf(dir, sizeof dir, "%s/sh", root), sizeof dir))
        return 2;
    rc = csr_mkdirs(dir);
    if (rc)
        return rc;
    if (ovf(snprintf(path, sizeof path, "%s/sandbox_probe.sh", dir),
            sizeof path))
        return 2;
    rc = csr_write(path, c->body);
    if (rc)
        return rc;
    strcpy(files[0], path);
    rc = cds_scan_list(files, 1, &rows);
    if (rc)
        return rc;
    viol = rows.nneg > 0 || rows.nmkp > 0;
    if (c->want_fail && !viol)
        return cdss_fail(c->name);
    if (!c->want_fail && viol)
        return cdss_fail(c->name);
    return 0;
}

/* This gate must not carry either bug it detects: the ported sources are
 * scanned with the same detector and must come back clean. */
static int cdss_self_check(void)
{
    static const char *const srcs[] = {
        "tools/lint/lintc/gate_discarded_status.c",
        "tools/lint/lintc/gate_discarded_status_selftest.c"
    };
    char files[2][CDS_PATH];
    static struct cds_rows rows;
    int rc, i;
    for (i = 0; i < 2; i++)
        strcpy(files[i], srcs[i]);
    rc = cds_scan_list(files, 2, &rows);
    if (rc)
        return cdss_fail("cannot scan this gate's own source");
    for (i = 0; i < rows.nneg; i++)
        fprintf(stderr, "  %s\n", rows.neg[i]);
    for (i = 0; i < rows.nmkp; i++)
        fprintf(stderr, "  %s\n", rows.mkp[i]);
    if (rows.nneg || rows.nmkp)
        return cdss_fail("this gate itself carries a shape it exists to "
                         "refuse");
    return 0;
}

int check_discarded_status_selftest(void)
{
    char root[CDS_PATH];
    size_t i;
    if (cdss_scratch(root, sizeof root))
        return 2;
    if (cdss_guards()) {
        rap_rm_rf(root);
        return 2;
    }
    for (i = 0; i < sizeof k_cdss_cases / sizeof k_cdss_cases[0]; i++) {
        int rc = cdss_case(root, &k_cdss_cases[i]);
        if (rc) {
            rap_rm_rf(root);
            return rc;
        }
    }
    if (cdss_self_check()) {
        rap_rm_rf(root);
        return 2;
    }
    printf("[%s] SELFTEST PASS (a bare '! cmd' under set -e and a "
           "pipefail-less 'make | tail' both fail, including the reindented "
           "spelling; refute(), if/while/until !, '! .. ||', '! .. &&', a "
           "commented-out negation, a redirected make, a value pipeline, a "
           "no-errexit script and a pipefail script are all clean; this gate "
           "is clean)\n",
           k_cdss_gate);
    rap_rm_rf(root);
    return 0;
}
