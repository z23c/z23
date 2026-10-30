/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-crypto-perf (gate_crypto_perf.c). Runs the
 * nine evaluator cases of the shell original, then runs the whole gate
 * (ccp_core) on fixture baselines and fixture bench output files under the
 * lintc scratch dir: ratchet pass, ratchet fail, lost lead, behind-rust
 * BEHIND pass, malformed baseline row. The real benchmark never runs here.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_crypto_perf_priv.h"

struct ccps_eval {
    const char *desc;
    const char *expect;
    const char *meas, *cbase, *rust;
    const char *mode;
};

static const struct ccps_eval k_ccps_eval[] = {
    { "beat, at baseline, well under rust", "OK_BEAT", "100", "100", "200", "beat" },
    { "beat, +15% (within margin), under rust", "OK_BEAT", "115", "100", "200", "beat" },
    { "beat, +25% self-regression", "FAIL_RATCHET", "125", "100", "200", "beat" },
    { "beat, faster than baseline", "OK_BEAT", "80", "100", "200", "beat" },
    { "beat, but lost lead (meas>=rust)", "FAIL_BEAT", "125", "100", "120", "beat" },
    { "beat, mis-pinned (no headroom vs rust)", "FAIL_CONFIG", "100", "100", "110", "beat" },
    { "behind, within ratchet, slower than rust", "OK_BEHIND", "110", "100", "40", "behind" },
    { "behind, self-regression beyond margin", "FAIL_RATCHET", "130", "100", "40", "behind" },
    { "behind, we happen to be ahead", "OK_BEHIND", "90", "100", "200", "behind" },
};

struct ccps_gate {
    const char *name;
    const char *baseline;
    const char *bench;
    int want;
    const char *needle; /* NULL: rc only */
};

static const struct ccps_gate k_ccps_gate[] = {
    { "within ratchet passes", "prim,100,200,beat,cite,x\n", "CRYPTOPERF prim 95 1000\n", 0, "check-crypto-perf: OK" },
    { "over ratchet fails", "prim,100,200,beat,cite,x\n", "CRYPTOPERF prim 130 1000\n", 1, "FAIL: self-regression" },
    { "lost lead over rust fails", "prim,100,120,beat,cite,x\n", "CRYPTOPERF prim 125 1000\n", 1, "lost lead" },
    { "behind rust prints BEHIND and passes", "prim,100,40,behind,cite,x\n", "CRYPTOPERF prim 110 1000\n", 0, "BEHIND RUST — optimize prim" },
    { "non-numeric c_ns is a malformed baseline row", "prim,abc,200,beat,cite,x\n", "CRYPTOPERF prim 100 1000\n", 2, "malformed baseline row" },
    { "hex c_ns is a malformed baseline row", "prim,0x1000,200,beat,cite,x\n", "CRYPTOPERF prim 100 1000\n", 2, "malformed baseline row" },
    { "non-numeric rust in a beat row is malformed", "prim,100,abc,beat,cite,x\n", "CRYPTOPERF prim 100 1000\n", 2, "malformed baseline row" },
};

static int ccps_eval_cases(int *fails)
{
    for (size_t i = 0; i < sizeof k_ccps_eval / sizeof k_ccps_eval[0]; i++) {
        const struct ccps_eval *c = &k_ccps_eval[i];
        char ratio[CCP_NUM];
        int v = ccp_eval_row(c->meas, c->cbase, c->rust, c->mode, "0.20",
                             ratio, sizeof ratio);
        const char *got = v < 0 ? "ERROR" : ccp_verdict_name(v);
        if (strcmp(got, c->expect) == 0)
            printf("  OK   %-42s -> %s\n", c->desc, got);
        else {
            printf("  FAIL %-42s -> %s (expected %s)\n", c->desc, got,
                   c->expect);
            (*fails)++;
        }
    }
    return 0;
}

static int ccps_gate_case(const char *root, const struct ccps_gate *c,
                          int *fails)
{
    char base_p[CCP_PATH], bench_p[CCP_PATH];
    if (ovf(snprintf(base_p, sizeof base_p, "%s/base.csv", root), sizeof base_p)
        || ovf(snprintf(bench_p, sizeof bench_p, "%s/bench.txt", root),
               sizeof bench_p))
        return 2;
    if (csr_write(base_p, c->baseline) || csr_write(bench_p, c->bench))
        return 2;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err)
        return die("z23-lint: tmpfile failed\n", "");
    struct ccp_opts o = { "", base_p, "0.20", bench_p,
                          "docs/bench-history.csv", out, err };
    int rc = ccp_core(&o);
    static char buf[CCP_RAW];
    rewind(out);
    rewind(err);
    size_t n = fread(buf, 1, sizeof buf - 1, out);
    buf[n] = '\0';
    size_t ne = fread(buf + n, 1, sizeof buf - 1 - n, err);
    buf[n + ne] = '\0';
    int bad = rc != c->want || (c->needle && !strstr(buf, c->needle));
    fclose(out);
    fclose(err);
    if (bad) {
        printf("  FAIL %-42s -> rc=%d (expected %d)\n", c->name, rc, c->want);
        (*fails)++;
    } else
        printf("  OK   %-42s -> rc=%d\n", c->name, rc);
    return 0;
}

int check_crypto_perf_selftest(void)
{
    puts("check_crypto_perf --selftest (evaluator logic, no build)");
    int fails = 0;
    int total = (int)(sizeof k_ccps_eval / sizeof k_ccps_eval[0])
              + (int)(sizeof k_ccps_gate / sizeof k_ccps_gate[0]);
    ccps_eval_cases(&fails);
    char root[CCP_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "crypto-perf");
    if (rc)
        return rc;
    for (size_t i = 0; i < sizeof k_ccps_gate / sizeof k_ccps_gate[0]; i++) {
        rc = ccps_gate_case(root, &k_ccps_gate[i], &fails);
        if (rc)
            return rc;
    }
    rap_rm_rf(root);
    if (fails == 0) {
        printf("check_crypto_perf selftest: OK (%d/%d)\n", total, total);
        return 0;
    }
    printf("check_crypto_perf selftest: FAIL (%d failing case(s))\n", fails);
    return 1;
}
