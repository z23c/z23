/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the planted-table fixture selftest of the
 * check-fleet-airship-rules family (the 700-line family ceiling split).
 * The gate body lives in gate_fleet_airship_rules.c, the awk row reader
 * in gate_fleet_airship_rules_parse.c, and the scan checks in
 * gate_fleet_airship_rules_rules.c; the files share their internals
 * through gate_fleet_airship_rules_priv.h.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_fleet_airship_rules_priv.h"

static const char k_gate[] = "check_fleet_airship_rules";

/* ── fixture self-test ────────────────────────────────────────────────── */

#define FAR_ST_HEAD \
    "AIRSHIP_FACT(\"reachable\", PEER_VERIFIED)\n" \
    "AIRSHIP_FACT(\"cpus\", SELF_REPORTED)\n" \
    "AIRSHIP_ASSET(\"airship\")\n"

struct far_st { char tmp[4096]; int fails; };

/* One planted table, one real gate run over it with the env knobs the
 * shell selftest sets; pass|fail grading like expect(). */
static int far_st_case(struct far_st *st, const char *label, int want_pass,
                       const char *text)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/rules.def", st->tmp),
            sizeof path))
        return 2;
    int bad = csr_write(path, text);
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err)
        bad = 1;
    if (bad || setenv("ZCL_AIRSHIP_ROOT", st->tmp, 1) != 0
        || setenv("ZCL_AIRSHIP_DEF", "rules.def", 1) != 0
        || setenv("ZCL_AIRSHIP_FLOOR", "1", 1) != 0) {
        fputs("check_fleet_airship_rules selftest: fixture setup failed\n",
              stderr);
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return 1;
    }
    int rc = far_impl(out, err);
    fclose(out);
    fclose(err);
    int got_pass = rc == 0;
    if (got_pass == want_pass) {
        printf("  selftest ok: %s\n", label);
        return 0;
    }
    fprintf(stderr, "%s: SELFTEST FAILED — %s (got %s, wanted %s)\n",
            k_gate, label, got_pass ? "pass" : "fail",
            want_pass ? "pass" : "fail");
    return 1;
}

static int far_st_missing(struct far_st *st)
{
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err
        || setenv("ZCL_AIRSHIP_ROOT", st->tmp, 1) != 0
        || setenv("ZCL_AIRSHIP_DEF", "missing.def", 1) != 0
        || setenv("ZCL_AIRSHIP_FLOOR", "1", 1) != 0) {
        fputs("check_fleet_airship_rules selftest: fixture setup failed\n",
              stderr);
        return 1;
    }
    int rc = far_impl(out, err);
    fclose(out);
    fclose(err);
    if (rc != 2) {
        fprintf(stderr, "%s: SELFTEST FAILED — a missing table did not "
                "exit 2 (rc=%d)\n", k_gate, rc);
        return 1;
    }
    puts("  selftest ok: a missing table exits 2");
    return 0;
}

int check_fleet_airship_rules_selftest(void)
{
    char tmpl[4096];
    (void)csr_mkdirs("test-tmp");
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-far-XXXXXX",
                     env_or("TMPDIR", "test-tmp")), sizeof tmpl))
        return 2;
    if (!mkdtemp(tmpl))
        return die("z23-lint: mkdtemp failed\n", "");
    struct far_st st = { { 0 }, 0 };
    if (ovf(snprintf(st.tmp, sizeof st.tmp, "%s", tmpl), sizeof st.tmp))
        return 2;
    int bad = 0;
    bad |= far_st_case(&st, "a paying peer-verified rule beside a zero "
                       "self-reported one", 1,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"a dial connects or it does not\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 0, DOCTRINE, "
                       "\"the node says so itself\")\n");
    bad |= far_st_case(&st, "a self-reported fact that pays", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"w\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 2, OBSERVED, "
                       "\"the node says so itself\")\n");
    bad |= far_st_case(&st, "an asset no row declares", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"zeppelin\", 1, "
                       "OBSERVED, \"w\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 0, DOCTRINE, "
                       "\"w\")\n");
    bad |= far_st_case(&st, "a fact no row declares", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"ram_total\", \"airship\", 1, "
                       "OBSERVED, \"w\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 0, DOCTRINE, "
                       "\"w\")\n"
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"w\")\n");
    bad |= far_st_case(&st, "a zero rule claiming to be an observation", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"w\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 0, OBSERVED, "
                       "\"w\")\n");
    bad |= far_st_case(&st, "a duplicated rule", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"a dial connects or it does not\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 0, DOCTRINE, "
                       "\"the node says so itself\")\n"
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"w\")\n");
    bad |= far_st_case(&st, "a per_node and a confidence written as "
                       "strings", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"airship\", \"1\", "
                       "\"OBSERVED\", \"w\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 0, DOCTRINE, "
                       "\"w\")\n");
    bad |= far_st_case(&st, "an empty why", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 0, DOCTRINE, "
                       "\"w\")\n");
    bad |= far_st_case(&st, "a declared fact no rule reads", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"w\")\n");
    bad |= far_st_case(&st, "a table where nothing pays", 0,
                       FAR_ST_HEAD
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 0, "
                       "DOCTRINE, \"w\")\n"
                       "AIRSHIP_RULE(\"cpus\", \"airship\", 0, DOCTRINE, "
                       "\"w\")\n");
    bad |= far_st_case(&st, "a verification that is neither PEER_VERIFIED "
                       "nor SELF_REPORTED", 0,
                       "AIRSHIP_FACT(\"reachable\", TRUSTED)\n"
                       "AIRSHIP_ASSET(\"airship\")\n"
                       "AIRSHIP_RULE(\"reachable\", \"airship\", 1, "
                       "OBSERVED, \"w\")\n");
    bad |= far_st_missing(&st);
    (void)unsetenv("ZCL_AIRSHIP_ROOT");
    (void)unsetenv("ZCL_AIRSHIP_DEF");
    (void)unsetenv("ZCL_AIRSHIP_FLOOR");
    (void)rap_rm_rf(st.tmp);
    if (bad) {
        fprintf(stderr, "[%s] SELFTEST FAIL\n", k_gate);
        return 1;
    }
    printf("[%s] SELFTEST PASS (a paying self-reported fact, an "
           "undeclared fact or asset, a mislabelled zero row, a "
           "duplicate, an empty why, an unread fact and a table that "
           "pays nothing all fail; an honest table passes; a missing "
           "table exits 2)\n", k_gate);
    return 0;
}
