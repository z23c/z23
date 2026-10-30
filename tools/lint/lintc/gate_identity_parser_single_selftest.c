/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check_identity_parser_single
 * (gate_identity_parser_single.c). Ports the shell selftest: a sandboxed
 * tools/ tree with an empty baseline, a zero ceiling, and a marker budget
 * of one; proves a clean consumer passes, named and renamed class-A
 * validator copies fail, a class-B extraction fails, each revert passes,
 * an allowlisted+in-budget marker exempts in class B and in class A
 * (single-line and multi-line body), an unmarked class-A copy in that
 * same allowlisted file still fails, and a marker in an unauthorized
 * file — or over MARKER_CEILING — fails in either class.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_identity_parser_single_priv.h"

static const char k_ipss_a_copy[] =
    "is_sha256() { [[ \"${1:-}\" =~ ^[0-9a-f]{64}$ ]]; }";
static const char k_ipss_a_renamed[] =
    "totally_unrelated_name_not_on_any_list() {\n"
    "    [[ \"${1:-}\" =~ ^[0-9a-f]{64}$ ]]\n"
    "}";
static const char k_ipss_b_copy[] =
    "x=$(printf %s \"$1\" | grep -oE"
    " '\"source_id_sha256\"[[:space:]]*:[[:space:]]*\"[^\"]*\"'"
    " | head -1 | sed -E"
    " 's/.*\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\\1/')";
static const char k_ipss_b_marked[] =
    "# zcl-identity-parser-allow: fixture, cannot source the lib here\n"
    "x=$(printf %s \"$1\" | grep -oE"
    " '\"source_id_sha256\"[[:space:]]*:[[:space:]]*\"[^\"]*\"'"
    " | head -1)";
static const char k_ipss_a_marked[] =
    "# zcl-identity-parser-allow: fixture, cannot source the lib here\n"
    "is_sha256() { [[ \"${1:-}\" =~ ^[0-9a-f]{64}$ ]]; }";
static const char k_ipss_a_marked_multi[] =
    "# zcl-identity-parser-allow: fixture, cannot source the lib here\n"
    "totally_unrelated_name_not_on_any_list() {\n"
    "    [[ \"${1:-}\" =~ ^[0-9a-f]{64}$ ]]\n"
    "}";
static const char k_ipss_two_markers[] =
    "# zcl-identity-parser-allow: fixture A\n"
    "a=1\n"
    "# zcl-identity-parser-allow: fixture B\n"
    "b=2";

struct ipss_case {
    int want_fail;
    const char *msg;
    const char *extra;
};

static const struct ipss_case k_ipss_cases[] = {
    { 0, "a clean consumer with no copy was reported as a violation", "" },
    { 1, "an inline is_sha256() definition (class A, named) did not fail"
         " the gate", k_ipss_a_copy },
    { 0, "reverting the class-A copy did not clear the violation", "" },
    { 1, "a RENAMED validator (class A, structural — no name on any list)"
         " did not fail the gate; the name-list dodge is not closed",
      k_ipss_a_renamed },
    { 0, "reverting the renamed structural copy did not clear the"
         " violation", "" },
    { 1, "an inline grep/sed source_id_sha256 extraction (class B) did"
         " not fail the gate", k_ipss_b_copy },
    { 0, "reverting the class-B copy did not clear the violation", "" },
    { 0, "a zcl-identity-parser-allow-marked copy in the allowed file was"
         " still counted as debt", k_ipss_b_marked },
    { 0, "reverting left a stray marker violation", "" },
    { 0, "a zcl-identity-parser-allow-marked class-A copy (single-line)"
         " in the allowed file was still counted as debt",
      k_ipss_a_marked },
    { 0, "reverting the marked single-line class-A copy left a violation",
      "" },
    { 0, "a zcl-identity-parser-allow-marked class-A copy (multi-line"
         " body) in the allowed file was still counted as debt; the"
         " marker above the HEADER must survive the body",
      k_ipss_a_marked_multi },
    { 0, "reverting the marked multi-line class-A copy left a violation",
      "" },
    { 1, "an UNMARKED class-A copy in the allowlisted file stopped"
         " failing — the class-A marker wiring exempts too much",
      k_ipss_a_copy },
    { 0, "reverting the unmarked class-A copy did not clear the"
         " violation", "" },
    { 1, "an UNMARKED renamed structural class-A copy in the allowlisted"
         " file stopped failing", k_ipss_a_renamed },
    { 0, "reverting the unmarked renamed class-A copy did not clear the"
         " violation", "" },
};

static int ipss_scratch_root(char *out, size_t cap)
{
    const char *td = env_or("TMPDIR", "test-tmp");
    int rc = csr_mkdirs(td);
    if (rc)
        return rc;
    if (ovf(snprintf(out, cap, "%s/z23-lint-ips.XXXXXX", td), cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
}

static int ipss_plant(const char *root, const char *name, const char *extra)
{
    char path[IPS_PATH], text[IPS_LINE * 2];
    int other = strcmp(name, "other_copy.sh") == 0;
    if (ovf(snprintf(path, sizeof path, "%s/tools/scripts/%s", root, name),
            sizeof path))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "#!/usr/bin/env bash\n"
                     "# %s, not a real tool\n"
                     "%s\n"
                     "%s\n",
                     other ? "a second fixture consumer"
                           : "a fixture consumer",
                     other ? "echo hello2" : "echo hello", extra),
            sizeof text))
        return 2;
    return csr_write(path, text);
}

/* One sandboxed gate run with stdout/stderr silenced, as the shell
 * selftest's run_sandbox did with >/dev/null 2>&1. */
static int ipss_sandbox(const struct ips_cfg *cfg)
{
    FILE *out = fopen("/dev/null", "w");
    FILE *err = fopen("/dev/null", "w");
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return die("z23-lint: cannot open /dev/null\n", "");
    }
    struct ips_cfg c = *cfg;
    c.out = out;
    c.err = err;
    int rc = ips_run_cfg(&c);
    fclose(out);
    fclose(err);
    return rc;
}

static int ipss_expect_case(const struct ips_cfg *cfg, const char *root,
                            const struct ipss_case *c)
{
    int rc = ipss_plant(root, "selftest_copy.sh", c->extra);
    if (rc)
        return rc;
    int got = ipss_sandbox(cfg);
    if ((c->want_fail && got == 0) || (!c->want_fail && got != 0)) {
        fprintf(stderr,
                "%s: SELFTEST FAILED — %s\n", k_ips_gate, c->msg);
        return 2;
    }
    return 0;
}

/* plant(extra) must FAIL, then reverting to the clean body must PASS. */
static int ipss_expect_pair(const struct ips_cfg *cfg, const char *root,
                            const char *name, const char *extra,
                            const char *msg_fail, const char *msg_revert)
{
    int rc = ipss_plant(root, name, extra);
    if (rc)
        return rc;
    if (ipss_sandbox(cfg) == 0) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s\n", k_ips_gate, msg_fail);
        return 2;
    }
    rc = ipss_plant(root, name, "");
    if (rc)
        return rc;
    if (ipss_sandbox(cfg) != 0) {
        fprintf(stderr, "%s: SELFTEST FAILED — %s\n", k_ips_gate,
                msg_revert);
        return 2;
    }
    return 0;
}

static int ipss_two_markers(const struct ips_cfg *cfg, const char *root)
{
    int rc = ipss_plant(root, "selftest_copy.sh", k_ipss_two_markers);
    if (rc)
        return rc;
    if (ipss_sandbox(cfg) == 0) {
        fprintf(stderr, "%s: SELFTEST FAILED — exceeding MARKER_CEILING in"
                " the allowed file was not caught\n", k_ips_gate);
        return 2;
    }
    return 0;
}

int check_identity_parser_single_selftest(void)
{
    char root[IPS_PATH], dir[IPS_PATH], baseline[IPS_PATH];
    char allowed[IPS_PATH];
    int rc = ipss_scratch_root(root, sizeof root);
    if (rc)
        return rc;
    if (ovf(snprintf(dir, sizeof dir, "%s/tools/scripts", root), sizeof dir))
        return 2;
    rc = csr_mkdirs(dir);
    if (rc) {
        rap_rm_rf(root);
        return rc;
    }
    if (ovf(snprintf(baseline, sizeof baseline, "%s/empty_baseline.txt",
                     root), sizeof baseline))
        return 2;
    rc = csr_write(baseline, "");
    if (rc) {
        rap_rm_rf(root);
        return rc;
    }
    if (ovf(snprintf(allowed, sizeof allowed,
                     "%s/tools/scripts/selftest_copy.sh", root),
            sizeof allowed))
        return 2;
    const char *allowedv[1] = { allowed };
    struct ips_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.mode = "FAIL";
    cfg.baseline_path = baseline;
    char scanroot[IPS_PATH];
    if (ovf(snprintf(scanroot, sizeof scanroot, "%s/tools", root),
            sizeof scanroot))
        return 2;
    cfg.scan_root = scanroot;
    cfg.ceiling = 0;
    cfg.marker_ceiling = 1;
    cfg.file_floor = 1;
    cfg.marker_allowed = allowedv;
    cfg.nmarker_allowed = 1;
    cfg.out = stdout;
    cfg.err = stderr;
    int bad = 0;
    for (size_t i = 0; i < sizeof k_ipss_cases / sizeof k_ipss_cases[0]; i++)
        bad |= ipss_expect_case(&cfg, root, &k_ipss_cases[i]) != 0;
    bad |= ipss_expect_pair(&cfg, root, "other_copy.sh", k_ipss_b_marked,
                            "a zcl-identity-parser-allow marker in an"
                            " unauthorized file was not caught",
                            "reverting the unauthorized marker did not"
                            " clear the violation") != 0;
    bad |= ipss_expect_pair(&cfg, root, "other_copy.sh", k_ipss_a_marked,
                            "a zcl-identity-parser-allow-marked class-A"
                            " copy in an unauthorized file was not caught",
                            "reverting the unauthorized class-A marker did"
                            " not clear the violation") != 0;
    bad |= ipss_two_markers(&cfg, root) != 0;
    rap_rm_rf(root);
    if (bad)
        return 2;
    printf("[%s] SELFTEST PASS (clean passes; named and renamed class-A"
           " copies fail; class-B copies fail; reverted copies pass; an"
           " allowlisted+in-budget marker does not count, in class A —"
           " single-line AND multi-line body — as well as class B; an"
           " UNMARKED class-A copy in that same file still fails; a marker"
           " in an unauthorized file, or over MARKER_CEILING, fails in"
           " either class)\n", k_ips_gate);
    return 0;
}
