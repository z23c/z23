/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest for check-hotswap-denied-leaves (sibling of
 * gate_hotswap_denied_leaves.c — the run() implementation lives there, its
 * declarations in lintc.h). Port of the 9-case --selftest of
 * tools/lint/check_hotswap_denied_leaves.sh: an unmodified sandbox copy
 * passes, a denied leaf trips as an eligibility PROBE, as one entry of a
 * space-separated swappable LEAF LIST, as a resident PROBE CASE, and inside
 * a C ZCL_HOTSWAP_GEN leaf table; the same leaf named only in a COMMENT or
 * only in RESIDENT code does not trip; a missing denylist and an empty
 * denylist are both exit 2; the real tree is exit 0. Every fixture is
 * planted under a private mkdtemp() beneath the worktree's own build/ and
 * removed on the way out — never under core/, never in the real tree.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"

extern FILE *g_hdl_out, *g_hdl_err;

/* Each level below is built by one "%s/<literal-suffix>" onto the level
 * before it (dir -> sandbox -> turoot -> fixture); every level's cap grows
 * by a fixed margin over its source's so -Wformat-truncation's worst-case
 * proof always has headroom, however deep the chain. */
enum {
    HDLS_BUF = 1 << 16,
    HDLS_PATH = 4096,
    HDLS_L1 = HDLS_PATH + 512,
    HDLS_L2 = HDLS_L1 + 512,
    HDLS_L3 = HDLS_L2 + 512,
};

static int hdls_copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "r");
    if (!in) return 1;
    FILE *out = fopen(dst, "w");
    if (!out) { fclose(in); return 1; }
    char buf[8192];
    size_t n;
    int bad = 0;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0)
        if (fwrite(buf, 1, n, out) != n) { bad = 1; break; }
    bad |= ferror(in);
    fclose(in);
    if (fclose(out) != 0) bad = 1;
    return bad;
}

static int hdls_append(const char *path, const char *text)
{
    FILE *f = fopen(path, "a");
    if (!f) return 1;
    int bad = fputs(text, f) < 0;
    return fclose(f) != 0 ? 1 : bad;
}

static int hdls_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) return 1;
    int bad = fputs(text, f) < 0;
    return fclose(f) != 0 ? 1 : bad;
}

static int hdls_is_manifest_name(const char *name)
{
    if (strcmp(name, "hotfork_capsules.def") == 0) return 1;
    if (strcmp(name, "hotswap_denied_leaves.def") == 0) return 0;
    size_t nl = strlen(name);
    return nl > 11 && strncmp(name, "hotswap", 7) == 0
        && strcmp(name + nl - 4, ".def") == 0;
}

/* Seed the sandbox with every real hot-swap manifest EXCEPT the denylist
 * itself, mirroring `cp engine/composition/hotswap*.def "$sandbox/"`. */
static int hdls_seed_sandbox(const char *real_dir, const char *sandbox)
{
    DIR *d = opendir(real_dir);
    if (!d) return 1;
    struct dirent *de;
    int bad = 0;
    while (!bad && (de = readdir(d)) != NULL) {
        if (!hdls_is_manifest_name(de->d_name)) continue;
        char src[HDLS_PATH], dst[HDLS_L2];
        snprintf(src, sizeof src, "%s/%s", real_dir, de->d_name);
        snprintf(dst, sizeof dst, "%s/%s", sandbox, de->d_name);
        bad |= hdls_copy_file(src, dst);
    }
    closedir(d);
    return bad;
}

static int hdls_run_case(const char *scan, const char *deny, const char *turoot,
                         char *out, size_t outcap, char *err, size_t errcap,
                         int *rc)
{
    setenv("ZCL_HOTSWAP_DENY_SCAN_DIR", scan, 1);
    setenv("ZCL_HOTSWAP_DENYLIST", deny, 1);
    setenv("ZCL_HOTSWAP_DENY_TU_ROOT", turoot ? turoot : ".", 1);
    FILE *out_f = tmpfile(), *err_f = tmpfile();
    if (!out_f || !err_f) {
        if (out_f) fclose(out_f);
        if (err_f) fclose(err_f);
        return die("z23-lint: tmpfile failed\n", "");
    }
    g_hdl_out = out_f;
    g_hdl_err = err_f;
    *rc = check_hotswap_denied_leaves_run(0, NULL);
    int bad = csr_slurp(out_f, out, outcap) || csr_slurp(err_f, err, errcap);
    fclose(out_f);
    fclose(err_f);
    g_hdl_out = stdout;
    g_hdl_err = stderr;
    unsetenv("ZCL_HOTSWAP_DENY_SCAN_DIR");
    unsetenv("ZCL_HOTSWAP_DENYLIST");
    unsetenv("ZCL_HOTSWAP_DENY_TU_ROOT");
    return bad ? 2 : 0;
}

static int hdls_fail(const char *why, const char *out, const char *err)
{
    fprintf(stderr, "check_hotswap_denied_leaves selftest: FAIL — %s\n", why);
    fputs(out, stderr);
    fputs(err, stderr);
    return 1;
}

/* Cases 0, 5, 6, 7: no fixture mutation, just the sandbox/denylist paths. */
static int hdls_case_baseline(const char *sandbox, const char *deny,
                              const char *missing, const char *empty)
{
    char out[HDLS_BUF], err[HDLS_BUF];
    int rc;
    if (hdls_run_case(sandbox, deny, NULL, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    if (rc != 0)
        return hdls_fail("an unmodified sandbox copy did not pass", out, err);

    if (hdls_run_case(sandbox, missing, NULL, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    if (rc != 2)
        return hdls_fail("a missing denylist did not fail closed (wanted 2)", out, err);

    if (hdls_write(empty, "/* every row commented out */\n"))
        return die("z23-lint: write failed\n", "");
    if (hdls_run_case(sandbox, empty, NULL, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    if (rc != 2)
        return hdls_fail("an empty denylist did not fail closed (wanted 2)", out, err);

    if (hdls_run_case("engine/composition", deny, NULL, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    if (rc != 0)
        return hdls_fail("the real tree does not pass", out, err);
    return 0;
}

static int hdls_case_probe(const char *sandbox, const char *deny)
{
    char eligible[HDLS_L2], backup[HDLS_L2];
    snprintf(eligible, sizeof eligible, "%s/hotswap_eligible.def", sandbox);
    snprintf(backup, sizeof backup, "%s/eligible.orig", sandbox);
    if (hdls_copy_file(eligible, backup))
        return die("z23-lint: read failed: %s\n", eligible);
    if (hdls_append(eligible,
        "HOTSWAP_ELIGIBLE(\"engine/controllers/src/chain_native_handlers.c\") "
        "HOTSWAP_PROBE(\"core.chain.block.get\")\n"))
        return die("z23-lint: write failed\n", "");
    char out[HDLS_BUF], err[HDLS_BUF];
    int rc;
    if (hdls_run_case(sandbox, deny, NULL, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    int bad = 0;
    if (rc != 1)
        bad = hdls_fail("a denied leaf planted as a HOTSWAP_PROBE did not trip the gate", out, err);
    else if (!strstr(err, "core.chain.block.get"))
        bad = hdls_fail("the failure did not name the denied leaf", out, err);
    if (hdls_copy_file(backup, eligible) && !bad)
        bad = die("z23-lint: write failed: %s\n", eligible);
    return bad;
}

static int hdls_case_leaf_list(const char *sandbox, const char *deny)
{
    char swappable[HDLS_L2], backup[HDLS_L2];
    snprintf(swappable, sizeof swappable, "%s/hotswap_swappable.def", sandbox);
    snprintf(backup, sizeof backup, "%s/swappable.orig", sandbox);
    if (hdls_copy_file(swappable, backup))
        return die("z23-lint: read failed: %s\n", swappable);
    if (hdls_append(swappable,
        "HOTSWAP_SWAPPABLE(\"engine/controllers/src/chain_native_handlers.c\",\n"
        "                  \"core.consensus.utxo.audit core.chain.transaction.get\")\n"))
        return die("z23-lint: write failed\n", "");
    char out[HDLS_BUF], err[HDLS_BUF];
    int rc;
    if (hdls_run_case(sandbox, deny, NULL, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    int bad = rc != 1
        ? hdls_fail("a denied leaf inside a swappable leaf LIST did not trip the gate", out, err)
        : 0;
    if (hdls_copy_file(backup, swappable) && !bad)
        bad = die("z23-lint: write failed: %s\n", swappable);
    return bad;
}

static int hdls_case_probe_case(const char *sandbox, const char *deny)
{
    char cases[HDLS_L2], backup[HDLS_L2];
    snprintf(cases, sizeof cases, "%s/hotswap_probe_cases.def", sandbox);
    snprintf(backup, sizeof backup, "%s/probe.orig", sandbox);
    if (hdls_copy_file(cases, backup))
        return die("z23-lint: read failed: %s\n", cases);
    if (hdls_append(cases,
        "HOTSWAP_PROBE_CASE(\"command.chain.block.get.v1\", \"command\",\n"
        "    \"core.chain.block.get\", \"{}\", \"zcl.block.v1\", 4096)\n"))
        return die("z23-lint: write failed\n", "");
    char out[HDLS_BUF], err[HDLS_BUF];
    int rc;
    if (hdls_run_case(sandbox, deny, NULL, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    int bad = rc != 1
        ? hdls_fail("a denied leaf planted as a probe CASE did not trip the gate", out, err)
        : 0;
    if (hdls_copy_file(backup, cases) && !bad)
        bad = die("z23-lint: write failed: %s\n", cases);
    return bad;
}

/* Case 4: a leaf named only in a COMMENT (with a stray star in its body, to
 * prove the block-comment stripper anchors on the real close sequence
 * rather than the first star it meets) must not trip the gate. Reuses the
 * eligible.orig backup left behind by hdls_case_probe. */
static int hdls_case_comment_only(const char *sandbox, const char *deny,
                                  const char *eligible, const char *backup)
{
    if (hdls_append(eligible,
        "/* core.chain.block.get is denied * see hotswap_denied_leaves.def */\n"))
        return die("z23-lint: write failed\n", "");
    char out[HDLS_BUF], err[HDLS_BUF];
    int rc;
    if (hdls_run_case(sandbox, deny, NULL, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    int bad = rc != 0
        ? hdls_fail("a denied leaf mentioned only in a COMMENT tripped the gate", out, err)
        : 0;
    if (hdls_copy_file(backup, eligible) && !bad)
        return die("z23-lint: write failed: %s\n", eligible);
    return bad;
}

/* Case 4b: the C-side leaf table — a denied leaf inside a ZCL_HOTSWAP_GEN
 * block must trip the gate and name the TU; the same leaf named only in
 * RESIDENT code (outside the block) must not be reported. */
static int hdls_case_gen_table(const char *sandbox, const char *deny,
                               const char *eligible, const char *backup)
{
    char turoot[HDLS_L2], fixture[HDLS_L3];
    snprintf(turoot, sizeof turoot, "%s/turoot", sandbox);
    if (mkdir(turoot, 0700) != 0 && errno != EEXIST)
        return die("z23-lint: mkdir failed: %s\n", turoot);
    snprintf(fixture, sizeof fixture, "%s/gen_fixture.c", turoot);
    if (hdls_write(fixture,
        "#ifdef ZCL_HOTSWAP_GEN\n"
        "static const struct zcl_hotswap_leaf_replacement k_leaves[] = {\n"
        "    { \"core.chain.block.get\", tramp_getblock },\n"
        "};\n"
        "ZCL_HOTSWAP_EXPORT_LEAVES(k_leaves, 1)\n"
        "#endif\n"
        "/* resident code may name \"core.chain.transaction.get\" freely */\n"
        "static const char *k_resident = \"core.chain.transaction.get\";\n"))
        return die("z23-lint: write failed: %s\n", fixture);
    if (hdls_append(eligible,
        "HOTSWAP_ELIGIBLE(\"gen_fixture.c\") HOTSWAP_PROBE(\"core.status\")\n"))
        return die("z23-lint: write failed\n", "");
    char out[HDLS_BUF], err[HDLS_BUF];
    int rc;
    if (hdls_run_case(sandbox, deny, turoot, out, sizeof out, err, sizeof err, &rc))
        return die("z23-lint: read failed\n", "");
    int bad;
    if (rc != 1)
        bad = hdls_fail("a denied leaf in a ZCL_HOTSWAP_GEN leaf table did not trip the gate", out, err);
    else if (!strstr(err, "gen_fixture.c stages denied leaf"))
        bad = hdls_fail("the C-table failure did not name the TU", out, err);
    else if (strstr(err, "core.chain.transaction.get"))
        bad = hdls_fail("a leaf named only in RESIDENT code was reported", out, err);
    else
        bad = 0;
    if (hdls_copy_file(backup, eligible) && !bad)
        bad = die("z23-lint: write failed: %s\n", eligible);
    return bad;
}

static int hdls_case_comment_and_gen_table(const char *sandbox, const char *deny)
{
    char eligible[HDLS_L2], backup[HDLS_L2];
    snprintf(eligible, sizeof eligible, "%s/hotswap_eligible.def", sandbox);
    snprintf(backup, sizeof backup, "%s/eligible.orig", sandbox);

    int bad = hdls_case_comment_only(sandbox, deny, eligible, backup);
    if (!bad) bad = hdls_case_gen_table(sandbox, deny, eligible, backup);
    return bad;
}

int check_hotswap_denied_leaves_selftest(void)
{
    char tmpl[HDLS_PATH];
    snprintf(tmpl, sizeof tmpl, "build/z23-lint-hdl-selftest.XXXXXX");
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        fprintf(stderr, "check_hotswap_denied_leaves selftest: FATAL — no scratch dir\n");
        return 2;
    }
    char sandbox[HDLS_L1], missing[HDLS_L1], empty[HDLS_L1];
    snprintf(sandbox, sizeof sandbox, "%s/config", dir);
    snprintf(missing, sizeof missing, "%s/does-not-exist.def", dir);
    snprintf(empty, sizeof empty, "%s/empty.def", dir);
    const char *deny = "engine/composition/hotswap_denied_leaves.def";

    int bad = mkdir(sandbox, 0700) != 0
        || hdls_seed_sandbox("engine/composition", sandbox);
    if (!bad) bad = hdls_case_baseline(sandbox, deny, missing, empty);
    if (!bad) bad = hdls_case_probe(sandbox, deny);
    if (!bad) bad = hdls_case_leaf_list(sandbox, deny);
    if (!bad) bad = hdls_case_probe_case(sandbox, deny);
    if (!bad) bad = hdls_case_comment_and_gen_table(sandbox, deny);

    rap_rm_rf(dir);
    if (bad) return 1;
    return st_ok(0,
        "check_hotswap_denied_leaves selftest: PASS — 9 cases (probe, leaf list, "
        "C leaf table, probe case, comment-only, missing denylist, empty "
        "denylist, clean copy, real tree)\n");
}
