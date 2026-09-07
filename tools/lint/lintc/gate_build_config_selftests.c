/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: planted-violation selftests for the gate_build_config.c family
 * (check-tu-random-seed, check-privileged-transition-receipt,
 * check-asan-adx-exception). Split out of gate_build_config.c to keep that
 * file under the family line-count ceiling; the two files share their
 * gate internals through gate_build_config_priv.h.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_build_config_priv.h"

static const char k_trs_ok[] =
    "ZCL_TU_RANDOM_SEED = -frandom-seed=$<\n"
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS) $(ZCL_TU_RANDOM_SEED)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

static const char k_trs_missing[] =
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS) $(ZCL_TU_RANDOM_SEED)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

static const char k_trs_unseeded[] =
    "ZCL_TU_RANDOM_SEED = -frandom-seed=$<\n"
    "all:\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) dep \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(CFLAGS)\n"
    "\t@$(BUILD_EPOCH_OBJECT_TOOL) coverage \"$@\" \"$<\" \\\n"
    "\t  -- \\\n"
    "\t  $(CC) $(COV)\n";

static int trs_case(FILE *out, const char *content, int want_rc,
    const char *want_substr)
{
    int bad = 0;
    char ob[4096];
    rewind(out);
    if (ftruncate(fileno(out), 0) != 0)
        bad = 1;
    if (csr_write("./Makefile", content))
        bad = 1;
    int rc = trs_check(out);
    if (csr_slurp(out, ob, sizeof ob))
        bad = 1;
    bad |= rc != want_rc || strstr(ob, want_substr) == NULL;
    return bad;
}

int check_tu_random_seed_selftest(void)
{
    char cwd[4096];
    if (!getcwd(cwd, sizeof cwd))
        return die("z23-lint: getcwd failed\n", "");
    char tmpl[] = "/tmp/z23-lint-trs-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile();
    if (!out) {
        rmdir(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    int bad = 0;
    if (chdir(root) != 0) {
        fclose(out);
        rmdir(root);
        return die("z23-lint: cannot scan %s\n", root);
    }

    bad |= trs_case(out, k_trs_missing, 1,
        "FAIL: Makefile does not define ZCL_TU_RANDOM_SEED");
    bad |= trs_case(out, k_trs_ok, 0,
        "check-tu-random-seed: PASS — 1/1 per-TU object recipes "
        "pin GCC's random seed (1 coverage recipe exempt)");
    bad |= trs_case(out, k_trs_unseeded, 1,
        "FAIL: Makefile:3 — per-TU object recipe does not carry $("
        "ZCL_TU_RANDOM_SEED)");

    fclose(out);
    unlink("./Makefile");
    if (chdir(cwd) != 0)
        return die("z23-lint: cannot scan %s\n", cwd);
    rmdir(root);
    if (bad)
        fputs("FAIL: check_tu_random_seed selftest\n", stderr);
    return st_ok(bad, "check_tu_random_seed selftest: OK\n");
}
static int ptr_st_save_env(int *had_d, char *oldd, size_t oldd_sz, int *had_b,
    char *oldb, size_t oldb_sz)
{
    const char *ed = getenv("ZCL_PRIV_RECEIPT_DEF_DIR");
    const char *eb = getenv("ZCL_PRIV_RECEIPT_BASELINE");
    int bad = 0;
    *had_d = 0;
    *had_b = 0;
    if (ed) {
        if (ovf(snprintf(oldd, oldd_sz, "%s", ed), oldd_sz))
            bad = 1;
        else
            *had_d = 1;
    }
    if (eb) {
        if (ovf(snprintf(oldb, oldb_sz, "%s", eb), oldb_sz))
            bad = 1;
        else
            *had_b = 1;
    }
    return bad;
}

static int ptr_st_paths(const char *root, char *defs, size_t defs_sz, char *empty,
    size_t empty_sz, char *base, size_t base_sz, char *handler, size_t handler_sz,
    char *defa, size_t defa_sz)
{
    int bad = 0;
    bad |= ovf(snprintf(defs, defs_sz, "%s/defs", root), defs_sz);
    bad |= ovf(snprintf(empty, empty_sz, "%s/empty", root), empty_sz);
    bad |= ovf(snprintf(base, base_sz, "%s/baseline.txt", root), base_sz);
    bad |= ovf(snprintf(handler, handler_sz, "%s/handler.c", root), handler_sz);
    bad |= ovf(snprintf(defa, defa_sz, "%s/defs/a.def", root), defa_sz);
    bad |= (csr_mkdirs(defs) || csr_mkdirs(empty));
    return bad;
}

static int ptr_case_run(const char *defs, const char *base, const char *root,
    FILE *out, FILE *err, char *ob, size_t obsz, char *ebout, size_t ebsz, int *rc)
{
    int bad = 0;
    bad |= (psp_st_reset(out) || psp_st_reset(err));
    *rc = ptr_scan(defs, base, root, out, err);
    bad |= (csr_slurp(out, ob, obsz) || csr_slurp(err, ebout, ebsz));
    return bad;
}

static int ptr_case_clean_two_exempt(const char *defs, const char *base,
    const char *root, FILE *out, FILE *err)
{
    char ob[8192], ebout[8192];
    int rc = 0, bad = 0;
    bad |= csr_write(base,
        "app.test.clean  exempt: fixture\n"
        "app.test.dev    exempt: fixture\n") != 0;
    bad |= ptr_case_run(defs, base, root, out, err, ob, sizeof ob, ebout, sizeof ebout, &rc);
    bad |= rc != 0
        || strstr(ob, "check_privileged_transition_receipt: clean — 2 owner-mutating leaves, all dispositioned (0 receipt, 2 exempt)") == NULL;
    return bad;
}

static int ptr_case_missing_dispositions(const char *defs, const char *base,
    const char *root, FILE *out, FILE *err)
{
    char ob[8192], ebout[8192];
    int rc = 0, bad = 0;
    bad |= csr_write(base, "# none\n") != 0;
    bad |= ptr_case_run(defs, base, root, out, err, ob, sizeof ob, ebout, sizeof ebout, &rc);
    bad |= rc != 1
        || strstr(ebout, "app.test.clean") == NULL
        || strstr(ebout, "app.test.dev") == NULL
        || strstr(ebout, "Every ZCL_COMMAND_AUTH_OWNER + EFFECT_MUTATE/DESTRUCTIVE leaf must be dispositioned.") == NULL;
    return bad;
}

static int ptr_case_malformed_disposition(const char *defs, const char *base,
    const char *root, FILE *out, FILE *err)
{
    char ob[8192], ebout[8192];
    int rc = 0, bad = 0;
    bad |= csr_write(base,
        "app.test.clean  nope:xyz\n"
        "app.test.dev    exempt: fixture\n") != 0;
    bad |= ptr_case_run(defs, base, root, out, err, ob, sizeof ob, ebout, sizeof ebout, &rc);
    bad |= rc != 1
        || strstr(ebout, "app.test.clean (malformed disposition: 'nope:xyz' — must start receipt: or exempt:)") == NULL;
    return bad;
}

static int ptr_case_receipt_present_pass(const char *defs, const char *base,
    const char *handler, const char *root, FILE *out, FILE *err)
{
    char ob[8192], ebout[8192];
    int rc = 0, bad = 0;
    bad |= csr_write(handler, "int x(void) { authority_receipt_x_available(0); return 0; }\n") != 0;
    bad |= csr_write(base,
        "app.test.clean  receipt:handler.c\n"
        "app.test.dev    exempt: fixture\n") != 0;
    bad |= ptr_case_run(defs, base, root, out, err, ob, sizeof ob, ebout, sizeof ebout, &rc);
    bad |= rc != 0 || strstr(ob, "(1 receipt, 1 exempt)") == NULL;
    return bad;
}

static int ptr_case_receipt_missing_call_fail(const char *defs, const char *base,
    const char *handler, const char *root, FILE *out, FILE *err)
{
    char ob[8192], ebout[8192];
    int rc = 0, bad = 0;
    bad |= csr_write(handler, "int x(void) { return 0; }\n") != 0;
    bad |= ptr_case_run(defs, base, root, out, err, ob, sizeof ob, ebout, sizeof ebout, &rc);
    bad |= rc != 1
        || strstr(ebout, "app.test.clean -> handler.c (no authority_receipt verify call)") == NULL;
    return bad;
}

static int ptr_case_receipt_file_missing(const char *defs, const char *base,
    const char *root, FILE *out, FILE *err)
{
    char ob[8192], ebout[8192];
    int rc = 0, bad = 0;
    bad |= csr_write(base,
        "app.test.clean  receipt:missing.c\n"
        "app.test.dev    exempt: fixture\n") != 0;
    bad |= ptr_case_run(defs, base, root, out, err, ob, sizeof ob, ebout, sizeof ebout, &rc);
    bad |= rc != 1 || strstr(ebout, "app.test.clean -> missing.c (file not found)") == NULL;
    return bad;
}

static int ptr_case_empty_defs_dir_fatal(const char *empty, const char *base,
    const char *root, FILE *out, FILE *err)
{
    char ob[8192], ebout[8192];
    int rc = 0, bad = 0;
    bad |= ptr_case_run(empty, base, root, out, err, ob, sizeof ob, ebout, sizeof ebout, &rc);
    bad |= rc != 2 || strstr(ebout, "FATAL") == NULL;
    return bad;
}

static int ptr_case_public_leaf_fatal(const char *defs, const char *base,
    const char *defa, const char *k_pub, const char *root, FILE *out, FILE *err)
{
    char ob[8192], ebout[8192];
    int rc = 0, bad = 0;
    bad |= csr_write(defa, k_pub) != 0;
    bad |= ptr_case_run(defs, base, root, out, err, ob, sizeof ob, ebout, sizeof ebout, &rc);
    bad |= rc != 2 || strstr(ebout, "FATAL") == NULL;
    return bad;
}

int check_privileged_transition_receipt_selftest(void)
{
    char tmpl[] = "/tmp/z23-lint-ptr-XXXXXX";
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdir failed: %s\n", "/tmp");
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        (void)rap_rm_rf(root);
        return die("z23-lint: tmpfile failed\n", "");
    }
    char oldd[4096], oldb[4096];
    int had_d = 0, had_b = 0, bad = 0;
    bad |= ptr_st_save_env(&had_d, oldd, sizeof oldd, &had_b, oldb, sizeof oldb);

    char defs[4096], empty[4096], base[4096], handler[4096], defa[4096];
    static const char k_def[] =
        "ZCL_COMMAND_READY_COMMAND(\n"
        "    \"app.test.clean\", \"parent\", \"has (parens) and \\\"quotes\\\" inside\",\n"
        "    ZCL_COMMAND_AUTH_OWNER, ZCL_COMMAND_EFFECT_MUTATE)\n"
        "ZCL_COMMAND_DEV_COMMAND(\n"
        "    \"app.test.dev\", ZCL_COMMAND_AUTH_OWNER, ZCL_COMMAND_EFFECT_DESTRUCTIVE)\n";
    static const char k_pub[] =
        "ZCL_COMMAND_READY_COMMAND(\n"
        "    \"app.test.public\", ZCL_COMMAND_AUTH_PUBLIC, ZCL_COMMAND_EFFECT_MUTATE)\n";
    bad |= ptr_st_paths(root, defs, sizeof defs, empty, sizeof empty, base, sizeof base,
        handler, sizeof handler, defa, sizeof defa);
    bad |= csr_write(defa, k_def) != 0;

    bad |= (!bad && ptr_st_env(defs, base));

    bad |= ptr_case_clean_two_exempt(defs, base, root, out, err);
    bad |= ptr_case_missing_dispositions(defs, base, root, out, err);
    bad |= ptr_case_malformed_disposition(defs, base, root, out, err);
    bad |= ptr_case_receipt_present_pass(defs, base, handler, root, out, err);
    bad |= ptr_case_receipt_missing_call_fail(defs, base, handler, root, out, err);
    bad |= ptr_case_receipt_file_missing(defs, base, root, out, err);
    bad |= ptr_case_empty_defs_dir_fatal(empty, base, root, out, err);
    bad |= ptr_case_public_leaf_fatal(defs, base, defa, k_pub, root, out, err);

    fclose(out);
    fclose(err);
    ptr_st_clear_env(had_d, oldd, had_b, oldb);
    (void)rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_privileged_transition_receipt selftest\n", stderr);
    return st_ok(bad, "check_privileged_transition_receipt selftest: OK\n");
}
static int aae_prepare(char *tmp, size_t tmpsz, const char *mk, char *copy,
    size_t copysz, char *nextp, size_t nextpsz)
{
    const char *td = env_or("TMPDIR", "/tmp");
    if (ovf(snprintf(tmp, tmpsz, "%s/z23-lint-asan-adx-XXXXXX", td), tmpsz))
        return 2;
    if (!mkdtemp(tmp))
        return die("z23-lint: mkdir failed: %s\n", td);
    if (ovf(snprintf(copy, copysz, "%s/Makefile", tmp), copysz)
        || ovf(snprintf(nextp, nextpsz, "%s/Makefile.next", tmp), nextpsz)
        || aae_copy(mk, copy)) {
        (void)rap_rm_rf(tmp);
        return 2;
    }
    if (setenv("ZCL_ASAN_ADX_MAKEFILE", copy, 1) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: setenv failed\n", "");
    }
    return 0;
}

static int aae_expect_clean_pass(char *logb, size_t logbsz, const char *tmp)
{
    int code = 0;
    int rc = cic_invoke("check-asan-adx-exception", 0, logb, logbsz, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code != 0) {
        (void)rap_rm_rf(tmp);
        return code;
    }
    return 0;
}

static int aae_expect_mutated_fail(char *copy, char *nextp, char *logb,
    size_t logbsz, const char *tmp)
{
    static const char from[] = "core/modules/sapling/src/bn254_accel.c";
    static const char to[] =
        "core/modules/sapling/src/bn254_accel.c core/modules/sapling/src/unaudited_accel.c";
    if (aae_rewrite_first(copy, nextp, from, to) || rename(nextp, copy) != 0) {
        (void)rap_rm_rf(tmp);
        return die("z23-lint: write failed\n", "");
    }
    int code = 0;
    int rc = cic_invoke("check-asan-adx-exception", 1, logb, logbsz, &code);
    if (rc) {
        (void)rap_rm_rf(tmp);
        return rc;
    }
    if (code == 0) {
        (void)rap_rm_rf(tmp);
        return aae_fail("selftest expanded the exception allowlist but the gate passed");
    }
    if (strstr(logb, "exception source allowlist changed") == NULL) {
        (void)rap_rm_rf(tmp);
        return aae_fail("selftest failed for the wrong reason");
    }
    return 0;
}

int check_asan_adx_exception_selftest(void)
{
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    if (chdir(root) != 0)
        return die("z23-lint: cannot scan %s\n", root);
    const char *mk = aae_makefile();
    char tmp[4096], copy[4096], nextp[4096];
    static char logb[256 * 1024];
    int rc = aae_prepare(tmp, sizeof tmp, mk, copy, sizeof copy, nextp, sizeof nextp);
    if (rc)
        return rc;
    rc = aae_expect_clean_pass(logb, sizeof logb, tmp);
    if (rc)
        return rc;
    rc = aae_expect_mutated_fail(copy, nextp, logb, sizeof logb, tmp);
    if (rc)
        return rc;
    (void)rap_rm_rf(tmp);
    if (fputs("check_asan_adx_exception: selftest PASS — an allowlist expansion is rejected\n",
              stdout) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}
