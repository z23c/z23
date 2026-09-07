/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the planted-violation fixture selftest of the
 * check-source-identity-authority family (the 700-line family ceiling
 * split). The gate body and the list helpers live in
 * gate_source_identity_authority.c, the walk and per-file counter in
 * gate_source_identity_authority_scan.c, and the baseline/evaluate/report
 * in gate_source_identity_authority_ratchet.c; the files share their
 * internals through gate_source_identity_authority_priv.h.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_source_identity_authority_priv.h"

static const char k_gate[] = "check_source_identity_authority";

/* ── fixture self-test ────────────────────────────────────────────────── */

static const char k_st_clean[] =
    "#!/usr/bin/env bash\n"
    "# a clean consumer: reads a DIFFERENT schema (agent RPC "
    "public_status), and\n"
    "# the schema-anchored reader for a real agentbuild response.\n"
    ". tools/scripts/source_identity_lib.sh\n"
    "status_id=\"$(zcl_json_first_string \"$agent_status\" "
    "\"source_id_sha256\")\"\n"
    "agentbuild=\"$(\"$bin\" agentbuild 2>&1)\"\n"
    "observed=\"$(zcl_agentbuild_v2_top_source_id \"$agentbuild\")\"\n";

static const char k_st_class_r[] =
    "#!/usr/bin/env bash\n"
    ". tools/scripts/source_identity_lib.sh\n"
    "candidate_agentbuild=\"$(timeout 30 \"$candidate\" agentbuild 2>&1)\"\n"
    "candidate_source_id=\"$(zcl_json_first_sha256 "
    "\"$candidate_agentbuild\" source_id_sha256)\"\n";

static const char k_st_class_p[] =
    "#!/usr/bin/env bash\n"
    "record=\"$(\"$tool\" capture-record 2>/dev/null)\"\n"
    "read -r source_id clean mutation <<< \"$record\"\n"
    "printf '\"source_id_sha256\":\"%s\"' \"$source_id\"\n";

struct sia_st { char tmp[4096]; char log[65536]; };

static int sia_st_env(struct sia_st *st, const char *scan_root)
{
    char tools[4096], mk[4096], bl[4096];
    if (ovf(snprintf(tools, sizeof tools, "%s/%s", st->tmp, scan_root),
            sizeof tools)
        || ovf(snprintf(mk, sizeof mk, "%s/no-such-makefile", st->tmp),
               sizeof mk)
        || ovf(snprintf(bl, sizeof bl, "%s/empty_baseline.txt", st->tmp),
               sizeof bl))
        return 2;
    if (setenv("ZCL_SOURCE_AUTHORITY_SCAN_ROOT", tools, 1) != 0
        || setenv("ZCL_SOURCE_AUTHORITY_MAKEFILE", mk, 1) != 0
        || setenv("ZCL_SOURCE_AUTHORITY_BASELINE", bl, 1) != 0
        || setenv("ZCL_SOURCE_AUTHORITY_CEILING", "0", 1) != 0
        || setenv("ZCL_SOURCE_AUTHORITY_FILE_FLOOR", "1", 1) != 0
        || setenv("ZCL_LINT_MODE", "FAIL", 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    return 0;
}

/* One real gate run against the sandbox, stdout+stderr captured into
 * st->log (the shell's `>"$tmp/out.log" 2>&1`). */
static int sia_st_invoke(struct sia_st *st, const char *scan_root)
{
    int rc = sia_st_env(st, scan_root);
    if (rc)
        return rc;
    FILE *out = tmpfile(), *errf = tmpfile();
    if (!out || !errf) {
        if (out)
            fclose(out);
        if (errf)
            fclose(errf);
        return die("z23-lint: tmpfile failed\n", "");
    }
    rc = sia_impl(out, errf);
    char eb[16384];
    if (csr_slurp(out, st->log, sizeof st->log)
        || csr_slurp(errf, eb, sizeof eb))
        rc = 2;
    fclose(out);
    fclose(errf);
    size_t used = strlen(st->log);
    if (rc == 0 || rc == 1) {
        if (ovf(snprintf(st->log + used, sizeof st->log - used, "%s%s",
                         used ? "\n" : "", eb), sizeof st->log - used))
            rc = 2;
    }
    return rc;
}

/* sed 's/^/  /' over the captured log, to stderr. */
static void sia_st_dump(const struct sia_st *st)
{
    for (const char *p = st->log; *p; ) {
        const char *nl = strchr(p, '\n');
        if (!nl) {
            fprintf(stderr, "  %s\n", p);
            break;
        }
        fprintf(stderr, "  %.*s\n", (int)(nl - p), p);
        p = nl + 1;
    }
}

static int sia_st_fail(const char *msg)
{
    fprintf(stderr, "%s: SELFTEST FAILED — %s\n", k_gate, msg);
    return 2;
}

static int sia_st_write(struct sia_st *st, const char *name,
                        const char *text)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/tools/scripts/%s", st->tmp,
                     name), sizeof path))
        return 2;
    return csr_write(path, text);
}

static int sia_st_rm(struct sia_st *st, const char *name)
{
    char path[4096];
    if (ovf(snprintf(path, sizeof path, "%s/tools/scripts/%s", st->tmp,
                     name), sizeof path))
        return 2;
    return unlink(path) != 0;
}

/* plant a violator, prove the gate fails on it and names it, revert it,
 * prove the gate clears. */
static int sia_st_violator(struct sia_st *st, const char *name,
                           const char *text, const char *needle,
                           const char *fail_msg, const char *name_msg,
                           const char *clear_msg)
{
    int rc = sia_st_write(st, name, text);
    if (rc == 0)
        rc = sia_st_invoke(st, "tools");
    if (rc == 0)
        return sia_st_fail(fail_msg);
    if (!strstr(st->log, needle))
        return sia_st_fail(name_msg);
    if (sia_st_rm(st, name) != 0)
        return sia_st_fail("fixture removal failed");
    rc = sia_st_invoke(st, "tools");
    if (rc != 0)
        return sia_st_fail(clear_msg);
    return 0;
}

int check_source_identity_authority_selftest(void)
{
    char tmpl[4096];
    (void)csr_mkdirs("test-tmp");
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-sia-XXXXXX",
                     env_or("TMPDIR", "test-tmp")), sizeof tmpl))
        return 2;
    if (!mkdtemp(tmpl))
        return die("z23-lint: mkdtemp failed\n", "");
    struct sia_st st;
    if (ovf(snprintf(st.tmp, sizeof st.tmp, "%s", tmpl), sizeof st.tmp))
        return 2;
    int bad = 0;
    char d1[4096], d2[4096], bl[4096];
    bad |= ovf(snprintf(d1, sizeof d1, "%s/tools/scripts", st.tmp),
               sizeof d1) != 0;
    bad |= ovf(snprintf(d2, sizeof d2, "%s/tools/lint", st.tmp),
               sizeof d2) != 0;
    bad |= ovf(snprintf(bl, sizeof bl, "%s/empty_baseline.txt", st.tmp),
               sizeof bl) != 0;
    if (!bad)
        bad |= csr_mkdirs(d1) || csr_mkdirs(d2) || csr_write(bl, "");
    if (!bad)
        bad |= sia_st_write(&st, "selftest_clean.sh", k_st_clean);
    if (!bad && sia_st_invoke(&st, "tools") != 0) {
        (void)sia_st_fail("a clean consumer (different schema, plus a "
                          "properly schema-anchored agentbuild read) was "
                          "reported as a violation");
        sia_st_dump(&st);
        bad = 1;
    }
    if (!bad)
        bad = sia_st_violator(&st, "selftest_class_r.sh", k_st_class_r,
                              "class_r",
                              "a positional agentbuild source_id_sha256 "
                              "read (class R) did not fail the gate",
                              "class-R violation did not name the "
                              "offending file",
                              "reverting the class-R copy did not clear "
                              "the violation") != 0;
    if (!bad)
        bad = sia_st_violator(&st, "selftest_class_p.sh", k_st_class_p,
                              "class_p",
                              "a working-tree identity published under "
                              "the bare source_id_sha256 key (class P) "
                              "did not fail the gate",
                              "class-P violation did not name the "
                              "offending file",
                              "reverting the class-P copy did not clear "
                              "the violation") != 0;
    if (!bad) {
        int rc = sia_st_invoke(&st, "no-such-dir");
        if (rc != 2) {
            char msg[160];
            (void)snprintf(msg, sizeof msg,
                           "an empty/moved scan root did not hit the "
                           "gate_require_scanned floor (got rc=%d, "
                           "wanted 2)", rc);
            (void)sia_st_fail(msg);
            sia_st_dump(&st);
            bad = 1;
        }
    }
    (void)unsetenv("ZCL_SOURCE_AUTHORITY_SCAN_ROOT");
    (void)unsetenv("ZCL_SOURCE_AUTHORITY_MAKEFILE");
    (void)unsetenv("ZCL_SOURCE_AUTHORITY_BASELINE");
    (void)unsetenv("ZCL_SOURCE_AUTHORITY_CEILING");
    (void)unsetenv("ZCL_SOURCE_AUTHORITY_FILE_FLOOR");
    (void)unsetenv("ZCL_LINT_MODE");
    (void)rap_rm_rf(st.tmp);
    if (bad)
        return 2;
    printf("[%s] SELFTEST PASS (clean multi-schema/strict-reader consumer "
           "passes; a positional agentbuild read (class R) and a bare-key "
           "working-tree producer (class P) each fail; reverting either "
           "clears the violation; a hollow scan root hits the floor "
           "instead of reporting clean)\n", k_gate);
    return 0;
}
