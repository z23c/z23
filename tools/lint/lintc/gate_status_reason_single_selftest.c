/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the planted-violation selftest of check-status-reason-single.
 * Plants fresh inline ladders in a sandbox scan tree and proves the gate
 * fails on each (named, renamed, vocabulary-only, same-line brace) and
 * passes on the innocuous shapes; then proves both consolidated surfaces
 * are clean. The gate core is gate_status_reason_single.c.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_status_reason_single_priv.h"

static const char k_st_gate[] = "check_status_reason_single";

static const char k_st_clean[] =
    "int nothing(void) { return 0; }\n";

static const char k_st_named[] =
    "size_t surface_status(struct json_value *out)\n"
    "{\n"
    "    bool operator_needed = false;\n"
    "    if (a) {\n"
    "        operator_needed = true;\n"
    "    } else if (b) {\n"
    "        operator_needed = true;\n"
    "    } else if (c) {\n"
    "        operator_needed = true;\n"
    "    }\n"
    "    json_push_kv_bool(out, \"operator_needed\", operator_needed);\n"
    "    return 0;\n"
    "}\n";

/* The same ladder with the name on no list anywhere. */
static const char k_st_renamed[] =
    "size_t surface_status(struct json_value *out)\n"
    "{\n"
    "    bool wants_a_human = false;\n"
    "    if (a) {\n"
    "        wants_a_human = true;\n"
    "    } else if (b) {\n"
    "        wants_a_human = true;\n"
    "    } else if (c) {\n"
    "        wants_a_human = true;\n"
    "    }\n"
    "    json_push_kv_bool(out, \"wants_a_human\", wants_a_human);\n"
    "    return 0;\n"
    "}\n";

/* No json_push_kv_bool, but it publishes the status vocabulary. */
static const char k_st_vocab[] =
    "const char *surface_word(void)\n"
    "{\n"
    "    bool needs_hands = false;\n"
    "    const char *word = \"healthy\";\n"
    "    if (a) {\n"
    "        needs_hands = true; word = \"blocked\";\n"
    "    } else if (b) {\n"
    "        needs_hands = true; word = \"degraded\";\n"
    "    } else if (c) {\n"
    "        needs_hands = true; word = \"catching_up\";\n"
    "    }\n"
    "    return needs_hands ? word : \"healthy\";\n"
    "}\n";

/* The same ladder with each branch's assignments on its brace line. */
static const char k_st_sameline[] =
    "size_t surface_status_compact(struct json_value *out)\n"
    "{\n"
    "    bool wants_hands = false;\n"
    "    const char *word = \"healthy\";\n"
    "    if (a) { word = \"blocked\"; wants_hands = true; }\n"
    "    else if (b) { word = \"degraded\"; wants_hands = true; }\n"
    "    else if (c) { word = \"catching_up\"; wants_hands = true; }\n"
    "    json_push_kv_bool(out, \"wants_hands\", wants_hands);\n"
    "    return 0;\n"
    "}\n";

/* A multi-branch flag that publishes nothing an operator reads. */
static const char k_st_innocuous[] =
    "int parse_thing(const char *s)\n"
    "{\n"
    "    bool bad = false;\n"
    "    if (a) {\n"
    "        bad = true;\n"
    "    } else if (b) {\n"
    "        bad = true;\n"
    "    } else if (c) {\n"
    "        bad = true;\n"
    "    }\n"
    "    return bad ? -1 : 0;\n"
    "}\n";

/* Role signals present, but only one branch: no ladder. */
static const char k_st_no_ladder[] =
    "size_t one_branch(struct json_value *out)\n"
    "{\n"
    "    bool flag = false;\n"
    "    if (a)\n"
    "        flag = true;\n"
    "    json_push_kv_bool(out, \"flag\", flag);\n"
    "    return 0;\n"
    "}\n";

/* Role signals present, a long chain, but the bool is touched only twice. */
static const char k_st_short_ladder[] =
    "size_t two_assigns(struct json_value *out)\n"
    "{\n"
    "    bool flag = false;\n"
    "    if (a) {\n"
    "        flag = true;\n"
    "    } else if (b) {\n"
    "        other = 1;\n"
    "    } else if (c) {\n"
    "        flag = true;\n"
    "    }\n"
    "    json_push_kv_bool(out, \"flag\", flag);\n"
    "    return 0;\n"
    "}\n";

struct srs_st_case { const char *body; int want_fail; const char *msg; };

static const struct srs_st_case k_st_cases[] = {
    { k_st_clean, 0, "a clean file with no ladder was reported as a violation" },
    { k_st_named, 1, "an inline operator_needed ladder did not fail the gate" },
    { k_st_clean, 0, "reverting the named ladder did not clear the violation" },
    { k_st_renamed, 1, "a RENAMED ladder (no name on any list) did not fail the gate; the rename dodge is not closed" },
    { k_st_clean, 0, "reverting the renamed ladder did not clear the violation" },
    { k_st_vocab, 1, "a ladder detected only through the status vocabulary did not fail the gate" },
    { k_st_clean, 0, "reverting the vocabulary ladder did not clear the violation" },
    { k_st_sameline, 1, "a ladder whose assignments sit on the same line as their braces did not fail the gate; the reindent dodge is not closed" },
    { k_st_clean, 0, "reverting the same-line ladder did not clear the violation" },
    { k_st_innocuous, 0, "an innocuous multi-branch flag with no operator role was miscounted as a ladder" },
    { k_st_no_ladder, 0, "a single-branch flag that publishes to JSON was miscounted as a ladder" },
    { k_st_short_ladder, 0, "a long chain touching the bool only twice was miscounted as a ladder" },
};

struct srs_st { char root[4096], src[4200], base[4200], glob[4200], file[4200]; };

static int srs_st_fail(const char *msg)
{
    fprintf(stderr, "%s: SELFTEST FAILED — %s\n", k_st_gate, msg);
    return 2;
}

/* Makes the sandbox tree and points the gate's knobs at it. */
static int srs_st_setup(struct srs_st *st)
{
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-status-reason.XXXXXX",
                     env_or("TMPDIR", P_tmpdir)), sizeof tmpl))
        return 2;
    if (!mkdtemp(tmpl))
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    if (ovf(snprintf(st->root, sizeof st->root, "%s", tmpl), sizeof st->root)
        || ovf(snprintf(st->src, sizeof st->src, "%s/src", tmpl), sizeof st->src)
        || ovf(snprintf(st->base, sizeof st->base, "%s/empty_baseline.txt", tmpl),
               sizeof st->base)
        || ovf(snprintf(st->glob, sizeof st->glob, "%s/src/*.c", tmpl),
               sizeof st->glob)
        || ovf(snprintf(st->file, sizeof st->file, "%s/sandbox_surface.c", st->src),
               sizeof st->file))
        return 2;
    if (csr_mkdirs(st->src) || csr_write(st->base, ""))
        return 2;
    if (setenv("ZCL_STATUS_REASON_GATE_SCAN_GLOB", st->glob, 1) != 0
        || setenv("ZCL_STATUS_REASON_GATE_BASELINE", st->base, 1) != 0
        || setenv("ZCL_STATUS_REASON_GATE_CEILING", "0", 1) != 0
        || setenv("ZCL_STATUS_REASON_GATE_FILE_FLOOR", "1", 1) != 0
        || setenv("ZCL_LINT_MODE", "FAIL", 1) != 0)
        return die("z23-lint: setenv failed\n", "");
    return 0;
}

/* Plants one fixture as the only file of the sandbox scan set and runs the
 * whole gate over it. The shell's expect(): a fail case must not exit 0; a
 * pass case must exit 0. */
static int srs_st_run_case(const struct srs_st *st, const struct srs_st_case *c)
{
    char text[8192];
    if (ovf(snprintf(text, sizeof text, "/* sandbox fixture, not real code */\n%s",
                     c->body), sizeof text))
        return 2;
    if (csr_write(st->file, text))
        return 2;
    FILE *out = tmpfile(), *err = tmpfile();
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        return die("z23-lint: tmpfile failed\n", "");
    }
    int rc = srs_run_core(out, err);
    fclose(out);
    fclose(err);
    if (c->want_fail ? rc == 0 : rc != 0)
        return srs_st_fail(c->msg);
    return 0;
}

/* The two consolidated surfaces must exist and carry no inline ladder, or
 * the gate would pass only because its scan set does not reach them. */
static int srs_st_surfaces(void)
{
    static const char *const k_surf[] = {
        "engine/controllers/src/api_controller_status.c",
        "cognition/controllers/src/event_agent_summary.c",
    };
    for (size_t i = 0; i < 2; i++) {
        FILE *f = fopen(k_surf[i], "r");
        if (!f) {
            fprintf(stderr, "%s: SELFTEST FAILED — %s is missing; the consolidated surfaces moved and this gate no longer watches them\n",
                    k_st_gate, k_surf[i]);
            return 2;
        }
        fclose(f);
        int count = 0;
        if (srs_scan_file(k_surf[i], &count))
            return 2;
        if (count != 0) {
            fprintf(stderr, "%s: SELFTEST FAILED — %s still carries an inline ladder\n",
                    k_st_gate, k_surf[i]);
            return 2;
        }
    }
    return 0;
}

/* The rename fixture must really be renamed and the same-line fixture must
 * really be in that brace style, or the matching cases prove nothing. */
static int srs_st_fixtures_sane(void)
{
    if (strstr(k_st_renamed, "operator_needed") != NULL)
        return srs_st_fail("the rename fixture still contains 'operator_needed'; the rename-dodge assertion is hollow");
    if (strstr(k_st_sameline, "{ word = ") == NULL)
        return srs_st_fail("the same-line fixture is not in the same-line brace style; the reindent-dodge assertion is hollow");
    return 0;
}

static void srs_st_teardown(const struct srs_st *st)
{
    if (st->root[0])
        rap_rm_rf(st->root);
}

int check_status_reason_single_selftest(void)
{
    struct srs_st st;
    memset(&st, 0, sizeof st);
    int rc = srs_st_setup(&st);
    if (rc == 0 && srs_st_fixtures_sane())
        rc = 2;
    for (size_t i = 0; rc == 0 && i < sizeof k_st_cases / sizeof k_st_cases[0]; i++)
        rc = srs_st_run_case(&st, &k_st_cases[i]);
    if (rc == 0)
        rc = srs_st_surfaces();
    srs_st_teardown(&st);
    if (rc != 0)
        return rc;
    printf("[%s] SELFTEST PASS (clean passes; named, renamed and same-line-brace ladders all fail; a vocabulary-only ladder fails; an innocuous multi-branch flag and a single-branch flag do not count; both consolidated surfaces are clean)\n",
           k_st_gate);
    return 0;
}
