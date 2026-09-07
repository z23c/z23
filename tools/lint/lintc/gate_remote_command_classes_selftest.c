/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-remote-command-classes — plants each
 * defect class from tools/lint/check_remote_command_classes.sh's own
 * selftest() into a miniature registry/agent/table fixture and asserts the
 * gate's verdict, so a gate nobody has watched fail is not an assertion.
 *
 * Gates: (selftest sibling of check-remote-command-classes)
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_remote_command_classes_priv.h"

static const char k_mini_def[] =
    "ZCL_COMMAND_BRANCH(\"mini\", \"\", \"not a leaf\", "
    "ZCL_COMMAND_LAYER_OPS)\n"
    "\n"
    "ZCL_COMMAND_READY_READ(\n"
    "    \"mini.alpha\", \"mini\", \"\", \"s\", \"sem\", 0, \"k\", \"in\", "
    "\"out\", \"\", \"\", \"ex\")\n"
    "ZCL_COMMAND_READY_COMMAND(\n"
    "    \"mini.beta\", \"mini\", \"\", \"s\", \"sem\", 0, \"k\", \"in\", "
    "\"out\", \"\", \"\", \"ex\")\n";

static const char k_mini_agent[] =
    "AGENT_CONTRACT(\"minimethod\", \"cap\", \"schema.v1\", "
    "\"z23 minimethod\", \"\", \"\", \"\", 0, \"\", \"\", \"p\")\n";

static const char k_mini_table[] =
    "REMOTE_COMMAND_CLASS(\"mini.alpha\", REMOTE_CLASS_READ_ONLY, "
    "\"bounded read\")\n"
    "REMOTE_COMMAND_CLASS(\"mini.beta\", REMOTE_CLASS_NEVER, \"\")\n"
    "REMOTE_COMMAND_CLASS(\"minimethod\", REMOTE_CLASS_NEVER, \"\")\n";

struct rcc_st_ctx {
    char root[4096];
    char commands_dir[4096];
    char agent_path[4096];
    char base_table[4096];
    int fails;
};

static int rcc_st_write(const struct rcc_st_ctx *s, const char *rel,
                        const char *text)
{
    char p[8192];
    if (ovf(snprintf(p, sizeof p, "%s/%s", s->root, rel), sizeof p))
        return 1;
    return csr_write(p, text) != 0;
}

static int rcc_st_setup(struct rcc_st_ctx *s)
{
    const char *td = env_or("TMPDIR", "test-tmp");
    (void)csr_mkdirs("test-tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-rcc-XXXXXX", td),
            sizeof tmpl))
        return 1;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    memset(s, 0, sizeof *s);
    if (ovf(snprintf(s->root, sizeof s->root, "%s", root), sizeof s->root))
        return 1;
    if (ovf(snprintf(s->commands_dir, sizeof s->commands_dir, "%s/commands",
                     s->root), sizeof s->commands_dir))
        return 1;
    if (ovf(snprintf(s->agent_path, sizeof s->agent_path, "%s/agent.def",
                     s->root), sizeof s->agent_path))
        return 1;
    if (ovf(snprintf(s->base_table, sizeof s->base_table, "%s/table.def",
                     s->root), sizeof s->base_table))
        return 1;
    return rcc_st_write(s, "commands/mini.def", k_mini_def)
        || rcc_st_write(s, "agent.def", k_mini_agent)
        || rcc_st_write(s, "table.def", k_mini_table);
}

/* probe(): re-run the gate with TYPED_FLOOR=1/AGENT_FLOOR=1 (the mini
 * fixture is far under the production floors) against the given table
 * variant, and assert the exit code. Output is discarded on both streams,
 * matching the shell's `>/dev/null 2>&1`. */
static void rcc_st_probe(struct rcc_st_ctx *s, const char *name, int want,
                         const char *table)
{
    FILE *out = fopen("/dev/null", "w");
    FILE *err = fopen("/dev/null", "w");
    if (!out || !err) {
        if (out)
            fclose(out);
        if (err)
            fclose(err);
        fprintf(stderr,
                "check_remote_command_classes: SELFTEST FAIL — %s: cannot "
                "open /dev/null\n", name);
        s->fails++;
        return;
    }
    int rc = rcc_run_gate_for_selftest(s->commands_dir, s->agent_path, table,
                                       1, 1, out, err);
    fclose(out);
    fclose(err);
    if (rc != want) {
        fprintf(stderr,
                "check_remote_command_classes: SELFTEST FAIL — %s: "
                "expected exit %d, got %d\n", name, want, rc);
        s->fails++;
    } else {
        fprintf(stdout,
                "check_remote_command_classes: selftest ok — %s (exit "
                "%d)\n", name, rc);
    }
}

static int rcc_st_variant(struct rcc_st_ctx *s, const char *rel,
                          const char *text)
{
    char p[8192];
    if (ovf(snprintf(p, sizeof p, "%s/%s", s->root, rel), sizeof p))
        return 1;
    return csr_write(p, text) != 0;
}

int check_remote_command_classes_selftest(void)
{
    struct rcc_st_ctx s;
    if (rcc_st_setup(&s))
        return 2;

    rcc_st_probe(&s, "clean fixture passes", 0, s.base_table);

    rcc_st_variant(&s, "missing.def",
        "REMOTE_COMMAND_CLASS(\"mini.alpha\", REMOTE_CLASS_READ_ONLY, "
        "\"bounded read\")\n"
        "REMOTE_COMMAND_CLASS(\"minimethod\", REMOTE_CLASS_NEVER, \"\")\n");
    char p_missing[8192];
    snprintf(p_missing, sizeof p_missing, "%s/missing.def", s.root);
    rcc_st_probe(&s, "missing classification fails", 1, p_missing);

    rcc_st_variant(&s, "orphan.def",
        "REMOTE_COMMAND_CLASS(\"mini.alpha\", REMOTE_CLASS_READ_ONLY, "
        "\"bounded read\")\n"
        "REMOTE_COMMAND_CLASS(\"mini.beta\", REMOTE_CLASS_NEVER, \"\")\n"
        "REMOTE_COMMAND_CLASS(\"minimethod\", REMOTE_CLASS_NEVER, \"\")\n"
        "REMOTE_COMMAND_CLASS(\"mini.gone\", REMOTE_CLASS_NEVER, \"\")\n");
    char p_orphan[8192];
    snprintf(p_orphan, sizeof p_orphan, "%s/orphan.def", s.root);
    rcc_st_probe(&s, "stale row fails", 1, p_orphan);

    rcc_st_variant(&s, "dupe.def",
        "REMOTE_COMMAND_CLASS(\"mini.alpha\", REMOTE_CLASS_READ_ONLY, "
        "\"bounded read\")\n"
        "REMOTE_COMMAND_CLASS(\"mini.beta\", REMOTE_CLASS_NEVER, \"\")\n"
        "REMOTE_COMMAND_CLASS(\"minimethod\", REMOTE_CLASS_NEVER, \"\")\n"
        "REMOTE_COMMAND_CLASS(\"mini.beta\", REMOTE_CLASS_READ_ONLY, "
        "\"second opinion\")\n");
    char p_dupe[8192];
    snprintf(p_dupe, sizeof p_dupe, "%s/dupe.def", s.root);
    rcc_st_probe(&s, "duplicate row fails", 1, p_dupe);

    rcc_st_variant(&s, "badclass.def",
        "REMOTE_COMMAND_CLASS(\"mini.alpha\", REMOTE_CLASS_MAYBE, "
        "\"bounded read\")\n"
        "REMOTE_COMMAND_CLASS(\"mini.beta\", REMOTE_CLASS_NEVER, \"\")\n"
        "REMOTE_COMMAND_CLASS(\"minimethod\", REMOTE_CLASS_NEVER, \"\")\n");
    char p_badclass[8192];
    snprintf(p_badclass, sizeof p_badclass, "%s/badclass.def", s.root);
    rcc_st_probe(&s, "unknown class token fails", 1, p_badclass);

    rcc_st_variant(&s, "noreason.def",
        "REMOTE_COMMAND_CLASS(\"mini.alpha\", REMOTE_CLASS_READ_ONLY, "
        "\"\")\n"
        "REMOTE_COMMAND_CLASS(\"mini.beta\", REMOTE_CLASS_NEVER, \"\")\n"
        "REMOTE_COMMAND_CLASS(\"minimethod\", REMOTE_CLASS_NEVER, \"\")\n");
    char p_noreason[8192];
    snprintf(p_noreason, sizeof p_noreason, "%s/noreason.def", s.root);
    rcc_st_probe(&s, "unexplained permission fails", 1, p_noreason);

    /* A bare quote in the reason prose: still parses, still non-empty,
     * still a known class token — and would not compile. */
    rcc_st_variant(&s, "strayquote.def",
        "REMOTE_COMMAND_CLASS(\"mini.alpha\", REMOTE_CLASS_READ_ONLY, "
        "\"a bounded \"peek\" only\")\n"
        "REMOTE_COMMAND_CLASS(\"mini.beta\", REMOTE_CLASS_NEVER, \"\")\n"
        "REMOTE_COMMAND_CLASS(\"minimethod\", REMOTE_CLASS_NEVER, \"\")\n");
    char p_strayquote[8192];
    snprintf(p_strayquote, sizeof p_strayquote, "%s/strayquote.def", s.root);
    rcc_st_probe(&s, "stray quote in reason fails", 1, p_strayquote);

    char p_missing_table[8192];
    snprintf(p_missing_table, sizeof p_missing_table,
             "%s/does-not-exist.def", s.root);
    rcc_st_probe(&s, "missing table is FATAL", 2, p_missing_table);

    (void)rap_rm_rf(s.root);
    if (s.fails) {
        fprintf(stderr,
                "check_remote_command_classes: SELFTEST FAILED (%d)\n",
                s.fails);
        return 1;
    }
    fputs("check_remote_command_classes: selftest passed\n", stdout);
    return 0;
}
