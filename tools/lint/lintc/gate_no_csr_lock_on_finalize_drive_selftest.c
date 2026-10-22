/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-no-csr-lock-on-finalize-drive
 * (gate_no_csr_lock_on_finalize_drive.c). Builds a two-file fixture tree
 * under $HOME/.local/state/zclassic23/scratch (never /tmp) whose note body
 * and drive body are clean, and proves each case: the clean tree passes; a
 * csr->lock token in the note body trips; a forbidden token only inside
 * comments does not; a csr_snapshot call in the drive trips; a renamed note
 * function and a missing drive file both fail closed. The drain function in
 * the note file takes csr->lock on purpose, which proves the scan is scoped
 * to the note body only.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_no_csr_lock_on_finalize_drive_priv.h"

enum { CNFS_PATH = 1024, CNFS_TEXT = 4096 };

static const char k_cnfs_note_fn[] = "chain_evidence_note_finalized_tip";
static const char k_cnfs_drive_rel[] =
    "engine/jobs/src/tip_finalize_post_step.c";
static const char k_cnfs_note_rel[] =
    "engine/services/src/chain_evidence_live_advance.c";

struct cnfs_case {
    const char *name;
    const char *drive_line; /* inserted in the drive() body */
    const char *note_line;  /* inserted in the note body */
    int note_named;         /* 0 renames the note function */
    int drop_drive;         /* 1 deletes the drive file after writing */
    int want;               /* expected return: 0 pass, 1 fail */
};

static const struct cnfs_case k_cnfs_cases[] = {
    { "clean fixture passes", "", "", 1, 0, 0 },
    { "csr->lock in the note body fails",
      "", "    pthread_mutex_lock(&csr->lock);\n", 1, 0, 1 },
    { "forbidden tokens only in comments pass",
      "    /* csr_snapshot and csr->lock are named here in prose */\n"
      "    // chain_evidence_controller_init stays in a comment\n",
      "    // chain_evidence_drain_pending_tip in a line comment\n", 1, 0, 0 },
    { "csr_snapshot call in the drive fails",
      "    csr_snapshot(NULL);\n", "", 1, 0, 1 },
    { "renamed note function fails closed", "", "", 0, 0, 1 },
    { "missing drive file fails closed", "", "", 1, 1, 1 },
};

/* Fixture drive body: a clean drive() with one caller-chosen line inside. */
static int cnfs_write_drive(const char *root, const char *line)
{
    char path[CNFS_PATH], text[CNFS_TEXT];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, k_cnfs_drive_rel),
             sizeof path))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "/* Fixture drive file: csr->lock in prose is not code. */\n"
                     "#include <stdio.h>\n"
                     "void tip_finalize_post_step_fixture(void)\n"
                     "{\n"
                     "%s"
                     "    return;\n"
                     "}\n", line),
             sizeof text))
        return 2;
    return csr_write(path, text);
}

/* Fixture note file: the note function with one caller-chosen line inside,
 * plus a drain function that takes csr->lock legitimately (out of scope). */
static int cnfs_write_note(const char *root, int named, const char *line)
{
    char path[CNFS_PATH], text[CNFS_TEXT];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, k_cnfs_note_rel),
             sizeof path))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "/* Fixture note file. */\n"
                     "#include <stdio.h>\n"
                     "static int fixture_helper(void)\n"
                     "{\n"
                     "    return 0;\n"
                     "}\n"
                     "void %s(void)\n"
                     "{\n"
                     "    /* leaf mutex only; csr->lock named in a comment */\n"
                     "%s"
                     "    return;\n"
                     "}\n"
                     "\n"
                     "void chain_evidence_controller_drain_fixture(void)\n"
                     "{\n"
                     "    pthread_mutex_lock(&csr->lock); /* drain path */\n"
                     "}\n",
                     named ? k_cnfs_note_fn : "chain_evidence_note_renamed",
                     line),
             sizeof text))
        return 2;
    return csr_write(path, text);
}

static int cnfs_write_fixture(const char *root, const struct cnfs_case *c)
{
    int rc = cnfs_write_drive(root, c->drive_line);
    if (rc == 0)
        rc = cnfs_write_note(root, c->note_named, c->note_line);
    if (rc == 0 && c->drop_drive) {
        char path[CNFS_PATH];
        if (ovf(snprintf(path, sizeof path, "%s/%s", root, k_cnfs_drive_rel),
                 sizeof path))
            return 2;
        if (unlink(path) != 0)
            return die("z23-lint: cannot remove fixture %s\n", path);
    }
    return rc;
}

/* Fixture scratch root (never /tmp): mkdtemp under the state scratch dir. */
static int cnfs_fixture_root(char *out, size_t cap)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return die("z23-lint: HOME unset; cannot place selftest scratch\n", "");
    char base[CNFS_PATH];
    if (ovf(snprintf(base, sizeof base, "%s/.local/state/zclassic23/scratch",
                     home), sizeof base))
        return 2;
    int rc = csr_mkdirs(base);
    if (rc)
        return rc;
    if (ovf(snprintf(out, cap, "%s/no-csr-lock-finalize-drive.XXXXXX", base),
            cap))
        return 2;
    if (!mkdtemp(out))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    return 0;
}

/* Runs one case; returns 0 when the gate answered the way the case expects. */
static int cnfs_run_case(const char *root, const struct cnfs_case *c)
{
    int rc = cnfs_write_fixture(root, c);
    if (rc)
        return rc;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = cnf_check_root(root, sink);
    fclose(sink);
    if (got != c->want) {
        fprintf(stderr, "check-no-csr-lock-on-finalize-drive selftest: %s: "
                "want rc=%d got rc=%d\n", c->name, c->want, got);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", c->name, got);
    return 0;
}

int check_no_csr_lock_on_finalize_drive_selftest(void)
{
    char root[CNFS_PATH];
    int rc = cnfs_fixture_root(root, sizeof root);
    if (rc)
        return rc;
    int bad = 0;
    for (size_t i = 0; i < sizeof k_cnfs_cases / sizeof k_cnfs_cases[0]; i++)
        bad |= cnfs_run_case(root, &k_cnfs_cases[i]) != 0;
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_no_csr_lock_on_finalize_drive selftest\n", stderr);
    return st_ok(bad, "check-no-csr-lock-on-finalize-drive selftest: OK\n");
}
