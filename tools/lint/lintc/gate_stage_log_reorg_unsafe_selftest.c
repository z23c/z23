/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-stage-log-reorg-unsafe
 * (gate_stage_log_reorg_unsafe.c). Plants fixture store files under a
 * scratch dir and proves: the at-baseline tree passes; a below-baseline
 * count passes; a 9th UPSERT site fails; a missing tracked file and an
 * empty file list both fail closed (exit 2).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_stage_log_reorg_unsafe_priv.h"

enum { SLSS_PATH = 1024, SLSS_TEXT = 2048, SLSS_FILES = 16 };

static const char k_slss_body_one[] =
    "static const char k_schema[] =\n"
    "    \"CREATE TABLE log (height INTEGER PRIMARY KEY, w);\";\n"
    "INSERT OR REPLACE INTO log VALUES (1, 2);\n";

static const char k_slss_body_two[] =
    "INSERT OR REPLACE INTO log VALUES (1, 2);\n"
    "insert or replace into log values (3, 4);\n";

static const char *const k_slss_names[SLSS_FILES] = {
    "stores/a.c", "stores/b.c", "stores/c.c", "stores/d.c",
    "stores/e.c", "stores/f.c", "stores/g.c", "stores/h.c",
    "stores/i.c", "stores/j.c", "stores/k.c", "stores/l.c",
    "stores/m.c", "stores/n.c", "stores/o.c", "stores/p.c",
};

/* Joins root and the fixture name for slot i into out (cap bytes). */
static int slss_path(char *out, size_t cap, const char *root, int i)
{
    return ovf(snprintf(out, cap, "%s/%s", root, k_slss_names[i]), (int)cap);
}

/* Writes nfiles fixture stores under root; the first one holds two UPSERT
 * lines when extra is set, so the total count is nfiles + extra. drop_one
 * then removes the first store again, leaving a drifted list. */
static int slss_plant(const char *root, int nfiles, int extra, int drop_one)
{
    char path[SLSS_PATH], text[SLSS_TEXT];
    for (int i = 0; i < nfiles; i++) {
        if (slss_path(path, sizeof path, root, i))
            return 2;
        const char *body = i == 0 && extra ? k_slss_body_two : k_slss_body_one;
        if (ovf(snprintf(text, sizeof text,
                         "/* fixture store %d */\n%s", i, body),
                 (int)sizeof text))
            return 2;
        int rc = csr_write(path, text);
        if (rc)
            return rc;
    }
    if (drop_one) {
        if (slss_path(path, sizeof path, root, 0))
            return 2;
        if (unlink(path) != 0)
            return die("z23-lint: cannot remove fixture %s\n", path);
    }
    return 0;
}

/* Runs the whole gate over files with its report sunk into a scratch file,
 * returning the gate's rc. */
static int slss_check_rc(const char *root, const char *const *files,
                         int nfiles)
{
    char sink_path[SLSS_PATH];
    if (ovf(snprintf(sink_path, sizeof sink_path, "%s/sink.txt", root),
            (int)sizeof sink_path))
        return 2;
    FILE *sink = fopen(sink_path, "w");
    if (!sink)
        return die("z23-lint: cannot open sink %s\n", sink_path);
    int rc = slr_check(files, nfiles, sink);
    fclose(sink);
    return rc;
}

static int slss_run_case(const char *root, const char *name, int nfiles,
                         int extra, int drop_one, int want)
{
    int rc = slss_plant(root, nfiles, extra, drop_one);
    if (rc)
        return rc;
    char storage[SLSS_FILES][SLSS_PATH];
    const char *files[SLSS_FILES];
    for (int i = 0; i < nfiles; i++) {
        if (slss_path(storage[i], sizeof storage[i], root, i))
            return 2;
        files[i] = storage[i];
    }
    rc = slss_check_rc(root, files, nfiles);
    if (rc != want) {
        fprintf(stderr, "check-stage-log-reorg-unsafe selftest: %s: "
                "want rc=%d got rc=%d\n", name, want, rc);
        return 1;
    }
    printf("  selftest ok: %s (rc=%d)\n", name, rc);
    return 0;
}

int check_stage_log_reorg_unsafe_selftest(void)
{
    char root[SLSS_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "stage-log-reorg-unsafe");
    if (rc)
        return rc;
    int bad = 0;
    bad |= slss_run_case(root, "at-baseline tree passes", 8, 0, 0, 0) != 0;
    bad |= slss_run_case(root, "below-baseline count passes", 3, 0, 0, 0) != 0;
    bad |= slss_run_case(root, "ninth UPSERT site fails", 8, 1, 0, 1) != 0;
    bad |= slss_run_case(root, "missing tracked file fails closed", 4, 0, 1,
                         2) != 0;
    bad |= slss_check_rc(root, NULL, 0) != 2;
    if (!bad)
        printf("  selftest ok: empty file list fails closed (rc=2)\n");
    else
        fputs("check-stage-log-reorg-unsafe selftest: empty-list case failed\n",
              stderr);
    rap_rm_rf(root);
    if (bad)
        fputs("FAIL: check_stage_log_reorg_unsafe selftest\n", stderr);
    return st_ok(bad, "check-stage-log-reorg-unsafe selftest: OK\n");
}
