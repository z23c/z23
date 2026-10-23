/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-doc-no-false-deleted
 * (gate_doc_no_false_deleted.c). Builds one fixture tree per case under
 * $HOME/.local/state/zclassic23/scratch (never /tmp), enters it, runs the
 * same check the gate runs, and proves each rule: a clean tree passes; a
 * wrapped "legacy block-connect engine ... deleted" claim fails while the
 * code is live; a "connect_block ... was deleted" claim fails the same way;
 * the claim passes once the code is gone or no caller is live; a cited size
 * outside the band fails and one inside it passes; a missing release binary
 * skips the size check.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_doc_no_false_deleted_priv.h"

enum { DFNS_PATH = 1024, DFNS_MB = 1048576 };

struct dfns_case {
    const char *name;
    const char *doc;       /* docs/a.md body */
    int code;              /* 1: core connect_block.c exists */
    int caller;            /* 1: boot_index.c calls connect_block() */
    long bin_mb;           /* 0: no release binary, else its size in MB */
    const char *framework; /* docs/commons/FRAMEWORK.md body, or NULL */
    int want;              /* 0 pass, 1 fail */
};

static const struct dfns_case k_dfns_cases[] = {
    { "clean tree passes", "The node is compact.\n", 1, 1, 16, NULL, 0 },
    { "wrapped legacy engine claim with live code fails",
      "The legacy\nblock-connect engine has been deleted.\n", 1, 1, 16, NULL, 1 },
    { "connect_block was deleted claim with live code fails",
      "connect_block was deleted in an earlier release.\n", 1, 1, 16, NULL, 1 },
    { "claim with the code gone passes",
      "connect_block was deleted.\n", 0, 1, 16, NULL, 0 },
    { "claim with no live caller passes",
      "connect_block was deleted.\n", 1, 0, 16, NULL, 0 },
    { "size cited outside the band fails",
      "Plain text.\n", 1, 1, 16, "Size: 30 MB binary.\n", 1 },
    { "size cited inside the band passes",
      "Plain text.\n", 1, 1, 16, "Size: 18 MB binary.\n", 0 },
    { "missing release binary skips the size check",
      "Plain text.\n", 1, 1, 0, "Size: 30 MB binary.\n", 0 },
};

/* Writes text to dir/rel, creating parents. */
static int dfns_put(const char *dir, const char *rel, const char *text)
{
    char path[DFNS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", dir, rel), sizeof path))
        return 2;
    return csr_write(path, text);
}

/* A sparse release binary of exactly mb megabytes. */
static int dfns_bin(const char *dir, long mb)
{
    char bindir[DFNS_PATH], path[DFNS_PATH];
    FILE *f;
    if (ovf(snprintf(bindir, sizeof bindir, "%s/build/bin", dir), sizeof bindir)
        || ovf(snprintf(path, sizeof path, "%s/z23", bindir), sizeof path)
        || csr_mkdirs(bindir))
        return 2;
    f = fopen(path, "wb");
    if (!f)
        return die("z23-lint: cannot create %s\n", path);
    if (fseek(f, mb * (long)DFNS_MB - 1, SEEK_SET) != 0 || fputc(0, f) == EOF) {
        (void)fclose(f);
        return die("z23-lint: cannot size %s\n", path);
    }
    return fclose(f) == 0 ? 0 : die("z23-lint: cannot close %s\n", path);
}

static int dfns_fixture(const char *dir, const struct dfns_case *c)
{
    if (dfns_put(dir, "CLAUDE.md", "compact\n")
        || dfns_put(dir, "docs/a.md", c->doc)) // error-doc-ref-ok:selftest fixture
        return 2;
    if (c->code
        && dfns_put(dir, "core/modules/validation/src/connect_block.c",
                    "int connect_block(void) { return 0; }\n"))
        return 2;
    if (c->caller
        && dfns_put(dir, "engine/composition/src/boot_index.c",
                    "void boot(void) { connect_block(); }\n"))
        return 2;
    if (c->framework && dfns_put(dir, "docs/commons/FRAMEWORK.md", c->framework))
        return 2;
    if (c->bin_mb > 0 && dfns_bin(dir, c->bin_mb))
        return 2;
    return 0;
}

/* Builds case idx, runs the check inside it, and returns to saved. Returns
 * 0 when the rc matches, 1 when it does not, 2 on a fault. */
static int dfns_run_case(const char *base, int idx,
                         const struct dfns_case *c, const char *saved)
{
    char dir[DFNS_PATH];
    int rc;
    if (ovf(snprintf(dir, sizeof dir, "%s/case%d", base, idx), sizeof dir)
        || csr_mkdirs(dir)
        || dfns_fixture(dir, c))
        return 2;
    if (chdir(dir) != 0)
        return die("z23-lint: cannot enter %s\n", dir);
    rc = dfn_check_tree();
    if (chdir(saved) != 0)
        return die("z23-lint: cannot return to %s\n", saved);
    if (rc == 2)
        return 2;
    if (rc != c->want) {
        fprintf(stderr, "check-doc-no-false-deleted: FAIL — %s: rc %d, "
                        "want %d\n", c->name, rc, c->want);
        return 1;
    }
    return 0;
}

int check_doc_no_false_deleted_selftest(void)
{
    char base[DFNS_PATH], tmpl[DFNS_PATH], saved[DFNS_PATH];
    const char *home = getenv("HOME");
    size_t n = sizeof k_dfns_cases / sizeof k_dfns_cases[0];
    int bad = 0, rc = 0;
    if (!home || !home[0])
        return die("z23-lint: HOME is unset\n", "");
    if (!getcwd(saved, sizeof saved))
        return die("z23-lint: cannot read the working directory\n", "");
    if (ovf(snprintf(base, sizeof base, "%s/.local/state/zclassic23/scratch",
                     home), sizeof base)
        || csr_mkdirs(base)
        || ovf(snprintf(tmpl, sizeof tmpl, "%s/dfn-XXXXXX", base),
               sizeof tmpl))
        return 2;
    if (!mkdtemp(tmpl))
        return die("z23-lint: mkdtemp failed\n", "");
    for (size_t i = 0; i < n && rc != 2; i++) {
        rc = dfns_run_case(tmpl, (int)i, &k_dfns_cases[i], saved);
        if (rc == 1)
            bad++;
    }
    if (rap_rm_rf(tmpl) || rc == 2)
        return 2;
    if (bad > 0)
        return 1;
    printf("check-doc-no-false-deleted selftest: %zu/%zu passed\n", n, n);
    return 0;
}
