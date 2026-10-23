/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-no-stale-pinned-facts
 * (gate_no_stale_pinned_facts.c). Writes one fixture doc per case under
 * $HOME/.local/state/zclassic23/scratch (never /tmp) and proves each rule:
 * a clean doc passes; a binary size before or after the word binary fails;
 * a size beside an unrelated binary mention passes; a height pin fails; a
 * baselined pin passes; a stale-ok marker exempts a line; a file that cannot
 * be read fails closed; the scan set keeps HANDOFF.md and the archive in.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_no_stale_pinned_facts_priv.h"

enum { SNFS_PATH = 1024, SNFS_TEXT = 1024 };

struct snfs_case {
    const char *name;
    const char *body;     /* the fixture doc */
    const char *base_row; /* a baseline row for the doc's path, or NULL */
    int want;             /* expected rc: 0 clean, 1 violation */
};

static const struct snfs_case k_snfs_cases[] = {
    { "clean fixture passes",
      "# Doc\n\nThe node keeps its live state in HANDOFF.\n", NULL, 0 },
    { "binary size before the word fails",
      "The release binary is 15 MB and the binary is compact.\n", NULL, 1 },
    { "binary size after the word fails",
      "The binary is 20 MB on disk.\n", NULL, 1 },
    { "a size beside an unrelated binary mention passes",
      "Needs 512 MB RAM; the binary handles it.\n", NULL, 0 },
    { "H* pin fails",
      "Live state: H* = 1,234,567 right now.\n", NULL, 1 },
    { "wedged at a six-digit height fails",
      "The node is wedged at 1234567 today.\n", NULL, 1 },
    { "held at a comma-grouped height fails",
      "It was held at 1,234 blocks.\n", NULL, 1 },
    { "a trigger without a height number passes",
      "The node is currently wedged at the tip of its log.\n", NULL, 0 },
    { "a stale-ok marker exempts the line",
      "Dated: wedged at 1234567. <!-- stale-ok: dated 2026 measurement -->\n",
      NULL, 0 },
    { "a baselined height pin passes",
      "The node is wedged at 1234567 today.\n",
      "The node is wedged at 1234567 today.", 0 },
};

/* Writes one case's doc and optional baseline, then runs the check on it.
 * Returns 0 when the rc matches the case, 1 when it does not, 2 on fault. */
static int snfs_run_case(const char *dir, const struct snfs_case *c)
{
    char doc[SNFS_PATH], base[SNFS_PATH], row[SNFS_TEXT];
    char *files[1];
    FILE *sink;
    int rc;
    if (ovf(snprintf(doc, sizeof doc, "%s/doc.md", dir), sizeof doc)
        || ovf(snprintf(base, sizeof base, "%s/base.txt", dir), sizeof base))
        return 2;
    if (csr_write(doc, c->body))
        return 2;
    if (c->base_row) {
        if (ovf(snprintf(row, sizeof row, "%s|%s\n", doc, c->base_row),
                sizeof row)
            || csr_write(base, row))
            return 2;
    } else if (ovf(snprintf(base, sizeof base, "%s/none.txt", dir),
                   sizeof base)) {
        return 2;
    }
    sink = tmpfile();
    if (!sink)
        return 2;
    files[0] = doc;
    rc = snf_check(files, 1, base, sink, sink, 0);
    if (fclose(sink) != 0 && rc == 0)
        rc = 2;
    if (rc == 2)
        return 2;
    if (rc != c->want) {
        fprintf(stderr,
                "check-no-stale-pinned-facts: FAIL — %s: rc %d, want %d\n",
                c->name, rc, c->want);
        return 1;
    }
    return 0;
}

/* A file that cannot be read is fatal (exit 2), never a silent pass. */
static int snfs_missing_fails_closed(const char *dir)
{
    char missing[SNFS_PATH], base[SNFS_PATH];
    char *files[1];
    FILE *sink;
    int rc;
    if (ovf(snprintf(missing, sizeof missing, "%s/absent.md", dir),
            sizeof missing)
        || ovf(snprintf(base, sizeof base, "%s/none.txt", dir), sizeof base))
        return 2;
    sink = tmpfile();
    if (!sink)
        return 2;
    files[0] = missing;
    rc = snf_check(files, 1, base, sink, sink, 0);
    (void)fclose(sink);
    if (rc == 2)
        return 0;
    fprintf(stderr, "check-no-stale-pinned-facts: FAIL — missing file: "
                    "rc %d, want 2\n", rc);
    return 1;
}

/* The scan set keeps every docs path, the live-state page and the archive too. */
static int snfs_scope(void)
{
    int bad = 0;
    if (!snf_keep_path("docs/HANDOFF.md") // error-doc-ref-ok:selftest fixture
        || !snf_keep_path("docs/work/archive/x.md")) { // error-doc-ref-ok:selftest fixture
        fprintf(stderr, "check-no-stale-pinned-facts: FAIL — scope dropped a "
                        "docs path\n");
        bad++;
    }
    if (!snf_keep_path("docs/adr/0001-x.md") || !snf_keep_path("CLAUDE.md")) { // error-doc-ref-ok:selftest fixture
        fprintf(stderr, "check-no-stale-pinned-facts: FAIL — scope dropped a "
                        "doc path\n");
        bad++;
    }
    return bad;
}

/* Runs every case. Returns the number of failed checks, or -1 on a fault. */
static int snfs_run_all(const char *dir, int *ran)
{
    int bad = 0, rc;
    for (size_t i = 0; i < sizeof k_snfs_cases / sizeof k_snfs_cases[0]; i++) {
        rc = snfs_run_case(dir, &k_snfs_cases[i]);
        if (rc == 2)
            return -1;
        bad += rc;
        (*ran)++;
    }
    rc = snfs_missing_fails_closed(dir);
    if (rc == 2)
        return -1;
    bad += rc;
    (*ran)++;
    bad += snfs_scope();
    (*ran)++;
    return bad;
}

int check_no_stale_pinned_facts_selftest(void)
{
    char base[SNFS_PATH], tmpl[SNFS_PATH];
    const char *home = getenv("HOME");
    int ran = 0, bad;
    if (!home || !home[0])
        return die("z23-lint: HOME is unset\n", "");
    if (ovf(snprintf(base, sizeof base, "%s/.local/state/zclassic23/scratch",
                     home), sizeof base)
        || csr_mkdirs(base))
        return 2;
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/snf-XXXXXX", base), sizeof tmpl))
        return 2;
    if (!mkdtemp(tmpl))
        return die("z23-lint: mkdtemp failed\n", "");
    bad = snfs_run_all(tmpl, &ran);
    if (rap_rm_rf(tmpl) || bad < 0)
        return 2;
    if (bad > 0)
        return 1;
    printf("check-no-stale-pinned-facts selftest: %d/%d passed\n", ran, ran);
    return 0;
}
