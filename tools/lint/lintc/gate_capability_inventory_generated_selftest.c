/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-capability-inventory-generated
 * (gate_capability_inventory_generated.c). Mirrors the shell selftest: the
 * full pipeline (run the generator binary — the path given to the selftest,
 * or <ZCL_LINT_BIN_DIR or build/bin>/gen_capability_inventory when none is
 * given — derive the report, verify) must pass on the current tree; a copy
 * of the report with one capability row dropped must FAIL (summary count
 * disagrees with the rows and the header census loses a header); a copy
 * with the regenerate claim removed from the header record must FAIL.
 * Output matches the script exactly: on success only the PASS line followed
 * by the clean verify log. Tampered copies are written under the pipeline's
 * mkdtemp scratch dir (never /tmp), which is removed on every exit path.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"

/* Shared with gate_capability_inventory_generated.c. */
int cig_pipeline(const char *gen, char *scratch_out, size_t scap,
                 char *doc_out, size_t dcap, FILE *err);
int cig_verify_file(const char *path, FILE *out, FILE *err);
int cig_default_gen(char *out, size_t cap);

enum { CIGS_PATH = 1024, CIGS_LINE = 16384 };

static const char k_cigs_claim[] =
    "\"regenerate\":\"make docs-capability-inventory\"";
static const char k_cigs_repl[] = "\"regenerate\":\"-\"";
static const char k_cigs_cap[] = "{\"record\":\"capability";

/* lc_each_line context for both tampered copies: pending is 1 until the
 * first line is tampered (dropped, or its regenerate claim replaced). */
struct cigs_tamper { FILE *out; int pending; };

/* lc_each_line context: copy every line, skipping the first capability row. */
static int cigs_drop_line(void *ctx, const char *line, size_t len)
{
    struct cigs_tamper *d = ctx;
    if (d->pending && strncmp(line, k_cigs_cap, strlen(k_cigs_cap)) == 0) {
        d->pending = 0;
        return 0;
    }
    (void)len;
    return fputs(line, d->out) < 0 ? 2 : 0;
}

/* lc_each_line context: copy, with the regenerate claim replaced in the
 * first line only. */
static int cigs_claim_line(void *ctx, const char *line, size_t len)
{
    struct cigs_tamper *c = ctx;
    (void)len;
    if (c->pending) {
        c->pending = 0;
        const char *p = strstr(line, k_cigs_claim);
        if (p) {
            size_t head = (size_t)(p - line);
            if (fwrite(line, 1, head, c->out) != head ||
                fputs(k_cigs_repl, c->out) < 0 ||
                fputs(p + strlen(k_cigs_claim), c->out) < 0)
                return 2;
            return 0;
        }
    }
    return fputs(line, c->out) < 0 ? 2 : 0;
}

static void cigs_dump(FILE *f, FILE *to)
{
    rewind(f);
    char line[CIGS_LINE];
    while (fgets(line, sizeof line, f))
        fputs(line, to);
}

/* The tampered copies must be refused; their output is discarded, exactly
 * as the script's >/dev/null 2>&1 verify calls. */
static int cigs_expect_fail(const char *path, const char *name)
{
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int rc = cig_verify_file(path, sink, sink);
    fclose(sink);
    if (rc == 0) {
        fprintf(stderr,
                "check_capability_inventory_generated selftest: FAIL — "
                "%s passed\n", name);
        return 1;
    }
    return 0;
}

static int cigs_write_tamper(const char *doc, const char *path,
                             int (*cb)(void *ctx, const char *line, size_t len))
{
    FILE *out = fopen(path, "w");
    if (!out)
        return die("z23-lint: cannot write %s\n", path);
    struct cigs_tamper t = { out, 1 };
    int rc = lc_each_line(doc, cb, &t, 1);
    fclose(out);
    return rc;
}

/* Writes the two tampered copies under scratch and proves both are
 * refused. *bad collects a selftest violation. 0 ok, 2 internal. */
static int cigs_tamper_suite(const char *doc, const char *scratch, int *bad)
{
    char dropped[CIGS_PATH], claim[CIGS_PATH];
    if (ovf(snprintf(dropped, sizeof dropped, "%s/dropped_row.jsonl",
                     scratch), sizeof dropped) ||
        ovf(snprintf(claim, sizeof claim, "%s/dropped_claim.jsonl", scratch),
            sizeof claim))
        return 2;
    int rc = cigs_write_tamper(doc, dropped, cigs_drop_line);
    if (rc)
        return rc;
    *bad |= cigs_expect_fail(dropped, "a dropped capability row");
    rc = cigs_write_tamper(doc, claim, cigs_claim_line);
    if (rc)
        return rc;
    *bad |= cigs_expect_fail(claim, "a removed header claim");
    return 0;
}

int cig_selftest_with(const char *gen)
{
    char genbuf[CIGS_PATH], scratch[CIGS_PATH] = "", doc[CIGS_PATH];
    FILE *clean = NULL;
    int rc = 0, bad = 0;
    if (gen) {
        if (ovf(snprintf(genbuf, sizeof genbuf, "%s", gen), sizeof genbuf))
            return 2;
    } else if (cig_default_gen(genbuf, sizeof genbuf)) {
        return 2;
    }
    FILE *perr = tmpfile();
    if (!perr)
        return die("z23-lint: tmpfile failed\n", "");
    rc = cig_pipeline(genbuf, scratch, sizeof scratch, doc, sizeof doc, perr);
    if (rc) {
        cigs_dump(perr, stderr);
        goto out;
    }
    clean = tmpfile();
    if (!clean) {
        rc = die("z23-lint: tmpfile failed\n", "");
        goto out;
    }
    rc = cig_verify_file(doc, clean, clean);
    if (rc != 0) {
        cigs_dump(clean, stderr);
        goto out;
    }
    rc = cigs_tamper_suite(doc, scratch, &bad);
    if (rc)
        goto out;
    if (bad) {
        rc = 1;
        goto out;
    }
    printf("check_capability_inventory_generated selftest: PASS — the "
           "generated report passes; a dropped capability row and a removed "
           "header claim fail\n");
    cigs_dump(clean, stdout);
    rc = 0;
out:
    if (scratch[0] != '\0')
        rap_rm_rf(scratch);
    if (clean)
        fclose(clean);
    fclose(perr);
    return rc;
}

int check_capability_inventory_generated_selftest(void)
{
    return cig_selftest_with(NULL);
}
