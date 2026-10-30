/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-no-live-lab-history
 * (gate_no_live_lab_history.c). Ports every case of the shell selftest:
 * a safe baseline fixture passes; an appended live_confirmed receipt, an
 * appended micro-lab event, a duplicate tracked notebook, and a tracked
 * recipient-wallet manifest each fail.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <string.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_no_live_lab_history_priv.h"

enum { NLLS_PATH = 1024 };

static const char k_nlls_lab_line[] =
    "{\"schema\":\"zcl.transaction_lab_event.v1\",\"proof\":\"simnet_confirmed\"}\n";

struct nlls_case {
    const char *name;
    const char *lab_tail;  /* appended to the lab baseline */
    const char *micro_tail;/* appended to the micro template */
    const char *extra;     /* extra tracked path, or NULL */
    const char *extra_text;/* its full content */
    size_t extra_len;      /* its length; 0 means strlen(extra_text) */
    int want;              /* expected nllh_check_paths return */
    size_t micro_len;      /* micro_tail length; 0 means strlen(micro_tail) */
    int micro_bare;        /* 1: the micro header is written with no newline */
};

/* A tracked .jsonl with a NUL after the lab line that nlls_write prepends,
 * then the live-confirmed marker. The NUL must not hide the marker: the
 * shell's $(<file) drops NULs. */
static const char k_nul_probe[] = "\0{\"proof\":\"live_confirmed\"}\n";

/* A micro baseline written as the bare header (no newline), then a NUL and
 * junk, then the one newline. The shell's $(<file) drops the NUL, so the
 * content is not the template and must fail. */
static const char k_nul_micro[] = "\0junk\n";

static const struct nlls_case k_nlls_cases[] = {
    { "safe baseline fixture is accepted", "", "", NULL, NULL, 0, 0, 0, 0 },
    { "tracked live confirmation is rejected",
      "{\"proof\":\"live_confirmed\"}\n", "", NULL, NULL, 0, 1, 0, 0 },
    { "tracked micro-lab history is rejected", "",
      "{\"schema\":\"zcl.transaction_micro_lab_event.v1\"}\n", NULL, NULL, 0, 1, 0, 0 },
    { "duplicate tracked notebook is rejected", "", "",
      "private/transaction-lab-events.jsonl", NULL, 0, 1, 0, 0 },
    { "tracked recipient-wallet manifest is rejected", "", "",
      "private/recipient.json",
      "{\"schema\":\"zcl.transaction_micro_lab_recipient_wallet.v1\"}\n", 0, 1, 0, 0 },
    { "NUL byte before a live confirmation is rejected", "", "",
      "private/nul-probe.jsonl", k_nul_probe, sizeof k_nul_probe - 1, 1, 0, 0 },
    { "micro baseline with NUL-then-junk after the header is rejected", "",
      k_nul_micro, NULL, NULL, 0, 1, sizeof k_nul_micro - 1, 1 },
};

static size_t nlls_extra_len(const struct nlls_case *c)
{
    if (c->extra_len)
        return c->extra_len;
    return c->extra_text ? strlen(c->extra_text) : 0;
}

static size_t nlls_micro_len(const struct nlls_case *c)
{
    return c->micro_len ? c->micro_len : strlen(c->micro_tail);
}

static int nlls_write(const char *root, const char *rel, const char *tail,
                      size_t tail_len, int bare)
{
    char path[NLLS_PATH];
    char hdr[NLLS_PATH];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    const char *base = strcmp(rel, nllh_micro_baseline) == 0
                           ? nllh_micro_header : k_nlls_lab_line;
    if (ovf(snprintf(hdr, sizeof hdr, bare ? "%s" : "%s\n", base), sizeof hdr))
        return 2;
    FILE *f = fopen(path, "wb");
    if (!f)
        return die("z23-lint: cannot write fixture %s\n", path);
    fputs(hdr, f);
    if (tail_len)
        fwrite(tail, 1, tail_len, f);
    fclose(f);
    return 0;
}

static int nlls_fixture(const char *root, const struct nlls_case *c)
{
    char dir[NLLS_PATH];
    if (ovf(snprintf(dir, sizeof dir, "%s/docs/quality", root), sizeof dir))
        return 2;
    int rc = csr_mkdirs(dir);
    if (rc == 0) {
        rc = nlls_write(root, nllh_lab_baseline, c->lab_tail, strlen(c->lab_tail), 0);
        if (rc == 0)
            rc = nlls_write(root, nllh_micro_baseline, c->micro_tail, nlls_micro_len(c), c->micro_bare);
    }
    if (rc == 0 && c->extra) {
        if (ovf(snprintf(dir, sizeof dir, "%s/private", root), sizeof dir))
            return 2;
        rc = csr_mkdirs(dir);
        if (rc == 0)
            rc = nlls_write(root, c->extra, c->extra_text, nlls_extra_len(c), 0);
    }
    return rc;
}

static int nlls_run_case(const char *root, const struct nlls_case *c)
{
    int rc = nlls_fixture(root, c);
    if (rc)
        return rc;
    const char *paths[3];
    size_t n = 2;
    paths[0] = nllh_lab_baseline;
    paths[1] = nllh_micro_baseline;
    if (c->extra)
        paths[n++] = c->extra;
    FILE *sink = tmpfile();
    if (!sink)
        return die("z23-lint: tmpfile failed\n", "");
    int got = nllh_check_paths(root, paths, n, sink);
    fclose(sink);
    if (got != c->want) {
        fprintf(stderr,
                "check-no-live-lab-history selftest: %s: want rc=%d got rc=%d\n",
                c->name, c->want, got);
        return 1;
    }
    return 0;
}

int check_no_live_lab_history_selftest(void)
{
    char root[NLLS_PATH];
    int rc = lct_scratch_dir(root, sizeof root, "no-live-lab-history");
    if (rc)
        return rc;
    int bad = 0;
    for (size_t i = 0; i < sizeof k_nlls_cases / sizeof k_nlls_cases[0]; i++)
        bad |= nlls_run_case(root, &k_nlls_cases[i]) != 0;
    rap_rm_rf(root);
    if (bad) {
        fputs("FAIL: check_no_live_lab_history selftest\n", stderr);
        return 1;
    }
    puts("check-no-live-lab-history selftest: PASS");
    return 0;
}
