/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family - check-promotion-receipt-chain of the C23 lint
 * runtime, the replacement for the bash body of
 * build/bin/z23-lint check-promotion-receipt-chain. The promotion receipt ledger
 * stays a chain: append-only, hash-linked, signed, replicated and verifiable
 * by someone who does not trust us. The gate runs the writer's tamper-detection
 * self-test, checks the trust anchor against the record count, verifies the
 * in-tree ledger with no private key in reach, enforces append-only against
 * git, asserts that init refuses to default a signing key and that
 * tools/ship.sh still appends a receipt on promotion. The checks live in
 * gate_promotion_receipt_chain_checks.c and _git.c.
 *
 * SIGINT, SIGTERM and SIGHUP stop the running child group, remove the scratch
 * directory and are re-raised. Selftest: gate_promotion_receipt_chain_selftest.c.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_promotion_receipt_chain_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

const char k_prc_want_nokey[] =
    "promotion_receipt: refuse — no signing key configured; set ZCL_RECEIPT_KEY to a key whose "
    "only purpose is signing promotion evidence";

int prc_say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    return n;
}

char *prc_fmt(const char *fmt, ...)
{
    va_list ap, cp;
    va_start(ap, fmt);
    va_copy(cp, ap);
    int n = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);
    char *out = n >= 0 ? malloc((size_t)n + 1) : NULL; // raw-alloc-ok:lint-runtime
    if (out)
        vsnprintf(out, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return out;
}

/* Runs spec and returns its exit status (127 when it cannot start), -1 when a
 * termination signal stopped it. Output that could not be kept whole is
 * reported on stderr and stops the gate with status 2. */
static int prc_exec(struct prc_run *g, const struct lcp_spec *spec, char **out)
{
    struct lcp_buf buf = { 0 };
    int code = 127, rc = lcp_run(spec, &buf, &code);
    lcp_buf_subst(&buf);
    if (out)
        *out = strdup(buf.data ? buf.data : "");
    if (rc == 0 && (buf.lost || (out && !*out))) {
        fflush(stdout);
        fprintf(stderr, "check_promotion_receipt_chain: %s\n",
                buf.lost == LCP_LOST_TRUNCATED ? "command output exceeded the capture limit"
                                               : "out of memory while capturing command output");
        g->rc = 2;
    }
    lcp_buf_free(&buf);
    if (rc == 1 && out) {
        free(*out);
        *out = NULL;
    }
    return rc == 1 ? -1 : (rc == 0 ? code : 127);
}

int prc_bash(struct prc_run *g, const char *const *args, const char *const *set,
             const char *const *unset, int mode, char **out)
{
    size_t n = 0, cnt = 3;
    for (const char *const *a = args; *a; a++)
        cnt++;
    char **argv = malloc(cnt * sizeof *argv); // raw-alloc-ok:lint-runtime
    if (!argv) {
        g->rc = 2;
        fprintf(stderr, "check_promotion_receipt_chain: out of memory\n");
        *out = NULL;
        return 127;
    }
    argv[n++] = (char *)"bash";
    argv[n++] = (char *)g->cfg->tool;
    for (; *args; args++)
        argv[n++] = (char *)*args;
    argv[n] = NULL;
    struct lcp_spec s = { argv, set, unset, (enum lcp_mode)mode, g->cfg->grace_ms, NULL };
    int rc = prc_exec(g, &s, out);
    free(argv);
    return rc;
}

int prc_git(struct prc_run *g, char *const argv[], int mode, char **out)
{
    struct lcp_spec s = { argv, NULL, NULL, (enum lcp_mode)mode, g->cfg->grace_ms, NULL };
    return prc_exec(g, &s, out);
}

long prc_count_lines(const char *path)
{
    FILE *f = fopen(path, "r");
    long lines = 0, len = 0;
    int c;
    if (!f)
        return -1;
    while ((c = getc(f)) != EOF) {
        if (c == '\n') {
            lines += len > 0;
            len = 0;
        } else {
            len++;
        }
    }
    lines += len > 0;
    fclose(f);
    return lines;
}

static void (*const k_prc_steps[])(struct prc_run *) = {
    prc_check_selftest, prc_check_anchor, prc_check_ledger,
    prc_check_append_only, prc_check_no_key, prc_check_ship,
};

static int prc_steps(struct prc_run *g)
{
    for (size_t i = 0; i < sizeof k_prc_steps / sizeof k_prc_steps[0]; i++) {
        k_prc_steps[i](g);
        if (g->rc || lsc_pending())
            break;
    }
    if (g->rc)
        return g->rc;
    if (lsc_pending())
        return 1;
    if (g->fail)
        return 1;
    puts("check_promotion_receipt_chain: clean — chain verifies, tamper detection proven, "
         "append-only vs HEAD, and ship.sh still records");
    return 0;
}

int prc_gate(const struct prc_cfg *cfg)
{
    struct prc_run g = { .cfg = cfg };
    int rc, sig;
    setenv("LC_ALL", "C", 1);
    if (lsc_install() != 0 || chdir(cfg->root) != 0) {
        fprintf(stderr, "z23-lint: check-promotion-receipt-chain: cannot enter %s\n", cfg->root);
        return 1;
    }
    rc = prc_steps(&g);
    fflush(stdout);
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc;
}

int check_promotion_receipt_chain_run(int argc, char **argv)
{
    char *root = malloc(PRC_ROOT_CAP); // raw-alloc-ok:lint-runtime
    (void)argc;
    (void)argv;
    if (!root || cic_repo_root(root, PRC_ROOT_CAP)) {
        free(root);
        return 1;
    }
    const struct prc_cfg cfg = {
        .root = root,
        .tool = "tools/scripts/promotion_receipt.sh",
        .ledger = "platform/deploy/promotion-receipts.jsonl",
        .signers = "platform/deploy/promotion-signers",
        .ship = "tools/ship.sh",
        .grace_ms = PRC_GRACE_MS,
    };
    int rc = prc_gate(&cfg);
    free(root);
    return rc;
}
