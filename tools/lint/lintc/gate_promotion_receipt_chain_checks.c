/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the self-test, trust-anchor and ledger-verification checks of
 * check-promotion-receipt-chain (prongs 1, 3 and 2 of the replaced script, in
 * the order the script ran them).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gate_promotion_receipt_chain_priv.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

static const char k_prc_pass[] = "PROMOTION RECEIPT SELF-TEST: PASS";

/* The start of the line after the one at p, or NULL at the end of text. */
static const char *prc_next(const char *p)
{
    const char *nl = strchr(p, '\n');
    return nl && nl[1] ? nl + 1 : NULL;
}

static int prc_has_line(const char *text, const char *line)
{
    size_t n = strlen(line);
    for (const char *p = text; p && *p; p = prc_next(p)) {
        if (strncmp(p, line, n) == 0 && (p[n] == '\n' || p[n] == '\0'))
            return 1;
    }
    return 0;
}

void prc_check_selftest(struct prc_run *g)
{
    const struct prc_cfg *c = g->cfg;
    const char *const args[] = { "--self-test", NULL };
    char *out = NULL;
    if (access(c->tool, R_OK) != 0) {
        prc_say("FAIL: %s is missing — the promotion receipt ledger has no writer or verifier", c->tool);
        g->fail = 1;
        return;
    }
    int rc = prc_bash(g, args, NULL, NULL, LCP_BOTH, &out);
    if (rc < 0 || g->rc)
        goto done;
    if (rc != 0 || !prc_has_line(out, k_prc_pass)) {
        prc_say("FAIL: %s --self-test (rc=%d; no '%s' line)", c->tool, rc, k_prc_pass);
        prc_say("%s", out);
        g->fail = 1;
    } else {
        prc_say("  ok: %s --self-test (chain + signature tamper detection)", c->tool);
    }
done:
    free(out);
}

static long prc_count_keys(const char *path)
{
    static const char re_text[] =
        "^[^#[:space:]]+[[:space:]]+(ssh|sk-ssh|ecdsa)[^[:space:]]*[[:space:]]+[A-Za-z0-9+/=]+";
    regex_t re;
    FILE *f = fopen(path, "r");
    char *line = NULL;
    size_t cap = 0;
    long keys = 0;
    if (!f || regcomp(&re, re_text, REG_EXTENDED | REG_NOSUB) != 0) {
        if (f)
            fclose(f);
        return -1;
    }
    while (getline(&line, &cap, f) >= 0)
        keys += regexec(&re, line, 0, NULL, 0) == 0;
    regfree(&re);
    free(line);
    fclose(f);
    return keys;
}

static void prc_anchor_verdict(struct prc_run *g, long keys, long records)
{
    const struct prc_cfg *c = g->cfg;
    if (keys == 0 && records > 0) {
        prc_say("FAIL: %s holds %ld record(s) but %s lists no public key.", c->ledger, records, c->signers);
        prc_say("      Those records cannot be verified by anyone, which makes them assertions");
        prc_say("      rather than evidence. Add the signing identity that produced them.");
        g->fail = 1;
    } else if (keys == 0) {
        prc_say("  ok: %s lists no key yet and %s holds no records — consistent, unrecorded", c->signers,
                c->ledger);
        prc_say("      (the evidence-signing identity is an owner decision: docs/dev/PROMOTION_RECEIPTS.md, "
                "\"Owner setup\")");
    } else {
        prc_say("  ok: %s names %ld signing identity/identities for %ld record(s)", c->signers, keys, records);
    }
}

void prc_check_anchor(struct prc_run *g)
{
    const struct prc_cfg *c = g->cfg;
    long records = access(c->ledger, R_OK) == 0 ? prc_count_lines(c->ledger) : 0;
    if (access(c->signers, R_OK) != 0) {
        prc_say("FAIL: %s is missing — nothing could verify a receipt's authorship", c->signers);
        g->fail = 1;
        return;
    }
    if (prc_count_lines(c->signers) < 1) {
        fflush(stdout);
        fprintf(stderr,
                "check-promotion-receipt-chain: FATAL — scan set is '%ld' (< floor 1).\n"
                "  The scan producer (find/glob/grep) returned too little; a\n"
                "  scanned dir/file was likely renamed, moved, or deleted.\n"
                "  Refusing to report 'clean' off a hollow (empty) scan.\n"
                "  %s read as empty; the scan producer broke (the file carries a documented header)\n",
                prc_count_lines(c->signers), c->signers);
        g->rc = 2;
        return;
    }
    long keys = prc_count_keys(c->signers);
    prc_anchor_verdict(g, keys < 0 ? 0 : keys, records < 0 ? 0 : records);
}

static void prc_print_matching(const char *out)
{
    for (const char *p = out; p && *p; p = prc_next(p)) {
        size_t n = strcspn(p, "\n");
        char *line = strndup(p, n);
        if (line && (strstr(line, "chain intact") || strstr(line, "NO PROMOTION RECORDED")))
            prc_say("      %s", line);
        free(line);
    }
}

void prc_check_ledger(struct prc_run *g)
{
    const struct prc_cfg *c = g->cfg;
    const char *const args[] = { "verify", NULL };
    const char *const set[] = { "ZCL_RECEIPT_KEY=/nonexistent/no-private-key-here", NULL };
    char *out = NULL;
    if (access(c->ledger, F_OK) != 0) {
        prc_say("FAIL: %s does not exist. The ledger file itself is the replication", c->ledger);
        prc_say("      story — it ships tracked and empty so a promotion has somewhere to land");
        prc_say("      that reaches origin. Recreate it (an empty file is the correct shipped");
        prc_say("      state) rather than letting the path disappear.");
        g->fail = 1;
    } else if (access(c->ledger, R_OK) != 0) {
        prc_say("FAIL: %s exists but is not readable", c->ledger);
        g->fail = 1;
    } else {
        int rc = prc_bash(g, args, set, NULL, LCP_BOTH, &out);
        if (rc < 0 || g->rc) {
            free(out);
            return;
        }
        if (rc != 0) {
            prc_say("FAIL: %s verify on the in-tree ledger (rc=%d)", c->tool, rc);
            prc_say("%s", out);
            g->fail = 1;
        } else {
            prc_say("  ok: %s verifies with no private key present", c->ledger);
            prc_print_matching(out);
        }
        free(out);
    }
}
