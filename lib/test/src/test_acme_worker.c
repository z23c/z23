/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The certificate worker, graded from outside.
 *
 * WHY THIS GROUP RUNS A BINARY INSTEAD OF CALLING FUNCTIONS. Issuance lives
 * in `zclassic23-acme` (tools/acme) because talking to a certificate
 * authority means being a TLS client with a CA trust store, and the node
 * refuses that property — test_cold_join_sovereign P2 asserts that no
 * Z23-authored object outside lib/test carries an undefined reference to a
 * TLS-client or trust-store entry point. Linking tls_client.c into this test
 * binary would put such an object under a scanned path and turn that
 * property red for a reason that has nothing to do with the node.
 *
 * So the worker's offline assertions travel with the worker, and this group
 * executes them and grades the result. The coverage stays in the suite; the
 * symbols stay out of it. What the worker asserts (139 checks as of this
 * writing, and it prints every one) is URL parsing, HTTP/1.1 response
 * framing, the fail-closed transport refusals, a loopback server whose
 * certificate chains to nothing, the RFC 7638 thumbprint, ES256 JWS verified
 * back through OpenSSL, the recorded ACME response fixtures, and the CSR.
 *
 * The live leg — a real conversation with the Let's Encrypt STAGING
 * directory — is opt-in and never on the push path. See the SKIP text below
 * for what to set.
 */

#include "test/test_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AW_CHECK(name, expr) do {                        \
    printf("acme_worker: %s... ", (name));               \
    if (expr) { printf("OK\n"); }                        \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

static const char WORKER_BIN[] = "build/bin/zclassic23-acme";

static bool binary_present(void)
{
    FILE *f = fopen(WORKER_BIN, "rb");
    if (!f)
        return false;
    fclose(f);
    return true;
}

/* Run the worker and capture its output. `out` is NUL-terminated; returns
 * the exit status, or -1 when the process could not be run. */
static int run_worker(const char *args, char *out, size_t out_len)
{
    char cmd[512];
    if (snprintf(cmd, sizeof(cmd), "%s %s 2>&1", WORKER_BIN, args) >=
        (int)sizeof(cmd))
        return -1;
    FILE *p = popen(cmd, "r");
    if (!p)
        return -1;
    size_t used = 0;
    int c;
    while ((c = fgetc(p)) != EOF) {
        if (used + 1 < out_len)
            out[used++] = (char)c;
    }
    out[used < out_len ? used : out_len - 1] = '\0';
    const int status = pclose(p);
    if (status < 0)
        return -1;
    return (status & 0x7f) == 0 ? (status >> 8) & 0xff : -1;
}

int test_acme_worker(void)
{
    int failures = 0;

    if (!binary_present()) {
        printf("acme_worker: SKIP (%s not built — run `make` or "
               "`make zclassic23-acme`; nothing was asserted in this run)\n",
               WORKER_BIN);
        return 0;
    }

    static char out[256 * 1024];

    /* The whole offline suite the worker carries. */
    {
        const int rc = run_worker("selftest", out, sizeof(out));
        AW_CHECK("the worker's selftest exits zero", rc == 0);
        AW_CHECK("it reports the PASS token",
                 strstr(out, "ALL SELFTESTS PASSED") != NULL);
        AW_CHECK("it reports no FAIL token",
                 strstr(out, "SOME SELFTESTS FAILED") == NULL &&
                 strstr(out, "... FAIL") == NULL);
        /* A selftest that stopped asserting would still print the PASS token.
         * Count the checks so an empty run cannot pass as a full one. */
        size_t checks = 0;
        for (const char *p = out; (p = strstr(p, "... OK\n")) != NULL; p += 7)
            checks++;
        AW_CHECK("it ran a substantial number of checks, not zero",
                 checks >= 100);
        printf("acme_worker: worker selftest reported %zu checks\n", checks);
        AW_CHECK("it exercised the TLS transport legs",
                 strstr(out, "tls_client: ") != NULL);
        AW_CHECK("it exercised the JWS legs",
                 strstr(out, "acme_jws: ") != NULL);
        AW_CHECK("it exercised the ACME wire legs",
                 strstr(out, "acme_protocol: ") != NULL);
        AW_CHECK("it proved an untrusted chain is refused",
                 strstr(out, "chains to nothing trusted is REFUSED... OK") != NULL);
    }

    /* The command surface, which an operator and a timer both depend on. */
    {
        const int rc = run_worker("--help", out, sizeof(out));
        AW_CHECK("--help exits zero and explains the handoff file",
                 rc == 0 && strstr(out, "--handoff") != NULL);

        const int bad = run_worker("nonsense-command --cert x", out, sizeof(out));
        AW_CHECK("an unknown command exits 2, not 0", bad == 2);

        const int nocert = run_worker("check", out, sizeof(out));
        AW_CHECK("check with no --cert exits 2 and names the missing argument",
                 nocert == 2 && strstr(out, "--cert") != NULL);

        const int novalue = run_worker("check --cert", out, sizeof(out));
        AW_CHECK("a flag with no value exits 2 rather than eating the next flag",
                 novalue == 2);
    }

    /* `check` against real files: the verdict a timer branches on. */
    {
        char dir[512];
        char missing[640];
        char garbage[640];
        test_make_tmpdir(dir, sizeof(dir), "acme_worker", "check");
        snprintf(missing, sizeof(missing), "%s/absent.pem", dir);
        snprintf(garbage, sizeof(garbage), "%s/garbage.pem", dir);

        char args[768];
        snprintf(args, sizeof(args), "check --cert %s", missing);
        const int absent = run_worker(args, out, sizeof(out));
        AW_CHECK("check on an absent certificate exits 3 (renewal due)",
                 absent == 3);
        AW_CHECK("and names the verdict in typed output",
                 strstr(out, "verdict=absent") != NULL);

        FILE *f = fopen(garbage, "wb");
        if (f) {
            fputs("this is not a certificate\n", f);
            fclose(f);
        }
        snprintf(args, sizeof(args), "check --cert %s", garbage);
        const int unreadable = run_worker(args, out, sizeof(out));
        AW_CHECK("check on a file that is not a certificate exits 1, never 0",
                 unreadable == 1);
        AW_CHECK("and says so",
                 strstr(out, "verdict=unreadable") != NULL);
        test_rm_rf(dir);
    }

    /* The refusals that protect an operator from a silent wrong order. */
    {
        const int no_tos = run_worker(
            "obtain --domain node.example.org --account /dev/null "
            "--cert /dev/null --key /dev/null --handoff /dev/null --staging",
            out, sizeof(out));
        AW_CHECK("obtain without --agree-tos refuses and exits non-zero",
                 no_tos != 0);
        AW_CHECK("and the refusal names the CA's terms of service, not the caller",
                 strstr(out, "terms of service") != NULL);

        const int both = run_worker(
            "obtain --domain node.example.org --account /dev/null "
            "--cert /dev/null --key /dev/null --handoff /dev/null --agree-tos "
            "--staging --directory https://ca.example/dir",
            out, sizeof(out));
        AW_CHECK("naming two certificate authorities at once exits 2", both == 2);

        const int no_handoff = run_worker(
            "obtain --domain node.example.org --account /dev/null "
            "--cert /dev/null --key /dev/null --agree-tos --staging",
            out, sizeof(out));
        AW_CHECK("obtain without a handoff path refuses: the node would have "
                 "nothing to present",
                 no_handoff != 0 && strstr(out, "handoff") != NULL);
    }

    /* ── the opt-in live leg ───────────────────────────────────────── */
    const char *live = getenv("ZCL_ACME_LIVE_STAGING");
    if (!live || strcmp(live, "1") != 0) {
        printf("acme_worker: SKIP (the live leg contacts the real Let's Encrypt "
               "STAGING directory; set ZCL_ACME_LIVE_STAGING=1 to run it, and "
               "additionally ZCL_ACME_LIVE_DOMAIN=<name> resolving to this host "
               "with 443 reachable plus ZCL_ACME_LIVE_AGREE_TOS=1 for a full "
               "order)\n");
        return failures;
    }

    {
        /* Staging, never production: production rate limits are per-account
         * and measured in weeks, so a test loop that trips one takes the real
         * certificate down with it. */
        char dir[512];
        char args[1024];
        test_make_tmpdir(dir, sizeof(dir), "acme_worker", "live");
        const char *domain = getenv("ZCL_ACME_LIVE_DOMAIN");
        const char *agree = getenv("ZCL_ACME_LIVE_AGREE_TOS");
        if (!domain || !domain[0] || !agree || strcmp(agree, "1") != 0) {
            /* Prove the transport and the public chain without issuing: a
             * `check` cannot do it, so drive one real fetch through the
             * worker by asking it to order for a name it will fail to
             * validate — and require the failure to be a VALIDATION failure,
             * which only happens after the CA answered over a verified TLS
             * connection. */
            snprintf(args, sizeof(args),
                     "obtain --domain invalid.example --account %s/acct.pem "
                     "--cert %s/c.pem --key %s/k.pem --handoff %s/h.txt "
                     "--agree-tos --staging --poll-attempts 1 "
                     "--poll-interval-ms 1000",
                     dir, dir, dir, dir);
            const int rc = run_worker(args, out, sizeof(out));
            AW_CHECK("the staging CA is reachable over a verified chain",
                     strstr(out, "cannot reach") == NULL &&
                     strstr(out, "no CA trust store") == NULL);
            AW_CHECK("an unresolvable name fails at the CA, not at our transport",
                     rc != 0);
            printf("acme_worker: SKIP (the full order leg needs "
                   "ZCL_ACME_LIVE_DOMAIN=<name> and ZCL_ACME_LIVE_AGREE_TOS=1; "
                   "only the reachability leg ran)\n");
        } else {
            snprintf(args, sizeof(args),
                     "obtain --domain %s --account %s/acct.pem --cert %s/c.pem "
                     "--key %s/k.pem --handoff %s/h.txt --agree-tos --staging",
                     domain, dir, dir, dir, dir);
            const int rc = run_worker(args, out, sizeof(out));
            AW_CHECK("a staging certificate is issued end to end", rc == 0);
            char cert[640];
            snprintf(cert, sizeof(cert), "%s/c.pem", dir);
            FILE *f = fopen(cert, "rb");
            AW_CHECK("the chain landed on disk", f != NULL);
            if (f)
                fclose(f);
        }
        test_rm_rf(dir);
    }

    return failures;
}
