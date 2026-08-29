/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The renewal decision, at its boundaries.
 *
 * This is the piece whose absence breaks the one-line bootstrap silently and
 * on a timer, so the boundary is pinned to the second in both directions:
 * exactly thirty days remaining is NOT due, one second under it IS. A rule
 * that is off by one day here is invisible until the day it is not.
 */

#include "test/test_core.h"

#include "net/acme_challenge.h"
#include "net/acme_b64url.h"
#include "net/acme_renewal.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <time.h>
#include <string.h>

#include "platform/time_compat.h"

#define AR_CHECK(name, expr) do {                        \
    printf("acme_renewal: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                        \
    else { printf("FAIL\n"); failures++; }               \
} while (0)

#define DAY (24 * 3600)

int test_acme_renewal(void)
{
    int failures = 0;
    const int64_t now = 1788000000; /* an arbitrary fixed "now"; nothing reads a clock */

    /* ── the 30-day rule, to the second ────────────────────────────── */
    AR_CHECK("90 days remaining is not due",
             !acme_renewal_due(now + 90 * DAY, now));
    AR_CHECK("31 days remaining is not due",
             !acme_renewal_due(now + 31 * DAY, now));
    AR_CHECK("exactly 30 days remaining is NOT yet due",
             !acme_renewal_due(now + 30 * DAY, now));
    AR_CHECK("30 days minus one second IS due",
             acme_renewal_due(now + 30 * DAY - 1, now));
    AR_CHECK("29 days remaining is due",
             acme_renewal_due(now + 29 * DAY, now));
    AR_CHECK("one second remaining is due", acme_renewal_due(now + 1, now));
    AR_CHECK("expiring exactly now is due", acme_renewal_due(now, now));
    AR_CHECK("expired an hour ago is due", acme_renewal_due(now - 3600, now));
    AR_CHECK("the window constant is thirty days",
             ACME_RENEWAL_WINDOW_SECONDS == 30 * DAY);

    /* An extreme notAfter must not overflow into the wrong answer — a
     * certificate parser can hand this function anything. */
    AR_CHECK("INT64_MIN notAfter is due, not wrapped",
             acme_renewal_due(INT64_MIN, now));
    AR_CHECK("INT64_MAX notAfter is not due, not wrapped",
             !acme_renewal_due(INT64_MAX, now));

    /* ── the full verdict ──────────────────────────────────────────── */
    AR_CHECK("a fresh 90-day certificate is current",
             acme_renewal_decide(now - DAY, now + 89 * DAY, now) ==
                 ACME_RENEWAL_CURRENT);
    AR_CHECK("a certificate inside the window is due",
             acme_renewal_decide(now - 60 * DAY, now + 20 * DAY, now) ==
                 ACME_RENEWAL_DUE);
    AR_CHECK("a certificate at exactly the window edge is still current",
             acme_renewal_decide(now - 60 * DAY, now + 30 * DAY, now) ==
                 ACME_RENEWAL_CURRENT);
    AR_CHECK("an expired certificate reports expired, not merely due",
             acme_renewal_decide(now - 90 * DAY, now - 1, now) ==
                 ACME_RENEWAL_EXPIRED);
    AR_CHECK("expiring exactly now reports expired",
             acme_renewal_decide(now - 90 * DAY, now, now) ==
                 ACME_RENEWAL_EXPIRED);
    AR_CHECK("a certificate whose notBefore is in the future reports not-yet-valid",
             acme_renewal_decide(now + DAY, now + 90 * DAY, now) ==
                 ACME_RENEWAL_NOT_YET_VALID);
    AR_CHECK("notAfter at or before notBefore is nonsense, not a verdict",
             acme_renewal_decide(now, now, now) == ACME_RENEWAL_UNREADABLE &&
             acme_renewal_decide(now, now - 1, now) == ACME_RENEWAL_UNREADABLE);

    AR_CHECK("every verdict has a stable name",
             strcmp(acme_renewal_action_name(ACME_RENEWAL_CURRENT), "current") == 0 &&
             strcmp(acme_renewal_action_name(ACME_RENEWAL_DUE), "due") == 0 &&
             strcmp(acme_renewal_action_name(ACME_RENEWAL_EXPIRED), "expired") == 0 &&
             strcmp(acme_renewal_action_name(ACME_RENEWAL_NOT_YET_VALID),
                    "not_yet_valid") == 0 &&
             strcmp(acme_renewal_action_name(ACME_RENEWAL_ABSENT), "absent") == 0 &&
             strcmp(acme_renewal_action_name(ACME_RENEWAL_UNREADABLE),
                    "unreadable") == 0);

    /* ── the scheduling seam, against real files ───────────────────── */
    {
        char dir[512];
        char missing[640];
        char garbage[640];
        char real[640];
        test_make_tmpdir(dir, sizeof(dir), "acme_renewal", "certs");
        snprintf(missing, sizeof(missing), "%s/absent.pem", dir);
        snprintf(garbage, sizeof(garbage), "%s/garbage.pem", dir);
        snprintf(real, sizeof(real), "%s/cert.pem", dir);

        const int64_t real_now = (int64_t)platform_time_wall_time_t();

        AR_CHECK("no certificate on disk reports absent, not current",
                 acme_renewal_check(missing, real_now) == ACME_RENEWAL_ABSENT);
        AR_CHECK("an empty path reports absent",
                 acme_renewal_check("", real_now) == ACME_RENEWAL_ABSENT);
        AR_CHECK("a NULL path reports absent",
                 acme_renewal_check(NULL, real_now) == ACME_RENEWAL_ABSENT);

        FILE *f = fopen(garbage, "wb");
        if (f) {
            fputs("this file exists and is not a certificate\n", f);
            fclose(f);
        }
        AR_CHECK("a file that is not a certificate reports unreadable, never current",
                 acme_renewal_check(garbage, real_now) == ACME_RENEWAL_UNREADABLE);
        {
            int64_t nb = 1;
            int64_t na = 1;
            AR_CHECK("validity extraction refuses a non-certificate",
                     !acme_certificate_validity(garbage, &nb, &na) &&
                     nb == 0 && na == 0);
            AR_CHECK("validity extraction refuses an absent file",
                     !acme_certificate_validity(missing, &nb, &na));
        }

        /* The challenge-certificate builder is the one certificate factory
         * in the tree that needs no CA; its output is valid for seven days,
         * which is inside the thirty-day window by construction. */
        char authz[256];
        uint8_t thumb[32];
        memset(thumb, 0x5A, sizeof(thumb));
        X509 *cert = NULL;
        EVP_PKEY *key = NULL;
        if (acme_key_authorization("tok", thumb, authz, sizeof(authz)) &&
            acme_alpn_challenge_certificate("node.example.org", authz, &cert, &key)) {
            FILE *out = fopen(real, "wb");
            const bool wrote = out && PEM_write_X509(out, cert) == 1;
            if (out)
                fclose(out);
            AR_CHECK("a real certificate is written for the file legs", wrote);

            int64_t nb = 0;
            int64_t na = 0;
            AR_CHECK("its validity window reads back",
                     acme_certificate_validity(real, &nb, &na) && na > nb);
            AR_CHECK("notBefore is backdated and notAfter is in the future",
                     nb <= real_now && na > real_now);
            /* Cert-internal arithmetic, no real clock: the builder sets
             * notAfter - notBefore to backdate + lifetime; the ±1 covers a
             * one-second tick between the two gmtime_adj calls. */
            AR_CHECK("the lifetime is the hour backdate plus seven days",
                     na - nb >= 3600 + 7 * DAY - 1 &&
                     na - nb <= 3600 + 7 * DAY + 1);
            AR_CHECK("a seven-day certificate is DUE, being inside the window",
                     acme_renewal_check(real, real_now) == ACME_RENEWAL_DUE);
            AR_CHECK("nothing to wait for when a certificate is already due",
                     acme_renewal_seconds_until_due(real, real_now) == 0);
            AR_CHECK("a certificate read at a time past its notAfter is expired",
                     acme_renewal_check(real, na + 1) == ACME_RENEWAL_EXPIRED);
            AR_CHECK("a certificate read before its notBefore is not yet valid",
                     acme_renewal_check(real, nb - 1) == ACME_RENEWAL_NOT_YET_VALID);
            AR_CHECK("an absent certificate has nothing to wait for either",
                     acme_renewal_seconds_until_due(missing, real_now) == 0);
        } else {
            failures += 8;
        }
        X509_free(cert);
        EVP_PKEY_free(key);
        test_rm_rf(dir);
    }

    return failures;
}
