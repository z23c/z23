/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The renewal decision. See net/acme_renewal.h for why the rule is a pure
 * function of two integers.
 */

#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "net/acme_renewal.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "base/log_macros.h"
#include "platform/time_compat.h"

bool acme_renewal_due(int64_t not_after, int64_t now)
{
    /* Subtraction, not `now > not_after - window`: the second form overflows
     * for a notAfter near INT64_MIN, and a certificate parser can hand us
     * anything. */
    if (now >= not_after)
        return true;
    return not_after - now < ACME_RENEWAL_WINDOW_SECONDS;
}

enum acme_renewal_action acme_renewal_decide(int64_t not_before,
                                             int64_t not_after, int64_t now)
{
    if (not_after <= not_before)
        return ACME_RENEWAL_UNREADABLE;
    if (now >= not_after)
        return ACME_RENEWAL_EXPIRED;
    if (now < not_before)
        return ACME_RENEWAL_NOT_YET_VALID;
    return acme_renewal_due(not_after, now) ? ACME_RENEWAL_DUE
                                            : ACME_RENEWAL_CURRENT;
}

const char *acme_renewal_action_name(enum acme_renewal_action action)
{
    switch (action) {
    case ACME_RENEWAL_CURRENT:        return "current";
    case ACME_RENEWAL_DUE:            return "due";
    case ACME_RENEWAL_EXPIRED:        return "expired";
    case ACME_RENEWAL_NOT_YET_VALID:  return "not_yet_valid";
    case ACME_RENEWAL_ABSENT:         return "absent";
    case ACME_RENEWAL_UNREADABLE:     return "unreadable";
    }
    return "unknown";
}

/* ASN1_TIME to Unix seconds, via OpenSSL's own difference-from-now so the
 * calendar arithmetic (leap years, the two-digit UTCTime pivot) stays in one
 * audited implementation rather than being re-derived here. */
static bool asn1_time_to_unix(const ASN1_TIME *t, int64_t *out)
{
    if (!t || !out)
        return false;
    const time_t reference = platform_time_wall_time_t();
    if (reference == (time_t)-1)
        return false;
    int days = 0;
    int seconds = 0;
    if (ASN1_TIME_diff(&days, &seconds, NULL, t) != 1)
        return false;
    *out = (int64_t)reference + (int64_t)days * 86400 + (int64_t)seconds;
    return true;
}

bool acme_certificate_validity(const char *pem_path, int64_t *not_before,
                               int64_t *not_after)
{
    if (!pem_path || !not_before || !not_after)
        return false;
    *not_before = 0;
    *not_after = 0;
    FILE *f = fopen(pem_path, "rb");
    if (!f)
        return false;
    X509 *cert = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    if (!cert)
        LOG_FAIL("acme", "no certificate could be read from %s", pem_path);
    const bool ok = asn1_time_to_unix(X509_get0_notBefore(cert), not_before) &&
                    asn1_time_to_unix(X509_get0_notAfter(cert), not_after);
    X509_free(cert);
    if (!ok) {
        *not_before = 0;
        *not_after = 0;
        LOG_FAIL("acme", "cannot read the validity window of %s", pem_path);
    }
    return true;
}

enum acme_renewal_action acme_renewal_check(const char *pem_path, int64_t now)
{
    if (!pem_path || !pem_path[0])
        return ACME_RENEWAL_ABSENT;
    FILE *probe = fopen(pem_path, "rb");
    if (!probe)
        return ACME_RENEWAL_ABSENT;
    fclose(probe);

    int64_t not_before = 0;
    int64_t not_after = 0;
    if (!acme_certificate_validity(pem_path, &not_before, &not_after))
        return ACME_RENEWAL_UNREADABLE;
    return acme_renewal_decide(not_before, not_after, now);
}

int64_t acme_renewal_seconds_until_due(const char *pem_path, int64_t now)
{
    int64_t not_before = 0;
    int64_t not_after = 0;
    if (acme_renewal_check(pem_path, now) != ACME_RENEWAL_CURRENT)
        return 0;
    if (!acme_certificate_validity(pem_path, &not_before, &not_after))
        return 0;
    const int64_t due_at = not_after - ACME_RENEWAL_WINDOW_SECONDS;
    return due_at > now ? due_at - now : 0;
}
