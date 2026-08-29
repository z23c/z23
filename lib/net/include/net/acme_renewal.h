/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * When to renew, and the seam that asks.
 *
 * A Let's Encrypt certificate lasts ninety days. `curl -fsSL https://…`
 * fails hard on an expired one, with no warning beforehand, so an unattended
 * certificate is a silent timer to an outage of the one-line bootstrap. The
 * decision below is deliberately a pure function of two integers: it is the
 * part that must never be wrong, and it is the part a test can pin at its
 * boundaries without a clock, a CA, or a filesystem.
 *
 * Thirty days of margin is not arbitrary. It leaves room for roughly a
 * fortnight of failed attempts — a CA outage, a rate limit, a box that was
 * powered off — before anything a visitor can see changes.
 */

#ifndef ZCL_NET_ACME_RENEWAL_H
#define ZCL_NET_ACME_RENEWAL_H

#include <stdbool.h>
#include <stdint.h>

#define ACME_RENEWAL_WINDOW_SECONDS (30 * 24 * 3600)

enum acme_renewal_action {
    ACME_RENEWAL_CURRENT = 0,  /* more than the window remains; do nothing */
    ACME_RENEWAL_DUE,          /* inside the window; renew now */
    ACME_RENEWAL_EXPIRED,      /* already past notAfter; renew now, loudly */
    ACME_RENEWAL_NOT_YET_VALID,/* notBefore is in the future */
    ACME_RENEWAL_ABSENT,       /* no certificate on disk at all */
    ACME_RENEWAL_UNREADABLE,   /* a file exists but is not a certificate */
};

/* Pure. The whole rule: renew once fewer than ACME_RENEWAL_WINDOW_SECONDS
 * remain. Exactly the window remaining is NOT yet due. */
bool acme_renewal_due(int64_t not_after, int64_t now);

/* Pure. The full verdict, including the two states that are not simply
 * "soon": already expired, and not yet valid. */
enum acme_renewal_action acme_renewal_decide(int64_t not_before,
                                             int64_t not_after, int64_t now);

/* Stable one-word name for a verdict, for logs and typed status output. */
const char *acme_renewal_action_name(enum acme_renewal_action action);

/* Read notBefore/notAfter (as Unix seconds) from the FIRST certificate in a
 * PEM file — the leaf. Returns false when the file is absent or unparsable;
 * the two cases are distinguished by acme_renewal_check(). */
bool acme_certificate_validity(const char *pem_path, int64_t *not_before,
                               int64_t *not_after);

/* The scheduling seam: look at what is on disk right now and say what should
 * happen. Does not renew anything and never blocks — a caller on a timer
 * tick calls this, and only then decides whether to run the order flow. */
enum acme_renewal_action acme_renewal_check(const char *pem_path, int64_t now);

/* Seconds until the certificate at `pem_path` enters the renewal window, or
 * 0 when it is already due, absent, or unreadable. A scheduler uses this to
 * sleep instead of polling. */
int64_t acme_renewal_seconds_until_due(const char *pem_path, int64_t now);

#endif /* ZCL_NET_ACME_RENEWAL_H */
