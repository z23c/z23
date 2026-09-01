/* zotp — HOTP one-time passwords (RFC 4226)
 *
 * Apache-2.0 licensed. C23, freestanding-friendly, no allocation.
 *
 * HMAC-SHA1-based one-time passwords: the counter-based HOTP
 * algorithm used by TOTP authenticators, hardware tokens, and
 * two-factor login flows. Includes the HMAC-SHA1 construction itself
 * (built on zsha1) exposed separately, since HMAC-SHA1 is still
 * required by legacy protocols even though bare SHA-1 is broken.
 *
 * HOTP(secret, counter) = Truncate(HMAC-SHA1(secret, counter))
 * rendered as `digits` decimal digits (6 or 8 in practice).
 */
#ifndef ZOTP_H
#define ZOTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZOTP_MIN_DIGITS 6u
#define ZOTP_MAX_DIGITS 9u /* 10^9 still fits in uint32_t */

/* RFC 2104 HMAC-SHA1, one-shot. Keys longer than the 64-byte block
 * are hashed first per the RFC. No context reuse, no global state. */
void zotp_hmac_sha1(const void *key, size_t key_len,
                    const void *data, size_t data_len,
                    uint8_t out[20]);

/* RFC 4226 dynamic truncation of a 20-byte HMAC result: 31-bit
 * value selected by the low nibble of the last byte. */
uint32_t zotp_truncate(const uint8_t hmac[20]);

/* HOTP value (pre-modulo) for a counter. */
uint32_t zotp_hotp_value(const void *secret, size_t secret_len,
                         uint64_t counter);

/* HOTP rendered as `digits` decimal digits into out (capacity
 * digits+1, NUL-terminated). Returns 0 on bad arguments (digits out
 * of range, NULL pointers), 1 on success. */
int zotp_hotp(const void *secret, size_t secret_len, uint64_t counter,
              unsigned digits, char *out);

#ifdef __cplusplus
}
#endif

#endif /* ZOTP_H */
