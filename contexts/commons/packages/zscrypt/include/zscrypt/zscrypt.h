/* zscrypt — RFC 7914 scrypt password-based KDF (C23).
 *
 * scrypt is a memory-hard key derivation function: deriving a key
 * costs N*r*128 bytes of RAM and 2*N*p*r Salsa20/8 core rounds, which
 * makes parallel hardware guessing attacks expensive per attempt.
 *
 * Also exposes PBKDF2-HMAC-SHA256 (RFC 8018), which scrypt uses
 * internally and which legacy systems use directly.
 *
 * Parameters: N must be a power of two greater than 1; r and p must
 * be positive; memory use is N*r*128 bytes plus p*r*128 bytes of
 * working buffers.  RFC 7914 suggests N=16384, r=8, p=1 for
 * interactive logins.
 *
 * Depends on the Commons package zsha256 for HMAC-SHA256.
 *
 * Apache-2.0 licensed.
 */
#ifndef ZSCRYPT_H
#define ZSCRYPT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PBKDF2-HMAC-SHA256: iterate HMAC iters times over pw/salt into dk.
 * Returns 0 on success, -1 on invalid arguments. */
int zpbkdf2_sha256(const void *pw, size_t pw_len,
                   const void *salt, size_t salt_len,
                   uint32_t iters,
                   uint8_t *dk, size_t dk_len);

/* scrypt: derive dk_len bytes from passwd and salt.
 * N is the CPU/memory cost (power of two, >1); r the block size;
 * p the parallelism.  Returns 0 on success, -1 on invalid arguments,
 * -2 on allocation failure. */
int zscrypt(const void *passwd, size_t passwd_len,
            const void *salt, size_t salt_len,
            uint64_t n, uint32_t r, uint32_t p,
            uint8_t *dk, size_t dk_len);

#ifdef __cplusplus
}
#endif

#endif /* ZSCRYPT_H */
