/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "bridge_auth.h"
#include "base/cleanse.h"
#include "sha3/sha3.h"
#include <errno.h>
#include <string.h>
#include <sys/random.h>

#define BLOCK 136u
bool zapp_auth_random(unsigned char *out, size_t size)
{
    for (size_t used = 0; used < size;) {
#if defined(__APPLE__)
        size_t chunk = size - used > 256 ? 256 : size - used;
        if (getentropy(out + used, chunk) != 0) { memory_cleanse(out, size); return false; }
        used += chunk;
#else
        ssize_t n = getrandom(out + used, size - used, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { memory_cleanse(out, size); return false; }
        used += (size_t)n;
#endif
    }
    return true;
}
void zapp_auth_hex(const unsigned char *in, size_t size, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) { out[i * 2] = digits[in[i] >> 4]; out[i * 2 + 1] = digits[in[i] & 15]; }
    out[size * 2] = 0;
}
static int nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
bool zapp_auth_unhex(const char *hex, size_t size, unsigned char *out)
{
    for (size_t i = 0; i < size; i++) {
        int hi = nibble(hex[i * 2]), lo = hi < 0 ? -1 : nibble(hex[i * 2 + 1]);
        if (lo < 0) return false;
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    return true;
}
void zapp_auth_wipe(struct zapp_auth *auth) { memory_cleanse(auth, sizeof(*auth)); }
bool zapp_auth_start(struct zapp_auth *auth, const char *secret_hex)
{
    memset(auth, 0, sizeof(*auth));
    if (secret_hex && strlen(secret_hex) == ZAPP_AUTH_HEX && zapp_auth_unhex(secret_hex, 32, auth->key)) return true;
    zapp_auth_wipe(auth);
    return false;
}
void zapp_auth_bind(struct zapp_auth *auth, const void *request, size_t size)
{
    sha3_256(request, size, auth->rd);
}
static void be64(uint64_t v, unsigned char out[8])
{
    for (int i = 7; i >= 0; i--) { out[i] = (unsigned char)v; v >>= 8; }
}
/* HMAC-SHA3-256 over label, NS, NC, request digest, index and line. */
static void tag(const struct zapp_auth *a, const char *label, uint64_t index,
                const char *line, size_t size, unsigned char out[32])
{
    unsigned char pad[BLOCK], inner[32], counter[8];
    struct sha3_256_ctx ctx;
    memset(pad, 0, sizeof(pad)); memcpy(pad, a->key, sizeof(a->key));
    for (size_t i = 0; i < BLOCK; i++) pad[i] ^= 0x36;
    be64(index, counter);
    sha3_256_init(&ctx); sha3_256_write(&ctx, pad, BLOCK);
    sha3_256_write(&ctx, (const unsigned char *)label, strlen(label) + 1);
    sha3_256_write(&ctx, a->ns, 32); sha3_256_write(&ctx, a->nc, 32);
    sha3_256_write(&ctx, a->rd, 32); sha3_256_write(&ctx, counter, 8);
    sha3_256_write(&ctx, (const unsigned char *)line, size);
    sha3_256_finalize(&ctx, inner);
    for (size_t i = 0; i < BLOCK; i++) pad[i] ^= 0x36 ^ 0x5c;
    sha3_256_init(&ctx); sha3_256_write(&ctx, pad, BLOCK); sha3_256_write(&ctx, inner, 32);
    sha3_256_finalize(&ctx, out);
    memory_cleanse(pad, sizeof(pad)); memory_cleanse(inner, sizeof(inner)); memory_cleanse(&ctx, sizeof(ctx));
}
size_t zapp_auth_seal(const struct zapp_auth *a, const char *label, uint64_t index,
                      const char *line, size_t size, char *out)
{
    unsigned char mac[32];
    tag(a, label, index, line, size, mac);
    zapp_auth_hex(mac, sizeof(mac), out);
    out[ZAPP_AUTH_HEX] = ' ';
    memmove(out + ZAPP_AUTH_HEX + 1, line, size);
    return ZAPP_AUTH_HEX + 1 + size;
}
const char *zapp_auth_open(const struct zapp_auth *a, const char *label, uint64_t index, const char *frame)
{
    unsigned char got[32], want[32];
    if (!frame || strnlen(frame, ZAPP_AUTH_HEX + 1) < ZAPP_AUTH_HEX + 1 || frame[ZAPP_AUTH_HEX] != ' ' ||
        !zapp_auth_unhex(frame, 32, got)) return NULL;
    const char *line = frame + ZAPP_AUTH_HEX + 1;
    tag(a, label, index, line, strlen(line), want);
    unsigned diff = 0;
    for (size_t i = 0; i < sizeof(want); i++) diff |= (unsigned)(got[i] ^ want[i]);
    memory_cleanse(want, sizeof(want));
    return diff == 0 ? line : NULL;
}
size_t zapp_auth_seal_request(struct zapp_auth *a, const char *request, size_t size, char *out)
{
    zapp_auth_bind(a, request, size);
    return zapp_auth_seal(a, "client", 0, request, size, out);
}
const char *zapp_auth_open_request(struct zapp_auth *a, const char *frame)
{
    if (!frame || strnlen(frame, ZAPP_AUTH_HEX + 1) < ZAPP_AUTH_HEX + 1 || frame[ZAPP_AUTH_HEX] != ' ') return NULL;
    zapp_auth_bind(a, frame + ZAPP_AUTH_HEX + 1, strlen(frame + ZAPP_AUTH_HEX + 1));
    return zapp_auth_open(a, "client", 0, frame);
}
