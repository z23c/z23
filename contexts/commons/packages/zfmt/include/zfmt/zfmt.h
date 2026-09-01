/* zfmt — allocation-free buffer formatting (C23).
 *
 * A cursor over a caller-provided buffer with append operations for
 * strings, spans, characters, integers (dec/hex, zero-padded) and
 * fixed-precision doubles. Every append reports success; on overflow
 * the cursor remembers the error, keeps a valid (truncated,
 * NUL-terminated) string, and refuses further appends — one check at
 * the end suffices.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZFMT_H
#define ZFMT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char  *buf;     /* caller buffer */
    size_t cap;     /* total capacity including NUL */
    size_t len;     /* current length, < cap */
    bool   failed;  /* sticky: an append did not fit */
} zfmt;

/* Initialize over buf[0..cap). cap==0 or NULL buf yields an
 * immediately-failed cursor that is still safe to use. */
void zfmt_init(zfmt *f, char *buf, size_t cap);

/* Appends; return false when they (or a previous append) did not fit.
 * All leave the buffer NUL-terminated. */
bool zfmt_str(zfmt *f, const char *s);              /* NUL-terminated */
bool zfmt_span(zfmt *f, const char *p, size_t len); /* explicit length */
bool zfmt_char(zfmt *f, char c);
bool zfmt_u64(zfmt *f, uint64_t v);
bool zfmt_i64(zfmt *f, int64_t v);
bool zfmt_hex64(zfmt *f, uint64_t v);               /* 16 lowercase digits */
bool zfmt_u64_pad(zfmt *f, uint64_t v, unsigned width); /* zero-padded */
bool zfmt_double(zfmt *f, double v, unsigned precision); /* fixed notation */
bool zfmt_repeat(zfmt *f, char c, size_t count);

/* Clear to empty (also clears the sticky error). */
void zfmt_reset(zfmt *f);

/* Final state: false if anything ever failed to fit since init/reset. */
bool        zfmt_ok(const zfmt *f);
const char *zfmt_cstr(const zfmt *f); /* always valid, "" when failed */
size_t      zfmt_len(const zfmt *f);

#ifdef __cplusplus
}
#endif

#endif /* ZFMT_H */
