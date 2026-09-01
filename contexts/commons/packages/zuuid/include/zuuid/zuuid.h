/* zuuid — UUID (RFC 9562) parse, format, compare and v4 generation (C23).
 *
 * 16-byte value type with strict and lenient parsing (hyphenated,
 * braced, urn: prefix, bare 32-hex), canonical lowercase formatting,
 * and version-4 generation from a caller-supplied random source.
 *
 * Apache-2.0 licensed. No dependencies beyond libc.
 */
#ifndef ZUUID_H
#define ZUUID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZUUID_BYTES 16
/* "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" plus NUL. */
#define ZUUID_STR_LEN 37

typedef struct {
    uint8_t b[ZUUID_BYTES];
} zuuid;

typedef enum {
    ZUUID_OK = 0,
    ZUUID_ERR_NULL,
    ZUUID_ERR_FORMAT,   /* not a recognizable UUID shape */
    ZUUID_ERR_BAD_CHAR, /* non-hex digit in a hex field */
    ZUUID_ERR_RNG       /* random source failed */
} zuuid_err;

/* The all-zero nil UUID. */
zuuid zuuid_nil(void);

bool zuuid_is_nil(const zuuid *u);

/* Parse canonical hyphenated form strictly:
 * exactly 36 chars, hyphens at 8/13/18/23, hex elsewhere. */
zuuid_err zuuid_parse(const char *str, zuuid *out);

/* Lenient parse: also accepts bare 32-hex, {braced}, and
 * "urn:uuid:" prefix, any hex case. */
zuuid_err zuuid_parse_lenient(const char *str, zuuid *out);

/* Format canonical lowercase into out (must hold ZUUID_STR_LEN bytes,
 * NUL-terminated). */
zuuid_err zuuid_format(const zuuid *u, char *out);

/* Uppercase variant. */
zuuid_err zuuid_format_upper(const zuuid *u, char *out);

/* Three-way comparison (lexicographic over the 16 bytes). */
int zuuid_compare(const zuuid *a, const zuuid *b);

bool zuuid_equal(const zuuid *a, const zuuid *b);

/* Version (1..8) from the time_hi_and_version field; 0 for nil. */
int zuuid_version(const zuuid *u);

/* Variant: 0 = NCS, 1 = RFC 4122/9562, 2 = Microsoft, 3 = future. */
int zuuid_variant(const zuuid *u);

/* Generate a version-4 (random) UUID. rng must fill buf with n bytes
 * and return 0 on success; ctx is passed through. Sets the version and
 * variant bits per RFC 9562 §5.4. */
zuuid_err zuuid_generate_v4(zuuid *out,
                            int (*rng)(void *ctx, uint8_t *buf, size_t n),
                            void *ctx);

const char *zuuid_err_str(zuuid_err e);

#ifdef __cplusplus
}
#endif

#endif /* ZUUID_H */
