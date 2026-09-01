# zuuid

UUID (RFC 9562) handling for C23: parse, format, compare, generate.

- 16-byte value type, no allocation.
- Strict parser for the canonical 36-character form; lenient parser
  additionally accepts bare 32-hex, `{braced}`, and `urn:uuid:` forms,
  in any hex case.
- Canonical lowercase formatting (uppercase variant available).
- Version/variant inspection.
- Version-4 generation from a caller-supplied random source — the
  library never picks an entropy source for you.

## API

```c
#include <zuuid/zuuid.h>

zuuid zuuid_nil(void);
bool  zuuid_is_nil(const zuuid *u);

zuuid_err zuuid_parse(const char *str, zuuid *out);          /* strict */
zuuid_err zuuid_parse_lenient(const char *str, zuuid *out);  /* bare/{}/urn: */
zuuid_err zuuid_format(const zuuid *u, char out[ZUUID_STR_LEN]);
zuuid_err zuuid_format_upper(const zuuid *u, char out[ZUUID_STR_LEN]);

int  zuuid_compare(const zuuid *a, const zuuid *b);
bool zuuid_equal(const zuuid *a, const zuuid *b);
int  zuuid_version(const zuuid *u);   /* 0 for nil */
int  zuuid_variant(const zuuid *u);   /* 1 = RFC 9562 */

zuuid_err zuuid_generate_v4(zuuid *out,
                            int (*rng)(void *ctx, uint8_t *buf, size_t n),
                            void *ctx);
```

## CLI

```sh
zuuid new 3
zuuid parse '{F81D4FAE7DEC11D0A76500A0C91E6BF6}'
zuuid nil
```

## License

Apache-2.0. See LICENSE.
