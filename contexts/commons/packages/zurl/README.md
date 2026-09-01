# zurl — bounded absolute-URI parser for C23

zurl parses absolute URIs (RFC 3986) from caller memory into byte
slices. No allocation, no copying: components point into the input,
and every malformed input is a clean `false`.

- Strict grammar: scheme rules, optional userinfo (last `@` wins, so
  raw `@` inside userinfo is rejected), reg-name / IPv4 / `[...]`
  IP-literal hosts, port bounded to 0..65535, and percent-encoding
  validated everywhere it is allowed.
- Honest edge semantics: empty authorities parse (`file:///path`);
  `:0` is a present port with value 0, distinct from no port; IPv4
  hosts must be four octets 0..255; a URI without an authority may
  not begin its path with `//`.
- Total: any byte string is either parsed or rejected; nothing is
  read outside the input (fuzz-verified).

Relative references and normalization are out of scope for 0.1.0.

## API

```c
#include "zurl/zurl.h"

zurl u;
if (zurl_parse("https://user@example.com:8443/p?q=1#f", &u)) {
  /* u.scheme/u.host/u.path/u.query/u.fragment are slices of the
   * input; u.port == 8443; u.has_userinfo == true */
  if (zurl_scheme_is(&u, "https://user@example.com:8443/p?q=1#f",
                     "https")) { /* TLS endpoint */ }
}
```

## CLI

`zurl URI...` prints each URI's components; exit 1 if any is invalid.

```
$ zurl 'https://user@example.com:8443/path?q=1#frag'
https://user@example.com:8443/path?q=1#frag:
  scheme: https
  userinfo: user
  host: example.com
  port: 8443
  path: /path
  query: q=1
  fragment: frag
```

## Build and test

```sh
cc -std=c23 -O2 -Iinclude src/zurl.c app/main.c -o zurl

cc -std=c23 -O1 -g -fsanitize=address,undefined -Iinclude \
   src/zurl.c tests/test_zurl.c -o test_zurl
./test_zurl
```

Tests cover component KATs (userinfo, IPv4, IP literals, empty
authority, `:0` port, percent-encodings, case-folded scheme compare),
a 20+ case invalid table, bounded component copying, NULL safety,
failure zeroing, and 40000 fuzz parses (generated + single-byte
mutated inputs) under ASan/UBSan.

## License

Apache-2.0 (see LICENSE).
