# zcidr

IPv4/IPv6 address and CIDR prefix parsing, formatting, and containment
in freestanding C23 — no network headers, no allocation.

Strict by design:

- IPv4: four decimal octets, no leading zeros, no hex/octal, no
  shorthand (`127.1` rejected).
- IPv6: hex groups with at most one `::` compression, embedded IPv4
  tails accepted, zone ids rejected.
- Prefix `/n` within family range, no leading zeros.

Formatting is canonical: lowercase, maximal left-most `::` (lone zero
groups not compressed), pure hex groups.

Containment is a masked byte comparison; the host part of the network
address is ignored, so `192.168.1.77/24` and `192.168.1.0/24` contain
the same set. A bare address contains only itself; families never mix.

## API

```c
zcidr net, addr;
zcidr_parse("2001:db8::/32", 14, &net);
zcidr_parse("2001:db8::1", 11, &addr);
int yes = zcidr_contains(&net, &addr);
zcidr_format(&net, buf, sizeof buf);  /* "2001:db8::/32" */
zcidr_network(&net);                  /* mask host bits in place */
int c = zcidr_cmp(&a, &b);            /* total order, v4 < v6 */
```

## CLI

```
zcidr 2001:0DB8::FF00:42:8329      # 2001:db8::ff00:42:8329
zcidr contains 10.0.0.0/8 10.1.2.3 # yes
zcidr contains 10.0.0.0/8 11.1.2.3 # no (exit 3)
```

## Tests

Parse/format KATs, rejection tables (leading zeros, double `::`,
truncated v4 tails, out-of-range prefixes), containment tables
including odd prefix lengths, a 20k-trial masked-compare oracle
against a bit-by-bit reference, a 20k-trial v6 format/parse round-trip
fuzz, and NULL/zero-capacity handling. Built with
`-std=c23 -Wall -Wextra -Werror -pedantic` under ASan/UBSan.

Apache-2.0 licensed.
