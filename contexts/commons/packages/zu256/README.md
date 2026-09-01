# zu256

Fixed-size 256-bit unsigned integer arithmetic in portable C23, no
dependencies beyond libc.

Four little-endian u64 limbs. Fixed size means no allocation and
predictable cost — the shape used by hashes, IDs, and checksums.
All arithmetic is modular (wraps mod 2^256); the `*_overflow` out
parameters report when the true mathematical result exceeded the
modulus. Not constant-time — do not use for secrets.

## API sketch

```c
zu256256 a = zu256_from_u64(42);
bool ovf;
zu256256 b = zu256_mul(a, ZU256256_MAX, &ovf);
zu256_divmod(b, a, &q, &r);          /* binary long division */
zu256_to_dec(b, buf, sizeof buf);    /* exact decimal */
```

Also: cmp, bitlen, bit, shl/shr, big-endian 32-byte import/export,
canonical hex (64 lowercase digits) and decimal conversion, both
fail-closed on malformed input.

Verified against 220 differential vectors generated from Python's
arbitrary-precision integers, plus edge identities (wrap at 2^256,
division by zero, 256-bit shifts).

## CLI

```sh
cc -std=c23 -Iinclude -o zu256 app/main.c src/zu256.c
./zu256 mul 0xffffffffffffffffffffffffffffffff 0x10001
./zu256 dec 0xdeadc0de
```

## License

Apache-2.0
