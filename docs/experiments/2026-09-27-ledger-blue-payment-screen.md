<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Transparent output screen preview

Local time: 2026-09-27T01:17:52-04:00

UTC: 2026-09-27T05:17:52Z

## Question

Can one bounded C23 screen model show every character of a standard ZCL
transparent address, the exact amount, and a clear no-signing status on a
320 × 480 Ledger Blue preview in both light and dark themes?

## Evidence

The formatter takes the one pending output from the replay controller. It
constructs the mainnet Base58Check address from the parsed hash160 and
output type, then splits all 35 characters across three lines. It formats
the ZCL amount to eight decimals and labels the output index and type.
Independent OpenSSL address generation verifies P2PKH and P2SH results;
tests also cover the maximum money value, invalid index/count/amount, and
hash failure. Hash failure clears the screen model. The controller test
also formats both pending outputs before acknowledging them.

The C23 host canvas generated 320 × 480 RGB PNGs in light and dark themes
with the Blue SDK font bitmap. Both images were inspected at original size.
The complete address is visible over three 22-pixel lines, the amount fits
at the maximum value, and the screen states "DRAFT; NO SIGNING". A separate
"CONTINUE REVIEW" control represents moving to the next provisional output,
not payment approval. Reproduce the previews with:

```sh
build/zcl-ledger/test-blue-payment-screen /tmp/zcl-payment-light.png /tmp/zcl-payment-dark.png
```

Clang 22.1.6 Debug with address and undefined behavior sanitizers passed
22/22 host tests; GCC 16.1.1 Release passed 22/22. Both ran on AMD Ryzen
7 PRO 8840U. ARM GCC 16.2.0 compiled the formatter as ISO C23 with `-Os
-Wall -Wextra -Werror -pedantic -fstack-usage`: the isolated object uses
692 bytes of `.text`, 24 bytes of read-only string data, zero `.data`, and
zero `.bss`. The ARM screen model is 143 bytes; the largest reported local
frame is 160 bytes. These numbers exclude the Base58 encoder, SHA-256,
review controller, transport, touch handling, and linked Blue image.

## Limit

The PNG canvas uses SDK font data but cannot prove physical Blue pixels,
contrast, touchscreen hit boxes, or USB responsiveness. The preview is not
linked into the Blue app and cannot authorize a transaction. The controller
still needs verified previous outputs, an independently checked fee and
change path, and final device approval before payment signing is safe.
