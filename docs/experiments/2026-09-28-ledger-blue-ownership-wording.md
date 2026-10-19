<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue payment ownership wording

Date: 2026-09-28T18:12:51-04:00; UTC: 2026-09-28T22:12:51+00:00.
Host: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics. Compiler: Clang
22.1.6. Device linker: ARM GCC 16.2.0. Target: Ledger Blue firmware 2.1.x,
SDK revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with its pinned
C23 patch.

## Claim and check

The earlier totals and final signing pages called every output outside two
device-derived P2PKH hashes an output to someone else. A P2SH script hash
does not establish who owns its redeem script; it may be the user's
multisig output. A foreign P2PKH hash likewise does not prove that the user
cannot spend it through another path. The two verified P2PKH hashes are the
fixed external `0/0` and internal `1/0` keys.

The totals and final signing pages now label the exact device-key matches
MATCHES YOUR KEY and the remainder OWNER NOT VERIFIED. The latter amount
equals all outputs minus the exact matches. The device derives the matching
hashes; the host does not provide a verified ownership claim. An assertion
for OWNER NOT VERIFIED failed on the old device UI. After the edit, the UI
test passed and its simulator preview matched the device BAGL elements byte
for byte in decoded RGB. The totals pixel SHA-256 is
`5068c22a12ac4a6189f66ae924c99d4fa4eefc85f255fa2cf81805f22520635f`;
the final signing pixel SHA-256 is
`41a3e8b91676f92c76d7e235c58341ec17a603c99db91a132bd9520833416667`.
Both 320 × 480 screenshots were inspected: the labels and amounts fit
without overlap or clipping. The fixture uses 5 ZCL in outputs, 1 ZCL
matching a device key, and a 1.23456789 ZCL fee on the totals screen. The
final signing fixture uses 2 ZCL in outputs, 0.5 ZCL matching a device key,
and a 1 ZCL fee.

The Release suite passed 59/59. The AddressSanitizer and
UndefinedBehaviorSanitizer Debug suite passed 59/59 with
`ASAN_OPTIONS=detect_leaks=0`. The pinned C23 device image passed the static
RAM and modeled stack gates. `.text` is 48,640 bytes, `.data` is zero, and
`.bss` is 5,120 bytes, including the 2,048-byte stack reserve. The largest
modeled app path is 1,112 bytes, leaving the required 512-byte margin;
BOLOS frames are outside this model. The `.text` SHA-256 is
`21a760706c0020a0526acc59bd7bb6bf4550aeae51bef1a15a0071d1c8d05d56`;
Intel HEX SHA-256 is
`da290ac33809b20fff8ed77b113b2f4f07a262860c4dffbb4c61c651d6dd53d5`.
A separate source copy from `git archive` with the two modified device
files and a separate pinned SDK copy produced byte-identical `.text` and
Intel HEX bytes.

```sh
make -B -C apps/zcl-ledger/device-blue-wallet \
  BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

## Limit

The image has not run on a physical Blue. The pixel preview and static stack
model do not prove BOLOS touchscreen or runtime stack behavior. The
physical Wallet install block remains after 0.3.4 froze on opening. This
wording change does not implement Sapling signing, general change discovery,
or ownership proof for P2SH.
