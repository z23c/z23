<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue address prototype failure and startup guard

Recorded: 2026-09-26T04:20:49-04:00 (2026-09-26T08:20:49Z)
Updated: 2026-09-26T04:27:05-04:00 (2026-09-26T08:27:05Z)

## Question

Can a C23 Blue app expose a ZCL transparent public key under the fixed
`m/44'/147'/0'/0/0` path, and which build defects can be detected before
installing it?

## Evidence

The first 13,312-byte `ZCL Address` image was installed on a dedicated test
Blue. It froze when opened and its USB interface stopped enumerating. The
device returned to its home screen after a restart and USB replug. The C23
secure installer deleted the broken app; BOLOS 2.1.1 responded afterward.

The image contained a 19-byte initialized `.data` section. The installer
allocates zero bytes for `.data`, as shown by its 21-byte legacy create-app
command and Ledger's loader format. The screen's initial mutable text caused
the section. The corrected source initializes that text at runtime, moving
it to `.bss`; `arm-none-eabi-size -A` reports `.data` size zero. A new
`check-image` Make target rejects any nonzero `.data`: it rejected the old
image and accepted the corrected image. The installer also rejects the old
binary by its SHA-256 before opening a USB device.

The corrected image was built with Clang 22.1.6 from two separate patched
SDK trees. Both builds produced identical 13,312-byte binaries with SHA-256
`e600197fb2e37820655f599213fc14a422c86c7d27f957c4ba11c4057995f811`
and identical HEX files with SHA-256
`db5e146a0d8381bd4c1c0b480a70a489b34643f6da482de919770c2f5e10a26e`.
The corrected image was installed. The user reported that it opens and EXIT
works; the BOLOS non-genuine warning remains. The host Clang Debug sanitizer
and GCC 16.1.1 Release builds passed 3/3 local tests each.

The live public-key request then failed. The host returned
`invalid_address_reply`, which covered multiple possible device replies and
did not preserve the status bytes. The user reported an error or frozen
screen. The USB quit command did not receive a reply. The user restarted the
Blue, BOLOS 2.1.1 responded, and the installer deleted the app. The exact
cause of this second failure is unknown. The prototype and unverified host
command are excluded from `main`; the original no-key ZCL Probe remains.

## Limits

No live public key or on-screen address was validated. The next offline test
must separate derivation, address encoding, and UI refresh, record the exact
APDU status, and exercise the display flow with a public fixture key before
another key derivation request. No transaction has been signed or broadcast.
Signing work will use deterministic transaction fixtures and regtest before
any mainnet path.
