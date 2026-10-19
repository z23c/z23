<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue linker SRAM accounting correction

Local time: 2026-09-27T01:03:28-04:00

UTC: 2026-09-27T05:03:28Z

## Question

Does the Blue SDK's `.bss` section size already include its 2,048-byte stack
reservation, and how much SRAM can the receive app add while preserving 512
bytes of unallocated headroom?

## Evidence

The pinned Blue linker script declares SRAM from `0x20001800` for 6,144 bytes
and advances the `.bss` location counter by `STACK_SIZE = 2048` after a
four-byte canary. In the 0.1.0 Wallet ELF, `_bss = 0x20001800`,
`app_stack_canary = 0x20001d10`, and `_stack = 0x20001d14`.
`arm-none-eabi-size -A` reports `.bss = 3348`; this equals the 1,296-byte
static region, four-byte canary, and 2,048-byte linker stack reservation.
The section ends at `0x20002514`, leaving 2,796 bytes before SRAM end
`0x20003000`. The earlier 748-byte calculation subtracted the stack twice.

The Wallet `check-image` gate now refuses `.bss > 5632`, leaving at least 512
bytes after the complete section, including its stack reservation. Its
separate `-fstack-usage` gate continues to require a 512-byte margin inside
the 2,048-byte stack reserve on named C paths. The real 0.1.0 image passed
both gates and retained its 14,848-byte code hash
`baf36150563cecd659692434800d5bb106a9679a9fa6e36598a3e38fb0836df2`.
A synthetic `arm-none-eabi-size -A` report of `.bss = 5632`, `.data = 0`
passed `make check-image`; `.bss = 5633` was rejected. These injected values
exercise the threshold; they are not measured images.

ARM GCC 16.2.0 and Clang 22.1.6 ran on AMD Ryzen 7 PRO 8840U. This
correction changes only the build gate and documentation, not device code.

## Implication and limit

With the 512-byte unallocated headroom rule, the current Wallet image can
add at most 2,284 bytes of `.bss`. The isolated 684-byte replay state and
800-byte two-context state each fit that amount. A complete integrated image
must still include payment UI, USB protocol, verified prevout evidence, and
key handling, then pass linked SRAM and stack checks. Linker arithmetic does
not prove BOLOS runtime behavior or touchscreen responsiveness.
