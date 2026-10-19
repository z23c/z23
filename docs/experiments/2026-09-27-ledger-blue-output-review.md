<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Bounded transparent output review controller

Local time: 2026-09-27T01:14:07-04:00

UTC: 2026-09-27T05:14:07Z

## Question

Can a C23 controller stop a three-pass transparent transaction upload at
each public output, require a separate acknowledgement, and reject a changed
replay before returning a ZIP-243 digest?

## Result

The read-only controller retains one P2PKH or P2SH output at a time during
pass three. It rejects a new chunk while that output is pending and rejects
a chunk that completes two outputs. It requires one acknowledgement per output,
caps the complete session at 16 outputs, and returns no digest until the
whole third pass matches the first pass's SHA-256 commitment. Output facts
remain provisional until that final check. This controller has no key or
signing operation.

The synthetic one-input/two-output fixture exercises both script types and
compares the completed digest with the independent whole-transaction ZIP-243
implementation. Tests reject unacknowledged continuation, two outputs in one
chunk, finish with a pending output, a changed later output, and continuation
after abort. Failed finalization zeroes the digest and aggregate facts.
Clang 22.1.6 Debug with address and undefined behavior sanitizers passed
21/21 host tests; GCC 16.1.1 Release passed 21/21. Both ran on an AMD Ryzen
7 PRO 8840U. The repository cyclomatic gate passed with cap 15.

ARM GCC 16.2.0 compiled the new controller as ISO C23 with `-Os -Wall
-Wextra -Werror -pedantic -fstack-usage`. Its isolated object has 540 bytes
of `.text`, zero `.data`, and zero `.bss`. The largest reported local frame
is 40 bytes. Its state type measures 376 bytes on ARM. This excludes the
BLAKE2b and SHA-256 contexts, UI, USB transport, linker stack reservation,
and any future previous-output verification.

## Limit

The test acknowledges outputs through a direct C call. A future device app
must expose that call only through its touchscreen callback and must display
the exact output address and amount before accepting the touch. The current
controller is not linked into a Blue image, so physical responsiveness and
the full linked SRAM budget are untested. It does not authenticate previous
outputs, fee, change, account, network branch, or chain status. No payment
signature can be produced from this API.
