<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Streaming transparent ZIP-243 digest and Blue memory limit

Local time: 2026-09-27T00:50:28-04:00

UTC: 2026-09-27T04:50:28Z

## Question

Can the bounded C23 transaction parser compute an exact transparent input
ZIP-243 SIGHASH_ALL digest without retaining the transaction wire bytes,
and does this approach fit the current Blue receive app's SRAM budget?

## Method and result

The `zcl_tx_stream_zip243` wrapper accepts arbitrary chunks of an unsigned,
all-transparent Sapling-v4 transaction. It uses independent personalized
BLAKE2b contexts for prevouts and sequences, then reuses one for outputs and
the final input-specific digest. It serializes each accepted P2PKH/P2SH
output from the parsed amount, script type, and hash160. The parser rejects
noncanonical or unsupported wire bytes and requires the complete declared
length before `finish` returns a digest. With a non-null state and valid
output pointers, a failed `finish` leaves the caller-visible facts and
digest zeroed.

The published ZIP-243 transparent vector contains a 107-byte signed input
script. The streaming parser intentionally rejects that wire format. The C23
test removes that script to make an unsigned transaction, computes its
reference digest using the existing complete-transaction ZIP-243 library,
then compares the streaming result at every chunk width from one byte to the
full unsigned length. It also checks selected-input rejection, truncated
upload, same-context rejection, and zeroed results after failure. The Clang
Debug sanitizer and GCC Release suites each passed 20/20 tests. A 20,000-run
Clang libFuzzer session compared accepted streaming digests with the
complete-transaction implementation and ended without a sanitizer finding.
The final fuzzer instrumentation counters were `cov: 9428` and `ft: 10265`;
these are not coverage percentages. The repository cyclomatic gate passed:
60,182 functions scanned in 4,391 files, with 4,113 baseline pins exact at
cap 15.

ARM GCC 16.2.0 accepted both ISO C23 sources with `-Wall -Wextra -Werror
-pedantic -fstack-usage`. The parser object measured 2,168 bytes of `.text`,
and the digest wrapper 1,980 bytes; neither object has `.data` or `.bss`.
The largest reported wrapper function frame was 144 bytes. ARM type-size
symbols measured the parser state at 136 bytes, the digest wrapper including
that parser at 288 bytes, and each Blue SDK `cx_blake2b_t` at 256 bytes.
Two independent SDK contexts plus the wrapper therefore require 800 bytes
of live state before any payment UI, prevout, or transport state. The original
Wallet headroom estimate double-subtracted the reserved stack. The corrected
2,796-byte space after `.bss` admits this state as an isolated addition under
the 512-byte headroom guard. A linked image must still measure the complete
payment UI, transport, and stack paths before device integration.

Clang 22.1.6 and GCC 16.1.1 ran on AMD Ryzen 7 PRO 8840U. No Blue image
changed or was installed during this experiment.

## Security boundary

The supplied previous-output scriptCode and amount are not authenticated by
this wrapper. The branch ID is not selected from ZCL chain state here. The
digest alone proves neither prevout ownership nor approval; no signing path
uses it. A payment app must verify prevout bytes and chain context,
derive change and account information on device, display all outputs and fee,
and bind the resulting exact digest to explicit approval before releasing a
signature. The next ARM experiment must measure a smaller state arrangement
against the actual Wallet image and its stack gate.

A [same-day replay experiment](2026-09-27-ledger-blue-replay-zip243.md)
measured a one-BLAKE2b-context alternative with SHA-256 binding across three
complete uploads. It reduces the live ARM state to 684 bytes. Corrected linker
accounting admits this isolated state; the full Wallet integration remains
unmeasured.
