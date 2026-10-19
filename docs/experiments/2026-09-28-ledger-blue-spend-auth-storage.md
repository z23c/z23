<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue Sapling SpendAuth storage boundary

Date: 2026-09-28T14:14:37Z (2026-09-28T10:14:37-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can the isolated SpendAuth signer approve a mismatched transaction `rk` if
the expected `rk` aliases its signature output?

## Method

The host test starts from the consensus-accepted Sapling fixture's `ask`,
`ar`, ZIP-243 digest, and `rk`. It changes one byte of `rk`, places that
wrong value at the start of the 64-byte signature output, and passes the
same address as `expected_rk`. Before the fix, the signer returned success:
it wrote its recomputed `rk` into the expected value before comparing them.
The failing assertion is in the Release test log. A second adversarial case
places `ask` inside the writable point workspace; the old initial workspace
wipe destroys the key bytes. The fixed signer checks both writable regions
against the key, randomizer, expected `rk`, entropy, and digest before any
write. Further cases place the signature output over `ask` and the reviewed
ZIP-243 digest. Rejected storage leaves input bytes not yet checked by the device unchanged.
The caller must treat a false result as no signature, regardless of prior
output contents.

## ARM memory result

The source before the guard, at signed commit
`fbb9e05dc455a92a06d630b46c961a07628ee9f9`, measured a 1,512-byte
Cortex-M0 QEMU stack peak for its complete isolated Sapling case. The
first guard implementation raised the peak to 1,528 bytes. Inlining the
input-disjoint check restored the 1,512-byte peak, leaving 536 bytes of the
2,048-byte test stack. The corrected Cortex-M3 case measured 1,404 bytes.
Both emulators executed the positive SpendAuth fixture and rejected the
aliased wrong `rk`; each reported PASS. The M0 test image increased from
49,280 to 49,856 bytes of `.text`, while its `.data` remained 1,364 bytes
and `.bss` remained 2,720 bytes. These sizes describe a QEMU test image,
not the Wallet app.

The full serial Clang Release suite passed 57/57 tests in 17.17 seconds
before the final test-only digest-alias assertion was added. The
AddressSanitizer plus UndefinedBehaviorSanitizer Debug suite passed 57/57
tests on the final source in 49.88 seconds, with LeakSanitizer disabled for
this runner's ptrace environment. The focused Release and sanitized Debug
SpendAuth tests passed with the additional digest case. The host fixture's
valid 64-byte signature remained identical after the guard; its aliased
wrong-`rk` case failed before the change and passed after it.

On the final source, two serial Release suite attempts timed out in the
Cortex-M3 emulator at its unchanged 15-second limit; the second also timed
out in the Cortex-M0 emulator at its unchanged 30-second limit. All other
Release cases passed. The two emulator cases passed together in a fresh
CTest process, 2/2 in 8.09 seconds, with the same images and timeout gates.
This establishes their functionality under the tested conditions while
recording that a full default Release run was not green on this shared host.

The isolated signer is not linked into ZCL Wallet, has no BOLOS key or
approval path, and cannot sign on a physical Blue. Its QEMU stack model
does not include BOLOS frames or Ledger's app memory layout. Shielded
recipient, amount, proof, memo, and fee validation remain prerequisites
for any real Sapling payment approval.
