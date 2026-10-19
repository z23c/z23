<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue signer storage alias boundary

Date: 2026-09-29T05:43:11Z (2026-09-29T01:43:11-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Compilers: Clang 22.1.6 and ARM GCC 16.2.0, ISO C23.

## Question

Can overlapping caller storage change the reviewed digest or account hashes
before the Blue signer validates them?

## Reproduction and correction

The signer previously cleared its public-key and signature outputs before
checking their storage against the digest and account hashes. The new host
test aliases the signature output with the reviewed digest. Against the
previous source, the cleared digest reached the SDK signing stub and failed
its assertion that the original fixture digest begins with `a5`.

Wallet 0.3.38 rejects overlap between the digest, account hashes, public-key
output, signature output, and signature-length output before writing any
caller buffer. The private signer workspace is still wiped first. Further
tests reject public-key overlap with the digest, signature overlap with the
account hashes, and signature-length overlap with the digest. Rejected calls
leave inputs not yet checked by the device unchanged and do not invoke ECDSA. Normal disjoint
signing still passes.

The final C23 Release suite passed 60/60 in 46.26 seconds. The final
sanitized Debug suite passed 60/60 in 170.79 seconds with LeakSanitizer
disabled for this runner's ptrace environment; address and undefined-behavior
sanitizers remained enabled.
All 33 fast lint gates passed with the Windows acceptance scratch override
under `/tmp`. The core seal matched 554 files and 80 sections, and the
unchanged cyclomatic cap of 15 passed across 63,540 functions.

## Image and limits

Two clean builds against separately patched copies of Blue SDK revision
`3c710b4c62ad847599a2deb0932a50dd1ae4bdff`, each with patch SHA-256
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`,
produced identical 49,920-byte `.text` SHA-256
`d4e09ab78c46425dae05b60e65816ac0e235a576d5f3764dda82ea9ac77fe1b9`
and Intel HEX SHA-256
`71103f0963f788440370379224a7631669a0cfb3b206fc170640c5f91737f62d`.
`.data` is zero and `.bss` is 5,120 bytes, including the 2,048-byte stack
reserve; 1,024 bytes of Blue app SRAM remain. The largest modeled payment
path uses 1,120 bytes plus the required 512-byte margin. The largest modeled
signing subpath uses 1,080 bytes. BOLOS firmware frames are excluded. The
installer does not admit this image, and it has not run on a physical Blue.
