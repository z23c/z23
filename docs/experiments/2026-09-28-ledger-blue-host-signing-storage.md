<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue host signing storage boundary

Date: 2026-09-28T15:01:45Z (2026-09-28T11:01:45-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Compiler: Clang 22.1.6.

## Question

Can host-side signature verification or assembly change the expected digest,
the reviewed unsigned transaction, or the checked signed transaction through
overlapping caller buffers?

## Reproduction

Three tests failed against the preceding signed source, before the guards:

1. The assembler accepted an output-length pointer placed inside its output
   transaction and returned success. Its final length write then landed in
   the first bytes of the returned transaction, after the wire comparison.
2. The signature collector erased its result array before checking that the
   same storage held the expected ZIP-243 digest. The test found the expected
   digest changed on rejection.
3. The host verifier erased its result before checking that the expected
   ZIP-243 digest shared the same storage. The test found the digest changed
   on rejection.

The assembler now rejects an output-length pointer overlapping the unsigned
wire, verified signatures, expected digests, or any byte of the declared
output capacity before writing the length. Further tests cover a length
inside the unsigned wire, expected digest, and signature record, and require
the unchecked bytes to remain identical. The collector rejects a signature
array overlapping the expected paths, ownership hashes, or digests before
zeroing it or requesting approval. The verifier rejects a result overlapping
the reply frame, expected ownership hash, or digest before clearing it.
On rejected overlap, the caller must ignore the output and abort the signing
flow; preservation of unchecked inputs takes precedence over zeroing aliased
output storage.

The focused Release tests `blue-payment-review` and `blue-payment-sign`
passed 2/2. Their AddressSanitizer plus UndefinedBehaviorSanitizer Debug
counterparts passed 2/2 with LeakSanitizer disabled for this runner's ptrace
environment. The full serial Release suite passed 57/57 in 11.90 seconds;
the full serial sanitized Debug suite passed 57/57 in 14.45 seconds with the
same LeakSanitizer setting.
All 33 fast lint gates passed in 39.880 seconds. The unchanged consensus-core
seal matched 554 files and 80 sections. The Markdown link check scanned 514
documents and 942 local targets; the inline-path check scanned 514 documents
with 12 baselined findings and no new findings.

These are host-only C23 modules. They are not linked into the Wallet image,
so this change has no Blue SRAM or stack cost and does not justify a device
image version change. It does not authenticate the installed device app or
prove physical touchscreen approval. The fixture CLI still does not save or
broadcast assembled transaction bytes.
