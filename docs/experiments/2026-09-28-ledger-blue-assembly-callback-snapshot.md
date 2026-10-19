<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue host assembly callback mutation

Date: 2026-09-28T17:56:13-04:00; UTC: 2026-09-28T21:56:13+00:00.
Host: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics. Compiler:
Clang 22.1.6, ISO C23.

The authenticated host assembler previously checked the reviewed unsigned
wire hash, then called supplied HASH160 and ECDSA verifier callbacks, then
assembled from the caller's wire. A verifier callback changed a transparent
output amount after the hash check. The regression demonstrated that the
old assembler returned success for the changed wire. The signature still
covered the original digest, so the resulting transaction was not the one
the Blue reviewed.

The corrected entry point copies the unsigned wire, signature records,
expected digests, paths, ownership hashes, and reviewed hash before calling
the verifier. It rejects caller changes during verification and assembles
from the frozen copy. Tests inject callback changes to each of those six
input groups. A rejected authentication leaves output bytes and length
untouched. An output buffer aliased to the caller's unsigned wire is also
rejected before a write.

The snapshot header is 3,120 bytes with this compiler; its flexible wire
array accepts at most 2,097,152 bytes. Maximum allocation is therefore
2,100,272 bytes. The Wallet device image and its SRAM use are unchanged.
The verifier callback remains an accepted implementation of secp256k1 ECDSA;
the snapshot protects against changes in its caller-owned inputs, not a
verifier that lies about signature validity.

```sh
cmake --build /tmp/z23-blue-standalone-release --parallel 4
ctest --test-dir /tmp/z23-blue-standalone-release --output-on-failure --parallel 4
cmake --build /tmp/z23-blue-standalone-debug --parallel 4
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug --output-on-failure --parallel 4
make check-core-seal check-cyclomatic-complexity
ZCL_WINDOWS_ACCEPTANCE_GUARD_SCRATCH=/tmp/z23-blue-assemble-wag make lint-fast
make check-markdown-links check-doc-inline-paths
```

The focused real secp256k1 review test passes after the correction. The
complete Release and sanitized Debug suites passed 59/59 each. The sealed
consensus core matched 554 files and 80 sections; the unchanged cyclomatic
complexity cap of 15 passed. All 33 fast lint gates passed. Both Markdown
gates passed with 534 documents scanned and zero new inline-path findings.
No transaction was broadcast. Physical Blue signing and the host's chain
UTXO checks remain unverified.
