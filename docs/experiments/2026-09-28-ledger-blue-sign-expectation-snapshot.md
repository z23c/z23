<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue host signing expectation snapshot

Date: 2026-09-28T19:03:51Z (2026-09-28T15:03:51-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Compiler: Clang 22.1.6.

## Question

Can a host callback change the expected input path, public-key hash, or
ZIP-243 digest after signing begins and make the host accept a signature
against the changed expectation?

## Result

The former host signer reread caller-owned expectation arrays after the
identity and approval callbacks. A new regression starts each expectation
with one wrong byte, then repairs it in the approval callback while the
Blue's simulated review retains the correct original input. The new test was
also compiled against the prior signer from commit `cdf7d0f32`, in an
isolated source copy. It failed at the first repaired path case: the prior
signer returned success and accepted that signature.

The signer now snapshots all bounded expectations before callbacks. It
checks caller storage after identity, approval, and each signature reply,
verifies against the snapshot, clears any results, and requests a device
review abort if caller storage differs at those boundaries. The snapshots
are explicitly erased before return. The three repaired-expectation cases
make no signing request and leave approval and fee state cleared.

## Measurements and reproduction

```sh
cmake --build /tmp/z23-blue-standalone-release -j2 --target test-blue-payment-review zcl-blue-wallet-fixture
ctest --test-dir /tmp/z23-blue-standalone-release -R '^blue-payment-review$' --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2 --target test-blue-payment-review zcl-blue-wallet-fixture
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug -R '^blue-payment-review$' --output-on-failure
make check-cyclomatic-complexity
```

The focused review tests and the full Release and sanitized Debug suites
passed 57/57 each. The unchanged cyclomatic cap of 15 and core seal passed;
all 33 fast lint gates passed. The Markdown gates scanned 525 documents,
with zero new inline-path findings. The seal matched 554 files and 80
sections. With Clang `-std=c23 -O3 -fstack-usage`, the host signer's largest
frame rose from 216 to 1,096 bytes, and the object `.text`
rose from 1,026 to 1,673 bytes. This cost is on the host; no Wallet ARM
source or image changed.

## Limit

The snapshot prevents callback changes from altering the expectations used
by this signing call. The caller must still derive the expected digest from the
reviewed unsigned transaction and verified previous outputs. Host software
and callbacks remain in the verification boundary. The Wallet image remains
uninstalled and physical signing is unverified.
