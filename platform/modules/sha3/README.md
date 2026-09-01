# zclassic23/sha3

Allocation-free scalar FIPS-202 SHA3-256, SHA3-512, SHAKE128 and SHAKE256 for
C23. Streaming SHA3 layouts and symbols are the ones used by the ZClassic23
monolith. SHAKE one-shots validate pointer/length pairs and support arbitrary
caller-bounded multi-block output.

This package depends only on the exact `zclassic23/base` package root recorded
in its external dependency lock. Batched x4/AVX-512 acceleration remains owned
by `core/modules/crypto` and uses this scalar package as its byte-parity oracle.
