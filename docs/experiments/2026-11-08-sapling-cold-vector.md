<!-- Copyright 2026 Rhett Creighton. Apache License 2.0. -->

# Cold Sapling replay vector

The registered `catchup_parallel_cold` group exercises the production replay
decrypt path in a fresh test-runner group. It uses public synthetic input,
asserts that the worker pool was created, and checks the resulting note and
position-zero nullifier. This is a correctness fixture, not a performance
measurement. On a maintainer host, run it by itself in a fresh runner with
hotswap disabled and cache reuse refused:

```sh
env -u ZCL_HOTSWAP_TEST_MODULE DEVBUILD_CLASS=normal devbuild --wait --project z23 \
  make t-fast-exact ONLY=catchup_parallel_cold 'T_FAST_EXACT_ARGS=--no-cache --jobs=1'
```

The ordinary sequential suite can run this group after other crypto tests and
does not establish cold first use.

The unwrapped generator output has SHA-256
`c0944a584c98e337d0923a65cb30e49f539bf5cddc94e013c0b6eca3ab3e2e55`.
The checked-in header adds the license and include guard and removes trailing
whitespace; its SHA-256 is
`2b4690548067103b4a95df9a3fe9f49461f3426009b91c89c17614a5a34f2d06`.
The generator source below has SHA-256
`decc5873ecf73a6bf46335a3a47da8843fb18378f3caf0ec5520a44d6a75e62c`.

For reproduction, save the following source as `/tmp/sapling-cold-vector.c`.
The literal seed and all emitted values are synthetic.

```c
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Emits deterministic public synthetic Sapling test input; no wallet data. */
#include "sapling/sapling.h"
#include "sapling/prf.h"
#include "sapling/note_encryption.h"
#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void emit(const char *name, const uint8_t *bytes, size_t len)
{
    printf("static const uint8_t %s[%zu] = {", name, len);
    for (size_t i = 0; i < len; ++i) {
        if (i % 12 == 0) printf("\n    ");
        printf("0x%02x%s", bytes[i], i + 1 == len ? "" : ", ");
    }
    puts("\n};");
}
int main(void)
{
    struct uint256 seed = {{0}}, ask = {{0}}, nsk = {{0}};
    for (size_t i = 0; i < 32; ++i) seed.data[i] = (uint8_t)(i + 1);
    prf_ask(&seed, &ask); prf_nsk(&seed, &nsk);
    uint8_t ak[32], nk[32], ivk[32], d[11] = {0}, pk[32], epk[32];
    uint8_t esk[32] = {2}, shared[32], receiver[32], key[32], cm[32], nf[32];
    uint8_t plain[564] = {0}, cipher[580], decoded[564];
    sapling_ask_to_ak(ask.data, ak); sapling_nsk_to_nk(nsk.data, nk);
    sapling_crh_ivk(ak, nk, ivk);
    bool found = false;
    for (unsigned i = 1; i < 65536; ++i) {
        d[0] = (uint8_t)i; d[1] = (uint8_t)(i >> 8);
        if (sapling_ivk_to_pkd(ivk, d, pk) && sapling_ka_derivepublic(d, esk, epk)) { found = true; break; }
    }
    plain[0] = 1; memcpy(plain + 1, d, 11); plain[12] = 10; plain[20] = 1;
    if (!found || !sapling_compute_cm(d, pk, 10, plain + 20, cm) ||
        !sapling_compute_nf(d, pk, 10, plain + 20, ak, nk, 0, nf) ||
        !sapling_ka_agree(pk, esk, shared) || !sapling_ka_agree(epk, ivk, receiver) ||
        memcmp(shared, receiver, 32) || !sapling_kdf(key, shared, epk) ||
        !sapling_note_encrypt(key, plain, sizeof(plain), cipher) ||
        !sapling_note_decrypt(key, cipher, sizeof(cipher), decoded) ||
        memcmp(plain, decoded, sizeof(plain))) return 1;
    puts("/* Public synthetic fixture; expected value 10, position 0. */");
    emit("cold_ivk", ivk, sizeof(ivk)); emit("cold_ak", ak, sizeof(ak));
    emit("cold_nk", nk, sizeof(nk)); emit("cold_epk", epk, sizeof(epk));
    emit("cold_cm", cm, sizeof(cm)); emit("cold_ciphertext", cipher, sizeof(cipher));
    emit("cold_plaintext", plain, sizeof(plain)); emit("cold_nf_position0", nf, sizeof(nf));
    return ferror(stdout) ? 1 : 0;
}
```

From the repository root, using a C23 compiler:

```sh
set --
for d in $(find core platform contexts -type d -name include); do set -- "$@" "-I$d"; done
cc -D_POSIX_C_SOURCE=200809L -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
  -ffunction-sections -fdata-sections "$@" /tmp/sapling-cold-vector.c \
  core/modules/sapling/src/prf.c core/modules/sapling/src/sapling.c \
  core/modules/sapling/src/jubjub.c core/modules/sapling/src/fr.c \
  core/modules/sapling/src/fr_avx512.c core/modules/sapling/src/pedersen_hash.c \
  core/modules/sapling/src/note_encryption.c core/modules/crypto/src/blake2s.c \
  core/modules/crypto/src/blake2b.c core/modules/crypto/src/chacha20poly1305.c \
  core/modules/crypto/src/simd_dispatch.c platform/modules/base/src/cleanse.c \
  platform/modules/base/src/safe_alloc.c platform/modules/base/src/log_level.c \
  platform/modules/util/src/workpool.c platform/modules/util/src/util.c platform/modules/platform/src/clock.c \
  platform/modules/support/src/log_throttle.c -Wl,--gc-sections -pthread -lm \
  -o /tmp/sapling-cold-vector
/tmp/sapling-cold-vector > /tmp/sapling-cold-vector.h
sha256sum /tmp/sapling-cold-vector.h
```

On 2026-11-08 UTC, a host replay experiment completed 32 cases and six repeat
cases with matching results across worker settings. The host identifies as an
AMD Ryzen 9 7950X3D; the build compiler version was not recorded. One dense,
no-owner sample took 838 ms with forced serial fallback and 242 ms with four
workers. An owner-19 sample took 953 ms serial and 1,663 ms with four workers;
four-worker repeats ranged from 528 to 1,219 ms as host load changed. These
are individual observations, not an aggregate speedup or Android measurement.
Real Android replay timing and responsiveness remain to be measured.
