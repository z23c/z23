/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * secp256k1 compatibility — RESOLVED.
 *
 * The alias secp256k1_ec_seckey_tweak_add is now baked into
 * vendor/lib/libsecp256k1.a permanently (seckey_alias.o added
 * via `ar rcs`). This file is intentionally empty.
 *
 * No matter what happens to this file, the build will work.
 * The symbol lives in the .a, not here. */

typedef int secp256k1_compat_resolved_;
