/* purpose: Verify the full Ironwood proof from the funded H127 ballot rehearsal transaction. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "services/ironwood_verify_proof.h"
#include "services/ironwood_postnu63_pinned_h.h"
#include "services/ironwood_opening_equation.h"
#include "primitives/transaction_v6_wire.h"
#include "base/hex.h"
#include <stdio.h>
#include <stdlib.h>
#if !defined(_WIN32)
#include <unistd.h>
#include <fcntl.h>
#endif

struct fixture {
    struct ironwood_opening_basis basis;
    uint8_t custom[48484], permutation[997], lookup[1159], wire[9622];
};
static bool load_exact(const char *path, void *out, size_t bytes)
{
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fread(out, 1, bytes, f) == bytes && fgetc(f) == EOF && !ferror(f);
    return fclose(f) == 0 && ok;
}
static bool load_fixture(struct fixture *f)
{
    return load_exact("engine/services/resources/ironwood/ipa-generators.bin", f->basis.generators, sizeof f->basis.generators) &&
        zcl_hex_decode("379dc4dcfdbf61ccc7d5a0bb9759acf611694f24d0c040f249bad30a83b1a897", f->basis.u, 32) &&
        zcl_hex_decode("7520d96f3e5cd41760367151608b54821883c10c4b9a4ff2beae227bef94bcab", f->basis.w, 32) &&
        load_exact("engine/services/resources/ironwood/postnu63-custom-gates.bin", f->custom, sizeof f->custom) &&
        load_exact("engine/services/resources/ironwood/postnu63-permutation-gates.bin", f->permutation, sizeof f->permutation) &&
        load_exact("engine/services/resources/ironwood/postnu63-lookup-gates.bin", f->lookup, sizeof f->lookup) &&
        load_exact("tests/fixtures/ironwood/postnu63-ballot-v6.bin", f->wire, sizeof f->wire);
}

/* H127 wire SHA256 684900bd4595fa07474506a5b6d04b524ff2954877b259a6de6c7da5f4ee2111.
 * Orchard 0.16.0 verified the extracted two action statements and 7264-byte
 * proof independently of this production path. No intermediate H, P, v,
 * transcript challenge, or expected proof verdict is supplied to it. */
static bool check_proof(struct fixture *f)
{
    const struct ironwood_postnu63_constraint_programs programs = {
        {f->custom, sizeof f->custom}, {f->permutation, sizeof f->permutation}, {f->lookup, sizeof f->lookup}
    };
    struct v6_wire_view view;
    if (v6_core_parse(f->wire, sizeof f->wire, &view) != V6_WIRE_OK ||
        view.ironwood.count != 2 || view.ironwood.proof.size != 7264) return false;
    struct zcl_result r = ironwood_postnu63_verify_proof(f->wire, sizeof f->wire, &programs, &f->basis);
    if (!r.ok) { fprintf(stderr, "H127 proof refused: %s\n", r.message); return false; }
    struct v6_action_view action;
    if (!v6_core_bundle_action(&view.ironwood, 0, &action)) return false;
    size_t nullifier = (size_t)(action.nullifier.data - f->wire);
    f->wire[nullifier] ^= 1;
    r = ironwood_postnu63_verify_proof(f->wire, sizeof f->wire, &programs, &f->basis);
    f->wire[nullifier] ^= 1;
    if (r.ok) return false;
    f->custom[0] ^= 1;
    r = ironwood_postnu63_verify_proof(f->wire, sizeof f->wire, &programs, &f->basis);
    f->custom[0] ^= 1;
    if (r.ok) return false;
#if !defined(_WIN32)
    int saved = open(".", O_RDONLY);
    if (saved < 0) return false;
    bool changed = chdir("/") == 0;
    r = changed ? ironwood_postnu63_verify_proof_resident(f->wire, sizeof f->wire) : ZCL_ERR(-1, "chdir failed");
    bool restored = fchdir(saved) == 0;
    bool closed = close(saved) == 0;
    if (!r.ok || !restored || !closed) return false;
#else
    if (!ironwood_postnu63_verify_proof_resident(f->wire, sizeof f->wire).ok) return false;
#endif
    size_t last_scalar = (size_t)(view.ironwood.proof.data - f->wire) + view.ironwood.proof.size - 32;
    f->wire[last_scalar] ^= 1;
    r = ironwood_postnu63_verify_proof(f->wire, sizeof f->wire, &programs, &f->basis);
    f->wire[last_scalar] ^= 1;
    if (r.ok) return false;
    return !ironwood_postnu63_verify_proof(f->wire, sizeof f->wire - 1, &programs, &f->basis).ok;
}
int test_ironwood_verify_proof(void)
{
    struct fixture *f = malloc(sizeof *f);
    bool ok = f && load_fixture(f) && check_proof(f);
    free(f);
    return ok ? 0 : 1;
}
