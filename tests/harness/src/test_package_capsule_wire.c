/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: a package capsule path is a counted byte string on the wire and a
 * C string in memory, so a wire whose path holds a NUL byte has no canonical
 * re-encoding. The parser must refuse it and leave the output zeroed; the
 * honest spelling of the same path must still round-trip. Called from
 * test_vcs_core. */

#include "test/test_core.h"

#include "vcs/package_capsule.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Two inputs found by fuzzing: one header whose 17-byte path holds a NUL at
 * offset 9 and at offset 2. The serializer would write a shorter path. */
#define PCW_HEAD 'Z', 'C', 'L', 'A', 'P', 'I', '\r', '\n', 1, 0, 1, 0, 0x11, 0
#define PCW_STARS7 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a
#define PCW_ROOT                                                           \
    PCW_STARS7, PCW_STARS7, 0x2a, 0x2a, 0x2a, 0x2a, 0, 0, 0, 0, 0, 0,     \
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0a

static const uint8_t pcw_nul_mid[] = {
    PCW_HEAD, 0x41, 0x49, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x63, 0x00,
    PCW_STARS7, PCW_ROOT,
};

static const uint8_t pcw_nul_early[] = {
    PCW_HEAD, 0x41, 0x49, 0x00, 0x40, 0x2a, 0x83, 0x2a, 0x2a, 0x2a, 0x2a,
    0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, PCW_ROOT,
};

static_assert(sizeof(pcw_nul_mid) == 63u && sizeof(pcw_nul_early) == 63u,
              "fuzz inputs are 63 capsule bytes");

static bool pcw_refused_clean(const uint8_t *wire, size_t len)
{
    struct vcs_package_capsule out;
    memset(&out, 0xa5, sizeof(out));
    if (vcs_package_capsule_parse(wire, len, &out) !=
        VCS_PACKAGE_CAPSULE_ERR_HEADER)
        return false;
    struct vcs_package_capsule zero;
    memset(&zero, 0, sizeof(zero));
    return memcmp(&out, &zero, sizeof(out)) == 0;
}

/* The honest sender writes "a.h" at its own length; no NUL rides along. */
static bool pcw_honest_round_trip(void)
{
    struct vcs_package_capsule capsule;
    vcs_package_capsule_init(&capsule);
    memcpy(capsule.headers[0].path, "a.h", 4);
    memset(capsule.headers[0].file_root, 0x2a, 32);
    capsule.count = 1;
    uint8_t *wire = NULL;
    size_t len = 0;
    if (vcs_package_capsule_serialize(&capsule, &wire, &len) !=
        VCS_PACKAGE_CAPSULE_OK)
        return false;
    struct vcs_package_capsule parsed;
    bool ok = vcs_package_capsule_parse(wire, len, &parsed) ==
                  VCS_PACKAGE_CAPSULE_OK &&
              parsed.count == 1 && strcmp(parsed.headers[0].path, "a.h") == 0;
    /* The same wire with the NUL counted into the path is refused. */
    uint8_t *padded = malloc(len + 1u); // raw-alloc-ok:test-fixture
    if (!padded) {
        free(wire);
        return false;
    }
    memcpy(padded, wire, len);
    padded[12] = 4;                     /* path length 3 -> 4 */
    memmove(padded + 18, padded + 17, len - 17u);
    padded[17] = 0;                     /* the NUL is the last path byte */
    ok = ok && pcw_refused_clean(padded, len + 1u);
    free(padded);
    free(wire);
    return ok;
}

static int pcw_case(const char *name, bool ok)
{
    int failures = 0;
    TEST_CASE(name) {
        ASSERT(ok);
    } TEST_END
    return failures;
}

int package_capsule_wire_tests(void);

int package_capsule_wire_tests(void)
{
    int failures = 0;
    printf("\n=== package_capsule_wire: NUL inside a path ===\n");
    failures += pcw_case("capsule parse refuses a path holding a NUL (mid-path)",
                         pcw_refused_clean(pcw_nul_mid, sizeof(pcw_nul_mid)));
    failures += pcw_case("capsule parse refuses a path holding a NUL (early)",
                         pcw_refused_clean(pcw_nul_early,
                                           sizeof(pcw_nul_early)));
    failures += pcw_case("capsule honest path round-trips, NUL-padded refused",
                         pcw_honest_round_trip());
    return failures;
}
