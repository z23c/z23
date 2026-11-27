/* purpose: Inspect experimental offline regtest-shielded profile fixtures. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "common.h"
#include "base/hex.h"
#include <stdio.h>
#include <string.h>

static int finish_output(const char *label)
{
    if (fflush(stdout) == 0 && !ferror(stdout)) return 0;
    fprintf(stderr, "%s output write failed\n", label);
    return 1;
}

static void export_catalog(const struct experimental_profile *p)
{
    fputs("[\"", stdout);
    profile_print_hex(p->catalog.network_id, 32);
    printf("\",%d,%d,[", p->catalog.start, p->catalog.window);
    for (size_t i = 0; i < p->catalog.count; ++i) {
        if (i) putchar(',');
        fputs("[\"", stdout);
        profile_print_hex(p->catalog.entries[i].rule_revision, 32);
        printf("\",%d]", p->catalog.entries[i].activation);
    }
    puts("]]");
}

static enum experimental_profile_status load_profile(
    const char *manifest_path, const char *genesis_path, const char *pin,
    bool export, struct experimental_profile *p)
{
    uint8_t manifest[PROFILE_MAX + 1], genesis[GENESIS_SIZE + 1], expected[32];
    size_t mlen = 0, glen = 0;
    if (!experimental_profile_read_file(manifest_path, manifest, sizeof(manifest), &mlen).ok ||
        !experimental_profile_read_file(genesis_path, genesis, sizeof(genesis), &glen).ok)
        return EXPERIMENTAL_PROFILE_INVALID;
    if (!pin) return experimental_profile_inspect(manifest, mlen, genesis, glen, p);
    bool decoded = export ? zcl_hex_decode_lower(pin, expected, sizeof(expected))
                          : zcl_hex_decode(pin, expected, sizeof(expected));
    if (decoded) return experimental_profile_load(manifest, mlen, genesis, glen, expected, p);
    enum experimental_profile_status status =
        experimental_profile_inspect(manifest, mlen, genesis, glen, p);
    return status == EXPERIMENTAL_PROFILE_OK ? EXPERIMENTAL_PROFILE_PIN_MISMATCH : status;
}

static int check_options(int argc, char **argv, bool *export)
{
    *export = argc > 1 && strcmp(argv[1], "--export-catalog") == 0;
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        fputs("Usage: profile-inspector MANIFEST GENESIS [EXPECTED_CATALOG_HEX]\n"
              "       profile-inspector --export-catalog MANIFEST GENESIS EXPECTED_CATALOG_HEX\n"
              "Export requires a previously agreed lowercase pin; save output as\n"
              "DATADIR/ballots/EXPECTED_CATALOG_HEX.json for the node loader.\n",
              stdout);
        return finish_output("profile");
    }
    if (*export && argc != 5) {
        fputs("Usage: profile-inspector --export-catalog MANIFEST GENESIS EXPECTED_CATALOG_HEX\n", stderr);
        return 1;
    }
    return -1;
}

int main(int argc, char **argv)
{
    bool export;
    int option_result = check_options(argc, argv, &export);
    if (option_result >= 0) return option_result;
    int offset = export ? 1 : 0;
    struct experimental_profile p = {0};
    if (!export && argc != 3 && argc != 4) {
        fputs("invalid experimental profile or genesis\n", stderr);
        return 1;
    }
    const char *pin = (export || argc == 4) ? argv[3 + offset] : NULL;
    enum experimental_profile_status status =
        load_profile(argv[1 + offset], argv[2 + offset], pin, export, &p);
    if (status != EXPERIMENTAL_PROFILE_OK) {
        fputs(status == EXPERIMENTAL_PROFILE_CATALOG_INVALID ? "invalid experimental catalog\n" :
              status == EXPERIMENTAL_PROFILE_PIN_MISMATCH ? "expected catalog mismatch or invalid digest\n" :
              "invalid experimental profile or genesis\n", stderr);
        return 1;
    }
    if (export) {
        export_catalog(&p);
        return finish_output("catalog");
    }
    char display[65];
    uint256_get_hex(&p.genesis_hash, display);
    fputs("{\"format\":\"Z23-PROFILE-EXPERIMENT-1\",\"profile\":\"", stdout);
    profile_print_hex(p.digest, 32);
    fputs("\",\"magic\":\"", stdout); profile_print_hex(p.magic, 4);
    printf("\",\"genesis\":\"%s\",\"catalog\":\"", display);
    profile_print_hex(p.catalog.digest, 32);
    printf("\",\"start\":%d,\"window\":%d,\"proposals\":%zu,\"rules\":[",
           p.catalog.start, p.catalog.window, p.catalog.count);
    for (size_t i = 0; i < p.catalog.count; i++) {
        if (i) putchar(',');
        fputs("{\"revision\":\"", stdout);
        profile_print_hex(p.catalog.entries[i].rule_revision, 32);
        printf("\",\"activation\":%d}", p.catalog.entries[i].activation);
    }
    puts("]}");
    return finish_output("profile");
}
