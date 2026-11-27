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

static void export_catalog(const struct profile *p)
{
    fputs("[\"", stdout);
    profile_print_hex(p->catalog.network_id, 32);
    printf("\",%d,%d,[", p->catalog.start, p->catalog.window);
    for (size_t i = 0; i < p->catalog.count; ++i) {
        if (i) putchar(',');
        fputs("[\"", stdout);
        profile_print_hex(p->entries[i].rule_revision, 32);
        printf("\",%d]", p->entries[i].activation);
    }
    puts("]]");
}

static bool load_profile(const char *manifest_path, const char *genesis_path,
                         struct profile *p, struct uint256 *hash)
{
    uint8_t manifest[PROFILE_MAX + 1], genesis[GENESIS_SIZE + 1];
    size_t mlen = 0, glen = 0;
    return profile_read_file(manifest_path, manifest, sizeof(manifest), &mlen) &&
           profile_read_file(genesis_path, genesis, sizeof(genesis), &glen) &&
           profile_parse(manifest, mlen, p) &&
           profile_inspect_genesis(genesis, glen, p, hash);
}

static bool pin_matches(const char *text, bool export, const uint8_t digest[32])
{
    uint8_t expected[32];
    bool decoded = export ? zcl_hex_decode_lower(text, expected, sizeof(expected))
                          : zcl_hex_decode(text, expected, sizeof(expected));
    return decoded && memcmp(expected, digest, sizeof(expected)) == 0;
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
    struct profile p = {0};
    struct uint256 hash;
    struct miner_signal_schedule schedule;
    if ((!export && argc != 3 && argc != 4) ||
        !load_profile(argv[1 + offset], argv[2 + offset], &p, &hash)) {
        fputs("invalid experimental profile or genesis\n", stderr);
        return 1;
    }
    memcpy(p.catalog.genesis, hash.data, 32);
    if (!miner_signal_catalog_select(&p.catalog, 0, &schedule).ok) {
        fputs("invalid experimental catalog\n", stderr);
        return 1;
    }
    if ((export || argc == 4) &&
        !pin_matches(argv[3 + offset], export, schedule.catalog)) {
        fputs("expected catalog mismatch or invalid digest\n", stderr);
        return 1;
    }
    if (export) {
        export_catalog(&p);
        return finish_output("catalog");
    }
    char display[65];
    uint256_get_hex(&hash, display);
    fputs("{\"format\":\"Z23-PROFILE-EXPERIMENT-1\",\"profile\":\"", stdout);
    profile_print_hex(p.digest, 32);
    fputs("\",\"magic\":\"", stdout); profile_print_hex(p.magic, 4);
    printf("\",\"genesis\":\"%s\",\"catalog\":\"", display);
    profile_print_hex(schedule.catalog, 32);
    printf("\",\"start\":%d,\"window\":%d,\"proposals\":%zu,\"rules\":[",
           p.catalog.start, p.catalog.window, p.catalog.count);
    for (size_t i = 0; i < p.catalog.count; i++) {
        if (i) putchar(',');
        fputs("{\"revision\":\"", stdout);
        profile_print_hex(p.entries[i].rule_revision, 32);
        printf("\",\"activation\":%d}", p.entries[i].activation);
    }
    puts("]}");
    return finish_output("profile");
}
