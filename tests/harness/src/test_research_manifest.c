/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Pin the Ironwood release manifest file checksum. */

#include "services/research_manifest.h"

#include "chain/chainparams.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

static const char manifest_path[] =
    "tests/fixtures/ironwood/selected-manifest.json";
static const char published_manifest[] =
    "2ab8c84b459c331e946a5848f9a84ed9df5e6c908388d170669c683c47c2b8b5";

static int manifest_check(const char *cond, int ok)
{
    if (!ok) {
        fprintf(stderr, "research_manifest: %s\n", cond);
        return 1;
    }
    return 0;
}

static int bytes_are(const unsigned char *raw, size_t n, unsigned char expect)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (raw[i] != expect)
            return 0;
    }
    return 1;
}

static void manifest_hex(const unsigned char *raw, char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < SHA3_256_OUTPUT_SIZE; i++) {
        unsigned char b = raw[i];
        out[i * 2] = hexd[b / 16];
        out[i * 2 + 1] = hexd[b % 16];
    }
    out[64] = '\0';
}

static int refuse_null(void)
{
    struct zcl_result r;

    r = research_manifest_read(manifest_path, NULL, SHA3_256_OUTPUT_SIZE);
    return manifest_check("null manifest refused",
                          !r.ok && strcmp(r.message, "Missing manifest") == 0);
}

static int refuse_short(void)
{
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    struct zcl_result r;

    memset(digest, 'X', sizeof digest);
    r = research_manifest_read(manifest_path, digest, 16);
    if (manifest_check("short manifest refused",
                       !r.ok && strcmp(r.message, "Manifest cap refused") == 0))
        return 1;
    return manifest_check("short manifest writes nothing",
                          bytes_are(digest, sizeof digest, 'X'));
}

static int refuse_path(void)
{
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    struct zcl_result r;

    memset(digest, 'X', sizeof digest);
    r = research_manifest_read(NULL, digest, sizeof digest);
    if (manifest_check("null path refused",
                       !r.ok && strcmp(r.message, "Missing manifest path") == 0))
        return 1;
    if (manifest_check("null path writes nothing",
                       bytes_are(digest, sizeof digest, 'X')))
        return 1;
    r = research_manifest_read("", digest, sizeof digest);
    if (manifest_check("empty path refused",
                       !r.ok && strcmp(r.message, "Missing manifest path") == 0))
        return 1;
    r = research_manifest_read("tests/fixtures/ironwood/not-a-manifest.json",
                               digest, sizeof digest);
    if (manifest_check("missing file refused",
                       !r.ok && strcmp(r.message, "Manifest unreadable") == 0))
        return 1;
    return manifest_check("missing file writes nothing",
                          bytes_are(digest, sizeof digest, 'X'));
}

static int read_published(void)
{
    unsigned char raw[256];
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    unsigned char got[SHA3_256_OUTPUT_SIZE];
    char shown[65];
    FILE *f;
    size_t n;

    f = fopen(manifest_path, "rb");
    if (manifest_check("manifest file opens", f != NULL))
        return 1;
    n = fread(raw, 1, sizeof raw, f);
    if (manifest_check("manifest file read",
                       ferror(f) == 0 && fclose(f) == 0 && n == 224))
        return 1;
    printf("manifest_bytes=%zu\n", n);
    sha3_256(raw, n, digest);
    memset(got, 'X', sizeof got);
    if (manifest_check("manifest read ok",
                       research_manifest_read(manifest_path, got,
                                              sizeof got).ok))
        return 1;
    manifest_hex(got, shown);
    printf("manifest_sha3=%s\n", shown);
    if (manifest_check("manifest matches file",
                       memcmp(got, digest, SHA3_256_OUTPUT_SIZE) == 0))
        return 1;
    return manifest_check("manifest published",
                          strcmp(shown, published_manifest) == 0);
}

int test_research_manifest(void)
{
    const struct chain_params *main;
    const struct chain_research_descriptor *current;

    main = chain_params_get();
    current = chain_research_profile_current();
    if (manifest_check("lookup starts unselected", main && !current))
        return 1;
    if (refuse_null() || refuse_short() || refuse_path() || read_published())
        return 1;
    if (manifest_check("read does not select",
                       chain_params_get() == main &&
                       !chain_research_profile_current()))
        return 1;
    printf("research_manifest: ironwood manifest file checksum pinned\n");
    return 0;
}
