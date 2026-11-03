/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Regression: NULL base pointers with a zero length must never reach pointer
 * arithmetic (UBSan "applying zero offset to null pointer"), and the status
 * endpoint must close its sqlite handle when the open fails. Digests stay
 * bit-identical to the published empty-input vectors. */

#include "test/test_core.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "core/hash.h"
#include "net/compact_blocks.h"
#include "net/onion_service.h"
#include "script/htlc.h"

static int check(const char *name, bool ok)
{
    printf("core nullptr: %s... %s\n", name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static int hex_eq(const unsigned char *d, size_t n, const char *hex)
{
    char buf[130];
    for (size_t i = 0; i < n; i++)
        snprintf(buf + 2 * i, 3, "%02x", d[i]);
    return strcmp(buf, hex) == 0;
}

static int nullptr_hashes(void)
{
    int failures = 0;
    unsigned char out[64];
    struct sha256_ctx c256;
    sha256_init(&c256);
    sha256_write(&c256, NULL, 0);
    sha256_finalize(&c256, out);
    failures += check("sha256_write(NULL,0) is the empty digest",
        hex_eq(out, 32,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

    struct sha512_ctx c512;
    sha512_init(&c512);
    sha512_write(&c512, NULL, 0);
    sha512_finalize(&c512, out);
    failures += check("sha512_write(NULL,0) is the empty digest",
        hex_eq(out, 64,
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));

    hash256(NULL, 0, out);
    failures += check("hash256(NULL,0) is double-sha256 of empty",
        hex_eq(out, 32,
        "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"));
    return failures;
}

static int nullptr_parsers(void)
{
    int failures = 0;
    uint8_t secret[32] = {0};
    failures += check("htlc_extract_secret(NULL,0) is false",
                      !htlc_extract_secret(NULL, 0, secret));

    uint8_t key[16];
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
    failures += check("siphash_2_4(NULL,0) is the reference empty vector",
                      siphash_2_4(key, NULL, 0) == 0x726fdb47dd0e0e31ULL);
    return failures;
}

/* A missing node.db makes sqlite3_open_v2 fail but still hand back a handle;
 * under LEAK_CHECK=fail the unclosed handle fails the run. */
static int nullptr_status_db(void)
{
    char tmpdir[256], missing[300];
    uint8_t buf[4096];
    test_make_tmpdir(tmpdir, sizeof(tmpdir), "core_nullptr", "status");
    onion_service_stop();
    snprintf(missing, sizeof(missing), "%s/absent-datadir", tmpdir);
    onion_service_start(missing);
    size_t len = onion_service_handle_request("GET", "/status", NULL, 0,
                                              buf, sizeof(buf));
    onion_service_stop();
    return check("/status with no node.db answers and closes the handle",
                 len > 0);
}

int test_core_nullptr(void)
{
    int failures = 0;
    failures += nullptr_hashes();
    failures += nullptr_parsers();
    failures += nullptr_status_db();
    return failures;
}
