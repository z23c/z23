/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent_sha3 — SHA3-256 of files or stdin, for the agent gate-receipt harness.
 *
 * The receipts written by tools/agent/gate-receipt.sh commit to the captured
 * output of a gate with a SHA3-256 digest, and tools/agent/check-claims.sh
 * recomputes it. Both need a hash the repo already owns: this links the
 * in-tree FIPS-202 SHA3-256 (platform/modules/sha3/src/sha3.c) and nothing else, so the
 * harness introduces no hashing dependency and no shell-out to openssl (which
 * is not a dependency of this project and whose sha3 support varies by build).
 *
 * Deliberately NOT sha256sum from coreutils: the rest of this tree commits to
 * state with SHA3-256 (core/MANIFEST.sha3, the UTXO commitment, the codeindex
 * merkle), and a receipt that used a different hash would be the only place an
 * agent had to remember which one.
 *
 * Streaming, fixed 64 KiB buffer, no allocation — a receipt may cover a
 * multi-hundred-megabyte test log.
 *
 * Usage:
 *   agent_sha3 FILE...        one "<64-hex>  <path>" line per file
 *   agent_sha3                digest of stdin, printed bare (no path column)
 *   agent_sha3 -              same as no arguments
 *
 * Exit: 0 all files hashed; 1 any file unreadable (the failure is named on
 * stderr and the remaining files are still hashed, like sha256sum).
 */
#define _POSIX_C_SOURCE 200809L

#include "base/hex.h"
#include "crypto/sha3.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define AGENT_SHA3_BUFSZ 65536u

/* SHA3-256 of everything readable from `fp`. Returns 0 on success, -1 on a
 * read error (the caller names the path; this function has no opinion). */
static int hash_stream(FILE *fp, char hex_out[65])
{
    struct sha3_256_ctx ctx;
    unsigned char buf[AGENT_SHA3_BUFSZ];
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    size_t got;

    sha3_256_init(&ctx);
    while ((got = fread(buf, 1, sizeof buf, fp)) > 0)
        sha3_256_write(&ctx, buf, got);
    if (ferror(fp))
        return -1;
    sha3_256_finalize(&ctx, digest);
    /* The single tree-wide hex codec (platform/modules/base/include/base/hex.h). A private
     * one here would be a real check-hex-codec-single violation, and was —
     * this file had one until `make lint` refused it. */
    zcl_hex_encode(digest, sizeof digest, hex_out);
    return 0;
}

int main(int argc, char **argv)
{
    char hex[65];
    int status = 0;

    if (argc < 2 || (argc == 2 && strcmp(argv[1], "-") == 0)) {
        if (hash_stream(stdin, hex) != 0) {
            fprintf(stderr, "agent_sha3: read error on stdin: %s\n",
                    strerror(errno));
            return 1;
        }
        printf("%s\n", hex);
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-") == 0) {
            if (hash_stream(stdin, hex) != 0) {
                fprintf(stderr, "agent_sha3: read error on stdin: %s\n",
                        strerror(errno));
                status = 1;
                continue;
            }
            printf("%s  -\n", hex);
            continue;
        }
        FILE *fp = fopen(argv[i], "rb");
        if (!fp) {
            fprintf(stderr, "agent_sha3: cannot open %s: %s\n", argv[i],
                    strerror(errno));
            status = 1;
            continue;
        }
        int rc = hash_stream(fp, hex);
        fclose(fp);
        if (rc != 0) {
            fprintf(stderr, "agent_sha3: read error on %s: %s\n", argv[i],
                    strerror(errno));
            status = 1;
            continue;
        }
        printf("%s  %s\n", hex, argv[i]);
    }
    return status;
}
