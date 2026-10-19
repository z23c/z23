/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: pure helpers of ops host legacy status: binary identity against a
 *          pin, port conflicts, catch-up rate and mirror credential digests. */

#define _GNU_SOURCE

#include "command/legacy_status.h"

#include "rpc/legacy_rpc_client.h"
#include "sha3/sha3.h"
#include "crypto/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *lstat_identity_name(enum lstat_identity id)
{
    switch (id) {
    case LSTAT_ID_MATCH: return "match";
    case LSTAT_ID_MISMATCH: return "mismatch";
    case LSTAT_ID_MISSING: return "missing";
    case LSTAT_ID_UNPINNED: return "unpinned";
    }
    return "unknown";
}

enum lstat_identity lstat_identity(const char *binary, const char *pinned,
                                   char actual[65])
{
    struct sha256_ctx ctx;
    unsigned char digest[SHA256_OUTPUT_SIZE];
    unsigned char buf[65536];
    size_t got;
    actual[0] = '\0';
    FILE *f = binary && binary[0] ? fopen(binary, "rb") : NULL;
    if (!f)
        return LSTAT_ID_MISSING;
    sha256_init(&ctx);
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
        sha256_write(&ctx, buf, got);
    bool bad = ferror(f) != 0;
    fclose(f);
    if (bad)
        return LSTAT_ID_MISSING;
    sha256_finalize(&ctx, digest);
    for (size_t i = 0; i < sizeof(digest); i++)
        (void)snprintf(actual + 2 * i, 3, "%02x", digest[i]);
    if (!pinned || !pinned[0])
        return LSTAT_ID_UNPINNED;
    return strcmp(actual, pinned) == 0 ? LSTAT_ID_MATCH : LSTAT_ID_MISMATCH;
}

static void lstat_conflict_row(char (*rows)[LSTAT_CONFLICT_MAX], size_t *n, size_t max,
                         const struct lstat_inst *a, const char *an,
                         const struct lstat_inst *b, const char *bn, int port)
{
    if (*n < max)
        (void)snprintf(rows[(*n)++], LSTAT_CONFLICT_MAX, "%s.%s==%s.%s:%d",
                       a->name, an, b->name, bn, port);
}

size_t lstat_port_conflicts(const struct lstat_inst *inst, size_t n,
                            char (*rows)[LSTAT_CONFLICT_MAX], size_t max)
{
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            const int a[2] = { inst[i].port, inst[i].rpcport };
            const int b[2] = { inst[j].port, inst[j].rpcport };
            const char *const names[2] = { "port", "rpcport" };
            for (int x = 0; x < 2; x++)
                for (int y = 0; y < 2; y++)
                    if (a[x] > 0 && a[x] == b[y])
                        lstat_conflict_row(rows, &count, max, &inst[i], names[x],
                                     &inst[j], names[y], a[x]);
        }
    }
    return count;
}

struct lstat_rate lstat_rate(int64_t prev_height, int64_t prev_unix,
                             int64_t height, int64_t unix_now, int64_t gap)
{
    struct lstat_rate r = { 0 };
    int64_t dt = unix_now - prev_unix;
    if (prev_height < 0 || height < prev_height || dt <= 0)
        return r;
    r.known = true;
    r.blocks_per_min_x100 = (height - prev_height) * 6000 / dt;
    if (gap <= 0) {
        r.eta_known = true;
        return r;
    }
    if (r.blocks_per_min_x100 > 0) {
        r.eta_known = true;
        r.eta_seconds = gap * 6000 / r.blocks_per_min_x100;
    }
    return r;
}

const char *lstat_creds_name(enum lstat_creds c)
{
    switch (c) {
    case LSTAT_CREDS_MATCH: return "match";
    case LSTAT_CREDS_MISMATCH: return "mismatch";
    case LSTAT_CREDS_UNKNOWN: return "unknown";
    }
    return "unknown";
}

static void lstat_wipe(char *p, size_t n)
{
    volatile char *v = p;
    while (n--)
        *v++ = 0;
}

static bool lstat_creds_digest(const char *path,
                         unsigned char out[SHA3_256_OUTPUT_SIZE])
{
    char user[64] = { 0 }, pass[128] = { 0 };
    struct sha3_256_ctx ctx;
    bool ok = legacy_rpc_parse_conf_file(path, user, sizeof(user), pass,
                                         sizeof(pass), NULL);
    if (ok) {
        sha3_256_init(&ctx);
        sha3_256_write(&ctx, (const unsigned char *)user, strlen(user) + 1);
        sha3_256_write(&ctx, (const unsigned char *)pass, strlen(pass));
        sha3_256_finalize(&ctx, out);
    }
    lstat_wipe(user, sizeof(user));
    lstat_wipe(pass, sizeof(pass));
    return ok;
}

const char *lstat_node_conf(const char *override_path, char *out, size_t cap)
{
    const char *env = getenv("ZCL_LEGACY_ORACLE_CONF");
    const char *home = getenv("HOME");
    if (override_path && override_path[0]) {
        (void)snprintf(out, cap, "%s", override_path);
        return "input";
    }
    if (env && env[0]) {
        (void)snprintf(out, cap, "%s", env);
        return "env";
    }
    (void)snprintf(out, cap, "%s/.zclassic/zclassic.conf",
                   home && home[0] ? home : "");
    return "default";
}

enum lstat_creds lstat_mirror_creds(const char *node_conf,
                                    const char *instance_conf)
{
    unsigned char inst[SHA3_256_OUTPUT_SIZE], node[SHA3_256_OUTPUT_SIZE];
    if (!lstat_creds_digest(instance_conf, inst))
        return LSTAT_CREDS_UNKNOWN;
    if (!lstat_creds_digest(node_conf, node))
        return LSTAT_CREDS_MISMATCH;
    return memcmp(inst, node, sizeof(inst)) == 0 ? LSTAT_CREDS_MATCH
                                                 : LSTAT_CREDS_MISMATCH;
}

bool lstat_no_peers(int64_t connections, int64_t height, int64_t z23_height,
                    int64_t prev_height)
{
    bool behind = height >= 0 && z23_height > height;
    bool stalled = prev_height >= 0 && height >= 0 && height <= prev_height;
    return connections == 0 && (behind || stalled);
}
