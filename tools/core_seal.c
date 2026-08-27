/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * core_seal — the sealed-consensus-core manifest tool (Wave 1.1 / W0).
 *
 * The sealed core (top-level core/) holds the consensus predicates and static
 * parameter tables that decide whether a block/tx is valid. Its integrity is
 * pinned by a SHA3-256 manifest at core/MANIFEST.sha3: a per-file digest of
 * every tracked file under core/ (excluding the manifest itself) plus a single
 * ROOT digest over the sorted (path, filehash) stream. Any change to a sealed
 * file changes ROOT, which `make core-seal-check` catches.
 *
 * This tool deliberately does NOT shell to git. The Makefile feeds it the file
 * list on stdin (NUL-separated, from `git ls-files -z core/`); the tool only
 * hashes file bytes and reads/writes the manifest. No external dependencies —
 * it links the in-tree FIPS-202 SHA3-256 (lib/sha3/src/sha3.c) plus
 * memory_cleanse (lib/base/src/cleanse.c), stock libc otherwise.
 *
 * Usage (paths on stdin, NUL-separated):
 *   core_seal seal  core/MANIFEST.sha3   < filelist   (writes the manifest)
 *   core_seal check core/MANIFEST.sha3   < filelist   (0=match, 1=drift, 2=error)
 *
 * See CLAUDE.md "Tenacity & recovery" and the plan
 * ~/.claude/plans/we-are-working-to-concurrent-melody.md (Pillar 1, Wave 1.1).
 */
#define _POSIX_C_SOURCE 200809L

#include "crypto/sha3.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One sealed-file record: path + its 32-byte SHA3-256 content digest. */
struct entry {
    char *path;
    unsigned char hash[SHA3_256_OUTPUT_SIZE];
};

static void die(const char *msg)
{
    fprintf(stderr, "core_seal: %s\n", msg);
    if (errno)
        fprintf(stderr, "core_seal: errno: %s\n", strerror(errno));
    exit(2);
}

static void hex_of(const unsigned char *in, size_t n, char *out /* 2n+1 */)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[in[i] >> 4];
        out[2 * i + 1] = d[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

/* SHA3-256 over the full contents of `path`. Returns 0 on success. */
static int hash_file(const char *path, unsigned char out[SHA3_256_OUTPUT_SIZE])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    unsigned char buf[65536];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), f)) > 0)
        sha3_256_write(&ctx, buf, r);
    int ferr = ferror(f);
    fclose(f);
    if (ferr)
        return -1;
    sha3_256_finalize(&ctx, out);
    return 0;
}

static int cmp_entry(const void *a, const void *b)
{
    const struct entry *ea = a, *eb = b;
    return strcmp(ea->path, eb->path);
}

/* Read NUL-separated (or newline-separated) paths from stdin. Excludes the
 * manifest path itself. Hashes each file, returns a path-sorted array. */
static struct entry *read_and_hash(const char *manifest_path, size_t *out_n)
{
    /* Slurp stdin. */
    size_t cap = 65536, len = 0;
    char *data = malloc(cap); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
    if (!data)
        die("out of memory reading stdin");
    for (;;) {
        if (len == cap) {
            cap *= 2;
            char *nd = realloc(data, cap); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
            if (!nd)
                die("out of memory reading stdin");
            data = nd;
        }
        size_t r = fread(data + len, 1, cap - len, stdin);
        len += r;
        if (r == 0)
            break;
    }

    struct entry *ents = NULL;
    size_t n = 0, ecap = 0;

    size_t i = 0;
    while (i < len) {
        /* A path token runs up to the next NUL or newline. */
        size_t j = i;
        while (j < len && data[j] != '\0' && data[j] != '\n')
            j++;
        size_t plen = j - i;
        if (plen > 0) {
            char *path = malloc(plen + 1); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
            if (!path)
                die("out of memory");
            memcpy(path, data + i, plen);
            path[plen] = '\0';
            /* Skip the manifest itself — it can never seal its own bytes. */
            if (strcmp(path, manifest_path) != 0) {
                if (n == ecap) {
                    ecap = ecap ? ecap * 2 : 64;
                    struct entry *ne = realloc(ents, ecap * sizeof(*ents)); // raw-alloc-ok:standalone-build-time-seal-tool-links-no-safe_alloc
                    if (!ne)
                        die("out of memory");
                    ents = ne;
                }
                ents[n].path = path;
                if (hash_file(path, ents[n].hash) != 0) {
                    fprintf(stderr, "core_seal: cannot read sealed file '%s'\n",
                            path);
                    exit(2);
                }
                n++;
            } else {
                free(path);
            }
        }
        i = j + 1;
    }
    free(data);

    qsort(ents, n, sizeof(*ents), cmp_entry);
    *out_n = n;
    return ents;
}

/* ROOT = SHA3-256 over, for each sorted entry: path bytes, one NUL, 32 raw
 * hash bytes. Path-sorted so the digest is order-independent of the input. */
static void compute_root(const struct entry *ents, size_t n,
                         unsigned char root[SHA3_256_OUTPUT_SIZE])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    for (size_t i = 0; i < n; i++) {
        sha3_256_write(&ctx, (const unsigned char *)ents[i].path,
                       strlen(ents[i].path));
        unsigned char nul = 0;
        sha3_256_write(&ctx, &nul, 1);
        sha3_256_write(&ctx, ents[i].hash, SHA3_256_OUTPUT_SIZE);
    }
    sha3_256_finalize(&ctx, root);
}

static int do_seal(const char *manifest_path)
{
    size_t n = 0;
    struct entry *ents = read_and_hash(manifest_path, &n);
    unsigned char root[SHA3_256_OUTPUT_SIZE];
    compute_root(ents, n, root);

    FILE *m = fopen(manifest_path, "wb");
    if (!m)
        die("cannot open manifest for writing");
    fprintf(m,
            "# Consensus seal — SHA3-256 manifest. AUTO-GENERATED by "
            "`make core-seal`.\n"
            "# Do not edit by hand. `make core-seal-check` fails loud if any "
            "sealed file drifts from this.\n"
            "# Sealed set: core/ (consensus predicates + parameter tables) plus\n"
            "# the block-connection ordering layer named in the Makefile's\n"
            "# CORE_SEAL_PATHS (an ordering bug forks exactly as hard as a\n"
            "# predicate bug — see docs/adr/0002-sealed-consensus-core.md).\n"
            "# Format: <sha3-256 hex>  <path>, one per sealed file (sorted), "
            "then a final ROOT line.\n");
    char hex[2 * SHA3_256_OUTPUT_SIZE + 1];
    for (size_t i = 0; i < n; i++) {
        hex_of(ents[i].hash, SHA3_256_OUTPUT_SIZE, hex);
        fprintf(m, "%s  %s\n", hex, ents[i].path);
    }
    hex_of(root, SHA3_256_OUTPUT_SIZE, hex);
    fprintf(m, "ROOT  %s\n", hex);
    if (fclose(m) != 0)
        die("write error closing manifest");

    hex_of(root, SHA3_256_OUTPUT_SIZE, hex);
    fprintf(stderr, "core_seal: sealed %zu file(s), ROOT %s\n", n, hex);
    for (size_t i = 0; i < n; i++)
        free(ents[i].path);
    free(ents);
    return 0;
}

/* Parse the ROOT hex from an existing manifest. Returns 0 on success. */
static int read_manifest_root(const char *manifest_path,
                              char out_hex[2 * SHA3_256_OUTPUT_SIZE + 1])
{
    FILE *m = fopen(manifest_path, "rb");
    if (!m)
        return -1;
    char line[4096];
    int found = -1;
    while (fgets(line, sizeof(line), m)) {
        if (strncmp(line, "ROOT ", 5) == 0) {
            const char *p = line + 5;
            while (*p == ' ')
                p++;
            size_t k = 0;
            while (k < 2 * SHA3_256_OUTPUT_SIZE && p[k] &&
                   p[k] != '\n' && p[k] != '\r') {
                out_hex[k] = p[k];
                k++;
            }
            out_hex[k] = '\0';
            if (k == 2 * SHA3_256_OUTPUT_SIZE)
                found = 0;
        }
    }
    fclose(m);
    return found;
}

static int do_check(const char *manifest_path)
{
    char have[2 * SHA3_256_OUTPUT_SIZE + 1];
    if (read_manifest_root(manifest_path, have) != 0) {
        fprintf(stderr,
                "core_seal: FATAL — no valid ROOT line in manifest '%s'.\n"
                "  Run `make core-seal` to (re)generate it.\n",
                manifest_path);
        return 2;
    }

    size_t n = 0;
    struct entry *ents = read_and_hash(manifest_path, &n);
    unsigned char root[SHA3_256_OUTPUT_SIZE];
    compute_root(ents, n, root);
    char now[2 * SHA3_256_OUTPUT_SIZE + 1];
    hex_of(root, SHA3_256_OUTPUT_SIZE, now);

    int rc = 0;
    if (strcmp(have, now) != 0) {
        fprintf(stderr,
                "core_seal: DRIFT — core/ does not match its seal.\n"
                "  manifest ROOT: %s\n"
                "  computed ROOT: %s\n",
                have, now);
        rc = 1;
    } else {
        fprintf(stderr, "core_seal: OK — %zu sealed file(s) match ROOT %s\n", n,
                now);
    }
    for (size_t i = 0; i < n; i++)
        free(ents[i].path);
    free(ents);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,
                "usage: %s <seal|check> <manifest-path>   (paths on stdin, "
                "NUL-separated)\n",
                argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    const char *manifest = argv[2];
    if (strcmp(mode, "seal") == 0)
        return do_seal(manifest);
    if (strcmp(mode, "check") == 0)
        return do_check(manifest);
    fprintf(stderr, "core_seal: unknown mode '%s' (want seal|check)\n", mode);
    return 2;
}
