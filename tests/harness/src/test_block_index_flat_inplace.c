/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Incremental in-place block-index flat save: the file it produces is
 * byte-identical to the full atomic rewrite, a crash between the payload sync
 * and the header write is rejected by the embedded verifier, and the full
 * rewrite remains the fallback (no file, or more than a quarter of the rows
 * changed). */

#include "test/test_core.h"
#include "services/block_index_loader.h"
#include "services/block_index_integrity.h"
#include "storage/sha3_sidecar_io.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "validation/accept_block_header.h"
#include "primitives/block.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern int g_block_index_flat_inplace_fault;

#define BFIP_CHECK(name, expr) do {                         \
    printf("block_index_flat_inplace: %s... ", (name));     \
    if ((expr)) printf("OK\n");                             \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

struct bfip_fixture {
    struct main_state ms;
    struct block_index *arena;
    size_t total, inserted;
};

static void bfip_hash(struct uint256 *h, size_t i)
{
    memset(h, 0, sizeof(*h));
    h->data[0] = (uint8_t)i; h->data[1] = (uint8_t)(i >> 8);
    h->data[2] = (uint8_t)(i >> 16); h->data[3] = 0xB7;
}

static bool bfip_open(struct bfip_fixture *f, size_t total)
{
    memset(f, 0, sizeof(*f));
    block_map_init(&f->ms.map_block_index);
    active_chain_init(&f->ms.chain_active);
    f->total = total;
    f->arena = calloc(total, sizeof(*f->arena)); // raw-alloc-ok:test
    if (!f->arena || !block_map_reserve(&f->ms.map_block_index, total + 16))
        return false;
    for (size_t i = 0; i < total; i++) {
        struct block_index *pi = &f->arena[i];
        block_index_init(pi);
        bfip_hash(&pi->hashBlock, i);
        pi->phashBlock = &pi->hashBlock;
        pi->pprev = i ? &f->arena[i - 1] : NULL;
        pi->nHeight = (int32_t)i; pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)i * 150; pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1; pi->nDataPos = (uint32_t)(i * 200);
    }
    return true;
}

static bool bfip_insert_to(struct bfip_fixture *f, size_t upto)
{
    for (; f->inserted < upto; f->inserted++)
        if (!block_map_insert(&f->ms.map_block_index,
                              &f->arena[f->inserted].hashBlock,
                              &f->arena[f->inserted]))
            return false;
    return true;
}

static void bfip_close(struct bfip_fixture *f)
{
    block_map_free(&f->ms.map_block_index);
    free(f->arena); // raw-alloc-ok:test
}

static bool bfip_same_bytes(const char *a, const char *b)
{
    char pa[1100], pb[1100];
    snprintf(pa, sizeof(pa), "%s/block_index.bin", a);
    snprintf(pb, sizeof(pb), "%s/block_index.bin", b);
    FILE *fa = fopen(pa, "rb"), *fb = fopen(pb, "rb");
    bool same = fa && fb;
    while (same) {
        uint8_t x[65536], y[65536];
        size_t na = fread(x, 1, sizeof(x), fa), nb = fread(y, 1, sizeof(y), fb);
        same = na == nb && memcmp(x, y, na) == 0;
        if (na == 0) break;
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return same;
}

static bool bfip_path_is(const char *want)
{
    const char *p = NULL; uint64_t bytes = 0;
    return block_index_flat_last_save_stats(&p, &bytes) && p &&
           strcmp(p, want) == 0;
}

static bool bfip_loads(const char *dir, size_t want)
{
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    block_map_init(&ms.map_block_index);
    active_chain_init(&ms.chain_active);
    bool ok = load_block_index_flat(dir, &ms).ok &&
              ms.map_block_index.size == want;
    block_map_free(&ms.map_block_index);
    return ok;
}

static void bfip_mutate(struct bfip_fixture *f)
{
    f->arena[3].nStatus |= BLOCK_FAILED_VALID;
    f->arena[900].nStatus &= ~(uint32_t)BLOCK_HAVE_DATA;
    f->arena[2500].nFile = 7;
    f->arena[1234].nDataPos += 99;
}

static int bfip_equivalence(const char *da, const char *db)
{
    int failures = 0;
    struct bfip_fixture f;
    bool ok = bfip_open(&f, 6100) && bfip_insert_to(&f, 6000);
    BFIP_CHECK("fixture built", ok);
    if (!ok) { bfip_close(&f); return failures + 1; }
    ok = save_block_index_flat_identity(da, &f.ms, NULL).ok;
    BFIP_CHECK("first save writes the file in full", ok && bfip_path_is("full"));
    ok = bfip_insert_to(&f, 6100);
    bfip_mutate(&f);
    struct block_index_flat_identity id = {0};
    ok = ok && save_block_index_flat_identity(da, &f.ms, &id).ok;
    BFIP_CHECK("second save takes the incremental path",
               ok && bfip_path_is("incremental"));
    const char *p; uint64_t bytes = 0;
    ok = block_index_flat_last_save_stats(&p, &bytes) && bytes < 40000;
    BFIP_CHECK("incremental save writes only a few KB", ok);
    ok = save_block_index_flat_identity(db, &f.ms, NULL).ok;
    BFIP_CHECK("reference save into a fresh datadir is the full rewrite",
               ok && bfip_path_is("full"));
    BFIP_CHECK("incremental file is byte-identical to the full rewrite",
               bfip_same_bytes(da, db));
    BFIP_CHECK("embedded header verifies", bii_verify_embedded(da, NULL, NULL) == 0);
    BFIP_CHECK("flat loader loads every row", bfip_loads(da, 6100));
    ok = save_block_index_flat_identity(da, &f.ms, NULL).ok;
    BFIP_CHECK("an unchanged index saves incrementally with zero row writes",
               ok && bfip_path_is("incremental") && bfip_same_bytes(da, db));
    bfip_close(&f);
    return failures;
}

static int bfip_crash_and_fallback(const char *da)
{
    int failures = 0;
    struct bfip_fixture f;
    bool ok = bfip_open(&f, 3000) && bfip_insert_to(&f, 3000) &&
              save_block_index_flat_identity(da, &f.ms, NULL).ok;
    bfip_mutate(&f);
    g_block_index_flat_inplace_fault = 1;
    bool saved = save_block_index_flat_identity(da, &f.ms, NULL).ok;
    g_block_index_flat_inplace_fault = 0;
    BFIP_CHECK("crash after payload sync, before header: save reports failure",
               ok && !saved);
    BFIP_CHECK("crash-order: verifier REJECTS the half-published file",
               bii_verify_embedded(da, NULL, NULL) != 0);
    BFIP_CHECK("crash-order: the flat loader refuses it cleanly",
               !bfip_loads(da, 3000));
    ok = save_block_index_flat_identity(da, &f.ms, NULL).ok;
    BFIP_CHECK("the next save repairs it and verifies",
               ok && bii_verify_embedded(da, NULL, NULL) == 0 &&
               bfip_loads(da, 3000));
    for (size_t i = 0; i < 1200; i++) f.arena[i].nTx = 5;
    ok = save_block_index_flat_identity(da, &f.ms, NULL).ok;
    BFIP_CHECK("more than a quarter of rows changed falls back to full",
               ok && bfip_path_is("full") &&
               bii_verify_embedded(da, NULL, NULL) == 0);
    bfip_close(&f);
    return failures;
}

/* The flat file carries no merkle root, nonce or solution: a save -> load
 * round trip yields entries without a header extension whose accessors read
 * zero, and the same identity tuple as the entries that were saved (even when
 * the saved entries carried an extension). */
static bool bfip_roundtrip_tuples_match(struct main_state *src,
                                        struct main_state *dst, size_t n)
{
    struct uint256 zero;
    memset(&zero, 0, sizeof(zero));
    for (size_t i = 0; i < n; i++) {
        struct uint256 h;
        bfip_hash(&h, i);
        struct block_index *a = block_map_find(&src->map_block_index, &h);
        struct block_index *b = block_map_find(&dst->map_block_index, &h);
        if (!a || !b || b->ext != NULL)
            return false;
        size_t len = 77;
        struct uint256 m = block_index_merkle_root(b);
        struct uint256 nn = block_index_nonce(b);
        if (block_index_solution(b, &len) != NULL || len != 0 ||
            memcmp(&m, &zero, sizeof(zero)) != 0 ||
            memcmp(&nn, &zero, sizeof(zero)) != 0)
            return false;
        if (a->nHeight != b->nHeight || a->nStatus != b->nStatus ||
            a->nFile != b->nFile || a->nDataPos != b->nDataPos ||
            a->nTime != b->nTime || a->nBits != b->nBits)
            return false;
    }
    return true;
}

static int bfip_roundtrip_no_ext(const char *dir)
{
    int failures = 0;
    enum { N = 300 };
    struct bfip_fixture f;
    static struct block_index_hdrext exts[N];
    bool ok = bfip_open(&f, N) && bfip_insert_to(&f, N);
    BFIP_CHECK("roundtrip fixture built", ok);
    if (!ok) { bfip_close(&f); return failures + 1; }
    for (size_t i = 0; i < N; i++) {
        memset(&exts[i], 0xA5, sizeof(exts[i]));
        exts[i].nSolution = NULL;
        exts[i].nSolutionSize = 0;
        f.arena[i].ext = &exts[i];
        f.arena[i].nFile = (int)(i % 5);
    }
    ok = save_block_index_flat_identity(dir, &f.ms, NULL).ok;
    BFIP_CHECK("roundtrip save", ok);
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    block_map_init(&ms.map_block_index);
    active_chain_init(&ms.chain_active);
    ok = ok && load_block_index_flat(dir, &ms).ok &&
         ms.map_block_index.size == N;
    BFIP_CHECK("roundtrip load", ok);
    ok = ok && bfip_roundtrip_tuples_match(&f.ms, &ms, N);
    BFIP_CHECK("flat-loaded entries have no extension and read zero", ok);
    block_map_free(&ms.map_block_index);
    for (size_t i = 0; i < N; i++)
        f.arena[i].ext = NULL;
    bfip_close(&f);
    return failures;
}

static void bfip_fill_header(struct block_header *h_out)
{
    struct block_header hdr;
    block_header_init(&hdr);
    hdr.nVersion = 4;
    hdr.nTime = 1700000000u;
    hdr.nBits = 0x1f07ffff;
    for (int i = 0; i < 32; i++) {
        hdr.hashMerkleRoot.data[i] = (uint8_t)(0x10 + i);
        hdr.nNonce.data[i] = (uint8_t)(0x90 + i);
    }
    hdr.nSolutionSize = 400;
    for (size_t i = 0; i < hdr.nSolutionSize; i++)
        hdr.nSolution[i] = (uint8_t)(i * 7 + 3);
    *h_out = hdr;
}

/* A live header accepted into the index carries the exact merkle root, nonce
 * and solution bytes in its extension; teardown releases them once. */
static int bfip_live_header_ext(void)
{
    int failures = 0;
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    block_map_init(&ms.map_block_index);
    active_chain_init(&ms.chain_active);

    struct block_header hdr;
    bfip_fill_header(&hdr);

    struct block_index *bi = add_to_block_index(&ms, &hdr);
    bool ok = bi != NULL && bi->ext != NULL;
    BFIP_CHECK("accepted header gets a header extension", ok);
    if (!ok) {
        block_map_free(&ms.map_block_index);
        return failures + 1;
    }
    size_t len = 0;
    const unsigned char *sol = block_index_solution(bi, &len);
    struct uint256 m = block_index_merkle_root(bi);
    struct uint256 nn = block_index_nonce(bi);
    ok = memcmp(&m, &hdr.hashMerkleRoot, sizeof(m)) == 0 &&
         memcmp(&nn, &hdr.nNonce, sizeof(nn)) == 0 &&
         sol != NULL && sol != hdr.nSolution && len == hdr.nSolutionSize &&
         memcmp(sol, hdr.nSolution, len) == 0;
    BFIP_CHECK("extension holds the exact merkle root, nonce and solution", ok);

    unsigned char other[48];
    memset(other, 0x5c, sizeof(other));
    ok = block_index_set_solution(bi, other, sizeof(other));
    sol = block_index_solution(bi, &len);
    ok = ok && sol && len == sizeof(other) && memcmp(sol, other, len) == 0;
    BFIP_CHECK("solution replacement frees the old copy and keeps the new", ok);

    block_index_hdrext_free(bi);
    block_index_hdrext_free(bi);
    m = block_index_merkle_root(bi);
    len = 9;
    struct uint256 zero;
    memset(&zero, 0, sizeof(zero));
    ok = bi->ext == NULL && block_index_solution(bi, &len) == NULL &&
         len == 0 && memcmp(&m, &zero, sizeof(zero)) == 0;
    BFIP_CHECK("teardown frees the extension once and leaves zero accessors", ok);

    block_map_free(&ms.map_block_index);
    free(bi);
    return failures;
}

int test_block_index_flat_inplace(void)
{
    int failures = 0;
    char da[PATH_MAX], db[PATH_MAX], dc[PATH_MAX], dd[PATH_MAX];
    if (!test_mkdtemp(da, sizeof(da), "bfip_a") ||
        !test_mkdtemp(db, sizeof(db), "bfip_b") ||
        !test_mkdtemp(dc, sizeof(dc), "bfip_c") ||
        !test_mkdtemp(dd, sizeof(dd), "bfip_d")) {
        printf("block_index_flat_inplace: tmpdir FAIL\n");
        return 1;
    }
    failures += bfip_equivalence(da, db);
    failures += bfip_crash_and_fallback(dc);
    failures += bfip_roundtrip_no_ext(dd);
    failures += bfip_live_header_ext();
    return failures;
}
