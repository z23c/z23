/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_utxo_snapshot_loader: round-trips the sidecar format.
 *
 *   1. Synthesize a tiny in-memory sidecar (3 records).
 *   2. uss_open() with verify_full_sha3=true → must succeed and
 *      report the same header.
 *   3. uss_iter() → must visit all 3 records with matching values.
 *   4. Corrupt one byte → re-open must fail with "body sha3 mismatch".
 */

#include "test/test_core.h"
#include "chain/utxo_snapshot_loader.h"
#include "core/amount.h"
#include "crypto/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct cap_ctx {
    int n;
    int script_lens[3];
    int64_t values[3];
};

static bool cap_cb(const struct uss_record *r, void *vctx)
{
    struct cap_ctx *c = vctx;
    if (c->n >= 3) return false;
    c->script_lens[c->n] = (int)r->script_len;
    c->values[c->n] = r->value;
    c->n++;
    return true;
}

static void wle32(uint8_t *p, uint32_t v)
{ p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)(v>>16); p[3]=(uint8_t)(v>>24); }
static void wle64(uint8_t *p, uint64_t v)
{ for (int i=0;i<8;i++) p[i]=(uint8_t)(v>>(8*i)); }

static bool write_snapshot_fixture(const char *path, uint8_t header[104],
                                   const uint8_t *body, size_t body_len)
{
    struct sha3_256_ctx ctx;
    uint8_t digest[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, body, body_len);
    sha3_256_finalize(&ctx, digest);
    memcpy(header + 72, digest, sizeof(digest));
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(header, 1, 104, f) == 104 &&
              fwrite(body, 1, body_len, f) == body_len &&
              fclose(f) == 0;
    return ok;
}

/* Build the 3-record body, its SHA3, and the v1 header. `body` and `header`
 * arrive zeroed; bytes the builder does not write stay zero, including the
 * anchor block hash. */
static void uss_loader_fill_fixture(uint8_t *body, size_t *body_len,
                                    uint8_t sha3[32], uint8_t header[104])
{
    /* Build the body in a buffer. 3 records, ascending vout indices. */
    size_t off = 0;

    uint8_t txid[32];
    for (int i = 0; i < 32; i++) txid[i] = (uint8_t)i;
    uint8_t script_a[3] = { 0x76, 0xa9, 0x14 };
    uint8_t script_b[1] = { 0x6a };
    uint8_t script_c[5] = { 0x21, 0x02, 0x03, 0x04, 0x05 };

    struct rec_in { uint32_t vout; int64_t value; const uint8_t *s; uint32_t sl;
                    uint32_t height; uint8_t is_cb; };
    struct rec_in recs[3] = {
        { 0, 50000, script_a, 3, 100, 1 },
        { 1, 12345, script_b, 1, 200, 0 },
        { 2, 99999, script_c, 5, 300, 0 },
    };
    for (int i = 0; i < 3; i++) {
        memcpy(body + off, txid, 32); off += 32;
        wle32(body + off, recs[i].vout); off += 4;
        wle64(body + off, (uint64_t)recs[i].value); off += 8;
        wle32(body + off, recs[i].sl); off += 4;
        memcpy(body + off, recs[i].s, recs[i].sl); off += recs[i].sl;
        wle32(body + off, recs[i].height); off += 4;
        body[off++] = recs[i].is_cb;
    }
    *body_len = off;

    /* Hash the body. */
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, body, off);
    sha3_256_finalize(&ctx, sha3);

    /* Build header. */
    memcpy(header, "ZCLUTXO\x00", 8);
    wle32(header + 8, 1);
    wle32(header + 16, 12345);
    wle64(header + 24, 3);
    wle64(header + 32, (uint64_t)(50000 + 12345 + 99999));
    /* anchor block hash: leave zero */
    memcpy(header + 72, sha3, 32);
}

/* Returns 1 when the temp file cannot be opened. */
static int uss_loader_write_tmp(const char *tmp, const uint8_t header[104],
                                const uint8_t *body, size_t body_len)
{
    FILE *f = fopen(tmp, "wb");
    if (!f) {
        printf("uss: tmp open FAIL\n");
        return 1;
    }
    fwrite(header, 1, 104, f);
    fwrite(body, 1, body_len, f);
    fclose(f);
    return 0;
}

/* Open and verify. Returns -1 when open fails (caller cleans up), otherwise
 * the number of header mismatches. Prints OK even after a mismatch. */
static int uss_loader_check_open(const char *tmp, struct uss_handle **out)
{
    /* Open and verify. */
    printf("uss: open+verify... ");
    char err[128] = {0};
    struct uss_header hdr;
    struct uss_handle *h = uss_open(tmp, true, NULL, &hdr,
                                    err, sizeof(err));
    if (!h) { printf("FAIL (%s)\n", err); return -1; }
    int failures = 0;
    if (hdr.count != 3) { printf("FAIL (count=%llu)\n",
        (unsigned long long)hdr.count); failures++; }
    if (hdr.total_supply != 50000 + 12345 + 99999) {
        printf("FAIL (supply=%lld)\n", (long long)hdr.total_supply);
        failures++;
    }
    printf("OK\n");
    *out = h;
    return failures;
}

/* Iterate. */
static int uss_loader_check_iter(struct uss_handle *h)
{
    /* Iterate. */
    printf("uss: iter... ");
    struct cap_ctx cap = {0};
    int64_t n = uss_iter(h, cap_cb, &cap);
    if (n != 3 || cap.n != 3) { printf("FAIL (n=%lld)\n",
        (long long)n); return 1; }
    else if (cap.values[0] != 50000 ||
             cap.values[1] != 12345 ||
             cap.values[2] != 99999 ||
             cap.script_lens[0] != 3 ||
             cap.script_lens[1] != 1 ||
             cap.script_lens[2] != 5) {
        printf("FAIL (record content mismatch)\n");
        return 1;
    }
    else printf("OK\n");
    return 0;
}

static int uss_loader_check_component(struct uss_handle *h,
                                      const uint8_t sha3[32])
{
    printf("uss: independent UTXO component... ");
    struct uss_utxo_component component;
    char component_err[128] = {0};
    if (!uss_utxo_component_compute(h, &component, component_err,
                                    sizeof(component_err)) ||
        component.count != 3 ||
        component.total_supply != 50000 + 12345 + 99999 ||
        memcmp(component.sha3_hash, sha3, 32) != 0) {
        printf("FAIL (%s)\n", component_err);
        return 1;
    } else {
        printf("OK\n");
    }
    return 0;
}

static void uss_fill_v2_frontier(uint8_t *frontier, int n)
{
    for (int i = 0; i < n; i++)
        frontier[i] = (uint8_t)(0xA0 + (i & 0x1f));
}

static bool uss_v2_frontier_ok(struct uss_handle *hv,
                               const uint8_t *frontier, uint32_t flen)
{
    const uint8_t *gotb = NULL;
    uint32_t gotl = 0;
    bool version_ok = uss_version(hv) == 2;
    bool got = version_ok && uss_frontier(hv, &gotb, &gotl);
    return got && gotb && gotl == flen && memcmp(gotb, frontier, flen) == 0;
}

static bool uss_v2_iter_and_component_ok(struct uss_handle *hv,
                                         const uint8_t sha3[32],
                                         const uint8_t v2sha3[32],
                                         char *e2, size_t e2_len)
{
    struct cap_ctx cap2 = {0};
    bool iter_ok = uss_iter(hv, cap_cb, &cap2) == 3 && cap2.n == 3;
    struct uss_utxo_component v2_component;
    memset(&v2_component, 0, sizeof(v2_component));
    bool computed = iter_ok &&
        uss_utxo_component_compute(hv, &v2_component, e2, e2_len);
    /* Full v2 payload includes the frontier and must not be confused with
     * the independently recomputed transparent checkpoint. */
    return computed &&
           v2_component.count == 3 &&
           v2_component.total_supply == 50000 + 12345 + 99999 &&
           memcmp(v2_component.sha3_hash, sha3, 32) == 0 &&
           memcmp(v2sha3, v2_component.sha3_hash, 32) != 0;
}

static bool uss_v1_has_no_frontier(struct uss_handle *hv1)
{
    const uint8_t *nb = (const uint8_t *)1; uint32_t nl = 1;
    bool version_ok = uss_version(hv1) == 1;
    bool no_front = version_ok && !uss_frontier(hv1, &nb, &nl);
    return no_front && nb == NULL && nl == 0;
}

static int uss_loader_check_v2(const char *ussdir, const char *tmp,
                               const uint8_t *body, size_t body_len,
                               const uint8_t sha3[32])
{
    /* ── v2 round-trip: records + embedded Sapling frontier section ──
     * Append [u32 frontier_len][blob] after the records (inside the body SHA3),
     * stamp version 2, and confirm uss_version()==2 + uss_frontier() returns the
     * exact blob, that records still iterate, and that the v1 file (still valid
     * here) reports version 1 + NO frontier. Run BEFORE the corruption test
     * below so `tmp` is uncorrupted. */
    printf("uss: v2 frontier round-trip... ");
    uint8_t frontier[71];
    uss_fill_v2_frontier(frontier, (int)sizeof(frontier));
    uint32_t flen = (uint32_t)sizeof(frontier);

    /* Body = the 3 records + [u32 len][blob]. */
    uint8_t v2body[4096];
    size_t v2off = 0;
    memcpy(v2body, body, body_len); v2off = body_len;
    wle32(v2body + v2off, flen); v2off += 4;
    memcpy(v2body + v2off, frontier, flen); v2off += flen;

    uint8_t v2sha3[32];
    struct sha3_256_ctx c2;
    sha3_256_init(&c2);
    sha3_256_write(&c2, v2body, v2off);
    sha3_256_finalize(&c2, v2sha3);

    uint8_t v2hdr[104] = {0};
    memcpy(v2hdr, "ZCLUTXO\x00", 8);
    wle32(v2hdr + 8, 2);                 /* version 2 */
    wle32(v2hdr + 16, 12345);
    wle64(v2hdr + 24, 3);
    wle64(v2hdr + 32, (uint64_t)(50000 + 12345 + 99999));
    memcpy(v2hdr + 72, v2sha3, 32);

    char tmp2buf[600];
    snprintf(tmp2buf, sizeof(tmp2buf), "%s/uss_v2.dat", ussdir);
    const char *tmp2 = tmp2buf;
    FILE *fv = fopen(tmp2, "wb");
    bool ok = (fv != NULL);
    if (fv) {
        fwrite(v2hdr, 1, 104, fv);
        fwrite(v2body, 1, v2off, fv);
        fclose(fv);
    }

    char e2[128] = {0};
    struct uss_handle *hv = ok
        ? uss_open(tmp2, true, NULL, NULL, e2, sizeof(e2)) : NULL;
    ok = ok && hv != NULL;
    ok = ok && uss_v2_frontier_ok(hv, frontier, flen);
    ok = ok && uss_v2_iter_and_component_ok(hv, sha3, v2sha3, e2, sizeof(e2));
    if (hv) uss_close(hv);

    /* v1 file (uncorrupted here) => version 1, no frontier. */
    struct uss_handle *hv1 = uss_open(tmp, true, NULL, NULL, e2, sizeof(e2));
    if (hv1) {
        ok = ok && uss_v1_has_no_frontier(hv1);
        uss_close(hv1);
    } else {
        ok = false;
    }
    unlink(tmp2);
    if (ok) printf("OK\n"); else { printf("FAIL (e=%s)\n", e2); return 1; }
    return 0;
}

enum uss_bad_kind {
    USS_BAD_TRAILING,
    USS_BAD_RESERVED,
    USS_BAD_SUPPLY,
    USS_BAD_ORDER,
    USS_BAD_COINBASE,
    USS_BAD_MONEY
};

struct uss_bad_spec {
    enum uss_bad_kind kind;
    const char *expect;
    int open_must_fail;
};

static const struct uss_bad_spec uss_bad_specs[] = {
    { USS_BAD_TRAILING, "v1 trailing payload bytes", 1 },
    { USS_BAD_RESERVED, "nonzero reserved header bytes", 1 },
    { USS_BAD_SUPPLY, "UTXO supply mismatch", 0 },
    { USS_BAD_ORDER, "UTXO order", 0 },
    { USS_BAD_COINBASE, "coinbase", 0 },
    { USS_BAD_MONEY, "MoneyRange", 0 },
};

/* Apply one legacy-layout mutation. `*payload` / `*payload_len` select the
 * bytes written after the header copy the caller just made. */
static void uss_mutate_bad_snapshot(enum uss_bad_kind kind, uint8_t bh[104],
                                    uint8_t *bb, const uint8_t *body,
                                    size_t body_len, const uint8_t **payload,
                                    size_t *payload_len)
{
    switch (kind) {
    case USS_BAD_TRAILING:
        memcpy(bb, body, body_len);
        bb[body_len] = 0x42;
        *payload = bb;
        *payload_len = body_len + 1;
        break;
    case USS_BAD_RESERVED:
        bh[12] = 1;
        *payload = body;
        *payload_len = body_len;
        break;
    case USS_BAD_SUPPLY:
        wle64(bh + 32, (uint64_t)(50000 + 12345 + 99999 + 1));
        *payload = body;
        *payload_len = body_len;
        break;
    case USS_BAD_ORDER:
        memcpy(bb, body, body_len);
        wle32(bb + 32, 2); /* first key now collides with/out-orders vout=2 */
        *payload = bb;
        *payload_len = body_len;
        break;
    case USS_BAD_COINBASE:
        memcpy(bb, body, body_len);
        bb[55] = 2; /* first record's is_coinbase byte */
        *payload = bb;
        *payload_len = body_len;
        break;
    case USS_BAD_MONEY:
        memcpy(bb, body, body_len);
        wle64(bb + 36, (uint64_t)MAX_MONEY + 1u);
        wle64(bh + 32, (uint64_t)MAX_MONEY + 1u + 12345u + 99999u);
        *payload = bb;
        *payload_len = body_len;
        break;
    }
}

/* Write `payload`, reopen it, and require the rejection this spec names.
 * `be` is cleared after the write and before the open, including when `ok`
 * is already false, so a later spec wipes an earlier error string. */
static bool uss_probe_bad_snapshot(bool ok, const char *path, uint8_t bh[104],
                                   const uint8_t *payload, size_t payload_len,
                                   char *be, size_t be_len,
                                   const char *expect, int open_must_fail)
{
    ok = ok && write_snapshot_fixture(path, bh, payload, payload_len);
    memset(be, 0, be_len);
    struct uss_handle *bad_h = ok ?
        uss_open(path, true, NULL, NULL, be, be_len) : NULL;
    if (open_must_fail)
        ok = ok && !bad_h && strcmp(be, expect) == 0;
    else {
        struct uss_utxo_component bad_component;
        ok = ok && bad_h &&
             !uss_utxo_component_compute(bad_h, &bad_component,
                                         be, be_len) &&
             strstr(be, expect) != NULL;
    }
    if (bad_h) uss_close(bad_h);
    return ok;
}

static int uss_loader_check_bad_layouts(const char *ussdir,
                                        const uint8_t header[104],
                                        const uint8_t *body, size_t body_len)
{
    /* A valid body digest must not authorize an ambiguous legacy layout. */
    printf("uss: exact legacy layout + canonical records... ");
    bool ok = true;
    char badbuf[600];
    snprintf(badbuf, sizeof(badbuf), "%s/uss_bad_layout.dat", ussdir);
    const char *bad = badbuf;
    uint8_t bh[104];
    uint8_t bb[4097];
    char be[128] = {0};

    for (int i = 0; i < (int)(sizeof uss_bad_specs / sizeof uss_bad_specs[0]);
         i++) {
        memcpy(bh, header, sizeof(bh));
        const uint8_t *payload = body;
        size_t payload_len = body_len;
        uss_mutate_bad_snapshot(uss_bad_specs[i].kind, bh, bb, body, body_len,
                                &payload, &payload_len);
        ok = uss_probe_bad_snapshot(ok, bad, bh, payload, payload_len,
                                    be, sizeof(be), uss_bad_specs[i].expect,
                                    uss_bad_specs[i].open_must_fail);
    }
    unlink(bad);
    if (ok) printf("OK\n");
    else { printf("FAIL (%s)\n", be); return 1; }
    return 0;
}

/* Corruption detection. Returns -1 when the file cannot be reopened. */
static int uss_loader_check_corruption(const char *tmp)
{
    /* Corruption detection. */
    printf("uss: corruption detection... ");
    FILE *f2 = fopen(tmp, "rb+");
    if (!f2) { printf("FAIL (reopen)\n"); return -1; }
    fseek(f2, 200, SEEK_SET); /* somewhere in the body */
    uint8_t orig;
 TEST_DISCARD(fread(&orig, 1, 1, f2));
    fseek(f2, 200, SEEK_SET);
    uint8_t flipped = orig ^ 0xff;
    fwrite(&flipped, 1, 1, f2);
    fclose(f2);

    char err[128] = {0};
    err[0] = '\0';
    struct uss_handle *h = uss_open(tmp, true, NULL, NULL, err, sizeof(err));
    if (h) {
        printf("FAIL (open succeeded on corrupted file)\n");
        uss_close(h);
        return 1;
    } else if (strcmp(err, "body sha3 mismatch") != 0) {
        printf("FAIL (wrong err: %s)\n", err);
        return 1;
    } else {
        printf("OK\n");
    }
    return 0;
}

/* ── Pinned branches of uss_open(), uss_layout_exact() and
 * uss_component_record(). Every row reaches its branch through a public
 * call; the static helpers are never copied here. Rows are sealed with the
 * body SHA3 unless the row exists to test the digest itself. ── */

#define USS_PIN_BYTES  1024
#define USS_PIN_HDR    104
#define USS_PIN_PATHMAX 1024

struct uss_pin_file {
    uint8_t bytes[USS_PIN_BYTES];
    size_t  len;
    bool    overflow;
};

static void uss_pin_begin(struct uss_pin_file *f, uint32_t version,
                          uint32_t height, uint64_t count, int64_t supply)
{
    memset(f, 0, sizeof(*f));
    memcpy(f->bytes, "ZCLUTXO\x00", 8);
    wle32(f->bytes + 8, version);
    wle32(f->bytes + 16, height);
    wle64(f->bytes + 24, count);
    wle64(f->bytes + 32, (uint64_t)supply);
    f->len = USS_PIN_HDR;
}

static void uss_pin_put(struct uss_pin_file *f, const void *src, size_t n)
{
    if (n > sizeof(f->bytes) - f->len) {
        f->overflow = true;
        return;
    }
    memcpy(f->bytes + f->len, src, n);
    f->len += n;
}

static void uss_pin_fill(struct uss_pin_file *f, uint8_t byte, size_t n)
{
    uint8_t buf[USS_PIN_BYTES];
    if (n > sizeof(buf)) {
        f->overflow = true;
        return;
    }
    memset(buf, byte, n);
    uss_pin_put(f, buf, n);
}

static void uss_pin_u32(struct uss_pin_file *f, uint32_t v)
{
    uint8_t b[4];
    wle32(b, v);
    uss_pin_put(f, b, sizeof(b));
}

static void uss_pin_u64(struct uss_pin_file *f, uint64_t v)
{
    uint8_t b[8];
    wle64(b, v);
    uss_pin_put(f, b, sizeof(b));
}

/* The first 48 bytes of a record: txid, vout, value, script_len. */
static void uss_pin_record_head(struct uss_pin_file *f, uint8_t txid_fill,
                                uint32_t vout, int64_t value,
                                uint32_t script_len)
{
    uss_pin_fill(f, txid_fill, 32);
    uss_pin_u32(f, vout);
    uss_pin_u64(f, (uint64_t)value);
    uss_pin_u32(f, script_len);
}

/* A complete canonical record; the script is script_len bytes of 0x51. */
static void uss_pin_record(struct uss_pin_file *f, uint8_t txid_fill,
                           uint32_t vout, int64_t value, uint32_t script_len,
                           uint32_t height, uint8_t is_cb)
{
    uss_pin_record_head(f, txid_fill, vout, value, script_len);
    uss_pin_fill(f, 0x51, script_len);
    uss_pin_u32(f, height);
    uss_pin_fill(f, is_cb, 1);
}

/* Stamp header bytes 72..103 with the SHA3 of the body. */
static void uss_pin_seal(struct uss_pin_file *f)
{
    struct sha3_256_ctx ctx;
    uint8_t digest[32];
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, f->bytes + USS_PIN_HDR, f->len - USS_PIN_HDR);
    sha3_256_finalize(&ctx, digest);
    memcpy(f->bytes + 72, digest, sizeof(digest));
}

static bool uss_pin_write_raw(const char *path, const uint8_t *bytes,
                              size_t len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp)
        return false;
    bool ok = fwrite(bytes, 1, len, fp) == len;
    return fclose(fp) == 0 && ok;
}

/* Expect uss_open() to refuse the bytes with exactly `expect`. */
static int uss_pin_reject_raw(const char *path, const uint8_t *bytes,
                              size_t len, bool verify,
                              const uint8_t *expect_sha3, const char *expect)
{
    if (!uss_pin_write_raw(path, bytes, len)) {
        printf("uss pin: fixture write FAIL\n");
        return 1;
    }
    char err[160] = {0};
    struct uss_handle *h = uss_open(path, verify, expect_sha3, NULL,
                                    err, sizeof(err));
    if (h) {
        uss_close(h);
        printf("uss pin: opened, wanted '%s'\n", expect);
        return 1;
    }
    if (strcmp(err, expect) != 0) {
        printf("uss pin: got '%s', wanted '%s'\n", err, expect);
        return 1;
    }
    return 0;
}

/* Expect uss_open() to accept the bytes; optionally return the header. */
static int uss_pin_accept_raw(const char *path, const uint8_t *bytes,
                              size_t len, bool verify,
                              const uint8_t *expect_sha3,
                              struct uss_header *hdr)
{
    if (!uss_pin_write_raw(path, bytes, len)) {
        printf("uss pin: fixture write FAIL\n");
        return 1;
    }
    char err[160] = {0};
    struct uss_handle *h = uss_open(path, verify, expect_sha3, hdr,
                                    err, sizeof(err));
    if (!h) {
        printf("uss pin: open FAIL (%s)\n", err);
        return 1;
    }
    uss_close(h);
    return 0;
}

static int uss_pin_reject(const char *path, const struct uss_pin_file *f,
                          const char *expect)
{
    if (f->overflow) {
        printf("uss pin: fixture overflow\n");
        return 1;
    }
    return uss_pin_reject_raw(path, f->bytes, f->len, false, NULL, expect);
}

static int uss_pin_accept(const char *path, const struct uss_pin_file *f,
                          struct uss_header *hdr)
{
    if (f->overflow) {
        printf("uss pin: fixture overflow\n");
        return 1;
    }
    return uss_pin_accept_raw(path, f->bytes, f->len, false, NULL, hdr);
}

static int uss_pin_check_open_rows(const char *ussdir, const char *pin)
{
    int fail = 0;
    char err[160] = {0};
    struct uss_handle *h = uss_open(NULL, false, NULL, NULL,
                                    err, sizeof(err));
    if (h) {
        uss_close(h);
        fail++;
    }
    if (strcmp(err, "null path") != 0) {
        printf("uss pin: null path got '%s'\n", err);
        fail++;
    }

    char missing[USS_PIN_PATHMAX];
    char want[USS_PIN_PATHMAX + 16];
    snprintf(missing, sizeof(missing), "%s/uss_pin_missing.dat", ussdir);
    snprintf(want, sizeof(want), "open(%s): ", missing);
    memset(err, 0, sizeof(err));
    h = uss_open(missing, false, NULL, NULL, err, sizeof(err));
    if (h) {
        uss_close(h);
        fail++;
    }
    if (strncmp(err, want, strlen(want)) != 0) {
        printf("uss pin: missing file got '%s'\n", err);
        fail++;
    }

    uint8_t small[103];
    memset(small, 0, sizeof(small));
    memcpy(small, "ZCLUTXO\x00", 8);
    fail += uss_pin_reject_raw(pin, small, sizeof(small), false, NULL,
                               "too small or metadata failed");

    struct uss_pin_file f;
    uss_pin_begin(&f, 1, 0, 0, 0);
    f.bytes[7] = 'X';
    fail += uss_pin_reject(pin, &f, "bad magic");

    uss_pin_begin(&f, 0, 0, 0, 0);
    fail += uss_pin_reject(pin, &f, "bad version 0");
    uss_pin_begin(&f, 4, 0, 0, 0);
    fail += uss_pin_reject(pin, &f, "bad version 4");

    uss_pin_begin(&f, 1, 0, 0, 0);
    f.bytes[20] = 1;
    fail += uss_pin_reject(pin, &f, "nonzero reserved header bytes");

    uss_pin_begin(&f, 1, 0, 0, -1);
    fail += uss_pin_reject(pin, &f, "negative header supply");
    return fail;
}

static int uss_pin_check_header_fields(const char *pin)
{
    struct uss_pin_file f;
    uss_pin_begin(&f, 1, 7, 0, 0);
    memset(f.bytes + 40, 0x5a, 32);
    uss_pin_seal(&f);

    struct uss_header hdr;
    memset(&hdr, 0, sizeof(hdr));
    int fail = uss_pin_accept(pin, &f, &hdr);
    uint8_t anchor[32];
    memset(anchor, 0x5a, sizeof(anchor));
    if (hdr.version != 1 || hdr.height != 7 || hdr.count != 0 ||
        hdr.total_supply != 0 ||
        memcmp(hdr.anchor_block_hash, anchor, 32) != 0 ||
        memcmp(hdr.sha3_hash, f.bytes + 72, 32) != 0) {
        printf("uss pin: header fields not copied to hdr_out\n");
        fail++;
    }
    return fail;
}

static int uss_pin_check_expected_sha(const char *pin)
{
    struct uss_pin_file f;
    uss_pin_begin(&f, 1, 0, 0, 0);
    uss_pin_seal(&f);
    uint8_t want[32];
    uint8_t zero[32] = {0};
    memcpy(want, f.bytes + 72, sizeof(want));
    int fail = uss_pin_reject_raw(pin, f.bytes, f.len, false, zero,
                                  "expected sha3 mismatch");
    fail += uss_pin_accept_raw(pin, f.bytes, f.len, false, want, NULL);
    fail += uss_pin_accept_raw(pin, f.bytes, f.len, true, want, NULL);
    return fail;
}

/* verify_full_sha3 = false skips the body digest; = true enforces it. */
static int uss_pin_check_verify_flag(const char *pin)
{
    struct uss_pin_file f;
    uss_pin_begin(&f, 1, 100, 1, 50000);
    uss_pin_record(&f, 0x01, 0, 50000, 3, 100, 0);
    uss_pin_seal(&f);
    int fail = uss_pin_accept_raw(pin, f.bytes, f.len, false, NULL, NULL);
    f.bytes[USS_PIN_HDR + 5] ^= 0xff; /* txid byte: layout still exact */
    fail += uss_pin_accept_raw(pin, f.bytes, f.len, false, NULL, NULL);
    fail += uss_pin_reject_raw(pin, f.bytes, f.len, true, NULL,
                               "body sha3 mismatch");
    return fail;
}

/* uss_layout_exact() for versions 1 and 2. */
static int uss_pin_check_layout_legacy(const char *pin)
{
    struct uss_pin_file f;
    int fail = 0;

    uss_pin_begin(&f, 1, 0, 1, 0);
    fail += uss_pin_reject(pin, &f, "truncated UTXO record 0");

    uss_pin_begin(&f, 1, 0, 1, 0);
    uss_pin_fill(&f, 0x00, 47);
    fail += uss_pin_reject(pin, &f, "truncated UTXO record 0");

    uss_pin_begin(&f, 1, 0, 1, 0);
    uss_pin_record_head(&f, 0x01, 0, 1, 3);
    fail += uss_pin_reject(pin, &f, "truncated UTXO script 0");

    uss_pin_begin(&f, 1, 0, 2, 0);
    uss_pin_record(&f, 0x01, 0, 0, 0, 0, 0);
    fail += uss_pin_reject(pin, &f, "truncated UTXO record 1");

    uss_pin_begin(&f, 1, 0, 0, 0);
    uss_pin_fill(&f, 0x00, 1);
    fail += uss_pin_reject(pin, &f, "v1 trailing payload bytes");

    uss_pin_begin(&f, 1, 0, 0, 0);
    fail += uss_pin_accept(pin, &f, NULL);

    uss_pin_begin(&f, 2, 0, 0, 0);
    fail += uss_pin_reject(pin, &f, "missing Sapling section length");

    uss_pin_begin(&f, 2, 0, 0, 0);
    uss_pin_fill(&f, 0x00, 3);
    fail += uss_pin_reject(pin, &f, "missing Sapling section length");

    uss_pin_begin(&f, 2, 0, 0, 0);
    uss_pin_u32(&f, 10);
    uss_pin_fill(&f, 0x00, 2);
    fail += uss_pin_reject(pin, &f, "truncated Sapling section");

    uss_pin_begin(&f, 2, 0, 0, 0);
    uss_pin_u32(&f, 0);
    fail += uss_pin_reject(pin, &f, "empty v2 Sapling section");

    uss_pin_begin(&f, 2, 0, 0, 0);
    uss_pin_u32(&f, 5);
    uss_pin_fill(&f, 0x11, 5);
    uss_pin_fill(&f, 0x00, 1);
    fail += uss_pin_reject(pin, &f, "v2 trailing payload bytes");

    uss_pin_begin(&f, 2, 0, 0, 0);
    uss_pin_u32(&f, 5);
    uss_pin_fill(&f, 0x11, 5);
    fail += uss_pin_accept(pin, &f, NULL);
    return fail;
}

/* uss_layout_exact() for version 3: Sapling, Sprout and nullifier sections. */
static int uss_pin_check_layout_v3(const char *pin)
{
    struct uss_pin_file f;
    int fail = 0;

    uss_pin_begin(&f, 3, 0, 0, 0);
    fail += uss_pin_reject(pin, &f, "missing Sapling section length");

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 10);
    uss_pin_fill(&f, 0x00, 2);
    fail += uss_pin_reject(pin, &f, "truncated Sapling section");

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 0);
    fail += uss_pin_reject(pin, &f, "missing Sprout section length");

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u32(&f, 10);
    uss_pin_fill(&f, 0x00, 2);
    fail += uss_pin_reject(pin, &f, "truncated Sprout section");

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u32(&f, 0);
    fail += uss_pin_reject(pin, &f, "missing nullifier count");

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u64(&f, UINT64_MAX);
    fail += uss_pin_reject(pin, &f, "nullifier count overflow");

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u64(&f, 1);
    uss_pin_fill(&f, 0x00, 40);
    fail += uss_pin_reject(pin, &f, "truncated nullifier section");

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u64(&f, 0);
    uss_pin_fill(&f, 0x00, 1);
    fail += uss_pin_reject(pin, &f, "v3 trailing payload bytes");

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u64(&f, 0);
    fail += uss_pin_accept(pin, &f, NULL);

    uss_pin_begin(&f, 3, 0, 0, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u32(&f, 0);
    uss_pin_u64(&f, 1);
    uss_pin_fill(&f, 0x00, 41);
    fail += uss_pin_accept(pin, &f, NULL);
    return fail;
}

/* Seal, write, and run uss_utxo_component_compute() on the opened file.
 * Returns true when the component pass succeeds; `cerr` gets the reason. */
static bool uss_pin_component_run(const char *pin, struct uss_pin_file *f,
                                  struct uss_utxo_component *comp,
                                  char *cerr, size_t cerr_sz)
{
    uss_pin_seal(f);
    if (!uss_pin_write_raw(pin, f->bytes, f->len)) {
        snprintf(cerr, cerr_sz, "fixture write");
        return false;
    }
    char err[160] = {0};
    struct uss_handle *h = uss_open(pin, true, NULL, NULL, err, sizeof(err));
    if (!h) {
        snprintf(cerr, cerr_sz, "open: %s", err);
        return false;
    }
    bool ok = uss_utxo_component_compute(h, comp, cerr, cerr_sz);
    uss_close(h);
    return ok;
}

static int uss_pin_component_reject(const char *pin, struct uss_pin_file *f,
                                    const char *expect)
{
    struct uss_utxo_component comp;
    char cerr[160] = {0};
    if (uss_pin_component_run(pin, f, &comp, cerr, sizeof(cerr))) {
        printf("uss pin: component accepted, wanted '%s'\n", expect);
        return 1;
    }
    if (strcmp(cerr, expect) != 0) {
        printf("uss pin: component got '%s', wanted '%s'\n", cerr, expect);
        return 1;
    }
    return 0;
}

static int uss_pin_component_accept(const char *pin, struct uss_pin_file *f,
                                    uint64_t count, int64_t supply)
{
    struct uss_utxo_component comp;
    char cerr[160] = {0};
    if (!uss_pin_component_run(pin, f, &comp, cerr, sizeof(cerr))) {
        printf("uss pin: component FAIL (%s)\n", cerr);
        return 1;
    }
    if (comp.count != count || comp.total_supply != supply) {
        printf("uss pin: component count/supply mismatch\n");
        return 1;
    }
    return 0;
}

/* uss_component_record() refusals, reached through the component pass. */
static int uss_pin_check_component_reject(const char *pin)
{
    struct uss_pin_file f;
    int fail = 0;

    uss_pin_begin(&f, 1, 0, 1, 50000);
    uss_pin_record(&f, 0x01, 0, 50000, 3, 100, 0);
    fail += uss_pin_component_reject(pin, &f,
                                     "UTXO height above snapshot");

    uss_pin_begin(&f, 1, 100, 1, 0);
    uss_pin_record(&f, 0x01, 0, -1, 0, 100, 0);
    fail += uss_pin_component_reject(pin, &f,
                                     "UTXO value outside MoneyRange");

    uss_pin_begin(&f, 1, 100, 1, 50000);
    uss_pin_record(&f, 0x01, 0, 50000, 3, 100, 2);
    fail += uss_pin_component_reject(pin, &f,
                                     "non-canonical coinbase flag");

    uss_pin_begin(&f, 1, 100, 2, 100000);
    uss_pin_record(&f, 0x01, 1, 50000, 0, 100, 0);
    uss_pin_record(&f, 0x01, 1, 50000, 0, 100, 0);
    fail += uss_pin_component_reject(pin, &f,
                                     "non-canonical or duplicate UTXO order");

    uss_pin_begin(&f, 1, 100, 2, 100000);
    uss_pin_record(&f, 0xff, 0, 50000, 0, 100, 0);
    uss_pin_record(&f, 0x00, 0, 50000, 0, 100, 0);
    fail += uss_pin_component_reject(pin, &f,
                                     "non-canonical or duplicate UTXO order");

    uss_pin_begin(&f, 1, 0, 2, 2 * (int64_t)MAX_MONEY);
    uss_pin_record(&f, 0x01, 0, MAX_MONEY, 0, 0, 0);
    uss_pin_record(&f, 0x01, 1, MAX_MONEY, 0, 0, 0);
    fail += uss_pin_component_reject(pin, &f,
                                     "UTXO supply outside MoneyRange");
    return fail;
}

/* uss_component_record() accepting boundary and ascending-txid records. */
static int uss_pin_check_component_accept(const char *pin)
{
    struct uss_pin_file f;
    int fail = 0;

    uss_pin_begin(&f, 1, 100, 1, MAX_MONEY);
    uss_pin_record(&f, 0x01, 0, MAX_MONEY, 0, 100, 0);
    fail += uss_pin_component_accept(pin, &f, 1, MAX_MONEY);

    uss_pin_begin(&f, 1, 100, 2, 100000);
    uss_pin_record(&f, 0x00, 5, 50000, 3, 100, 0);
    uss_pin_record(&f, 0x01, 0, 50000, 0, 100, 0);
    fail += uss_pin_component_accept(pin, &f, 2, 100000);
    return fail;
}

static int uss_pin_check_all(const char *ussdir)
{
    char pin[USS_PIN_PATHMAX];
    snprintf(pin, sizeof(pin), "%s/uss_pin.dat", ussdir);
    printf("uss: uss_open / layout / component branch pins... ");
    int fail = uss_pin_check_open_rows(ussdir, pin) +
               uss_pin_check_header_fields(pin) +
               uss_pin_check_expected_sha(pin) +
               uss_pin_check_verify_flag(pin) +
               uss_pin_check_layout_legacy(pin) +
               uss_pin_check_layout_v3(pin) +
               uss_pin_check_component_reject(pin) +
               uss_pin_check_component_accept(pin);
    unlink(pin);
    if (fail) {
        printf("FAIL (%d rows)\n", fail);
        return 1;
    }
    printf("OK\n");
    return 0;
}

int test_utxo_snapshot_loader(void)
{
    int failures = 0;

    uint8_t body[4096] = {0};
    size_t body_len = 0;
    uint8_t sha3[32];
    uint8_t header[104] = {0};
    uss_loader_fill_fixture(body, &body_len, sha3, header);

    /* Write to a tmp file. Per-process: these fixtures were fixed /tmp paths,
     * so two concurrent copies of the suite would truncate and rewrite each
     * other's snapshot file mid-read. */
    char ussdir[512], tmpbuf[600];
    test_make_tmpdir(ussdir, sizeof(ussdir), "uss", "loader");
    snprintf(tmpbuf, sizeof(tmpbuf), "%s/uss.dat", ussdir);
    const char *tmp = tmpbuf;
    if (uss_loader_write_tmp(tmp, header, body, body_len)) {
        test_rm_rf(ussdir);
        return 1;
    }

    struct uss_handle *h = NULL;
    int open_rc = uss_loader_check_open(tmp, &h);
    if (open_rc < 0) { failures++; goto cleanup; }
    failures += open_rc;

    failures += uss_loader_check_iter(h);
    failures += uss_loader_check_component(h, sha3);
    uss_close(h);

    failures += uss_loader_check_v2(ussdir, tmp, body, body_len, sha3);
    failures += uss_loader_check_bad_layouts(ussdir, header, body, body_len);

    int corr_rc = uss_loader_check_corruption(tmp);
    if (corr_rc < 0) { failures++; goto cleanup; }
    failures += corr_rc;

    failures += uss_pin_check_all(ussdir);

cleanup:
    unlink(tmp);
    test_rm_rf(ussdir);
    return failures;
}
