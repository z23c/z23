/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for the overlay SDK (engine/modules/overlay) — the shared skeleton behind the
 * on-chain OP_RETURN overlays (ZNAM/ZSLP/ZMSG/ZANC).
 *
 * Three parts:
 *   1. The pedantic codec helpers — every malformed / truncated / oversize /
 *      trailing-byte / overflow case is refused (fail-anything).
 *   2. The lokad registry + explorer-ingestion seam — register, find, dispatch,
 *      and reject duplicates/overflow/malformed tags.
 *   3. A tiny fixture overlay ("ZFIX") built entirely on the SDK in under 30
 *      lines, proving the "add an overlay" recipe end-to-end (build → parse →
 *      registry ingest → apply). */

#include "overlay/overlay_codec.h"
#include "overlay/overlay_projection.h"

#include <stdio.h>
#include <string.h>

/* ── The fixture overlay: the whole "add an overlay" recipe in <30 lines ── */

#define ZFIX_LOKAD "ZFIX"

struct zfix_msg { uint8_t kind; uint8_t payload[16]; size_t payload_len; };

static size_t zfix_build(uint8_t *out, size_t cap, uint8_t kind,
                         const uint8_t *payload, size_t plen)
{
    struct overlay_writer w;
    overlay_writer_begin(&w, out, cap, ZFIX_LOKAD);
    overlay_put_u8(&w, 1);                 /* version */
    overlay_put_u8(&w, kind);
    overlay_put_field(&w, payload, plen);
    return overlay_writer_finish(&w);
}

static bool zfix_parse(const uint8_t *s, size_t n, struct zfix_msg *m)
{
    memset(m, 0, sizeof(*m));
    struct overlay_reader r;
    if (!overlay_reader_begin(&r, s, n, ZFIX_LOKAD)) return false;
    if (!overlay_expect_u8(&r, 1)) return false;                 /* version */
    if (!overlay_read_u8(&r, &m->kind)) return false;
    if (!overlay_read_bounded(&r, m->payload, sizeof m->payload,
                              &m->payload_len)) return false;
    return overlay_reader_finish(&r);
}

/* The projection apply: re-parse with the codec, record into ctx (a real
 * overlay would INSERT OR REPLACE into its rebuildable table keyed on txid). */
struct zfix_sink { int applied; struct zfix_msg last; };

static bool zfix_apply(struct node_db *ndb, const struct transaction *tx,
                       const uint8_t *script, size_t len, int height, void *ctx)
{
    (void)ndb; (void)tx; (void)height;
    struct zfix_sink *sink = ctx;
    if (!zfix_parse(script, len, &sink->last)) return false;
    sink->applied++;
    return true;
}

/* ── Codec helper negatives ──────────────────────────────────────────── */

static bool codec_reader_open_rejects_bad_script(struct overlay_reader *r)
{
    uint8_t good[] = {0x6a, 0x01, 0x00};
    uint8_t notret[] = {0x76, 0x01, 0x00};
    return !overlay_reader_open(r, NULL, 3) &&
           !overlay_reader_open(r, good, 0) &&
           !overlay_reader_open(r, notret, sizeof notret) &&
           overlay_reader_open(r, good, sizeof good);
}

static bool codec_reader_begin_rejects_wrong_lokad(struct overlay_reader *r)
{
    uint8_t buf[32];
    size_t n = zfix_build(buf, sizeof buf, 7, (const uint8_t *)"x", 1);
    return n > 0 && overlay_reader_begin(r, buf, n, ZFIX_LOKAD) &&
           !overlay_reader_begin(r, buf, n, "ZNAM");
}

static bool codec_read_field_rejects_truncated_push(struct overlay_reader *r)
{
    /* PUSH claims 5 bytes but only 2 follow. */
    uint8_t bad[] = {0x6a, 0x04, 'Z','F','I','X', 0x05, 'a','b'};
    const uint8_t *d; size_t l;
    overlay_reader_open(r, bad, sizeof bad);
    overlay_read_field(r, &d, &l);            /* lokad ok */
    return !overlay_read_field(r, &d, &l) && !r->ok;
}

static bool codec_read_fixed_rejects_wrong_length(struct overlay_reader *r)
{
    uint8_t buf[32];
    size_t n = zfix_build(buf, sizeof buf, 7, (const uint8_t *)"ab", 2);
    overlay_reader_begin(r, buf, n, ZFIX_LOKAD);
    overlay_expect_u8(r, 1);
    uint8_t dst4[4];
    /* next field is the 1-byte kind; demanding 4 bytes must fail. */
    return !overlay_read_fixed(r, dst4, 4) && !r->ok;
}

static bool codec_expect_u8_rejects_value_mismatch(struct overlay_reader *r)
{
    uint8_t buf[32];
    size_t n = zfix_build(buf, sizeof buf, 7, NULL, 0);
    overlay_reader_begin(r, buf, n, ZFIX_LOKAD);
    return !overlay_expect_u8(r, 9) && !r->ok;   /* version is 1, not 9 */
}

static bool codec_read_bounded_rejects_oversize_field(void)
{
    uint8_t big[20]; memset(big, 'q', sizeof big);
    uint8_t buf[64];
    size_t n = zfix_build(buf, sizeof buf, 7, big, sizeof big);  /* 20 > 16 */
    struct zfix_msg m;
    return n > 0 && !zfix_parse(buf, n, &m);
}

static bool codec_reader_finish_rejects_trailing_bytes(void)
{
    uint8_t buf[32];
    size_t n = zfix_build(buf, sizeof buf, 7, (const uint8_t *)"z", 1);
    buf[n] = 0x00;                                   /* stray trailing byte */
    struct zfix_msg m;
    return !zfix_parse(buf, n + 1, &m);
}

static bool codec_writer_overflow_yields_length_zero(void)
{
    uint8_t tiny[6];                                 /* too small for ZFIX */
    struct overlay_writer w;
    overlay_writer_begin(&w, tiny, sizeof tiny, ZFIX_LOKAD);
    overlay_put_u8(&w, 1);
    overlay_put_field(&w, (const uint8_t *)"aaaaaaaa", 8);
    bool ok = overlay_writer_finish(&w) == 0;
    /* zero cap also refuses. */
    overlay_writer_begin(&w, tiny, 0, ZFIX_LOKAD);
    return ok && overlay_writer_finish(&w) == 0;
}

static bool codec_put_field_rejects_null_data(void)
{
    uint8_t buf[32];
    struct overlay_writer w;
    overlay_writer_begin(&w, buf, sizeof buf, ZFIX_LOKAD);
    return !overlay_put_field(&w, NULL, 4) &&
           overlay_writer_finish(&w) == 0;
}

static int test_codec_helpers(void)
{
    int f = 0;
    struct overlay_reader r;

    printf("overlay_reader_open: reject NULL/empty/non-OP_RETURN... ");
    {
        bool ok = codec_reader_open_rejects_bad_script(&r);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_reader_begin: reject wrong lokad... ");
    {
        bool ok = codec_reader_begin_rejects_wrong_lokad(&r);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_read_field: reject truncated push... ");
    {
        bool ok = codec_read_field_rejects_truncated_push(&r);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_read_fixed: reject wrong length... ");
    {
        bool ok = codec_read_fixed_rejects_wrong_length(&r);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_expect_u8: reject value mismatch... ");
    {
        bool ok = codec_expect_u8_rejects_value_mismatch(&r);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_read_bounded: reject oversize field... ");
    {
        bool ok = codec_read_bounded_rejects_oversize_field();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_reader_finish: reject trailing bytes... ");
    {
        bool ok = codec_reader_finish_rejects_trailing_bytes();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_writer: overflow yields length 0... ");
    {
        bool ok = codec_writer_overflow_yields_length_zero();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_put_field: reject NULL data with len>0... ");
    {
        bool ok = codec_put_field_rejects_null_data();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    return f;
}

/* ── Registry + ingest seam ──────────────────────────────────────────── */

static bool registry_identity_apply(struct node_db *ndb,
                                    const struct transaction *tx,
                                    const uint8_t *script, size_t len,
                                    int height, void *ctx)
{
    (void)ndb; (void)tx; (void)script; (void)len; (void)height; (void)ctx;
    return true;
}

static bool registry_descriptor_matches(const struct overlay_descriptor *hit,
                                        const struct overlay_descriptor *want)
{
    return hit && memcmp(hit->lokad, want->lokad, OVERLAY_LOKAD_LEN) == 0 &&
           hit->name == want->name && hit->apply == want->apply &&
           hit->ctx == want->ctx;
}

static int registry_lookup_identity(void)
{
    struct overlay_registry reg;
    char name_a[] = "A", name_b[] = "B";
    struct zfix_sink ctx_a = {0}, ctx_b = {0};
    const struct overlay_descriptor a = {
        .lokad = {'A', 'F', 'I', 'X'}, .name = name_a,
        .apply = zfix_apply, .ctx = &ctx_a,
    };
    const struct overlay_descriptor b = {
        .lokad = {'B', 'F', 'I', 'X'}, .name = name_b,
        .apply = registry_identity_apply, .ctx = &ctx_b,
    };
    overlay_registry_init(&reg);
    if (!overlay_registry_add(&reg, &a) || !overlay_registry_add(&reg, &b)) {
        printf("overlay_registry: lookup identity setup FAIL\n");
        return 1;
    }

    int failures = 0;
    const struct overlay_descriptor *hit = overlay_registry_find(&reg, "BFIX");
    if (registry_descriptor_matches(hit, &b))
        printf("overlay_registry: later hit preserves tag/name/apply/ctx OK\n");
    else {
        printf("overlay_registry: later hit preserves tag/name/apply/ctx FAIL\n");
        failures++;
    }
    if (overlay_registry_find(&reg, "CFIX") == NULL)
        printf("overlay_registry: lookup identity miss OK\n");
    else {
        printf("overlay_registry: lookup identity miss FAIL\n");
        failures++;
    }

    struct overlay_descriptor duplicate = b;
    duplicate.name = a.name;
    duplicate.apply = a.apply;
    duplicate.ctx = a.ctx;
    bool refused = !overlay_registry_add(&reg, &duplicate);
    hit = overlay_registry_find(&reg, "BFIX");
    if (refused && overlay_registry_count(&reg) == 2 &&
        registry_descriptor_matches(hit, &b) &&
        registry_descriptor_matches(overlay_registry_find(&reg, "AFIX"), &a))
        printf("overlay_registry: duplicate retains original descriptors OK\n");
    else {
        printf("overlay_registry: duplicate retains original descriptors FAIL\n");
        failures++;
    }
    return failures;
}

static bool registry_add_find_count_rejects_bad_regs(struct overlay_registry *reg,
                                                     struct zfix_sink *sink)
{
    overlay_registry_init(reg);
    struct overlay_descriptor d = {
        .name = "zfix", .apply = zfix_apply, .ctx = sink,
    };
    memcpy(d.lokad, ZFIX_LOKAD, 4);
    bool add_ok = overlay_registry_add(reg, &d);
    bool dup = !overlay_registry_add(reg, &d);             /* dup lokad */
    struct overlay_descriptor noapply = d; noapply.apply = NULL;
    memcpy(noapply.lokad, "ZNUL", 4);
    bool no_apply = !overlay_registry_add(reg, &noapply);
    struct overlay_descriptor badtag = d;
    memcpy(badtag.lokad, "ZF\0X", 4);                        /* embedded NUL */
    bool bad_tag = !overlay_registry_add(reg, &badtag);
    const struct overlay_descriptor *hit =
        overlay_registry_find(reg, ZFIX_LOKAD);
    bool miss = overlay_registry_find(reg, "ZNAM") == NULL;
    return add_ok && dup && no_apply && bad_tag && hit &&
           overlay_registry_count(reg) == 1 && miss;
}

static bool registry_padded_tags_register_embedded_reject(
    struct overlay_registry *reg, struct zfix_sink *sink)
{
    overlay_registry_init(reg);
    struct overlay_descriptor d = {
        .name = "pad", .apply = zfix_apply, .ctx = sink,
    };
    memcpy(d.lokad, "\x53\x4c\x50\x00", 4);                  /* "SLP\0" */
    bool slp_ok = overlay_registry_add(reg, &d);
    memcpy(d.lokad, "\x5a\x49\x44\x00", 4);                  /* "ZID\0" */
    bool zid_ok = overlay_registry_add(reg, &d);
    memcpy(d.lokad, "Z\0\0\0", 4);                     /* 1 char + pad */
    bool one_ok = overlay_registry_add(reg, &d);
    memcpy(d.lokad, "\0ZID", 4);                           /* leading NUL */
    bool lead_rejected = !overlay_registry_add(reg, &d);
    memcpy(d.lokad, "ZF\0X", 4);                          /* embedded NUL */
    bool mid_rejected = !overlay_registry_add(reg, &d);
    memcpy(d.lokad, "Z\0I\0", 4);                    /* NUL-then-non-NUL */
    bool gap_rejected = !overlay_registry_add(reg, &d);
    bool found = overlay_registry_find(reg, "\x53\x4c\x50\x00") != NULL &&
                 overlay_registry_find(reg, "\x5a\x49\x44\x00") != NULL;
    return slp_ok && zid_ok && one_ok && lead_rejected && mid_rejected &&
           gap_rejected && found && overlay_registry_count(reg) == 3;
}

static bool registry_rejects_overflow_past_max(struct overlay_registry *reg,
                                               struct zfix_sink *sink)
{
    overlay_registry_init(reg);
    struct overlay_descriptor d = {
        .name = "n", .apply = zfix_apply, .ctx = sink,
    };
    bool all_add = true, overflow_rejected;
    for (int i = 0; i < OVERLAY_REGISTRY_MAX; i++) {
        d.lokad[0] = 'A'; d.lokad[1] = 'A';
        d.lokad[2] = (char)('A' + i / 26);
        d.lokad[3] = (char)('A' + i % 26);
        all_add = all_add && overlay_registry_add(reg, &d);
    }
    d.lokad[0] = 'Z'; d.lokad[1] = 'Z'; d.lokad[2] = 'Z'; d.lokad[3] = 'Z';
    overflow_rejected = !overlay_registry_add(reg, &d);
    return all_add && overflow_rejected &&
           overlay_registry_count(reg) == OVERLAY_REGISTRY_MAX;
}

static bool peek_lokad_extracts_tag_refuses_malformed(void)
{
    uint8_t buf[32];
    size_t n = zfix_build(buf, sizeof buf, 3, (const uint8_t *)"p", 1);
    char tag[4];
    uint8_t notret[] = {0x76, 0x04, 'Z','F','I','X'};
    return overlay_peek_lokad(buf, n, tag) &&
           memcmp(tag, ZFIX_LOKAD, 4) == 0 &&
           !overlay_peek_lokad(notret, sizeof notret, tag) &&
           !overlay_peek_lokad(NULL, 0, tag);
}

static bool ingest_dispatches_matched_apply_skips_others(
    struct overlay_registry *reg, struct zfix_sink *sink)
{
    overlay_registry_init(reg);
    sink->applied = 0;
    struct overlay_descriptor d = {
        .name = "zfix", .apply = zfix_apply, .ctx = sink,
    };
    memcpy(d.lokad, ZFIX_LOKAD, 4);
    overlay_registry_add(reg, &d);

    uint8_t dummy_db;                       /* non-NULL ndb for the seam */
    struct node_db *ndb = (struct node_db *)&dummy_db;

    uint8_t buf[32];
    size_t n = zfix_build(buf, sizeof buf, 42, (const uint8_t *)"hi", 2);
    bool applied = overlay_ingest(reg, ndb, NULL, buf, n, 100);

    /* An unregistered lokad ("ZNAM") does not dispatch. */
    uint8_t other[] = {0x6a, 0x04, 'Z','N','A','M', 0x01, 0x00};
    bool skipped = !overlay_ingest(reg, ndb, NULL, other, sizeof other, 1);

    /* A malformed (truncated) script does not dispatch. */
    uint8_t junk[] = {0x6a, 0x04, 'Z'};
    bool junk_ok = !overlay_ingest(reg, ndb, NULL, junk, sizeof junk, 1);

    return applied && sink->applied == 1 && sink->last.kind == 42 &&
           sink->last.payload_len == 2 &&
           memcmp(sink->last.payload, "hi", 2) == 0 && skipped && junk_ok;
}

static int test_registry(void)
{
    int f = 0;
    struct overlay_registry reg;
    struct zfix_sink sink = {0};

    printf("overlay_registry: add/find/count + reject bad regs... ");
    {
        bool ok = registry_add_find_count_rejects_bad_regs(&reg, &sink);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    /* The on-chain SLP lineage spells a THREE-character tag NUL-padded to
     * four ("SLP\0", "ZID\0"), so trailing NUL padding must register. An
     * embedded NUL (leading, or NUL-then-non-NUL) must still reject. */
    printf("overlay_registry: NUL-padded tags register, embedded NUL rejects... ");
    {
        bool ok = registry_padded_tags_register_embedded_reject(&reg, &sink);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_registry: reject overflow past OVERLAY_REGISTRY_MAX... ");
    {
        bool ok = registry_rejects_overflow_past_max(&reg, &sink);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_peek_lokad: extract tag / refuse malformed... ");
    {
        bool ok = peek_lokad_extracts_tag_refuses_malformed();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    printf("overlay_ingest: dispatch matched apply, skip others... ");
    {
        bool ok = ingest_dispatches_matched_apply_skips_others(&reg, &sink);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }

    return f;
}

/* ── Fixture round-trip (the recipe works) ───────────────────────────── */

static int test_fixture_roundtrip(void)
{
    int f = 0;
    printf("zfix build+parse roundtrip via SDK... ");
    {
        uint8_t buf[64];
        size_t n = zfix_build(buf, sizeof buf, 9,
                              (const uint8_t *)"payload!", 8);
        struct zfix_msg m;
        bool ok = n > 0 && zfix_parse(buf, n, &m) && m.kind == 9 &&
                  m.payload_len == 8 && memcmp(m.payload, "payload!", 8) == 0;
        /* empty payload also round-trips. */
        n = zfix_build(buf, sizeof buf, 0, NULL, 0);
        ok = ok && zfix_parse(buf, n, &m) && m.kind == 0 && m.payload_len == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); f++; }
    }
    return f;
}

int test_overlay(void)
{
    int failures = 0;
    printf("\n=== Overlay SDK Tests ===\n");
    failures += test_codec_helpers();
    failures += test_registry();
    failures += registry_lookup_identity();
    failures += test_fixture_roundtrip();
    printf("\n%d overlay SDK test(s) failed\n", failures);
    return failures;
}
