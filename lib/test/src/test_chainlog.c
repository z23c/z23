/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_chainlog — the lib/chainlog gate.
 *
 * The module exists to make one claim: nothing in this file's history can be
 * changed without the change showing. A test that only appends and reads back
 * proves none of that, so most of what is here corrupts a log on purpose and
 * requires the right refusal, by name and by sequence number.
 *
 *  1. A RESTART IS INVISIBLE TO THE CHAIN. Five records written in one
 *     session and five written across five open/close cycles produce the
 *     same head. If they did not, a node's history would depend on when it
 *     was restarted and no two nodes could ever agree.
 *
 *  2. A LOG IS BOUND TO ITS STREAM. The stream id is hashed into the header,
 *     the header seeds the chain, so the same records under a different
 *     stream give a different head and frames cannot be lifted between logs.
 *
 *  3. AN EDIT IS NAMED, NOT JUST DETECTED. Flipping one bit of one payload
 *     must refuse with BROKEN_CHAIN and report the sequence number of the
 *     first frame that does not verify — and must report the records before
 *     it as good, because a localised break is what makes the log useful
 *     rather than merely alarming.
 *
 *  4. TORN IS NOT TAMPERED. An interrupted append leaves an uncommitted tail
 *     and must be recovered silently-but-reported. A committed frame that
 *     does not verify must refuse and must NOT be truncated: discarding it
 *     would destroy the evidence that something was altered. The two cases
 *     are exercised side by side because confusing them is the whole risk.
 *
 *  5. verify() NEVER WRITES. The file size is captured before and after. An
 *     auditor that repairs what it is auditing is not an auditor.
 *
 *  6. EVERY SINGLE BIT IS LOAD-BEARING. The last case flips every bit of a
 *     complete log file in turn and requires that each flip is noticed —
 *     the same discipline node_character_wire.c is held to. A bit nobody
 *     notices is a bit an attacker can use.
 */

#include "test/test_core.h"

#include "base/safe_alloc.h"
#include "chainlog/chainlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CL_CHECK(name, expr)                                          \
    do {                                                              \
        const bool cl_ok_ = (expr);                                   \
        if (!cl_ok_) failures++;                                      \
        printf("chainlog: %s %s\n", cl_ok_ ? "OK  " : "FAIL", (name)); \
    } while (0)

static const uint8_t k_stream_a[32] = {
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7,
    0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
};
static const uint8_t k_stream_b[32] = {
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
    0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
    0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
    0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
};

/* Three short records, used by nearly every case so the expected sequence
 * numbers below can be read off directly. */
static const char *const k_body[] = { "alpha", "beta", "gamma" };
#define BODY_N (sizeof k_body / sizeof k_body[0])

/* ── file helpers ──────────────────────────────────────────────────── */

static long file_size(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long n = ftell(f);
    fclose(f);
    return n;
}

static uint8_t *file_slurp(const char *path, size_t *len)
{
    long n = file_size(path);
    if (n <= 0)
        return NULL;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    uint8_t *buf = zcl_malloc((size_t)n, "test_chainlog_slurp");
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static bool file_spill(const char *path, const uint8_t *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = fwrite(buf, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

/* Flip one bit of a file in place. */
static bool file_flip_bit(const char *path, size_t bit)
{
    size_t len = 0;
    uint8_t *buf = file_slurp(path, &len);
    if (!buf || bit / 8 >= len) {
        free(buf);
        return false;
    }
    buf[bit / 8] ^= (uint8_t)(1u << (bit % 8));
    bool ok = file_spill(path, buf, len);
    free(buf);
    return ok;
}

static bool file_shorten(const char *path, size_t drop)
{
    size_t len = 0;
    uint8_t *buf = file_slurp(path, &len);
    if (!buf || drop >= len) {
        free(buf);
        return false;
    }
    bool ok = file_spill(path, buf, len - drop);
    free(buf);
    return ok;
}

/* Write `count` records of k_body into a fresh log; returns the head. */
static bool build_log(const char *path, const uint8_t stream[32], size_t count,
                      uint8_t head[32])
{
    struct zcl_chainlog_report rep;
    struct zcl_chainlog *log = zcl_chainlog_open(path, stream, &rep);
    if (!log)
        return false;
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        const char *b = k_body[i % BODY_N];
        ok = zcl_chainlog_append(log, (uint32_t)(i + 1), b, strlen(b), NULL,
                                 NULL) == ZCL_CHAINLOG_OK;
    }
    if (ok && head)
        ok = zcl_chainlog_head(log, head);
    zcl_chainlog_close(log);
    return ok;
}

/* ── 1. round trip, and a restart the chain cannot see ─────────────── */

static int case_roundtrip(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "rt");
    char path[640];
    snprintf(path, sizeof path, "%s/one.chainlog", dir);

    struct zcl_chainlog_report rep;
    struct zcl_chainlog *log = zcl_chainlog_open(path, k_stream_a, &rep);
    CL_CHECK("a new log opens", log != NULL);
    CL_CHECK("and starts empty",
             rep.status == ZCL_CHAINLOG_OK && rep.records == 0 &&
                 rep.torn_bytes == 0);
    if (!log) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    uint64_t seq = 0;
    bool appended = true;
    for (size_t i = 0; i < BODY_N; i++)
        appended = appended &&
                   zcl_chainlog_append(log, (uint32_t)(i + 1), k_body[i],
                                       strlen(k_body[i]), &seq, NULL) ==
                       ZCL_CHAINLOG_OK &&
                   seq == (uint64_t)(i + 1);
    CL_CHECK("three records append with dense sequence numbers", appended);
    CL_CHECK("the count agrees", zcl_chainlog_count(log) == BODY_N);

    uint8_t head_live[32] = { 0 };
    CL_CHECK("a head is available", zcl_chainlog_head(log, head_live));

    /* Read every record back through the API that re-verifies on the way. */
    bool read_ok = true;
    for (size_t i = 0; i < BODY_N; i++) {
        char buf[64] = { 0 };
        size_t len = 0;
        uint32_t kind = 0;
        read_ok = read_ok &&
                  zcl_chainlog_read(log, (uint64_t)(i + 1), &kind, buf,
                                    sizeof buf, &len) == ZCL_CHAINLOG_OK &&
                  kind == (uint32_t)(i + 1) && len == strlen(k_body[i]) &&
                  memcmp(buf, k_body[i], len) == 0;
    }
    CL_CHECK("every record reads back with its kind and payload", read_ok);
    zcl_chainlog_close(log);

    /* Reopen: the head must be the same value, recomputed from the file. */
    struct zcl_chainlog_report rep2;
    struct zcl_chainlog *again = zcl_chainlog_open(path, k_stream_a, &rep2);
    CL_CHECK("it reopens", again != NULL);
    CL_CHECK("with nothing torn and every record accepted",
             rep2.status == ZCL_CHAINLOG_OK && rep2.records == BODY_N &&
                 rep2.torn_bytes == 0);
    CL_CHECK("and recomputes the identical head",
             memcmp(rep2.head, head_live, 32) == 0);

    if (again) {
        uint64_t next = 0;
        CL_CHECK("appending after a reopen continues the sequence",
                 zcl_chainlog_append(again, 9, "delta", 5, &next, NULL) ==
                         ZCL_CHAINLOG_OK &&
                     next == BODY_N + 1);
        zcl_chainlog_close(again);
    }

    /* verify() agrees with open(), from the outside, without a handle. */
    struct zcl_chainlog_report rep3;
    CL_CHECK("verify walks the same log",
             zcl_chainlog_verify(path, k_stream_a, &rep3) == ZCL_CHAINLOG_OK &&
                 rep3.records == BODY_N + 1);

    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_restart_invisible(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "restart");
    char one[640], many[640];
    snprintf(one, sizeof one, "%s/one_session.chainlog", dir);
    snprintf(many, sizeof many, "%s/five_sessions.chainlog", dir);

    uint8_t head_one[32] = { 0 };
    CL_CHECK("five records in one session", build_log(one, k_stream_a, 5,
                                                      head_one));

    /* The same five, one open/close per record. */
    bool ok = true;
    uint8_t head_many[32] = { 0 };
    for (size_t i = 0; i < 5 && ok; i++) {
        struct zcl_chainlog_report rep;
        struct zcl_chainlog *log = zcl_chainlog_open(many, k_stream_a, &rep);
        if (!log) {
            ok = false;
            break;
        }
        const char *b = k_body[i % BODY_N];
        ok = zcl_chainlog_append(log, (uint32_t)(i + 1), b, strlen(b), NULL,
                                 NULL) == ZCL_CHAINLOG_OK &&
             zcl_chainlog_head(log, head_many);
        zcl_chainlog_close(log);
    }
    CL_CHECK("five records across five sessions", ok);
    CL_CHECK("a restart is invisible to the chain",
             memcmp(head_one, head_many, 32) == 0);
    size_t la = 0, lb = 0;
    uint8_t *ba = file_slurp(one, &la);
    uint8_t *bb = file_slurp(many, &lb);
    CL_CHECK("and the two files are byte-identical",
             ba && bb && la == lb && la > 0 && memcmp(ba, bb, la) == 0);
    free(ba);
    free(bb);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 2. the log is bound to its stream ─────────────────────────────── */

static int case_stream_binding(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "stream");
    char a[640], b[640];
    snprintf(a, sizeof a, "%s/a.chainlog", dir);
    snprintf(b, sizeof b, "%s/b.chainlog", dir);

    uint8_t head_a[32] = { 0 }, head_b[32] = { 0 };
    CL_CHECK("a log builds under stream A", build_log(a, k_stream_a, 3, head_a));
    CL_CHECK("the same records build under stream B",
             build_log(b, k_stream_b, 3, head_b));
    CL_CHECK("identical records under different streams differ",
             memcmp(head_a, head_b, 32) != 0);

    struct zcl_chainlog_report rep;
    struct zcl_chainlog *wrong = zcl_chainlog_open(a, k_stream_b, &rep);
    CL_CHECK("opening a log as the wrong stream refuses", wrong == NULL);
    CL_CHECK("and says which way it is wrong",
             rep.status == ZCL_CHAINLOG_STREAM_MISMATCH);
    zcl_chainlog_close(wrong);

    CL_CHECK("verify refuses the wrong stream too",
             zcl_chainlog_verify(a, k_stream_b, &rep) ==
                 ZCL_CHAINLOG_STREAM_MISMATCH);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 3. an edit is named ───────────────────────────────────────────── */

static int case_tampered_record(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "tamper");
    char path[640];
    snprintf(path, sizeof path, "%s/edited.chainlog", dir);

    CL_CHECK("a three-record log builds", build_log(path, k_stream_a, 3, NULL));
    long before = file_size(path);

    /* Frame 2's payload starts after the header and one whole frame:
     *   header 64 + (16 + 5 + 32 + 16) for "alpha" = 133, then 16 of prefix. */
    const size_t frame2_payload = 64u + (16u + 5u + 32u + 16u) + 16u;
    CL_CHECK("one bit of the middle record is flipped",
             file_flip_bit(path, frame2_payload * 8 + 3));

    struct zcl_chainlog_report rep;
    struct zcl_chainlog *log = zcl_chainlog_open(path, k_stream_a, &rep);
    CL_CHECK("the log refuses to open", log == NULL);
    CL_CHECK("naming a broken chain",
             rep.status == ZCL_CHAINLOG_BROKEN_CHAIN);
    CL_CHECK("at exactly the edited record", rep.first_bad_seq == 2);
    CL_CHECK("with the records before it still counted as good",
             rep.records == 1);
    CL_CHECK("and nothing was truncated to make it pass",
             file_size(path) == before);
    zcl_chainlog_close(log);

    struct zcl_chainlog_report vrep;
    CL_CHECK("verify reaches the same verdict",
             zcl_chainlog_verify(path, k_stream_a, &vrep) ==
                     ZCL_CHAINLOG_BROKEN_CHAIN &&
                 vrep.first_bad_seq == 2);
    CL_CHECK("and verify left the file exactly as it found it",
             file_size(path) == before);

    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_tampered_header(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "hdr");
    char empty[640], full[640];
    snprintf(empty, sizeof empty, "%s/empty.chainlog", dir);
    snprintf(full, sizeof full, "%s/full.chainlog", dir);

    /* An EMPTY log has no frames to break, so only the header's own digest
     * can catch an edit. That is exactly why the digest is there. */
    CL_CHECK("an empty log is created", build_log(empty, k_stream_a, 0, NULL));
    CL_CHECK("a bit of its stream id is flipped", file_flip_bit(empty, 16 * 8));
    struct zcl_chainlog_report rep;
    CL_CHECK("an empty log still notices a header edit",
             zcl_chainlog_open(empty, k_stream_a, &rep) == NULL &&
                 rep.status == ZCL_CHAINLOG_FORMAT);

    /* The reserved word is checked, not ignored. */
    CL_CHECK("a populated log builds", build_log(full, k_stream_a, 2, NULL));
    CL_CHECK("a bit of the reserved word is set", file_flip_bit(full, 12 * 8));
    CL_CHECK("a set reserved bit refuses rather than being skipped",
             zcl_chainlog_open(full, k_stream_a, &rep) == NULL &&
                 rep.status == ZCL_CHAINLOG_FORMAT);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 4. torn is not tampered ───────────────────────────────────────── */

static int case_torn_tail(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "torn");
    char path[640];
    snprintf(path, sizeof path, "%s/torn.chainlog", dir);

    CL_CHECK("a three-record log builds", build_log(path, k_stream_a, 3, NULL));
    uint8_t head2[32] = { 0 };
    {   /* the head after two records, for comparison below */
        char two[640];
        snprintf(two, sizeof two, "%s/two.chainlog", dir);
        CL_CHECK("a two-record log builds for comparison",
                 build_log(two, k_stream_a, 2, head2));
    }

    /* Cut the last frame in half: an append interrupted in phase 1. What
     * open() discards is the whole INCOMPLETE FRAME REMAINDER, not the
     * number of bytes removed here — the surviving half was never
     * committed either. */
    const size_t last_frame = 16u + 5u + 32u + 16u; /* "gamma" */
    const size_t cut = last_frame / 2;
    const size_t torn = last_frame - cut;
    CL_CHECK("the last frame is cut short", file_shorten(path, cut));
    long torn_size = file_size(path);

    /* verify() reports it and must not repair it. */
    struct zcl_chainlog_report vrep;
    CL_CHECK("verify accepts the committed part",
             zcl_chainlog_verify(path, k_stream_a, &vrep) == ZCL_CHAINLOG_OK);
    CL_CHECK("reports two good records and a torn tail",
             vrep.records == 2 && vrep.torn_bytes == torn);
    CL_CHECK("and changed nothing", file_size(path) == torn_size);

    /* open() recovers: the uncommitted bytes go, the history stays. */
    struct zcl_chainlog_report rep;
    struct zcl_chainlog *log = zcl_chainlog_open(path, k_stream_a, &rep);
    CL_CHECK("open recovers the log", log != NULL);
    CL_CHECK("keeping the two committed records",
             rep.status == ZCL_CHAINLOG_OK && rep.records == 2);
    CL_CHECK("and saying how much it discarded",
             rep.torn_bytes == torn);
    CL_CHECK("the recovered head is the head after two records",
             memcmp(rep.head, head2, 32) == 0);
    CL_CHECK("the file actually shrank",
             file_size(path) == torn_size - (long)torn);

    if (log) {
        uint64_t seq = 0;
        CL_CHECK("and appending resumes at the right sequence number",
                 zcl_chainlog_append(log, 7, "resumed", 7, &seq, NULL) ==
                         ZCL_CHAINLOG_OK &&
                     seq == 3);
        zcl_chainlog_close(log);
    }

    test_cleanup_tmpdir(dir);
    return failures;
}

static int case_uncommitted_gap(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "gap");
    char path[640];
    snprintf(path, sizeof path, "%s/gap.chainlog", dir);

    CL_CHECK("a three-record log builds", build_log(path, k_stream_a, 3, NULL));
    long before = file_size(path);

    /* Break the FIRST frame's commit sentinel. No crash can produce this —
     * a later frame is committed and an earlier one is not — so it must
     * refuse rather than truncate two good records away. */
    const size_t sentinel1 = 64u + 16u + 5u + 32u;
    CL_CHECK("a bit of the first commit sentinel is flipped",
             file_flip_bit(path, sentinel1 * 8 + 1));

    struct zcl_chainlog_report rep;
    CL_CHECK("the log refuses to open",
             zcl_chainlog_open(path, k_stream_a, &rep) == NULL);
    CL_CHECK("naming an uncommitted frame with history after it",
             rep.status == ZCL_CHAINLOG_UNCOMMITTED_GAP);
    CL_CHECK("at the first record", rep.first_bad_seq == 1);
    CL_CHECK("and it refused instead of truncating",
             file_size(path) == before);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 5. every bit is load-bearing ──────────────────────────────────── */

static int case_bit_sweep(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "sweep");
    char golden[640], work[640];
    snprintf(golden, sizeof golden, "%s/golden.chainlog", dir);
    snprintf(work, sizeof work, "%s/work.chainlog", dir);

    uint8_t head[32] = { 0 };
    CL_CHECK("a two-record log builds", build_log(golden, k_stream_a, 2, head));

    size_t len = 0;
    uint8_t *pristine = file_slurp(golden, &len);
    CL_CHECK("its bytes are readable", pristine != NULL && len > 0);
    if (!pristine) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    size_t missed = 0;
    size_t first_missed_bit = 0;
    for (size_t bit = 0; bit < len * 8; bit++) {
        if (!file_spill(work, pristine, len) || !file_flip_bit(work, bit)) {
            missed++;
            continue;
        }
        struct zcl_chainlog_report rep;
        struct zcl_chainlog *log = zcl_chainlog_open(work, k_stream_a, &rep);
        /* Noticed means: refused outright, or opened with a different story
         * than the pristine log told — fewer records, a discarded tail, or a
         * different head. A flip that changes none of those is a flip
         * nobody would ever see. */
        bool noticed = (log == NULL) || rep.records != 2 ||
                       rep.torn_bytes != 0 || memcmp(rep.head, head, 32) != 0;
        if (!noticed) {
            if (missed == 0)
                first_missed_bit = bit;
            missed++;
        }
        zcl_chainlog_close(log);
    }
    free(pristine);

    if (missed)
        printf("chainlog: first unnoticed bit was %zu of %zu\n",
               first_missed_bit, len * 8);
    CL_CHECK("every single bit of the file is noticed when flipped",
             missed == 0);

    test_cleanup_tmpdir(dir);
    return failures;
}

/* ── 6. the surface refuses nonsense ───────────────────────────────── */

static int case_surface(void)
{
    int failures = 0;
    char dir[512];
    test_make_tmpdir(dir, sizeof dir, "chainlog", "surface");
    char path[640];
    snprintf(path, sizeof path, "%s/surface.chainlog", dir);

    struct zcl_chainlog_report rep;
    CL_CHECK("a NULL path refuses",
             zcl_chainlog_open(NULL, k_stream_a, &rep) == NULL &&
                 rep.status == ZCL_CHAINLOG_ARGUMENT);
    CL_CHECK("a NULL stream refuses",
             zcl_chainlog_open(path, NULL, &rep) == NULL &&
                 rep.status == ZCL_CHAINLOG_ARGUMENT);
    CL_CHECK("open without a report refuses",
             zcl_chainlog_open(path, k_stream_a, NULL) == NULL);
    CL_CHECK("verify without a report refuses",
             zcl_chainlog_verify(path, k_stream_a, NULL) ==
                 ZCL_CHAINLOG_ARGUMENT);
    CL_CHECK("a NULL log has no records", zcl_chainlog_count(NULL) == 0);
    CL_CHECK("a NULL log has no head", !zcl_chainlog_head(NULL, NULL));
    CL_CHECK("appending to nothing refuses",
             zcl_chainlog_append(NULL, 1, "x", 1, NULL, NULL) ==
                 ZCL_CHAINLOG_ARGUMENT);
    zcl_chainlog_close(NULL); /* must not crash */

    struct zcl_chainlog *log = zcl_chainlog_open(path, k_stream_a, &rep);
    CL_CHECK("a log opens", log != NULL);
    if (!log) {
        test_cleanup_tmpdir(dir);
        return failures;
    }

    CL_CHECK("a payload over the ceiling refuses, it is not split",
             zcl_chainlog_append(log, 1, "x", ZCL_CHAINLOG_PAYLOAD_MAX + 1,
                                 NULL, NULL) == ZCL_CHAINLOG_ARGUMENT);
    CL_CHECK("a length with no payload refuses",
             zcl_chainlog_append(log, 1, NULL, 4, NULL, NULL) ==
                 ZCL_CHAINLOG_ARGUMENT);
    CL_CHECK("a refused append left the log empty",
             zcl_chainlog_count(log) == 0);

    uint64_t seq = 0;
    CL_CHECK("an empty payload is a legal record",
             zcl_chainlog_append(log, 5, NULL, 0, &seq, NULL) ==
                     ZCL_CHAINLOG_OK &&
                 seq == 1);
    CL_CHECK("a real record follows it",
             zcl_chainlog_append(log, 6, "abcdefgh", 8, &seq, NULL) ==
                     ZCL_CHAINLOG_OK &&
                 seq == 2);

    size_t got = 0;
    char small[4];
    CL_CHECK("a buffer too small is refused, not silently cut",
             zcl_chainlog_read(log, 2, NULL, small, sizeof small, &got) ==
                 ZCL_CHAINLOG_TRUNCATED);
    CL_CHECK("and it says how much room the record needs", got == 8);
    CL_CHECK("record zero does not exist",
             zcl_chainlog_read(log, 0, NULL, small, sizeof small, &got) ==
                 ZCL_CHAINLOG_ARGUMENT);
    CL_CHECK("a record past the end is NOT_FOUND",
             zcl_chainlog_read(log, 99, NULL, small, sizeof small, &got) ==
                 ZCL_CHAINLOG_NOT_FOUND);
    CL_CHECK("an empty record reads back as empty",
             zcl_chainlog_read(log, 1, NULL, small, sizeof small, &got) ==
                     ZCL_CHAINLOG_OK &&
                 got == 0);

    CL_CHECK("every status names itself",
             strcmp(zcl_chainlog_status_label(ZCL_CHAINLOG_OK), "OK") == 0 &&
                 strcmp(zcl_chainlog_status_label(ZCL_CHAINLOG_BROKEN_CHAIN),
                        "BROKEN_CHAIN") == 0 &&
                 strcmp(zcl_chainlog_status_label(
                            (enum zcl_chainlog_status)77),
                        "UNKNOWN_STATUS") == 0);

    zcl_chainlog_close(log);
    test_cleanup_tmpdir(dir);
    return failures;
}

int test_chainlog(void);
int test_chainlog(void)
{
    int failures = 0;
    failures += case_roundtrip();
    failures += case_restart_invisible();
    failures += case_stream_binding();
    failures += case_tampered_record();
    failures += case_tampered_header();
    failures += case_torn_tail();
    failures += case_uncommitted_gap();
    failures += case_bit_sweep();
    failures += case_surface();
    printf("chainlog: %d failure(s)\n", failures);
    return failures;
}
