/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * kpi_ledger — canonical frame bytes, and the append-only history they live in.
 *
 * THE BYTES ARE THE CONTRACT. Two honest runs over the same tree with the same
 * numbers must produce the same payload, byte for byte, whatever compiler
 * flags, host or clock produced them. That is why the payload holds no
 * timestamp, no path and no pid: each of those differs between two runs that
 * measured exactly the same thing, and any one of them would make the ledger
 * incomparable while still looking like a ledger. Ordering comes from the
 * chainlog's `seq`, which is the one place ordering belongs.
 *
 * The state byte is the load-bearing field. Without it an UNAVAILABLE metric
 * and a metric that genuinely measured 0 would encode identically, and the
 * distinction this module exists to preserve would be destroyed on disk rather
 * than merely mis-rendered.
 *
 * READ BEFORE WRITE. kpi_ledger_record() reads the previous frame first, then
 * appends. Doing it the other way round would make every run's baseline the
 * row it had just written, so every delta would be zero and the ledger would
 * report a tree that never changes.
 */

#include "kpi/kpi.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <string.h>

/* ── canonical bytes ─────────────────────────────────────────────────── */

size_t kpi_encode(const struct kpi_frame *f, uint8_t *buf, size_t cap)
{
    if (!f || !buf || f->count > KPI_METRIC_MAX)
        return 0;

    size_t need = 32 + 4;
    for (uint32_t i = 0; i < f->count; i++) {
        size_t idlen = strnlen(f->metric[i].id, KPI_ID_MAX);
        if (idlen == 0 || idlen >= KPI_ID_MAX)
            return 0;
        if (f->metric[i].state != KPI_STATE_PRESENT &&
            f->metric[i].state != KPI_STATE_UNAVAILABLE)
            return 0;
        need += 1 + idlen + 1 + 8;
    }
    if (need > cap)
        return 0;

    size_t at = 0;
    memcpy(buf + at, f->source_root_sha3, 32);
    at += 32;
    zcl_write_u32_be(buf + at, f->count);
    at += 4;
    for (uint32_t i = 0; i < f->count; i++) {
        size_t idlen = strnlen(f->metric[i].id, KPI_ID_MAX);
        buf[at++] = (uint8_t)idlen;
        memcpy(buf + at, f->metric[i].id, idlen);
        at += idlen;
        buf[at++] = (uint8_t)f->metric[i].state;
        /* An unavailable metric carries no number, so it carries ZERO — never
         * the last value it happened to have, which would read back as a
         * measurement nobody took. */
        zcl_write_u64_be(buf + at, f->metric[i].state == KPI_STATE_PRESENT
                              ? f->metric[i].value
                              : 0);
        at += 8;
    }
    return at;
}

bool kpi_decode(const uint8_t *buf, size_t len, struct kpi_frame *out)
{
    if (!buf || !out || len < 32 + 4)
        return false;
    struct kpi_frame f;
    memset(&f, 0, sizeof f);

    size_t at = 0;
    memcpy(f.source_root_sha3, buf + at, 32);
    at += 32;
    uint32_t count = zcl_read_u32_be(buf + at);
    at += 4;
    if (count > KPI_METRIC_MAX)
        return false;
    f.count = count;

    for (uint32_t i = 0; i < count; i++) {
        if (at + 1 > len)
            return false;
        size_t idlen = buf[at++];
        if (idlen == 0 || idlen >= KPI_ID_MAX)
            return false;
        if (at + idlen + 1 + 8 > len)
            return false;
        memcpy(f.metric[i].id, buf + at, idlen);
        f.metric[i].id[idlen] = '\0';
        at += idlen;
        uint8_t state = buf[at++];
        if (state != KPI_STATE_PRESENT && state != KPI_STATE_UNAVAILABLE)
            return false;
        f.metric[i].state = (enum kpi_state)state;
        uint64_t value = zcl_read_u64_be(buf + at);
        at += 8;
        /* A non-zero value under an unavailable state is a frame that
         * contradicts itself. Refuse it rather than pick which half to
         * believe. */
        if (state == KPI_STATE_UNAVAILABLE && value != 0)
            return false;
        f.metric[i].value = value;
    }
    /* Trailing bytes mean the writer and this reader disagree about the
     * format. A reader that ignored them would silently accept a frame it did
     * not fully understand. */
    if (at != len)
        return false;
    *out = f;
    return true;
}

const struct kpi_entry *kpi_frame_find(const struct kpi_frame *f,
                                       const char *id)
{
    if (!f || !id)
        return NULL;
    for (uint32_t i = 0; i < f->count && i < KPI_METRIC_MAX; i++)
        if (strcmp(f->metric[i].id, id) == 0)
            return &f->metric[i];
    return NULL;
}

enum kpi_verdict kpi_verdict_of(enum kpi_direction d,
                                const struct kpi_entry *prev,
                                const struct kpi_entry *cur)
{
    if (!cur || cur->state != KPI_STATE_PRESENT)
        return KPI_VERDICT_UNAVAILABLE;
    /* No prior frame, or a prior frame that could not read this metric: there
     * is nothing to compare against. That is NO_BASELINE, never UNCHANGED —
     * "equal to nothing" is not a measurement, and calling it unchanged would
     * report a first run as a run in which nothing moved. */
    if (!prev || prev->state != KPI_STATE_PRESENT)
        return KPI_VERDICT_NO_BASELINE;
    if (cur->value == prev->value)
        return KPI_VERDICT_UNCHANGED;
    bool went_up = cur->value > prev->value;
    switch (d) {
    case KPI_DIRECTION_HIGHER_IS_BETTER:
        return went_up ? KPI_VERDICT_IMPROVED : KPI_VERDICT_REGRESSED;
    case KPI_DIRECTION_LOWER_IS_BETTER:
        return went_up ? KPI_VERDICT_REGRESSED : KPI_VERDICT_IMPROVED;
    case KPI_DIRECTION_NEUTRAL:
        break;
    }
    /* A neutral metric that moved has changed, and that is all anyone can
     * honestly say about it. Scoring it either way would invent a verdict. */
    return KPI_VERDICT_UNCHANGED;
}

/* ── the ledger ──────────────────────────────────────────────────────── */

void kpi_stream_id(uint8_t out[32])
{
    static const char k_stream[] = "zcl.code_kpi.v1";
    zcl_sha3_256((const unsigned char *)k_stream, sizeof k_stream - 1, out);
}

bool kpi_ledger_record(const char *path, const struct kpi_frame *cur,
                       struct kpi_ledger_result *out)
{
    if (!path || !cur || !out)
        return false;
    memset(out, 0, sizeof *out);
    out->status = ZCL_CHAINLOG_ARGUMENT;

    uint8_t payload[KPI_PAYLOAD_MAX];
    size_t len = kpi_encode(cur, payload, sizeof payload);
    if (len == 0)
        return false;

    uint8_t stream[32];
    kpi_stream_id(stream);

    struct zcl_chainlog_report report;
    memset(&report, 0, sizeof report);
    struct zcl_chainlog *log = zcl_chainlog_open(path, stream, &report);
    out->status = report.status;
    out->torn_bytes = report.torn_bytes;
    if (!log)
        return false;

    /* READ FIRST. The baseline is the most recent frame that already existed;
     * appending before reading would make every run its own baseline. */
    uint64_t prior = zcl_chainlog_count(log);
    out->prior_records = prior;
    if (prior > 0) {
        uint8_t buf[KPI_PAYLOAD_MAX];
        size_t got = 0;
        uint32_t kind = 0;
        enum zcl_chainlog_status rs =
            zcl_chainlog_read(log, prior, &kind, buf, sizeof buf, &got);
        if (rs == ZCL_CHAINLOG_OK && kind == KPI_FRAME_KIND &&
            kpi_decode(buf, got, &out->previous))
            out->have_previous = true;
        /* A prior frame this build cannot decode is reported as no baseline
         * rather than as a zero baseline. The frame stays in the log — it is
         * evidence — and the run still writes its own. */
    }

    enum zcl_chainlog_status as =
        zcl_chainlog_append(log, KPI_FRAME_KIND, payload, len, &out->seq, NULL);
    out->status = as;
    out->wrote = (as == ZCL_CHAINLOG_OK);
    zcl_chainlog_close(log);
    return out->wrote;
}
