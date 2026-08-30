/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The claim register. The reasoning lives in science/science_claim.h; this
 * file only has to obey it. Two rules are worth restating where the code is:
 *
 *   1. Nothing in this file assigns a status. compute_reading() derives one
 *      from the trial array every time it is asked, and there is no member
 *      anywhere to cache it in.
 *   2. Canonical bytes are big-endian, length-prefixed and padding-free, and
 *      carry no clock and no path. Two machines that recorded the same
 *      evidence hold the same bytes and therefore the same chainlog head.
 */

#include "science/science_claim.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "chainlog/chainlog.h"
#include "sha3/sha3.h"

#include <stdlib.h>
#include <string.h>

/* Frame kinds in the chainlog. An unrecognised kind on replay refuses: it
 * means a newer version wrote this log, and guessing at a record we cannot
 * decode would report a claim's status from partial evidence. */
#define SCIENCE_FRAME_CLAIM 1u
#define SCIENCE_FRAME_TRIAL 2u

#define SCIENCE_CANON_VERSION 1u

/* Enough for the longest claim frame and the longest trial frame, the latter
 * being the one that carries the reproduction and observation blocks. */
#define SCIENCE_FRAME_MAX 4096u

/* ── stored rows ─────────────────────────────────────────────────────── */

struct science_claim_row {
    uint8_t  id[SCIENCE_CLAIM_ID_BYTES];
    char     statement[SCIENCE_STATEMENT_MAX];
    char     treatment[SCIENCE_TREATMENT_MAX];
    char     source[SCIENCE_SOURCE_MAX];
    enum science_metric metric;
    enum science_direction direction;
    int64_t  effect_floor_milli;
    uint32_t sample_floor;
};

struct science_trial_row {
    uint32_t claim_index;
    char     producer[SCIENCE_PRODUCER_MAX];
    enum science_arm arm;
    char     engine[SCIENCE_FIELD_MAX];
    char     model[SCIENCE_FIELD_MAX];
    char     territory[SCIENCE_FIELD_MAX];
    char     group[SCIENCE_FIELD_MAX];
    uint32_t files_changed;
    int32_t  groups_ran;
    int32_t  groups_failed;
    bool     cached;
    int64_t  prompt_tokens;
    int64_t  completion_tokens;
    enum engine_verdict verdict;
    /* reproduction */
    char     command[SCIENCE_COMMAND_MAX];
    char     commit[SCIENCE_COMMIT_MAX];
    char     input[SCIENCE_INPUT_MAX];
    char     compiler[SCIENCE_COMPILER_MAX];
    char     optimisation[SCIENCE_OPT_MAX];
    uint32_t nproc;
    bool     stress_tests;
    /* observation */
    enum science_availability availability;
    char     unit[SCIENCE_UNIT_MAX];
    uint32_t n;
    int64_t  min_milli;
    int64_t  median_milli;
    int64_t  p95_milli;
    int64_t  max_milli;
    char     reason[SCIENCE_REASON_MAX];
};

struct science_register {
    struct zcl_chainlog *log;
    struct science_claim_row *claims;
    uint32_t claim_count;
    struct science_trial_row *trials;
    uint32_t trial_count;
};

/* ── names ───────────────────────────────────────────────────────────── */

const char *science_metric_name(enum science_metric metric)
{
    switch (metric) {
    case SCIENCE_METRIC_VERDICT_PASS_RATE:      return "verdict_pass_rate";
    case SCIENCE_METRIC_FILES_CHANGED:          return "files_changed";
    case SCIENCE_METRIC_COMPLETION_TOKENS:      return "completion_tokens";
    case SCIENCE_METRIC_TOKENS_PER_LANDED_FILE: return "tokens_per_landed_file";
    case SCIENCE_METRIC_HOLLOW_RATE:            return "hollow_rate";
    case SCIENCE_METRIC_COUNT:                  break;
    }
    return "unknown_metric";
}

bool science_metric_from_name(const char *name, enum science_metric *out)
{
    if (!name || !out)
        return false;
    for (int i = 0; i < (int)SCIENCE_METRIC_COUNT; i++) {
        if (strcmp(name, science_metric_name((enum science_metric)i)) == 0) {
            *out = (enum science_metric)i;
            return true;
        }
    }
    /* Not in the closed set. Refusing here is the whole point: a metric this
     * tree does not measure cannot decide anything. */
    return false;
}

const char *science_direction_name(enum science_direction direction)
{
    switch (direction) {
    case SCIENCE_DIRECTION_UP:   return "up";
    case SCIENCE_DIRECTION_DOWN: return "down";
    case SCIENCE_DIRECTION_NONE: break;
    }
    return "unknown_direction";
}

const char *science_arm_name(enum science_arm arm)
{
    switch (arm) {
    case SCIENCE_ARM_CONTROL:   return "control";
    case SCIENCE_ARM_TREATMENT: return "treatment";
    case SCIENCE_ARM_NONE:      break;
    }
    return "unknown_arm";
}

const char *science_availability_name(enum science_availability a)
{
    switch (a) {
    case SCIENCE_OBSERVED:          return "observed";
    case SCIENCE_UNAVAILABLE:       return "unavailable";
    case SCIENCE_AVAILABILITY_NONE: break;
    }
    return "unknown_availability";
}

const char *science_status_name(enum science_status status)
{
    switch (status) {
    case SCIENCE_UNTESTED:     return "UNTESTED";
    case SCIENCE_SUPPORTED:    return "SUPPORTED";
    case SCIENCE_REFUTED:      return "REFUTED";
    case SCIENCE_INCONCLUSIVE: return "INCONCLUSIVE";
    }
    return "UNKNOWN_STATUS";
}

const char *science_refusal_name(enum science_refusal refusal)
{
    switch (refusal) {
    case SCIENCE_OK:                    return "OK";
    case SCIENCE_REFUSED_ARGUMENT:      return "ARGUMENT";
    case SCIENCE_REFUSED_STATEMENT:     return "STATEMENT";
    case SCIENCE_REFUSED_TREATMENT:     return "TREATMENT";
    case SCIENCE_REFUSED_METRIC:        return "METRIC";
    case SCIENCE_REFUSED_DIRECTION:     return "DIRECTION";
    case SCIENCE_REFUSED_EFFECT_FLOOR:  return "EFFECT_FLOOR";
    case SCIENCE_REFUSED_SAMPLE_FLOOR:  return "SAMPLE_FLOOR";
    case SCIENCE_REFUSED_ARM:           return "ARM";
    case SCIENCE_REFUSED_PRODUCER:      return "PRODUCER";
    case SCIENCE_REFUSED_FIELD:         return "FIELD";
    case SCIENCE_REFUSED_VERDICT:       return "VERDICT";
    case SCIENCE_REFUSED_SOURCE:        return "SOURCE";
    case SCIENCE_REFUSED_COMMAND:       return "COMMAND";
    case SCIENCE_REFUSED_COMMIT:        return "COMMIT";
    case SCIENCE_REFUSED_INPUT:         return "INPUT";
    case SCIENCE_REFUSED_COMPILER:      return "COMPILER";
    case SCIENCE_REFUSED_OPTIMISATION:  return "OPTIMISATION";
    case SCIENCE_REFUSED_NPROC:         return "NPROC";
    case SCIENCE_REFUSED_AVAILABILITY:  return "AVAILABILITY";
    case SCIENCE_REFUSED_SAMPLES:       return "SAMPLES";
    case SCIENCE_REFUSED_REASON:        return "REASON";
    case SCIENCE_REFUSED_DUPLICATE:     return "DUPLICATE";
    case SCIENCE_REFUSED_RESTATED:      return "RESTATED";
    case SCIENCE_REFUSED_UNKNOWN_CLAIM: return "UNKNOWN_CLAIM";
    case SCIENCE_REFUSED_FULL:          return "FULL";
    case SCIENCE_REFUSED_STORAGE:       return "STORAGE";
    }
    return "UNKNOWN_REFUSAL";
}

/* ── canonical encoding ──────────────────────────────────────────────── */

struct canon {
    uint8_t *buf;
    size_t   cap;
    size_t   len;
    bool     overflow;
};

static void canon_bytes(struct canon *c, const void *src, size_t n)
{
    if (c->overflow)
        return;
    if (n > c->cap - c->len) {
        c->overflow = true;
        return;
    }
    if (n)
        memcpy(c->buf + c->len, src, n);
    c->len += n;
}

static void canon_u8(struct canon *c, uint8_t v) { canon_bytes(c, &v, 1); }

/* Every multi-byte field goes through lib/base's one byte-order codec. There
 * is deliberately no hand-rolled shift-and-mask here: a second packing
 * implementation is a second thing that can disagree with the first, and the
 * whole value of these bytes is that two machines produce the same ones. */
static void canon_u32(struct canon *c, uint32_t v)
{
    uint8_t b[4];
    zcl_write_u32_be(b, v);
    canon_bytes(c, b, sizeof b);
}

static void canon_u64(struct canon *c, uint64_t v)
{
    uint8_t b[8];
    zcl_write_u64_be(b, v);
    canon_bytes(c, b, sizeof b);
}

/* Two's complement, written through the unsigned width so the encoding does
 * not depend on the host's signed representation. */
static void canon_i64(struct canon *c, int64_t v) { canon_u64(c, (uint64_t)v); }
static void canon_i32(struct canon *c, int32_t v) { canon_u32(c, (uint32_t)v); }

/* Length-prefixed, never NUL-padded: two strings of different lengths can
 * never produce the same bytes. NULL encodes exactly like "". The prefix is
 * a u32 because lib/base ships no big-endian u16 codec, and two extra bytes
 * per string is cheaper than a second byte-order implementation. */
static void canon_str(struct canon *c, const char *s)
{
    const size_t n = s ? strlen(s) : 0;
    canon_u32(c, (uint32_t)n);
    canon_bytes(c, s, n);
}

/* ── validation ──────────────────────────────────────────────────────── */

static bool str_within(const char *s, size_t cap)
{
    return s && s[0] != '\0' && strlen(s) < cap;
}

static bool str_optional_within(const char *s, size_t cap)
{
    return !s || strlen(s) < cap;
}

/* Refuse on the first missing falsifier, in the order the spec declares its
 * fields. The order is part of the contract: a caller fixing one field at a
 * time always learns about the next one. */
static enum science_refusal validate_spec(const struct science_claim_spec *spec)
{
    if (!spec)
        return SCIENCE_REFUSED_ARGUMENT;
    if (!str_within(spec->statement, SCIENCE_STATEMENT_MAX))
        return SCIENCE_REFUSED_STATEMENT;
    if (!str_within(spec->treatment, SCIENCE_TREATMENT_MAX))
        return SCIENCE_REFUSED_TREATMENT;
    if ((int)spec->metric < 0 || spec->metric >= SCIENCE_METRIC_COUNT)
        return SCIENCE_REFUSED_METRIC;
    if (spec->direction != SCIENCE_DIRECTION_UP &&
        spec->direction != SCIENCE_DIRECTION_DOWN)
        return SCIENCE_REFUSED_DIRECTION;
    /* Zero is not a small floor, it is no floor. See the header. */
    if (spec->effect_floor_milli <= 0)
        return SCIENCE_REFUSED_EFFECT_FLOOR;
    if (spec->sample_floor == 0)
        return SCIENCE_REFUSED_SAMPLE_FLOOR;
    /* Provenance is optional; an over-long one is refused rather than cut,
     * because a truncated citation points somewhere else. */
    if (!str_optional_within(spec->source, SCIENCE_SOURCE_MAX))
        return SCIENCE_REFUSED_SOURCE;
    return SCIENCE_OK;
}

/* Two claims are the SAME CLAIM, for the purpose of catching a moved floor,
 * when they assert the same thing about the same treatment on the same
 * metric. The falsifier is deliberately NOT part of this comparison — that is
 * the whole point: the restatement to refuse is the one that keeps the words
 * and changes the prediction. */
static bool same_claim_different_falsifier(const struct science_claim_row *row,
                                           const struct science_claim_spec *spec)
{
    if (strcmp(row->statement, spec->statement) != 0 ||
        strcmp(row->treatment, spec->treatment) != 0 ||
        row->metric != spec->metric)
        return false;
    return row->direction != spec->direction ||
           row->effect_floor_milli != spec->effect_floor_milli ||
           row->sample_floor != spec->sample_floor;
}

static bool verdict_known(enum engine_verdict v)
{
    switch (v) {
    case ENGINE_VERDICT_PASS:
    case ENGINE_VERDICT_FAIL:
    case ENGINE_VERDICT_HOLLOW:
    case ENGINE_VERDICT_NO_CHANGE:
    case ENGINE_VERDICT_TIMEOUT:
    case ENGINE_VERDICT_REFUSED:
    case ENGINE_VERDICT_UNVERIFIED:
        return true;
    }
    return false;
}

static enum science_refusal validate_receipt(const struct science_receipt *r)
{
    if (!r)
        return SCIENCE_REFUSED_ARGUMENT;
    /* An unattributed trial cannot be counted toward distinct producers, and
     * the distinct-producer figure is what keeps a self-confirmed claim
     * visible. So there is no anonymous trial. */
    if (!str_within(r->producer, SCIENCE_PRODUCER_MAX))
        return SCIENCE_REFUSED_PRODUCER;
    if (r->arm != SCIENCE_ARM_CONTROL && r->arm != SCIENCE_ARM_TREATMENT)
        return SCIENCE_REFUSED_ARM;
    if (!str_optional_within(r->engine, SCIENCE_FIELD_MAX) ||
        !str_optional_within(r->model, SCIENCE_FIELD_MAX) ||
        !str_optional_within(r->territory, SCIENCE_FIELD_MAX) ||
        !str_optional_within(r->group, SCIENCE_FIELD_MAX))
        return SCIENCE_REFUSED_FIELD;
    if (r->files_changed > SCIENCE_FILES_MAX)
        return SCIENCE_REFUSED_FIELD;
    if (r->prompt_tokens < 0 || r->prompt_tokens > SCIENCE_TOKENS_MAX ||
        r->completion_tokens < 0 || r->completion_tokens > SCIENCE_TOKENS_MAX)
        return SCIENCE_REFUSED_FIELD;
    if (!verdict_known(r->verdict))
        return SCIENCE_REFUSED_VERDICT;

    /* REPRODUCTION. Every field required, each with its own refusal, because
     * "invalid trial" tells a caller nothing about which hole to fill. */
    if (!str_within(r->repro.command, SCIENCE_COMMAND_MAX))
        return SCIENCE_REFUSED_COMMAND;
    if (!str_within(r->repro.commit, SCIENCE_COMMIT_MAX))
        return SCIENCE_REFUSED_COMMIT;
    if (!str_within(r->repro.input, SCIENCE_INPUT_MAX))
        return SCIENCE_REFUSED_INPUT;
    if (!str_within(r->repro.compiler, SCIENCE_COMPILER_MAX))
        return SCIENCE_REFUSED_COMPILER;
    if (!str_within(r->repro.optimisation, SCIENCE_OPT_MAX))
        return SCIENCE_REFUSED_OPTIMISATION;
    /* Zero cores is not a small machine, it is an unfilled field. */
    if (r->repro.nproc == 0)
        return SCIENCE_REFUSED_NPROC;

    /* OBSERVATION. */
    if (r->observed.availability != SCIENCE_OBSERVED &&
        r->observed.availability != SCIENCE_UNAVAILABLE)
        return SCIENCE_REFUSED_AVAILABILITY;
    if (r->observed.availability == SCIENCE_OBSERVED) {
        /* n = 0 with numbers filled in is a summary pretending to be data. */
        if (r->observed.n == 0 || !str_within(r->observed.unit,
                                              SCIENCE_UNIT_MAX))
            return SCIENCE_REFUSED_SAMPLES;
        if (r->observed.min_milli > r->observed.median_milli ||
            r->observed.median_milli > r->observed.p95_milli ||
            r->observed.p95_milli > r->observed.max_milli)
            return SCIENCE_REFUSED_SAMPLES;
        if (!str_optional_within(r->observed.reason, SCIENCE_REASON_MAX))
            return SCIENCE_REFUSED_REASON;
    } else {
        /* UNAVAILABLE must say why. Otherwise a reader has no way to tell a
         * measurement that could not be taken from one nobody tried to take,
         * and both would end up read as zero. */
        if (!str_within(r->observed.reason, SCIENCE_REASON_MAX))
            return SCIENCE_REFUSED_REASON;
        if (r->observed.n != 0 || r->observed.min_milli != 0 ||
            r->observed.median_milli != 0 || r->observed.p95_milli != 0 ||
            r->observed.max_milli != 0)
            return SCIENCE_REFUSED_SAMPLES;
        if (!str_optional_within(r->observed.unit, SCIENCE_UNIT_MAX))
            return SCIENCE_REFUSED_SAMPLES;
    }
    return SCIENCE_OK;
}

/* ── public canonical bytes ──────────────────────────────────────────── */

size_t science_claim_canonical(const struct science_claim_spec *spec,
                               uint8_t *out, size_t cap)
{
    if (!out || validate_spec(spec) != SCIENCE_OK)
        return 0;
    struct canon c = { .buf = out, .cap = cap, .len = 0, .overflow = false };
    canon_u32(&c, SCIENCE_CANON_VERSION);
    canon_u32(&c, (uint32_t)spec->metric);
    canon_u32(&c, (uint32_t)spec->direction);
    canon_i64(&c, spec->effect_floor_milli);
    canon_u32(&c, spec->sample_floor);
    canon_str(&c, spec->statement);
    canon_str(&c, spec->treatment);
    /* Provenance is in the bytes, so a claim and the same claim with a
     * citation attached are distinguishable rows rather than one row whose
     * attribution depends on who wrote it last. */
    canon_str(&c, spec->source);
    return c.overflow ? 0 : c.len;
}

size_t science_trial_canonical(const uint8_t claim_id[32],
                               const struct science_receipt *receipt,
                               uint8_t *out, size_t cap)
{
    if (!out || !claim_id || validate_receipt(receipt) != SCIENCE_OK)
        return 0;
    struct canon c = { .buf = out, .cap = cap, .len = 0, .overflow = false };
    /* THE HYPOTHESIS COMES FIRST. Version, then the 32-byte claim id — which
     * commits to the statement, the treatment, the metric, the direction and
     * both floors — and only then anything the run produced. A record cannot
     * be re-cut so a prediction matches an outcome after the fact: changing
     * the hypothesis changes the claim id, which changes these bytes, which
     * changes the trial id every receiver recomputes. */
    canon_u32(&c, SCIENCE_CANON_VERSION);
    canon_bytes(&c, claim_id, SCIENCE_CLAIM_ID_BYTES);
    /* the result */
    canon_u32(&c, (uint32_t)receipt->arm);
    canon_u32(&c, receipt->files_changed);
    canon_i32(&c, receipt->groups_ran);
    canon_i32(&c, receipt->groups_failed);
    canon_u8(&c, receipt->cached ? 1u : 0u);
    canon_u32(&c, (uint32_t)receipt->verdict);
    canon_i64(&c, receipt->prompt_tokens);
    canon_i64(&c, receipt->completion_tokens);
    /* the observation: availability first, so a reader cannot reach a number
     * without first learning whether there is one */
    canon_u32(&c, (uint32_t)receipt->observed.availability);
    canon_u32(&c, receipt->observed.n);
    canon_i64(&c, receipt->observed.min_milli);
    canon_i64(&c, receipt->observed.median_milli);
    canon_i64(&c, receipt->observed.p95_milli);
    canon_i64(&c, receipt->observed.max_milli);
    /* the environment */
    canon_u32(&c, receipt->repro.nproc);
    canon_u8(&c, receipt->repro.stress_tests ? 1u : 0u);
    /* the strings, in a fixed order */
    canon_str(&c, receipt->producer);
    canon_str(&c, receipt->engine);
    canon_str(&c, receipt->model);
    canon_str(&c, receipt->territory);
    canon_str(&c, receipt->group);
    canon_str(&c, receipt->repro.command);
    canon_str(&c, receipt->repro.commit);
    canon_str(&c, receipt->repro.input);
    canon_str(&c, receipt->repro.compiler);
    canon_str(&c, receipt->repro.optimisation);
    canon_str(&c, receipt->observed.unit);
    canon_str(&c, receipt->observed.reason);
    return c.overflow ? 0 : c.len;
}

bool science_trial_id(const uint8_t claim_id[32],
                      const struct science_receipt *receipt, uint8_t out[32])
{
    if (!out || !claim_id)
        return false;
    uint8_t frame[SCIENCE_FRAME_MAX];
    const size_t n = science_trial_canonical(claim_id, receipt, frame,
                                             sizeof frame);
    if (n == 0)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)frame, n);
    sha3_256_finalize(&ctx, (unsigned char *)out);
    return true;
}

bool science_claim_id(const struct science_claim_spec *spec, uint8_t out[32])
{
    if (!out)
        return false;
    uint8_t frame[SCIENCE_FRAME_MAX];
    const size_t n = science_claim_canonical(spec, frame, sizeof frame);
    if (n == 0)
        return false;
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)frame, n);
    sha3_256_finalize(&ctx, (unsigned char *)out);
    return true;
}

/* ── canonical decoding, for replay ──────────────────────────────────── */

struct decan {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    bool   bad;
};

static void decan_bytes(struct decan *d, void *dst, size_t n)
{
    if (d->bad || n > d->len - d->pos) {
        d->bad = true;
        return;
    }
    if (n)
        memcpy(dst, d->buf + d->pos, n);
    d->pos += n;
}

static uint8_t decan_u8(struct decan *d)
{
    uint8_t v = 0;
    decan_bytes(d, &v, 1);
    return v;
}

static uint32_t decan_u32(struct decan *d)
{
    uint8_t b[4] = { 0, 0, 0, 0 };
    decan_bytes(d, b, sizeof b);
    return zcl_read_u32_be(b);
}

static uint64_t decan_u64(struct decan *d)
{
    uint8_t b[8] = { 0 };
    decan_bytes(d, b, sizeof b);
    return zcl_read_u64_be(b);
}

static int64_t decan_i64(struct decan *d) { return (int64_t)decan_u64(d); }
static int32_t decan_i32(struct decan *d) { return (int32_t)decan_u32(d); }

/* Reads a length-prefixed string into a fixed field. A string that does not
 * fit marks the decode bad rather than truncating: a truncated replay would
 * hash to a different claim id than the one that was written. */
static void decan_str(struct decan *d, char *dst, size_t cap)
{
    const uint32_t n = decan_u32(d);
    if (d->bad || (size_t)n >= cap) {
        d->bad = true;
        return;
    }
    decan_bytes(d, dst, n);
    if (!d->bad)
        dst[n] = '\0';
}

/* ── open / replay ───────────────────────────────────────────────────── */

/* The chainlog stream id: SHA3-256 of this module's schema name. Opening a
 * log of anything else is STREAM_MISMATCH inside the chainlog, so a science
 * register can never append into someone else's history. */
static void science_stream_id(uint8_t out[32])
{
    static const char k_schema[] = "zcl.science.claims.v1";
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)k_schema,
                   sizeof k_schema - 1u);
    sha3_256_finalize(&ctx, (unsigned char *)out);
}

static int find_claim(const struct science_register *reg,
                      const uint8_t id[32])
{
    for (uint32_t i = 0; i < reg->claim_count; i++)
        if (memcmp(reg->claims[i].id, id, SCIENCE_CLAIM_ID_BYTES) == 0)
            return (int)i;
    return -1;
}

static enum science_refusal replay_claim(struct science_register *reg,
                                         const uint8_t *payload, size_t len)
{
    if (reg->claim_count >= SCIENCE_CLAIM_CAP)
        return SCIENCE_REFUSED_FULL;
    struct science_claim_row row = { 0 };
    struct decan d = { .buf = payload, .len = len, .pos = 0, .bad = false };
    if (decan_u32(&d) != SCIENCE_CANON_VERSION)
        return SCIENCE_REFUSED_STORAGE;
    row.metric = (enum science_metric)decan_u32(&d);
    row.direction = (enum science_direction)decan_u32(&d);
    row.effect_floor_milli = decan_i64(&d);
    row.sample_floor = decan_u32(&d);
    decan_str(&d, row.statement, sizeof row.statement);
    decan_str(&d, row.treatment, sizeof row.treatment);
    decan_str(&d, row.source, sizeof row.source);
    if (d.bad || d.pos != d.len)
        return SCIENCE_REFUSED_STORAGE;

    /* A stored claim is re-validated on the way in. A log that somehow holds
     * a claim with no falsifier must not become a claim with no falsifier in
     * memory; the register's guarantee is about what it will ANSWER, not only
     * about what it will accept from a live caller. */
    const struct science_claim_spec spec = {
        .statement = row.statement,
        .treatment = row.treatment,
        .metric = row.metric,
        .direction = row.direction,
        .effect_floor_milli = row.effect_floor_milli,
        .sample_floor = row.sample_floor,
        .source = row.source,
    };
    if (validate_spec(&spec) != SCIENCE_OK)
        return SCIENCE_REFUSED_STORAGE;
    if (!science_claim_id(&spec, row.id))
        return SCIENCE_REFUSED_STORAGE;
    if (find_claim(reg, row.id) >= 0)
        return SCIENCE_REFUSED_DUPLICATE;
    /* A log holding both a claim and its moved-floor restatement is a history
     * the live API refuses to produce, so replaying one refuses too. */
    for (uint32_t i = 0; i < reg->claim_count; i++)
        if (same_claim_different_falsifier(&reg->claims[i], &spec))
            return SCIENCE_REFUSED_RESTATED;
    reg->claims[reg->claim_count++] = row;
    return SCIENCE_OK;
}

/* Decode a trial frame into a row. Pure: no register, no network, nothing
 * about who sent it. This is both the replay path and the peer-verification
 * path, deliberately the same code — a record a peer would reject must not be
 * one our own replay silently accepts. */
static bool decode_trial(const uint8_t *payload, size_t len,
                         struct science_trial_row *row,
                         uint8_t claim_id[SCIENCE_CLAIM_ID_BYTES])
{
    memset(row, 0, sizeof *row);
    struct decan d = { .buf = payload, .len = len, .pos = 0, .bad = false };
    if (decan_u32(&d) != SCIENCE_CANON_VERSION)
        return false;
    decan_bytes(&d, claim_id, SCIENCE_CLAIM_ID_BYTES);
    row->arm = (enum science_arm)decan_u32(&d);
    row->files_changed = decan_u32(&d);
    row->groups_ran = decan_i32(&d);
    row->groups_failed = decan_i32(&d);
    row->cached = decan_u8(&d) != 0u;
    row->verdict = (enum engine_verdict)decan_u32(&d);
    row->prompt_tokens = decan_i64(&d);
    row->completion_tokens = decan_i64(&d);
    row->availability = (enum science_availability)decan_u32(&d);
    row->n = decan_u32(&d);
    row->min_milli = decan_i64(&d);
    row->median_milli = decan_i64(&d);
    row->p95_milli = decan_i64(&d);
    row->max_milli = decan_i64(&d);
    row->nproc = decan_u32(&d);
    row->stress_tests = decan_u8(&d) != 0u;
    decan_str(&d, row->producer, sizeof row->producer);
    decan_str(&d, row->engine, sizeof row->engine);
    decan_str(&d, row->model, sizeof row->model);
    decan_str(&d, row->territory, sizeof row->territory);
    decan_str(&d, row->group, sizeof row->group);
    decan_str(&d, row->command, sizeof row->command);
    decan_str(&d, row->commit, sizeof row->commit);
    decan_str(&d, row->input, sizeof row->input);
    decan_str(&d, row->compiler, sizeof row->compiler);
    decan_str(&d, row->optimisation, sizeof row->optimisation);
    decan_str(&d, row->unit, sizeof row->unit);
    decan_str(&d, row->reason, sizeof row->reason);
    /* Trailing bytes are a refusal, not slack: two encodings of one record
     * would be two content addresses for one fact. */
    return !d.bad && d.pos == d.len;
}

/* Rebuild the caller-facing receipt from a decoded row, so validation runs
 * on exactly the same shape whether the record came from this process or
 * from another node. */
static struct science_receipt receipt_of_row(const struct science_trial_row *r)
{
    return (struct science_receipt){
        .producer = r->producer,
        .arm = r->arm,
        .engine = r->engine,
        .model = r->model,
        .territory = r->territory,
        .group = r->group,
        .files_changed = r->files_changed,
        .groups_ran = r->groups_ran,
        .groups_failed = r->groups_failed,
        .cached = r->cached,
        .prompt_tokens = r->prompt_tokens,
        .completion_tokens = r->completion_tokens,
        .verdict = r->verdict,
        .repro = { .command = r->command,
                   .commit = r->commit,
                   .input = r->input,
                   .compiler = r->compiler,
                   .optimisation = r->optimisation,
                   .nproc = r->nproc,
                   .stress_tests = r->stress_tests },
        .observed = { .availability = r->availability,
                      .unit = r->unit,
                      .n = r->n,
                      .min_milli = r->min_milli,
                      .median_milli = r->median_milli,
                      .p95_milli = r->p95_milli,
                      .max_milli = r->max_milli,
                      .reason = r->reason },
    };
}

static enum science_refusal replay_trial(struct science_register *reg,
                                         const uint8_t *payload, size_t len)
{
    if (reg->trial_count >= SCIENCE_TRIAL_CAP)
        return SCIENCE_REFUSED_FULL;
    struct science_trial_row row;
    uint8_t claim_id[SCIENCE_CLAIM_ID_BYTES];
    if (!decode_trial(payload, len, &row, claim_id))
        return SCIENCE_REFUSED_STORAGE;

    const int idx = find_claim(reg, claim_id);
    if (idx < 0)
        return SCIENCE_REFUSED_UNKNOWN_CLAIM;
    const struct science_receipt check = receipt_of_row(&row);
    if (validate_receipt(&check) != SCIENCE_OK)
        return SCIENCE_REFUSED_STORAGE;
    row.claim_index = (uint32_t)idx;
    reg->trials[reg->trial_count++] = row;
    return SCIENCE_OK;
}

/* ── peer verification ───────────────────────────────────────────────── */

bool science_claim_verify(const uint8_t *frame, size_t len, uint8_t out_id[32])
{
    if (!frame || len == 0)
        return false;
    struct science_claim_row row = { 0 };
    struct decan d = { .buf = frame, .len = len, .pos = 0, .bad = false };
    if (decan_u32(&d) != SCIENCE_CANON_VERSION)
        return false;
    row.metric = (enum science_metric)decan_u32(&d);
    row.direction = (enum science_direction)decan_u32(&d);
    row.effect_floor_milli = decan_i64(&d);
    row.sample_floor = decan_u32(&d);
    decan_str(&d, row.statement, sizeof row.statement);
    decan_str(&d, row.treatment, sizeof row.treatment);
    decan_str(&d, row.source, sizeof row.source);
    if (d.bad || d.pos != d.len)
        return false;
    const struct science_claim_spec spec = {
        .statement = row.statement,
        .treatment = row.treatment,
        .metric = row.metric,
        .direction = row.direction,
        .effect_floor_milli = row.effect_floor_milli,
        .sample_floor = row.sample_floor,
        .source = row.source,
    };
    /* A claim with no falsifier is refused on the way IN from a peer for the
     * same reason it is refused from a local caller. */
    if (validate_spec(&spec) != SCIENCE_OK)
        return false;
    /* Re-encode and require the bytes back: this is what makes the id the
     * address of exactly these bytes and rejects a second encoding of the
     * same content. */
    uint8_t again[SCIENCE_FRAME_MAX];
    const size_t n = science_claim_canonical(&spec, again, sizeof again);
    if (n != len || memcmp(again, frame, len) != 0)
        return false;
    return !out_id || science_claim_id(&spec, out_id);
}

bool science_trial_verify(const uint8_t *frame, size_t len,
                          uint8_t out_claim_id[32], uint8_t out_trial_id[32])
{
    if (!frame || len == 0)
        return false;
    struct science_trial_row row;
    uint8_t claim_id[SCIENCE_CLAIM_ID_BYTES];
    if (!decode_trial(frame, len, &row, claim_id))
        return false;
    const struct science_receipt r = receipt_of_row(&row);
    if (validate_receipt(&r) != SCIENCE_OK)
        return false;
    uint8_t again[SCIENCE_FRAME_MAX];
    const size_t n = science_trial_canonical(claim_id, &r, again, sizeof again);
    if (n != len || memcmp(again, frame, len) != 0)
        return false;
    if (out_claim_id)
        memcpy(out_claim_id, claim_id, SCIENCE_CLAIM_ID_BYTES);
    if (out_trial_id && !science_trial_id(claim_id, &r, out_trial_id))
        return false;
    return true;
}

struct science_register *science_open(const char *path,
                                      struct science_open_report *report)
{
    if (!report)
        LOG_NULL("science", "science_open needs a report: an open that "
                            "refuses without saying what it found is not a "
                            "diagnosis");
    memset(report, 0, sizeof *report);
    report->chainlog_status = (int)ZCL_CHAINLOG_OK;
    if (!path || path[0] == '\0') {
        report->refusal = SCIENCE_REFUSED_ARGUMENT;
        LOG_NULL("science", "science_open needs a path; this module never "
                            "chooses a directory of its own");
    }

    struct science_register *reg =
        zcl_calloc(1, sizeof *reg, "science_register");
    if (!reg) {
        report->refusal = SCIENCE_REFUSED_STORAGE;
        return NULL;
    }
    reg->claims = zcl_calloc(SCIENCE_CLAIM_CAP, sizeof *reg->claims,
                             "science_claims");
    reg->trials = zcl_calloc(SCIENCE_TRIAL_CAP, sizeof *reg->trials,
                             "science_trials");
    if (!reg->claims || !reg->trials) {
        science_close(reg);
        report->refusal = SCIENCE_REFUSED_STORAGE;
        return NULL;
    }

    uint8_t stream[32];
    science_stream_id(stream);
    struct zcl_chainlog_report clrep;
    reg->log = zcl_chainlog_open(path, stream, &clrep);
    report->chainlog_status = (int)clrep.status;
    report->torn_bytes = clrep.torn_bytes;
    if (!reg->log) {
        science_close(reg);
        report->refusal = SCIENCE_REFUSED_STORAGE;
        LOG_NULL("science", "chainlog refused %s: %s", path,
                 zcl_chainlog_status_label(clrep.status));
    }

    const uint64_t records = zcl_chainlog_count(reg->log);
    uint8_t payload[SCIENCE_FRAME_MAX];
    for (uint64_t seq = 1; seq <= records; seq++) {
        uint32_t kind = 0;
        size_t got = 0;
        const enum zcl_chainlog_status st = zcl_chainlog_read(
            reg->log, seq, &kind, payload, sizeof payload, &got);
        if (st != ZCL_CHAINLOG_OK) {
            report->chainlog_status = (int)st;
            report->refusal = SCIENCE_REFUSED_STORAGE;
            science_close(reg);
            LOG_NULL("science", "replay stopped at seq %llu: %s",
                     (unsigned long long)seq,
                     zcl_chainlog_status_label(st));
        }
        enum science_refusal r;
        if (kind == SCIENCE_FRAME_CLAIM)
            r = replay_claim(reg, payload, got);
        else if (kind == SCIENCE_FRAME_TRIAL)
            r = replay_trial(reg, payload, got);
        else
            r = SCIENCE_REFUSED_STORAGE; /* a kind this version cannot decode */
        if (r != SCIENCE_OK) {
            report->refusal = r;
            science_close(reg);
            LOG_NULL("science", "replay refused frame %llu (kind %u): %s",
                     (unsigned long long)seq, kind, science_refusal_name(r));
        }
        report->frames++;
    }
    report->claims = reg->claim_count;
    report->trials = reg->trial_count;
    report->refusal = SCIENCE_OK;
    return reg;
}

void science_close(struct science_register *reg)
{
    if (!reg)
        return;
    if (reg->log)
        zcl_chainlog_close(reg->log);
    free(reg->claims);
    free(reg->trials);
    free(reg);
}

/* ── register / record ───────────────────────────────────────────────── */

enum science_refusal science_claim_register(struct science_register *reg,
                                            const struct science_claim_spec *spec,
                                            uint8_t out_claim_id[32])
{
    if (!reg)
        return SCIENCE_REFUSED_ARGUMENT;
    const enum science_refusal bad = validate_spec(spec);
    if (bad != SCIENCE_OK)
        return bad;
    if (reg->claim_count >= SCIENCE_CLAIM_CAP)
        return SCIENCE_REFUSED_FULL;

    uint8_t frame[SCIENCE_FRAME_MAX];
    const size_t n = science_claim_canonical(spec, frame, sizeof frame);
    if (n == 0)
        return SCIENCE_REFUSED_STATEMENT; /* only over-long text can land here */

    struct science_claim_row row = { 0 };
    if (!science_claim_id(spec, row.id))
        return SCIENCE_REFUSED_ARGUMENT;
    if (find_claim(reg, row.id) >= 0)
        return SCIENCE_REFUSED_DUPLICATE;
    /* The moved floor. Content addressing already means this cannot EDIT the
     * original claim; refusing it here also stops the edited variant sitting
     * beside the original so that whichever came out better could be quoted.
     * The prediction a claim made before it had results is the only one it
     * ever made. */
    for (uint32_t i = 0; i < reg->claim_count; i++)
        if (same_claim_different_falsifier(&reg->claims[i], spec))
            return SCIENCE_REFUSED_RESTATED;

    /* Durable first, in memory second. If the append fails the register must
     * not answer questions about a claim that is not on disk. */
    if (zcl_chainlog_append(reg->log, SCIENCE_FRAME_CLAIM, frame, n, NULL,
                            NULL) != ZCL_CHAINLOG_OK)
        return SCIENCE_REFUSED_STORAGE;

    /* strlen was bounded by validate_spec; the copies cannot truncate. */
    memcpy(row.statement, spec->statement, strlen(spec->statement) + 1u);
    memcpy(row.treatment, spec->treatment, strlen(spec->treatment) + 1u);
    if (spec->source)
        memcpy(row.source, spec->source, strlen(spec->source) + 1u);
    row.metric = spec->metric;
    row.direction = spec->direction;
    row.effect_floor_milli = spec->effect_floor_milli;
    row.sample_floor = spec->sample_floor;
    reg->claims[reg->claim_count++] = row;
    if (out_claim_id)
        memcpy(out_claim_id, row.id, SCIENCE_CLAIM_ID_BYTES);
    return SCIENCE_OK;
}

static void copy_field(char *dst, size_t cap, const char *src)
{
    const size_t n = src ? strlen(src) : 0;
    if (n >= cap) { /* unreachable: validate_receipt bounded every field */
        dst[0] = '\0';
        return;
    }
    if (n)
        memcpy(dst, src, n);
    dst[n] = '\0';
}

enum science_refusal science_trial_record(struct science_register *reg,
                                          const uint8_t claim_id[32],
                                          const struct science_receipt *receipt)
{
    if (!reg || !claim_id)
        return SCIENCE_REFUSED_ARGUMENT;
    const enum science_refusal bad = validate_receipt(receipt);
    if (bad != SCIENCE_OK)
        return bad;
    const int idx = find_claim(reg, claim_id);
    if (idx < 0)
        return SCIENCE_REFUSED_UNKNOWN_CLAIM;
    if (reg->trial_count >= SCIENCE_TRIAL_CAP)
        return SCIENCE_REFUSED_FULL;

    uint8_t frame[SCIENCE_FRAME_MAX];
    const size_t n =
        science_trial_canonical(claim_id, receipt, frame, sizeof frame);
    if (n == 0)
        return SCIENCE_REFUSED_FIELD;
    if (zcl_chainlog_append(reg->log, SCIENCE_FRAME_TRIAL, frame, n, NULL,
                            NULL) != ZCL_CHAINLOG_OK)
        return SCIENCE_REFUSED_STORAGE;

    struct science_trial_row row = { 0 };
    row.claim_index = (uint32_t)idx;
    copy_field(row.producer, sizeof row.producer, receipt->producer);
    row.arm = receipt->arm;
    copy_field(row.engine, sizeof row.engine, receipt->engine);
    copy_field(row.model, sizeof row.model, receipt->model);
    copy_field(row.territory, sizeof row.territory, receipt->territory);
    copy_field(row.group, sizeof row.group, receipt->group);
    row.files_changed = receipt->files_changed;
    row.groups_ran = receipt->groups_ran;
    row.groups_failed = receipt->groups_failed;
    row.cached = receipt->cached;
    row.prompt_tokens = receipt->prompt_tokens;
    row.completion_tokens = receipt->completion_tokens;
    row.verdict = receipt->verdict;
    copy_field(row.command, sizeof row.command, receipt->repro.command);
    copy_field(row.commit, sizeof row.commit, receipt->repro.commit);
    copy_field(row.input, sizeof row.input, receipt->repro.input);
    copy_field(row.compiler, sizeof row.compiler, receipt->repro.compiler);
    copy_field(row.optimisation, sizeof row.optimisation,
               receipt->repro.optimisation);
    row.nproc = receipt->repro.nproc;
    row.stress_tests = receipt->repro.stress_tests;
    row.availability = receipt->observed.availability;
    copy_field(row.unit, sizeof row.unit, receipt->observed.unit);
    row.n = receipt->observed.n;
    row.min_milli = receipt->observed.min_milli;
    row.median_milli = receipt->observed.median_milli;
    row.p95_milli = receipt->observed.p95_milli;
    row.max_milli = receipt->observed.max_milli;
    copy_field(row.reason, sizeof row.reason, receipt->observed.reason);
    reg->trials[reg->trial_count++] = row;
    return SCIENCE_OK;
}

/* ── the derivation ──────────────────────────────────────────────────── */

/* One arm's totals. Kept separate from the reading so the metric switch has
 * exactly one place to read from. */
struct arm_totals {
    uint32_t trials;
    uint32_t passes;
    uint32_t hollow;
    uint64_t files;      /* bounded: CAP * SCIENCE_FILES_MAX */
    int64_t  completion; /* bounded: CAP * SCIENCE_TOKENS_MAX */
};

static void tally(const struct science_register *reg, uint32_t claim_index,
                  enum science_arm arm, struct arm_totals *t)
{
    memset(t, 0, sizeof *t);
    for (uint32_t i = 0; i < reg->trial_count; i++) {
        const struct science_trial_row *row = &reg->trials[i];
        if (row->claim_index != claim_index || row->arm != arm)
            continue;
        t->trials++;
        if (engine_verdict_is_pass(row->verdict))
            t->passes++;
        if (row->verdict == ENGINE_VERDICT_HOLLOW)
            t->hollow++;
        t->files += row->files_changed;
        t->completion += row->completion_tokens;
    }
}

/* Distinct producers among the trials of one claim; `arm` of SCIENCE_ARM_NONE
 * means both arms. Linear scan against a fixed window — the register's trial
 * cap bounds it, and a set would buy nothing at this size. */
static uint32_t distinct_producers(const struct science_register *reg,
                                   uint32_t claim_index, enum science_arm arm)
{
    uint32_t n = 0;
    for (uint32_t i = 0; i < reg->trial_count; i++) {
        const struct science_trial_row *a = &reg->trials[i];
        if (a->claim_index != claim_index)
            continue;
        if (arm != SCIENCE_ARM_NONE && a->arm != arm)
            continue;
        bool seen = false;
        for (uint32_t j = 0; j < i && !seen; j++) {
            const struct science_trial_row *b = &reg->trials[j];
            if (b->claim_index != claim_index)
                continue;
            if (arm != SCIENCE_ARM_NONE && b->arm != arm)
                continue;
            seen = strcmp(a->producer, b->producer) == 0;
        }
        if (!seen)
            n++;
    }
    return n;
}

static void read_arm(const struct science_register *reg,
                     const struct science_claim_row *claim, uint32_t index,
                     enum science_arm arm, struct science_arm_reading *out)
{
    struct arm_totals t;
    tally(reg, index, arm, &t);
    memset(out, 0, sizeof *out);
    out->trials = t.trials;
    out->producers = distinct_producers(reg, index, arm);
    if (t.trials == 0)
        return;

    switch (claim->metric) {
    case SCIENCE_METRIC_VERDICT_PASS_RATE:
        out->value_milli = (int64_t)t.passes * SCIENCE_MILLI / (int64_t)t.trials;
        out->defined = true;
        break;
    case SCIENCE_METRIC_HOLLOW_RATE:
        out->value_milli = (int64_t)t.hollow * SCIENCE_MILLI / (int64_t)t.trials;
        out->defined = true;
        break;
    case SCIENCE_METRIC_FILES_CHANGED:
        out->value_milli = (int64_t)t.files * SCIENCE_MILLI / (int64_t)t.trials;
        out->defined = true;
        break;
    case SCIENCE_METRIC_COMPLETION_TOKENS:
        out->value_milli = t.completion * SCIENCE_MILLI / (int64_t)t.trials;
        out->defined = true;
        break;
    case SCIENCE_METRIC_TOKENS_PER_LANDED_FILE:
        /* Zero landed files is not efficiency, it is a division by zero. Say
         * so; never drop the arm and never pick a number for it. */
        if (t.files == 0) {
            out->defined = false;
            break;
        }
        out->value_milli = t.completion * SCIENCE_MILLI / (int64_t)t.files;
        out->defined = true;
        break;
    case SCIENCE_METRIC_COUNT:
        break;
    }
}

static void compute_reading(const struct science_register *reg,
                            uint32_t index, struct science_reading *out)
{
    const struct science_claim_row *claim = &reg->claims[index];
    memset(out, 0, sizeof *out);
    out->metric = claim->metric;
    out->direction = claim->direction;
    out->effect_floor_milli = claim->effect_floor_milli;
    out->sample_floor = claim->sample_floor;
    read_arm(reg, claim, index, SCIENCE_ARM_CONTROL, &out->control);
    read_arm(reg, claim, index, SCIENCE_ARM_TREATMENT, &out->treatment);
    out->trials = out->control.trials + out->treatment.trials;
    out->producers = distinct_producers(reg, index, SCIENCE_ARM_NONE);
    out->single_producer = out->producers <= 1u;

    /* THE SAMPLE FLOOR COMES FIRST, ALWAYS. An effect that looks enormous on
     * three trials is still untested; reading a verdict off it is exactly how
     * a register turns into a rumour mill. */
    if (out->control.trials < claim->sample_floor ||
        out->treatment.trials < claim->sample_floor) {
        out->status = SCIENCE_UNTESTED;
        out->reason = "fewer trials than the sample floor in at least one arm";
        return;
    }
    if (!out->control.defined || !out->treatment.defined) {
        out->status = SCIENCE_INCONCLUSIVE;
        out->effect_readable = false;
        out->reason = "an arm landed zero files, so the metric is undefined "
                      "for it; no effect can be read";
        return;
    }

    out->effect_readable = true;
    out->effect_milli = out->treatment.value_milli - out->control.value_milli;
    const int64_t floor = claim->effect_floor_milli;
    const int64_t effect = out->effect_milli;
    const bool up = claim->direction == SCIENCE_DIRECTION_UP;
    const int64_t with = up ? effect : -effect;   /* movement the claim wants */

    if (with >= floor) {
        out->status = SCIENCE_SUPPORTED;
        out->reason = "the effect reaches the floor in the stated direction";
    } else if (with <= -floor) {
        out->status = SCIENCE_REFUTED;
        out->reason = "the effect reaches the floor in the OPPOSITE direction";
    } else {
        out->status = SCIENCE_INCONCLUSIVE;
        out->reason = "the effect is inside the floor the claim declared";
    }
}

enum science_refusal science_claim_read(const struct science_register *reg,
                                        const uint8_t claim_id[32],
                                        struct science_reading *out)
{
    if (!reg || !claim_id || !out)
        return SCIENCE_REFUSED_ARGUMENT;
    const int idx = find_claim(reg, claim_id);
    if (idx < 0)
        return SCIENCE_REFUSED_UNKNOWN_CLAIM;
    compute_reading(reg, (uint32_t)idx, out);
    return SCIENCE_OK;
}

/* ── enumeration ─────────────────────────────────────────────────────── */

uint32_t science_claim_count(const struct science_register *reg)
{
    return reg ? reg->claim_count : 0u;
}

bool science_claim_id_at(const struct science_register *reg, uint32_t index,
                         uint8_t out_id[32])
{
    if (!reg || !out_id || index >= reg->claim_count)
        return false;
    memcpy(out_id, reg->claims[index].id, SCIENCE_CLAIM_ID_BYTES);
    return true;
}

bool science_claim_spec_at(const struct science_register *reg, uint32_t index,
                           struct science_claim_spec *out,
                           char statement[SCIENCE_STATEMENT_MAX],
                           char treatment[SCIENCE_TREATMENT_MAX],
                           char source[SCIENCE_SOURCE_MAX])
{
    if (!reg || !out || !statement || !treatment || !source ||
        index >= reg->claim_count)
        return false;
    const struct science_claim_row *row = &reg->claims[index];
    memcpy(statement, row->statement, sizeof row->statement);
    memcpy(treatment, row->treatment, sizeof row->treatment);
    memcpy(source, row->source, sizeof row->source);
    out->statement = statement;
    out->treatment = treatment;
    out->source = source;
    out->metric = row->metric;
    out->direction = row->direction;
    out->effect_floor_milli = row->effect_floor_milli;
    out->sample_floor = row->sample_floor;
    return true;
}
