/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Aggregate candidate reports by exact ref without mutation.
 * Reports carry provenance, never verification authority. Unread sources and truncated
 * inventories keep totals unknown; no files, locks or processes are used. */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "json/json.h"
#include "command/native_fleet.h"

/* State ranks, weakest to strongest. A later note may only raise a row's
 * state, never lower it: evidence accumulates, and a weaker sighting
 * arriving second must not erase a stronger one seen first. */
#define FCD_UNKNOWN 0u
#define FCD_DELIVERED 1u
#define FCD_PROVEN 2u
#define FCD_LANDED 4u

static const char *fcd_state_name(unsigned rank)
{
    switch (rank) {
    case FCD_LANDED:
        return "reported_landed";
    case FCD_PROVEN:
        return "reported_proven";
    case FCD_DELIVERED:
        return "delivered";
    default:
        return "unknown";
    }
}

/* Each reason names a missing observation or verification. */
#define FCD_UNVERIFIED "remote-verification-unavailable"
#define FCD_NO_EVIDENCE "no-classifying-evidence"
#define FCD_AGE_UNKNOWN "evidence-age-unparsable"
#define FCD_LANDING_UNATTESTED "landing-unattested"

static void fcd_copy(char *dst, size_t cap, const char *src)
{
    size_t n;
    if (!dst || cap == 0)
        return;
    dst[0] = '\0';
    if (!src)
        return;
    n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void zcl_fmc_cand_init(struct zcl_fmc_cand_reg *reg)
{
    if (!reg)
        return;
    memset(reg, 0, sizeof(*reg));
}

void zcl_fmc_cand_source_ok(struct zcl_fmc_cand_reg *reg, unsigned source)
{
    if (!reg)
        return;
    if (source & ZCL_FMC_CAND_SRC_MAIL)
        reg->mail_ok = true;
    if (source & ZCL_FMC_CAND_SRC_BOARD)
        reg->board_ok = true;
    if (source & ZCL_FMC_CAND_SRC_QUEUE)
        reg->queue_ok = true;
}

/* Find an existing row by identity, or claim a free one. Returns NULL only
 * when the cap is full, and then counts the sighting as dropped so the
 * emitted total can still be truthful about what was not shown. */
static struct zcl_fmc_cand *fcd_row(struct zcl_fmc_cand_reg *reg,
                                    const char *id)
{
    size_t i;
    if (!reg || !id || !id[0])
        return NULL;
    if (strlen(id) >= ZCL_FMC_CAND_ID_CAP) {
        reg->dropped++;
        return NULL;
    }
    for (i = 0; i < reg->count; i++) {
        if (strcmp(reg->row[i].id, id) == 0)
            return &reg->row[i];
    }
    if (reg->count >= ZCL_FMC_CAND_CAP) {
        reg->dropped++;
        return NULL;
    }
    memset(&reg->row[reg->count], 0, sizeof(reg->row[reg->count]));
    fcd_copy(reg->row[reg->count].id, ZCL_FMC_CAND_ID_CAP, id);
    reg->row[reg->count].state = FCD_UNKNOWN;
    reg->row[reg->count].age_known = false;
    reg->count++;
    return &reg->row[reg->count - 1];
}

/* Sender labels are provenance for reports, never verification authority. */
static void fcd_attest(struct zcl_fmc_cand *c, const char *who)
{
    unsigned i;
    if (!c || !who || !who[0])
        return;
    for (i = 0; i < c->attesters; i++) {
        if (strcmp(c->attester[i], who) == 0)
            return;
    }
    if (c->attesters == ZCL_FMC_CAND_ATTESTERS ||
        strlen(who) >= ZCL_FMC_CAND_AGENT_CAP) {
        c->attesters_incomplete = true;
        return;
    }
    fcd_copy(c->attester[c->attesters], ZCL_FMC_CAND_AGENT_CAP, who);
    c->attesters++;
}

/* The freshest evidence wins the age. An unparsable timestamp leaves the
 * age unknown rather than pinning it to 0, which would read as "seen just
 * now" — the exact lie this registry exists to stop. */
static void fcd_age(struct zcl_fmc_cand *c, long long age_s, bool known)
{
    if (!c)
        return;
    if (!known) {
        c->age_unparsable = true;
        return;
    }
    if (age_s < 0)
        age_s = 0;
    if (!c->age_known || age_s < c->age_s) {
        c->age_s = age_s;
        c->age_known = true;
    }
}

static void fcd_raise(struct zcl_fmc_cand *c, unsigned rank)
{
    if (c && rank > c->state)
        c->state = rank;
}

void zcl_fmc_cand_note(struct zcl_fmc_cand_reg *reg, const char *id,
                       unsigned source, const char *attester,
                       long long age_s, bool age_known)
{
    struct zcl_fmc_cand *c = fcd_row(reg, id);
    if (!c)
        return;
    c->sources |= source;
    fcd_attest(c, attester);
    fcd_age(c, age_s, age_known);
    /* A result row naming a ref is a handover; that is `delivered`. The
     * queue knowing a name is not, on its own, a handover. */
    if (source != ZCL_FMC_CAND_SRC_QUEUE)
        fcd_raise(c, FCD_DELIVERED);
}

void zcl_fmc_cand_note_proven(struct zcl_fmc_cand_reg *reg, const char *id,
                              long long age_s, bool age_known)
{
    struct zcl_fmc_cand *c = fcd_row(reg, id);
    if (!c)
        return;
    c->sources |= ZCL_FMC_CAND_SRC_QUEUE;
    c->proven = true;
    fcd_age(c, age_s, age_known);
    fcd_raise(c, FCD_PROVEN);
}

void zcl_fmc_cand_note_landed(struct zcl_fmc_cand_reg *reg, const char *id,
                              const char *attester, long long age_s,
                              bool age_known)
{
    struct zcl_fmc_cand *c = fcd_row(reg, id);
    if (!c)
        return;
    c->landed_attested = true;
    fcd_attest(c, attester);
    fcd_age(c, age_s, age_known);
    fcd_raise(c, FCD_LANDED);
}

/* Why this row is not stronger than it is. One token, always. */
static const char *fcd_reason(const struct zcl_fmc_cand *c)
{
    if (c->state == FCD_UNKNOWN)
        return FCD_NO_EVIDENCE;
    if (c->age_unparsable && !c->age_known)
        return FCD_AGE_UNKNOWN;
    if (!c->landed_attested)
        return FCD_LANDING_UNATTESTED;
    return FCD_UNVERIFIED;
}

static bool fcd_push_null(struct json_value *obj, const char *key)
{
    struct json_value nv;
    bool ok;
    json_init(&nv);
    json_set_null(&nv);
    ok = json_push_kv(obj, key, &nv);
    json_free(&nv);
    return ok;
}

static void fcd_emit_sources(struct json_value *o,
                             const struct zcl_fmc_cand *c)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    if (c->sources & ZCL_FMC_CAND_SRC_MAIL) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, "mail");
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    if (c->sources & ZCL_FMC_CAND_SRC_BOARD) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, "board");
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    if (c->sources & ZCL_FMC_CAND_SRC_QUEUE) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, "queue");
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(o, "sources", &arr);
    json_free(&arr);
}

static void fcd_emit_attesters(struct json_value *o,
                               const struct zcl_fmc_cand *c)
{
    struct json_value arr;
    unsigned i, shown = c->attesters;
    json_init(&arr);
    json_set_array(&arr);
    if (shown > ZCL_FMC_CAND_ATTESTERS)
        shown = ZCL_FMC_CAND_ATTESTERS;
    for (i = 0; i < shown; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, c->attester[i]);
        (void)json_push_back(&arr, &s);
        json_free(&s);
    }
    (void)json_push_kv(o, "attesters", &arr);
    json_free(&arr);
    if (c->attesters_incomplete)
        (void)fcd_push_null(o, "attester_count");
    else
        (void)json_push_kv_int(o, "attester_count", (long long)c->attesters);
    (void)json_push_kv_bool(o, "attesters_complete", !c->attesters_incomplete);
}

static void fcd_emit_row(struct json_value *out,
                         const struct zcl_fmc_cand *c)
{
    struct json_value o;
    json_init(&o);
    json_set_object(&o);
    (void)json_push_kv_str(&o, "id", c->id);
    (void)json_push_kv_str(&o, "state", fcd_state_name(c->state));
    (void)json_push_kv_str(&o, "reason", fcd_reason(c));
    (void)json_push_kv_str(&o, "age_basis", "latest_sighting");
    fcd_emit_sources(&o, c);
    fcd_emit_attesters(&o, c);
    if (c->age_known)
        (void)json_push_kv_int(&o, "evidence_age_s", c->age_s);
    else
        (void)fcd_push_null(&o, "evidence_age_s");
    /* These inputs are reports. No verified receipt is supplied here. */
    (void)fcd_push_null(&o, "landed");
    (void)fcd_push_null(&o, "proven");
    (void)json_push_kv_str(&o, "test_state", c->proven ? "reported_pass" : "unknown");
    (void)json_push_kv_str(&o, "publication_state", c->landed_attested ? "reported_landed" : "unknown");
    (void)json_push_kv_str(&o, "remote_verification_state", "unknown");
    (void)json_push_back(out, &o);
    json_free(&o);
}

/* A source the registry never got to read. Same {source, reason, age_ms}
 * shape the rest of missing[] uses, so one consumer parses them all; the
 * age is -1 because no attempt was timed here, and -1 is not a duration. */
static void fcd_missing(struct json_value *missing, const char *source)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    if (json_push_kv_str(&item, "source", source) &&
        json_push_kv_str(&item, "reason", "source-unread") &&
        json_push_kv_int(&item, "age_ms", -1))
        (void)json_push_back(missing, &item);
    json_free(&item);
}

void zcl_fmc_cand_emit(const struct zcl_fmc_cand_reg *reg,
                       struct json_value *out, struct json_value *summary,
                       struct json_value *missing)
{
    size_t i;
    bool complete;
    if (!reg || !out)
        return;
    for (i = 0; i < reg->count; i++)
        fcd_emit_row(out, &reg->row[i]);
    if (!summary)
        return;
    complete = reg->mail_ok && reg->board_ok && reg->queue_ok && reg->dropped == 0;
    /* The total is only a number when every source was actually read.
     * With a source missing, the count of what exists is UNKNOWN, and
     * emitting reg->count there would quietly present a floor as a total. */
    if (complete)
        (void)json_push_kv_int(summary, "candidates_total",
                               (long long)reg->count);
    else
        (void)fcd_push_null(summary, "candidates_total");
    (void)json_push_kv_int(summary, "candidates_shown", (long long)reg->count);
    (void)json_push_kv_int(summary, "candidates_dropped",
                           (long long)reg->dropped);
    (void)json_push_kv_bool(summary, "candidates_complete", complete);
    if (!missing)
        return;
    if (!reg->mail_ok)
        fcd_missing(missing, "candidates.mail");
    if (!reg->board_ok)
        fcd_missing(missing, "candidates.board");
    if (!reg->queue_ok)
        fcd_missing(missing, "candidates.queue");
}
