/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The record shape, the chain rule, and why this file is not the binary
 * chainlog are all in engine/engine_receipt.h. Read that first.
 *
 * This file is the one place in engine/modules/engine that touches a file
 * descriptor. Everything else in the module is a pure function of its
 * arguments, and that property is worth naming rather than losing quietly:
 * the append here opens one path the caller named, reads its tail, and
 * appends one line. It resolves no path of its own, follows no environment
 * variable, and writes nothing anywhere else.
 */

#include "engine/engine_receipt.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <string.h>

static const char *or_empty(const char *s)
{
    return s ? s : "";
}

static void sha3_hex(const char *data, size_t len, char out[65])
{
    uint8_t digest[32];
    zcl_sha3_256((const unsigned char *)data, len, digest);
    zcl_hex_encode(digest, 32, out);
    out[64] = '\0';
}

/* Read the last complete line of `path` into `line`, without its newline.
 *
 * A file whose final byte is not a newline has a torn tail: some earlier
 * append did not finish. That is refused rather than repaired, because the
 * two available repairs — hashing the partial line, or dropping it — both
 * produce a chain that verifies over a history that is not what happened.
 *
 * Returns 1 with `line` filled, 0 when the file does not exist or is empty
 * (a genesis append), and -1 on a refusal. */
static int read_last_line(const char *path, char *line, size_t cap)
{
    line[0] = '\0';
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;             /* absent is an empty chain, not an error */
    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        LOG_ERR("engine_receipt", "cannot seek %s", path);
    }
    const long size = ftell(f);
    if (size < 0) {
        (void)fclose(f);
        LOG_ERR("engine_receipt", "cannot size %s", path);
    }
    if (size == 0) {
        (void)fclose(f);
        return 0;
    }
    /* One line is bounded, so the tail we must look at is bounded too. */
    const size_t window = (size_t)size < cap ? (size_t)size : cap;
    if (fseek(f, size - (long)window, SEEK_SET) != 0) {
        (void)fclose(f);
        LOG_ERR("engine_receipt", "cannot seek the tail of %s", path);
    }
    char *buf = line;
    const size_t got = fread(buf, 1, window, f);
    (void)fclose(f);
    if (got != window)
        LOG_ERR("engine_receipt", "short read of the tail of %s", path);
    if (buf[got - 1] != '\n')
        LOG_ERR("engine_receipt",
                "refusing to append to %s: its last line has no newline, so a "
                "previous append did not finish and the chain cannot be "
                "continued honestly", path);
    /* Drop the trailing newline, then find the start of that final line. */
    size_t end = got - 1;
    size_t start = 0;
    for (size_t i = end; i > 0; i--) {
        if (buf[i - 1] == '\n') {
            start = i;
            break;
        }
    }
    if (start == 0 && (size_t)size > window)
        LOG_ERR("engine_receipt",
                "refusing %s: its last line is longer than the %zu-byte cap",
                path, cap);
    const size_t n = end - start;
    memmove(line, buf + start, n);
    line[n] = '\0';
    return 1;
}

/* SHA3-256("zcl.engine_unit.id.v1\0" || task || "\0" || engine || "\0" || ts)
 * — see the header for why a same-second repeat is deliberately the same id. */
static void unit_id_of(const char *task_sha3, const char *engine, int64_t ts,
                       char out[65])
{
    char ts_dec[32];
    (void)snprintf(ts_dec, sizeof(ts_dec), "%lld", (long long)ts);
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    static const char k_domain[] = "zcl.engine_unit.id.v1";
    sha3_256_write(&ctx, (const unsigned char *)k_domain, sizeof(k_domain));
    sha3_256_write(&ctx, (const unsigned char *)or_empty(task_sha3),
                   strlen(or_empty(task_sha3)) + 1u);
    sha3_256_write(&ctx, (const unsigned char *)or_empty(engine),
                   strlen(or_empty(engine)) + 1u);
    sha3_256_write(&ctx, (const unsigned char *)ts_dec, strlen(ts_dec));
    uint8_t digest[32];
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, 32, out);
    out[64] = '\0';
}

static bool build_line(const struct engine_receipt *r, const char *prev_sha3,
                       char *out, size_t cap, size_t *out_len)
{
    char unit_id[65];
    unit_id_of(r->task_sha3, r->engine, r->ts, unit_id);

    struct json_value rules;
    json_init(&rules);
    json_set_array(&rules);
    bool ok = true;
    for (size_t i = 0; ok && i < r->rules_count; i++) {
        struct json_value s;
        json_init(&s);
        json_set_str(&s, or_empty(r->rules_shown ? r->rules_shown[i] : NULL));
        ok = json_push_back(&rules, &s);
        json_free(&s);
    }

    struct json_value outcome;
    json_init(&outcome);
    json_set_object(&outcome);
    ok = ok
        && json_push_kv_bool(&outcome, "applied", r->outcome.applied)
        && json_push_kv_int(&outcome, "groups_ran", r->outcome.groups_ran)
        && json_push_kv_int(&outcome, "groups_failed", r->outcome.groups_failed)
        && json_push_kv_bool(&outcome, "gate_pass", r->outcome.gate_pass)
        && json_push_kv_int(&outcome, "retries", r->outcome.retries)
        && json_push_kv_int(&outcome, "lines_changed", r->outcome.lines_changed)
        && json_push_kv_int(&outcome, "lint_rc", r->outcome.lint_rc);

    struct json_value doc;
    json_init(&doc);
    json_set_object(&doc);
    ok = ok
        && json_push_kv_str(&doc, "schema", ENGINE_RECEIPT_SCHEMA)
        && json_push_kv_str(&doc, "prev_sha3", prev_sha3)
        && json_push_kv_str(&doc, "unit_id", unit_id)
        && json_push_kv_int(&doc, "ts", r->ts)
        && json_push_kv_str(&doc, "engine", or_empty(r->engine))
        && json_push_kv_str(&doc, "model", or_empty(r->model))
        && json_push_kv_str(&doc, "kind", or_empty(r->kind))
        && json_push_kv_str(&doc, "template_sha3", or_empty(r->template_sha3))
        && json_push_kv(&doc, "rules_shown", &rules)
        && json_push_kv_str(&doc, "task_sha3", or_empty(r->task_sha3))
        && json_push_kv_str(&doc, "group", or_empty(r->group))
        && json_push_kv_int(&doc, "prompt_tokens", r->prompt_tokens)
        && json_push_kv_int(&doc, "completion_tokens", r->completion_tokens)
        && json_push_kv_int(&doc, "wall_ms", r->wall_ms)
        && json_push_kv_int(&doc, "http_status", r->http_status)
        && json_push_kv(&doc, "outcome", &outcome)
        && json_push_kv_str(&doc, "worktree_head", or_empty(r->worktree_head));
    json_free(&rules);
    json_free(&outcome);
    if (!ok) {
        json_free(&doc);
        LOG_FAIL("engine_receipt", "cannot assemble the receipt document");
    }
    const size_t n = json_write(&doc, out, cap);
    json_free(&doc);
    if (n >= cap)
        LOG_FAIL("engine_receipt",
                 "refusing a %zu-byte receipt line: over the %u-byte cap. A "
                 "truncated line would break every link after it and read as "
                 "tampering", n, (unsigned)ENGINE_RECEIPT_LINE_MAX);
    *out_len = n;
    return true;
}

bool engine_receipt_append(const char *path, const struct engine_receipt *r,
                           char *out_line_sha3)
{
    if (out_line_sha3)
        out_line_sha3[0] = '\0';
    if (!path || !path[0] || !r)
        LOG_FAIL("engine_receipt", "refusing an append with no path or record");
    if (!r->engine || !r->engine[0])
        LOG_FAIL("engine_receipt",
                 "refusing a receipt with no engine id: a cost nobody can "
                 "attribute is not a measurement");
    if (r->rules_count > ENGINE_RECEIPT_RULES_MAX)
        LOG_FAIL("engine_receipt",
                 "refusing %zu rule ids: over the cap of %u", r->rules_count,
                 (unsigned)ENGINE_RECEIPT_RULES_MAX);

    char last[ENGINE_RECEIPT_LINE_MAX + 2u];
    const int have = read_last_line(path, last, ENGINE_RECEIPT_LINE_MAX + 1u);
    if (have < 0)
        return false;

    char prev[65];
    if (have == 1) {
        sha3_hex(last, strlen(last), prev);
    } else {
        /* Genesis. 64 zeros, never an empty string: a reader that cannot
         * tell "first record" from "field missing" cannot tell a new file
         * from a spliced one. */
        memset(prev, '0', 64);
        prev[64] = '\0';
    }

    char line[ENGINE_RECEIPT_LINE_MAX + 2u];
    size_t len = 0;
    if (!build_line(r, prev, line, ENGINE_RECEIPT_LINE_MAX, &len))
        return false;

    FILE *f = fopen(path, "ab");
    if (!f)
        LOG_FAIL("engine_receipt", "cannot open %s for append", path);
    line[len] = '\n';
    const size_t wrote = fwrite(line, 1, len + 1u, f);
    const bool flushed = (fflush(f) == 0);
    const bool closed = (fclose(f) == 0);
    if (wrote != len + 1u || !flushed || !closed)
        LOG_FAIL("engine_receipt", "short write appending to %s", path);
    if (out_line_sha3)
        sha3_hex(line, len, out_line_sha3);
    return true;
}

bool engine_receipt_verify_chain(const char *path,
                                 struct engine_receipt_chain_report *report)
{
    if (!report)
        LOG_FAIL("engine_receipt", "verify needs a report to fill");
    memset(report, 0, sizeof(*report));
    memset(report->head_sha3, '0', 64);
    report->head_sha3[64] = '\0';
    if (!path || !path[0])
        LOG_FAIL("engine_receipt", "verify needs a path");

    FILE *f = fopen(path, "rb");
    if (!f)
        return true;          /* no file is an empty chain, not a broken one */

    char expect[65];
    memset(expect, '0', 64);
    expect[64] = '\0';

    char line[ENGINE_RECEIPT_LINE_MAX + 2u];
    uint64_t lineno = 0;
    bool ok = true;
    while (ok && fgets(line, (int)sizeof(line), f)) {
        lineno++;
        size_t n = strlen(line);
        if (n == 0 || line[n - 1] != '\n') {
            report->first_bad_line = lineno;
            (void)snprintf(report->why, sizeof(report->why),
                           "line %llu has no newline: an append did not finish",
                           (unsigned long long)lineno);
            ok = false;
            break;
        }
        line[--n] = '\0';

        struct json_value doc;
        json_init(&doc);
        if (!json_read(&doc, line, n) || doc.type != JSON_OBJ) {
            json_free(&doc);
            report->first_bad_line = lineno;
            (void)snprintf(report->why, sizeof(report->why),
                           "line %llu is not a JSON object",
                           (unsigned long long)lineno);
            ok = false;
            break;
        }
        const struct json_value *pv = json_get(&doc, "prev_sha3");
        const char *ps = (pv && pv->type == JSON_STR) ? json_get_str(pv) : NULL;
        const bool linked = ps && strcmp(ps, expect) == 0;
        json_free(&doc);
        if (!linked) {
            report->first_bad_line = lineno;
            (void)snprintf(report->why, sizeof(report->why),
                           "line %llu carries the wrong prev_sha3: an earlier "
                           "line was edited, removed, or reordered",
                           (unsigned long long)lineno);
            ok = false;
            break;
        }
        sha3_hex(line, n, expect);
        (void)snprintf(report->head_sha3, sizeof(report->head_sha3), "%s",
                       expect);
        report->records++;
    }
    (void)fclose(f);
    return ok;
}
