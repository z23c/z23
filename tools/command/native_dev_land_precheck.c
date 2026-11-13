/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land precheck -- the cheap deterministic lint gates a lane
 *          runs locally before `dev land submit` queues it or `dev land send`
 *          bundles it. See native_dev_land_precheck.h for the contract.
 *
 * Core gates run directly; file-purpose uses the canonical runner command.
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include "command/native_dev_land_precheck.h"

#include "command/native_command.h"
#include "command/native_dev_land_internal.h"
#include "command/native_fleet.h"
#include "dev_proof.h"
#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"
#include "platform/rng.h"

#include "base/safe_alloc.h"
#include "base/hex.h"
#include "json/json.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#define PC_TAIL_BYTES (4u * 1024u * 1024u)
#define PC_OUT_CAP (128u * 1024u)
#define PC_EVIDENCE_CAP 4096u
#define PC_TEXT_CAP 1600u
#define PC_SHIP_GATE "check-ship-remote-transaction"
#define PC_DEPFILE_GATE "check-make-depfile-scope-selftest"
#define PC_DEPFILE_BIN "build/bin/depfile-scope-launch"

static const char *const k_pc_core[] = {
    "check-file-size-ceiling", "check-cyclomatic-complexity",
    "check-core-seal", "check-arm-symbol-single",
    /* Candidate-content ratchets that failed seven landings in a week; each
     * measured under 5 s (under 20 s together) on a loaded host. */
    "check-kpi-floor", "check-describe-budget", "check-hardening-ratchet",
};

/* What to do about a refused gate, named in the refusal body. */
static const struct {
    const char *gate, *hint;
} k_pc_hints[] = {
    {"check-kpi-floor", "a tracked KPI fell below its recorded floor; "
                        "restore the metric, never lower the floor"},
    {"check-describe-budget", "a describe leaf exceeds its byte budget; "
                              "shorten the leaf text, never raise the budget"},
    {"check-hardening-ratchet", "a hardening finding count rose; remove the "
                                "finding, never raise the baseline"},
    {"check-file-size-ceiling", "a production C file passed the 1500-line "
                                "ceiling or grew past its baseline; split it "
                                "along a seam, never raise the baseline"},
};

/* The file-size gate is a make target over its own binary, not a z23-lint
 * gate, so `z23-lint --list` never names it and it used to be skipped. */
#define PC_SIZE_GATE "check-file-size-ceiling"
#define PC_SIZE_BIN "build/bin/file_size_policy"

#if defined(ZCL_TESTING)
static bool g_pc_force;
static _Thread_local int64_t g_pc_now;
static _Thread_local int64_t g_pc_budget_ms;
static _Thread_local int64_t g_pc_clock_step, g_pc_clock_value;
void zcl_dev_land_precheck_test_clock(int64_t step_ms)
{
    g_pc_clock_step = step_ms > 0 ? step_ms : 0;
    g_pc_clock_value = 0;
}
void zcl_dev_land_precheck_test_budget(int64_t budget_ms)
{
    g_pc_budget_ms = budget_ms > 0 ? budget_ms : 0;
}
void zcl_dev_land_precheck_test_now(int64_t now_s)
{
    g_pc_now = now_s > 0 ? now_s : 0;
}

void zcl_dev_land_precheck_test_force(bool on)
{
    g_pc_force = on;
}
#endif

static int64_t pc_monotonic_ms(void)
{
#if defined(ZCL_TESTING)
    if (g_pc_clock_step) {
        int64_t now = g_pc_clock_value;
        g_pc_clock_value += g_pc_clock_step;
        return now;
    }
#endif
    return platform_time_monotonic_ms();
}

/* ── gate set ──────────────────────────────────────────────────────────── */

static bool pc_gate_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
}

static void pc_gate_add(struct zcl_land_precheck_gates *g, const char *name,
                        size_t len)
{
    if (len <= 6 || len >= ZCL_LAND_PRECHECK_GATE_MAX ||
        g->count >= ZCL_LAND_PRECHECK_MAX_GATES)
        return;
    for (size_t i = 0; i < g->count; i++) {
        if (strlen(g->name[i]) == len && memcmp(g->name[i], name, len) == 0)
            return;
    }
    memcpy(g->name[g->count], name, len);
    g->name[g->count][len] = '\0';
    g->count++;
}

/* Every check-* word of `text`, added to the set. */
static void pc_gates_from_text(const char *text,
                               struct zcl_land_precheck_gates *g)
{
    for (const char *p = text; (p = strstr(p, "check-")) != NULL;) {
        size_t n = 0;
        if (p != text && pc_gate_char(p[-1])) {
            p += 6;
            continue;
        }
        while (pc_gate_char(p[n]))
            n++;
        while (n > 0 && p[n - 1] == '-')
            n--;
        pc_gate_add(g, p, n);
        p += n > 0 ? n : 6;
    }
}

/* Unix seconds of "YYYY-MM-DDTHH:MM:SSZ", or -1. */
static int64_t pc_ts_parse(const char *ts)
{
    int y, mo, d, h, mi, s;
    int64_t era, yoe, doy, doe;
    if (!ts || sscanf(ts, "%d-%d-%dT%d:%d:%dZ", &y, &mo, &d, &h, &mi, &s) != 6 ||
        mo < 1 || mo > 12 || d < 1 || d > 31)
        return -1;
    y -= mo <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (era * 146097 + doe - 719468) * 86400 + h * 3600 + mi * 60 + s;
}

struct pc_line {
    long long seq;
    size_t off, len;
};

/* The last DL tail of the ledger, minus a cut first line. */
static char *pc_tail_read(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    char *text;
    long size;
    size_t start = 0, got, skip = 0;
    *len = 0;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (size = ftell(f)) < 0) {
        (void)fclose(f);
        return NULL;
    }
    if ((size_t)size > PC_TAIL_BYTES)
        start = (size_t)size - PC_TAIL_BYTES;
    text = zcl_malloc(PC_TAIL_BYTES + 1, "dev_land_precheck.tail");
    if (fseek(f, (long)start, SEEK_SET) != 0) {
        (void)fclose(f);
        free(text);
        return NULL;
    }
    got = fread(text, 1, PC_TAIL_BYTES, f);
    (void)fclose(f);
    text[got] = '\0';
    if (start > 0) {
        const char *nl = memchr(text, '\n', got);
        skip = nl ? (size_t)(nl - text) + 1 : got;
    }
    memmove(text, text + skip, got - skip + 1);
    *len = got - skip;
    return text;
}

/* One ledger line as a JSON object, or false. */
static bool pc_line_parse(const char *text, size_t len, struct json_value *doc)
{
    json_init(doc);
    if (json_read(doc, text, len) && doc->type == JSON_OBJ)
        return true;
    json_free(doc);
    return false;
}

static const char *pc_str(const struct json_value *doc, const char *key)
{
    const struct json_value *v = json_get(doc, key);
    const char *s = v && v->type == JSON_STR ? json_get_str(v) : NULL;
    return s ? s : "";
}

/* Remember the newest line of each seq: a later line replaces an earlier. */
static bool pc_line_note(struct pc_line **lines, size_t *n, size_t *cap,
                         long long seq, size_t off, size_t len)
{
    for (size_t i = 0; i < *n; i++) {
        if ((*lines)[i].seq == seq) {
            (*lines)[i].off = off;
            (*lines)[i].len = len;
            return true;
        }
    }
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 256;
        *lines = zcl_realloc(*lines, *cap * sizeof(**lines),
                             "dev_land_precheck.lines");
    }
    (*lines)[(*n)++] = (struct pc_line){seq, off, len};
    return true;
}

static void pc_learn_row(const struct json_value *doc, int64_t now_s,
                         struct zcl_land_precheck_gates *g)
{
    char text[PC_TEXT_CAP];
    int64_t ts = pc_ts_parse(pc_str(doc, "ts"));
    if (strcmp(pc_str(doc, "state"), "failed") != 0 ||
        strcmp(pc_str(doc, "dimension"), "lint") != 0 || ts < 0 ||
        ts < now_s - ZCL_LAND_PRECHECK_WINDOW_S)
        return;
    (void)snprintf(text, sizeof(text), "%s %s", pc_str(doc, "detail"),
                   pc_str(doc, "note"));
    pc_gates_from_text(text, g);
}

void zcl_land_precheck_gate_set(const char *outcomes_path, int64_t now_s,
                                struct zcl_land_precheck_gates *out)
{
    struct pc_line *lines = NULL;
    size_t n = 0, cap = 0, len = 0;
    char *text;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < sizeof(k_pc_core) / sizeof(k_pc_core[0]); i++)
        pc_gate_add(out, k_pc_core[i], strlen(k_pc_core[i]));
    text = outcomes_path ? pc_tail_read(outcomes_path, &len) : NULL;
    if (!text)
        return;
    for (size_t off = 0; off < len;) {
        const char *nl = memchr(text + off, '\n', len - off);
        size_t end = nl ? (size_t)(nl - text) : len;
        struct json_value doc;
        if (pc_line_parse(text + off, end - off, &doc)) {
            const struct json_value *seq = json_get(&doc, "seq");
            if (seq && seq->type == JSON_INT)
                (void)pc_line_note(&lines, &n, &cap, json_get_int(seq), off,
                                   end - off);
            json_free(&doc);
        }
        off = end + 1;
    }
    for (size_t i = 0; i < n; i++) {
        struct json_value doc;
        if (!pc_line_parse(text + lines[i].off, lines[i].len, &doc))
            continue;
        pc_learn_row(&doc, now_s, out);
        json_free(&doc);
    }
    free(lines);
    free(text);
}

/* ── budget ────────────────────────────────────────────────────────────── */

int64_t zcl_land_precheck_budget_ms(int64_t cpus, int64_t load5_centi)
{
    const int64_t base = ZCL_LAND_PRECHECK_BUDGET_MS;
    const int64_t cap = base * ZCL_LAND_PRECHECK_BUDGET_MAX_SCALE;
    if (cpus <= 0 || load5_centi <= 0 || cpus > INT32_MAX)
        return base;
    /* Decide the cap by ratio first, so the product below stays bounded
     * (load5_centi < 100 * scale * cpus) for every valid input. */
    if (load5_centi / cpus >= 100 * (int64_t)ZCL_LAND_PRECHECK_BUDGET_MAX_SCALE)
        return cap;
    int64_t scaled = base * load5_centi / (100 * cpus);
    return scaled < base ? base : scaled > cap ? cap : scaled;
}

static int64_t pc_budget_ms(void)
{
    struct zcl_fleet_vitals_now now;
    zcl_fleet_vitals_measure(&now);
    return zcl_land_precheck_budget_ms(now.cpus, now.load5_centi);
}
int64_t zcl_land_precheck_budget_floor(int64_t automatic_ms, int64_t floor_ms)
{
    return floor_ms > automatic_ms ? floor_ms : automatic_ms;
}

/* ── running ───────────────────────────────────────────────────────────── */

static void pc_fail(struct zcl_command_reply *reply, const char *leaf,
                    const char *code, const char *msg, const char *evidence)
{
    (void)json_push_kv_str(&reply->data, "leaf", leaf);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_FAILED, code, "precheck", false,
                           false, msg, evidence);
    reply->error.human_action_required = true;
}
bool zcl_dev_land_precheck_input_valid(const struct json_value *input,
                                      bool checked_elsewhere, struct zcl_command_reply *reply)
{
    const struct json_value *budget = json_get(input, "precheck_budget_ms");
    const char *mode = json_get_str(json_get(input, "precheck"));
    if (!budget) return true;
    if (budget->type == JSON_INT && json_get_int(budget) >= 180000 &&
        json_get_int(budget) <= 720000 && !checked_elsewhere &&
        !json_get_bool(json_get(input, "qualify")) && strcmp(mode, "skip")) return true;
    pc_fail(reply, "dev.land.submit", "BAD_INPUT",
        "precheck_budget_ms requires a running precheck and must be 180000..720000", "precheck_budget_ms");
    return false;
}

static void pc_push_names(struct zcl_command_reply *reply, const char *key,
                          const char *const *names, size_t n)
{
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; i < n; i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, names[i]);
        (void)json_push_back(&list, &item);
        json_free(&item);
    }
    (void)json_push_kv(&reply->data, key, &list);
    json_free(&list);
}

/* `bin gate` in `wt`, stderr folded into the capture. -1 on timeout. */
static int pc_run(const char *wt, const char *bin, const char *gate,
                  int64_t deadline_ms, char *out, size_t cap,
                  struct zcl_spawn_evidence *evidence)
{
    const char *argv[] = {"sh", "-c", "exec 2>&1; cd \"$1\" || exit 126; shift; exec \"$@\"",
                          "sh", wt, bin, gate, NULL};
    int64_t left = deadline_ms - pc_monotonic_ms();
    int rc;
    out[0] = '\0';
    memset(evidence, 0, sizeof(*evidence));
    if (left <= 0)
        return -1;
    rc = zcl_spawn_capture_evidence(argv, out, cap, (int)left, evidence);
    return evidence->timed_out ? -1 : rc;
}

/* The first ZCL_LAND_PRECHECK_SHOW_LINES lines of `out`. */
static void pc_head_lines(const char *out, char *ev, size_t cap)
{
    size_t used = 0, lines = 0;
    for (const char *p = out; *p && lines < ZCL_LAND_PRECHECK_SHOW_LINES;
         lines++) {
        size_t n = strcspn(p, "\n");
        if (used + n + 2 > cap)
            break;
        memcpy(ev + used, p, n);
        used += n;
        ev[used++] = '\n';
        p += n + (p[n] == '\n' ? 1 : 0);
    }
    ev[used] = '\0';
}

static bool pc_known(const char *list, const char *gate)
{
    size_t n = strlen(gate);
    for (const char *p = list; *p;) {
        size_t l = strcspn(p, "\n");
        if (l == n && memcmp(p, gate, n) == 0)
            return true;
        p += l + (p[l] == '\n' ? 1 : 0);
    }
    return false;
}

/* A gate that exits PC_EXIT_UNPROVEN cannot decide here: an input is absent
 * or the environment is incomplete. It is skipped, not refused. */
#define PC_EXIT_UNPROVEN 2

struct pc_run {
    const char *leaf, *wt;
    char bin[4096 + 32];
    char *out;
    int64_t deadline, budget_ms;
    const char *skipped[ZCL_LAND_PRECHECK_MAX_GATES];
    const char *ran[ZCL_LAND_PRECHECK_MAX_GATES];
    int64_t elapsed_ms[ZCL_LAND_PRECHECK_MAX_GATES];
    char unproven[PC_EVIDENCE_CAP];
    size_t nskipped, nran;
    bool gate_output_available;
    char land[4096];
    struct zcl_spawn_evidence capture;
};

static void pc_history_unproven(struct pc_run *r, const char *reason)
{
    (void)snprintf(r->unproven, sizeof(r->unproven), "proof-history: %s", reason);
}

#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
struct pc_history {
    struct zcl_land_precheck_gates gates;
    int64_t now;
    const char *uncertain_reason;
    char uncertain_attempt[sizeof(((struct zcl_dev_proof_history_failure *)0)->attempt)];
};

/* Retain the first visited uncertainty; directory order is not chronology. */
static void pc_history_uncertain(struct pc_history *h,
                                  const struct zcl_dev_proof_history_failure *row,
                                  const char *reason)
{
    if (h->uncertain_reason) return;
    h->uncertain_reason = reason;
    (void)snprintf(h->uncertain_attempt, sizeof(h->uncertain_attempt), "%s", row->attempt);
}

static bool pc_history_request_recent(struct pc_history *h,
                                       const struct zcl_dev_proof_history_failure *row)
{
    if (row->request_started_unix > h->now) {
        pc_history_uncertain(h, row, "future-request-start");
        return false;
    }
    if (row->request_started_unix < h->now - ZCL_LAND_PRECHECK_WINDOW_S) {
        pc_history_uncertain(h, row, "old-request-start");
        return false;
    }
    return true;
}

static bool pc_recording_expired(const struct zcl_dev_proof_history_failure *row,
                                 int64_t now)
{
    return row->time_state == ZCL_PROOF_HISTORY_TIME_BOUND_RECORDING &&
        row->recorded_unix <= now &&
        row->recorded_unix < now - ZCL_LAND_PRECHECK_WINDOW_S &&
        row->observation_state != ZCL_PROOF_HISTORY_OBSERVATION_UNUSABLE &&
        (row->observation_state != ZCL_PROOF_HISTORY_OBSERVATION_BOUND_UPPER ||
         row->observed_upper_unix <= now);
}

static bool pc_history_visit(const struct zcl_dev_proof_history_failure *row,
                              void *context)
{
    struct pc_history *h = context;
    if (row->classification != ZCL_PROOF_HISTORY_FAILURE) return true;
    if (!row->digest[0]) {
        if (pc_recording_expired(row, h->now))
            return true;
        if (row->observation_state == ZCL_PROOF_HISTORY_OBSERVATION_BOUND_UPPER &&
            row->observed_upper_unix <= h->now &&
            row->observed_upper_unix < h->now - ZCL_LAND_PRECHECK_WINDOW_S)
            return true;
        pc_history_uncertain(h, row, "missing-failure-detail");
        return true;
    }
    if (strncmp(row->digest, "lint:", 5) != 0 &&
        strncmp(row->digest, "lint ", 5) != 0) return true;
    /* A bound recording timestamp is an upper bound on when the failure
     * existed. It can prove expiration, never that the failure is recent. */
    if (pc_recording_expired(row, h->now))
        return true;
    if (row->observation_state == ZCL_PROOF_HISTORY_OBSERVATION_BOUND_UPPER) {
        if (row->observed_upper_unix > h->now)
            pc_history_uncertain(h, row, "future-observation-bound");
        else if (row->observed_upper_unix < h->now - ZCL_LAND_PRECHECK_WINDOW_S)
            return true; /* Failure existed no later than this old bound. */
    }
    /* A retained failure observed now and requested within the window is
     * definitely recent. An older request cannot date its eventual failure. */
    if (!pc_history_request_recent(h, row))
        return true;
    pc_gates_from_text(row->digest, &h->gates);
    return h->gates.count < ZCL_LAND_PRECHECK_MAX_GATES;
}

#endif

static int64_t pc_now(void)
{
#if defined(ZCL_TESTING)
    if (g_pc_now > 0) return g_pc_now;
#endif
    return (int64_t)platform_time_wall_time_t();
}

/* Merge only a complete read; no partial callback result escapes refusal. */
static void pc_history_learn(struct pc_run *r, const char *land,
                              struct zcl_land_precheck_gates *g)
{
#if defined(ZCL_DEV_BUILD) || defined(ZCL_TESTING)
    char path[4096 + 4], canonical[4096];
    if (snprintf(path, sizeof(path), "%s/wt", land) >= (int)sizeof(path) ||
        !platform_directory_canonical_real(path, canonical, sizeof(canonical))) {
        pc_history_unproven(r, "canonical land worktree unavailable");
        return;
    }
    struct pc_history *h = zcl_calloc(1, sizeof(*h), "dev_land_precheck.history");
    if (!h) {
        pc_history_unproven(r, "history allocation unavailable");
        return;
    }
    struct zcl_dev_proof_observation_report observation;
    bool observation_ok = zcl_dev_proof_observe_legacy_failures(canonical, &observation);
    h->now = pc_now();
    enum zcl_dev_proof_history_result result =
        zcl_dev_proof_history_failures(canonical, pc_history_visit, h);
    if (result != ZCL_PROOF_HISTORY_COMPLETE) {
        pc_history_unproven(r, "incomplete or unsafe retained attempt evidence; historical gates not merged");
    } else {
        struct zcl_land_precheck_gates merged = *g;
        for (size_t i = 0; i < h->gates.count; i++)
            pc_gate_add(&merged, h->gates.name[i], strlen(h->gates.name[i]));
        if (merged.count >= ZCL_LAND_PRECHECK_MAX_GATES)
            pc_history_unproven(r, "historical gate capacity reached; historical gates not merged");
        else {
            *g = merged;
            if (h->uncertain_reason) {
                char detail[320];
                (void)snprintf(detail, sizeof(detail),
                    "attempt=%s reason=%s; lint history remains uncertain",
                    h->uncertain_attempt, h->uncertain_reason);
                pc_history_unproven(r, detail);
            }
        }
    }
    if (!observation_ok)
        pc_history_unproven(r, "legacy observation incomplete; retained history coverage remains unproven");
    free(h);
#else
    (void)land;
    (void)g;
    pc_history_unproven(r, "native proof history requires a development build");
#endif
}

#if !defined(_WIN32)
static bool pc_ship_file(const char *path, int mode)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, mode) == 0;
}
#endif

static bool pc_ship_ready(struct pc_run *r)
{
#if defined(_WIN32)
    (void)snprintf(r->out, PC_OUT_CAP, "ship adapter unavailable on Windows");
    return false;
#else
    static const char *const required[] = {
        "tools/ship.sh", "tools/ship_selftest.sh",
        "build/bin/z23-lint", "build/bin/jsonq",
        "build/bin/z23-tor-provenance", "build/bin/check_no_hardlink_seeding"
    };
    char path[4096 + 80];
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        if (snprintf(path, sizeof(path), "%s/%s", r->wt, required[i]) >= (int)sizeof(path) ||
            !pc_ship_file(path, X_OK)) {
            (void)snprintf(r->out, PC_OUT_CAP, "ship prerequisite unavailable: %s", required[i]);
            return false;
        }
    }
    if (snprintf(path, sizeof(path), "%s/tools/scripts/ship_progress_lib.sh", r->wt) >= (int)sizeof(path) ||
        !pc_ship_file(path, R_OK)) {
        (void)snprintf(r->out, PC_OUT_CAP, "ship prerequisite unavailable: tools/scripts/ship_progress_lib.sh");
        return false;
    }
    return true;
#endif
}

static int pc_ship_run(struct pc_run *r)
{
    static const char *const commands[] = {
        "./tools/ship.sh", "./tools/ship_selftest.sh",
        "./build/bin/z23-lint"
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        int rc = pc_run(r->wt, commands[i],
                        i == 0 ? "--selftest"
                               : (i == 2 ? "check-ship-remote-transaction" : NULL),
                        r->deadline, r->out, PC_OUT_CAP, &r->capture);
        if (rc != 0) return rc;
    }
    return 0;
}

/* Appends "gate: first output line" for an unproven gate to r->unproven and
 * counts the gate as skipped. Both writes are bounded; a full buffer drops
 * the reason but never the skip. */
static void pc_note_unproven(struct pc_run *r, const char *gate)
{
    char line[160];
    size_t used = strlen(r->unproven), n = strcspn(r->out, "\r\n");
    if (n >= sizeof(line))
        n = sizeof(line) - 1;
    memcpy(line, r->out, n);
    line[n] = '\0';
    if (used > 0 && used + 2 < sizeof(r->unproven))
        (void)snprintf(r->unproven + used, sizeof(r->unproven) - used, "; ");
    used = strlen(r->unproven);
    if (used < sizeof(r->unproven))
        (void)snprintf(r->unproven + used, sizeof(r->unproven) - used,
                       "%s: %s", gate, line);
    r->skipped[r->nskipped++] = gate;
}

static void pc_push_unproven(const struct pc_run *r,
                             struct zcl_command_reply *reply)
{
    if (r->unproven[0])
        (void)json_push_kv_str(&reply->data, "precheck_unproven", r->unproven);
}

/* Retain the bounded raw prefix in the existing private land log directory. */
static bool pc_retain_capture(const struct pc_run *r, char *path, size_t cap)
{
    char root[4096], expected[4096], dir[4096], leaf[80], hex[33];
    uint8_t random[16];
    struct platform_private_staging file;
    if (!r->land[0] || !platform_state_root_existing(root, sizeof(root)) ||
        snprintf(expected, sizeof(expected), "%s/land", root) >= (int)sizeof(expected) ||
        strcmp(expected, r->land) || !platform_private_directory_ensure(r->land) ||
        snprintf(dir, sizeof(dir), "%s/logs", r->land) >= (int)sizeof(dir) ||
        !platform_private_directory_ensure(dir) || !rng_host_fill(random, sizeof(random)))
        return false;
    zcl_hex_encode(random, sizeof(random), hex);
    (void)snprintf(leaf, sizeof(leaf), "precheck-%s.log", hex);
    if (snprintf(path, cap, "development_state:land/logs/%s", leaf) >= (int)cap) return false;
    platform_private_staging_init(&file);
    if (!platform_private_staging_create(&file, dir, leaf)) return false;
    size_t n = r->capture.stdout_observed < PC_OUT_CAP - 1
        ? (size_t)r->capture.stdout_observed : PC_OUT_CAP - 1;
    bool ok = platform_private_file_write_at(&file.file, r->out, n, 0) &&
              platform_private_file_flush(&file.file) &&
              platform_private_parent_flush(dir);
    if (!ok) (void)platform_private_staging_retire(&file);
    platform_private_staging_close(&file);
    return ok;
}

/* The inline excerpt stops at NUL and escapes non-ASCII bytes for JSON. */
static void pc_escape_output(const char *source, char output[2048], size_t limit)
{
    size_t used = 0, wire = 0;
    for (const unsigned char *p = (const unsigned char *)source; *p; p++) {
        unsigned char c = *p;
        if (c >= 32 && c <= 126 && c != '\\') {
            size_t n = c == '"' ? 2 : 1;
            if (used + 1 >= 2048 || wire + n > limit) break;
            output[used++] = (char)c;
            wire += n;
        } else {
            if (used + 4 >= 2048 || wire + 5 > limit) break;
            output[used++] = '\\'; output[used++] = 'x';
            zcl_hex_encode(&c, 1, output + used);
            used += 2;
            wire += 5;
        }
    }
    output[used] = '\0';
}

static bool pc_stream_complete(const struct pc_run *r, bool timeout)
{
    return r->capture.stdout_complete && r->capture.stderr_complete && !timeout;
}

static bool pc_capture_sizes(struct pc_run *r, struct json_value *facts,
                             bool timeout, bool retained)
{
    uint64_t observed = r->capture.stdout_observed;
    int64_t count = observed > INT64_MAX ? INT64_MAX : (int64_t)observed;
    int64_t stored = observed < PC_OUT_CAP - 1 ? (int64_t)observed : PC_OUT_CAP - 1;
    int64_t stderr_count = r->capture.stderr_observed > INT64_MAX ? INT64_MAX :
        (int64_t)r->capture.stderr_observed;
    return json_push_kv_int(facts, "observed", count) &&
        json_push_kv_int(facts, "stderr", stderr_count) &&
        json_push_kv_int(facts, "bytes", retained ? stored : 0) &&
        json_push_kv_bool(facts, "truncated", r->capture.stdout_truncated) &&
        (timeout || (json_push_kv_bool(facts, "stream_complete", pc_stream_complete(r, timeout)) &&
        json_push_kv_bool(facts, "capture_complete", pc_stream_complete(r, timeout) &&
                          !r->capture.stdout_truncated && stderr_count == 0)));
}

static bool pc_capture_facts(struct pc_run *r, const char *gate,
                             struct json_value *facts, bool timeout)
{
    char path[512];
    bool retained = r->gate_output_available && pc_retain_capture(r, path, sizeof(path));
    return json_push_kv_str(facts, "gate", gate) &&
        json_push_kv_bool(facts, "retained", retained) &&
        pc_capture_sizes(r, facts, timeout, retained) &&
        (!retained || json_push_kv_str(facts, "ref", path));
}

static size_t pc_digit_extra(uint64_t count, size_t base)
{
    size_t digits = 1;
    if (count > INT64_MAX) count = INT64_MAX;
    while (count >= 10) { count /= 10; digits++; }
    return digits > base ? digits - base : 0;
}

static void pc_failure_facts(struct pc_run *r, const char *gate,
                             struct zcl_command_reply *reply, bool timeout)
{
    char output[2048];
    size_t gate_len = strlen(gate);
    size_t gate_extra = gate_len > 1038 ? 2047 : gate_len > 15 ? 2 * (gate_len - 15) : 0;
    size_t penalty = gate_extra +
        pc_digit_extra(r->capture.stdout_observed, 4) +
        pc_digit_extra(r->capture.stderr_observed, 1);
    size_t limit = penalty < 2047 ? 2047 - penalty : 0;
    pc_escape_output(r->out, output, limit);
    struct json_value facts;
    json_init(&facts);
    json_set_object(&facts);
    bool ok = pc_capture_facts(r, gate, &facts, timeout);
    if (timeout) ok = ok && json_push_kv_str(&facts, "output_ascii_escaped", output) &&
        json_push_kv_bool(&facts, "partial", true) &&
        json_push_kv_bool(&facts, "output_may_be_truncated", true);
    if (ok) (void)json_push_kv(&reply->data, "failure_facts", &facts);
    json_free(&facts);
}

static void pc_gate_failed(struct pc_run *r, const char *gate, int rc,
                           struct zcl_command_reply *reply)
{
    char ev[PC_EVIDENCE_CAP], msg[512];
    const char *hint = "fix and resubmit";
    for (size_t i = 0; i < sizeof(k_pc_hints) / sizeof(k_pc_hints[0]); i++)
        if (strcmp(k_pc_hints[i].gate, gate) == 0)
            hint = k_pc_hints[i].hint;
    if (rc < 0) {
        (void)snprintf(msg, sizeof(msg), "timeout: %ds",
                       (int)(r->budget_ms / 1000));
        if (r->gate_output_available)
            pc_failure_facts(r, gate, reply, true);
        pc_fail(reply, r->leaf, "PRECHECK_TIMEOUT", msg, gate);
        (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "inspect facts");
        return;
    }
    pc_head_lines(r->out, ev, sizeof(ev));
    pc_failure_facts(r, gate, reply, false);
    (void)snprintf(msg, sizeof(msg),
                   "precheck gate %s failed (exit %d); fix and resubmit: %s",
                   gate, rc, hint);
    (void)json_push_kv_str(&reply->data, "gate", gate);
    (void)json_push_kv_str(&reply->data, "hint", hint);
    pc_push_names(reply, "precheck_skipped", r->skipped, r->nskipped);
    pc_push_unproven(r, reply);
    pc_fail(reply, r->leaf, "PRECHECK_FAILED", msg, ev[0] ? ev : gate);
}

/* Resolve only the mode-sensitive gate through the canonical runner table.
 * Discovery, syntax validation and execution consume the same deadline. */
static int pc_canonical_capture(struct pc_run *r, const char *const argv[],
                                char *out, size_t cap)
{
    int64_t left = r->deadline - pc_monotonic_ms();
    memset(&r->capture, 0, sizeof(r->capture));
    out[0] = '\0';
    if (left <= 0)
        return -1;
    int rc = zcl_spawn_capture_evidence(argv, out, cap, (int)left, &r->capture);
    return r->capture.timed_out ? -1 : rc;
}

static bool pc_command_shape(char *command, size_t cap)
{
    size_t n = strlen(command);
    if (n == 0 || n >= cap - 1)
        return false;
    if (command[n - 1] == '\n')
        command[--n] = '\0';
    if (n == 0)
        return false;
    bool nonspace = false;
    for (size_t i = 0; i < n; i++) {
        nonspace = nonspace || command[i] != 32;
        if ((unsigned char)command[i] < 32 || command[i] == 127)
            return false;
    }
    return nonspace;
}

/* -2 distinguishes unavailable/malformed metadata from a gate's UNPROVEN. */
static int pc_file_purpose_run(struct pc_run *r)
{
    char command[4096];
    const char *reader[] = {"sh", "-c",
        "exec 2>&1; cd \"$1\" || exit 126; exec \"$2\" run --print-command check-file-purpose",
        "sh", r->wt, r->bin, NULL};
    int rc = pc_canonical_capture(r, reader, r->out, PC_OUT_CAP);
    r->gate_output_available = true;
    if (rc < 0)
        return -1;
    if (rc != 0 || r->capture.stdout_observed >= sizeof(command))
        return -2;
    memcpy(command, r->out, (size_t)r->capture.stdout_observed + 1);
    if (!pc_command_shape(command, sizeof(command))) return -2;
    const char *syntax[] = {"sh", "-c", "exec 2>&1; exec sh -n -c \"$1\"", "sh", command, NULL};
    rc = pc_canonical_capture(r, syntax, r->out, PC_OUT_CAP);
    if (rc < 0)
        return -1;
    if (rc != 0)
        return -2;
    const char *run[] = {"sh", "-c",
        "exec 2>&1; cd \"$1\" || exit 126; ZCL_LINT_PRODUCTION_SCAN=1 sh -c \"$2\"",
        "sh", r->wt, command, NULL};
    return pc_canonical_capture(r, run, r->out, PC_OUT_CAP);
}

/* The size gate's own binary, run in the lane. A missing binary cannot decide:
 * PC_EXIT_UNPROVEN, so the gate is named unproven and submit continues. */
static int pc_size_run(struct pc_run *r)
{
#if defined(_WIN32)
    (void)snprintf(r->out, PC_OUT_CAP, "size gate unavailable on Windows");
    return PC_EXIT_UNPROVEN;
#else
    char path[4096 + 40];
    if (snprintf(path, sizeof(path), "%s/%s", r->wt, PC_SIZE_BIN) >=
            (int)sizeof(path) || !pc_ship_file(path, X_OK)) {
        (void)snprintf(r->out, PC_OUT_CAP,
                       "prerequisite unavailable: %s (run: make file_size_policy)",
                       PC_SIZE_BIN);
        return PC_EXIT_UNPROVEN;
    }
    r->gate_output_available = true;
    return pc_run(r->wt, "./" PC_SIZE_BIN, NULL, r->deadline, r->out, PC_OUT_CAP, &r->capture);
#endif
}

/* Canonical script adapters, the file-purpose command, the size binary,
 * or `z23-lint GATE`. Script verdicts do not use lint's exit-2 convention. */
static int pc_gate_exec(struct pc_run *r, const char *gate, bool ship,
                        bool size)
{
    r->gate_output_available = false;
    if (strcmp(gate, "check-file-purpose") == 0)
        return pc_file_purpose_run(r);
    if (ship) {
        r->gate_output_available = true;
        return pc_ship_run(r);
    }
    if (size)
        return pc_size_run(r);
    r->gate_output_available = true;
    if (strcmp(gate, PC_DEPFILE_GATE) == 0)
        return pc_run(r->wt, "./" PC_DEPFILE_BIN, NULL,
                      r->deadline, r->out, PC_OUT_CAP, &r->capture);
    return pc_run(r->wt, r->bin, gate, r->deadline, r->out, PC_OUT_CAP, &r->capture);
}

/* Lane files a gate reads that a lane gated on a host (zgate builds in a
 * scratch directory, so the lane itself has no build/) never holds. Without
 * one the gate reports a false red, so it is unproven, never refused:
 * check-cookbook runs its recipes through build/bin/z23-dev; the windows
 * sweep compiles the generated guest-kernel TU (its make rule builds it
 * first, the precheck does not). Package anatomy and its doc-claim oracle
 * invoke the bounded KAT runner, also built by their make prerequisites. */
#if !defined(_WIN32)
static const struct {
    const char *gate, *file;
    int mode;
} k_pc_needs[] = {
    {"check-cookbook", "build/bin/z23-dev", X_OK},
    {"check-windows-cross-syntax", "build/gen/guest_kernel_data.c", R_OK},
    {"check-doc-claims", "build/bin/z23_bounded_run", X_OK},
    {"check-package-anatomy", "build/bin/z23_bounded_run", X_OK},
    {PC_DEPFILE_GATE, PC_DEPFILE_BIN, X_OK},
    {PC_DEPFILE_GATE, "Makefile", R_OK},
    {PC_DEPFILE_GATE, "tools/dev/make_depfile_scope_selftest.c", R_OK},
    {PC_DEPFILE_GATE, "tools/dev/make_depfile_scope_process.h", R_OK},
};

/* The launcher derives its root from its executable location. This is a
 * point-in-time location check, not executable freshness or identity proof. */
static bool pc_depfile_lane_launcher(const char *wt)
{
    char path[4096 + 80], expected[4096 + 80];
    int n = snprintf(path, sizeof(path), "%s/%s", wt, PC_DEPFILE_BIN);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;
    char *root = realpath(wt, NULL);
    char *actual = realpath(path, NULL);
    bool ok = false;
    if (root && actual) {
        n = snprintf(expected, sizeof(expected), "%s/%s", root, PC_DEPFILE_BIN);
        ok = n > 0 && (size_t)n < sizeof(expected) && strcmp(expected, actual) == 0;
    }
    free(root);
    free(actual);
    return ok;
}
#endif

/* The first lane file `gate` needs that is absent (named in r->out), or NULL. */
static const char *pc_missing_need(struct pc_run *r, const char *gate)
{
#if defined(_WIN32)
    if (strcmp(gate, PC_DEPFILE_GATE) == 0) {
        (void)snprintf(r->out, PC_OUT_CAP, "depfile launcher adapter unavailable on Windows");
        return PC_DEPFILE_BIN;
    }
    return NULL;
#else
    char path[4096 + 80];
    for (size_t i = 0; i < sizeof(k_pc_needs) / sizeof(k_pc_needs[0]); i++) {
        if (strcmp(k_pc_needs[i].gate, gate) != 0)
            continue;
        if (snprintf(path, sizeof(path), "%s/%s", r->wt, k_pc_needs[i].file) <
                (int)sizeof(path) && pc_ship_file(path, k_pc_needs[i].mode))
            continue;
        (void)snprintf(r->out, PC_OUT_CAP, "prerequisite unavailable: %s",
                       k_pc_needs[i].file);
        return k_pc_needs[i].file;
    }
    if (strcmp(gate, PC_DEPFILE_GATE) == 0 && !pc_depfile_lane_launcher(r->wt)) {
        (void)snprintf(r->out, PC_OUT_CAP, "prerequisite unavailable: %s (noncanonical launcher)",
                       PC_DEPFILE_BIN);
        return PC_DEPFILE_BIN;
    }
    return NULL;
#endif
}

enum pc_gate_state { PC_GATE_RAN, PC_GATE_SKIPPED, PC_GATE_REFUSED };

/* Diagnostic only: independent of the injected precheck deadline clock. */
static int pc_gate_timed(struct pc_run *r, const char *gate, bool ship, bool size)
{
    int64_t start = clock_now_monotonic_raw_us();
    int rc = pc_gate_exec(r, gate, ship, size);
    int64_t end = clock_now_monotonic_raw_us();
    if (rc == 0 && r->nran < ZCL_LAND_PRECHECK_MAX_GATES)
        r->elapsed_ms[r->nran] = start > 0 && end >= start ? (end - start) / 1000 : -1;
    return rc;
}

/* Passing-gate observations on successful submissions; unavailable clocks are null. */
static bool pc_push_timings(struct pc_run *r, struct zcl_command_reply *reply)
{
    struct json_value list; json_init(&list); json_set_array(&list);
    bool ok = list.type == JSON_ARR;
    for (size_t i = 0; ok && i < r->nran; i++) {
        struct json_value item, elapsed; json_init(&item); json_set_object(&item);
        json_init(&elapsed);
        if (r->elapsed_ms[i] >= 0) json_set_int(&elapsed, r->elapsed_ms[i]);
        else json_set_null(&elapsed);
        ok = item.type == JSON_OBJ && json_push_kv_str(&item, "gate", r->ran[i]) &&
            json_push_kv(&item, "elapsed_ms", &elapsed) && json_push_back(&list, &item);
        json_free(&elapsed); json_free(&item);
    }
    if (ok) ok = json_push_kv(&reply->data, "precheck_timings", &list);
    json_free(&list);
    return ok;
}

/* One gate: skipped (unknown or unproven), refused, or ran clean. */
static enum pc_gate_state pc_gate_one(struct pc_run *r, const char *gate,
                                      const char *list,
                                      struct zcl_command_reply *reply)
{
    bool ship = strcmp(gate, PC_SHIP_GATE) == 0;
    bool script = ship || strcmp(gate, PC_DEPFILE_GATE) == 0;
    bool size = strcmp(gate, PC_SIZE_GATE) == 0 && !pc_known(list, gate);
    int rc;
    if (ship && !pc_ship_ready(r)) {
        pc_note_unproven(r, gate);
        return PC_GATE_SKIPPED;
    }
    if (!script && !size && !pc_known(list, gate)) {
        r->skipped[r->nskipped++] = gate;
        return PC_GATE_SKIPPED;
    }
    if (pc_missing_need(r, gate)) {
        pc_note_unproven(r, gate);
        return PC_GATE_SKIPPED;
    }
    rc = pc_gate_timed(r, gate, ship, size);
    if (rc == -2&& strcmp(gate, "check-file-purpose") == 0) {
        pc_failure_facts(r, gate, reply, false);
        pc_fail(reply, r->leaf, "PRECHECK_UNAVAILABLE",
                "canonical file-purpose command could not be resolved safely",
                r->out);
        return PC_GATE_REFUSED;
    }
    if (!script && rc == PC_EXIT_UNPROVEN) {
        pc_note_unproven(r, gate);
        return PC_GATE_SKIPPED;
    }
    if (rc != 0) {
        pc_gate_failed(r, gate, rc, reply);
        return PC_GATE_REFUSED;
    }
    r->ran[r->nran++] = gate;
    return PC_GATE_RAN;
}

/* Prefer the source-only shell check to standalone tool compilation when
 * both were learned, without changing membership or the other gate order. */
static void pc_prioritize_shell(struct zcl_land_precheck_gates *g)
{
    size_t shell = g->count, standalone = g->count;
    for (size_t i = 0; i < g->count; i++) {
        if (!strcmp(g->name[i], "check-shell-host-assumptions")) shell = i;
        if (!strcmp(g->name[i], "check-standalone-tools-link")) standalone = i;
    }
    if (shell == g->count || standalone >= shell) return;
    char name[ZCL_LAND_PRECHECK_GATE_MAX];
    memcpy(name, g->name[shell], sizeof(name));
    memmove(g->name[standalone + 1], g->name[standalone],
            (shell - standalone) * sizeof(g->name[0]));
    memcpy(g->name[standalone], name, sizeof(name));
}

static bool pc_gates_run(struct pc_run *r,
                         const struct zcl_land_precheck_gates *g,
                         struct zcl_command_reply *reply)
{
    char list[PC_OUT_CAP / 4];
    int rc = pc_run(r->wt, r->bin, "--list", r->deadline, r->out, PC_OUT_CAP, &r->capture);
    if (rc != 0) {
        r->gate_output_available = true;
        pc_failure_facts(r, "--list", reply, rc < 0);
        pc_fail(reply, r->leaf, rc < 0 ? "PRECHECK_TIMEOUT" : "PRECHECK_UNAVAILABLE",
                "the lane's z23-lint --list did not answer; run `make "
                "build/bin/z23-lint docs-capability-inventory` in the lane, "
                "or resubmit with --precheck=skip",
                r->bin);
        return false;
    }
    (void)snprintf(list, sizeof(list), "%s", r->out);
    for (size_t i = 0; i < g->count; i++) {
        if (pc_gate_one(r, g->name[i], list, reply) == PC_GATE_REFUSED)
            return false;
    }
    return true;
}

static bool pc_land_dir(const char *land_dir, char *buf, size_t cap)
{
    char root[4096];
    if (land_dir)
        return snprintf(buf, cap, "%s", land_dir) < (int)cap;
    return platform_state_root_existing(root, sizeof(root)) &&
           snprintf(buf, cap, "%s/land", root) < (int)cap;
}

static bool pc_skip(const char *leaf, char *note, size_t cap,
                    struct zcl_command_reply *reply)
{
    size_t n = strlen(note), s = strlen(ZCL_LAND_PRECHECK_SKIP_SUFFIX);
    if (n + s >= cap) {
        pc_fail(reply, leaf, "PRECHECK_NOTE_TOO_LONG",
                "the note plus \" [precheck skipped]\" would pass the 512 "
                "character note limit; shorten the note",
                "input.note");
        return false;
    }
    memcpy(note + n, ZCL_LAND_PRECHECK_SKIP_SUFFIX, s + 1);
    return true;
}

static bool pc_enabled(void)
{
#if defined(ZCL_TESTING)
    if (g_pc_force)
        return true;
#endif
    return !dl_stubbed();
}

/* The lint gates lint the worktree root, so they only speak for the tip when
 * the tip is that tree's HEAD. */
static bool pc_tip_is_head(const char *wt, const char *tip)
{
    const char *argv[] = {"git", "-C", wt, "rev-parse", "HEAD", NULL};
    char head[128];
    if (zcl_spawn_capture(argv, head, sizeof(head), 30000) != 0)
        return false;
    head[strcspn(head, "\r\n")] = '\0';
    return strcmp(head, tip) == 0;
}

static bool pc_run_gates(const char *leaf, const char *wt,
                         const char *land_dir, int64_t floor_ms, struct zcl_command_reply *reply)
{
    struct zcl_land_precheck_gates *g;
    struct pc_run *r;
    char ledger[4096 + 32], dir[4096];
    bool ok;
    r = zcl_calloc(1, sizeof(*r), "dev_land_precheck.run");
    r->leaf = leaf;
    r->wt = wt;
    if (snprintf(r->bin, sizeof(r->bin), "%s/build/bin/z23-lint", wt) >=
            (int)sizeof(r->bin) ||
#if defined(_WIN32)
        true
#else
        access(r->bin, X_OK) != 0
#endif
    ) {
        pc_fail(reply, leaf, "PRECHECK_UNAVAILABLE",
                "the lane has no build/bin/z23-lint to run the precheck "
                "gates; run `make build/bin/z23-lint docs-capability-inventory` "
                "in the lane and resubmit (--precheck=skip is for emergencies "
                "only)",
                wt);
        free(r);
        return false;
    }
    g = zcl_calloc(1, sizeof(*g), "dev_land_precheck.gates");
    ledger[0] = '\0';
    if (pc_land_dir(land_dir, dir, sizeof(dir)))
    {
        (void)snprintf(ledger, sizeof(ledger), "%s/outcomes.jsonl", dir);
        (void)snprintf(r->land, sizeof(r->land), "%s", dir);
    }
    zcl_land_precheck_gate_set(ledger[0] ? ledger : NULL,
                               pc_now(), g);
    r->out = zcl_malloc(PC_OUT_CAP, "dev_land_precheck.out");
    int64_t budget_ms = pc_budget_ms();
#if defined(ZCL_TESTING)
    if (g_pc_budget_ms > 0)
        budget_ms = g_pc_budget_ms;
#endif
    budget_ms = zcl_land_precheck_budget_floor(budget_ms, floor_ms);
    r->budget_ms = budget_ms;
    r->deadline = pc_monotonic_ms() + budget_ms;
    if (ledger[0]) pc_history_learn(r, dir, g);
    else pc_history_unproven(r, "land state unavailable");
    pc_prioritize_shell(g);
    ok = pc_gates_run(r, g, reply);
    if (ok) {
        pc_push_names(reply, "precheck_ran", r->ran, r->nran);
        pc_push_names(reply, "precheck_skipped", r->skipped, r->nskipped);
        pc_push_unproven(r, reply);
        if (!pc_push_timings(r, reply))
            (void)json_push_kv_bool(&reply->data, "precheck_timings_unavailable", true);
    }
    free(r->out);
    free(g);
    free(r);
    return ok;
}

static bool pc_floor_valid(int64_t floor_ms, const char *mode, bool checked_elsewhere)
{
    if (!floor_ms) return true;
    return floor_ms >= ZCL_LAND_PRECHECK_BUDGET_MS &&
        floor_ms <= ZCL_LAND_PRECHECK_BUDGET_MS * ZCL_LAND_PRECHECK_BUDGET_MAX_SCALE &&
        !checked_elsewhere && !(mode && !strcmp(mode, "skip"));
}
bool zcl_dev_land_precheck_budgeted(const char *leaf, const char *wt,
                           const char *land_dir, const char *mode,
                           const char *tip, bool checked_elsewhere, char *note,
                           size_t cap, int64_t floor_ms, struct zcl_command_reply *reply)
{
    if (!pc_floor_valid(floor_ms, mode, checked_elsewhere)) {
        pc_fail(reply, leaf, "BAD_INPUT", "precheck_budget_ms requires a running precheck and must be 180000..720000", "precheck_budget_ms");
        return false;
    }
    /* The mode is validated first, on every path: `sent` and any other word
     * are refused so a caller can never name a bypass. */
    if (mode && strcmp(mode, "run") != 0 && strcmp(mode, "skip") != 0) {
        pc_fail(reply, leaf, "BAD_INPUT",
                "precheck is `run` (the default) or `skip`; nothing else is "
                "accepted",
                mode);
        return false;
    }
    if (mode && strcmp(mode, "skip") == 0)
        return pc_skip(leaf, note, cap, reply);
    if (checked_elsewhere || !pc_enabled())
        return true;
    if (tip && !pc_tip_is_head(wt, tip)) {
        pc_fail(reply, leaf, "PRECHECK_TIP_NOT_HEAD",
                "the precheck lints the worktree, which is not at the tip "
                "being queued; check out the tip (or use --qualify) and "
                "resubmit, or pass --precheck=skip",
                tip);
        return false;
    }
    return pc_run_gates(leaf, wt, land_dir, floor_ms, reply);
}
bool zcl_dev_land_precheck(const char *leaf, const char *wt,
                           const char *land_dir, const char *mode,
                           const char *tip, bool checked_elsewhere, char *note,
                           size_t cap, struct zcl_command_reply *reply)
{
    return zcl_dev_land_precheck_budgeted(leaf, wt, land_dir, mode, tip,
                                         checked_elsewhere, note, cap, 0, reply);
}
