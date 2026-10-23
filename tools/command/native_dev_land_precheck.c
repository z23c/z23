/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land precheck -- the cheap deterministic lint gates a lane
 *          runs locally before `dev land submit` queues it or `dev land send`
 *          bundles it. See native_dev_land_precheck.h for the contract.
 *
 * The gates run as `build/bin/z23-lint <gate>` with the lane worktree as cwd.
 * Gate diagnostics go to stderr, which the cwd-scoped spawn capture discards,
 * so each child is a `sh -c 'cd "$1" && exec "$@" 2>&1'` trampoline whose
 * every operand is a positional parameter: nothing a caller supplies is ever
 * parsed as shell text. The trampoline needs no other shell feature.
 */

#include "command/native_dev_land_precheck.h"

#include "command/native_command.h"
#include "command/native_dev_land_internal.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define PC_TAIL_BYTES (4u * 1024u * 1024u)
#define PC_OUT_CAP (128u * 1024u)
#define PC_EVIDENCE_CAP 4096u
#define PC_TEXT_CAP 1600u

static const char *const k_pc_core[] = {
    "check-file-size-ceiling", "check-cyclomatic-complexity",
    "check-core-seal", "check-arm-symbol-single",
};

#if defined(ZCL_TESTING)
static bool g_pc_force;
void zcl_dev_land_precheck_test_force(bool on)
{
    g_pc_force = on;
}
#endif

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
                  int64_t deadline_ms, char *out, size_t cap)
{
    const char *argv[] = {"sh", "-c", "cd \"$1\" || exit 126; shift; exec \"$@\" 2>&1",
                          "sh", wt, bin, gate, NULL};
    int64_t left = deadline_ms - platform_time_monotonic_ms();
    bool timed_out = false;
    int rc;
    out[0] = '\0';
    if (left <= 0)
        return -1;
    rc = zcl_spawn_capture_observed(argv, out, cap, (int)left, &timed_out);
    return timed_out ? -1 : rc;
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
    int64_t deadline;
    const char *skipped[ZCL_LAND_PRECHECK_MAX_GATES];
    const char *ran[ZCL_LAND_PRECHECK_MAX_GATES];
    char unproven[PC_EVIDENCE_CAP];
    size_t nskipped, nran;
};

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

static void pc_gate_failed(struct pc_run *r, const char *gate, int rc,
                           struct zcl_command_reply *reply)
{
    char ev[PC_EVIDENCE_CAP], msg[256];
    if (rc < 0) {
        (void)snprintf(msg, sizeof(msg),
                       "the precheck ran past its %d s budget at %s; fix the "
                       "slow gate or resubmit with --precheck=skip",
                       ZCL_LAND_PRECHECK_BUDGET_MS / 1000, gate);
        pc_fail(reply, r->leaf, "PRECHECK_TIMEOUT", msg, gate);
        return;
    }
    pc_head_lines(r->out, ev, sizeof(ev));
    (void)snprintf(msg, sizeof(msg),
                   "precheck gate %s failed (exit %d); fix and resubmit",
                   gate, rc);
    (void)json_push_kv_str(&reply->data, "gate", gate);
    (void)json_push_kv_str(&reply->data, "hint", "fix and resubmit");
    pc_push_names(reply, "precheck_skipped", r->skipped, r->nskipped);
    pc_push_unproven(r, reply);
    pc_fail(reply, r->leaf, "PRECHECK_FAILED", msg, ev[0] ? ev : gate);
}

static bool pc_gates_run(struct pc_run *r,
                         const struct zcl_land_precheck_gates *g,
                         struct zcl_command_reply *reply)
{
    char list[PC_OUT_CAP / 4];
    int rc = pc_run(r->wt, r->bin, "--list", r->deadline, r->out, PC_OUT_CAP);
    if (rc != 0) {
        pc_fail(reply, r->leaf, rc < 0 ? "PRECHECK_TIMEOUT" : "PRECHECK_UNAVAILABLE",
                "the lane's z23-lint --list did not answer; run `make "
                "build/bin/z23-lint docs-capability-inventory` in the lane, "
                "or resubmit with --precheck=skip",
                r->bin);
        return false;
    }
    (void)snprintf(list, sizeof(list), "%s", r->out);
    for (size_t i = 0; i < g->count; i++) {
        if (!pc_known(list, g->name[i])) {
            r->skipped[r->nskipped++] = g->name[i];
            continue;
        }
        rc = pc_run(r->wt, r->bin, g->name[i], r->deadline, r->out, PC_OUT_CAP);
        if (rc == PC_EXIT_UNPROVEN) {
            pc_note_unproven(r, g->name[i]);
            continue;
        }
        if (rc != 0) {
            pc_gate_failed(r, g->name[i], rc, reply);
            return false;
        }
        r->ran[r->nran++] = g->name[i];
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
                         const char *land_dir, struct zcl_command_reply *reply)
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
        (void)snprintf(ledger, sizeof(ledger), "%s/outcomes.jsonl", dir);
    zcl_land_precheck_gate_set(ledger[0] ? ledger : NULL,
                               (int64_t)platform_time_wall_time_t(), g);
    r->out = zcl_malloc(PC_OUT_CAP, "dev_land_precheck.out");
    r->deadline = platform_time_monotonic_ms() + ZCL_LAND_PRECHECK_BUDGET_MS;
    ok = pc_gates_run(r, g, reply);
    if (ok) {
        pc_push_names(reply, "precheck_ran", r->ran, r->nran);
        pc_push_names(reply, "precheck_skipped", r->skipped, r->nskipped);
        pc_push_unproven(r, reply);
    }
    free(r->out);
    free(g);
    free(r);
    return ok;
}

bool zcl_dev_land_precheck(const char *leaf, const char *wt,
                           const char *land_dir, const char *mode,
                           const char *tip, bool checked_elsewhere, char *note,
                           size_t cap, struct zcl_command_reply *reply)
{
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
    return pc_run_gates(leaf, wt, land_dir, reply);
}
