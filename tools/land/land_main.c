/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * z23-land — the landing queue's command surface.
 *
 * WHY THIS IS A TOOL BINARY AND NOT A `z23` COMMAND LEAF
 * -----------------------------------------------------
 * Every leaf in engine/composition/commands/ carries a row in
 * engine/composition/remote_command_classes.def answering "may a peer on our own mesh
 * ask this node to run it?". A landing queue has no answer to that question
 * that is worth the risk of getting wrong: it is developer machinery that
 * merges branches and drives `make`, it touches no consensus state, and no
 * peer should ever be able to reach it even to read it. A leaf would also
 * put it on the read-latency contract, which dispatches every
 * ZCL_COMMAND_READY_READ leaf four times per suite run with empty input —
 * meaningless for a queue and actively wrong for anything that writes.
 *
 * So it lives where the tree already puts operator machinery that runs
 * `make` and git: a standalone tool binary, beside tools/ship.sh and
 * tools/dev/checkout-lock.sh, driven by tools/dev/land.sh.
 *
 * TIME IS AN ARGUMENT, NEVER A READING
 * ------------------------------------
 * Nothing here calls a clock. The caller passes `--at <unix>` for the
 * telemetry journal, so this program is a pure function of its arguments and
 * its log, and the same inputs produce the same bytes on any machine. It is
 * also why check_no_raw_clock_outside_platform has nothing to find here: the
 * question never comes up.
 *
 * EXIT CODES
 *   0  the thing was done
 *   1  a refusal with a reason (the fail-closed paths land here)
 *   2  bad usage, or the queue could not be opened
 */

#include "land_queue.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int usage(void)
{
    fputs(
        "usage: z23-land <command> [options]\n"
        "\n"
        "  submit   --queue P --branch B --head SHA --submitter S [--note T]\n"
        "  status   --queue P [--branch B]\n"
        "  pending  --queue P            (TSV: seq, branch, head, submitter)\n"
        "  gate-run --queue P --outcome green|red|timeout --integration SHA\n"
        "           --stress 0|1 --gate-id HEX64 --members SEQ[,SEQ...]\n"
        "  verdict  --queue P --seq N --state landed|refused|timeout\n"
        "           [--gate-run N] [--integration SHA] [--reason T]\n"
        "  metrics  --queue P [--timing F]\n"
        "  verify   --queue P\n"
        "  timing   --timing F --mark queued|settled --seq N --at UNIX\n"
        "  digest   --head SHA --integration SHA --gate-id HEX64\n"
        "           --state landed|refused|timeout --stress 0|1\n"
        "           (needs no queue: recompute a verdict's content address\n"
        "            from the four public facts and compare)\n",
        stderr);
    return 2;
}

/* ── argument plumbing ────────────────────────────────────────────────── */

struct args {
    const char *queue;
    const char *branch;
    const char *head;
    const char *submitter;
    const char *note;
    const char *outcome;
    const char *integration;
    const char *members;
    const char *state;
    const char *reason;
    const char *timing;
    const char *mark;
    const char *stress;
    const char *seq;
    const char *gate_run;
    const char *at;
    const char *gate_id;
};

static bool parse_args(int argc, char **argv, struct args *a)
{
    static const struct {
        const char *flag;
        size_t offset;
    } table[] = {
        { "--queue",       offsetof(struct args, queue) },
        { "--branch",      offsetof(struct args, branch) },
        { "--head",        offsetof(struct args, head) },
        { "--submitter",   offsetof(struct args, submitter) },
        { "--note",        offsetof(struct args, note) },
        { "--outcome",     offsetof(struct args, outcome) },
        { "--integration", offsetof(struct args, integration) },
        { "--members",     offsetof(struct args, members) },
        { "--state",       offsetof(struct args, state) },
        { "--reason",      offsetof(struct args, reason) },
        { "--timing",      offsetof(struct args, timing) },
        { "--mark",        offsetof(struct args, mark) },
        { "--stress",      offsetof(struct args, stress) },
        { "--seq",         offsetof(struct args, seq) },
        { "--gate-run",    offsetof(struct args, gate_run) },
        { "--at",          offsetof(struct args, at) },
        { "--gate-id",     offsetof(struct args, gate_id) },
    };
    memset(a, 0, sizeof *a);
    for (int i = 0; i < argc; i++) {
        bool matched = false;
        for (size_t t = 0; t < sizeof table / sizeof table[0]; t++) {
            if (strcmp(argv[i], table[t].flag) != 0)
                continue;
            if (i + 1 >= argc) {
                fprintf(stderr, "z23-land: %s needs a value\n", argv[i]);
                return false;
            }
            *(const char **)((char *)a + table[t].offset) = argv[++i];
            matched = true;
            break;
        }
        if (!matched) {
            fprintf(stderr, "z23-land: unknown option %s\n", argv[i]);
            return false;
        }
    }
    return true;
}

/* strtoull with the checks a shell-driven tool actually needs: a whole
 * string, a real digit, and no negative sneaking through as a huge
 * unsigned. */
static bool parse_u64(const char *s, uint64_t *out)
{
    if (!s || !*s)
        return false;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9')
            return false;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno != 0 || !end || *end)
        return false;
    *out = (uint64_t)v;
    return true;
}

static bool copy_field(char *dst, size_t cap, const char *src)
{
    if (!src)
        src = "";
    size_t n = strlen(src);
    if (n >= cap)
        return false;
    memcpy(dst, src, n + 1);
    return true;
}

static struct land_queue *open_queue(const struct args *a)
{
    if (!a->queue) {
        fputs("z23-land: --queue is required\n", stderr);
        return NULL;
    }
    struct zcl_chainlog_report rep;
    struct land_queue *q = land_queue_open(a->queue, &rep);
    if (!q)
        fprintf(stderr, "z23-land: cannot open %s: %s (first bad seq %llu)\n",
                a->queue, zcl_chainlog_status_label(rep.status),
                (unsigned long long)rep.first_bad_seq);
    return q;
}

/* ── commands ─────────────────────────────────────────────────────────── */

static int cmd_submit(const struct args *a)
{
    struct land_submit s;
    memset(&s, 0, sizeof s);
    if (!a->branch || !a->head || !a->submitter) {
        fputs("z23-land submit: --branch, --head and --submitter are "
              "required\n", stderr);
        return 2;
    }
    if (!land_sha_parse(a->head, s.head)) {
        fprintf(stderr, "z23-land submit: --head must be 40 lowercase hex "
                        "digits, got '%s'\n", a->head);
        return 2;
    }
    if (!copy_field(s.branch, sizeof s.branch, a->branch) ||
        !copy_field(s.submitter, sizeof s.submitter, a->submitter) ||
        !copy_field(s.note, sizeof s.note, a->note)) {
        fputs("z23-land submit: a field is over its bound\n", stderr);
        return 2;
    }
    struct land_queue *q = open_queue(a);
    if (!q)
        return 2;
    uint64_t seq = 0;
    enum land_status st = land_queue_submit(q, &s, &seq);
    land_queue_close(q);
    if (st != LAND_OK) {
        fprintf(stderr, "z23-land submit: refused (%s)\n",
                land_status_label(st));
        return 1;
    }
    printf("%llu\n", (unsigned long long)seq);
    return 0;
}

static void print_entry(const struct land_entry *e)
{
    char head[LAND_SHA_HEX + 1];
    land_sha_format(e->submit.head, head);
    printf("seq=%llu state=%s branch=%s head=%s submitter=%s gate_runs=%u\n",
           (unsigned long long)e->seq, land_state_label(e->state),
           e->submit.branch, head, e->submit.submitter, e->gate_runs);
    if (e->submit.note[0])
        printf("    note: %s\n", e->submit.note);

    /* A status that can only say "pending" makes the asker think, and making
     * the asker think is the cost this whole thing exists to remove. Every
     * live state says what it is waiting on and what will end the wait. */
    if (e->state == LAND_STATE_QUEUED) {
        if (e->ahead == 0)
            printf("    waiting on: the lander's next batch — nothing ahead "
                   "of it\n");
        else
            printf("    waiting on: the lander's next batch — %u submission"
                   "%s ahead of it\n", e->ahead, e->ahead == 1 ? "" : "s");
    } else if (e->state == LAND_STATE_GATING) {
        printf("    waiting on: gate run %llu, proving %u submission%s at "
               "once\n", (unsigned long long)e->gate_run_seq, e->batch_size,
               e->batch_size == 1 ? "" : "s");
    }

    if (e->has_verdict) {
        printf("    verdict: %s", land_state_label(e->verdict.state));
        if (e->verdict.gate_run_seq)
            printf(" backed-by-gate-run=%llu",
                   (unsigned long long)e->verdict.gate_run_seq);
        if (e->verdict.state == LAND_STATE_LANDED) {
            char integ[LAND_SHA_HEX + 1];
            land_sha_format(e->verdict.integration, integ);
            printf(" integration=%s", integ);
        }
        printf("\n");
        if (e->verdict.reason[0])
            printf("    reason: %s\n", e->verdict.reason);
    }
    if (e->has_digest) {
        /* The content address, printed beside the facts it is computed from,
         * so a reader on another machine can recompute it with
         * `z23-land digest` and never has to take this machine's word. */
        char dg[LAND_DIGEST_HEX + 1], gid[LAND_GATE_ID_HEX + 1];
        land_id32_format(e->digest, dg);
        land_id32_format(e->gate_id, gid);
        printf("    digest: %s\n", dg);
        printf("    gate-id: %s stress=%d\n", gid, e->gate_stress ? 1 : 0);
    }
    if (!e->landing_backed)
        printf("    ** UNBACKED LANDING: this log claims a landing with no "
               "green stress-enabled gate run behind it **\n");
}

static int cmd_status(const struct args *a)
{
    struct land_queue *q = open_queue(a);
    if (!q)
        return 2;
    int rc = 0;
    if (a->branch) {
        const struct land_entry *e = land_queue_find_branch(q, a->branch);
        if (!e) {
            printf("no submission for branch %s\n", a->branch);
            rc = 1;
        } else {
            print_entry(e);
        }
    } else {
        size_t n = land_queue_count(q);
        for (size_t i = 0; i < n; i++)
            print_entry(land_queue_at(q, i));
        printf("%zu submission(s)\n", n);
    }
    land_queue_close(q);
    return rc;
}

static int cmd_pending(const struct args *a)
{
    struct land_queue *q = open_queue(a);
    if (!q)
        return 2;
    size_t n = land_queue_count(q);
    for (size_t i = 0; i < n; i++) {
        const struct land_entry *e = land_queue_at(q, i);
        /* GATING is included: a lander that died mid-batch left work in
         * that state, and leaving it there forever would be a queue that
         * silently drops submissions after a crash. */
        if (e->state != LAND_STATE_QUEUED && e->state != LAND_STATE_GATING)
            continue;
        char head[LAND_SHA_HEX + 1];
        land_sha_format(e->submit.head, head);
        printf("%llu\t%s\t%s\t%s\t%u\n", (unsigned long long)e->seq,
               e->submit.branch, head, e->submit.submitter, e->gate_runs);
    }
    land_queue_close(q);
    return 0;
}

static int cmd_gate_run(const struct args *a)
{
    struct land_gate_run g;
    memset(&g, 0, sizeof g);
    if (!a->outcome || !a->integration || !a->members || !a->stress) {
        fputs("z23-land gate-run: --outcome, --integration, --stress and "
              "--members are required\n", stderr);
        return 2;
    }
    if (!land_gate_outcome_parse(a->outcome, &g.outcome)) {
        fprintf(stderr, "z23-land gate-run: --outcome must be green, red or "
                        "timeout, got '%s'\n", a->outcome);
        return 2;
    }
    if (strcmp(a->stress, "1") == 0)
        g.stress = true;
    else if (strcmp(a->stress, "0") == 0)
        g.stress = false;
    else {
        fputs("z23-land gate-run: --stress must be 0 or 1\n", stderr);
        return 2;
    }
    if (!land_sha_parse(a->integration, g.integration)) {
        fputs("z23-land gate-run: --integration must be 40 lowercase hex "
              "digits\n", stderr);
        return 2;
    }
    /* The gating tree's identity. Optional in the argument list and all-zero
     * when absent, because a runner that cannot capture one must still be
     * able to record HONESTLY what it did. An all-zero identity is not a
     * blank to be filled in later: it is the value "nobody can say which
     * tree this was", and it produces a verdict digest that will never match
     * one from a run that could say. */
    if (a->gate_id && !land_id32_parse(a->gate_id, g.gate_id)) {
        fputs("z23-land gate-run: --gate-id must be 64 lowercase hex "
              "digits\n", stderr);
        return 2;
    }
    /* --members is a comma-separated list of submit seqs. */
    const char *p = a->members;
    while (*p) {
        char tok[32];
        size_t n = 0;
        while (*p && *p != ',' && n + 1 < sizeof tok)
            tok[n++] = *p++;
        tok[n] = '\0';
        if (*p == ',')
            p++;
        uint64_t v = 0;
        if (!parse_u64(tok, &v) || v == 0) {
            fprintf(stderr, "z23-land gate-run: bad member '%s'\n", tok);
            return 2;
        }
        if (g.member_count >= LAND_MEMBERS_MAX) {
            fputs("z23-land gate-run: too many members\n", stderr);
            return 2;
        }
        g.member_seq[g.member_count++] = v;
    }
    if (g.member_count == 0) {
        fputs("z23-land gate-run: --members is empty\n", stderr);
        return 2;
    }
    struct land_queue *q = open_queue(a);
    if (!q)
        return 2;
    uint64_t seq = 0;
    enum land_status st = land_queue_gate_run(q, &g, &seq);
    land_queue_close(q);
    if (st != LAND_OK) {
        fprintf(stderr, "z23-land gate-run: refused (%s)\n",
                land_status_label(st));
        return 1;
    }
    printf("%llu\n", (unsigned long long)seq);
    return 0;
}

static int cmd_verdict(const struct args *a)
{
    struct land_verdict v;
    memset(&v, 0, sizeof v);
    if (!a->seq || !a->state) {
        fputs("z23-land verdict: --seq and --state are required\n", stderr);
        return 2;
    }
    if (!parse_u64(a->seq, &v.submit_seq) || v.submit_seq == 0) {
        fputs("z23-land verdict: --seq must be a positive integer\n", stderr);
        return 2;
    }
    if (!land_state_parse(a->state, &v.state) ||
        (v.state != LAND_STATE_LANDED && v.state != LAND_STATE_REFUSED &&
         v.state != LAND_STATE_TIMEOUT)) {
        fputs("z23-land verdict: --state must be landed, refused or "
              "timeout\n", stderr);
        return 2;
    }
    if (a->gate_run && !parse_u64(a->gate_run, &v.gate_run_seq)) {
        fputs("z23-land verdict: --gate-run must be an integer\n", stderr);
        return 2;
    }
    if (a->integration && !land_sha_parse(a->integration, v.integration)) {
        fputs("z23-land verdict: --integration must be 40 lowercase hex "
              "digits\n", stderr);
        return 2;
    }
    if (!copy_field(v.reason, sizeof v.reason, a->reason)) {
        fputs("z23-land verdict: --reason is over its bound\n", stderr);
        return 2;
    }
    struct land_queue *q = open_queue(a);
    if (!q)
        return 2;
    /* The branch is not taken from the caller: it is read out of the
     * submission being answered, so a verdict can never name a branch other
     * than the one submitted. */
    const struct land_entry *e = land_queue_find_seq(q, v.submit_seq);
    if (!e) {
        fprintf(stderr, "z23-land verdict: no submission with seq %llu\n",
                (unsigned long long)v.submit_seq);
        land_queue_close(q);
        return 1;
    }
    memcpy(v.branch, e->submit.branch, sizeof v.branch);
    memcpy(v.head, e->submit.head, sizeof v.head);

    enum land_status st = land_queue_verdict(q, &v, NULL);
    land_queue_close(q);
    if (st != LAND_OK) {
        fprintf(stderr, "z23-land verdict: refused (%s)\n",
                land_status_label(st));
        return 1;
    }
    printf("%s %s\n", land_state_label(v.state), v.branch);
    return 0;
}

/* ── the telemetry journal ────────────────────────────────────────────
 * Wall-clock waits, deliberately OUTSIDE the chainlog. Two columns and a
 * mark, appended with fopen("a"), which for lines this short is atomic
 * enough for a metric nobody makes a decision from. If it is lost, the
 * receipts are untouched. */

static int cmd_timing(const struct args *a)
{
    uint64_t seq = 0, at = 0;
    if (!a->timing || !a->mark || !a->seq || !a->at)
        return usage();
    if (!parse_u64(a->seq, &seq) || !parse_u64(a->at, &at))
        return usage();
    if (strcmp(a->mark, "queued") != 0 && strcmp(a->mark, "settled") != 0) {
        fputs("z23-land timing: --mark must be queued or settled\n", stderr);
        return 2;
    }
    FILE *f = fopen(a->timing, "a");
    if (!f) {
        fprintf(stderr, "z23-land timing: cannot open %s\n", a->timing);
        return 2;
    }
    fprintf(f, "%c %llu %llu\n", a->mark[0], (unsigned long long)seq,
            (unsigned long long)at);
    int rc = fclose(f) == 0 ? 0 : 2;
    return rc;
}

/* ── the decentralised half ───────────────────────────────────────────
 * `digest` takes NO queue. That is the point: a machine that receives a
 * claimed verdict — over the mesh, in a message, in a file — recomputes the
 * content address from the four public facts and compares it, without the
 * queue, without the network, and without trusting whoever sent it. A
 * verdict that does not reproduce is a verdict about some other tree.
 *
 * It is also why the queue is not a coordinator anyone has to trust: what it
 * hands out is checkable, so a second lander on a second box produces the
 * identical digest for the identical work, and neither is the authority. */
static int cmd_digest(const struct args *a)
{
    uint8_t head[LAND_SHA_BYTES], integ[LAND_SHA_BYTES];
    uint8_t gate_id[LAND_GATE_ID_BYTES];
    enum land_state state;
    bool stress;

    memset(head, 0, sizeof head);
    memset(integ, 0, sizeof integ);
    memset(gate_id, 0, sizeof gate_id);

    if (!a->head || !a->state || !a->stress) {
        fputs("z23-land digest: --head, --state and --stress are required\n",
              stderr);
        return 2;
    }
    if (!land_sha_parse(a->head, head)) {
        fputs("z23-land digest: --head must be 40 lowercase hex digits\n",
              stderr);
        return 2;
    }
    if (a->integration && !land_sha_parse(a->integration, integ)) {
        fputs("z23-land digest: --integration must be 40 lowercase hex "
              "digits\n", stderr);
        return 2;
    }
    if (a->gate_id && !land_id32_parse(a->gate_id, gate_id)) {
        fputs("z23-land digest: --gate-id must be 64 lowercase hex digits\n",
              stderr);
        return 2;
    }
    if (!land_state_parse(a->state, &state)) {
        fputs("z23-land digest: --state must be landed, refused or timeout\n",
              stderr);
        return 2;
    }
    if (strcmp(a->stress, "1") == 0)
        stress = true;
    else if (strcmp(a->stress, "0") == 0)
        stress = false;
    else {
        fputs("z23-land digest: --stress must be 0 or 1\n", stderr);
        return 2;
    }

    uint8_t out[LAND_DIGEST_BYTES];
    land_verdict_digest(head, integ, gate_id, state, stress, out);
    char hex[LAND_DIGEST_HEX + 1];
    land_id32_format(out, hex);
    printf("%s\n", hex);
    return 0;
}

static int cmp_u64(const void *x, const void *y)
{
    uint64_t a = *(const uint64_t *)x, b = *(const uint64_t *)y;
    return a < b ? -1 : (a > b ? 1 : 0);
}

/* Median wait, in seconds, over submissions that have both a queued mark and
 * a settled mark. Reported as -1 when nothing has settled yet: a "0" there
 * would read as "no wait at all", which is the opposite of the truth. */
static long median_wait(const char *path)
{
    if (!path)
        return -1;
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    enum { CAP = 4096 };
    static uint64_t queued_at[CAP];
    static uint64_t settled_at[CAP];
    static bool have_q[CAP], have_s[CAP];
    char line[128];
    while (fgets(line, sizeof line, f)) {
        char mark = 0;
        unsigned long long seq = 0, at = 0;
        if (sscanf(line, "%c %llu %llu", &mark, &seq, &at) != 3)
            continue;
        if (seq == 0 || seq >= CAP)
            continue;
        if (mark == 'q') { queued_at[seq] = at;  have_q[seq] = true; }
        if (mark == 's') { settled_at[seq] = at; have_s[seq] = true; }
    }
    fclose(f);
    static uint64_t waits[CAP];
    size_t n = 0;
    for (size_t i = 1; i < CAP; i++)
        if (have_q[i] && have_s[i] && settled_at[i] >= queued_at[i])
            waits[n++] = settled_at[i] - queued_at[i];
    if (n == 0)
        return -1;
    qsort(waits, n, sizeof waits[0], cmp_u64);
    return (long)waits[n / 2];
}

static int cmd_metrics(const struct args *a)
{
    struct land_queue *q = open_queue(a);
    if (!q)
        return 2;
    struct land_metrics m;
    land_queue_metrics(q, &m);
    land_queue_close(q);

    printf("submissions=%llu\n", (unsigned long long)m.submissions);
    printf("queue_depth=%llu\n",
           (unsigned long long)(m.queued + m.gating));
    printf("queued=%llu\n", (unsigned long long)m.queued);
    printf("gating=%llu\n", (unsigned long long)m.gating);
    printf("landed=%llu\n", (unsigned long long)m.landed);
    printf("refused=%llu\n", (unsigned long long)m.refused);
    printf("timed_out=%llu\n", (unsigned long long)m.timed_out);
    printf("gate_runs=%llu\n", (unsigned long long)m.gate_runs);
    printf("gate_runs_green=%llu\n", (unsigned long long)m.gate_runs_green);

    /* The number that says whether batching worked. Fixed point, two
     * decimals, computed in integers — a float here would print differently
     * on two machines for no reason. */
    if (m.landed == 0) {
        printf("gate_runs_per_landed=n/a\n");
    } else {
        uint64_t hundredths = (m.gate_runs * 100u + m.landed / 2u) / m.landed;
        printf("gate_runs_per_landed=%llu.%02llu\n",
               (unsigned long long)(hundredths / 100),
               (unsigned long long)(hundredths % 100));
    }
    long med = median_wait(a->timing);
    if (med < 0)
        printf("median_wait_seconds=n/a\n");
    else
        printf("median_wait_seconds=%ld\n", med);
    return 0;
}

static int cmd_verify(const struct args *a)
{
    if (!a->queue)
        return usage();
    uint8_t stream[32];
    land_stream_id(stream);
    struct zcl_chainlog_report rep;
    enum zcl_chainlog_status st = zcl_chainlog_verify(a->queue, stream, &rep);
    printf("chain=%s records=%llu first_bad_seq=%llu torn_bytes=%llu\n",
           zcl_chainlog_status_label(st), (unsigned long long)rep.records,
           (unsigned long long)rep.first_bad_seq,
           (unsigned long long)rep.torn_bytes);
    if (st != ZCL_CHAINLOG_OK)
        return 1;

    /* A verifying chain says the bytes were not edited. It says nothing
     * about whether the RULES were followed when they were written, so the
     * backing check runs too. */
    struct land_queue *q = open_queue(a);
    if (!q)
        return 2;
    struct land_metrics m;
    land_queue_metrics(q, &m);
    land_queue_close(q);
    printf("unbacked_landings=%llu first_unbacked_seq=%llu\n",
           (unsigned long long)m.unbacked_landings,
           (unsigned long long)m.first_unbacked_seq);
    return m.unbacked_landings == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return usage();
    struct args a;
    if (!parse_args(argc - 2, argv + 2, &a))
        return 2;
    const char *cmd = argv[1];
    if (strcmp(cmd, "submit") == 0)   return cmd_submit(&a);
    if (strcmp(cmd, "status") == 0)   return cmd_status(&a);
    if (strcmp(cmd, "pending") == 0)  return cmd_pending(&a);
    if (strcmp(cmd, "gate-run") == 0) return cmd_gate_run(&a);
    if (strcmp(cmd, "verdict") == 0)  return cmd_verdict(&a);
    if (strcmp(cmd, "metrics") == 0)  return cmd_metrics(&a);
    if (strcmp(cmd, "verify") == 0)   return cmd_verify(&a);
    if (strcmp(cmd, "timing") == 0)   return cmd_timing(&a);
    if (strcmp(cmd, "digest") == 0)   return cmd_digest(&a);
    return usage();
}
