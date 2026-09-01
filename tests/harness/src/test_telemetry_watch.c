/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_telemetry_watch — `ops.telemetry.watch`, the resumable change feed.
 *
 * THE ONE THING THIS GROUP EXISTS TO PROVE. Three outcomes must be different
 * shapes to a reader who has only the reply:
 *
 *   a quiet period    count 0, gap false, dropped_count 0
 *   a missed window   count >= 1 (NEVER empty), gap true, dropped_count > 0
 *   a restarted feed  epoch_changed true
 *
 * An agent that cannot tell the first two apart will confidently report
 * "nothing changed" about a node that changed everything, so the overrun case
 * below is asserted hardest and is additionally asserted AGAINST the quiet
 * case field by field — proving they differ, not merely that each looks
 * plausible on its own.
 *
 * It also proves the bound. An over-budget reply is written by the kernel as
 * an EMPTY document, so the batch size is computed from a static worst-case
 * record size before anything is encoded. That premise is only worth having if
 * someone has measured it, so the last case drives the REAL handler with a
 * ring full of maximum-width records and measures the document it produced.
 *
 * ISOLATION. The sampler calls sync_dump_state_fill(), which resolves
 * progress_store_db() and therefore whatever datadir this process has. A test
 * without SetDataDir would read the operator's RUNNING node and pass for the
 * wrong reason — that has happened in this repository. The datadir is pinned
 * to a hermetic per-pid temp directory for the whole group.
 */

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "services/telemetry_watch_service.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"
#include "util/telemetry_watch.h"
#include "util/util.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* One label-free assertion per line, same reason as test_telemetry_sync:
 * these checks are numerous and independent, and are more useful reported one
 * by one than collapsed behind a single TEST() label. */
#define TW_CHECK(name, cond) \
    do { \
        printf("%s... ", (name)); \
        if (cond) { printf("OK\n"); } \
        else { printf("FAIL (%s)\n", #cond); failures++; } \
    } while (0)

/* Publish `n` synthetic records. Used where a REAL change cannot be forced:
 * advancing a reducer cursor needs the whole ladder standing up, and the stage
 * headers expose readers with no setter. What is under test here is the ring's
 * sequencing and gap arithmetic, which is indifferent to where a record came
 * from — the sampler's own end of it is covered by the first two cases. */
static void tw_publish_synthetic(size_t n, const char *field)
{
    for (size_t i = 0; i < n; i++) {
        struct telemetry_watch_record rec;
        memset(&rec, 0, sizeof rec);
        rec.captured_at = 1700000000 + (int64_t)i;
        snprintf(rec.canonical_path, sizeof rec.canonical_path,
                 "ops.telemetry.sync.summary");
        snprintf(rec.changed_fields[0], sizeof rec.changed_fields[0], "%s",
                 field);
        rec.changed_count = 1;
        rec.changed_total = 1;
        rec.health = TELEMETRY_HEALTH_OK;
        (void)telemetry_watch_publish(&rec);
    }
}

/* A record at every declared maximum: the widest thing the encoder can ever be
 * handed, so the static per-record byte estimate is exercised at its bound
 * rather than on a typical record that would fit whatever the estimate said. */
static void tw_publish_widest(size_t n)
{
    for (size_t i = 0; i < n; i++) {
        struct telemetry_watch_record rec;
        memset(&rec, 0, sizeof rec);
        rec.captured_at = 9999999999LL;
        memset(rec.canonical_path, 'p', TELEMETRY_WATCH_PATH_MAX - 1);
        for (uint32_t f = 0; f < TELEMETRY_WATCH_FIELDS_MAX; f++)
            memset(rec.changed_fields[f], 'f', TELEMETRY_WATCH_FIELD_MAX - 1);
        rec.changed_count = TELEMETRY_WATCH_FIELDS_MAX;
        rec.changed_total = 4294967295u;
        rec.changed_truncated = true;
        rec.health = TELEMETRY_HEALTH_UNHEALTHY;
        (void)telemetry_watch_publish(&rec);
    }
}

/* ── 1: --since=0 answers with the current batch and a sequence ───────── */

static int check_since_zero_returns_a_batch(void)
{
    int failures = 0;
    telemetry_watch_restart();
    telemetry_watch_service_reset_baseline();

    size_t published = telemetry_watch_service_sample_once();
    TW_CHECK("[watch] the first sample of a fresh feed publishes a baseline "
             "record — from a cursor of 0 every field IS new",
             published == 1);
    TW_CHECK("[watch] publishing assigned sequence 1",
             telemetry_watch_last_sequence() == 1);

    struct telemetry_watch_batch b;
    TW_CHECK("[watch] read(since=0) succeeds",
             telemetry_watch_read(0, 0, TELEMETRY_WATCH_BATCH_MAX, &b));
    TW_CHECK("[watch] --since=0 returns the batch", b.count == 1);
    TW_CHECK("[watch] the record carries the sequence to resume from",
             b.count == 1 && b.records[0].sequence == 1 && b.next_since == 1);
    TW_CHECK("[watch] the record names the leaf a reader should open",
             b.count == 1 &&
             strcmp(b.records[0].canonical_path,
                    "ops.telemetry.sync.summary") == 0);
    TW_CHECK("[watch] the baseline record names changed fields and counts "
             "every one it found",
             b.count == 1 && b.records[0].changed_count > 0 &&
             b.records[0].changed_total >= b.records[0].changed_count);
    TW_CHECK("[watch] a batch delivered in full is not a gap",
             !b.gap && b.dropped_count == 0 && !b.more);
    TW_CHECK("[watch] the batch carries the feed's epoch",
             b.epoch != 0 && b.epoch == telemetry_watch_epoch());
    return failures;
}

/* ── 2: resuming returns ONLY what came after ─────────────────────────── */

static int check_resume_returns_only_subsequent(void)
{
    int failures = 0;
    telemetry_watch_restart();
    telemetry_watch_service_reset_baseline();
    (void)telemetry_watch_service_sample_once(); /* sequence 1 */

    /* An immediate second sample of an unchanged node must publish NOTHING.
     * This is "emits only changes": the snapshot-meta clock moved and is
     * deliberately not diffed, so a tick that observed no node change is
     * silent rather than a false event. */
    size_t again = telemetry_watch_service_sample_once();
    TW_CHECK("[watch] a second sample of an unchanged node publishes nothing",
             again == 0);

    struct telemetry_watch_batch b;
    (void)telemetry_watch_read(1, telemetry_watch_epoch(),
                               TELEMETRY_WATCH_BATCH_MAX, &b);
    TW_CHECK("[watch] resuming at the last seen sequence returns nothing new",
             b.count == 0 && b.next_since == 1);

    tw_publish_synthetic(2, "body_fetch_cursor");
    (void)telemetry_watch_read(1, telemetry_watch_epoch(),
                               TELEMETRY_WATCH_BATCH_MAX, &b);
    TW_CHECK("[watch] a resume returns ONLY the records after the cursor",
             b.count == 2);
    TW_CHECK("[watch] the already-seen record is not replayed",
             b.count == 2 && b.records[0].sequence == 2 &&
             b.records[1].sequence == 3);
    TW_CHECK("[watch] the resume cursor advances to the last record delivered",
             b.next_since == 3 && !b.more);
    TW_CHECK("[watch] a complete resume is not a gap",
             !b.gap && b.dropped_count == 0);

    /* A bounded batch says so rather than looking like the end of the feed. */
    (void)telemetry_watch_read(1, telemetry_watch_epoch(), 1, &b);
    TW_CHECK("[watch] a capped batch reports more records are waiting",
             b.count == 1 && b.more && b.next_since == 2);
    return failures;
}

/* ── 3: THE ONE THAT MATTERS — an overrun ring reports the gap ─────────
 * Asserted hardest, and asserted against the quiet case, because a missed
 * window that looks like a quiet period silently corrupts an agent's model of
 * the node. */

static int check_overrun_ring_reports_the_gap(void)
{
    int failures = 0;
    const size_t overrun = 10;
    telemetry_watch_restart();
    tw_publish_synthetic(TELEMETRY_WATCH_RING_CAP + overrun, "hstar");

    struct telemetry_watch_batch gapped;
    (void)telemetry_watch_read(0, telemetry_watch_epoch(),
                               TELEMETRY_WATCH_BATCH_MAX, &gapped);

    TW_CHECK("[watch] a resume that fell behind the ring returns a NON-EMPTY "
             "batch — an empty one would read as 'nothing changed'",
             gapped.count > 0);
    TW_CHECK("[watch] the gap is flagged", gapped.gap);
    TW_CHECK("[watch] dropped_count states exactly how many records were lost",
             gapped.dropped_count == overrun);
    TW_CHECK("[watch] the batch resumes at the OLDEST record still held, not "
             "at the caller's dead cursor",
             gapped.count > 0 &&
             gapped.records[0].sequence == overrun + 1 &&
             gapped.oldest_sequence == overrun + 1);
    TW_CHECK("[watch] the loss is stamped on the first record too, so a reader "
             "consuming records one at a time still sees it",
             gapped.count > 0 && gapped.records[0].dropped_count == overrun);
    TW_CHECK("[watch] only the first record carries the loss",
             gapped.count < 2 || gapped.records[1].dropped_count == 0);
    TW_CHECK("[watch] the gapped batch names its reason",
             gapped.reason &&
             strcmp(gapped.reason, "resume_fell_behind_the_ring") == 0);

    /* ── and now the quiet period, on the SAME feed ── */
    struct telemetry_watch_batch quiet;
    (void)telemetry_watch_read(telemetry_watch_last_sequence(),
                               telemetry_watch_epoch(),
                               TELEMETRY_WATCH_BATCH_MAX, &quiet);
    TW_CHECK("[watch] a quiet period returns an empty batch", quiet.count == 0);
    TW_CHECK("[watch] a quiet period is not a gap and drops nothing",
             !quiet.gap && quiet.dropped_count == 0);
    TW_CHECK("[watch] a quiet period names its own, different reason",
             quiet.reason &&
             strcmp(quiet.reason,
                    "no_change_recorded_after_this_sequence") == 0);

    /* The point of the whole group, stated as one assertion: the two cases
     * differ on every signal a reader could key off. */
    TW_CHECK("[watch] a missed window and a quiet period are DISTINGUISHABLE "
             "on gap, on dropped_count, on record count and on reason",
             gapped.gap != quiet.gap &&
             gapped.dropped_count != quiet.dropped_count &&
             (gapped.count > 0) != (quiet.count > 0) &&
             strcmp(gapped.reason, quiet.reason) != 0);

    /* A cursor past the newest record is a third thing again, and must not be
     * silently rounded into either of the two above. */
    struct telemetry_watch_batch ahead;
    (void)telemetry_watch_read(telemetry_watch_last_sequence() + 500,
                               telemetry_watch_epoch(),
                               TELEMETRY_WATCH_BATCH_MAX, &ahead);
    TW_CHECK("[watch] a cursor ahead of the feed is flagged, not treated as "
             "quiet",
             ahead.since_ahead && ahead.count == 0 && !ahead.gap);
    return failures;
}

/* ── 4: the epoch changes across a restart ────────────────────────────── */

static int check_epoch_changes_across_restart(void)
{
    int failures = 0;
    telemetry_watch_restart();
    tw_publish_synthetic(3, "tip_finalize_cursor");
    uint64_t before = telemetry_watch_epoch();
    uint64_t seq_before = telemetry_watch_last_sequence();

    telemetry_watch_restart(); /* what a process restart does to the feed */
    uint64_t after = telemetry_watch_epoch();

    TW_CHECK("[watch] the epoch changes across a restart — without it a feed "
             "whose sequence went back to 0 is indistinguishable from a stall",
             before != 0 && after != 0 && before != after);
    TW_CHECK("[watch] the sequence restarts, which is exactly why the epoch "
             "has to move",
             seq_before == 3 && telemetry_watch_last_sequence() == 0);

    /* Resuming with the dead epoch's cursor must be REFUSED as a resume and
     * reported, not quietly served out of the new feed. */
    tw_publish_synthetic(2, "hstar");
    struct telemetry_watch_batch b;
    (void)telemetry_watch_read(seq_before, before,
                               TELEMETRY_WATCH_BATCH_MAX, &b);
    TW_CHECK("[watch] a cursor from a previous epoch is flagged",
             b.epoch_changed && b.epoch == after);
    TW_CHECK("[watch] and is restarted from the oldest held record rather "
             "than applied to sequences it was never about",
             b.count == 2 && b.records[0].sequence == 1);
    TW_CHECK("[watch] a caller that sends no epoch is told it was not checked "
             "(the read cannot invent the answer)",
             telemetry_watch_read(0, 0, TELEMETRY_WATCH_BATCH_MAX, &b) &&
             !b.epoch_changed);
    return failures;
}

/* ── 5: the diff emits CHANGES, not samples ───────────────────────────── */

static int check_diff_ignores_the_sample_clock(void)
{
    int failures = 0;
    struct sync_snapshot a, b;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);

    TELEMETRY_SET_I64(&a, collected_unix, 1700000000,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&b, collected_unix, 1700000001,
                      TELEMETRY_SRC_IN_PROCESS);
    TELEMETRY_SET_I64(&a, hstar, 500, TELEMETRY_SRC_CACHED_PUBLICATION);
    TELEMETRY_SET_I64(&b, hstar, 500, TELEMETRY_SRC_CACHED_PUBLICATION);

    struct telemetry_watch_record rec;
    memset(&rec, 0, sizeof rec);
    TW_CHECK("[watch] two samples that differ only in the snapshot-meta clock "
             "are NOT a change — otherwise every tick is a false event",
             telemetry_watch_diff(&g_sync_schema, &a, &b, &rec) == 0);

    TELEMETRY_SET_I64(&b, hstar, 501, TELEMETRY_SRC_CACHED_PUBLICATION);
    TW_CHECK("[watch] a moved value IS a change, named by the field table's "
             "own key",
             telemetry_watch_diff(&g_sync_schema, &a, &b, &rec) == 1 &&
             rec.changed_count == 1 &&
             strcmp(rec.changed_fields[0], "hstar") == 0);

    /* Presence, not just value: "this stopped being readable" is a change an
     * operator must see, and comparing the stale bytes behind it would hide
     * it completely. */
    memcpy(&b, &a, sizeof b);
    TELEMETRY_UNAVAILABLE_LEAF(&b, hstar, "progress_store_busy");
    TW_CHECK("[watch] a leaf that became UNREADABLE is a change",
             telemetry_watch_diff(&g_sync_schema, &a, &b, &rec) == 1 &&
             strcmp(rec.changed_fields[0], "hstar") == 0);

    /* Two unreadable samples in a row are not an event. */
    struct sync_snapshot c;
    memcpy(&c, &b, sizeof c);
    TW_CHECK("[watch] two consecutive unreadable samples are not a change",
             telemetry_watch_diff(&g_sync_schema, &b, &c, &rec) == 0);
    return failures;
}

/* ── 6: the batch is bounded BEFORE it is built ───────────────────────── */

/* Drive the real leaf and measure what it produced. An over-budget reply is
 * written by the kernel as an EMPTY document, so a batch that does not fit
 * costs the caller the entire answer — the pre-bound is the only thing
 * standing between a wide feed and that outcome, and a bound nobody has
 * measured is a guess. */
static int check_reply_fits_its_budget(void)
{
    int failures = 0;
    telemetry_watch_restart();
    tw_publish_widest(TELEMETRY_WATCH_RING_CAP + 5);

    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_int(&input, "since", 0);

    struct zcl_command_request request = {
        .input = &input, .view = "normal",
        .invoked_name = "ops.telemetry.watch",
    };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.telemetry.change.v1");
    zcl_native_handle_telemetry_watch(&request, &reply);

    size_t bytes = json_write(&reply.data, NULL, 0);
    printf("  widest-record reply: %zu bytes of a %u byte list budget\n",
           bytes, (unsigned)ZCL_COMMAND_LIST_BUDGET);
    TW_CHECK("[watch] a reply built from maximum-width records still fits the "
             "list budget with envelope headroom",
             bytes > 0 && bytes + 1024u <= (size_t)ZCL_COMMAND_LIST_BUDGET);

    const struct json_value *records = json_get(&reply.data, "records");
    TW_CHECK("[watch] the handler returned a non-empty batch", records &&
             records->num_children > 0);
    TW_CHECK("[watch] and reported the gap the widest-record overrun created",
             json_get_bool(json_get(&reply.data, "gap")) &&
             json_get_int(json_get(&reply.data, "dropped_count")) > 0);
    TW_CHECK("[watch] the reply states the pre-computed record cap it used",
             json_get_int(json_get(&reply.data, "batch_max_records")) >= 1);
    TW_CHECK("[watch] the reply carries a ready-to-run resume that is DATA, "
             "not a next[] step back into itself",
             json_get_str(json_get(&reply.data, "resume_invocation")) != NULL);
    for (size_t i = 0; i < reply.next_count; i++) {
        TW_CHECK("[watch] no next[] step points back at watch itself",
                 strcmp(reply.next[i].command, "ops.telemetry.watch") != 0);
    }
    TW_CHECK("[watch] the reply states which domains the feed does NOT cover",
             json_get(json_get(&reply.data, "coverage"), "unsampled") != NULL);

    zcl_command_reply_free(&reply);
    json_free(&input);
    return failures;
}

/* ── 7: the declared coverage is complete and self-consistent ─────────── */

static int check_coverage_is_declared(void)
{
    int failures = 0;
    size_t n = telemetry_watch_service_source_count();
    TW_CHECK("[watch] every registered telemetry domain has a source row — a "
             "domain missing from the table is an invisible coverage hole",
             n == telemetry_domain_count());

    size_t sampled = 0, unsampled = 0;
    bool metaverse_declared_node_free = false;
    for (size_t i = 0; i < n; i++) {
        const char *domain = NULL, *path = NULL, *why = NULL;
        if (!telemetry_watch_service_source_at(i, &domain, &path, &why))
            continue;
        TW_CHECK("[watch] a source row names a registered domain",
                 telemetry_domain_find(domain) != NULL);
        TW_CHECK("[watch] a source row always names a leaf to read",
                 path && path[0]);
        if (why) {
            unsampled++;
            TW_CHECK("[watch] an unsampled domain states why", why[0] != '\0');
            if (strcmp(domain, "metaverse") == 0)
                metaverse_declared_node_free =
                    strstr(why, "node_free") != NULL ||
                    strstr(why, "directory_scoped") != NULL;
        } else {
            sampled++;
        }
    }
    TW_CHECK("[watch] exactly the domains with a real provider are sampled — "
             "today that is `sync` alone",
             sampled == 1);
    TW_CHECK("[watch] every other domain is declared unsampled, not omitted",
             unsampled == n - 1);
    TW_CHECK("[watch] metaverse is declared node-free rather than pending a "
             "provider — its data is directory-scoped, so a change feed for it "
             "would be inventing state",
             metaverse_declared_node_free);
    return failures;
}

int test_telemetry_watch(void)
{
    printf("\n=== telemetry watch (change feed) tests ===\n");
    int failures = 0;

    /* Hermetic datadir for the whole group. The sampler reaches
     * sync_dump_state_fill() -> progress_store_db(); a test that let that
     * resolve the operator's live node would pass by reading a running node's
     * state. See the file header. */
    char datadir[256];
    test_make_tmpdir(datadir, sizeof(datadir), "telemetry_watch", "datadir");
    SetDataDir(datadir);

    failures += check_since_zero_returns_a_batch();
    failures += check_resume_returns_only_subsequent();
    failures += check_overrun_ring_reports_the_gap();
    failures += check_epoch_changes_across_restart();
    failures += check_diff_ignores_the_sample_clock();
    failures += check_reply_fits_its_budget();
    failures += check_coverage_is_declared();

    test_cleanup_tmpdir(datadir);
    printf("=== telemetry_watch: %d failures ===\n", failures);
    return failures;
}
