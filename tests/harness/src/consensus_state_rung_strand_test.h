/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_rung_install_strand: a legacy rung install on a node that already
 * applied blocks (0 < H* < rung) and whose block index does not hold the rung
 * row would commit a wallet cutover the pending boot can never complete. The
 * arm site skips it, the install boot refuses it retriably and clears the
 * consumed request, and the arm check then keeps holding. Included once by
 * consensus_state_rung_window_test.h (reuses its crw fixture). */

#ifndef CONSENSUS_STATE_RUNG_STRAND_TEST_H
#define CONSENSUS_STATE_RUNG_STRAND_TEST_H

#include "conditions/checkpoint_rung_install_strand.h"
#include "event/event.h"
#include "framework/condition.h"
#include "jobs/block_header_emit.h"
#include "jobs/reducer_frontier.h"
#include "platform/time_compat.h"
#include "storage/event_log_payloads.h"
#include "jobs/tip_finalize_stage.h"
#include "storage/block_index_projection.h"
#include "storage/event_log.h"
#include "storage/event_log_singleton.h"
#include "test/reducer_prebinding_fixture.h"
#include "wallet/wallet_sqlite.h"

/* The 27 rows below the rung, durable through the pending restore's loader
 * (the rung itself is saved by crw_open). */
static bool crs_stage_window(const struct crw_fixture *f)
{
    bool ok = f->ready;
    for (int i = 1; ok && i < FSI_W; i++)
        ok = stage_repair_header_solution_save(progress_store_db(), FSI_RUNG_H - i,
                                               &f->is.hash[i], &f->is.w[i]);
    return ok;
}

/* Durable reducer rows giving H* = 1 (served) through compute_hstar. */
static bool crs_seed_hstar(struct crw_fixture *f)
{
    struct uint256 g;
    memset(&g, 0, sizeof(g));
    g.data[0] = 0x6e;
    struct block_index *genesis = chainstate_insert_block_index((struct chainstate *)&f->ms, &g);
    if (!genesis)
        return false;
    genesis->nHeight = 0;
    const uint8_t served[32] = {0x51}, coins[32] = {0x52};
    return test_reducer_prebinding_seed(progress_store_db(), genesis, served, coins);
}

static bool crs_open(struct crw_fixture *f, const char *tag, bool seed)
{
    return crw_open(f, tag, -1) && crs_stage_window(f) && (!seed || crs_seed_hstar(f));
}

static void crs_close(struct crw_fixture *f)
{
    reducer_frontier_provable_tip_reset();
    tip_finalize_stage_test_reset();
    crw_close(f);
}

/* H* as the live predicate reads it (-1: no positive bindable frontier). */
static int32_t crs_hstar_read(const struct crw_fixture *f)
{
    struct checkpoint_rung_install_strand s;
    (void)checkpoint_rung_install_would_strand(FSI_RUNG_H, f->is.hash[0].data, true, &s);
    return s.hstar;
}

/* One remedy round; *strand reports whether this round was a strand skip (as
 * opposed to a window wait, which also returns SKIP). */
static int crs_remedy(bool *strand)
{
    int before = checkpoint_rung_install_strand_test_arm_skips();
    int r = checkpoint_bundle_install_ready_test_remedy();
    *strand = checkpoint_rung_install_strand_test_arm_skips() == before + 1;
    return r;
}

static bool crs_arms(const struct crw_fixture *f)
{
    bool strand = true;
    return f->ready && crs_remedy(&strand) == (int)COND_REMEDY_OK &&
           boot_install_bundle_pending(f->dir) && !strand;
}

static bool crs_skips(const struct crw_fixture *f)
{
    bool strand = false;
    return f->ready && crs_remedy(&strand) == (int)COND_REMEDY_SKIP &&
           !boot_install_bundle_pending(f->dir) && strand;
}

/* The pure predicate at every boundary (N2, N3, N4, the route and the row). */
static int crs_case_core(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("strand core: fixture opens", crw_open(&f, "strand-core", -1));
    const uint8_t *h = f.is.hash[0].data;
    const int32_t t = FSI_RUNG_H;
    const enum checkpoint_rung_row a = CHECKPOINT_RUNG_ROW_ABSENT;
    uint8_t other[32];
    memcpy(other, h, 32);
    other[0] ^= 1;
    CSIR_CHECK("strand core: H*=0 and an unbindable H* do not strand",
               f.ready && !checkpoint_rung_install_strands(t, h, true, true, a, 0) &&
               !checkpoint_rung_install_strands(t, h, true, true, a, -1));
    CSIR_CHECK("strand core: H*=1 and H*=rung-1 strand",
               f.ready && checkpoint_rung_install_strands(t, h, true, true, a, 1) &&
               checkpoint_rung_install_strands(t, h, true, true, a, t - 1));
    CSIR_CHECK("strand core: H*=rung and H*>rung do not strand",
               f.ready && !checkpoint_rung_install_strands(t, h, true, true, a, t) &&
               !checkpoint_rung_install_strands(t, h, true, true, a, t + 1));
    CSIR_CHECK("strand core: a bound binding and an island route do not strand",
               f.ready && !checkpoint_rung_install_strands(t, h, false, true, a, 1) &&
               !checkpoint_rung_install_strands(t, h, true, false, a, 1));
    CSIR_CHECK("strand core: a projected rung row does not strand; an unknown projection does",
               f.ready &&
               !checkpoint_rung_install_strands(t, h, true, true, CHECKPOINT_RUNG_ROW_PROJECTED, 1) &&
               checkpoint_rung_install_strands(t, h, true, true, CHECKPOINT_RUNG_ROW_UNKNOWN, 1));
    CSIR_CHECK("strand core: a non-rung target does not strand",
               f.ready && !checkpoint_rung_install_strands(t, other, true, true, a, 1) &&
               !checkpoint_rung_install_strands(t - 1, h, true, true, a, 1));
    crw_close(&f);
    return failures;
}

/* The reproduction at the arm site: durable window, H* = 1, no projection. */
static int crs_case_arm_skips(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("strand arm: fixture opens with H* seeded", crs_open(&f, "strand-arm", true));
    CSIR_CHECK("strand arm: H* reads 1 through the binding's frontier read",
               f.ready && crs_hstar_read(&f) == 1);
    CSIR_CHECK("strand arm: H*=1 below the rung -> strand SKIP, nothing armed",
               crs_skips(&f));
    CSIR_CHECK("strand arm: the next tick still skips and arms nothing", crs_skips(&f));
    crs_close(&f);
    return failures;
}

/* No positive bindable H* (the fresh node, N2): arms exactly as before. */
static int crs_case_arm_fresh(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("strand fresh: fixture opens", crs_open(&f, "strand-fresh", false));
    CSIR_CHECK("strand fresh: no positive H* -> the install arms as before",
               f.ready && crs_hstar_read(&f) <= 0 && crs_arms(&f));
    crs_close(&f);
    return failures;
}

struct crs_projection { event_log_t *log; block_index_projection_t *p; };

static bool crs_projection_open(struct crs_projection *pr, const char *dir)
{
    char log_path[320], db_path[320];
    snprintf(log_path, sizeof(log_path), "%s/events.log", dir);
    snprintf(db_path, sizeof(db_path), "%s/block_index_projection.db", dir);
    pr->log = event_log_open(log_path);
    pr->p = pr->log ? block_index_projection_open(db_path, pr->log) : NULL;
    event_log_set_singleton(pr->log);
    block_index_projection_set_singleton(pr->p);
    return pr->p != NULL;
}

static bool crs_project_rung(const struct crs_projection *pr, const struct crw_fixture *f)
{
    return block_index_emit_header_event(f->own[0], "strand-test", NULL, NULL) &&
           event_log_flush(pr->log) && block_index_projection_catch_up(pr->p) != UINT64_MAX;
}

static void crs_projection_close(struct crs_projection *pr)
{
    block_index_projection_set_singleton(NULL);
    event_log_set_singleton(NULL);
    if (pr->p) block_index_projection_close(pr->p);
    if (pr->log) event_log_close(pr->log);
    pr->p = NULL;
    pr->log = NULL;
}

/* (d) evaluated exactly: an open projection without the rung row skips; the
 * rung row projected (a P2P header chain) keeps main's path and arms. */
static int crs_case_arm_projection(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    CSIR_CHECK("strand projection: fixture opens with H* seeded and a projection",
               crs_open(&f, "strand-proj", true) && crs_projection_open(&pr, f.dir));
    CSIR_CHECK("strand projection: projection open, rung row absent -> SKIP", crs_skips(&f));
    CSIR_CHECK("strand projection: rung row projected -> the install arms as before",
               pr.p && crs_project_rung(&pr, &f) && crs_arms(&f));
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* The rung header reached this node over P2P in this process: its event is in
 * the log tail the next boot's catch-up replays, not yet in the projection. */
static bool crs_log_rung(const struct crs_projection *pr, const struct crw_fixture *f)
{
    struct disk_block_index disk;
    disk_block_index_init(&disk);
    return block_index_emit_header_event(f->own[0], "strand-test", NULL, NULL) &&
           event_log_flush(pr->log) &&
           block_index_projection_lookup_strict(pr->p, f->own[0]->phashBlock->data, &disk) ==
               BIP_LOOKUP_ABSENT;
}

/* T1, T2 (F-0): a row in neither the log nor the projection skips; a row in the
 * unprojected log tail arms in this process, as on main. */
static int crs_case_arm_logged(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    CSIR_CHECK("strand logged: fixture opens with H* seeded and a projection",
               crs_open(&f, "strand-logged", true) && crs_projection_open(&pr, f.dir));
    CSIR_CHECK("strand logged: rung row in neither the log nor the projection -> remedy skip (T2)",
               crs_skips(&f));
    CSIR_CHECK("strand logged: rung header in the unprojected log tail -> the install arms (T1)",
               pr.p && crs_log_rung(&pr, &f) && crs_arms(&f));
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* T4 (N7 for design A): the tail lookup reads one record per call here and
 * resumes where it stopped. While it scans nothing arms and no skip is noted;
 * it arms on the call that reaches the rung header, and the next call stays
 * armed without a second request. */
/* The 27 rows below the rung, then the rung, in the unprojected log tail. */
static bool crs_log_window(const struct crs_projection *pr, const struct crw_fixture *f)
{
    bool logged = f->ready && pr->p;
    for (int i = FSI_W - 1; logged && i >= 1; i--)
        logged = block_index_emit_header_event(f->own[i], "strand-test", NULL, NULL);
    return logged && crs_log_rung(pr, f);
}

/* Remedy rounds until the install arms (at most `cap`); counts the rounds that
 * skipped without a strand note (the lookup still scanning). */
static int crs_rounds_until_armed(const struct crw_fixture *f, int cap, int *pending)
{
    int calls = 0;
    bool armed = false;
    *pending = 0;
    while (!armed && calls < cap) {
        bool strand = true;
        int r = crs_remedy(&strand);
        calls++;
        armed = r == (int)COND_REMEDY_OK && boot_install_bundle_pending(f->dir);
        *pending += !armed && r == (int)COND_REMEDY_SKIP && !strand;
    }
    return armed ? calls : -1;
}

static int crs_case_arm_tail_resumes(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    CSIR_CHECK("strand resume: fixture opens with H* seeded and a projection",
               crs_open(&f, "strand-resume", true) && crs_projection_open(&pr, f.dir));
    bool logged = crs_log_window(&pr, &f);
    checkpoint_rung_install_strand_test_set_scan_budget(1);
    int pending = 0;
    int calls = logged ? crs_rounds_until_armed(&f, FSI_W + 2, &pending) : -1;
    bool armed = calls > 0;
    CSIR_CHECK("strand resume: 27 bounded calls scan the filler, the 28th reaches the rung and arms",
               logged && calls == FSI_W && pending == FSI_W - 1);
    CSIR_CHECK("strand resume: no strand skip was noted while the lookup ran",
               checkpoint_rung_install_strand_test_arm_skips() == 0);
    CSIR_CHECK("strand resume: the found row stays found; the next call keeps the one request",
               armed && crs_arms(&f));
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* The engine on a test clock: every tick is one poll interval after the last,
 * so each one re-runs detect, and time passes the age budget without sleeping.
 * EV_OPERATOR_NEEDED is counted (only this condition is registered). */
#define CRS_COND "checkpoint_bundle_install_ready"
#define CRS_POLL_SECS 5
static int64_t g_crs_now;
static _Atomic int g_crs_pages;

static void crs_page_seen(enum event_type type, uint32_t peer_id, const void *payload,
                          uint32_t payload_len, void *ctx)
{
    (void)type; (void)peer_id; (void)payload; (void)payload_len; (void)ctx;
    atomic_fetch_add(&g_crs_pages, 1);
}

static bool crs_engine_begin(void)
{
    condition_engine_reset_for_testing();
    register_checkpoint_bundle_install_ready();
    event_clear_observers(EV_OPERATOR_NEEDED);
    atomic_store(&g_crs_pages, 0);
    g_crs_now = INT64_C(1700000000);
    return event_observe(EV_OPERATOR_NEEDED, crs_page_seen, NULL) &&
           condition_engine_has_registered(CRS_COND);
}

static void crs_engine_end(void)
{
    event_clear_observers(EV_OPERATOR_NEEDED);
    condition_engine_reset_for_testing();
}

static bool crs_tick_after(int secs)
{
    g_crs_now += secs;
    return condition_engine_tick_one_at_for_testing(CRS_COND, g_crs_now);
}

static bool crs_tick(void)
{
    return crs_tick_after(CRS_POLL_SECS);
}

static bool crs_snap(struct condition_runtime_snapshot *s)
{
    memset(s, 0, sizeof(*s));
    return condition_engine_get_registered_snapshot(CRS_COND, s);
}

/* One engine tick under the strand: detect re-ran (one more strand note), no
 * episode, no attempt, no page, no remedy. */
static bool crs_engine_quiet(const struct crw_fixture *f)
{
    struct condition_runtime_snapshot s;
    int skips = checkpoint_rung_install_strand_test_arm_skips();
    bool ticked = crs_tick();
    return f->ready && ticked && checkpoint_rung_install_strand_test_arm_skips() == skips + 1 &&
           !checkpoint_bundle_install_ready_test_detect() && crs_snap(&s) &&
           !s.currently_active && s.attempts == 0 && !s.operator_needed_emitted &&
           atomic_load(&g_crs_pages) == 0 &&
           checkpoint_bundle_install_ready_test_remedy_calls() == 0 &&
           !boot_install_bundle_pending(f->dir);
}

/* T3 (F-1): while the strand holds the condition consumes no attempt, never
 * latches and never pages; once the rung row is projected it arms. */
static int crs_case_engine_quiet(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    CSIR_CHECK("strand engine: fixture opens with H* seeded and a projection",
               crs_open(&f, "strand-engine", true) && crs_projection_open(&pr, f.dir));
    CSIR_CHECK("strand engine: condition registered", f.ready && crs_engine_begin());
    bool quiet = f.ready;
    for (int i = 0; quiet && i < 4; i++)
        quiet = crs_engine_quiet(&f);
    CSIR_CHECK("strand engine: 4 ticks under the strand, detect re-run on each: no episode, "
               "no attempt, no operator_needed", quiet);
    CSIR_CHECK("strand engine: the skip was noted for the once-per-process WARN",
               checkpoint_rung_install_strand_test_arm_skips() >= 1);
    CSIR_CHECK("strand engine: rung row projected -> detect fires and the install arms",
               pr.p && crs_project_rung(&pr, &f) && checkpoint_bundle_install_ready_test_detect() &&
               crs_arms(&f));
    crs_engine_end();
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* Ticks spanning `secs`; after each one: no page of any kind, nothing armed. */
static bool crs_ticks_no_page(const struct crw_fixture *f, int secs)
{
    bool ok = f->ready;
    for (int t = 0; ok && t < secs; t += CRS_POLL_SECS) {
        struct condition_runtime_snapshot s;
        ok = crs_tick() && crs_snap(&s) && !s.operator_needed_emitted &&
             atomic_load(&g_crs_pages) == 0 && !boot_install_bundle_pending(f->dir);
    }
    return ok;
}

/* The strand stops holding (rung header in the log tail, window durable): a new
 * episode arms on its first tick, exactly once; the armed episode is not ended
 * by the strand branch and the next tick, inside the backoff, runs no remedy. */
static int crs_episode_rearms(const struct crw_fixture *f, const struct crs_projection *pr)
{
    int failures = 0;
    struct condition_runtime_snapshot s;
    int calls = checkpoint_bundle_install_ready_test_remedy_calls();
    CSIR_CHECK("strand episode: rung header in the log tail -> a new episode arms on its first tick",
               crs_stage_window(f) && crs_log_rung(pr, f) && crs_tick() && crs_snap(&s) &&
               s.currently_active && s.attempts == 1 && boot_install_bundle_pending(f->dir) &&
               checkpoint_bundle_install_ready_test_remedy_calls() == calls + 1);
    CSIR_CHECK("strand episode: armed once; the next tick keeps the episode and runs no remedy",
               crs_tick() && crs_snap(&s) && s.currently_active &&
               checkpoint_bundle_install_ready_test_remedy_calls() == calls + 1 &&
               !checkpoint_bundle_install_ready_test_witness());
    return failures;
}

static bool crs_fill_tail(const struct crs_projection *pr, uint64_t want);
#define CRS_ONE_HEADER_EVENT \
    ((uint64_t)EVENT_LOG_FRAME_OVERHEAD + EV_BLOCK_HEADER_FIXED_BYTES + EV_BLOCK_HEADER_MAX_SOLUTION)

/* D-8: a second episode on the strand path logs its own reason line. H* drops
 * to 0 (the anchor row removed; one event appended, so the remembered answer is
 * recomputed on any tip), a new episode opens with the window still waiting;
 * H* returns to 1 and the witness ends it with a second reason line. */
static int crs_second_episode(const struct crw_fixture *f, const struct crs_projection *pr,
                              int cleared)
{
    int failures = 0;
    struct condition_runtime_snapshot s;
    const uint8_t served[32] = {0x51};
    CSIR_CHECK("strand episode 2: H* drops to 0 -> a new episode opens; the window waits",
               f->ready && test_reducer_prebinding_anchor(progress_store_db(), NULL) &&
               crs_fill_tail(pr, CRS_ONE_HEADER_EVENT) && crs_hstar_read(f) <= 0 && crs_tick() &&
               crs_snap(&s) && s.currently_active && !boot_install_bundle_pending(f->dir));
    CSIR_CHECK("strand episode 2: H* back to 1: 700 s of ticks, no operator_needed",
               test_reducer_prebinding_anchor(progress_store_db(), served) &&
               crs_fill_tail(pr, CRS_ONE_HEADER_EVENT) && crs_hstar_read(f) == 1 &&
               crs_ticks_no_page(f, 700));
    CSIR_CHECK("strand episode 2: the witness ended it with a second reason line",
               crs_snap(&s) && !s.currently_active && s.cleared_count == cleared + 2 &&
               checkpoint_rung_install_strand_test_episode_end_logs() == 2);
    return failures;
}

/* T3b (D-1): an episode opened while H*=0 with the window still waiting, then
 * H* rose below the rung with the rung row nowhere. The witness ends that
 * episode (reason logged once, cleared once) and nothing pages past the 600 s
 * age budget; a second such episode logs its own reason line (D-8); once the
 * row reaches the log tail a new episode arms once. */
static int crs_case_episode_ends(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    struct condition_runtime_snapshot s;
    memset(&s, 0, sizeof(s));
    CSIR_CHECK("strand episode: fixture opens (H*=0, window not durable) with a projection",
               crw_open(&f, "strand-episode", -1) && crs_projection_open(&pr, f.dir) &&
               crs_engine_begin());
    CSIR_CHECK("strand episode: H*=0 opens an episode; the window waits; nothing armed",
               f.ready && crs_tick() && crs_snap(&s) && s.currently_active &&
               checkpoint_header_fetch_is_armed() && !boot_install_bundle_pending(f.dir));
    int cleared = s.cleared_count;
    CSIR_CHECK("strand episode: H* rises to 1 below the rung (the strand holds)",
               f.ready && crs_seed_hstar(&f) && crs_hstar_read(&f) == 1);
    CSIR_CHECK("strand episode: 700 s of ticks past the 600 s age budget: no operator_needed, "
               "no EV_OPERATOR_NEEDED, nothing armed", crs_ticks_no_page(&f, 700));
    CSIR_CHECK("strand episode: the witness ended the episode (cleared once, reason logged once)",
               crs_snap(&s) && !s.currently_active && s.cleared_count == cleared + 1 &&
               checkpoint_rung_install_strand_test_episode_end_logs() == 1);
    failures += crs_second_episode(&f, &pr, cleared);
    failures += crs_episode_rearms(&f, &pr);
    crs_engine_end();
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* The 27 rows below the rung in the unprojected log tail, without the rung. */
static bool crs_log_filler(const struct crs_projection *pr, const struct crw_fixture *f)
{
    bool logged = f->ready && pr->p;
    for (int i = FSI_W - 1; logged && i >= 1; i--)
        logged = block_index_emit_header_event(f->own[i], "strand-test", NULL, NULL);
    return logged && event_log_flush(pr->log);
}

/* D-1: PENDING is not a strand. While the bounded lookup is still scanning the
 * witness stays false; once it decides ABSENT the witness is true and the
 * reason is logged once. */
static int crs_case_witness_pending(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    CSIR_CHECK("strand pending: fixture opens with H* seeded and 27 filler rows in the log tail",
               crs_open(&f, "strand-pending", true) && crs_projection_open(&pr, f.dir) &&
               crs_log_filler(&pr, &f));
    checkpoint_rung_install_strand_test_set_scan_budget(1);
    CSIR_CHECK("strand pending: the lookup is still scanning -> witness false, nothing logged",
               f.ready && !checkpoint_bundle_install_ready_test_witness() &&
               checkpoint_rung_install_strand_test_episode_end_logs() == 0);
    int calls = 1;
    bool ended = false;
    while (f.ready && !ended && calls < FSI_W + 2) {
        ended = checkpoint_bundle_install_ready_test_witness();
        calls++;
    }
    printf("consensus_state_install_runtime: strand pending: witness calls until decided=%d\n", calls);
    CSIR_CHECK("strand pending: witness false for 26 scanning calls, true on the 27th (it reads "
               "the last filler row and reaches the log end: decided ABSENT), reason logged once",
               ended && calls == FSI_W - 1 &&
               checkpoint_rung_install_strand_test_episode_end_logs() == 1);
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* D-1: an armed install clears only by the marker. H* rising after the arm with
 * the row nowhere leaves the witness false. */
static int crs_case_witness_armed(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    CSIR_CHECK("strand armed: fixture opens (H*=0) with a projection",
               crs_open(&f, "strand-armed", false) && crs_projection_open(&pr, f.dir));
    CSIR_CHECK("strand armed: H*=0 -> the install arms", crs_arms(&f));
    CSIR_CHECK("strand armed: H* then 1 with the row nowhere -> the armed request keeps the "
               "witness false and nothing is logged",
               f.ready && crs_seed_hstar(&f) && crs_hstar_read(&f) == 1 &&
               !checkpoint_bundle_install_ready_test_witness() &&
               checkpoint_rung_install_strand_test_episode_end_logs() == 0 &&
               boot_install_bundle_pending(f.dir));
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* One remedy round after the backoff: the remedy ran once and skipped, the
 * episode stays open, and its attempt did not count (no window progress and
 * no walk held, so only the strand round can have kept it). */
static bool crs_backstop_round(const struct crw_fixture *f)
{
    struct condition_runtime_snapshot s;
    int calls = checkpoint_bundle_install_ready_test_remedy_calls();
    return f->ready && crs_tick_after(30) && crs_snap(&s) && s.currently_active &&
           checkpoint_bundle_install_ready_test_remedy_calls() == calls + 1 &&
           s.last_outcome == (int)COND_REMEDY_SKIP && s.attempts == 0 &&
           checkpoint_header_fetch_window_progress() == 0 && !boot_install_bundle_pending(f->dir);
}

/* D-2: an open episode whose remedy round ends on the strand gate (the lookup
 * still scanning, window durable) keeps its attempt budget through
 * progressing(), so it never latches on the strand. */
static int crs_case_progress_backstop(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    struct condition_runtime_snapshot s;
    CSIR_CHECK("strand backstop: fixture opens (H*=0, window not durable) with a projection",
               crw_open(&f, "strand-backstop", -1) && crs_projection_open(&pr, f.dir) &&
               crs_engine_begin());
    CSIR_CHECK("strand backstop: H*=0 opens an episode; the window waits",
               f.ready && crs_tick() && crs_snap(&s) && s.currently_active);
    CSIR_CHECK("strand backstop: window durable, H*=1, rung row not yet found (lookup scanning)",
               crs_stage_window(&f) && crs_seed_hstar(&f) && crs_log_filler(&pr, &f));
    checkpoint_rung_install_strand_test_set_scan_budget(1);
    CSIR_CHECK("strand backstop: after the backoff the remedy skips on the strand and "
               "progressing() keeps the attempt from counting", crs_backstop_round(&f));
    crs_engine_end();
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* One arm-site evaluation: the row it answered and the H* reads it took. */
static enum checkpoint_rung_row crs_arm_row(const struct crw_fixture *f, int *reads)
{
    struct checkpoint_rung_install_strand s = { .row = CHECKPOINT_RUNG_ROW_UNKNOWN };
    int before = checkpoint_rung_install_strand_test_hstar_reads();
    (void)checkpoint_rung_arm_would_strand(FSI_RUNG_H, f->is.hash[0].data, &s);
    *reads = checkpoint_rung_install_strand_test_hstar_reads() - before;
    return s.row;
}

/* D-3: work that cannot change the answer is not repeated. A decided ABSENT is
 * reused without an H* read while the log end has not moved; a grown log is
 * read again; a found row stays found without an H* read. */
static int crs_case_tail_cache(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    int reads = -1;
    CSIR_CHECK("strand cache: fixture opens with H* seeded and a projection",
               crs_open(&f, "strand-cache", true) && crs_projection_open(&pr, f.dir));
    CSIR_CHECK("strand cache: first call reads H* once and decides ABSENT",
               f.ready && crs_arm_row(&f, &reads) == CHECKPOINT_RUNG_ROW_ABSENT && reads == 1);
    CSIR_CHECK("strand cache: log unchanged -> the same answer, no H* read",
               f.ready && crs_arm_row(&f, &reads) == CHECKPOINT_RUNG_ROW_ABSENT && reads == 0);
    CSIR_CHECK("strand cache: log grew (filler) -> H* read again, still ABSENT",
               crs_log_filler(&pr, &f) && crs_arm_row(&f, &reads) == CHECKPOINT_RUNG_ROW_ABSENT &&
               reads == 1);
    CSIR_CHECK("strand cache: rung header logged -> found",
               crs_log_rung(&pr, &f) && crs_arm_row(&f, &reads) == CHECKPOINT_RUNG_ROW_PROJECTED);
    CSIR_CHECK("strand cache: a found row stays found with no H* read",
               f.ready && crs_arm_row(&f, &reads) == CHECKPOINT_RUNG_ROW_PROJECTED && reads == 0);
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* Calls under a moving published frontier with the log end unchanged: each one
 * answers the remembered ABSENT; adds the H* reads they took to *reads. */
static bool crs_frontier_moves(const struct crw_fixture *f, int *reads)
{
    bool ok = f->ready;
    for (int32_t tip = 2; ok && tip <= 5; tip++) {
        int r = -1;
        reducer_frontier_provable_tip_set(tip);
        ok = crs_arm_row(f, &r) == CHECKPOINT_RUNG_ROW_ABSENT;
        *reads += r;
    }
    return ok;
}

/* D-3, QUIET log (D-7b): the published frontier moves while the log end does
 * not, and the remembered answer takes ZERO extra H* reads. This is not block
 * apply: a persisted block also appends a block-status event, which
 * crs_case_tail_block_status pins. The next event-log append makes the next
 * call read H* again. */
static int crs_case_tail_frontier(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    int reads = -1, moved = 0;
    CSIR_CHECK("strand frontier: fixture opens with H* seeded and a projection",
               crs_open(&f, "strand-frontier", true) && crs_projection_open(&pr, f.dir));
    CSIR_CHECK("strand frontier: first call reads H* once and decides ABSENT",
               f.ready && crs_arm_row(&f, &reads) == CHECKPOINT_RUNG_ROW_ABSENT && reads == 1);
    CSIR_CHECK("strand frontier: published frontier moved 4 times, log end unchanged -> "
               "ABSENT each call with zero H* reads",
               crs_frontier_moves(&f, &moved) && moved == 0);
    CSIR_CHECK("strand frontier: the log grew -> the next call reads H* again, still ABSENT",
               f.ready && crs_fill_tail(&pr, CRS_ONE_HEADER_EVENT) &&
               crs_arm_row(&f, &reads) == CHECKPOINT_RUNG_ROW_ABSENT && reads == 1);
    reducer_frontier_test_reset_high_water();
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* One block-status event, as body_persist and script_validate append for every
 * block they persist, through the same emitter; true when exactly one 52-byte
 * record was appended. */
static bool crs_log_status(const struct crs_projection *pr, const struct crw_fixture *f)
{
    uint64_t before = event_log_size(pr->log);
    if (!f->ready || !pr->p)
        return false;
    block_index_emit_status_event(f->own[1], "strand-test", NULL, NULL);
    return event_log_flush(pr->log) &&
           event_log_size(pr->log) == before + EVENT_LOG_FRAME_OVERHEAD + EV_BLOCK_STATUS_WIRE_LEN;
}

/* One arm-site evaluation: true when it answered a DECIDED strand; *reads is
 * the H* reads it took. */
static bool crs_arm_strand(const struct crw_fixture *f, int *reads)
{
    struct checkpoint_rung_install_strand s = { .row = CHECKPOINT_RUNG_ROW_UNKNOWN };
    int before = checkpoint_rung_install_strand_test_hstar_reads();
    bool strand = checkpoint_rung_arm_would_strand(FSI_RUNG_H, f->is.hash[0].data, &s);
    *reads = checkpoint_rung_install_strand_test_hstar_reads() - before;
    return strand && checkpoint_rung_strand_decided(&s);
}

/* D-7c, the per-block cost (a pin: no production seam). One persisted block
 * appends one block-status event, so the remembered ABSENT is dropped and the
 * next call folds H* again exactly once; the answer is still "strand", and the
 * following call on the unchanged log reuses it with no read. */
static int crs_case_tail_block_status(void)
{
    int failures = 0;
    struct crw_fixture f;
    struct crs_projection pr = {0};
    int reads = -1;
    CSIR_CHECK("strand block-status: fixture opens with H* seeded and a projection",
               crs_open(&f, "strand-status", true) && crs_projection_open(&pr, f.dir));
    CSIR_CHECK("strand block-status: first call reads H* once and decides the strand",
               f.ready && crs_arm_strand(&f, &reads) && reads == 1);
    bool appended = crs_log_status(&pr, &f);
    bool strand = appended && crs_arm_strand(&f, &reads);
    printf("consensus_state_install_runtime: strand block-status H* reads after one "
           "block-status event=%d\n", reads);
    CSIR_CHECK("strand block-status: one block-status event appended -> exactly one further "
               "H* read, still strand", strand && reads == 1);
    CSIR_CHECK("strand block-status: log unchanged after it -> strand again with no H* read",
               f.ready && crs_arm_strand(&f, &reads) && reads == 0);
    crs_projection_close(&pr);
    crs_close(&f);
    return failures;
}

/* Up to `want` bytes of full-size header events (1344-byte solution, none of
 * them the rung) appended to the unprojected tail, deferred-sync. */
static bool crs_fill_tail(const struct crs_projection *pr, uint64_t want)
{
    static uint8_t sol[EV_BLOCK_HEADER_MAX_SOLUTION];
    uint8_t buf[EV_BLOCK_HEADER_FIXED_BYTES + EV_BLOCK_HEADER_MAX_SOLUTION];
    struct ev_block_header h;
    memset(&h, 0, sizeof(h));
    h.nSolutionSize = EV_BLOCK_HEADER_MAX_SOLUTION;
    const uint64_t frame = EVENT_LOG_FRAME_OVERHEAD + sizeof(buf);
    event_log_set_deferred_sync(pr->log, true);
    bool ok = true;
    for (uint32_t n = 1; ok && (uint64_t)n * frame <= want; n++) {
        size_t len = 0;
        h.height = (int32_t)n;
        memcpy(h.hash, &n, sizeof(n));
        h.hash[31] = 0xee;
        ok = ev_block_header_serialize(&h, sol, buf, sizeof(buf), &len) && len == sizeof(buf) &&
             event_log_append(pr->log, EV_BLOCK_HEADER, buf, len) != UINT64_MAX &&
             (n % 4096 != 0 || event_log_flush(pr->log));
    }
    ok = ok && event_log_flush(pr->log);
    event_log_set_deferred_sync(pr->log, false);
    return ok;
}

/* Bounded arm-site calls until the lookup decides; reports the cost. */
static bool crs_measure_calls(const struct crw_fixture *f, uint64_t tail)
{
    struct checkpoint_rung_install_strand s = { .row = CHECKPOINT_RUNG_ROW_PENDING };
    int calls = 0;
    int64_t total_us = 0, max_us = 0;
    uint64_t max_bytes = 0;
    while (s.row == CHECKPOINT_RUNG_ROW_PENDING && calls < 4096) {
        int64_t t0 = platform_time_monotonic_us();
        (void)checkpoint_rung_arm_would_strand(FSI_RUNG_H, f->is.hash[0].data, &s);
        int64_t us = platform_time_monotonic_us() - t0;
        uint64_t bytes = checkpoint_rung_install_strand_test_last_scan_bytes();
        total_us += us;
        max_us = us > max_us ? us : max_us;
        max_bytes = bytes > max_bytes ? bytes : max_bytes;
        calls++;
    }
    printf("consensus_state_install_runtime: strand scan measure tail_bytes=%llu calls=%d "
           "max_bytes_per_call=%llu max_call_us=%lld mean_call_us=%lld max_lock_hold_us=%lld "
           "row=%d\n", (unsigned long long)tail, calls, (unsigned long long)max_bytes,
           (long long)max_us, (long long)(calls ? total_us / calls : 0),
           (long long)checkpoint_rung_install_strand_test_max_hold_us(), (int)s.row);
    return s.row == CHECKPOINT_RUNG_ROW_ABSENT && calls > 1;
}

/* D-3 measurement: an unprojected tail of 256 MiB without the rung under the
 * test scratch directory (removed afterwards); reports bytes per call, wall
 * time per call and the longest hold of the lookup's lock. Runs in a forked
 * child that sets ZCL_STRESS_TESTS=1 for itself (the same shape as
 * case_regtest_producer_input in test_consensus_state_install_runtime.c), so
 * the case never self-skips: the land proof's accounting refuses a self-skipped
 * group, and this group must stay complete. */
#define CRS_MEASURE_MIB 256L
static int crs_case_scan_measure(void)
{
    int failures = 0;
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) {
        if (setenv("ZCL_STRESS_TESTS", "1", 1) != 0) _exit(2);
        const long mib = CRS_MEASURE_MIB;
        int failures = 0;
        struct crw_fixture f;
        struct crs_projection pr = {0};
        CSIR_CHECK("strand measure: fixture opens with H* seeded and a projection",
                   crs_open(&f, "strand-measure", true) && crs_projection_open(&pr, f.dir));
        CSIR_CHECK("strand measure: tail written", f.ready && crs_fill_tail(&pr, (uint64_t)mib << 20));
        CSIR_CHECK("strand measure: the bounded lookup decides ABSENT over the whole tail",
                   f.ready && crs_measure_calls(&f, event_log_size(pr.log)));
        crs_projection_close(&pr);
        crs_close(&f);
        fflush(NULL);
        _exit(failures == 0 ? 0 : 1);
    }
    int status = 0;
    printf("consensus_state_install_runtime: strand scan measure ran in a child "
           "(%ld MiB tail)\n", CRS_MEASURE_MIB);
    CSIR_CHECK("strand scan measure: child wrote and scanned the 256 MiB tail and decided ABSENT",
               child > 0 && waitpid(child, &status, 0) == child &&
               WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return failures;
}

enum {
    CRS_INSTALLED = 1 << 2, CRS_FAILED = 1 << 3, CRS_PENDING = 1 << 4,
    CRS_CUTOVER = 1 << 5, CRS_ARMED_AFTER = 1 << 6, CRS_STRAND_SKIP_AFTER = 1 << 7,
};

/* The install boot as app_init runs it: a pending request, then the passive
 * autodetect; then the arm check of the next session. Returns observations. */
/* The startup identity app_init installs under, plus the armed request. */
static bool crs_install_startup(const struct crw_fixture *f, const char *bundle,
                                struct node_db **node, struct wallet_sqlite **ws,
                                struct main_state **main)
{
    struct wallet *wallet;
    boot_wallet_cutover_test_slots(node, ws, &wallet, main);
    progress_store_close();
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/node.db", f->dir);
    if (n < 0 || (size_t)n >= sizeof(path) || !boot_datadir_lock_acquire(f->dir) ||
        !progress_store_open(f->dir) || !node_db_open(*node, path) ||
        !wallet_sqlite_open_r(*ws, (*node)->db).ok || boot_install_bundle_request(f->dir, bundle) != 1)
        return false;
    wallet_init(wallet);
    main_state_init(*main);
    boot_stage_reset_for_testing();
    for (int stage = BOOT_STAGE_DATADIR_LOCKED; stage <= BOOT_STAGE_BLOCK_INDEX_LOADED; ++stage)
        boot_stage_advance_to((enum boot_stage)stage);
    return true;
}

static int crs_install_observe(const struct crw_fixture *f, const char *bundle)
{
    struct node_db *node; struct wallet_sqlite *ws; struct main_state *main;
    char failed[600];
    snprintf(failed, sizeof(failed), "%s.failed", bundle);
    if (!crs_install_startup(f, bundle, &node, &ws, &main))
        return 1;
    int seen = boot_maybe_auto_install_consensus_bundle(node, main, f->dir, false) ? CRS_INSTALLED : 0;
    struct wallet_cutover_binding binding;
    seen |= access(failed, F_OK) == 0 ? CRS_FAILED : 0;
    seen |= boot_install_bundle_pending(f->dir) ? CRS_PENDING : 0;
    seen |= wallet_sqlite_cutover_read(ws, &binding) != WALLET_CUTOVER_ABSENT ? CRS_CUTOVER : 0;
    bool strand = false;
    seen |= crs_remedy(&strand) == (int)COND_REMEDY_SKIP && strand ? CRS_STRAND_SKIP_AFTER : 0;
    seen |= boot_install_bundle_pending(f->dir) ? CRS_ARMED_AFTER : 0;
    return seen;
}

static int crs_install_child(const struct crw_fixture *f)
{
    char bundle[400];
    snprintf(bundle, sizeof(bundle), "%s/bundles/consensus-state-bundle-%d.sqlite", f->dir, FSI_RUNG_H);
    fflush(NULL);
    pid_t child = fork();
    if (child == 0)
        _exit(crs_install_observe(f, bundle));
    int status = 0;
    bool done = child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status);
    int seen = done ? WEXITSTATUS(status) : 255;
    printf("consensus_state_install_runtime: strand install observations=0x%02x\n", seen);
    return seen;
}

/* The install boot with H* = 1: retriable refusal, no .failed, the consumed
 * request cleared (budget untouched), no cutover; then the arm check holds (N7). */
static int crs_case_install_refuses(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("strand install: fixture opens with H* seeded", crs_open(&f, "strand-install", true));
    int seen = f.ready ? crs_install_child(&f) : 255;
    CSIR_CHECK("strand install: not installed, no .failed, request cleared, no cutover row",
               (seen & (1 | 2 | CRS_INSTALLED | CRS_FAILED | CRS_PENDING | CRS_CUTOVER)) == 0);
    CSIR_CHECK("strand install: the next arm check skips and re-arms nothing (no respawn loop)",
               seen == CRS_STRAND_SKIP_AFTER);
    crs_close(&f);
    return failures;
}

/* No positive H*: the install takes main's path unchanged (here the empty
 * fixture bundle is a genuine refusal: .failed, the consumed request kept). */
static int crs_case_install_fresh(void)
{
    int failures = 0;
    struct crw_fixture f;
    CSIR_CHECK("strand install fresh: fixture opens", crs_open(&f, "strand-install-fresh", false));
    int seen = f.ready ? crs_install_child(&f) : 255;
    CSIR_CHECK("strand install fresh: main's path (.failed, request kept, nothing installed)",
               seen == (CRS_FAILED | CRS_PENDING | CRS_ARMED_AFTER));
    crs_close(&f);
    return failures;
}

static int case_rung_install_strand(void)
{
    return crs_case_core() + crs_case_arm_skips() + crs_case_arm_fresh() +
           crs_case_arm_projection() + crs_case_arm_logged() + crs_case_arm_tail_resumes() +
           crs_case_engine_quiet() + crs_case_episode_ends() + crs_case_witness_pending() +
           crs_case_witness_armed() + crs_case_progress_backstop() + crs_case_tail_cache() +
           crs_case_tail_frontier() + crs_case_tail_block_status() + crs_case_scan_measure() +
           crs_case_install_refuses() + crs_case_install_fresh();
}

#endif /* CONSENSUS_STATE_RUNG_STRAND_TEST_H */
