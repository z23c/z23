/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Unit tests for process_block_invalidate / process_block_reconsider —
 * the operator recovery lever (Bitcoin Core invalidateblock /
 * reconsiderblock semantics).
 *
 * Pure, in-memory, no LevelDB / no live activation controller:
 *
 *   (a) invalidate a tip block -> it is marked BLOCK_FAILED_VALID and
 *       find_most_work_chain (the canonical selector the production reorg
 *       path uses) picks the sibling fork instead.
 *   (b) reconsiderblock -> the failure marks are cleared and the original
 *       chain is selectable again.
 *   (c) invalidate a DEEPER block -> the block AND its descendant subtree
 *       are marked failed (FAILED_VALID on the target, FAILED_CHILD on
 *       descendants).
 *
 * The full disconnect-and-reorg of the active chain is covered by
 * test_reorg_safety. Fixture style mirrors test_reorg_safety.c and
 * test_process_block_revalidate.c.
 */

#include "test/test_core.h"
#include "test/test_block_map.h"

#include "chain/chain.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "validation/process_block.h"
#include "validation/process_block_invalidate.h"
#include "validation/process_block_revalidate.h"
#include "services/block_index_loader.h"
#include "services/chain_restore_repair.h"
#include "jobs/block_header_emit.h"
#include "storage/event_log.h"
#include "storage/event_log_payloads.h"
#include "storage/event_log_singleton.h"
#include "storage/txdb.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#define IB_CHECK(name, expr) do { \
    printf("invalidateblock: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* find_most_work_chain is the canonical selector the reorg path uses; it
 * skips BLOCK_FAILED entries. Declared in process_block_core.c. */
struct block_index *find_most_work_chain(struct main_state *ms);

static int g_restore_hook_calls;
static bool g_restore_hook_context_ok;
static struct block_index *g_restore_hook_first;
static struct block_index *g_restore_hook_old_tip;
static enum process_block_mempool_segment_action g_restore_hook_action;

static bool fake_mempool_restore(
    void *ctx,
    struct block_index *first_disconnected,
    struct block_index *old_active_tip,
    enum process_block_mempool_segment_action action,
    struct process_block_mempool_restore_result *out)
{
    g_restore_hook_context_ok = ctx == &g_restore_hook_calls;
    g_restore_hook_calls++;
    g_restore_hook_first = first_disconnected;
    g_restore_hook_old_tip = old_active_tip;
    g_restore_hook_action = action;
    if (out) {
        out->blocks_read = 1;
        out->txs_attempted = 1;
        if (action == PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED) {
            out->txs_accepted = 1;
            out->txs_relayed = 1;
        } else {
            out->txs_removed = 1;
        }
    }
    return true;
}

/* Build a heap block_index at `height` with `work`, owned hash from
 * `seed`, prev link `prev`, and clean (valid+have-data) status. Inserts
 * into the block_map. Returns the pindex. */
static struct block_index *mk_idx(struct main_state *ms, int height,
                                  uint64_t work, uint8_t seed,
                                  struct block_index *prev)
{
    struct block_index *bi = calloc(1, sizeof(*bi));
    struct uint256 *hp = malloc(sizeof(*hp));
    memset(hp, seed, sizeof(*hp));
    /* Make the height part of the hash so siblings at the same height
     * (different seeds) get distinct hashes. */
    hp->data[0] = (uint8_t)height;
    bi->nHeight = height;
    bi->phashBlock = hp;
    bi->pprev = prev;
    bi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    arith_uint256_set_u64(&bi->nChainWork, work);
    test_block_map_insert(&ms->map_block_index, hp, bi);
    return bi;
}

static void free_idx(struct block_index *bi)
{
    if (!bi) return;
    free((void *)(uintptr_t)bi->phashBlock);
    free(bi);
}


/* ── Operator vs automated invalidation: restart + self-heal policy ───────
 *
 * Only an operator invalidateblock is local policy that survives a restart
 * and is exempt from automatic revalidation. An automated invalidation (the
 * tip_fork_stale healer) must keep healing by evidence or restart. */

struct opfix {
    struct main_state ms;
    struct block_index *g, *a1, *a2, *a3;   /* honest chain, tip a3 */
    struct block_index *c2, *c3, *c4;       /* heavier competing header fork */
};

static void opfix_init(struct opfix *f)
{
    memset(f, 0, sizeof(*f));
    main_state_init(&f->ms);
    f->g  = mk_idx(&f->ms, 0, 1,  0x00, NULL);
    f->a1 = mk_idx(&f->ms, 1, 10, 0x0A, f->g);
    f->a2 = mk_idx(&f->ms, 2, 20, 0x0B, f->a1);
    f->a3 = mk_idx(&f->ms, 3, 30, 0x0C, f->a2);
    f->c2 = mk_idx(&f->ms, 2, 21, 0x1B, f->a1);
    f->c3 = mk_idx(&f->ms, 3, 31, 0x1C, f->c2);
    f->c4 = mk_idx(&f->ms, 4, 41, 0x1D, f->c3);
    struct block_index *hdr_only[] = { f->c2, f->c3, f->c4 };
    for (size_t i = 0; i < 3; i++) {   /* headers without bodies */
        hdr_only[i]->nStatus = BLOCK_VALID_TREE;
        hdr_only[i]->nTx = 0;
        hdr_only[i]->nChainTx = 0;
    }
    struct block_index *all[] = { f->g, f->a1, f->a2, f->a3,
                                  f->c2, f->c3, f->c4 };
    for (size_t i = 0; i < 7; i++)
        all[i]->nBits = 0x207fffff;    /* the restart forward pass re-derives work */
    active_chain_move_window_tip(&f->ms.chain_active, f->g);
    active_chain_move_window_tip(&f->ms.chain_active, f->a1);
    active_chain_move_window_tip(&f->ms.chain_active, f->a2);
    active_chain_move_window_tip(&f->ms.chain_active, f->a3);
    f->ms.pindex_best_header = f->a3;
}

static void opfix_free(struct opfix *f)
{
    free_idx(f->g);  free_idx(f->a1); free_idx(f->a2); free_idx(f->a3);
    free_idx(f->c2); free_idx(f->c3); free_idx(f->c4);
    main_state_free(&f->ms);
}

/* What a restart does to the in-memory index: the loader's persisted-failure
 * policy per entry, the forward pass (derives FAILED_CHILD from a kept
 * parent), then the boot clear-failed-above-tip repair. */
static void opfix_restart(struct opfix *f)
{
    struct block_index *sorted[] = { f->g, f->a1, f->a2, f->c2,
                                     f->a3, f->c3, f->c4 };
    for (size_t i = 0; i < 7; i++)
        (void)block_index_apply_persisted_failure_trust(sorted[i], 0);
    block_index_forward_pass(sorted, 7);
    (void)chain_restore_clear_failed_above_tip(&f->ms);
}

static bool op_root(const struct block_index *b)
{
    return (b->nStatus & BLOCK_FAILED_VALID) && (b->nStatus & BLOCK_OPERATOR_INVALID);
}

static bool op_derived(const struct block_index *b)
{
    return (b->nStatus & BLOCK_FAILED_MASK) == BLOCK_FAILED_CHILD &&
           (b->nStatus & BLOCK_OPERATOR_INVALID);
}

static bool op_cleared(const struct opfix *f)
{
    return ((f->a2->nStatus | f->a3->nStatus) &
            (BLOCK_FAILED_ANY_MASK | BLOCK_OPERATOR_INVALID)) == 0;
}

/* (a) operator invalidate -> restart -> peer re-feeds the branch -> stays off;
 * reconsider -> back. */
static int check_operator_invalidation_restart(void)
{
    int failures = 0;
    struct opfix f;
    opfix_init(&f);
    struct uint256 out;

    IB_CHECK("operator: invalidate a2 ok",
             process_block_invalidate_from(&f.ms, f.a2->phashBlock, &out,
                                           INVALIDATE_ORIGIN_OPERATOR) ==
                 INVALIDATE_OK);
    IB_CHECK("operator: root carries FAILED_VALID + OPERATOR_INVALID",
             op_root(f.a2));
    IB_CHECK("operator: descendant carries derived CHILD + OPERATOR_INVALID",
             op_derived(f.a3));
    IB_CHECK("operator: honest parent untouched",
             (f.a1->nStatus & (BLOCK_FAILED_ANY_MASK | BLOCK_OPERATOR_INVALID)) == 0);
    IB_CHECK("operator: tip retreats to a1 and selector stays there",
             active_chain_height(&f.ms.chain_active) == 1 &&
             find_most_work_chain(&f.ms) == f.a1);

    int64_t kept_before = block_index_operator_invalid_kept();
    opfix_restart(&f);
    IB_CHECK("restart: operator root survives the loader and boot repair",
             op_root(f.a2) && !block_is_revalidation_pending(f.a2));
    IB_CHECK("restart: the kept operator root is counted for the operator",
             block_index_operator_invalid_kept() == kept_before + 1);
    IB_CHECK("restart: descendant failure is re-derived from the root",
             op_derived(f.a3));
    IB_CHECK("restart: selector does not return to the invalidated branch",
             find_most_work_chain(&f.ms) == f.a1);

    /* The peer re-sends the invalidated branch: bodies present again and the
     * boot repair runs again. */
    f.a3->nStatus |= BLOCK_HAVE_DATA;
    (void)chain_restore_clear_failed_above_tip(&f.ms);
    IB_CHECK("peer re-feed: repair leaves root and descendant failed",
             op_root(f.a2) && op_derived(f.a3) &&
             find_most_work_chain(&f.ms) == f.a1);

    /* reconsider (of the DESCENDANT) lifts the operator root above it. */
    IB_CHECK("reconsider descendant: ok",
             process_block_reconsider(&f.ms, f.a3->phashBlock, &out) ==
                 RECONSIDER_OK);
    IB_CHECK("reconsider: root and subtree cleared, mark gone", op_cleared(&f));
    IB_CHECK("reconsider: node returns to the branch",
             find_most_work_chain(&f.ms) == f.a3);
    opfix_restart(&f);
    IB_CHECK("reconsider: stays cleared across restart", op_cleared(&f));

    opfix_free(&f);
    return failures;
}

/* (c) revalidation never spins on an operator-marked block. */
static int check_operator_revalidation_bounded(void)
{
    int failures = 0;
    struct opfix f;
    opfix_init(&f);
    struct uint256 out;

    (void)process_block_invalidate_from(&f.ms, f.a2->phashBlock, &out,
                                        INVALIDATE_ORIGIN_OPERATOR);
    unsigned st2 = f.a2->nStatus, st3 = f.a3->nStatus;
    int bad = 0;
    for (int i = 0; i < 1000; i++) {
        if (process_block_revalidate(2, &f.ms, &out) != REVAL_OPERATOR_HELD ||
            process_block_revalidate(3, &f.ms, &out) != REVAL_OPERATOR_HELD)
            bad++;
    }
    IB_CHECK("revalidate: 2000 calls, all OPERATOR_HELD (no connect-failed loop)",
             bad == 0);
    IB_CHECK("revalidate: operator-marked blocks unchanged",
             f.a2->nStatus == st2 && f.a3->nStatus == st3);
    IB_CHECK("revalidate: result name is stable",
             strcmp(reval_result_name(REVAL_OPERATOR_HELD),
                    "operator_held") == 0);
    opfix_free(&f);
    return failures;
}

/* (b) the automated path (tip_fork_stale -> process_block_invalidate) keeps
 * today's behaviour: no operator mark, healed by a restart even while the
 * heavier competing fork's bodies fail validation. */
static int check_automated_invalidation_heals(void)
{
    int failures = 0;
    struct opfix f;
    opfix_init(&f);
    struct uint256 out;

    /* The competing fork's bodies failed validation. */
    f.c2->nStatus |= BLOCK_FAILED_VALID;
    f.c3->nStatus |= BLOCK_FAILED_CHILD;
    f.c4->nStatus |= BLOCK_FAILED_CHILD;

    IB_CHECK("automated: stale-fork invalidate of honest a2 ok",
             process_block_invalidate(&f.ms, f.a2->phashBlock, &out) ==
                 INVALIDATE_OK);
    IB_CHECK("automated: failure is NOT an operator mark",
             (f.a2->nStatus & BLOCK_FAILED_VALID) &&
             ((f.a2->nStatus | f.a3->nStatus) & BLOCK_OPERATOR_INVALID) == 0);
    IB_CHECK("automated: node is wedged below the honest chain until healed",
             active_chain_height(&f.ms.chain_active) == 1 &&
             find_most_work_chain(&f.ms) == f.a1);

    opfix_restart(&f);
    IB_CHECK("automated: restart demotes the verdict (revalidation candidate)",
             !block_has_any_failure(f.a2) && block_is_revalidation_pending(f.a2));
    IB_CHECK("automated: after restart the node heals back to the honest chain",
             find_most_work_chain(&f.ms) == f.a3);
    opfix_free(&f);
    return failures;
}

/* (d) an automated invalidation of a block already under an operator root
 * must not become a second, persisted operator root. */
static int check_automated_under_operator_root(void)
{
    int failures = 0;
    struct opfix f;
    opfix_init(&f);
    struct uint256 out;

    (void)process_block_invalidate_from(&f.ms, f.a2->phashBlock, &out,
                                        INVALIDATE_ORIGIN_OPERATOR);
    IB_CHECK("nested automated: invalidate of an operator-held block is ok",
             process_block_invalidate(&f.ms, f.a3->phashBlock, &out) ==
                 INVALIDATE_OK);
    IB_CHECK("nested automated: held block gains no FAILED_VALID of its own",
             op_derived(f.a3));
    opfix_restart(&f);
    IB_CHECK("nested automated: restart re-derives it, no second root",
             op_root(f.a2) && op_derived(f.a3));
    IB_CHECK("nested automated: reconsider of the root ok",
             process_block_reconsider(&f.ms, f.a2->phashBlock, &out) ==
                 RECONSIDER_OK);
    opfix_restart(&f);
    IB_CHECK("nested automated: subtree stays cleared across restart",
             op_cleared(&f) && find_most_work_chain(&f.ms) == f.a3);
    opfix_free(&f);
    return failures;
}

#if !defined(_WIN32)
struct hdr_scan { const struct uint256 *hash; bool seen; unsigned status; };

static bool scan_header_cb(uint64_t off, enum event_log_type type,
                           const void *payload, size_t len, void *user)
{
    (void)off;
    struct hdr_scan *s = user;
    struct ev_block_header h;
    const uint8_t *sol = NULL;
    if (type != EV_BLOCK_HEADER ||
        !ev_block_header_parse(payload, len, &h, &sol))
        return true;
    if (memcmp(h.hash, s->hash->data, 32) == 0) {
        s->seen = true;
        s->status = h.nStatus;       /* last event wins, like the projection */
    }
    return true;
}

static bool log_status_of(const char *path, const struct uint256 *hash,
                          unsigned *status)
{
    event_log_t *log = event_log_open(path);
    if (!log) return false;
    struct hdr_scan s = { hash, false, 0 };
    (void)event_log_stream(log, 0, scan_header_cb, &s);
    event_log_close(log);
    *status = s.status;
    return s.seen;
}

/* Child: do the operator action against a real event log, then die by SIGKILL
 * the instant it returns (no close, no flush, no atexit). */
static void kill_child(const char *log_path, bool then_reconsider,
                       bool nested_root)
{
    event_log_t *log = event_log_open(log_path);
    if (!log) _exit(2);
    event_log_set_singleton(log);
    struct opfix f;
    opfix_init(&f);
    struct uint256 out;
    if (process_block_invalidate_from(&f.ms, f.a2->phashBlock, &out,
                                      INVALIDATE_ORIGIN_OPERATOR) != INVALIDATE_OK)
        _exit(3);
    /* A second operator invalidateblock below the first root. */
    if (nested_root &&
        process_block_invalidate_from(&f.ms, f.a3->phashBlock, &out,
                                      INVALIDATE_ORIGIN_OPERATOR) != INVALIDATE_OK)
        _exit(6);
    if (then_reconsider &&
        process_block_reconsider(&f.ms, f.a2->phashBlock, &out) != RECONSIDER_OK)
        _exit(4);
    kill(getpid(), SIGKILL);
    _exit(5);
}

static bool run_kill_child(const char *log_path, bool then_reconsider,
                           bool nested_root)
{
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) kill_child(log_path, then_reconsider, nested_root);
    int st = 0;
    return waitpid(pid, &st, 0) == pid && WIFSIGNALED(st) &&
           WTERMSIG(st) == SIGKILL;
}

/* kill -9 right after invalidateblock returns: the operator mark must already
 * be durable; after reconsiderblock the cleared status must be durable too. */
static int check_operator_mark_durable_before_reply(void)
{
    int failures = 0;
    char dir[PATH_MAX];
    if (!test_mkdtemp(dir, sizeof(dir), "z23_invalidate")) {
        IB_CHECK("durable: mkdtemp", false);
        return failures;
    }
    char path[PATH_MAX + 16];
    snprintf(path, sizeof(path), "%s/events.log", dir);

    struct opfix f;
    opfix_init(&f);
    const struct uint256 hash = *f.a2->phashBlock;
    unsigned status = 0;

    IB_CHECK("durable: child killed -9 right after invalidateblock",
             run_kill_child(path, false, false));
    IB_CHECK("durable: operator mark is on disk after the kill",
             log_status_of(path, &hash, &status) &&
             (status & BLOCK_FAILED_VALID) && (status & BLOCK_OPERATOR_INVALID));
    IB_CHECK("durable: child killed -9 right after reconsiderblock",
             run_kill_child(path, true, false));
    IB_CHECK("durable: cleared status is on disk after the kill",
             log_status_of(path, &hash, &status) &&
             (status & (BLOCK_FAILED_ANY_MASK | BLOCK_OPERATOR_INVALID)) == 0);

    /* A second operator root below the first: reconsider of the upper root
     * clears both, and the lower one's on-disk record must say so, or the
     * loader would keep it as an operator root after restart. */
    const struct uint256 hash3 = *f.a3->phashBlock;
    IB_CHECK("durable: child killed -9 after nested invalidate + reconsider",
             run_kill_child(path, true, true));
    IB_CHECK("durable: nested root's cleared status is on disk",
             log_status_of(path, &hash3, &status) &&
             (status & (BLOCK_FAILED_ANY_MASK | BLOCK_OPERATOR_INVALID)) == 0);

    opfix_free(&f);
    (void)unlink(path);
    (void)rmdir(dir);
    return failures;
}

/* Permit exactly one cleared header to reach the file. Deferred appends
 * exercise the operator's explicit flush. Exit without close to model
 * a restart while the target write is still refused. */
static int partial_clear_child(const char *path)
{
    struct opfix f;
    opfix_init(&f);
    struct block_tree_db tree = {0};
    g_active_block_tree = &tree;
    event_log_t *log = event_log_open(path);
    if (!log) return 1;
    event_log_set_singleton(log);
    if (process_block_invalidate_from(&f.ms, f.a2->phashBlock, NULL,
                                     INVALIDATE_ORIGIN_OPERATOR) != INVALIDATE_OK)
        return 2;
    uint64_t first = event_log_size(log);
    if (process_block_invalidate_from(&f.ms, f.a3->phashBlock, NULL,
                                     INVALIDATE_ORIGIN_OPERATOR) != INVALIDATE_OK)
        return 3;
    uint64_t end = event_log_size(log);
    struct rlimit limit;
    if (getrlimit(RLIMIT_FSIZE, &limit) || end <= first) return 4;
    limit.rlim_cur = end + (end - first);
    if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR || setrlimit(RLIMIT_FSIZE, &limit))
        return 5;
    event_log_test_set_force_per_append(0);
    event_log_set_deferred_sync(log, true);
    if (!event_log_deferred_sync_enabled(log)) return 6;
    if (process_block_reconsider(&f.ms, f.a2->phashBlock, NULL) !=
        RECONSIDER_PERSIST_FAILED) return 7;
    return op_root(f.a2) && op_root(f.a3) ? 0 : 8;
}

static int check_partial_clear_restart(void)
{
    int failures = 0;
    char dir[PATH_MAX];
    if (!test_mkdtemp(dir, sizeof(dir), "z23_reconsider_partial")) {
        IB_CHECK("partial clear: create fixture", false);
        return failures;
    }
    char path[PATH_MAX + 16];
    snprintf(path, sizeof(path), "%s/events.log", dir);
    pid_t pid = fork();
    if (pid == 0) _exit(partial_clear_child(path));
    int st = 0;
    IB_CHECK("partial clear: target flush refused with both live roots held",
        pid > 0 && waitpid(pid, &st, 0) == pid && WIFEXITED(st) && WEXITSTATUS(st) == 0);
    struct opfix f;
    opfix_init(&f);
    unsigned root = 0, child = 0;
    IB_CHECK("partial clear: upper root remains durable, lower clear reached disk",
        log_status_of(path, f.a2->phashBlock, &root) &&
        log_status_of(path, f.a3->phashBlock, &child) &&
        (root & BLOCK_FAILED_VALID) && (root & BLOCK_OPERATOR_INVALID) &&
        !(child & (BLOCK_FAILED_ANY_MASK | BLOCK_OPERATOR_INVALID)));
    f.a2->nStatus = root;
    f.a3->nStatus = child;
    opfix_restart(&f);
    IB_CHECK("partial clear: restart holds the whole subtree",
        op_root(f.a2) && op_derived(f.a3));
    struct block_tree_db tree = {0};
    struct block_tree_db *prior_tree = g_active_block_tree;
    event_log_t *prior_log = event_log_singleton();
    event_log_t *log = event_log_open(path);
    event_log_set_singleton(log);
    g_active_block_tree = &tree;
    IB_CHECK("partial clear: retry on descendant completes",
        log && process_block_reconsider(&f.ms, f.a3->phashBlock, NULL) == RECONSIDER_OK &&
        op_cleared(&f));
    g_active_block_tree = prior_tree;
    event_log_set_singleton(prior_log);
    if (log) event_log_close(log);
    IB_CHECK("partial clear: retried root clear reached disk",
        log_status_of(path, f.a2->phashBlock, &root) &&
        !(root & (BLOCK_FAILED_ANY_MASK | BLOCK_OPERATOR_INVALID)));
    opfix_free(&f);
    (void)unlink(path);
    (void)rmdir(dir);
    return failures;
}

static int check_reconsider_write_retry(bool nested)
{
    int failures = 0;
    char dir[PATH_MAX];
    if (!test_mkdtemp(dir, sizeof(dir), "z23_reconsider_retry")) {
        IB_CHECK("retry: create event-log fixture", false);
        return failures;
    }
    char path[PATH_MAX + 16];
    snprintf(path, sizeof(path), "%s/events.log", dir);
    struct opfix f;
    opfix_init(&f);
    struct block_tree_db tree = {0};
    struct block_tree_db *prior_tree = g_active_block_tree;
    event_log_t *prior_log = event_log_singleton();
    g_active_block_tree = &tree;
    event_log_t *log = event_log_open(path);
    event_log_set_singleton(log);
    IB_CHECK("retry: record operator root", log &&
        process_block_invalidate_from(&f.ms, f.a2->phashBlock, NULL,
                                     INVALIDATE_ORIGIN_OPERATOR) == INVALIDATE_OK);
    if (nested) {
        IB_CHECK("retry: record nested operator root",
            process_block_invalidate_from(&f.ms, f.a3->phashBlock, NULL,
                                         INVALIDATE_ORIGIN_OPERATOR) == INVALIDATE_OK);
    }
    event_log_set_singleton(NULL);
    if (log) event_log_close(log);
    log = event_log_open_readonly(path);
    event_log_set_singleton(log);
    IB_CHECK("retry: operator receives persistence error", log &&
        process_block_reconsider(&f.ms, f.a2->phashBlock, NULL) ==
            RECONSIDER_PERSIST_FAILED);
    IB_CHECK("retry: subtree remains held after write refusal",
        op_root(f.a2) && (nested ? op_root(f.a3) : op_derived(f.a3)));
    event_log_set_singleton(NULL);
    if (log) event_log_close(log);
    log = event_log_open(path);
    event_log_set_singleton(log);
    IB_CHECK("retry: writable store completes reconsideration", log &&
        process_block_reconsider(&f.ms, f.a2->phashBlock, NULL) == RECONSIDER_OK &&
        op_cleared(&f));
    event_log_set_singleton(prior_log);
    if (log) event_log_close(log);
    g_active_block_tree = prior_tree;
    unsigned status = 0;
    IB_CHECK("retry: root clear survives reopen",
        log_status_of(path, f.a2->phashBlock, &status) &&
        !(status & (BLOCK_FAILED_ANY_MASK | BLOCK_OPERATOR_INVALID)));
    if (nested) {
        IB_CHECK("retry: nested root clear survives reopen",
            log_status_of(path, f.a3->phashBlock, &status) &&
            !(status & (BLOCK_FAILED_ANY_MASK | BLOCK_OPERATOR_INVALID)));
    }
    opfix_free(&f);
    (void)unlink(path);
    (void)rmdir(dir);
    return failures;
}
#endif

static int check_operator_policy(void)
{
    int failures = 0;
    failures += check_operator_invalidation_restart();
    failures += check_operator_revalidation_bounded();
    failures += check_automated_invalidation_heals();
    failures += check_automated_under_operator_root();
#if !defined(_WIN32)
    failures += check_operator_mark_durable_before_reply();
    failures += check_reconsider_write_retry(false);
    failures += check_reconsider_write_retry(true);
    failures += check_partial_clear_restart();
#endif
    return failures;
}

int test_invalidateblock(void)
{
    printf("\n=== invalidateblock / reconsiderblock tests ===\n");
    int failures = 0;

    /* ── 1. Result-name mappings (stable strings for RPC/native/logs) ── */
    IB_CHECK("name(INVALIDATE_OK)",
             strcmp(invalidate_result_name(INVALIDATE_OK), "ok") == 0);
    IB_CHECK("name(INVALIDATE_BLOCK_NOT_FOUND)",
             strcmp(invalidate_result_name(INVALIDATE_BLOCK_NOT_FOUND),
                    "block_not_found") == 0);
    IB_CHECK("name(INVALIDATE_IS_GENESIS)",
             strcmp(invalidate_result_name(INVALIDATE_IS_GENESIS),
                    "is_genesis") == 0);
    IB_CHECK("name(INVALIDATE_DISCONNECT_FAIL)",
             strcmp(invalidate_result_name(INVALIDATE_DISCONNECT_FAIL),
                    "disconnect_failed") == 0);
    IB_CHECK("name(INVALIDATE_PERSIST_FAILED)",
             strcmp(invalidate_result_name(INVALIDATE_PERSIST_FAILED),
                    "persist_failed") == 0);
    IB_CHECK("name(RECONSIDER_OK)",
             strcmp(reconsider_result_name(RECONSIDER_OK), "ok") == 0);
    IB_CHECK("name(RECONSIDER_NO_FAILURE)",
             strcmp(reconsider_result_name(RECONSIDER_NO_FAILURE),
                    "no_failure") == 0);
    IB_CHECK("name(RECONSIDER_BLOCK_NOT_FOUND)",
             strcmp(reconsider_result_name(RECONSIDER_BLOCK_NOT_FOUND),
                    "block_not_found") == 0);

    /* ── 2. Bad-args + not-found paths ─────────────────────────────── */
    {
        struct uint256 h;
        memset(&h, 0xAB, sizeof(h));
        IB_CHECK("invalidate NULL ms → NOT_ATTEMPTED",
                 process_block_invalidate(NULL, &h, NULL) ==
                     INVALIDATE_NOT_ATTEMPTED);
        IB_CHECK("reconsider NULL ms → NOT_ATTEMPTED",
                 process_block_reconsider(NULL, &h, NULL) ==
                     RECONSIDER_NOT_ATTEMPTED);

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        IB_CHECK("invalidate unknown hash → BLOCK_NOT_FOUND",
                 process_block_invalidate(&ms, &h, NULL) ==
                     INVALIDATE_BLOCK_NOT_FOUND);
        IB_CHECK("reconsider unknown hash → BLOCK_NOT_FOUND",
                 process_block_reconsider(&ms, &h, NULL) ==
                     RECONSIDER_BLOCK_NOT_FOUND);
        main_state_free(&ms);
    }

    /* ── 3. Invalidate a tip block → selection picks the sibling ───── */
    /*
     *   genesis(0) → A1(1,w=10) → A2(2,w=20)        [chain A, the tip]
     *             ↘ B1(1,w=11) → B2(2,w=21)         [chain B, more work]
     *
     * With everything clean, find_most_work_chain picks B2. After we
     * invalidate B2 (the most-work tip), B2 + descendants drop out and
     * the selector falls back to A2.
     */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *b1 = mk_idx(&ms, 1, 11, 0x1A, g);
        struct block_index *b2 = mk_idx(&ms, 2, 21, 0x1B, b1);

        /* Active tip = A2 (chain A). pindex_best_header = the
         * most-work header so selection is honest. */
        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        ms.pindex_best_header = b2;

        IB_CHECK("pre-invalidate: selector picks B2 (most work)",
                 find_most_work_chain(&ms) == b2);

        /* Invalidate B2 (pure mark — no activation/coins needed). */
        size_t marked_children = 0;
        process_block_mark_invalid(&ms, b2, &marked_children);

        IB_CHECK("invalidate tip: B2 carries BLOCK_FAILED_VALID",
                 (b2->nStatus & BLOCK_FAILED_VALID) != 0);
        /* Core semantics: validity level is preserved (not lowered) so
         * reconsider restores selectability by clearing only FAILED. */
        IB_CHECK("invalidate tip: B2 keeps its validity level",
                 (b2->nStatus & BLOCK_VALID_MASK) != 0);
        /* B2 has no descendants → zero FAILED_CHILD marks. */
        IB_CHECK("invalidate tip: no descendants marked",
                 marked_children == 0);
        IB_CHECK("invalidate tip: selector now picks A2 (reorg target)",
                 find_most_work_chain(&ms) == a2);

        /* ── 4. reconsiderblock → B2 cleared, B2 selectable again ── */
        size_t cleared = 0;
        process_block_clear_invalid(&ms, b2, &cleared);
        IB_CHECK("reconsider: cleared count == 1 (just B2)",
                 cleared == 1);
        IB_CHECK("reconsider: B2 failure bits cleared",
                 (b2->nStatus & BLOCK_FAILED_ANY_MASK) == 0);
        IB_CHECK("reconsider: selector picks B2 again",
                 find_most_work_chain(&ms) == b2);

        free_idx(g); free_idx(a1); free_idx(a2);
        free_idx(b1); free_idx(b2);
        main_state_free(&ms);
    }

    /* ── 5. Invalidate a DEEPER block → whole subtree drops out ────── */
    /*
     *   genesis(0) → A1(1,w=10) → A2(2,w=20)              [chain A, tip]
     *             ↘ B1(1,w=11) → B2(2,w=21) → B3(3,w=31)  [chain B]
     *
     * Invalidate B1 (the fork root, deeper than the B tip). B1 gets
     * FAILED_VALID; B2 and B3 inherit FAILED_CHILD. Selection falls back
     * to A2 even though the B branch had more raw work.
     */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *b1 = mk_idx(&ms, 1, 11, 0x1A, g);
        struct block_index *b2 = mk_idx(&ms, 2, 21, 0x1B, b1);
        struct block_index *b3 = mk_idx(&ms, 3, 31, 0x1C, b2);

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        ms.pindex_best_header = b3;

        IB_CHECK("deeper: pre-invalidate selector picks B3",
                 find_most_work_chain(&ms) == b3);

        size_t marked_children = 0;
        process_block_mark_invalid(&ms, b1, &marked_children);

        IB_CHECK("deeper: B1 carries FAILED_VALID",
                 (b1->nStatus & BLOCK_FAILED_VALID) != 0);
        IB_CHECK("deeper: B2 inherited FAILED_CHILD",
                 (b2->nStatus & BLOCK_FAILED_CHILD) != 0);
        IB_CHECK("deeper: B3 inherited FAILED_CHILD",
                 (b3->nStatus & BLOCK_FAILED_CHILD) != 0);
        IB_CHECK("deeper: 2 descendants marked",
                 marked_children == 2);
        IB_CHECK("deeper: A-chain untouched (A2 clean)",
                 (a2->nStatus & BLOCK_FAILED_ANY_MASK) == 0);
        IB_CHECK("deeper: selector falls back to A2",
                 find_most_work_chain(&ms) == a2);

        /* reconsider B1 clears the whole subtree (B1 + B2 + B3 = 3). */
        size_t cleared = 0;
        process_block_clear_invalid(&ms, b1, &cleared);
        IB_CHECK("deeper: reconsider clears B1+B2+B3 (3)",
                 cleared == 3);
        IB_CHECK("deeper: B3 failure bits cleared",
                 (b3->nStatus & BLOCK_FAILED_ANY_MASK) == 0);
        IB_CHECK("deeper: selector picks B3 again after reconsider",
                 find_most_work_chain(&ms) == b3);

        free_idx(g); free_idx(a1); free_idx(a2);
        free_idx(b1); free_idx(b2); free_idx(b3);
        main_state_free(&ms);
    }

    /* ── 6. reconsider on a clean block → NO_FAILURE no-op ─────────── */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);

        size_t cleared = 0;
        process_block_clear_invalid(&ms, a1, &cleared);
        IB_CHECK("reconsider clean block: nothing cleared", cleared == 0);

        free_idx(g); free_idx(a1);
        main_state_free(&ms);
    }

    /* ── 7. Hash identity: duplicate active object still disconnects ──
     *
     * Distinct block_index objects can exist for one block hash. The block
     * map resolves `target`, while the active-chain slot holds
     * `active_twin`. invalidateblock is hash-addressed and must retreat
     * through the active object's parent; pointer-only containment would
     * leave a FAILED active tip published while reporting success. */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        struct block_index *g = mk_idx(&ms, 0, 1, 0x00, NULL);
        struct block_index *target = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index active_twin = *target;
        active_twin.hashBlock = *target->phashBlock;
        active_twin.phashBlock = &active_twin.hashBlock;
        active_twin.pprev = g;
        ms.pindex_best_header = &active_twin;

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, &active_twin);
        IB_CHECK("same-hash fixture: pointer containment differs",
                 !active_chain_contains(&ms.chain_active, target));
        IB_CHECK("same-hash fixture: active and target hashes agree",
                 uint256_eq(active_twin.phashBlock, target->phashBlock));

        size_t marked_children = 0;
        process_block_mark_invalid(&ms, target, &marked_children);
        IB_CHECK("same-hash active object: live twin is marked failed",
                 (active_twin.nStatus & BLOCK_FAILED_VALID) != 0);
        bool disconnected = process_block_disconnect_to_parent(
            NULL, &ms, NULL, NULL, target, NULL);
        IB_CHECK("same-hash active object: disconnect succeeds",
                 disconnected);
        IB_CHECK("same-hash active object: tip retreats to parent",
                 active_chain_height(&ms.chain_active) == 0 &&
                 active_chain_tip(&ms.chain_active) == g);
        size_t cleared = 0;
        process_block_clear_invalid(&ms, target, &cleared);
        IB_CHECK("same-hash active object: reconsider clears live twin",
                 (active_twin.nStatus & BLOCK_FAILED_ANY_MASK) == 0);

        free_idx(g); free_idx(target);
        main_state_free(&ms);
    }

    /* ── 8. Full operator path dispatches post-unwind mempool restore ── */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g = mk_idx(&ms, 0, 1, 0x00, NULL);
        struct block_index *tip = mk_idx(&ms, 1, 10, 0x0A, g);
        active_chain_move_window_tip(&ms.chain_active, tip);
        ms.pindex_best_header = tip;

        g_restore_hook_calls = 0;
        g_restore_hook_context_ok = false;
        g_restore_hook_first = NULL;
        g_restore_hook_old_tip = NULL;
        process_block_set_mempool_restore_hook(fake_mempool_restore,
                                                &g_restore_hook_calls);
        IB_CHECK("mempool hook: full invalidate succeeds",
                 process_block_invalidate(&ms, tip->phashBlock, NULL) ==
                     INVALIDATE_OK);
        IB_CHECK("mempool hook: called exactly once after active disconnect",
                 g_restore_hook_calls == 1);
        IB_CHECK("mempool hook: context survives dispatch",
                 g_restore_hook_context_ok);
        IB_CHECK("mempool hook: exact disconnected segment named",
                 g_restore_hook_first == tip && g_restore_hook_old_tip == tip);
        IB_CHECK("mempool hook: invalidate requests restore action",
                 g_restore_hook_action ==
                     PROCESS_BLOCK_MEMPOOL_RESTORE_DISCONNECTED);
        IB_CHECK("mempool hook: failed ancestry retracts best header",
                 ms.pindex_best_header == g);
        /* Production's reducer reconnect repopulates the raw window before
         * the reconsider-side mempool reconciliation; mirror that here. */
        IB_CHECK("mempool hook: model reducer reconnect window",
                 active_chain_move_window_tip(&ms.chain_active, tip));
        IB_CHECK("mempool hook: reconsider succeeds",
                 process_block_reconsider(&ms, tip->phashBlock, NULL) ==
                     RECONSIDER_OK);
        IB_CHECK("mempool hook: reconsider dispatches second action",
                 g_restore_hook_calls == 2 &&
                     g_restore_hook_action ==
                         PROCESS_BLOCK_MEMPOOL_REMOVE_RECONNECTED);
        IB_CHECK("mempool hook: reconnected segment named exactly",
                 g_restore_hook_first == tip && g_restore_hook_old_tip == tip);
        IB_CHECK("mempool hook: reconsider rebuilds best header",
                 ms.pindex_best_header == tip);
        process_block_set_mempool_restore_hook(NULL, NULL);

        free_idx(g); free_idx(tip);
        main_state_free(&ms);
    }

    /* ── 9. Canonical tip FLOOR: refuse a below-tip higher-work fork ──
     *
     * A fork tip at a LOWER height but HIGHER nChainWork (bad work
     * accounting) must NOT trigger a backwards reorg: find_most_work_chain
     * returns the active TIP instead. The floor is DIRECTIONAL: a
     * higher-work fork ABOVE the tip is still selected. Both directions
     * are asserted.
     */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        /* Active chain to tip A4 (height 4, work 40). */
        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *a3 = mk_idx(&ms, 3, 30, 0x0C, a2);
        struct block_index *a4 = mk_idx(&ms, 4, 40, 0x0D, a3);
        /* Fork tip: height 1 (BELOW tip h=4) but work 99 (ABOVE tip work
         * 40) — the pathological backwards candidate. */
        struct block_index *s1 = mk_idx(&ms, 1, 99, 0x5A, g);

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        active_chain_move_window_tip(&ms.chain_active, a3);
        active_chain_move_window_tip(&ms.chain_active, a4);
        ms.pindex_best_header = s1; /* the import thinks s1 is "best" */

        /* s1 has the max nChainWork; without the floor the selector would
         * reorg backward 3 blocks. The floor must return the tip a4. */
        IB_CHECK("floor: below-tip higher-work fork → selector returns TIP",
                 find_most_work_chain(&ms) == a4);
        IB_CHECK("floor: below-tip fork s1 is NOT selected",
                 find_most_work_chain(&ms) != s1);

        free_idx(g); free_idx(a1); free_idx(a2);
        free_idx(a3); free_idx(a4); free_idx(s1);
        main_state_free(&ms);
    }
    {
        /* Directional check: a higher-work fork ABOVE the tip IS selected
         * (the floor only blocks BACKWARD reorgs, not forward ones).
         *   genesis → A1 → A2                 [active tip A2, h=2]
         *          ↘ D1 → D2 → D3             [fork, h=3, more work]
         */
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);

        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *d1 = mk_idx(&ms, 1, 11, 0x2A, g);
        struct block_index *d2 = mk_idx(&ms, 2, 21, 0x2B, d1);
        struct block_index *d3 = mk_idx(&ms, 3, 31, 0x2C, d2);

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        ms.pindex_best_header = d3;

        IB_CHECK("floor: above-tip higher-work fork IS selected (forward reorg)",
                 find_most_work_chain(&ms) == d3);

        free_idx(g); free_idx(a1); free_idx(a2);
        free_idx(d1); free_idx(d2); free_idx(d3);
        main_state_free(&ms);
    }

    /* ── 10. clear_invalid: refusal, descendant-only, unrelated marks ── */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);

        size_t cleared = 99;
        process_block_clear_invalid(NULL, a1, &cleared);
        IB_CHECK("clear NULL ms: cleared_out zeroed", cleared == 0);
        cleared = 99;
        process_block_clear_invalid(&ms, NULL, &cleared);
        IB_CHECK("clear NULL target: cleared_out zeroed", cleared == 0);
        a1->nStatus |= BLOCK_FAILED_VALID;
        process_block_clear_invalid(&ms, a1, NULL);
        IB_CHECK("clear NULL cleared_out: target failure still cleared",
                 (a1->nStatus & BLOCK_FAILED_ANY_MASK) == 0);

        free_idx(g); free_idx(a1);
        main_state_free(&ms);
    }
    {
        /* Clean target with a failed descendant: only the descendant counts. */
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        a2->nStatus |= BLOCK_FAILED_CHILD;

        size_t cleared = 0;
        process_block_clear_invalid(&ms, a1, &cleared);
        IB_CHECK("clean target: only failed descendant counted", cleared == 1);
        IB_CHECK("clean target: descendant failure bits cleared",
                 (a2->nStatus & BLOCK_FAILED_ANY_MASK) == 0);

        free_idx(g); free_idx(a1); free_idx(a2);
        main_state_free(&ms);
    }
    {
        /* Marks off the target's ancestry are never cleared: a fork root and
         * its child, and a corrupt ring whose pprev is not strictly
         * decreasing (walk breaks before reaching the target). */
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *a2 = mk_idx(&ms, 2, 20, 0x0B, a1);
        struct block_index *b1 = mk_idx(&ms, 1, 11, 0x1A, g);
        struct block_index *b2 = mk_idx(&ms, 2, 21, 0x1B, b1);
        struct block_index *q  = mk_idx(&ms, 3, 30, 0x7B, a1);
        struct block_index *p  = mk_idx(&ms, 3, 30, 0x7A, a2);
        p->pprev = q;

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        active_chain_move_window_tip(&ms.chain_active, a2);
        ms.pindex_best_header = a2;

        process_block_mark_invalid(&ms, b1, NULL);
        p->nStatus |= BLOCK_FAILED_CHILD;

        size_t cleared = 99;
        process_block_clear_invalid(&ms, a1, &cleared);
        IB_CHECK("unrelated marks: cleared count zero", cleared == 0);
        IB_CHECK("unrelated marks: fork root keeps FAILED_VALID",
                 (b1->nStatus & BLOCK_FAILED_VALID) != 0);
        IB_CHECK("unrelated marks: fork child keeps FAILED_CHILD",
                 (b2->nStatus & BLOCK_FAILED_CHILD) != 0);
        IB_CHECK("unrelated marks: corrupt-ring entry keeps FAILED_CHILD",
                 (p->nStatus & BLOCK_FAILED_CHILD) != 0);

        free_idx(g); free_idx(a1); free_idx(a2); free_idx(b1);
        free_idx(b2); free_idx(q); free_idx(p);
        main_state_free(&ms);
    }
    {
        /* Same-hash header twin (pindex_best_header) is cleared with the
         * target but does not add to the durable cleared count. */
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g = mk_idx(&ms, 0, 1, 0x00, NULL);
        struct block_index *target = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index header_twin = *target;
        header_twin.hashBlock = *target->phashBlock;
        header_twin.phashBlock = &header_twin.hashBlock;
        header_twin.pprev = g;
        active_chain_move_window_tip(&ms.chain_active, g);
        ms.pindex_best_header = &header_twin;

        process_block_mark_invalid(&ms, target, NULL);
        IB_CHECK("header twin: marked failed with target",
                 (header_twin.nStatus & BLOCK_FAILED_VALID) != 0);
        size_t cleared = 0;
        process_block_clear_invalid(&ms, target, &cleared);
        IB_CHECK("header twin: durable cleared count is target only",
                 cleared == 1);
        IB_CHECK("header twin: twin failure bits cleared",
                 (header_twin.nStatus & BLOCK_FAILED_ANY_MASK) == 0);

        free_idx(g); free_idx(target);
        main_state_free(&ms);
    }

    /* ── 11. reconsider: out-hash and no-failure contract ─────────── */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        main_state_init(&ms);
        struct block_index *g  = mk_idx(&ms, 0, 1,  0x00, NULL);
        struct block_index *a1 = mk_idx(&ms, 1, 10, 0x0A, g);
        struct block_index *b1 = mk_idx(&ms, 1, 11, 0x1A, g);

        active_chain_move_window_tip(&ms.chain_active, g);
        active_chain_move_window_tip(&ms.chain_active, a1);
        ms.pindex_best_header = a1;

        struct uint256 out;
        memset(&out, 0xEE, sizeof(out));
        IB_CHECK("reconsider NULL ms: out_hash zeroed",
                 process_block_reconsider(NULL, a1->phashBlock, &out) ==
                     RECONSIDER_NOT_ATTEMPTED && uint256_is_null(&out));

        struct uint256 unknown;
        memset(&unknown, 0xAB, sizeof(unknown));
        memset(&out, 0xEE, sizeof(out));
        IB_CHECK("reconsider unknown hash: out_hash zeroed",
                 process_block_reconsider(&ms, &unknown, &out) ==
                     RECONSIDER_BLOCK_NOT_FOUND && uint256_is_null(&out));

        memset(&out, 0xEE, sizeof(out));
        IB_CHECK("reconsider clean block: NO_FAILURE",
                 process_block_reconsider(&ms, a1->phashBlock, &out) ==
                     RECONSIDER_NO_FAILURE);
        IB_CHECK("reconsider clean block: out_hash names target",
                 uint256_eq(&out, a1->phashBlock));

        process_block_mark_invalid(&ms, b1, NULL);
        memset(&out, 0xEE, sizeof(out));
        IB_CHECK("reconsider failed fork block: RECONSIDER_OK",
                 process_block_reconsider(&ms, b1->phashBlock, &out) ==
                     RECONSIDER_OK);
        IB_CHECK("reconsider failed fork block: out_hash names target",
                 uint256_eq(&out, b1->phashBlock));
        IB_CHECK("reconsider failed fork block: failure bits cleared",
                 (b1->nStatus & BLOCK_FAILED_ANY_MASK) == 0);

        free_idx(g); free_idx(a1); free_idx(b1);
        main_state_free(&ms);
    }

    failures += check_operator_policy();

    printf("invalidateblock: %d failures\n", failures);
    return failures;
}
