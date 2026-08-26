/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Body torn-read repair note + quarantine (lane E3). Contract + rationale:
 * jobs/reducer_frontier.h. When stage_repair_read_active_block_checked
 * (reducer_frontier_replay.c) cannot read the canonical body for a HAVE_DATA
 * height — the on-disk bytes are torn (pread failed) or read fine but hash to
 * the WRONG block — a read that only DEFERs wedges every downstream
 * stage forever. This records the failing height HERE (event-driven; no new
 * scan) so the have_data_unreadable Condition clears BLOCK_HAVE_DATA OFF-LOCK
 * and body_fetch re-downloads the body. Deliberately does NOT clear HAVE_DATA
 * from inside the progress-locked replay (a side-channel write racing the
 * reducer's single writer). The single-slot, lowest-height-first record uses a
 * short independent mutex and generation-bound hash identity, so concurrent
 * readers never observe mixed fields and stale witnesses cannot clear a newer
 * same-height failure. */

#include "jobs/reducer_frontier.h"

#include "util/blocker.h"
#include "util/sync.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static zcl_mutex_t g_body_read_note_lock = PTHREAD_MUTEX_INITIALIZER;
static struct reducer_frontier_body_read_note g_body_read_note = {
    .height = -1,
};

const char *reducer_frontier_body_read_reason_name(
    enum reducer_frontier_body_read_reason r)
{
    switch (r) {
    case REDUCER_FRONTIER_BODY_READ_DISK:  return "disk_read_failed";
    case REDUCER_FRONTIER_BODY_READ_WRONG: return "wrong_block";
    case REDUCER_FRONTIER_BODY_READ_OK:    break;
    }
    return "none";
}

int64_t reducer_frontier_body_read_note_height(void)
{
    struct reducer_frontier_body_read_note note;
    return reducer_frontier_body_read_note_snapshot(&note) ? note.height : -1;
}

bool reducer_frontier_body_read_note_active(void)
{
    struct reducer_frontier_body_read_note note;
    return reducer_frontier_body_read_note_snapshot(&note);
}

int reducer_frontier_body_read_note_file(void)
{
    struct reducer_frontier_body_read_note note;
    return reducer_frontier_body_read_note_snapshot(&note) ? note.file : -1;
}

int64_t reducer_frontier_body_read_note_pos(void)
{
    struct reducer_frontier_body_read_note note;
    return reducer_frontier_body_read_note_snapshot(&note) ? note.pos : 0;
}

bool reducer_frontier_body_read_note_snapshot(
    struct reducer_frontier_body_read_note *out)
{
    if (!out)
        return false;
    zcl_mutex_lock(&g_body_read_note_lock);
    *out = g_body_read_note;
    zcl_mutex_unlock(&g_body_read_note_lock);
    return out->active;
}

/* Name ONE typed TRANSIENT blocker once the per-height failure count crosses
 * the quarantine bound. blocker_set de-dups within its rate-limit window, so a
 * repeated cross is not spam. Naming height/nFile/pos/reason turns a silent
 * "repair defers" into an operator-visible blocker. */
static void body_read_repair_raise_blocker(
    int height, int nFile, int64_t pos,
    enum reducer_frontier_body_read_reason reason, int count)
{
    char reason_s[BLOCKER_REASON_MAX];
    snprintf(reason_s, sizeof(reason_s),
             "body read failed height=%d nFile=%d pos=%lld reason=%s count=%d; "
             "indexed bytes cannot be hash-verified; clear HAVE_DATA, "
             "refetch the exact active hash, and revalidate before serving",
             height, nFile, (long long)pos,
             reducer_frontier_body_read_reason_name(reason), count);
    struct blocker_record b;
    if (blocker_init(&b, "reducer_frontier.body_read_torn", "stage_repair",
                     BLOCKER_TRANSIENT, reason_s))
        (void)blocker_set(&b);
}

uint64_t reducer_frontier_body_read_note_record(
    int height, int nFile, int64_t pos,
    enum reducer_frontier_body_read_reason reason,
    const struct uint256 *block_hash)
{
    if (height < 0 || !block_hash)
        return 0;
    zcl_mutex_lock(&g_body_read_note_lock);
    if (g_body_read_note.active && height > g_body_read_note.height) {
        uint64_t generation = g_body_read_note.generation;
        zcl_mutex_unlock(&g_body_read_note_lock);
        return generation;
    }
    bool same = g_body_read_note.active &&
        height == g_body_read_note.height &&
        uint256_eq(block_hash, &g_body_read_note.block_hash);
    if (same) {
        g_body_read_note.count++;
    } else {
        g_body_read_note.active = true;
        g_body_read_note.height = height;
        g_body_read_note.count = 1;
    }
    g_body_read_note.file = nFile;
    g_body_read_note.pos = pos;
    g_body_read_note.reason = reason;
    g_body_read_note.block_hash = *block_hash;
    g_body_read_note.generation++;
    int count = g_body_read_note.count;
    uint64_t generation = g_body_read_note.generation;
    if (count >= REDUCER_FRONTIER_BODY_READ_QUARANTINE_MAX)
        body_read_repair_raise_blocker(height, nFile, pos, reason, count);
    zcl_mutex_unlock(&g_body_read_note_lock);
    return generation;
}

bool reducer_frontier_body_read_note_clear_if(
    const struct reducer_frontier_body_read_note *expected)
{
    if (!expected || !expected->active)
        return false;
    zcl_mutex_lock(&g_body_read_note_lock);
    bool match = g_body_read_note.active &&
        g_body_read_note.generation == expected->generation &&
        g_body_read_note.height == expected->height &&
        uint256_eq(&g_body_read_note.block_hash, &expected->block_hash);
    if (match) {
        uint64_t generation = g_body_read_note.generation;
        memset(&g_body_read_note, 0, sizeof(g_body_read_note));
        g_body_read_note.height = -1;
        g_body_read_note.generation = generation;
    }
    if (match)
        blocker_clear("reducer_frontier.body_read_torn");
    zcl_mutex_unlock(&g_body_read_note_lock);
    return match;
}

#ifdef ZCL_TESTING
void reducer_frontier_body_read_note_reset_for_testing(void)
{
    zcl_mutex_lock(&g_body_read_note_lock);
    memset(&g_body_read_note, 0, sizeof(g_body_read_note));
    g_body_read_note.height = -1;
    zcl_mutex_unlock(&g_body_read_note_lock);
    blocker_clear("reducer_frontier.body_read_torn");
}

int reducer_frontier_body_read_note_count_for_testing(void)
{
    struct reducer_frontier_body_read_note note;
    return reducer_frontier_body_read_note_snapshot(&note) ? note.count : 0;
}
#endif
