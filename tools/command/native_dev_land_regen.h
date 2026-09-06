/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land regen phase — regenerate the generated-doc artifacts
 *          (capability inventory, executor routing, doc-counts block) in
 *          the landing worktree right after a successful rebase, so a
 *          submission never fails at push time for staleness a train
 *          assembler would otherwise have to fix by hand.
 *
 * Split out of tools/command/native_dev_land.c (which was already at its
 * file-size ceiling) rather than grown inside it. native_dev_land.c owns
 * the queue, the rows and every other phase; this file owns exactly one
 * phase's mechanics and is called from one site in dl_step_start(), between
 * the rebase and the lint pass.
 */
#ifndef ZCL_NATIVE_DEV_LAND_REGEN_H
#define ZCL_NATIVE_DEV_LAND_REGEN_H

#include <stddef.h>

/* Run the regen phase in the already-rebased landing worktree `wt` (HEAD is
 * the row's rebased tip, ancestor of `tip_sha`). `tip_sha` is the original
 * submitted commit id, used only to read its subject line for the regen
 * commit's own subject; it is never checked out or moved.
 *
 * Returns 1 on success (whether or not a commit was made — see below), or
 * -1 on a hard failure with a human-actionable `why` (min 128 bytes
 * recommended; longer is truncated, never overflowed).
 *
 * On return, regardless of success/failure sign:
 *   `transcript` (transcript_cap bytes) always holds whatever make/git
 *   output was captured, NUL-terminated, empty string if nothing ran yet
 *   (e.g. the worktree has no Makefile at all — a hermetic test rig, never
 *   a real landing worktree). The caller appends it to the attempt log
 *   exactly like every other phase's output.
 *
 * On success only:
 *   `new_head` (>= 41 bytes) receives HEAD's full commit id AFTER this
 *   call: identical to HEAD on entry when nothing changed, or the new
 *   regen commit's id when one was made. The caller folds this into
 *   row->local — the row schema gains no new field for the regen commit;
 *   row->local already IS "the tip the rest of the step proves and
 *   pushes", and a regen commit sitting on top of the rebased tip is
 *   exactly that same field's job. */
int zcl_dev_land_regen_phase(const char *wt, const char *tip_sha,
                             char *new_head, size_t new_head_cap,
                             char *transcript, size_t transcript_cap,
                             char *why, size_t why_cap);

#endif /* ZCL_NATIVE_DEV_LAND_REGEN_H */
