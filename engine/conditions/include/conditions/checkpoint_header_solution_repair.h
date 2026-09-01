/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_header_solution_repair — the app-half of the checkpoint-header
 * solution cure (the D8 instant-on last gate). See the .c for the full seam.
 *
 * DETECT: the node is below the compiled checkpoint, a checkpoint bundle is
 *   staged for install, the header chain owns the checkpoint block, BUT the
 *   checkpoint header's Equihash solution is not durably available (no pass
 *   record and no header_solution_repair row) — so
 *   validate_headers_stage_ensure_pass_record cannot mint the -4 header
 *   bootstrap anchor and the bundle install refuses (retriably).
 * REMEDY: arm the net-thread getheaders fetch (net/checkpoint_header_fetch.h);
 *   when it captures the one checkpoint header, frozen-verify (hash-pin +
 *   Equihash) and persist it, then mint the pass record. Names a typed blocker
 *   when no peer can supply it (bounded retry-forever, never silent).
 * WITNESS: the checkpoint solution is now durably available (pass record or
 *   repair row) — the bundle install can bind.
 *
 * checkpoint_bundle_install_ready gates its respawn on the SAME availability, so
 * it only arms the install-on-next-boot once this repair has landed the
 * solution — the install then binds on the next boot without burning the bounded
 * install budget on a solutionless retry. */

#ifndef ZCL_CONDITIONS_CHECKPOINT_HEADER_SOLUTION_REPAIR_H
#define ZCL_CONDITIONS_CHECKPOINT_HEADER_SOLUTION_REPAIR_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;
struct block_header;
struct uint256;

void register_checkpoint_header_solution_repair(void);

/* The testable trust core: given a fetched header, HASH-PIN it to the compiled
 * checkpoint hash (`expected_hash`) BEFORE anything is persisted, then require
 * the frozen Equihash checker to validate its solution, then durably persist it
 * hash-bound into header_solution_repair and mint the checkpoint pass record.
 * Returns true iff the header was verified AND persisted; on ANY refusal
 * (wrong hash, bad solution, missing params/store) nothing is persisted and it
 * returns false. A peer can waste one header of bandwidth, never inject. */
bool checkpoint_header_solution_verify_and_persist(
    struct main_state *ms, int32_t height,
    const struct uint256 *expected_hash, const struct block_header *hdr);

/* True iff the checkpoint solution is durably available (pass record OR a
 * hash-bound header_solution_repair row) — the exact predicate both this
 * condition's witness and checkpoint_bundle_install_ready's respawn gate use. */
bool checkpoint_header_solution_available(int32_t height,
                                          const struct uint256 *expected_hash);

#ifdef ZCL_TESTING
/* Frozen-Equihash verifier seam. Production ALWAYS uses block_row_verify (the
 * frozen PoW + Equihash checker); this lets the focused unit test drive the
 * good-header persist path without mining a real Equihash solution. Passing NULL
 * restores the production verifier. Returns true == solution valid. */
typedef bool (*checkpoint_header_frozen_verify_fn)(
    const struct uint256 *expected_hash, const struct block_header *hdr);
void checkpoint_header_solution_set_frozen_verifier_for_test(
    checkpoint_header_frozen_verify_fn fn);

void checkpoint_header_solution_repair_test_reset(void);
void checkpoint_header_solution_repair_test_set_main_state(struct main_state *ms);
void checkpoint_header_solution_repair_test_set_datadir(const char *datadir);
void checkpoint_header_solution_repair_test_set_peer_count(int n);
bool checkpoint_header_solution_repair_test_detect(void);
int  checkpoint_header_solution_repair_test_remedy(void);
#endif

#endif /* ZCL_CONDITIONS_CHECKPOINT_HEADER_SOLUTION_REPAIR_H */
