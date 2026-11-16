/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_rung_install_strand — the one predicate both the arm site
 * (checkpoint_bundle_install_ready) and the install boot (icb_install_from_bundle)
 * use to refuse a legacy checkpoint-bundle install that would strand the node.
 *
 * A legacy install binds the reducer frontier H* as the wallet cutover's
 * old_height. The pending boot after it rebuilds its block index from the
 * projection only; when the rung row is not projected (a header chain from the
 * solutionless header seed), that boot depends on the in-memory rung window
 * route, which admits only old_height == 0. With 0 < H* < rung the unchanged
 * pending restore refuses on every later boot. This predicate names exactly that
 * input so neither site arms or installs it; the node keeps syncing normally.
 * It changes no wallet code, trusts nothing new and writes nothing durable. */

#ifndef ZCL_CONDITIONS_CHECKPOINT_RUNG_INSTALL_STRAND_H
#define ZCL_CONDITIONS_CHECKPOINT_RUNG_INSTALL_STRAND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct rom_state_rung;

/* Distinct install refusal code: a retriable strand refusal (no .failed, the
 * consumed install-on-next-boot request is cleared). Header deferrals use -2;
 * no install step returns this code. */
#define CHECKPOINT_RUNG_INSTALL_STRAND_CODE (-230)

/* Distinct install refusal code: the boot-time rung-window precondition (the
 * strand's sibling). Same retriable shape — no .failed, the consumed
 * install-on-next-boot request is cleared, no attempt budget burnt — but its
 * own code so an operator (and the request-consumed clear) can tell "would
 * strand an applied node" from "the rung window the next boot needs is not
 * durably stored and verified yet". No install step returns it either. */
#define CHECKPOINT_RUNG_WINDOW_NOT_READY_CODE (-231)

/* The pending boot's own view of the rung row. */
enum checkpoint_rung_row {
    CHECKPOINT_RUNG_ROW_PROJECTED,   /* the projection holds a row for the rung hash (at the
                                      * arm site also: its header event is in the log tail
                                      * the next boot's catch-up replays) */
    CHECKPOINT_RUNG_ROW_ABSENT,      /* exact: no row */
    CHECKPOINT_RUNG_ROW_UNKNOWN,     /* no projection open or a lookup error: refuse */
    CHECKPOINT_RUNG_ROW_PENDING,     /* arm site: the bounded log-tail lookup has not finished */
};

struct checkpoint_rung_install_strand {
    int32_t target_height;
    int32_t hstar;
    enum checkpoint_rung_row row;
};

/* The compiled ladder rung at `height`, strictly above the keystone, at exactly
 * `hash`; NULL otherwise. */
const struct rom_state_rung *checkpoint_rung_at(int32_t height, const uint8_t hash[32]);

/* No -flysync request and no island fact of any kind: the pending boot has no
 * island window to rehydrate the rung row from. */
bool checkpoint_rung_window_route(void);

/* Pure core. True only when ALL hold: (a) the target is a compiled rung above the
 * keystone at that hash; (b) the install writes a LEGACY binding; (c) no island
 * route; (d) the projection does not hold the rung row (UNKNOWN counts as not
 * holding it); (e) 0 < hstar < target height. */
bool checkpoint_rung_install_strands(int32_t target_h, const uint8_t target_hash[32],
                                     bool legacy_binding, bool window_route,
                                     enum checkpoint_rung_row row, int32_t hstar);

/* Live wrapper: reads the route, the projection singleton and H* (the same
 * compute_hstar + block_hash_at pair the binding capture binds), cheap
 * conjuncts first; H* is read only when everything else holds. */
bool checkpoint_rung_install_would_strand(int32_t target_h, const uint8_t target_hash[32],
                                          bool legacy_binding,
                                          struct checkpoint_rung_install_strand *out);

/* Arm site: as would_strand for a legacy binding, but a rung row the projection
 * lacks is also looked up in the event-log tail past the projection's consumed
 * offset, which the next boot's catch-up replays into rows: a header that
 * reached this node over P2P in this process arms as on main. The lookup runs
 * only while 0 < H* < target, is bounded per call and resumes where it stopped;
 * out->row reads PENDING (true is returned: do not arm yet) until it finishes.
 * The install-boot refusal keeps the exact projection-only read. */
bool checkpoint_rung_arm_would_strand(int32_t target_h, const uint8_t target_hash[32],
                                      struct checkpoint_rung_install_strand *out);

/* Arm site: the install is not armed; log once per process in plain words.
 * A PENDING lookup is still looking: nothing is logged. */
void checkpoint_rung_install_strand_note_arm(const struct checkpoint_rung_install_strand *s);

/* The strand is DECIDED to hold: the projection answered and the log-tail
 * lookup finished without the rung row (ABSENT; never PENDING or UNKNOWN) and
 * 0 < H* < target. The projection answer is read on every call; the ABSENT and
 * its H* are either read now or remembered from the finished lookup only while
 * the event-log end has not moved since (every persisted block appends a
 * block-status event, so on a syncing node they are read again about once per
 * poll; while remembered, H* can lag until the next appended event; a
 * remembered pair always answers "strand", so a lag only delays). */
bool checkpoint_rung_strand_decided(const struct checkpoint_rung_install_strand *s);

/* detect() returned true (an episode can open or continue): the next episode
 * end on the strand path logs its own reason line. */
void checkpoint_rung_install_strand_note_episode_open(void);

/* Witness, right before it ends an episode on a decided strand with nothing
 * armed: one plain reason line per episode (no install happened, the node
 * keeps syncing block by block). */
void checkpoint_rung_install_strand_note_episode_end(const struct checkpoint_rung_install_strand *s);

/* Install site: evaluate a legacy install of `bundle_path` against the same
 * staged wait target the arm site used. True means refuse (retriable); `reason`
 * then names it. Logs once per process. */
bool checkpoint_rung_install_strand_refuses(const char *bundle_path, char *reason, size_t cap);

/* Install site, the window precondition (card W): a fresh legacy binding at a
 * compiled rung above the keystone on the legacy window route installs only
 * when the 28-header rung window its own pending boot rehydrates from is
 * ALREADY durable and verifies — the exact rows the pending restore loads with
 * node_db_runtime_load_header_by_hash_height and proves with
 * flysync_island_verify_window (the runtime arm gate makes them durable before
 * it arms; the boot path alone had no window precondition, which let a boot
 * that stopped seconds after the checkpoint solution persisted commit a wallet
 * cutover its next boot could never complete). Reads the staged wait target,
 * the route, the projection row and the durable rows; reads NO H* (the
 * predicate is route + row availability, not frontier height). True means
 * refuse (retriable, CHECKPOINT_RUNG_WINDOW_NOT_READY_CODE); `reason` then
 * names the first height that is not loadable right now — never "missing":
 * the loader's trylock fall-through under contention reads as absent, and the
 * runtime condition stores the window and arms the install as today. Writes
 * nothing. */
bool checkpoint_rung_window_ready_refuses(const char *bundle_path, char *reason,
                                          size_t cap);

#ifdef ZCL_TESTING
void checkpoint_rung_install_strand_test_reset(void);
/* Arm-site strand skips since the last reset. */
int checkpoint_rung_install_strand_test_arm_skips(void);
/* Episode-end reason lines logged since the last reset. */
int checkpoint_rung_install_strand_test_episode_end_logs(void);
/* H* reads (progress-store lock taken) since the last reset. */
int checkpoint_rung_install_strand_test_hstar_reads(void);
/* Longest hold of the log-tail lookup's lock, and the bytes the last bounded
 * step read, since the last reset. */
int64_t checkpoint_rung_install_strand_test_max_hold_us(void);
uint64_t checkpoint_rung_install_strand_test_last_scan_bytes(void);
/* Log-tail bytes one arm-site lookup call may scan (0 restores the default). */
void checkpoint_rung_install_strand_test_set_scan_budget(uint64_t bytes);
#endif

#endif /* ZCL_CONDITIONS_CHECKPOINT_RUNG_INSTALL_STRAND_H */
