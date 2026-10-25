/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared fixtures for the dev.land acceptance tests (test_dev_land*.c): the
 * isolated state root, the in-process command call, the git rigs and every
 * helper or scenario that more than one of those files uses. Split out of
 * the former single test_dev_land.c; each declaration below is the unchanged
 * definition that lives in the file named by its section of the source. */

#ifndef ZCL_TEST_DEV_LAND_COMMON_H
#define ZCL_TEST_DEV_LAND_COMMON_H

#include "test/test_core.h"
#include "test_group_catalog.h"

#include "command/native_command.h"
#include "command/native_dev_land_prepare.h"
#include "command/native_fleet_objectives.h"
#include "command/native_dev_land_qualify.h"
#include "command/native_dev_land_precheck.h"
#include "controllers/agent_impact_rules.h"
#include "command/native_dev_land_attestation.h"
#include "platform/logical_cpu.h"
#include "platform/state_root.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/time_compat.h"
#include "platform/os_proc.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "util/spawn.h"
#include "dev/dev_git_tree.h"
#include "dev/dev_proof.h"
#include "dev/dev_proof_signer.h"
#include "dev/dev_proof_budget.h"
#include "dev/devloop.h"
#include "base/bytes.h"
#include "base/safe_alloc.h"
#include "base/hex.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"

/* Hermetic seams from native_dev_land.c (ZCL_TESTING build): the idle-note
 * judgment dl_proof_read applies to a real proof status, and its bound. */
bool zcl_native_dev_land_test_idle_note(int64_t age_s, char *detail,
                                        size_t cap);
int64_t zcl_native_dev_land_test_idle_bound(void);
void zcl_native_dev_land_test_next_step(const char *code, const char *action,
                                        long long seq, char *out, size_t cap);
/* The drive's base probe (dl_base_observe) against one worktree's origin. */
int zcl_native_dev_land_test_base_observe(const char *wt, const char *base);
bool zcl_native_dev_land_test_chain_codec(const char *line, char *out, size_t cap);
bool zcl_native_dev_land_test_failure_capture(const char *root, const char *local,
    const char *base, bool reset, char *out, size_t cap);
bool zcl_native_dev_land_test_failure_replay(const char *root, const char *line, char *out, size_t cap);
bool zcl_native_dev_land_test_terminal_record(const char *root, const char *line, char *out, size_t cap);
int zcl_native_dev_land_test_chain_relation(const char *line,
    const char *const *lines, size_t count, const char *main, long long *waiting);
#if !defined(_WIN32)
/* dl_base_probe() watching an already-forked worker, as dl_drive_proof()
 * does, through the proof's own requester wait loop. */
int zcl_native_dev_land_test_watch_worker(const char *wt, const char *base,
                                          int worker_pid, int interval_ms,
                                          bool *superseded);
#endif
#if defined(__linux__)
void zcl_native_dev_land_test_watcher_launch(const char *wt,
    const char *scheduler, char *detail, size_t cap);
#endif
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_publication.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
void zcl_native_dev_land_test_pick_barrier(int ready_fd, int release_fd);
bool zcl_native_dev_land_test_producer_stale(const char *detail);
int zcl_native_dev_land_test_range_adds_source(const char *wt,
                                               const char *base,
                                               const char *local);
void zcl_native_dev_land_test_judged_hook(void (*hook)(void));
void zcl_native_dev_land_test_marker_batch(const char *text, int rc);
bool zcl_native_dev_land_test_origin_config(const char *bytes, size_t length);
int zcl_native_dev_land_test_producer_reproof(const char *root,
                                              const char *local,
                                              const char *base,
                                              const char *make_program,
                                              char *why, size_t why_cap);
#endif


#define DLX_PATH "dev.land"

/* ── isolated state root ───────────────────────────────────────────────── */
extern char g_dlx_state[1024];
#if !defined(_WIN32)
extern char g_dlx_hooks_ok[1024];
#endif

struct dlx_call {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

struct dlx_rig {
    char bare[600];
    char clone[600];
    char tip[64];
};

struct dlx_subrepo {
    char bare[600];
    char rev_a[64];
    char rev_b[64];
};

struct dlx_adopt_fix {
    struct dlx_rig rig;
    char before[64];
    char landdir[1200];
    char qpath[1400];
    char marker[700];
    char qsnap[8192];
    size_t qsnap_len;
};

enum dlx_producer { DLX_PRODUCER_OK, DLX_PRODUCER_QUIET, DLX_PRODUCER_BROKEN };

struct dlx_prove_rig {
    struct dlx_rig rig;
    char second[64];
    char make[1400];
    char count[1400];
};

struct dlx_fence_case {
    unsigned scenario; bool stop;
    long long old_recorded_at;
    struct dlx_rig rig; struct dlx_call c;
    char tag[64], base[64], wt[1400], successor[64], remote[64], land[1200];
    char before[32768], after[32768]; size_t before_len, after_len;
};

#if !defined(_WIN32)
extern const struct zcl_command_reply *g_dlx_captured_reply;
int dlx_git(const char *dir, const char *const *args);
int dlx_git_out(const char *dir, const char *const *args, char *out,
                       size_t cap);
bool dlx_write(const char *path, const char *text);
bool dlx_mkdir_p(const char *path);
bool dlx_write_dep(const char *root, const char *rel,
                          const char *body);
bool dlx_hooks_dir(char *out, size_t cap, const char *tag,
                          int exit_code);
bool dlx_commit(const char *dir, const char *name, const char *body,
                       char out[64]);
bool dlx_rig_make(struct dlx_rig *rig, const char *tag);
bool dlx_file_exists(const char *path);
bool dlx_hook_link(const char *path);
bool dlx_plant_hook_bin(const char *dir);
bool dlx_slurp(const char *path, char *out, size_t cap, size_t *len);
int dlx_step_lock_take(const char *landdir);
void dlx_step_lock_release(int fd);
int dlx_step_held(const char *landdir);
bool dlx_gitlink_commit(const char *dir, const char *path,
                               const char *sha, const char *url,
                               char out_tip[64]);
bool dlx_subrepo_make(struct dlx_subrepo *sub, const char *tag);
bool dlx_submodule_add(const char *dir, const char *url,
                              const char *path, char out_tip[64]);
bool dlx_submodule_checkout(const char *dir, const char *path,
                                   const char *rev);
void dlx_submit(struct dlx_call *c, const struct dlx_rig *rig,
                       const char *tip);
bool dlx_queue_has_one(void);
bool dlx_exact_submit_retry(void);
bool dlx_queue_empty(void);
bool dlx_exact_submit_mid_rebase_refused(void);
bool dlx_submit_operation_markers_refused(void);
bool dlx_marker_batch_clean(void);
bool dlx_marker_batch_fallback(void);
bool dlx_queue_outside_home(const char *base);
bool dlx_run_in_child(bool (*body)(const char *base));
bool dlx_discovery_checkout(const char *base);
bool dlx_discovery_nested(const char *base);
bool dlx_step_beside_checkout(const char *base);
bool dlx_origin_main(const struct dlx_rig *rig, char out[64]);
bool dlx_commit_tree(const char *dir, const char *msg, char out[64]);
bool dlx_submodule_uninit(const char *dir, const char *path);
bool dlx_sign_arm(const char *dir, const char *tag);
bool dlx_generated_conflict(struct dlx_rig *rig, const char *extra,
                               char out_tip[64]);
bool dlx_rerere_autoupdate_prime(struct dlx_rig *rig);
void dlx_land_wt(char *out, size_t cap);
int test_dev_land_integrated_merge(bool signing_failure);
int test_dev_land_proof_tools_preparation(void);
int test_dev_land_final_plan_preparation(void);
int test_dev_land_explicit_main(void);
int test_dev_land_stale_file_retests(void);
int test_dev_land_missing_main(void);
int test_dev_land_initial_remote_missing(void);
int test_dev_land_final_observation_missing(void);
int test_dev_land_lost_persistence(void);
int test_dev_land_after_proof_restart(void);
int test_dev_land_terminal_replay(void);
int test_dev_land_objectives_snapshot(void);
int test_dev_land_objectives_append_blocked(void);
int test_dev_land_objectives_failed_outcome(void);
pid_t dlx_wait_child(pid_t child, int *status);
pid_t dlx_wait_publisher(pid_t publisher, int *status);
bool dlx_resume_after_death(void);
int test_dev_land_outcome_visible_in_mail(void);
int test_dev_land_publisher_death(void);
bool dlx_eq_str(const char *got, const char *want);
bool dlx_has(const char *s, const char *frag);
const char *dlx_jstr(const struct json_value *obj, const char *key);
bool dlx_status_json(struct dlx_call *c);
bool dlx_arm_receive_count(struct dlx_adopt_fix *fx);
bool dlx_receive_once(const struct dlx_adopt_fix *fx);
int test_dev_land_drain_adoption(void);
int test_dev_land_postpush_observation_missing(bool lost_ack);
int test_dev_land_prepush_checkpoint(void);
int test_dev_land_prepush_persist_refusal(void);
int test_dev_land_prepush_sync_refusal(void);
int test_dev_land_missing_publication_intent(void);
bool dlx_attach_proven_pair(struct dlx_rig *rig, const char *tag,
                                   char base[64]);
bool dlx_queue_bytes(char *out, size_t cap, size_t *len);
int test_dev_land_blocked_names_attach_target(void);
int test_dev_land_attach_resolves_single_row(void);
int test_dev_land_attach_publish_one_window(void);
int test_dev_land_attach_publish_exact_pair(void);
int test_dev_land_attach_publish_malformed_pair(void);
int test_dev_land_attach_publish_wait_expires(void);
int test_dev_land_attach_publish_wait_failure(void);
int test_dev_land_attach_publish_wait_busy(void);
int test_dev_land_attach_publish_moved_base(void);
int test_dev_land_attach_publish_push_checkpoint(void);
int test_dev_land_cancel_push_checkpoint(void);
int test_dev_land_attach_target_none(void);
int test_dev_land_attach_explicit_unattachable(void);
bool dlx_duplicate_proven_row(void);
int test_dev_land_attach_target_cases(void);
int test_dev_land_nonfastforward_client_guard(void);
int test_dev_land_expected_base_race(void);
int test_dev_land_recovery_ignores_replace_refs(void);
int test_dev_land_postpush_result_unconfirmed(void);
int test_dev_land_vendor_dependencies(void);
int test_dev_land_missing_tor_makefile(void);
int test_dev_land_tree_types(void);
int test_dev_land_tree_replacements(void);
int test_dev_land_tree_missing(void);
int test_dev_land_tree_malformed(void);
bool dlx_signed_receipt_pending(struct dlx_rig *rig, char *queue,
                                      size_t queue_cap, char *marker,
                                      size_t marker_cap, bool persist_receipt);
bool dlx_signed_push_lossy(struct dlx_rig *rig, const char *tag,
                                  char base[64], char wt[1400],
                                  char marker[1400], char racer[64]);
bool dlx_is_ancestor(const char *dir, const char *ancestor,
                             const char *descendant);
bool dlx_marker_lines(const char *marker, size_t want);
bool dlx_dispatch_script(const char *marker, const char *body);
int test_dev_land_signed_crash_before_push(void);
int test_dev_land_signed_third_party_before_push(void);
int test_dev_land_signed_unknown_not_retried_blind(void);
int test_dev_land_two_candidates_same_base(void);
int test_dev_land_drive_base_watch(void);
bool dlx_queue_field_once(const char *anchor, const char *from,
                                 const char *to);
int test_dev_land_phase_mail_quiet(void);
int test_dev_land_proof_evidence_test(void);
int test_dev_land_proof_evidence_compile(void);
int test_dev_land_resubmit_failed_pair(void);
int test_dev_land_refusal_names_next_step(void);
int test_dev_land_status_observation(void);
bool dlx_fence_prepare(struct dlx_rig *rig, const char *tag,
                               char base[64], char wt[1400], char successor[64]);
void dlx_fence_call(struct dlx_call *c, const struct dlx_rig *rig,
                           const char *base, const char *head, const char *tip);
bool dlx_fence_crash_step(const char *point);
long long dlx_fence_old_recorded(void);
int dlx_fence_case_admission(struct dlx_fence_case *t);
int dlx_fence_cases(void);
bool dlx_fence_same_queue(struct dlx_fence_case *t);
int dlx_fence_negative_cases(void);
int dlx_fence_concurrent(void);
int dlx_case_unsigned_tip(void);
int dlx_case_checkout_location(void);
int dlx_case_submit_status(void);
int dlx_case_duplicate_submit(void);
bool dlx_pc_file(const struct dlx_rig *rig, const char *name,
                        const char *text);
bool dlx_pc_rig(struct dlx_rig *rig, const char *tag, bool with_lint,
                       const char *known);
void dlx_pc_submit(struct dlx_call *c, const struct dlx_rig *rig,
                          const char *mode, const char *note);
bool dlx_pc_has(const struct json_value *arr, const char *name);
bool dlx_pc_ran(const struct dlx_rig *rig, const char *gate);
bool dlx_pc_outcomes(const char *rows);
void dlx_pc_row(char *out, size_t cap, int seq, const char *state,
                       const char *dim, int days_ago, const char *detail);
bool dlx_pc_history_ship_pass(void);
bool dlx_pc_history_ship_refusal(const char *exit_code, bool ready);
bool dlx_pc_history_ignored(const char *tag, int days_ago,
                                  const char *reason, bool unsafe);
bool dlx_pc_history_allocation_unproven(void);
bool dlx_pc_observation_busy(void);
bool dlx_pc_observation_aged(void);
bool dlx_pc_gate_set_learns(void);
bool dlx_pc_failing_gate_refused(void);
bool dlx_pc_unproven_gate_skipped(void);
bool dlx_pc_clean_lane_queued(void);
bool dlx_pc_queued_note(const char *want);
bool dlx_pc_skip_marks_note(void);
int dlx_case_precheck(void);
int dlx_case_empty_step(void);
int dlx_case_step_lock(void);
int dlx_case_starts_proof(void);
int dlx_case_absent_watcher(void);
int dlx_case_unarmed_proof(void);
int dlx_case_stub_detail(void);
int dlx_case_lands_proof(void);
int dlx_case_hook_refusal(void);
int dlx_case_proof_failure(void);
int dlx_case_timing_detail(void);
int dlx_case_moved_base(void);
int dlx_case_cancel_request(void);
int dlx_case_concurrent_submit(void);
int dlx_case_dense_detail(void);
int dlx_case_missing_hook(void);
int dlx_case_cancel_race(void);
int dlx_case_aged_successor(void);
int dlx_case_option_path(void);
int dlx_case_dependency_links(void);
int dlx_case_missing_dependency(void);
int dlx_case_tor_gitlink(void);
int dlx_case_tor_head(void);
int dlx_case_hook_drift(void);
int dlx_case_idle_proof(void);
int dlx_case_unclaimed_proof(void);
int dlx_case_missing_hook_binary(void);
int dlx_case_quiet_hooks(void);
int dlx_case_uninitialised_tor(void);
int dlx_case_current_tor(void);
int dlx_case_generated_conflict(void);
int dlx_case_rerere_conflict(void);
int dlx_case_retired_generated_conflict(void);
int dlx_case_mixed_conflict(void);
int test_dev_land_window_defer(void);
int test_dev_land_window_replay(void);
int test_dev_land_rebase_count_conflicts(void);
bool dlx_qp_branch(struct dlx_rig *rig, const char *branch,
                          const char *path, const char *body,
                          const char *path2, const char *body2, char out[64]);
bool dlx_qp_push_main(struct dlx_rig *rig, const char *path,
                             const char *body, char out[64]);
bool dlx_qp_submit(struct dlx_rig *rig, const char *tip, int64_t seq);
bool dlx_qp_outcome(const char *tip, const char *state,
                           char *detail, size_t cap);
bool dlx_qp_file_has(const char *path, const char *needle);
int test_dev_land_queued_precheck_cases(void);
int test_dev_land_train_cases(void);
#endif /* !defined(_WIN32) */

void dlx_isolate(const char *tag);
void dlx_restore(void);
void dlx_landdir(char *out, size_t cap);
void dlx_begin(struct dlx_call *c, const char *action);
bool dlx_run(struct dlx_call *c);
void dlx_end(struct dlx_call *c);
void dlx_captured_handler(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply);
bool dlx_refusal_serializes(const struct dlx_call *call);
bool dlx_ok(const struct dlx_call *c);
const char *dlx_str(const struct dlx_call *c, const char *key);
int64_t dlx_int(const struct dlx_call *c, const char *key);
const struct json_value *dlx_arr(const struct dlx_call *c,
                                        const char *key);
const char *dlx_err_code(const struct dlx_call *c);
const char *dlx_err_evidence(const struct dlx_call *c);
int test_dev_land_exact_tree(void);
int test_dev_land_source_binding(void);
int test_dev_land_watcher_admission(void);
int test_dev_land_long_proof_root(void);
int test_dev_land_chain_codec(void);
bool dlx_chain_row(char *out, size_t cap, long long seq,
    const char *repo, const char *local, const char *base, const char *state,
    long long predecessor, const char *pred_base, const char *pred_tree);
int test_dev_land_chain_relation(void);
int test_dev_land_malformed_queue_refusal(void);
int test_dev_land_malformed_priority_refusal(void);
int test_dev_land_malformed_outcome_refusal(void);
int test_dev_land_missing_worker(void);
bool dlx_pick_barrier_open(int ready[2], int release[2]);
int test_dev_land_competing_publish(const char *winner, const char *loser,
                                           bool prepared);
int test_dev_land_bounded_drive(void);
bool dlx_drive_seq(struct dlx_call *c, int seq);
int test_dev_land_drive_seq_lands(void);
int test_dev_land_drive_seq_refusals(void);
int test_dev_land_drive_seq_proof_failed(void);
int test_dev_land_drive_seq_stops(void);
bool dlx_prove_drive(struct dlx_call *c, int max_rows);
size_t dlx_runs(const char *count);
bool dlx_prove_rig(struct dlx_prove_rig *p, const char *tag,
                          enum dlx_producer kind);
int test_dev_land_prove_drive1(void);
int test_dev_land_prove_drive2(void);
int test_dev_land_prove_drive3(void);
int test_dev_land_prove_drive4(void);
int test_dev_land_prove_drive5(void);
int test_dev_land_prove_drive6(void);
int test_dev_land_qualify_make_caps(void);
int test_dev_land_qualify_canonical_aliases(void);
int test_dev_land_qualify_unregistered_group(void);
int test_dev_land_qualify_job_caps(void);
int test_dev_land_qualify_passes(void);
int test_dev_land_qualify_stale_doc_refused(void);
int test_dev_land_qualify_complexity(void);
int test_dev_land_qualify_verdict_rule(void);
int test_dev_land_qualify_refusals(void);
int test_dev_land_qualify_dirty_tree(void);
int test_dev_land_qualify_group_verdicts(void);
int test_dev_land_qualify_groups_reported(void);
int test_dev_land_qualify_selection_refusals(void);
int test_dev_land_qualify_origin_moves(void);
int test_dev_land_qualify_rebase_and_fetch_failures(void);
int test_dev_land_drive_seq_landed_reply_stands_alone(void);
int test_dev_land_stubs_are_test_build_only(void);
int test_dev_land_main_moves_converge(void);
bool dlx_priority_snapshot(struct dlx_call *c, char ts[64]);
bool dlx_priority_successor_status(struct dlx_call *c,
                                           const char *original_ts);
int test_dev_land_signed_intent(void);
int test_dev_land_receipt_adversarial(void);
int test_dev_land_signer_takeover(void);
int test_dev_land_signed_tamper(void);
int test_dev_land_signed_stale(void);
int test_dev_land_signed_recovery(void);
int test_dev_land_new_source_precheck(void);
int test_dev_land_drive_producer_reproof(void);
int test_dev_land_signed_lost_ack(void);
int test_dev_land_signed_lost_race(void);
int test_dev_land_signed_lost_ack_resend(void);
int test_dev_land_signed_push_lost_race(void);
int test_dev_land_cancel_push_refused(void);
int test_dev_land_push_declined(void);
int test_dev_land_signed_publisher_death(void);
int test_dev_land_phase_digest(void);
int test_dev_land_step_producer_recovery(void);
int test_dev_land_interrupted_proof(void);
int dlx_origin_config_cases(void);
int dlx_attest_only_cases(void);
int dlx_attest_bounded_wire_cases(void);
bool dlx_beat_log_record(const char *prefix, const char *beat);
int dlx_attest_refusal_cases(void);
int dlx_launcher_join_cases(void);
bool dlx_hold_field_replace(const char *replacement);
bool dlx_priority_replace(const char *value);
bool dlx_priority_is(const char *value);
int dlx_guarded_priority_case(void);
int dlx_guarded_hold_mismatch_case(void);
int dlx_hold_legacy_case(void);
int dlx_hold_pushed_case(void);
int dlx_hold_malformed_case(void);
int dlx_hold_sealed_case(void);
int dlx_hold_lock_case(void);
int dlx_hold_admissible_during_step(void);
int dlx_hold_survives_step_rewrite(void);
int dlx_publication_hold_cases(void);
int dlx_outcome_escape_cases(void);
int dlx_optional_string_refusal_cases(void);
int dlx_string_compatibility_cases(void);
int dlx_case_registration(void);
int dlx_case_unknown_action(void);
int test_dev_land_test_hatches_testing_only(void);
int test_dev_land(void);

#endif /* ZCL_TEST_DEV_LAND_COMMON_H */
