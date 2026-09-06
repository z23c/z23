/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the split C23 lint runtime (the gate
 * table entry type and every gate family's run/selftest prototypes).
 */
#ifndef LINTC_H
#define LINTC_H

#include <regex.h>
#include <stddef.h>
#include <stdio.h>

struct lint_gate {
    const char *name;
    int (*run)(int argc, char **argv);
    int (*selftest)(void);
};

enum { RS_MAX = 256, RS_NAME = 64, RS_PATH = 192, RS_AUTH = 32, RS_SHAPE = 16,
       CLK_MATCH = 65536 };
enum { SR_ALLOW = 256, SR_NAME = 96, SR_STRAY = 128 };

struct sr_set { char n[SR_ALLOW][SR_NAME]; int count; };

extern const char k_ls_all[];
extern const char k_planted[];
extern const char *const k_domain[2];
extern const char *g_lint_argv0;
extern int g_n_shapes;
extern char g_shapes[RS_SHAPE][RS_NAME];
extern int g_n_ctx;
extern char g_ctx[RS_MAX][RS_NAME];
extern int g_n_libs;
extern char g_libs[RS_MAX][RS_NAME];

int die(const char *msg, const char *arg);
int fin(FILE *f, char *line, const char *path, int rc);
int reg_fail(regex_t *re, int err);
int ovf(int n, size_t cap);
int cmd_done(const char *cmd, int st, int allow_exit1);
void drop2(regex_t *a, regex_t *b);
void drop3(regex_t *a, regex_t *b, regex_t *c);
int each_zpath_st(const char *cmd, int allow_exit1,
                  int (*fn)(const char *, void *), void *ctx);
int each_zpath(const char *cmd, int (*fn)(const char *, void *), void *ctx);
int want(const char *tag, const regex_t *re, const char *s, int w);
int st_ok(int bad, const char *msg);
int walk_src(const char *dir, int hdrs,
             int (*scan)(const char *, void *), void *ctx);
int compile_pat(regex_t *re, int flags, const char *a, const char *b,
                const char *c, const char *d);
int pair_comp(regex_t *a, int fa, const char *a0, const char *a1,
              const char *a2, const char *a3, regex_t *b, int fb,
              const char *b0, const char *b1, const char *b2, const char *b3);
int miss(const char *path, FILE *out, const char *fmt);
int scan_re(const char *path, const regex_t *re, int *hits, int show);
int capture_cmd(const char *cmd, char *out, size_t cap, int *code);
const char *env_or(const char *name, const char *fallback);
int lint_self_exe(char *buf, size_t cap);
int sh_single_quote(const char *in, char *out, size_t cap);
int gate_require_scanned(int count, int floor, const char *name,
                         const char *hint);
int gate_count_and_report(const char *matches, int *out_count);
int lint_annotate_stray(const char *path, FILE *out);
int lint_filter_excluded(const char *in, char *out, size_t cap);
int lint_path_is_excluded(const char *path);
int excl_ensure(void);
int lint_prod_scan(void);
int rs_init(void);
int repo_shape_dirs(const char *family, const char *leaf,
                    char out[][RS_PATH], int max, int *n);
int repo_shape_room_dirs(const char *shape, char out[][RS_PATH], int max,
                         int *n);
int sr_has(const struct sr_set *s, const char *name);
int sr_add(struct sr_set *s, const char *name);
int sr_load(struct sr_set *s, const char *path);
int replay(FILE *out);
int csr_mkdirs(const char *path);
int csr_write(const char *path, const char *text);
int csr_slurp(FILE *f, char *buf, size_t cap);
int psp_st_reset(FILE *out);
int rap_rm_rf(const char *root);
int cic_repo_root(char *buf, size_t cap);
int cic_invoke(const char *gate, int merge_err, char *out, size_t cap,
               int *code);
const char *clock_mode(void);
int clock_grade(int v, const char *mode);

/* The one family-file size ceiling. `z23-lint --families` reports each
 * family's headroom against it and tools/lint/check_lint_gate_wiring.sh
 * refuses a breach; the shell side reads this single definition out of
 * this header, so the number exists exactly once. */
#define LINT_FAMILY_CEILING 1500

int lint_families_ledger(void);

int check_no_python_run(int argc, char **argv);
int check_no_python_selftest(void);
int check_malloc_run(int argc, char **argv);
int check_malloc_selftest(void);
int check_dev_proof_native_fast_path_run(int argc, char **argv);
int check_dev_proof_native_fast_path_selftest(void);
int check_before_save_hooks_run(int argc, char **argv);
int check_before_save_hooks_selftest(void);
int check_pthread_create_run(int argc, char **argv);
int check_pthread_create_selftest(void);
int check_silent_error_returns_run(int argc, char **argv);
int check_silent_error_returns_selftest(void);
int check_no_gnu_va_args_run(int argc, char **argv);
int check_no_gnu_va_args_selftest(void);
int check_sysinit_ordering_run(int argc, char **argv);
int check_sysinit_ordering_selftest(void);
int check_no_raw_clock_outside_platform_run(int argc, char **argv);
int check_no_raw_clock_outside_platform_selftest(void);
int check_no_shellouts_run(int argc, char **argv);
int check_no_shellouts_selftest(void);
int check_command_contract_run(int argc, char **argv);
int check_command_contract_selftest(void);
int check_no_writer_below_sealed_frontier_run(int argc, char **argv);
int check_no_writer_below_sealed_frontier_selftest(void);
int check_no_stray_root_files_run(int argc, char **argv);
int check_no_stray_root_files_selftest(void);
int check_proc_self_shim_run(int argc, char **argv);
int check_proc_self_shim_selftest(void);
int check_simd_os_support_run(int argc, char **argv);
int check_simd_os_support_selftest(void);
int check_c23_only_run(int argc, char **argv);
int check_c23_only_selftest(void);
int check_hotswap_dev_only_run(int argc, char **argv);
int check_hotswap_dev_only_selftest(void);
int check_no_api_keys_run(int argc, char **argv);
int check_no_api_keys_selftest(void);
int check_error_doc_refs_run(int argc, char **argv);
int check_error_doc_refs_selftest(void);
int check_core_seal_root_mirror_run(int argc, char **argv);
int check_core_seal_root_mirror_selftest(void);
int check_peer_floor_single_source_run(int argc, char **argv);
int check_peer_floor_single_source_selftest(void);
int check_proof_server_pin_run(int argc, char **argv);
int check_proof_server_pin_selftest(void);
int check_tu_random_seed_run(int argc, char **argv);
int check_tu_random_seed_selftest(void);
int check_no_retired_agent_protocol_run(int argc, char **argv);
int check_no_retired_agent_protocol_selftest(void);
int check_stopwatch_skip_detector_run(int argc, char **argv);
int check_stopwatch_skip_detector_selftest(void);
int check_no_warning_suppression_run(int argc, char **argv);
int check_no_warning_suppression_selftest(void);
int check_privileged_transition_receipt_run(int argc, char **argv);
int check_privileged_transition_receipt_selftest(void);
int check_no_new_coin_backfill_caller_run(int argc, char **argv);
int check_no_new_coin_backfill_caller_selftest(void);
int check_mind_owns_rebuild_run(int argc, char **argv);
int check_mind_owns_rebuild_selftest(void);
int check_codeindex_coverage_run(int argc, char **argv);
int check_codeindex_coverage_selftest(void);
int check_asan_adx_exception_run(int argc, char **argv);
int check_asan_adx_exception_selftest(void);
int check_framework_filename_suffix_run(int argc, char **argv);
int check_framework_filename_suffix_selftest(void);
int check_no_stray_untracked_source_run(int argc, char **argv);
int check_no_stray_untracked_source_selftest(void);
int check_group_purpose_run(int argc, char **argv);
int check_group_purpose_selftest(void);
int check_no_new_borrowed_seed_run(int argc, char **argv);
int check_no_new_borrowed_seed_selftest(void);
int check_silent_errors_bool_run(int argc, char **argv);
int check_silent_errors_bool_selftest(void);
int check_no_raw_sqlite_in_controllers_run(int argc, char **argv);
int check_no_raw_sqlite_in_controllers_selftest(void);
int check_blob_read_bounds_run(int argc, char **argv);
int check_blob_read_bounds_selftest(void);
int check_posix_ere_only_run(int argc, char **argv);
int check_posix_ere_only_selftest(void);
int check_no_orphan_placement_run(int argc, char **argv);
int check_no_orphan_placement_selftest(void);
int check_architecture_tree_run(int argc, char **argv);
int check_architecture_tree_selftest(void);
int check_sandbox_wired_run(int argc, char **argv);
int check_sandbox_wired_selftest(void);
int check_hotswap_eligible_scope_run(int argc, char **argv);
int check_hotswap_eligible_scope_selftest(void);
int check_hotswap_static_state_run(int argc, char **argv);
int check_hotswap_static_state_selftest(void);
int check_result_discard_run(int argc, char **argv);
int check_result_discard_selftest(void);
int check_wallet_raw_prepare_log_run(int argc, char **argv);
int check_wallet_raw_prepare_log_selftest(void);
int check_persona_resolves_run(int argc, char **argv);
int check_persona_resolves_selftest(void);
int check_prompt_templates_run(int argc, char **argv);
int check_prompt_templates_selftest(void);

#endif
