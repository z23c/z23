/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check-windows-cross-syntax gate port
 * (gate_windows_cross_syntax.c, gate_windows_cross_syntax_cache.c,
 * gate_windows_cross_syntax_selftest.c). Ported from
 * tools/lint/check_windows_cross_syntax.sh (deleted); its helpers
 * gate_lib.sh and tu_result_cache.sh remain in the tree for other callers.
 */
#ifndef WCS_PRIV_H
#define WCS_PRIV_H

#include <stddef.h>

enum {
    WCS_PATH = 1024,
    WCS_LINE = 4096,
    WCS_SRCLINE = 32768,
    WCS_TUS = 12000,
    WCS_FLAGS = 640,
    WCS_FLAGLEN = 1100,
    WCS_ARGS = 700,
    WCS_SHA = 65,
};

extern const char k_wcs_gate[];
extern char g_wcs_work[WCS_PATH];
extern char g_wcs_out[WCS_PATH];
extern char g_wcs_cc[WCS_PATH];
extern char g_wcs_flag[WCS_FLAGS][WCS_FLAGLEN];
extern int g_wcs_nflag;
extern char g_wcs_src[WCS_TUS][WCS_PATH];
extern int g_wcs_nsrc;

/* subprocess helpers (fork + execvp, never a shell string) */
int wcs_run_capture(const char *out_path, const char *err_path,
                    char *const argv[]);
int wcs_run_status(char *const argv[]);
int wcs_have_cmd(const char *name);
int wcs_copy(char *dst, size_t cap, const char *src);
int wcs_name_in(const char *name, const char *const *list);

/* artifact paths for one TU under an out dir */
int wcs_paths_for(const char *src, const char *out_dir, char *log,
                  size_t lcap, char *rc, size_t rcap);

/* classifier: writes CLEAN / SKIP_GENERATED / SKIP_OPENSSL /
 * SKIP_HEADERS / COMPILER_FAILURE / ERROR / INCONSISTENT_SUCCESS /
 * MISSING_RESULT into kind. rc is the string read from the .rc file
 * ("missing" when absent or non-numeric). */
int wcs_compile_kind(const char *log, const char *rc, char *kind,
                      size_t cap);

/* compile sweep (gate_windows_cross_syntax_sweep.c) */
int wcs_sweep(void);
extern const char k_wcs_baseline[];

/* sha256 + include digest (gate_windows_cross_syntax_digest.c), per-TU result cache (gate_windows_cross_syntax_cache.c) */
void wcs_sha_str(const char *d, size_t n, char out[WCS_SHA]);
int wcs_sha_file(const char *path, char out[WCS_SHA]);
int wcs_mkdirs_p(const char *path);
int wcs_include_digest(const char *root, char out[WCS_SHA]);
int wcs_cache_setup(const char *gate, const char *script_path,
                    const char *cc, const char *flags_nul,
                    const char *scratch, const char *root,
                    const char *cachedir);
int wcs_cache_on(void);
const char *wcs_cache_off_reason(void);
int wcs_cache_plan(const char *src_list, const char *miss_list,
                   const char *out_dir, int flat);
int wcs_cache_compile(const char *log, const char *rcf, const char *cc,
                      char *const cargv[], const char *src);
int wcs_cache_counts(int *h, int *m, int *s);
void wcs_cache_summary(void);

/* flow (main gate file) */
int wcs_begin(int selftest_only);

#endif
