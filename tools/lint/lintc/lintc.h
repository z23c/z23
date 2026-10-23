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

/* Generic "<path>:<symbol>" shrink-only ratchet baseline, shared by gates
 * that were re-rooted onto real scan roots and now see debt the dead roots
 * hid: a row may only be REMOVED (the site fixed or the file deleted), never
 * added — a NEW row FAILs, and a STALE row (baselined but no longer found)
 * also FAILs, forcing the list down as sites are cleaned up. */
enum { BLN_MAX = 512, BLN_ROW = RS_PATH + 64 };
struct bln_set { char n[BLN_MAX][BLN_ROW]; int count; };
int bln_has(const struct bln_set *s, const char *name);
int bln_add(struct bln_set *s, const char *name);
int bln_load(struct bln_set *s, const char *path);
int bln_diff_report(FILE *out, const char *gate, const char *baseline_path,
                    const struct bln_set *base, const struct bln_set *found);

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
extern int g_n_auth;
extern char g_auth[RS_AUTH][RS_PATH];

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
size_t lc_skip_ws(const char *s, size_t i, size_t n);
int lc_each_line(const char *path,
                 int (*cb)(void *ctx, const char *line, size_t len),
                 void *ctx, int missing_ok);
int lint_git_index_foreach(int (*fn)(const char *, int, void *), void *ctx,
                           char *badext);
int want(const char *tag, const regex_t *re, const char *s, int w);
int st_ok(int bad, const char *msg);
int walk_src(const char *dir, int hdrs,
             int (*scan)(const char *, void *), void *ctx);
int require_scan_root(const char *gate, const char *root);
int walk_src_root(const char *gate, const char *root, int hdrs,
                  int (*scan)(const char *, void *), void *ctx);

/* Shared comment/string-literal stripper for gates that regexec() raw
 * source lines (see cstrip_line in lib.c). in_block persists across the
 * getline() calls for one file (a block comment can span lines); reset
 * to {0} per file. */
struct cstrip { int in_block; };
int cstrip_line(struct cstrip *st, const char *line, size_t n, char *out,
               size_t cap);
/* Shared stack-buffer size for the two callers above: large enough for any
 * real source line, small enough to keep off the heap (raw malloc/calloc
 * outside zcl_* wrappers is itself gated in tools/). */
enum { CSTRIP_LINE_MAX = 8192 };

int fcount_scan(const char *path, void *ctx);
int walk_count_roots(const char *gate, const char *const *roots, size_t nroots,
                     int hdrs, int *out);
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
 * family's headroom against it and tools/lint/lintc/gate_lint_gate_wiring.c
 * refuses a breach; the shell side reads this single definition out of
 * this header, so the number exists exactly once. */
#define LINT_FAMILY_CEILING 1500

int lint_families_ledger(void);
/* Shared shrink-only ratchet baseline. A ratchet gate measures one integer
 * M per scanned item (complexity, lines, whatever its cap is on) and pins
 * the legacy over-cap items in a baseline file, one `key:M` row per line
 * (`#` comments and blank lines skipped; M is the text after the LAST
 * colon, so keys may themselves contain colons, e.g. `path:function:M`).
 * Exact-pin semantics: an over-cap item whose key is not pinned is NEW
 * (the caller reports it, since only the caller knows its cap and line);
 * a pin whose item grew fails lint_base_finish, and so does a pin whose item
 * is now within the caller's cap (retired); a pin whose item shrank but is
 * still over the cap passes with a note. A pin whose key
 * was never observed fails as stale. Pins may only ever fall.
 *
 * Keys must be unique per scan. When a scan can legitimately produce the
 * same logical name twice for one key scope (e.g. a function defined once
 * per platform #ifdef branch in a single file), the scan side suffixes
 * repeats `name#2`, `name#3`, ... in scan order so every pin stays an
 * exact match; lint_base_load rejects duplicate rows fail-closed.
 *
 * Call flow: lint_base_load once; lint_base_observe for EVERY scanned item
 * (any M — a pinned item that dropped under the cap must still be seen so
 * the ratchet-down is named, not misreported as stale); the caller emits
 * its own NEW-item diagnostics; lint_base_finish emits the grew/retired/
 * stale diagnostics (shrinks only as notes) and returns their count.
 * lint_base_tighten then lowers or deletes pins in memory for the
 * --tighten-baseline path; it never raises a pin or adds a row. Generation (the gate's
 * --write-baseline upkeep path): lint_base_pin per over-cap item, then
 * lint_base_write. Storage is caller-owned fixed buffers; declare the
 * struct in static storage (it is ~2.5 MB).
 *
 * Presence-set mode (lint_base_load_set): gates ported from the shell
 * gate_load_list_file() allowlists keep those semantics instead — the
 * baseline is a SET of plain keys (no :M), `#` starts a comment anywhere
 * on the line, whitespace is trimmed, duplicates collapse silently, and a
 * missing file is an empty set, not an error. Membership is
 * lint_base_observe(b, key, 1) >= 0. The set is superset-allowed: an
 * entry no scan observed is unused, never stale, so lint_base_finish is
 * not called on a set baseline. Choose this mode only when the gate's
 * pre-existing baseline contract demands it; new shrink-only ratchets use
 * the exact-pin flow above. */
enum { LB_MAX = 8192, LB_KEY = 320 };
struct lb_row { char key[LB_KEY]; int pinned, cur, seen; };
struct lint_base { struct lb_row row[LB_MAX]; int n; };

int lint_base_load(struct lint_base *b, const char *path, FILE *err);
int lint_base_load_set(struct lint_base *b, const char *path);
int lint_base_observe(struct lint_base *b, const char *key, int m);
int lint_base_finish(const struct lint_base *b, FILE *out, FILE *notes,
                     int cap, const char *hint);
int lint_base_tighten(struct lint_base *b, int cap, int *lowered, int *deleted,
                      int *kept);
int lint_base_pin(struct lint_base *b, const char *key, int m);
int lint_base_write(struct lint_base *b, const char *path, const char *hdr);


/* Extract the 1-based top-level comma argument span; quote/escape and
 * parenthesis aware. Returns total argument count; outputs change only
 * when the requested argument exists. Input length must fit INT_MAX. */
int lint_macro_arg(const char *s, int want, int *off, int *len);

/* Gate prototypes int NAME_run(int, char **) / int NAME_selftest(void),
 * generated from gates.def. */
#define LINT_GATE(name, base)                                                  \
    int base##_run(int argc, char **argv);                                     \
    int base##_selftest(void);
#include "gates.def"
#undef LINT_GATE

int check_hotswap_denied_leaves_run_io(FILE *out, FILE *err);

#endif
