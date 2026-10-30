/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_hotswap_service_islands_priv - the seam between
 * gate_hotswap_service_islands.c (row checks and entry points) and
 * gate_hotswap_service_islands_parse.c (fixed-storage violation buffer, text
 * helpers, manifest and pair parsers). NOT a public header: nothing outside
 * tools/lint/lintc/ includes this.
 */
#ifndef ZCL_LINTC_GATE_HSI_PRIV_H
#define ZCL_LINTC_GATE_HSI_PRIV_H

#include <regex.h>
#include <stddef.h>

extern const char k_hsi_gate[];

enum { HSI_ROWS = 128, HSI_PAIRS = 256, HSI_FILES = 64, HSI_CONTRACTS = 16,
       HSI_CALLS = 64, HSI_LINE = 8192, HSI_FLD = 512, HSI_SRC = 1024,
       HSI_BIG = 4096, HSI_CBUF = 1 << 16, HSI_TEXT = 1 << 19, HSI_VBUF = 1 << 19 };

struct hsi_row {
    char id[HSI_FLD], source[HSI_SRC], headers[HSI_BIG], contract[HSI_BIG],
        imports[HSI_BIG], abi[HSI_FLD], schema[HSI_FLD], wire[HSI_FLD],
        kat[HSI_FLD], probe[HSI_FLD];
};

struct hsi_pair { char a[HSI_SRC]; char b[HSI_BIG]; };

struct hsi_vio { char buf[HSI_VBUF]; size_t len; };

struct hsi_env {
    struct hsi_vio v;
    regex_t re_forb, re_inc, re_proj, re_static, re_extern, re_life,
        re_brace, re_srvc, re_fixture;
    int fixture_mode;
    int scanned;
    int eff_first; /* grep -n output joined as "$source:$hits": only the */
    int eff_multi; /* first line carries the prefix; grep -H when >1 file */
};

struct hsi_line_ctx {
    struct hsi_env *env;
    const char *path;   /* file being scanned (state messages) */
    const char *prefix; /* "$source:" prefix for grep -n style messages */
    const regex_t *re;  /* effect regex to apply (state cb ignores it) */
    long ln;
};

#define HSI_V(e, ...) \
    do { if (hsi_vadd(&(e)->v, __VA_ARGS__)) return 2; } while (0)

int hsi_vadd(struct hsi_vio *v, const char *fmt, ...);
int hsi_cpy(char *dst, size_t cap, const char *s);
int hsi_decor(char *dst, size_t cap, const char *pre, const char *s,
              const char *suf);
int hsi_slurp(const char *path, char *buf, size_t cap, size_t *outn);
int hsi_copy_line(char *dst, size_t cap, const char *line, size_t len,
                  const char *path, long ln);
int hsi_line_has(const char *s, size_t n, const char *needle, size_t nl);
int hsi_parse_manifest(const char *b, size_t n, struct hsi_row *rows,
                       int cap, int *count);
int hsi_parse_pairs(const char *b, size_t n, const char *marker,
                    struct hsi_pair *out, int cap, int *count);

#endif
