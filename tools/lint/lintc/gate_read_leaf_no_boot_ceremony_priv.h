/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared declarations for the check-read-leaf-no-boot-ceremony gate port
 * (gate_read_leaf_no_boot_ceremony*.c). The gate refuses any leaf declared
 * READ whose handler closure reaches a datadir boot-ceremony symbol.
 */
#ifndef GATE_READ_LEAF_NO_BOOT_CEREMONY_PRIV_H
#define GATE_READ_LEAF_NO_BOOT_CEREMONY_PRIV_H

#include <stdio.h>
#include <stddef.h>

#define RLB_GATE "check_read_leaf_no_boot_ceremony"

#define RLB_PATH 1024
#define RLB_LINE 8192
#define RLB_READS 512
#define RLB_ARG 8192
#define RLB_ARGS 32
#define RLB_DEFS 256
#define RLB_FAT 16
#define RLB_FNS 100000
#define RLB_CALLEES 262144
#define RLB_POOL (16u * 1024u * 1024u)
#define RLB_FILES 4096
#define RLB_BASE 256
#define RLB_VIOL 512
#define RLB_PEND 4096
#define RLB_CUR 8192
#define RLB_CHAIN 2048
#define RLB_NBAN 6
#define RLB_FILEBUF (4u * 1024u * 1024u)

struct rlb_read {
    char path[256];
    char file[256];
    int line;
    char handler[128];
};

struct rlb_readset {
    struct rlb_read v[RLB_READS];
    int n;
};

struct rlb_fatal {
    char file[RLB_PATH];
    int line;
    char mtype[64];
    char msg[512];
};

struct rlb_fatalset {
    struct rlb_fatal v[RLB_FAT];
    int n;
};

struct rlb_fn {
    char name[192];
    size_t off; /* callee string offset in the owning index pool */
};

struct rlb_fnidx {
    struct rlb_fn v[RLB_FNS];
    int n;    /* distinct function names */
    int ndef; /* function definitions, duplicates included (the awk FN count) */
    size_t pool_n;
    char pool[RLB_POOL]; /* callee strings, appended */
};

struct rlb_counts {
    int resolved, unresolved, nviol, ngrand, nstale, nbase;
};

extern const char *const rlb_banned[RLB_NBAN];

int rlb_parse_defs(const char *root, const char *def_dir,
                   struct rlb_readset *rs, int *nleaf, int *ndefs,
                   struct rlb_fatalset *fs);
int rlb_def_fatal_report(const struct rlb_fatalset *fs);
int rlb_index_paths(const char *root, const char *const *paths, int n,
                    struct rlb_fnidx *fi);
int rlb_banned_scan_file(const char *root, const char *rel,
                         unsigned char found[RLB_NBAN]);
/* Splits off leading and trailing blanks into dst; 2 when it does not fit. */
int rlb_trim(char *dst, size_t cap, const char *src);
/* C identifier character (letter, digit or underscore); defined in
 * gate_read_leaf_no_boot_ceremony_def.c. */
int rlb_isid(int c);
/* baseline is the path opened; shown is the repo-relative path printed in
 * the report, as the shell gate printed it. */
int rlb_verdict(const struct rlb_readset *rs, const struct rlb_fnidx *fi,
                const char *baseline, const char *shown,
                struct rlb_counts *c, FILE *out);

#endif
