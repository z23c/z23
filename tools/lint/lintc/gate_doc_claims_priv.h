/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-doc-claims gate port
 * (gate_doc_claims.c, gate_doc_claims_eval.c, gate_doc_claims_scan.c,
 * gate_doc_claims_selfcheck.c, gate_doc_claims_selftest.c). Lintc-internal;
 * the public entry points are declared in lintc.h via gates.def.
 */
#ifndef GATE_DOC_CLAIMS_PRIV_H
#define GATE_DOC_CLAIMS_PRIV_H
#include <stddef.h>
#include <stdio.h>

enum {
    DC_PATH = 1024,
    DC_LINE = 32768,
    DC_CTX = 512,
    DC_TOK = 512,
    DC_TOKS = 8,
    DC_REASON = 2048,
    DC_CMD = 4096,
    DC_FILES = 4096,
    DC_FILE = 512,
    DC_VIOL = 512,
    DC_VIOL_SZ = 9216,
    DC_MEMO = 64,
    DC_MEMO_NAME = 128,
    DC_ARGS = 16,
    DC_OUT = 1 << 21,
    MD_SCAN_FLOOR = 50,
    CLAIM_FLOOR = 1,
    DC_ENTRY_DOCS = 8
};

enum dc_part { DC_PART_ALL = 0, DC_PART_GATE, DC_PART_DOC };
enum dc_mode {
    DC_M_SCAN = 0,
    DC_M_SELFTEST,
    DC_M_LIST,
    DC_M_GLOBAL,
    DC_M_DOC
};

/* shared state, defined in gate_doc_claims.c */
extern char dc_root[DC_PATH];
extern int dc_mode;
extern int dc_claim_part;
extern int dc_claims_parsed;
extern int dc_claims_left;
extern int dc_reliance_scanned;
extern char dc_viol[DC_VIOL][DC_VIOL_SZ];
extern int dc_viol_n;
extern char dc_scan_files[DC_FILES][DC_FILE];
extern int dc_scan_n;
extern int dc_external;
extern int dc_gate_timeout;
extern int dc_table_override;
extern char dc_table_path[DC_PATH];

/* gate_doc_claims.c */
void dc_state_reset(void);
int dc_viol_add(const char *fmt, ...);
const char *dc_ltrim(const char *s);

/* gate_doc_claims_eval.c */
int dc_run_capture(char *const argv[], char *out, size_t cap, size_t *len,
                   int *rc);
int dc_eval_claim(const char *body, char *reason, size_t cap);
int dc_claim_owned(const char *body);
int dc_gate_rc(const char *gate);
void dc_memo_forget(const char *gate);
void dc_memo_clear(void);

/* gate_doc_claims_scan.c */
int dc_scan_claim_file(const char *path, const char *disp);
int dc_scan_positive_reliance(const char *path, const char *disp);
int dc_doc_has_claim(const char *path);

/* gate_doc_claims_selfcheck.c */
int dc_selfcheck(void);

#endif
