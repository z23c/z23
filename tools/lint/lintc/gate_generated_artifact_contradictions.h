/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: family-local declarations for the
 * check-generated-artifact-contradictions lint gate — the parsed-record
 * structs shared by the scan file and the gate body, and the scan file's
 * prototypes (gate_generated_artifact_contradictions_scan.c).
 */
#ifndef GATE_GENERATED_ARTIFACT_CONTRADICTIONS_H
#define GATE_GENERATED_ARTIFACT_CONTRADICTIONS_H

#include <stddef.h>

struct gac_multi {
    const char *h, *p, *s, *claimed, *agdef, *agcon;
};
struct gac_untested {
    const char *p, *s;
    int scope_ok, verdict_ok;
};

int gacs_comp(void);
void gacs_drop(void);
int gacs_discover_ok(const char *path);
int gacs_consumes_path(const char *path, char *out, size_t cap);
int gacs_meta_check(const char *path, const char *const *claims, int n,
                    const char **miss);
int gacs_file_has_line(const char *path, const char *line, int *out);
int gacs_load_baseline(const char *path);
int gacs_baseline_n(void);
int gacs_baseline_has(const char *key);
int gacs_parse_cap(const char *path);
int gacs_multi_n(void);
const struct gac_multi *gacs_multi_at(int i);
int gacs_arm_count(const char *h, const char *p, const char *s);
int gacs_arm_clean(const char *h, const char *p, const char *s);
int gacs_build_triples(void);
int gacs_ntriples(void);
const char *gacs_triple_key(int i);
int gacs_multi_has(const char *h, const char *p, const char *s);
int gacs_untested_n(void);
const struct gac_untested *gacs_untested_at(int i);

#endif
