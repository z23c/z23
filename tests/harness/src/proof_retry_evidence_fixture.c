/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Exercise retained retry evidence across fixture cleanup. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "test/test_core.h"
#include "dev_proof_retry_evidence.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#if !defined(_WIN32)
static bool proof_retry_fixture_result(struct zcl_retry_evidence_result r, bool rename_failure)
{
    if (rename_failure)
        return r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.observed == 1 &&
            r.retained == 0 && r.missing == 1 && r.errors == 0;
    return r.status == ZCL_RETRY_EVIDENCE_COMPLETE && r.observed == 1 &&
        r.retained == 1 && r.missing == 0 && r.errors == 0;
}

/* The caller supplies the actual runner transcript and later deletes the
 * generation; the evidence directory is a distinct isolated fixture. */
bool proof_retry_fixture_capture(const char *generation, const char *transcript,
                                 char *attempt, size_t cap, bool rename_failure)
{
    if (strstr(transcript, "RETRY-EVIDENCE-LATE-CONTENT")) {
        fprintf(stderr, "retry fixture: late marker unexpectedly in transcript\n"); return false;
    }
    test_make_tmpdir(attempt, cap, "proof_retry", "attempt");
    char log[4096];
    int n = snprintf(log, sizeof(log), "%s/runner.test.log", attempt);
    if (n <= 0 || (size_t)n >= sizeof(log)) return false;
    FILE *f = fopen(log, "w");
    if (!f) return false;
    bool ok = fputs(transcript, f) >= 0;
    if (fclose(f) != 0) ok = false;
    if (chmod(log, 0600) != 0) ok = false;
    if (!ok) return false;
    struct zcl_retry_evidence_result r = zcl_dev_proof_retry_evidence(
        generation, log, attempt, "test_hex_codec");
    bool retained = proof_retry_fixture_result(r, rename_failure);
    if (!retained) fprintf(stderr, "retry fixture capture status=%d observed=%zu retained=%zu missing=%zu errors=%zu root=%s\n",
                           r.status, r.observed, r.retained, r.missing, r.errors, generation);
    return retained;
}

bool proof_retry_fixture_check(const char *attempt, bool rename_failure)
{
    char path[4096], data[16384];
    int n = snprintf(path, sizeof(path), "%s/retry-first-001.log", attempt);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    if (rename_failure) return access(path, F_OK) != 0;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    size_t used = fread(data, 1, sizeof(data) - 1, f);
    bool ok = !ferror(f);
    if (fclose(f) != 0) ok = false;
    data[used] = 0;
    return ok && strstr(data, "RETRY-EVIDENCE-LATE-CONTENT") != NULL;
}
#else
bool proof_retry_fixture_capture(const char *generation, const char *transcript,
                                 char *attempt, size_t cap, bool rename_failure)
{ (void)generation; (void)transcript; (void)attempt; (void)cap; (void)rename_failure; return false; }
bool proof_retry_fixture_check(const char *attempt, bool rename_failure)
{ (void)attempt; (void)rename_failure; return false; }
#endif

#if !defined(_WIN32)
#include "test_group_catalog.h"
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static bool retry_fixture_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    if (fclose(f) != 0) ok = false;
    if (chmod(path, 0600) != 0) ok = false;
    return ok;
}

static bool retry_fixture_blob(const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    char bytes[8192]; memset(bytes, 'X', sizeof(bytes));
    bool ok = true;
    for (int i = 0; i < 129; i++)
        if (fwrite(bytes, 1, sizeof(bytes), f) != sizeof(bytes)) { ok = false; break; }
    if (fclose(f) != 0) ok = false;
    if (chmod(path, 0600) != 0) ok = false;
    return ok;
}

static size_t retry_fixture_hex_index(void)
{
    size_t n = zcl_test_group_catalog_count();
    for (size_t i = 0; i < n; i++)
        if (strcmp(zcl_test_group_catalog_at(i), "test_hex_codec") == 0) return i;
    return SIZE_MAX;
}

static bool retry_fixture_manifest(const char *attempt, const char *needle)
{
    char path[4096], line[512];
    int n = snprintf(path, sizeof(path), "%s/retry-first.manifest", attempt);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "r"); if (!f) return false;
    bool found = false;
    while (fgets(line, sizeof(line), f)) if (strstr(line, needle)) found = true;
    bool ok = !ferror(f) && found;
    if (fclose(f) != 0) ok = false;
    return ok;
}

static bool retry_fixture_output_total(const char *attempt, size_t *total)
{
    *total = 0;
    for (int i = 1; i <= 128; i++) {
        char path[4096]; struct stat st;
        int n = snprintf(path, sizeof(path), "%s/retry-first-%03d.log", attempt, i);
        if (n <= 0 || (size_t)n >= sizeof(path) || stat(path, &st) != 0 || st.st_size < 0) return false;
        *total += (size_t)st.st_size;
    }
    return true;
}

static bool retry_fixture_many(const char *gen, const char *attempt,
                               const char *log, const char *line)
{
    FILE *f = fopen(log, "w"); if (!f) return false;
    bool ok = true;
    for (int i = 0; i < 129; i++) if (fputs(line, f) < 0) ok = false;
    if (fclose(f) != 0) ok = false;
    if (chmod(log, 0600) != 0) ok = false;
    struct zcl_retry_evidence_result r = zcl_dev_proof_retry_evidence(gen, log, attempt, "test_hex_codec");
    size_t total = 0;
    ok = retry_fixture_output_total(attempt, &total) && ok;
    return ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.observed == 129 &&
        r.retained == 128 && r.errors == 1 && total == 16u * 1024u * 1024u;
}

struct retry_edge {
    char gen[4096], attempt[4096], source[4096], log[4096], line[512];
};

static bool retry_edge_attempt(struct retry_edge *e, const char *name)
{
    test_make_tmpdir(e->attempt, sizeof(e->attempt), "proof_retry", name);
    int n = snprintf(e->log, sizeof(e->log), "%s/runner.test.log", e->attempt);
    return n > 0 && (size_t)n < sizeof(e->log);
}

static bool retry_edge_init(struct retry_edge *e)
{
    char tmp[4096];
    size_t index = retry_fixture_hex_index();
    if (index == SIZE_MAX) return false;
    test_make_tmpdir(e->gen, sizeof(e->gen), "proof_retry", "generation");
    int a = snprintf(tmp, sizeof(tmp), "%s/test-tmp", e->gen);
    int b = snprintf(e->source, sizeof(e->source), "%s/test_parallel_1_%zu.log.first", tmp, index);
    int d = snprintf(e->line, sizeof(e->line), "RETRY-FIRST-PRESERVED test_hex_codec first_log=./test-tmp/test_parallel_1_%zu.log.first\n", index);
    return a > 0 && (size_t)a < sizeof(tmp) && b > 0 && (size_t)b < sizeof(e->source) &&
        d > 0 && (size_t)d < sizeof(e->line) && mkdir(tmp, 0700) == 0;
}

static bool retry_checkout_setup(struct retry_edge *e, const char *generation)
{
    char tmp[4096];
    size_t index = retry_fixture_hex_index();
    int a = snprintf(tmp, sizeof(tmp), "%s/test-tmp", generation);
    int b = snprintf(e->source, sizeof(e->source), "%s/test_parallel_1_%zu.log.first", tmp, index);
    int c = snprintf(e->line, sizeof(e->line), "RETRY-FIRST-PRESERVED test_hex_codec first_log=./test-tmp/test_parallel_1_%zu.log.first\n", index);
    return index != SIZE_MAX && a > 0 && (size_t)a < sizeof(tmp) && b > 0 &&
        (size_t)b < sizeof(e->source) && c > 0 && (size_t)c < sizeof(e->line) &&
        mkdir(tmp, 0755) == 0 && retry_edge_attempt(e, "checkout") &&
        retry_fixture_text(e->source, "checkout evidence\n") && retry_fixture_text(e->log, e->line);
}

/* Exercise the collector against an actual proof checkout, not a synthetic root. */
bool proof_retry_fixture_checkout(const char *generation)
{
    struct retry_edge e = {0};
    bool ok = retry_checkout_setup(&e, generation);
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(generation, e.log, e.attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_COMPLETE && r.retained == 1 &&
        retry_fixture_manifest(e.attempt, "status=retained");
    if (e.attempt[0] && test_rm_rf_recursive(e.attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_empty_and_forged(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "edge") && retry_fixture_text(e->log, "no retry\n");
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    char manifest[4096];
    int m = snprintf(manifest, sizeof(manifest), "%s/retry-first.manifest", e->attempt);
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_NONE && r.observed == 0 && m > 0 &&
        (size_t)m < sizeof(manifest) && access(manifest, F_OK) != 0;
    ok = ok && retry_fixture_text(e->log, "RETRY-FIRST-PRESERVED test_hex_codec first_log=../../outside\n");
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_UNAVAILABLE && r.errors == 1 && access(manifest, F_OK) != 0;
    return ok;
}

static bool retry_edge_missing(struct retry_edge *e)
{
    bool ok = retry_edge_empty_and_forged(e);
    struct zcl_retry_evidence_result r = {0};
    ok = ok && retry_fixture_text(e->log, "RETRY-FIRST-PRESERVE-FAILED test_hex_codec path=fixture error=denied\n");
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.missing == 1 && r.retained == 0;
    ok = ok && retry_fixture_text(e->log, e->line);
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.missing == 1 &&
        retry_fixture_manifest(e->attempt, "status=missing");
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_nul(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "nul") && retry_fixture_text(e->source, "original evidence\n");
    FILE *f = ok ? fopen(e->log, "wb") : NULL;
    static const unsigned char bad[] = {'x', 0, 'y', '\n'};
    if (!f) ok = false;
    if (f) {
        if (fwrite(bad, 1, sizeof(bad), f) != sizeof(bad) || fputs(e->line, f) < 0) ok = false;
        if (fclose(f) != 0) ok = false;
        if (chmod(e->log, 0600) != 0) ok = false;
    }
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.errors == 1 && r.retained == 1 &&
        retry_fixture_manifest(e->attempt, "truncated=0 status=retained");
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_fifo(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "fifo") && unlink(e->source) == 0 && mkfifo(e->source, 0600) == 0 &&
        retry_fixture_text(e->log, e->line);
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.errors == 1 &&
        retry_fixture_manifest(e->attempt, "status=copy_error");
    if (unlink(e->source) != 0) ok = false;
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

struct retry_mutation { const char *path; bool ok; };
static void retry_mutate_same_size(void *context)
{
    struct retry_mutation *m = context;
    FILE *f = fopen(m->path, "r+");
    if (!f) return;
    m->ok = fputc('Z', f) != EOF;
    if (fclose(f) != 0) m->ok = false;
    struct timespec times[2] = {{.tv_sec = 1}, {.tv_sec = 1}};
    if (utimensat(AT_FDCWD, m->path, times, 0) != 0) m->ok = false;
}

static bool retry_edge_mutation(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "mutation") && retry_fixture_text(e->log, e->line);
    struct retry_mutation mutation = {.path = e->source};
    struct zcl_retry_evidence_result r = {0};
    zcl_dev_proof_retry_test_after_copy(retry_mutate_same_size, &mutation);
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    zcl_dev_proof_retry_test_after_copy(NULL, NULL);
    ok = ok && mutation.ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.errors == 1 && r.retained == 0 &&
        retry_fixture_manifest(e->attempt, "status=copy_error");
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_log_fifo(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "log-fifo") && mkfifo(e->log, 0600) == 0;
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_UNAVAILABLE;
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_cap(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "cap") && retry_fixture_text(e->log, e->line) && retry_fixture_blob(e->source);
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.retained == 1 &&
        retry_fixture_manifest(e->attempt, "original=1056768 copied=1048576 truncated=1 status=retained");
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_many(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "many") && retry_fixture_many(e->gen, e->attempt, e->log, e->line);
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_writable(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "writable") && chmod(e->source, 0666) == 0 &&
        retry_fixture_text(e->log, e->line);
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.errors == 1 &&
        retry_fixture_manifest(e->attempt, "status=copy_error");
    if (chmod(e->source, 0600) != 0) ok = false;
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_symlink(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "symlink") && unlink(e->source) == 0 &&
        symlink("/etc/passwd", e->source) == 0 && retry_fixture_text(e->log, e->line);
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.errors == 1 &&
        retry_fixture_manifest(e->attempt, "status=copy_error");
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

static bool retry_edge_generation_mode(struct retry_edge *e)
{
    bool ok = retry_edge_attempt(e, "generation_mode") &&
        retry_fixture_text(e->log, e->line) && chmod(e->gen, 0775) == 0;
    struct zcl_retry_evidence_result r = {0};
    if (ok) r = zcl_dev_proof_retry_evidence(e->gen, e->log, e->attempt, "test_hex_codec");
    ok = ok && r.status == ZCL_RETRY_EVIDENCE_PARTIAL && r.errors == 1 &&
        r.prepare_stage && strcmp(r.prepare_stage, "generation") == 0 && r.prepare_errno == EACCES;
    if (chmod(e->gen, 0700) != 0) ok = false;
    if (test_rm_rf_recursive(e->attempt) != 0) ok = false;
    return ok;
}

/* Bounded inputs and no-follow refusal, independent from the real runner. */
bool proof_retry_fixture_edges(void)
{
    struct retry_edge e = {0};
    if (!retry_edge_init(&e)) return false;
    bool generation_mode = retry_edge_generation_mode(&e);
    bool missing = retry_edge_missing(&e), nul = retry_edge_nul(&e), mutation = retry_edge_mutation(&e);
    bool fifo = retry_edge_fifo(&e);
    bool log_fifo = retry_edge_log_fifo(&e);
    bool cap = retry_edge_cap(&e);
    bool many = retry_edge_many(&e), writable = retry_edge_writable(&e), symlink_ok = retry_edge_symlink(&e);
    bool cleaned = test_rm_rf_recursive(e.gen) == 0;
    bool ok = generation_mode && missing && nul && mutation && fifo && log_fifo && cap && many && writable && symlink_ok && cleaned;
    if (!ok) fprintf(stderr, "retry evidence edges generation_mode=%d missing=%d nul=%d mutation=%d fifo=%d log_fifo=%d cap=%d many=%d writable=%d symlink=%d cleanup=%d\n",
                     generation_mode, missing, nul, mutation, fifo, log_fifo, cap, many, writable, symlink_ok, cleaned);
    return ok;
}
#else
bool proof_retry_fixture_edges(void) { return true; }
bool proof_retry_fixture_checkout(const char *generation) { (void)generation; return true; }
#endif
