/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: independent-builder attestations for plugin images. A publisher
 * signature says who published an executable; an attestation says an
 * independent builder compiled the same source root and got the same bytes.
 * One record binds (plugin name, version, source package root, toolchain id,
 * output image SHA3-512) and is signed by one builder Ed25519 key, the same
 * key form and signature primitive as the plugin store. Records are canonical
 * single-line JSON, so equal inputs give byte-identical files and the parser
 * accepts exactly the bytes the encoder writes and nothing else.
 * plugin_attest_verify_dir accepts a manifest only when at least K DISTINCT
 * builder keys, each listed in the caller's builder pin file, attest the
 * manifest's sha3_512 for one shared source root. Every other shape is
 * refused with its own code. The pin file is a trust root: read no-follow
 * and owner-only. This module installs nothing and runs nothing; the future
 * fetch gate calls plugin_attest_verify_dir once. docs/dev/PLUGINS.md. */
#ifndef ZCL_PLUGIN_ATTEST_H
#define ZCL_PLUGIN_ATTEST_H

#include "plugin/plugin_store.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PLUGIN_ATTEST_RECORD_MAX = 1024,    /* bytes of one canonical record */
    PLUGIN_ATTEST_TOOLCHAIN_MAX = 64,
    PLUGIN_ATTEST_PINS_MAX = 256,       /* distinct pinned builder keys */
    PLUGIN_ATTEST_FILES_MAX = 256,      /* attestation files per directory */
    PLUGIN_ATTEST_HEX_KEY = 64,
    PLUGIN_ATTEST_HEX_SIG = 128
};

/* Stable leaf suffix of an attestation file. */
#define PLUGIN_ATTEST_SUFFIX ".attest.json"

enum plugin_attest_status {
    PLUGIN_ATTEST_OK = 0,
    PLUGIN_ATTEST_ARGUMENT,
    PLUGIN_ATTEST_UPSTREAM,         /* a store call failed: report.cause */
    PLUGIN_ATTEST_IO,
    PLUGIN_ATTEST_MALFORMED,        /* record is not the canonical encoding */
    PLUGIN_ATTEST_SIG_BAD,
    PLUGIN_ATTEST_PINS_MALFORMED,
    PLUGIN_ATTEST_THRESHOLD_INVALID,        /* below 1 */
    PLUGIN_ATTEST_THRESHOLD_EXCEEDS_PINS,   /* above the pinned builders */
    PLUGIN_ATTEST_TOO_MANY_FILES,
    PLUGIN_ATTEST_SUBJECT_MISMATCH,         /* name or version differs */
    PLUGIN_ATTEST_BUILDER_UNPINNED,
    PLUGIN_ATTEST_DUPLICATE_BUILDER,
    PLUGIN_ATTEST_HASH_MISMATCH,
    PLUGIN_ATTEST_SOURCE_ROOT_MISMATCH,
    PLUGIN_ATTEST_BELOW_THRESHOLD
};

/* "PLUGIN_ATTEST_DUPLICATE_BUILDER" and so on. */
const char *plugin_attest_status_code(enum plugin_attest_status status);
/* The operator action that resolves the refusal. */
const char *plugin_attest_status_next_action(enum plugin_attest_status status);

struct plugin_attest_record {
    char name[PLUGIN_NAME_MAX + 1];
    char version[PLUGIN_VERSION_MAX + 1];
    char source_root[PLUGIN_ATTEST_HEX_KEY + 1];  /* 64 lowercase hex */
    char toolchain[PLUGIN_ATTEST_TOOLCHAIN_MAX + 1]; /* [A-Za-z0-9._:+-] */
    char image[PLUGIN_HEX_SHA3_512 + 1];          /* SHA3-512 of the image */
    char builder_key[PLUGIN_ATTEST_HEX_KEY + 1];  /* Ed25519 public key */
    char signature[PLUGIN_ATTEST_HEX_SIG + 1];
};

/* Canonical record bytes, NUL-terminated, ending in one LF. Returns the
 * length, or 0 when a field is invalid or cap is too small. */
size_t plugin_attest_encode(const struct plugin_attest_record *rec,
                            char *out, size_t cap);

/* Total parser: any byte string either yields a record whose re-encoding is
 * byte-identical to the input or PLUGIN_ATTEST_MALFORMED. Reads no memory
 * past len and needs no NUL. Does not check the signature. */
enum plugin_attest_status plugin_attest_parse(const char *bytes, size_t len,
                                              struct plugin_attest_record *out);

/* Ed25519 over SHA3-512("z23.plugin.attest.v1" NUL signed-prefix) against
 * rec->builder_key; the prefix is every record byte before the signature. */
enum plugin_attest_status plugin_attest_check_signature(
    const struct plugin_attest_record *rec);

struct plugin_attest_request {
    const char *image_path;   /* the image the caller built */
    const char *key_path;     /* builder signing key: 32-byte Ed25519 seed */
    const char *name;
    const char *version;
    const char *source_root;  /* 64 lowercase hex */
    const char *toolchain;    /* build recipe or toolchain id */
    const char *dir;          /* output directory, NULL means "." */
};

struct plugin_attest_result {
    struct plugin_attest_record record;
    char path[4096];
    enum plugin_status cause; /* set with PLUGIN_ATTEST_UPSTREAM */
};

/* Hashes the image, signs the record and writes
 * dir/NAME-<first 16 builder key hex>.attest.json atomically. Deterministic. */
enum plugin_attest_status plugin_attest_make(
    const struct plugin_attest_request *request,
    struct plugin_attest_result *result);

struct plugin_attest_report {
    enum plugin_status cause;      /* set with PLUGIN_ATTEST_UPSTREAM */
    char file[256];                /* leaf that caused a refusal, else "" */
    uint32_t threshold;
    uint32_t pinned;               /* distinct pinned builder keys */
    uint32_t files;                /* attestation files read */
    uint32_t attested;             /* distinct pinned builders that agree */
    uint32_t toolchains;           /* distinct toolchain ids among them */
    char name[PLUGIN_NAME_MAX + 1];
    char version[PLUGIN_VERSION_MAX + 1];
    char source_root[PLUGIN_ATTEST_HEX_KEY + 1];
    char image[PLUGIN_HEX_SHA3_512 + 1];
    char builders[PLUGIN_ATTEST_PINS_MAX][PLUGIN_ATTEST_HEX_KEY + 1];
};

/* Accepts only when at least threshold distinct pinned builder keys attest
 * the manifest's sha3_512 for one source root. expected_root (64 hex) may be
 * NULL; when given every attestation must name it. Order: threshold against
 * the pinned count, then per file in sorted order: parse, signature, subject,
 * pinned, duplicate, hash, source root; last the count. report is filled on
 * every return. */
enum plugin_attest_status plugin_attest_verify_dir(
    const char *manifest_path, const char *attestations_dir,
    const char *builders_path, int64_t threshold, const char *expected_root,
    struct plugin_attest_report *report);

#ifdef ZCL_TESTING
/* Test seam: after `after` directory entries the scan fails with EIO once. */
void plugin_attest_test_fail_readdir(unsigned after);
#endif

#endif
