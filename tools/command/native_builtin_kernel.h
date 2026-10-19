/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The guest kernel built into the binary at build time: pinned
 *          identity, deterministic packing and verified in-memory unpacking.
 *
 * The built-in kernel is the published FreeBSD 15.1-RELEASE riscv64 GENERIC
 * kernel (docs/commons/RISCV_MACHINE.md, "KERNEL: release GENERIC kernel"), stored
 * gzip-compressed. It is present only in a build made with Z23_GUEST_KERNEL.
 * A buffer is returned only when the inflated bytes have exactly the pinned
 * length and SHA-256; the compressed bytes are treated as untrusted input. */
#ifndef ZCL_NATIVE_BUILTIN_KERNEL_H
#define ZCL_NATIVE_BUILTIN_KERNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_BUILTIN_KERNEL_BYTES UINT64_C(62745584)
#define ZCL_BUILTIN_KERNEL_SHA256 \
    "69320e312d5601c5fe228aa3bcbdc4bbc55e0d86a4cf9e68eb6ffdc7247701b1"
/* Largest pinned length accepted by any pin. */
#define ZCL_BUILTIN_KERNEL_MAX_BYTES (UINT64_C(1) << 30)

enum zcl_builtin_kernel_status {
    ZCL_BUILTIN_KERNEL_OK = 0,
    ZCL_BUILTIN_KERNEL_ABSENT,
    ZCL_BUILTIN_KERNEL_INFLATE_FAILED,
    ZCL_BUILTIN_KERNEL_LENGTH_MISMATCH,
    ZCL_BUILTIN_KERNEL_HASH_MISMATCH,
    ZCL_BUILTIN_KERNEL_TOO_LARGE,
    ZCL_BUILTIN_KERNEL_NO_MEMORY
};

struct zcl_builtin_kernel_pin {
    uint64_t length;
    const char *sha256_hex; /* 64 lowercase hex digits */
};

/* The compressed kernel of this build: defined by the generated source in a
 * build made with Z23_GUEST_KERNEL, otherwise by an empty definition. */
extern const uint8_t zcl_builtin_kernel_gz[];
extern const size_t zcl_builtin_kernel_gz_size;

/* Lowercase refusal name: "ok", "builtin_kernel_absent", ... */
const char *zcl_builtin_kernel_status_name(enum zcl_builtin_kernel_status status);

/* Inflates gz and returns a malloc'd buffer of exactly pin->length bytes whose
 * SHA-256 equals pin->sha256_hex. Inflation stops at pin->length + 1 bytes.
 * On any refusal *out is NULL and no buffer exists. */
enum zcl_builtin_kernel_status zcl_builtin_kernel_unpack(
    const uint8_t *gz, size_t gz_size, const struct zcl_builtin_kernel_pin *pin,
    uint8_t **out, size_t *out_length);

/* Unpacks this build's kernel against the documented pin. */
enum zcl_builtin_kernel_status zcl_builtin_kernel_load(uint8_t **out, size_t *out_length);

/* Pin of the documented release kernel. */
const struct zcl_builtin_kernel_pin *zcl_builtin_kernel_release_pin(void);

/* Gzip container with a fixed header (no time, no name, OS unknown) around a
 * raw deflate stream at level 9: the same input yields the same bytes with
 * the same zlib. Returns a malloc'd buffer, or NULL on failure. */
uint8_t *zcl_builtin_kernel_pack(const uint8_t *src, size_t length, size_t *out_size);

#endif
