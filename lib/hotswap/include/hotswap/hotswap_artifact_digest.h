/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — SHA3-256 artifact digest over an OPEN FILE DESCRIPTOR.
 *
 * hotswap_activate.c's artifact digest hashes a descriptor and then dlopens
 * "/proc/self/fd/N" from that SAME descriptor — never a path. That is
 * deliberate, and it buys exactly one property, stated precisely because a
 * vaguer version of this sentence was wrong:
 *
 *   WHAT THE fd PIN GUARANTEES: the loader cannot be redirected to a
 *   DIFFERENT FILE. /proc/self/fd/N resolves to the inode the descriptor
 *   already holds, so renaming or symlinking another artifact over the
 *   original path between the hash and the load has no effect — the bytes
 *   still come from the inode that was hashed. A path-based digest re-opens
 *   by name and loses this: the inode the digest describes need not be the
 *   inode later mapped.
 *
 *   WHAT IT DOES NOT GUARANTEE: that the inode's CONTENTS are unchanged.
 *   dlopen re-reads the file through that descriptor's inode, so a writer
 *   who overwrites the same inode in place (open+write, not rename) between
 *   the hash and the load makes the node hash bytes A and map bytes B. This
 *   was measured, not reasoned about. Two things narrow the window today —
 *   hotswap_path_is_acceptable() confines the artifact to the dev build tree
 *   or /tmp, and the Makefile publishes modules chmod a-w — but neither is a
 *   guarantee: the owning uid can restore write permission, and a fresh file
 *   in /tmp is writable by its creator. Closing it for real means loading
 *   from bytes that CANNOT change: copy the descriptor's contents into a
 *   memfd_create() region, apply F_SEAL_WRITE|F_SEAL_SHRINK|F_SEAL_GROW, and
 *   dlopen the sealed memfd; or re-hash after dlopen and compare. Until one
 *   of those lands, do not describe this as tamper-proof — describe it as
 *   redirect-proof, which is what it is.
 *
 * WHAT A MATCHING DIGEST PROVES: the bytes read from this fd are the exact
 * bytes some earlier party recorded when they computed the same digest — nothing
 * was substituted, truncated, or corrupted in transit or at rest.
 *
 * WHAT IT DOES NOT PROVE: that those bytes are SAFE to load. A digest is
 * silent on provenance (who wrote them), on authorization (whether loading
 * them is allowed here), and on content (whether the code inside is correct
 * or malicious). A byte-identical malicious artifact hashes exactly as clean
 * as a benign one. Digest equality is an integrity check, not a trust
 * decision — policy on top of it (an allowlist, a signature, a human review)
 * is a separate lane's job, not this one's.
 *
 * This header is deliberately narrow: one predicate, no comparison helper, no
 * logging, no allocation. It only reports what the bytes hash to.
 */
#ifndef ZCL_HOTSWAP_ARTIFACT_DIGEST_H
#define ZCL_HOTSWAP_ARTIFACT_DIGEST_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA3-256 digest of the full contents of open descriptor `fd`, read from the
 * start regardless of the descriptor's current offset.
 *
 * On success returns true and writes 64 lowercase hex characters plus a
 * terminating NUL into hex_out (hex_out[64] == '\0'). On any failure
 * (negative fd, NULL hex_out, seek failure, or a read error other than
 * EINTR) returns false and hex_out is left unspecified.
 *
 * Leaves the descriptor's file offset at 0 on success. Does not close fd;
 * ownership stays with the caller. */
bool hotswap_artifact_sha3_fd(int fd, char hex_out[65]);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_ARTIFACT_DIGEST_H */
