/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — SEALED IMAGE: an immutable memfd copy of an artifact.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * hotswap/hotswap_artifact_digest.h documents, precisely, a hole that was
 * MEASURED rather than theorised. The loader opens a module .so, hashes that
 * descriptor, then dlopens "/proc/self/fd/N" from the SAME descriptor. That
 * makes the load REDIRECT-PROOF — /proc/self/fd/N resolves to the inode the
 * descriptor already holds, so renaming or symlinking a different artifact
 * over the original path between the hash and the load changes nothing.
 *
 * It does NOT make the load TAMPER-PROOF. dlopen re-reads the file through
 * that descriptor's inode, so a writer who overwrites the same inode IN PLACE
 * (open + write, not rename) between the hash and the load makes the node hash
 * bytes A and map bytes B. Two things narrow that window today —
 * hotswap_path_is_acceptable() confines the artifact to the dev build tree or
 * /tmp, and the Makefile publishes modules chmod a-w — but neither is a
 * guarantee: the owning uid can restore write permission, and a fresh file in
 * /tmp is writable by its creator.
 *
 * This file implements the first of the two fixes that header names: copy the
 * descriptor's contents into a memfd_create() region and seal it, so the bytes
 * the loader maps CANNOT change after the copy returns. There is no window
 * left to lose, because after the seal there is no writer anywhere in the
 * system — not the artifact's owner, not root, not this process — who can
 * alter one byte of the image. Seals, once applied, can never be removed.
 *
 * WHAT SEALING BUYS
 * -----------------
 *   IMMUTABILITY. F_SEAL_WRITE forbids every future write and every future
 *   shared-writable mapping of the image. F_SEAL_SHRINK and F_SEAL_GROW pin
 *   its length. The kernel enforces all three against every descriptor, every
 *   mapping and every process, for the whole remaining life of the object.
 *
 *   Enforcement is at USE time, not at open time, and that surprises people:
 *   on Linux 6.8 an open("/proc/self/fd/N", O_RDWR) against a sealed image
 *   SUCCEEDS. It hands back a descriptor in writable mode that cannot write —
 *   every pwrite() through it returns EPERM, and every MAP_SHARED|PROT_WRITE
 *   mmap of it returns EPERM. Measured, not assumed. Do not write a check that
 *   concludes "the image is not sealed" because a writable open succeeded; the
 *   only sound test is F_GET_SEALS.
 *
 *   HASH-EQUALS-MAP. Because the bytes cannot change, a digest taken from the
 *   SEALED descriptor describes exactly the bytes dlopen will later map from
 *   that same descriptor. That equality is the entire point, and it is why the
 *   caller MUST hash the returned fd and NOT the source fd — see below.
 *
 * WHAT SEALING DOES NOT BUY — read this before believing anything else
 * -------------------------------------------------------------------
 *   IT DOES NOT MAKE THE CODE SAFE TO RUN. Sealing is an integrity property,
 *   not a trust decision. It freezes bytes; it says nothing about where they
 *   came from, whether loading them here is authorized, or whether the code
 *   inside is correct or malicious. A sealed malicious artifact is exactly as
 *   immutable as a sealed benign one, and dlopen will run its initialisers
 *   just as willingly. Provenance, authorization and review remain entirely
 *   separate lanes' jobs.
 *
 *   IT DOES NOT VALIDATE THE SOURCE. Whatever bytes the source descriptor held
 *   at copy time are what gets frozen. If the file was ALREADY tampered with
 *   before this call, sealing faithfully preserves the tampering.
 *
 *   IT DOES NOT CLOSE THE WINDOW BEFORE ITSELF. The copy loop reads the source
 *   over a non-zero interval, and a concurrent in-place writer can still change
 *   the source underneath it — meaning the image may be a torn mix of pre- and
 *   post-write bytes. What the seal guarantees is that WHATEVER was captured is
 *   what gets hashed AND what gets mapped: no divergence between the two. A
 *   torn image is not a silent compromise, it is an artifact whose digest will
 *   simply not match any digest anyone recorded, and the loader rejects it.
 *
 *   IT IS NOT A REPLACEMENT FOR THE fd PIN. It subsumes it: the returned fd is
 *   a distinct kernel object with no name in any directory, so it cannot be
 *   redirected either. Both properties now hold, for the first time.
 *
 * REQUIRED CALLING DISCIPLINE — getting this wrong reopens the hole
 * ----------------------------------------------------------------
 * The digest MUST be computed from the RETURNED descriptor, and the dlopen
 * MUST target the RETURNED descriptor:
 *
 *     int sealed = hotswap_sealed_image_from_fd(fd, err, sizeof(err));
 *     if (sealed < 0) { reject(err); return; }
 *     hotswap_artifact_sha3_fd(sealed, hex);          // hash the SEALED bytes
 *     snprintf(pin, sizeof(pin), "/proc/self/fd/%d", sealed);
 *     void *h = dlopen(pin, RTLD_NOW | RTLD_LOCAL);   // map the SAME bytes
 *     ...
 *     close(sealed);   // safe once dlopen has mapped it; the mapping outlives
 *                      // the descriptor, exactly as for an ordinary file.
 *
 * Hashing the SOURCE fd and then sealing a copy proves nothing at all — the
 * two reads are separated in time, which is the original bug wearing a memfd
 * costume. Hash the sealed fd or do not bother sealing.
 *
 * PLATFORM NOTE
 * -------------
 * memfd_create(2) and file sealing are Linux-only (memfd_create since 3.17,
 * sealing on tmpfs/hugetlbfs since 3.17). Z23's hot-swap tier is already
 * Linux-only — it is built around /proc/self/fd and dlopen of a build-tree
 * artifact — so this adds no portability constraint that tier did not have.
 *
 * One kernel knob can defeat the whole approach and is worth naming so a
 * future failure is diagnosed in seconds rather than hours: on Linux >= 6.3,
 * `sysctl vm.memfd_noexec=2` forces MFD_NOEXEC_SEAL onto every memfd created
 * without an explicit MFD_EXEC, which makes the image non-executable and makes
 * dlopen of it fail. If dlopen of a sealed image ever starts failing on a box
 * where it used to work, read that sysctl FIRST. This file does not pass
 * MFD_EXEC: doing so would opt the image out of a hardening default that the
 * operator chose deliberately, and the honest response to that configuration
 * is a loud load failure, not a quiet bypass.
 *
 * This header is deliberately narrow: one function, no allocation, no logging,
 * no policy. It produces immutable bytes and reports why it could not.
 */
#ifndef ZCL_HOTSWAP_SEALED_IMAGE_H
#define ZCL_HOTSWAP_SEALED_IMAGE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Copy the full contents of `src_fd` — from offset 0, regardless of that
 * descriptor's current offset — into an anonymous memory-backed file, then
 * seal it so its bytes and its length can never change again.
 *
 * On success returns a NEW descriptor that the caller OWNS and MUST close(),
 * positioned at offset 0 and carrying F_SEAL_WRITE | F_SEAL_SHRINK |
 * F_SEAL_GROW, verified by reading the seals back. `src_fd` is left open,
 * owned by the caller, with its offset at 0.
 *
 * On failure returns -1, closes anything it opened (no descriptor is leaked on
 * any path), and writes a specific NUL-terminated reason into `err` when `err`
 * is non-NULL and `err_cap` is non-zero. Failure is fail-closed in every case:
 * a negative src_fd, a non-seekable source such as a pipe (ESPIPE from the
 * initial lseek), an EMPTY source, a read or write error other than EINTR, a
 * memfd_create() that the kernel refuses, an F_ADD_SEALS that fails, or seals
 * that read back as anything other than the full set requested.
 *
 * An empty source is rejected rather than sealed. A zero-byte artifact is
 * never a loadable module — dlopen would reject it a moment later with a far
 * less informative message — and treating "nothing to copy" as success is the
 * shape of bug that turns a truncated file into a silent no-op.
 *
 * Cost: the image is anonymous memory, so a sealed copy of an N-byte artifact
 * costs N bytes of RAM until the descriptor is closed AND every mapping of it
 * is gone. Hot-swap modules are tens to a few hundred kilobytes; this is not
 * a path for sealing large files. */
int hotswap_sealed_image_from_fd(int src_fd, char *err, size_t err_cap);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_HOTSWAP_SEALED_IMAGE_H */
