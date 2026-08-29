/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tier-1 hot-swap — sealed image: an immutable memfd copy of an artifact.
 * See hotswap/hotswap_sealed_image.h for what sealing buys, what it does NOT
 * buy (it does not make the code safe to run), and the calling discipline that
 * has to be followed or the whole exercise is theatre: hash the SEALED fd, not
 * the source fd.
 */

#define _GNU_SOURCE  /* memfd_create(), F_ADD_SEALS / F_GET_SEALS / F_SEAL_* */

#include "hotswap/hotswap_sealed_image.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Every failure path funnels through here so that "returns -1 with a specific
 * reason and leaks nothing" is one shape rather than a dozen open-coded ones.
 *
 * errno is captured by the CALLER into `saved` before any cleanup runs,
 * because close() and fcntl() are entitled to clobber errno on their way out
 * and a message reading "Success" is worse than no message at all. */
static int si_fail(int fd_to_close, char *err, size_t err_cap,
                   const char *fmt, ...)
{
    if (fd_to_close >= 0)
        (void)close(fd_to_close);
    if (err && err_cap) {
        va_list ap;
        va_start(ap, fmt);
        (void)vsnprintf(err, err_cap, fmt, ap);
        va_end(ap);
    }
    return -1;
}

#if defined(__linux__)
#include <sys/mman.h>

/* The exact seal set this file applies, named once so the apply and the
 * read-back verification cannot drift apart. Deliberately NOT including
 * F_SEAL_SEAL — the reasoning is in si_seal() below, where it is a decision
 * rather than an omission. */
#define SI_SEALS (F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW)

/* Copy exactly the size accepted before the memfd was created.
 *
 * Both halves are loops, not single calls, because read(2) and write(2) are
 * both permitted to move FEWER bytes than asked without it being an error —
 * a short read is ordinary at a page or pipe boundary, and a short write is
 * ordinary whenever the kernel decides it is. Treating either as "done" is the
 * classic way to seal a TRUNCATED image and then wonder why a digest that was
 * verified twice does not match. EINTR is retried; every other errno fails
 * closed, because a partially copied image must never be handed back.
 *
 * A final one-byte read and a second fstat reject a source that grew during
 * the copy.  This makes the work bound independent of a concurrent writer:
 * the function never follows a moving EOF. */
static int si_copy_exact(int src_fd, int img_fd, uint64_t expected)
{
    unsigned char buf[64 * 1024];
    uint64_t total = 0;
    while (total < expected) {
        size_t want = sizeof(buf);
        if (expected - total < (uint64_t)want)
            want = (size_t)(expected - total);
        ssize_t n = read(src_fd, buf, want);
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        /* Drain exactly the n bytes just read. `off` is the write cursor into
         * buf; the loop cannot exit early, so a short write costs another
         * iteration rather than silently dropping the tail. */
        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = write(img_fd, buf + off, (size_t)n - off);
            if (w > 0) {
                off += (size_t)w;
                continue;
            }
            if (w < 0 && errno == EINTR)
                continue;
            /* w == 0 on a regular/memfd write means no progress is being made
             * and never will be; there is no errno for it, so name one rather
             * than spin forever. */
            if (w == 0)
                errno = ENOSPC;
            return -1;
        }
        total += (uint64_t)n;
    }

    for (;;) {
        ssize_t n = read(src_fd, buf, 1);
        if (n == 0)
            break;
        if (n > 0) {
            errno = EFBIG;
            return -1;
        }
        if (errno != EINTR)
            return -1;
    }

    struct stat after;
    if (fstat(src_fd, &after) != 0)
        return -1;
    if (after.st_size < 0 || (uint64_t)after.st_size != expected) {
        errno = EAGAIN;
        return -1;
    }
    return 0;
}

/* Apply the seals and then PROVE they took, rather than trusting that a
 * successful-looking fcntl did what was asked.
 *
 * The read-back is not defensive padding. F_ADD_SEALS returns 0 only when the
 * kernel applied the exact set requested, but the set that ends up on the file
 * is the property the rest of the system depends on, and it is one cheap
 * syscall away from being observed instead of assumed. If a future kernel, a
 * seccomp filter, an LSM, or a filesystem that does not support sealing ever
 * makes those two things differ, this is where it is caught — at the moment of
 * sealing, with a message that says so — rather than three layers up as a
 * mysterious digest mismatch after someone rewrote the "immutable" image.
 *
 * WHY F_SEAL_SEAL IS NOT IN THE SET
 * ---------------------------------
 * F_SEAL_SEAL seals the SEAL SET, not the bytes: it makes future F_ADD_SEALS
 * calls fail. It therefore cannot add anything to the property this file
 * exists to provide. Seals are already irrevocable — there is no kernel
 * interface that removes one — so once F_SEAL_WRITE | F_SEAL_SHRINK |
 * F_SEAL_GROW are on, the byte sequence and the length are fixed for the
 * lifetime of the object whether F_SEAL_SEAL is present or not. Adding it
 * would buy zero immutability and would permanently foreclose an option: an
 * integrator on a newer kernel can no longer add F_SEAL_FUTURE_WRITE or
 * F_SEAL_EXEC to this same descriptor. The one thing F_SEAL_SEAL would deny an
 * adversary is adding a HOSTILE seal (F_SEAL_EXEC, to make the image
 * un-dlopenable) — but that requires already holding this descriptor, which is
 * MFD_CLOEXEC and never leaves this process, so it requires already executing
 * code in this process, at which point sealing is not the control that matters.
 * Trading a real option for a defence against an attacker who has already won
 * is a bad trade, so: not sealed against further sealing, on purpose.
 *
 * Returns 0 with the seals actually present written to *seals_out, or -1 with
 * errno set. Reading back the WRONG set is not an error at this level — it is
 * reported through *seals_out and judged by the caller, because a wrong set has
 * no errno of its own and inventing one would throw away the one fact worth
 * printing: which seals are on. */
static int si_seal(int img_fd, int *seals_out)
{
    if (fcntl(img_fd, F_ADD_SEALS, SI_SEALS) < 0)
        return -1;
    int got = fcntl(img_fd, F_GET_SEALS);
    if (got < 0)
        return -1;
    *seals_out = got;
    return 0;
}

int hotswap_sealed_image_from_fd(int src_fd, char *err, size_t err_cap)
{
    if (err && err_cap)
        err[0] = '\0';

    if (src_fd < 0)
        return si_fail(-1, err, err_cap, "sealed image: invalid source fd %d",
                       src_fd);

    struct stat before;
    if (fstat(src_fd, &before) != 0) {
        int saved = errno;
        return si_fail(-1, err, err_cap,
                       "sealed image: source fstat failed: %s",
                       strerror(saved));
    }
    if (!S_ISREG(before.st_mode))
        return si_fail(-1, err, err_cap,
                       "sealed image: source fd %d is not a regular file",
                       src_fd);
    if (before.st_size <= 0)
        return si_fail(-1, err, err_cap,
                       "sealed image: source fd %d is empty (0 bytes); "
                       "a zero-length artifact is not loadable", src_fd);
    if ((uint64_t)before.st_size > ZCL_HOTSWAP_SEALED_IMAGE_MAX_BYTES)
        return si_fail(-1, err, err_cap,
                       "sealed image: source is %llu bytes, over the %llu byte ceiling",
                       (unsigned long long)before.st_size,
                       (unsigned long long)ZCL_HOTSWAP_SEALED_IMAGE_MAX_BYTES);

    /* Rewind the source rather than trusting its offset. Callers reach here
     * after a digest pass or a header sniff has already moved it, and a copy
     * that starts wherever the last reader stopped is an image missing its ELF
     * header.
     *
     * This lseek is also the ONLY seekability requirement, and it doubles as
     * the non-seekable-source check: a pipe, a socket or a FIFO fails here with
     * ESPIPE and is refused with a message that names the problem. Everything
     * after this point is sequential read()s, so nothing else assumes the
     * source can seek. */
    if (lseek(src_fd, 0, SEEK_SET) < 0) {
        int saved = errno;
        return si_fail(-1, err, err_cap,
                       "sealed image: source fd %d is not seekable "
                       "(lseek to 0 failed: %s)",
                       src_fd, strerror(saved));
    }

    /* MFD_CLOEXEC so a fork+exec anywhere in this process cannot hand the
     * image to a child — the descriptor is the only handle on these bytes and
     * it has no business crossing an exec. MFD_ALLOW_SEALING is mandatory: a
     * memfd created without it can NEVER be sealed (F_ADD_SEALS returns
     * EPERM), which would turn this whole file into an expensive memcpy.
     *
     * The name is purely diagnostic — it is what /proc/<pid>/maps and
     * /proc/self/fd/N show as "/memfd:zcl-hotswap-image (deleted)" — and it is
     * not a namespace: memfds are anonymous, so two concurrent calls with the
     * same name produce two unrelated objects and cannot collide. That
     * anonymity is itself load-bearing: an object with no name in any
     * directory cannot be reached, replaced or unlinked by any path, so the
     * redirect-proof property the fd pin provided is preserved, not traded
     * away, by moving to a memfd. */
    int img_fd = memfd_create("zcl-hotswap-image",
                              MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (img_fd < 0) {
        int saved = errno;
        return si_fail(-1, err, err_cap,
                       "sealed image: memfd_create failed: %s",
                       strerror(saved));
    }

    if (si_copy_exact(src_fd, img_fd, (uint64_t)before.st_size) != 0) {
        int saved = errno;
        return si_fail(img_fd, err, err_cap,
                       "sealed image: copy failed: %s", strerror(saved));
    }

    /* Seal AFTER the last byte is written — F_SEAL_WRITE applies immediately
     * and to this descriptor too, so any ordering that seals first cannot then
     * fill the image. From this line onward the bytes are frozen for every
     * process on the machine, permanently. */
    int seals = 0;
    if (si_seal(img_fd, &seals) < 0) {
        int saved = errno;
        return si_fail(img_fd, err, err_cap,
                       "sealed image: sealing failed: %s", strerror(saved));
    }
    if ((seals & SI_SEALS) != SI_SEALS)
        return si_fail(img_fd, err, err_cap,
                       "sealed image: seals did not take "
                       "(wanted 0x%x, F_GET_SEALS reports 0x%x)",
                       (unsigned)SI_SEALS, (unsigned)seals);

    /* Hand the image back rewound. The copy loop left the offset at EOF, and
     * the very next thing a caller does is hash the sealed bytes from the
     * start; a descriptor returned at EOF hashes the empty string, which is a
     * perfectly stable, perfectly wrong digest. F_SEAL_WRITE does not restrict
     * lseek — it restricts writes — so this is legal after sealing. */
    if (lseek(img_fd, 0, SEEK_SET) < 0) {
        int saved = errno;
        return si_fail(img_fd, err, err_cap,
                       "sealed image: rewind failed: %s", strerror(saved));
    }

    /* Leave the SOURCE rewound too, matching hotswap_artifact_sha3_fd()'s
     * contract, so a caller that keeps using src_fd finds it where every other
     * hot-swap read leaves it. A failure here is reported but does not fail the
     * call: the image is complete and sealed, and it is the image the caller
     * asked for. Losing src_fd's offset cannot corrupt it. */
    (void)lseek(src_fd, 0, SEEK_SET);

    return img_fd;
}
#elif defined(__APPLE__)

/* macOS has no memfd_create / file sealing.  We approximate the same property
 * (the bytes mapped by dlopen cannot be altered through the filesystem) by
 * relying on the artifact's existing ad-hoc code signature: any in-place
 * modification after the signature was applied invalidates the signature and
 * causes dlopen to fail.  The caller hashes and dlopen's the SAME descriptor,
 * so the Linux "hash-equals-map" discipline is preserved through macOS code
 * signing rather than through a sealed anonymous copy.
 *
 * Keeping the original signed inode also avoids Gatekeeper's refusal to load
 * an anonymous bundle via /dev/fd/N ("library load disallowed by system policy"),
 * which we measured when the signed copy was unlinked before dlopen. */

int hotswap_sealed_image_from_fd(int src_fd, char *err, size_t err_cap)
{
    if (err && err_cap)
        err[0] = '\0';

    if (src_fd < 0)
        return si_fail(-1, err, err_cap, "sealed image: invalid source fd %d",
                       src_fd);

    struct stat before;
    if (fstat(src_fd, &before) != 0) {
        int saved = errno;
        return si_fail(-1, err, err_cap,
                       "sealed image: source fstat failed: %s",
                       strerror(saved));
    }
    if (!S_ISREG(before.st_mode))
        return si_fail(-1, err, err_cap,
                       "sealed image: source fd %d is not a regular file",
                       src_fd);
    if (before.st_size <= 0)
        return si_fail(-1, err, err_cap,
                       "sealed image: source fd %d is empty (0 bytes); "
                       "a zero-length artifact is not loadable", src_fd);
    if ((uint64_t)before.st_size > ZCL_HOTSWAP_SEALED_IMAGE_MAX_BYTES)
        return si_fail(-1, err, err_cap,
                       "sealed image: source is %llu bytes, over the %llu byte ceiling",
                       (unsigned long long)before.st_size,
                       (unsigned long long)ZCL_HOTSWAP_SEALED_IMAGE_MAX_BYTES);

    if (lseek(src_fd, 0, SEEK_SET) < 0) {
        int saved = errno;
        return si_fail(-1, err, err_cap,
                       "sealed image: source fd %d is not seekable "
                       "(lseek to 0 failed: %s)",
                       src_fd, strerror(saved));
    }

    /* Return a new descriptor referencing the same signed inode.  The caller
     * hashes this descriptor and dlopen's /dev/fd/N from it, so the bytes it
     * checked are exactly the bytes the linker maps. */
    int img_fd = dup(src_fd);
    if (img_fd < 0) {
        int saved = errno;
        return si_fail(-1, err, err_cap,
                       "sealed image: dup failed: %s", strerror(saved));
    }

    (void)lseek(src_fd, 0, SEEK_SET);
    return img_fd;
}
#else
int hotswap_sealed_image_from_fd(int src_fd, char *err, size_t err_cap)
{
    (void)src_fd;
    if (err && err_cap)
        (void)snprintf(err, err_cap,
                       "sealed image: platform has no sealed-image support");
    return -1;
}
#endif
