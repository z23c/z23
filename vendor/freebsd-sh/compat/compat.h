/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * glibc compatibility shim for the vendored FreeBSD /bin/sh sources under
 * vendor/freebsd-sh. The Makefile force-includes this header ahead of every
 * upstream translation unit (-include compat/compat.h) so the upstream
 * files stay byte-identical to FreeBSD releng/14.2. Everything here fills
 * a gap that FreeBSD libc supplies and glibc does not; nothing here
 * changes shell semantics. Provenance: vendor/freebsd-sh/SOURCE. */

#ifndef ZCL_VENDOR_FREEBSD_SH_COMPAT_H
#define ZCL_VENDOR_FREEBSD_SH_COMPAT_H

/* _GNU_SOURCE must precede every system header: eaccess (bin/test/test.c),
 * stpcpy (bin/sh/mystring.c), O_CLOEXEC (bin/sh/jobs.c), and the _PATH_*
 * macros (paths.h) all sit behind it or _DEFAULT_SOURCE on glibc. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <paths.h>

/* FreeBSD <sys/cdefs.h> macros the upstream sources use. glibc's
 * sys/cdefs.h already defines __unused; the rest are FreeBSD-only. */
#ifndef __dead2
#define __dead2 __attribute__((__noreturn__))
#endif
#ifndef __unused
#define __unused __attribute__((__unused__))
#endif
#ifndef __printflike
#define __printflike(fmtarg, firstvararg) \
	__attribute__((__format__(__printf__, fmtarg, firstvararg)))
#endif
#ifndef __printf0like
#define __printf0like(fmtarg, firstvararg) \
	__attribute__((__format__(__printf__, fmtarg, firstvararg)))
#endif
#ifndef __DECONST
#define __DECONST(type, var) ((type)(uintptr_t)(const void *)(var))
#endif

/* FreeBSD <paths.h> default PATH for shells. glibc paths.h has
 * _PATH_DEFPATH but no _PATH_STDPATH (bin/sh/eval.c). */
#ifndef _PATH_STDPATH
#define _PATH_STDPATH "/usr/bin:/bin:/usr/sbin:/sbin"
#endif

/* O_VERIFY is a FreeBSD open(2) flag requesting kernel signature
 * verification of the opened file (bin/sh/input.c uses it for script
 * files). Linux has no equivalent open-time verification; opening
 * without the flag is the only available behavior, so define it away. */
#include <fcntl.h>
#ifndef O_VERIFY
#define O_VERIFY 0
#endif

/* FreeBSD <sys/param.h> ALIGN() (bin/sh/memalloc.c): round up to machine
 * pointer alignment. glibc sys/param.h does not define it. */
#ifndef ALIGN
#define ALIGN(x) \
	(((uintptr_t)(x) + (sizeof(void *) - 1)) & ~(uintptr_t)(sizeof(void *) - 1))
#endif

/* FreeBSD <sys/param.h> MAXLOGNAME (bin/sh/parser.c): max login name
 * length including the terminating NUL; 33 on releng/14.2. */
#ifndef MAXLOGNAME
#define MAXLOGNAME 33
#endif

/* strlcpy landed in glibc 2.38. Rename the shell's calls to our compat
 * symbol so the build is identical on older glibc and on libcs that
 * already provide the name; the macro also rewrites any later libc
 * declaration, keeping prototype and definition consistent. */
#define strlcpy fbsh_strlcpy
size_t fbsh_strlcpy(char *dst, const char *src, size_t siz);

/* setmode(3)/getmode(3): BSD-only, used by the umask builtin
 * (bin/sh/miscbltin.c). Implemented in compat.c. */
void *setmode(const char *p);
mode_t getmode(const void *set, mode_t mode);

/* fwopen(3) is a BSD funopen-family helper (bin/sh/output.c). glibc's
 * fopencookie(3) is the same mechanism with a ssize_t write callback;
 * compat.c adapts the BSD signature onto it. */
#include <stdio.h>
#define fwopen fbsh_fwopen
FILE *fbsh_fwopen(void *cookie, int (*writefn)(void *, const char *, int));

/* BSD libc exports sys_signame[] / sys_nsig (bin/kill/kill.c,
 * bin/sh/trap.c). glibc exports neither since 2.32; compat.c supplies a
 * canonical Linux table. Renamed like strlcpy so a libc that does
 * provide them cannot clash. */
#include <signal.h>
#define sys_signame fbsh_sys_signame
extern const char *const fbsh_sys_signame[];
#define sys_nsig fbsh_sys_nsig
extern const int fbsh_sys_nsig;

#endif /* ZCL_VENDOR_FREEBSD_SH_COMPAT_H */
