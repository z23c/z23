/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Implementations backing compat.h for the vendored FreeBSD /bin/sh.
 * strlcpy is the well-known bounded copy; setmode/getmode implement the
 * POSIX symbolic-mode grammar (clause[,clause]... with
 * clause = [ugoa]* ([+-=] [rwxXstugo]*)+) for the umask builtin. Semantics
 * follow chmod(1)/POSIX.1: an omitted who selects ugo masked by the
 * process umask, 'X' sets execute only when some execute bit is already
 * set or the mode is a directory, and the copy letters u/g/o copy the
 * current rwx triplet of that class. Every allocation is checked. */

#include "compat.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__APPLE__)

int
fbsh_eaccess(const char *path, int mode)
{
	return faccessat(AT_FDCWD, path, mode, AT_EACCESS);
}

#elif defined(__linux__)

size_t
fbsh_strlcpy(char *dst, const char *src, size_t siz)
{
	size_t srclen = strlen(src);

	if (siz > 0) {
		size_t n = srclen < siz - 1 ? srclen : siz - 1;
		memcpy(dst, src, n);
		dst[n] = '\0';
	}
	return srclen;
}

/* ── sys_signame / sys_nsig ───────────────────────────────────────────
 * Canonical Linux signal-name table, lowercase and without the "SIG"
 * prefix, exactly the shape BSD sys_signame[] has (trap.c probes for
 * NULL entries, so unused numbers stay NULL). Standard signals are
 * designated-initialized by macro so the numbering is correct by
 * construction; the real-time range is positional because glibc's
 * SIGRTMIN/SIGRTMAX are runtime function calls, not constants. */
_Static_assert(NSIG == 65, "fbsh compat signal table assumes Linux NSIG 65");

const char *const fbsh_sys_signame[NSIG] = {
	[0] = NULL,
	[SIGHUP] = "hup",	[SIGINT] = "int",	[SIGQUIT] = "quit",
	[SIGILL] = "ill",	[SIGTRAP] = "trap",	[SIGABRT] = "abrt",
	[SIGBUS] = "bus",	[SIGFPE] = "fpe",	[SIGKILL] = "kill",
	[SIGUSR1] = "usr1",	[SIGSEGV] = "segv",	[SIGUSR2] = "usr2",
	[SIGPIPE] = "pipe",	[SIGALRM] = "alrm",	[SIGTERM] = "term",
	[SIGSTKFLT] = "stkflt",	[SIGCHLD] = "chld",	[SIGCONT] = "cont",
	[SIGSTOP] = "stop",	[SIGTSTP] = "tstp",	[SIGTTIN] = "ttin",
	[SIGTTOU] = "ttou",	[SIGURG] = "urg",	[SIGXCPU] = "xcpu",
	[SIGXFSZ] = "xfsz",	[SIGVTALRM] = "vtalrm",	[SIGPROF] = "prof",
	[SIGWINCH] = "winch",	[SIGIO] = "io",		[SIGPWR] = "pwr",
	[SIGSYS] = "sys",
	/* 32 and 33 are glibc-internal (NPTL); 34..64 are the RT range. */
	[34] = "rtmin",		[35] = "rtmin+1",	[36] = "rtmin+2",
	[37] = "rtmin+3",	[38] = "rtmin+4",	[39] = "rtmin+5",
	[40] = "rtmin+6",	[41] = "rtmin+7",	[42] = "rtmin+8",
	[43] = "rtmin+9",	[44] = "rtmin+10",	[45] = "rtmin+11",
	[46] = "rtmin+12",	[47] = "rtmin+13",	[48] = "rtmin+14",
	[49] = "rtmin+15",	[50] = "rtmin+16",	[51] = "rtmin+17",
	[52] = "rtmin+18",	[53] = "rtmin+19",	[54] = "rtmin+20",
	[55] = "rtmin+21",	[56] = "rtmin+22",	[57] = "rtmin+23",
	[58] = "rtmin+24",	[59] = "rtmin+25",	[60] = "rtmin+26",
	[61] = "rtmin+27",	[62] = "rtmin+28",	[63] = "rtmin+29",
	[64] = "rtmax",
};

const int fbsh_sys_nsig = NSIG;

/* ── fwopen via fopencookie ─────────────────────────────────────────── */

struct fbsh_fwopen_ctx {
	void *cookie;
	int (*writefn)(void *, const char *, int);
};

static ssize_t
fbsh_fwopen_write(void *c, const char *buf, size_t n)
{
	struct fbsh_fwopen_ctx *ctx = c;

	return ctx->writefn(ctx->cookie, buf, (int)n);
}

static int
fbsh_fwopen_close(void *c)
{
	free(c);
	return 0;
}

FILE *
fbsh_fwopen(void *cookie, int (*writefn)(void *, const char *, int))
{
	static const cookie_io_functions_t io = {
		.read = NULL,
		.write = fbsh_fwopen_write,
		.seek = NULL,
		.close = fbsh_fwopen_close,
	};
	struct fbsh_fwopen_ctx *ctx = malloc(sizeof(*ctx));
	FILE *fp;

	if (ctx == NULL)
		return NULL;
	ctx->cookie = cookie;
	ctx->writefn = writefn;
	fp = fopencookie(ctx, "w", io);
	if (fp == NULL) {
		int saved = errno;
		free(ctx);
		errno = saved;
		return NULL;
	}
	return fp;
}

/* ── setmode / getmode ──────────────────────────────────────────────── */

struct fbsh_mode_op {
	mode_t who;	/* S_IRWXU | S_IRWXG | S_IRWXO subset; 0 = omitted */
	int op;		/* '+', '-', '=' */
	mode_t perms;	/* rwx in canonical positions, S_ISUID/S_ISGID/S_ISVTX */
	int perm_x;	/* permlist contained 'X' */
	int copy;	/* 0, or 'u' / 'g' / 'o' */
};

struct fbsh_mode_set {
	size_t nops;
	struct fbsh_mode_op ops[];
};

static mode_t
fbsh_class_rwx(mode_t who)
{
	return who;	/* who is already the union of the class rwx masks */
}

/* Map the rwx triplet of class `copy` ('u'/'g'/'o') of `mode` onto every
 * class selected by `who`. */
static mode_t
fbsh_copy_perms(mode_t mode, int copy, mode_t who)
{
	unsigned shift = copy == 'u' ? 6 : copy == 'g' ? 3 : 0;
	mode_t triplet = (mode >> shift) & 07;
	mode_t out = 0;

	if (who & S_IRWXU)
		out |= triplet << 6;
	if (who & S_IRWXG)
		out |= triplet << 3;
	if (who & S_IRWXO)
		out |= triplet;
	return out;
}

static int
fbsh_parse_perms(struct fbsh_mode_op *op, const char **pp)
{
	const char *p = *pp;
	/* An omitted who acts as 'a' here; getmode() applies the process
	 * umask to the result, exactly as chmod(1) does. */
	const mode_t who = op->who ? op->who : (S_IRWXU | S_IRWXG | S_IRWXO);
	int seen = 0;

	for (;; p++) {
		mode_t bit_u, bit_g, bit_o;
		switch (*p) {
		case 'r': bit_u = S_IRUSR; bit_g = S_IRGRP; bit_o = S_IROTH; break;
		case 'w': bit_u = S_IWUSR; bit_g = S_IWGRP; bit_o = S_IWOTH; break;
		case 'x': bit_u = S_IXUSR; bit_g = S_IXGRP; bit_o = S_IXOTH; break;
		case 'X':
			op->perm_x = 1;
			seen = 1;
			continue;
		case 's':
			if (who & S_IRWXU)
				op->perms |= S_ISUID;
			if (who & S_IRWXG)
				op->perms |= S_ISGID;
			seen = 1;
			continue;
		case 't':
			op->perms |= S_ISVTX;
			seen = 1;
			continue;
		case 'u': case 'g': case 'o':
			op->copy = *p;
			seen = 1;
			continue;
		default:
			*pp = p;
			return seen;
		}
		seen = 1;
		if (who & S_IRWXU)
			op->perms |= bit_u;
		if (who & S_IRWXG)
			op->perms |= bit_g;
		if (who & S_IRWXO)
			op->perms |= bit_o;
	}
}

void *
setmode(const char *p)
{
	struct fbsh_mode_set *set = NULL;
	size_t nops = 0, cap = 0;

	if (p == NULL || *p == '\0') {
		errno = EINVAL;
		return NULL;
	}
	for (;;) {
		struct fbsh_mode_op op;
		int have_action = 0;

		memset(&op, 0, sizeof(op));
		for (;; p++) {		/* who list */
			switch (*p) {
			case 'u': op.who |= S_IRWXU; continue;
			case 'g': op.who |= S_IRWXG; continue;
			case 'o': op.who |= S_IRWXO; continue;
			case 'a': op.who |= S_IRWXU | S_IRWXG | S_IRWXO; continue;
			default: goto who_done;
			}
		}
who_done:
		/* One clause is one or more (op, permlist) pairs. Each pair
		 * gets its own op record; the who applies to all of them. */
		for (;;) {
			struct fbsh_mode_op pair = op;

			if (*p != '+' && *p != '-' && *p != '=')
				break;
			pair.op = *p++;
			if (!fbsh_parse_perms(&pair, &p)) {
				/* op with empty permlist is legal (clears) */
			}
			if (nops == cap) {
				size_t ncap = cap == 0 ? 8 : cap * 2;
				struct fbsh_mode_set *nset = realloc(set,
				    sizeof(*set) + ncap * sizeof(*set->ops));
				if (nset == NULL) {
					free(set);
					errno = ENOMEM;
					return NULL;
				}
				set = nset;
				cap = ncap;
			}
			set->ops[nops++] = pair;
			have_action = 1;
		}
		if (!have_action) {
			free(set);
			errno = EINVAL;
			return NULL;
		}
		if (*p == '\0')
			break;
		if (*p != ',') {
			free(set);
			errno = EINVAL;
			return NULL;
		}
		p++;
	}
	set->nops = nops;
	return set;
}

mode_t
getmode(const void *setp, mode_t mode)
{
	const struct fbsh_mode_set *set = setp;
	mode_t omask = 0;
	int omask_known = 0;

	for (size_t i = 0; i < set->nops; i++) {
		const struct fbsh_mode_op *op = &set->ops[i];
		mode_t who = op->who;
		mode_t perm = op->perms;

		if (who == 0) {
			who = S_IRWXU | S_IRWXG | S_IRWXO;
			if (!omask_known) {
				omask = (mode_t)umask(0);
				(void)umask(omask);
				omask_known = 1;
			}
		}
		if (op->copy)
			perm |= fbsh_copy_perms(mode, op->copy, who);
		if (op->perm_x &&
		    (S_ISDIR(mode) || (mode & (S_IXUSR | S_IXGRP | S_IXOTH))))
			perm |= fbsh_copy_perms(0111, 'u', who);

		/* Confine rwx changes to the selected classes; special bits
		 * were already class-qualified at parse time. */
		perm &= fbsh_class_rwx(who) | S_ISUID | S_ISGID | S_ISVTX;
		if (op->who == 0)
			perm &= ~omask;

		switch (op->op) {
		case '+':
			mode |= perm;
			break;
		case '-':
			mode &= ~perm;
			break;
		case '=':
		default: {
			mode_t clear = fbsh_class_rwx(who);
			if (who & S_IRWXU)
				clear |= S_ISUID;
			if (who & S_IRWXG)
				clear |= S_ISGID;
			if (who & S_IRWXO)
				clear |= S_ISVTX;
			if (op->who == 0)
				clear &= ~omask | S_ISUID | S_ISGID | S_ISVTX;
			mode = (mode & ~clear) | perm;
			break;
		}
		}
	}
	return mode;
}

#elif !defined(__APPLE__)
#error "fbsh compat requires either Linux shims or Darwin BSD libc"
#endif
