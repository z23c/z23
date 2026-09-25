/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * os_sandbox — the Linux Landlock ruleset builder. It turns a
 * struct os_sandbox_landlock_policy into a ruleset fd that handles EVERY
 * filesystem right the running kernel's ABI knows, plus TCP bind/connect
 * when asked, then hands the fd to os_sandbox_linux.c, which enters it and
 * publishes the confinement witness.
 *
 * Why every right: Landlock ALLOWS any right a ruleset does not handle. A
 * builder that handled only read/write/read-dir let a confined child make
 * symlinks, FIFOs, sockets and device nodes, and truncate files, anywhere
 * the uid could write. The grant mapping is documented on
 * struct os_sandbox_path_rule in platform/os_sandbox.h.
 *
 * Compiled only on Linux (the Makefile filter-outs pair this file with
 * os_sandbox_linux.c); the portable stub carries the same entry points. */

#define _GNU_SOURCE

#include "platform/os_sandbox.h"
#include "os_sandbox_landlock_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#if defined(__has_include)
#  if __has_include(<linux/landlock.h>)
#    define ZCL_HAVE_LANDLOCK 1
#    include <linux/landlock.h>
#  endif
#endif

#ifdef ZCL_HAVE_LANDLOCK

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif

/* Rights newer than the build host's header. The values are kernel ABI and
 * never change; the runtime ABI probe decides whether they are handled. */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)      /* ABI 2 */
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)   /* ABI 3 */
#endif
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)  /* ABI 5 */
#endif
#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)   /* ABI 4 */
#endif
#ifndef LANDLOCK_ACCESS_NET_CONNECT_TCP
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

/* Kernel ABI layouts spelled locally, so an older <linux/landlock.h> that
 * lacks handled_access_net or LANDLOCK_RULE_NET_PORT still builds. */
struct ll_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;  /* ABI 4 */
};
struct ll_net_port_attr {
    uint64_t allowed_access;
    uint64_t port;                /* host byte order */
};
#define LL_RULE_NET_PORT 2

#define LL_FS_READ (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
#define LL_FS_WRITE (LANDLOCK_ACCESS_FS_WRITE_FILE | \
                     LANDLOCK_ACCESS_FS_TRUNCATE | \
                     LANDLOCK_ACCESS_FS_IOCTL_DEV)
#define LL_FS_CREATE (LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR | \
                      LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_MAKE_FIFO | \
                      LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_CHAR | \
                      LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
                      LANDLOCK_ACCESS_FS_REMOVE_FILE | \
                      LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REFER)
/* The rights the kernel accepts on a rule whose path is not a directory. */
#define LL_FS_ON_FILE (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | \
                       LL_FS_WRITE)
#define LL_FS_ABI1 (LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | \
                    LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | \
                    LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE | \
                    LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR | \
                    LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | \
                    LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
                    LANDLOCK_ACCESS_FS_MAKE_SYM)
#define LL_NET_TCP (LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)

/* Every filesystem right this ABI can enforce. ABI 6 and 7 add scopes and
 * logging, not filesystem rights, so ABI 5 is the top of this table. */
static uint64_t ll_fs_handled_for_abi(int abi)
{
    uint64_t handled = LL_FS_ABI1;
    if (abi >= 2) handled |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) handled |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) handled |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    return handled;
}

/* The two compatibility implications documented on os_sandbox_path_rule. */
struct ll_implied {
    bool exec_from_read;
    bool create_from_write;
};

static struct ll_implied ll_implied_for(const struct os_sandbox_path_rule *rules,
                                        size_t n_rules)
{
    struct ll_implied implied = { .exec_from_read = true,
                                  .create_from_write = true };
    for (size_t i = 0; i < n_rules; i++) {
        if (rules[i].allow_execute) implied.exec_from_read = false;
        if (rules[i].allow_create) implied.create_from_write = false;
    }
    return implied;
}

static uint64_t ll_rule_access(const struct os_sandbox_path_rule *r,
                               struct ll_implied implied, bool is_dir,
                               uint64_t handled)
{
    uint64_t allow = 0;
    if (r->allow_read)
        allow |= LL_FS_READ |
                 (implied.exec_from_read ? LANDLOCK_ACCESS_FS_EXECUTE : 0);
    if (r->allow_execute) allow |= LANDLOCK_ACCESS_FS_EXECUTE;
    if (r->allow_write)
        allow |= LL_FS_WRITE | (implied.create_from_write ? LL_FS_CREATE : 0);
    if (r->allow_create) allow |= LL_FS_CREATE;
    if (!is_dir) allow &= LL_FS_ON_FILE;
    return allow & handled;
}

static struct zcl_result ll_add_path_rule(int ruleset_fd, size_t index,
                                          const struct os_sandbox_path_rule *r,
                                          struct ll_implied implied,
                                          uint64_t handled)
{
    if (r->path == NULL)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                       "path rule %zu has NULL path", index);
    int path_fd = open(r->path, O_PATH | O_CLOEXEC);
    if (path_fd < 0)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                       "open(O_PATH) %s failed errno=%d (%s)",
                       r->path, errno, strerror(errno));
    struct stat st;
    if (fstat(path_fd, &st) != 0) {
        int e = errno;
        close(path_fd);
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                       "fstat %s failed errno=%d (%s)", r->path, e, strerror(e));
    }
    struct landlock_path_beneath_attr pb = {
        .allowed_access = ll_rule_access(r, implied, S_ISDIR(st.st_mode),
                                         handled),
        .parent_fd = path_fd,
    };
    int rc = (int)syscall(__NR_landlock_add_rule, ruleset_fd,
                          LANDLOCK_RULE_PATH_BENEATH, &pb, 0);
    int e = errno;
    close(path_fd);
    if (rc != 0)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                       "landlock_add_rule %s failed errno=%d (%s)",
                       r->path, e, strerror(e));
    return ZCL_OK;
}

static struct zcl_result ll_add_rules(int ruleset_fd,
                                      const struct os_sandbox_landlock_policy *p,
                                      uint64_t handled)
{
    struct ll_implied implied = ll_implied_for(p->fs_rules, p->n_fs_rules);
    for (size_t i = 0; i < p->n_fs_rules; i++)
        ZCL_CHECK(ll_add_path_rule(ruleset_fd, i, &p->fs_rules[i], implied,
                                   handled));
    for (size_t i = 0; i < p->n_tcp_rules; i++) {
        const struct os_sandbox_tcp_port_rule *t = &p->tcp_rules[i];
        struct ll_net_port_attr np = {
            .allowed_access =
                (t->allow_bind ? LANDLOCK_ACCESS_NET_BIND_TCP : 0) |
                (t->allow_connect ? LANDLOCK_ACCESS_NET_CONNECT_TCP : 0),
            .port = t->port,
        };
        if (syscall(__NR_landlock_add_rule, ruleset_fd, LL_RULE_NET_PORT, &np,
                    0) != 0)
            return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                           "landlock_add_rule tcp port %u failed errno=%d (%s)",
                           (unsigned)t->port, errno, strerror(errno));
    }
    return ZCL_OK;
}
#endif /* ZCL_HAVE_LANDLOCK */

/* Shape checks that hold on every kernel, so a malformed policy is refused
 * the same way whether or not this host can enforce it. */
static struct zcl_result ll_policy_validate(
    const struct os_sandbox_landlock_policy *p)
{
    if (p == NULL)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG, "policy==NULL");
    if (p->n_fs_rules > 0 && p->fs_rules == NULL)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG, "n_rules>0 but rules==NULL");
    if (p->n_tcp_rules > 0 && p->tcp_rules == NULL)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                       "n_tcp_rules>0 but tcp_rules==NULL");
    if (p->n_tcp_rules > 0 && !p->restrict_tcp)
        return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                       "tcp port rules without restrict_tcp would leave every "
                       "port open");
    for (size_t i = 0; i < p->n_tcp_rules; i++)
        if (!p->tcp_rules[i].allow_bind && !p->tcp_rules[i].allow_connect)
            return ZCL_ERR(OS_SANDBOX_ERR_INVALID_ARG,
                           "tcp port rule %zu grants neither bind nor connect",
                           i);
    return ZCL_OK;
}

bool os_sandbox_landlock_tcp_supported(void)
{
    return os_sandbox_landlock_abi() >= 4;
}

struct zcl_result os_sandbox_landlock_restrict_policy(
    const struct os_sandbox_landlock_policy *p)
{
    ZCL_CHECK(ll_policy_validate(p));
    int abi = os_sandbox_landlock_abi();
    if (p->restrict_tcp && abi < 4)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_NET_UNAVAILABLE,
                       "TCP port rules need Landlock ABI >= 4 (running ABI %d); "
                       "nothing was applied", abi);
#ifndef ZCL_HAVE_LANDLOCK
    return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE,
                   "Landlock headers absent at build time");
#else
    if (abi < 1)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_UNAVAILABLE,
                       "Landlock unavailable on this kernel (ABI probe failed)");
    struct ll_ruleset_attr attr = {
        .handled_access_fs = ll_fs_handled_for_abi(abi),
        .handled_access_net = p->restrict_tcp ? LL_NET_TCP : 0,
    };
    /* A pre-ABI-4 kernel rejects a larger attr only when the extra field is
     * nonzero, but pass the size it knows so the call never depends on it. */
    size_t attr_size = abi >= 4 ? sizeof(attr) : sizeof(attr.handled_access_fs);
    int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &attr,
                                  attr_size, 0);
    if (ruleset_fd < 0)
        return ZCL_ERR(OS_SANDBOX_ERR_LANDLOCK_SYSCALL,
                       "landlock_create_ruleset failed errno=%d (%s)",
                       errno, strerror(errno));
    struct zcl_result added = ll_add_rules(ruleset_fd, p,
                                           attr.handled_access_fs);
    if (!added.ok) {
        close(ruleset_fd);
        return added;
    }
    return os_sandbox_landlock_enforce_ruleset(ruleset_fd, abi, p->fs_rules,
                                               p->n_fs_rules);
#endif
}

struct zcl_result os_sandbox_landlock_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules)
{
    struct os_sandbox_landlock_policy policy = {
        .fs_rules = rules,
        .n_fs_rules = n_rules,
    };
    return os_sandbox_landlock_restrict_policy(&policy);
}
