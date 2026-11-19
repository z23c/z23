/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 *
 * peer_chain_recovery_unlink_fault — LD_PRELOAD unlink fault for proving that
 * a successful no-replace publication stays successful when temporary cleanup
 * fails. Only the exact path named by ZCL_TEST_PEER_RECOVERY_UNLINK is refused. */

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

int unlink(const char *path)
{
    typedef int (*unlink_fn)(const char *);
    unlink_fn real_unlink = NULL;
    void *symbol = dlsym(RTLD_NEXT, "unlink");
    memcpy(&real_unlink, &symbol, sizeof real_unlink);
    if (!real_unlink) {
        errno = ENOSYS;
        return -1;
    }
    const char *fault = getenv("ZCL_TEST_PEER_RECOVERY_UNLINK");
    if (fault && strcmp(fault, path) == 0) {
        errno = EACCES;
        return -1;
    }
    return real_unlink(path);
}
