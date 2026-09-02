/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Linux package-confinement selection over the Landlock backend. */

#include "platform/os_sandbox.h"

enum os_sandbox_package_confinement
os_sandbox_package_confinement(void)
{
    return os_sandbox_landlock_abi() >= 1
        ? OS_SANDBOX_PACKAGE_CONFINEMENT_LANDLOCK_SECCOMP
        : OS_SANDBOX_PACKAGE_CONFINEMENT_NONE;
}

const char *os_sandbox_package_confinement_name(
    enum os_sandbox_package_confinement confinement)
{
    switch (confinement) {
    case OS_SANDBOX_PACKAGE_CONFINEMENT_LANDLOCK_SECCOMP:
        return "landlock+seccomp";
    case OS_SANDBOX_PACKAGE_CONFINEMENT_SEATBELT:
        return "seatbelt";
    case OS_SANDBOX_PACKAGE_CONFINEMENT_NONE:
    default:
        return "none";
    }
}

struct zcl_result os_sandbox_package_restrict(
    const struct os_sandbox_path_rule *rules, size_t n_rules)
{
    if (os_sandbox_package_confinement() ==
        OS_SANDBOX_PACKAGE_CONFINEMENT_NONE)
        return ZCL_ERR(OS_SANDBOX_ERR_CONFINEMENT_UNAVAILABLE,
                       "package confinement is unavailable");
    return os_sandbox_landlock_restrict(rules, n_rules);
}
