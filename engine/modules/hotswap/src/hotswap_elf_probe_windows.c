/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Native Windows refuses ELF admission until PE validation is qualified. */
#include "hotswap/hotswap_elf_probe.h"
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
bool hotswap_elf_probe_fd(int fd, struct hotswap_elf_facts *out,
                          char *err, size_t err_cap)
{
    (void)fd;
    if (out)
        memset(out, 0, sizeof(*out));
    if (err && err_cap > 0)
        (void)snprintf(err, err_cap,
                      "ELF probing is unavailable on native Windows; PE "
                      "admission requires a qualified PE import validator");
    return false;
}
#endif
