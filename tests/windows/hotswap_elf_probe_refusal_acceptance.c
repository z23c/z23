/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "hotswap/hotswap_elf_probe.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    struct hotswap_elf_facts facts;
    memset(&facts, 0xa5, sizeof(facts));
    char err[192] = {0};
    if (hotswap_elf_probe_fd(7, &facts, err, sizeof(err)) ||
        memcmp(&facts, &(struct hotswap_elf_facts){0}, sizeof(facts)) != 0 ||
        strstr(err, "PE import validator") == NULL)
        return 1;
    puts("hotswap_elf_probe_refusal_acceptance: PASS");
    return 0;
}
