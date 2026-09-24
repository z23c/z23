/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Report a script's device and inode for the broker cutover fixture.
 */
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    struct stat st;
    if (argc != 2 || stat(argv[1], &st) != 0)
        return 1;
    if (printf("%" PRIuMAX ":%" PRIuMAX "\n",
               (uintmax_t)st.st_dev, (uintmax_t)st.st_ino) < 0)
        return 1;
    return 0;
}
