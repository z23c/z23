/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef __APPLE__
static int mode, calls, memory_reads;
static ssize_t real_pread(int fd, void *buf, size_t count, off_t offset)
{
    return pread(fd, buf, count, offset);
}
static ssize_t fake_pread(int fd, void *buf, size_t count, off_t offset)
{
    if (mode == 1) { errno = EIO; return -1; }
    if (mode == 2 && calls++ == 0) { errno = EINTR; return -1; }
    if (mode == 3 && count > 100) count = 100;
    if (mode == 4) { errno = EINVAL; return -1; }
    if (mode == 5 && calls++ == 0) { errno = EIO; return -1; }
    if (mode == 6) {
        if (calls++ == 0) { errno = EIO; return -1; }
        if (count > 100) count = 100;
    }
    if (mode == 7) {
        if (calls++ == 0) return real_pread(fd, buf, count, offset);
        errno = EIO;
        return -1;
    }
    if (mode >= 8) ++memory_reads;
    return real_pread(fd, buf, count, offset);
}
static char *real_fgets(char *text, int cap, FILE *file)
{
    return fgets(text, cap, file);
}
static char *fake_fgets(char *text, int cap, FILE *file)
{
    if (mode == 8 && memory_reads > 0) {
        (void)fputc(0, file);
        return NULL;
    }
    if (mode == 9 && memory_reads > 0 && calls++ == 0) {
        memcpy(text, "1bad mapping\n", sizeof("1bad mapping\n"));
        return text;
    }
    if (mode == 11 && memory_reads > 0 && calls++ == 0) {
        memcpy(text, "1bad- mapping\n", sizeof("1bad- mapping\n"));
        return text;
    }
    if (mode == 10 && memory_reads > 0 && calls++ == 0) {
        memcpy(text, "AnonExtra: 4 kB\n", sizeof("AnonExtra: 4 kB\n"));
        return text;
    }
    return real_fgets(text, cap, file);
}
#define pread fake_pread
#define fgets fake_fgets
#endif
#ifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
static mach_vm_address_t fixture_address;
static int region_mode, region_calls;
static kern_return_t test_region(vm_map_read_t task, mach_vm_address_t *address, mach_vm_size_t *size,
                                 vm_region_flavor_t flavor, vm_region_info_t info,
                                 mach_msg_type_number_t *count, mach_port_t *object)
{
    if (!region_mode) return mach_vm_region(task, address, size, flavor, info, count, object);
    if (region_calls++) return region_mode == 2 ? KERN_FAILURE : KERN_INVALID_ADDRESS;
    *address = fixture_address;
    *size = region_mode == 3 ? 0 : (region_mode == 4 ? UINT64_MAX : 16384);
    *object = MACH_PORT_NULL;
    vm_region_extended_info_data_t *entry = (void *)info;
    memset(entry, 0, sizeof(*entry));
    entry->protection = VM_PROT_READ | VM_PROT_WRITE;
    return KERN_SUCCESS;
}
#define mach_vm_region test_region
#endif
#include "residue.h"
#ifdef __APPLE__
#undef mach_vm_region
#endif
#ifndef __APPLE__
#undef pread
#undef fgets
#endif

#ifdef __APPLE__
static void region_enumeration_cases(void)
{
    assert(mach_vm_allocate(mach_task_self(), &fixture_address, 16384, VM_FLAGS_ANYWHERE) == KERN_SUCCESS);
    memset((void *)(uintptr_t)fixture_address, 'x', 16384);
    region_mode = 1; region_calls = 0;
    assert(!process_holds("isolated-missing-marker") && region_calls == 2);
    region_mode = 2; region_calls = 0;
    assert(process_holds("isolated-missing-marker") && region_calls == 2);
    region_mode = 3; region_calls = 0;
    assert(process_holds("isolated-missing-marker"));
    region_mode = 4; region_calls = 0;
    assert(process_holds("isolated-missing-marker"));
    region_mode = 0;
    assert(mach_vm_deallocate(mach_task_self(), fixture_address, 16384) == KERN_SUCCESS);
}
static void region_boundary_cases(void)
{
    enum { REGION_SIZE = 262144 };
    static const struct { size_t offset, length; } cases[] = {
        {0, 1}, {65528, 21}, {65535, 2}, {65536, 21},
        {131064, 21}, {150, 70000}, {65528, 70000}, {REGION_SIZE - 21, 21}
    };
    mach_vm_address_t address = 0;
    assert(mach_vm_allocate(mach_task_self(), &address, REGION_SIZE, VM_FLAGS_ANYWHERE) == KERN_SUCCESS);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        size_t length = cases[i].length;
        char *marker = malloc(length);
        assert(marker);
        memset(marker, 'Z', length);
        marker[length - 1] = '!';
        memset((void *)(uintptr_t)address, 'x', REGION_SIZE);
        memcpy((void *)(uintptr_t)(address + cases[i].offset), marker, length);
        bool read_any = false;
        assert(region_contains(address, REGION_SIZE, marker, length, &read_any) && read_any);
        memset((void *)(uintptr_t)address, 'x', REGION_SIZE);
        read_any = false;
        assert(!region_contains(address, REGION_SIZE, marker, length, &read_any) && read_any);
        free(marker);
    }
    assert(mach_vm_deallocate(mach_task_self(), address, REGION_SIZE) == KERN_SUCCESS);
}
#endif

int main(void)
{
#ifdef __APPLE__
    region_enumeration_cases();
    region_boundary_cases();
    char *marker = malloc(32);
    assert(marker);
    memcpy(marker, "residue-long-short", 19);
    assert(process_holds(marker));
    assert(process_holds(""));
    assert(!process_holds("residue-missing"));
    memset(marker, 0, 32);
#else
    char *marker = malloc(70001);
    assert(marker);
    memset(marker, 'Z', 70000);
    memcpy(marker, "residue-long-", 13);
    marker[70000] = 0;
    assert(process_holds(marker));
    assert(process_holds(""));
#endif
#ifndef __APPLE__
    mode = 2; calls = 0;
    assert(process_holds(marker));
    mode = 1;
    assert(process_holds("residue-missing"));
    mode = 3;
    assert(process_holds(marker));
    assert(!process_holds("residue-missing"));
    mode = 4;
    assert(process_holds("residue-missing"));
    mode = 5; calls = 0;
    assert(process_holds(marker));
    mode = 6; calls = 0;
    assert(process_holds("residue-missing"));
    mode = 7; calls = 0;
    assert(process_holds("residue-missing"));
    mode = 8; calls = 0; memory_reads = 0;
    assert(process_holds("residue-missing"));
    assert(memory_reads > 0);
    mode = 9; calls = 0; memory_reads = 0;
    assert(process_holds("residue-missing"));
    assert(memory_reads > 0);
    mode = 10; calls = 0; memory_reads = 0;
    assert(!process_holds("residue-missing"));
    mode = 11; calls = 0; memory_reads = 0;
    assert(process_holds("residue-missing"));
    assert(memory_reads > 0 && calls > 0);
    mode = 0;
    assert(!process_holds("residue-missing"));
    const size_t page = 4096;
    unsigned char *grow = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    assert(grow != MAP_FAILED);
    memcpy(grow + page, "residue-grow-down", sizeof("residue-grow-down"));
    assert(!process_holds((const char *)grow + page));
    assert(munmap(grow, page * 2) == 0);
#endif
#ifndef __APPLE__
    memset(marker, 0, 70001);
#endif
    free(marker);
    puts("residue tests passed");
    return 0;
}
