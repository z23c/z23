/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_TEST_RESIDUE_H
#define ZAPP_TEST_RESIDUE_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#endif

static inline bool mapping_scan(unsigned char *buf, size_t total, const char *needle, size_t needle_len, size_t *carry)
{
    bool found = memmem(buf, total, needle, needle_len) != NULL;
    *carry = needle_len > 1 ? (total < needle_len - 1 ? total : needle_len - 1) : 0;
    if (*carry) memmove(buf, buf + total - *carry, *carry);
    return found;
}

static inline bool read_eio_pages(int mem, unsigned char *buf, size_t *carry, unsigned long at, size_t want,
                                  const char *needle, size_t needle_len, bool *failed, bool *read_any)
{
    enum { PAGE = 4096 };
    bool found = false;
    for (size_t off = 0; off < want && !found; off += PAGE) {
        size_t page = want - off < PAGE ? want - off : PAGE;
        ssize_t got;
        do got = pread(mem, buf + *carry, page, (off_t)(at + off)); while (got < 0 && errno == EINTR);
        if (got < 0 && errno == EIO) { *failed = true; break; }
        if (got != (ssize_t)page) { *failed = true; break; }
        *read_any = true;
        found = mapping_scan(buf, *carry + (size_t)got, needle, needle_len, carry);
    }
    return found;
}
static inline bool mapping_holds(int mem, unsigned long low, unsigned long high, const char *needle, size_t needle_len,
                                 bool *failed, bool *read_any)
{
    enum { CHUNK = 65536 };
    if (needle_len > SIZE_MAX - (CHUNK - 1)) return true;
    unsigned char *buf = malloc(CHUNK + needle_len - 1);
    if (!buf) return true;
    bool found = false;
    size_t carry = 0;
    for (unsigned long at = low; !found && at < high;) {
        size_t want = high - at < CHUNK ? (size_t)(high - at) : CHUNK;
        ssize_t got;
        do got = pread(mem, buf + carry, want, (off_t)at); while (got < 0 && errno == EINTR);
        if (got < 0 && errno == EIO) {
            found = read_eio_pages(mem, buf, &carry, at, want, needle, needle_len, failed, read_any);
            if (*failed) break;
            at += want;
            continue;
        }
        if (got <= 0) { *failed = true; break; }
        *read_any = true;
        found = mapping_scan(buf, carry + (size_t)got, needle, needle_len, &carry);
        at += (unsigned long)got;
    }
    free(buf);
    return found;
}

/* Whether the text appears in this process's writable program data or its heap:
 * the places a copy of wallet data could survive after the screens that held it are gone. Stacks,
 * mappings of libraries and read-only data are not searched: the fixtures live in read-only data, and a
 * stack is reused by every call. Run on one thread, so that every allocation is in the main heap.
 * An incomplete mapping or maps-stream scan counts as presence, never as a clean wipe. */
#if defined(__APPLE__)
static inline bool residue_tag(unsigned tag)
{
    return tag == 0 || tag == VM_MEMORY_REALLOC ||
        (tag >= VM_MEMORY_MALLOC && tag <= VM_MEMORY_MALLOC_PROB_GUARD && tag != VM_MEMORY_ANALYSIS_TOOL);
}
static inline bool region_readable(const vm_region_extended_info_data_t *info, mach_vm_address_t address,
                                   mach_vm_size_t size, uintptr_t stack_low, uintptr_t stack_high)
{
    bool writable = (info->protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE);
    bool stack = info->user_tag == VM_MEMORY_STACK || (address < stack_high && address + size > stack_low);
    return writable && !stack && residue_tag(info->user_tag) && size > 0;
}
static inline bool region_contains(mach_vm_address_t address, mach_vm_size_t size, const char *needle, size_t needle_len,
                                   bool *read_any)
{
    /* Overlap reads so a marker crossing a chunk boundary is still searched.
     * Mach reports the returned byte count in a 32-bit field. */
    if (!needle_len || needle_len > UINT32_MAX - 65535 || size > UINT64_MAX - address) return true;
    const mach_vm_size_t window = 65536 + needle_len - 1;
    bool found = false;
    mach_vm_address_t at = address;
    while (at < address + size && !found) {
        mach_vm_size_t want = address + size - at;
        vm_offset_t data = 0;
        mach_msg_type_number_t data_count = 0;
        if (want > window) want = window;
        if (mach_vm_read(mach_task_self(), at, want, &data, &data_count) != KERN_SUCCESS) return true;
        *read_any = true;
        bool incomplete = data_count != want;
        if (data_count >= needle_len && memmem((void *)data, data_count, needle, needle_len)) found = true;
        vm_deallocate(mach_task_self(), data, data_count);
        if (incomplete) return true;
        if (want == address + size - at) break;
        at += 65536;
    }
    return found;
}
static inline bool apple_process_holds(const char *needle)
{
    if (!needle || !*needle) return true;
    size_t needle_len = strlen(needle);
    uintptr_t stack_high = (uintptr_t)pthread_get_stackaddr_np(pthread_self());
    uintptr_t stack_low = stack_high - pthread_get_stacksize_np(pthread_self());
    mach_vm_address_t address = 0;
    bool found = false, read_any = false;
    for (;;) {
        mach_vm_size_t size = 0;
        vm_region_extended_info_data_t info;
        mach_msg_type_number_t count = VM_REGION_EXTENDED_INFO_COUNT;
        mach_port_t object = MACH_PORT_NULL;
        mach_vm_address_t requested = address;
        kern_return_t kr = mach_vm_region(mach_task_self(), &address, &size, VM_REGION_EXTENDED_INFO,
                                          (vm_region_info_t)&info, &count, &object);
        if (kr == KERN_INVALID_ADDRESS) break;
        if (kr != KERN_SUCCESS) return true;
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
        if (address < requested || !size || size > UINT64_MAX - address) return true;
        if (region_readable(&info, address, size, stack_low, stack_high))
            found = region_contains(address, size, needle, needle_len, &read_any);
        if (found) break;
        address += size;
    }
    return found || !read_any;
}
static inline bool process_holds(const char *needle)
{
    return apple_process_holds(needle);
}
#else
static inline bool metadata_known(const char *line)
{
    static const char *const metadata[] = {"Anonymous:", "AnonHugePages:", "FilePmdMapped:", "Decommit:"};
    for (size_t i = 0; i < sizeof(metadata) / sizeof(metadata[0]); ++i)
        if (!strncmp(line, metadata[i], strlen(metadata[i]))) return true;
    return false;
}
static inline bool guard_flags(const char *line)
{
    return !strncmp(line, "VmFlags:", 8) &&
        (strstr(line, " gu ") || strstr(line, " gu\n") || strstr(line, " gd ") || strstr(line, " gd\n"));
}
static inline bool private_data(const char *perms, const char *path, unsigned long low, unsigned long high)
{
    return perms[0] == 'r' && perms[1] == 'w' && perms[3] == 'p' && high > low &&
        !strstr(path, "[stack") && !strstr(path, ".so") && !strstr(path, "[vvar") && !strstr(path, "[vsyscall");
}
static inline bool scan_candidate(int mem, unsigned long low, unsigned long high, const char *needle, size_t needle_len,
                                  bool *read_any)
{
    bool failed = false;
    bool found = mapping_holds(mem, low, high, needle, needle_len, &failed, read_any);
    return found || failed;
}
struct maps_scan {
    bool found, read_any, have_mapping, candidate;
    unsigned long low, high;
    int mem;
    const char *needle;
    size_t needle_len;
};
static inline bool maps_unreadable(FILE *maps, int mem)
{
    if (maps && mem >= 0) return false;
    if (maps) fclose(maps);
    if (mem >= 0) close(mem);
    return true;
}
static inline bool maps_line(struct maps_scan *scan, const char *line)
{
    bool address = isxdigit((unsigned char)line[0]) && strchr(line, '-');
    /* Hex that is not an address and not a "Name:" field is a broken map line. */
    if (isxdigit((unsigned char)line[0]) && !address && !metadata_known(line) && !strchr(line, ':')) {
        scan->found = true;
        return true;
    }
    if (!address) {
        if (scan->have_mapping && guard_flags(line)) scan->candidate = false;
        return false;
    }
    unsigned long next_low = 0, next_high = 0;
    char perms[8] = "", path[400] = "";
    if (sscanf(line, "%lx-%lx %7s %*s %*s %*s %399[^\n]", &next_low, &next_high, perms, path) < 3) {
        scan->found = true;
        return true;
    }
    if (scan->have_mapping && scan->candidate)
        scan->found = scan_candidate(scan->mem, scan->low, scan->high, scan->needle, scan->needle_len, &scan->read_any);
    scan->low = next_low;
    scan->high = next_high;
    scan->candidate = private_data(perms, path, scan->low, scan->high);
    scan->have_mapping = true;
    return scan->found;
}
static inline bool maps_finish(FILE *maps, struct maps_scan *scan)
{
    if (!scan->found && scan->have_mapping && scan->candidate)
        scan->found = scan_candidate(scan->mem, scan->low, scan->high, scan->needle, scan->needle_len, &scan->read_any);
    if (ferror(maps) || !scan->read_any) scan->found = true;
    close(scan->mem);
    if (fclose(maps)) scan->found = true;
    return scan->found;
}
static inline bool linux_process_holds(const char *needle)
{
    if (!needle || !*needle) return true;
    FILE *maps = fopen("/proc/self/smaps", "r");
    int mem = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
    char line[600];
    struct maps_scan scan = {.mem = mem, .needle = needle, .needle_len = strlen(needle)};
    if (maps_unreadable(maps, mem)) return true;
    while (!scan.found && fgets(line, sizeof(line), maps))
        if (maps_line(&scan, line)) break;
    return maps_finish(maps, &scan);
}
static inline bool process_holds(const char *needle)
{
    return linux_process_holds(needle);
}
#endif
#endif
