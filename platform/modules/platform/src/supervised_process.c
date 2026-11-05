/* purpose: Supervise exact Linux images through retained descriptors and subreaper custody. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "platform/supervised_process.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

void platform_supervised_init(struct platform_supervised_process *process)
{
    if (process) *process = (struct platform_supervised_process){
        .supervisor_pid = -1, .control_fd = -1,
        .observation = {.state = PLATFORM_SUPERVISED_INVALID}};
}
#if defined(__linux__)
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include "sha3/sha3.h"

#ifdef ZCL_TESTING
static _Thread_local bool observation_error_once;
static _Thread_local int retirement_cleanup_gate = -1;
#endif

struct image_layout {
    const uint8_t *bytes;
    size_t length;
    Elf64_Ehdr header;
    Elf64_Phdr loads[128];
    size_t load_count;
    uint64_t page_size;
    Elf64_Phdr dynamic;
    bool has_dynamic, has_interpreter, entry_found;
};

static bool image_range(const struct image_layout *image, uint64_t offset, uint64_t length)
{
    return offset <= image->length && length <= image->length - offset;
}

static bool image_native(const Elf64_Ehdr *header)
{
#if defined(__x86_64__)
    const uint16_t machine = EM_X86_64;
#elif defined(__aarch64__)
    const uint16_t machine = EM_AARCH64;
#else
    const uint16_t machine = EM_NONE;
    (void)header;
    return false;
#endif
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    const unsigned data = ELFDATA2LSB;
#else
    const unsigned data = ELFDATANONE;
#endif
    return header->e_machine == machine && header->e_ident[EI_DATA] == data;
}

static bool image_header(struct image_layout *image)
{
    if (image->length < sizeof(image->header)) return false;
    memcpy(&image->header, image->bytes, sizeof(image->header));
    const Elf64_Ehdr *h = &image->header;
    bool format = !memcmp(h->e_ident, ELFMAG, SELFMAG) && h->e_ident[EI_CLASS] == ELFCLASS64 &&
        h->e_ident[EI_VERSION] == EV_CURRENT && h->e_version == EV_CURRENT && image_native(h);
    bool layout = h->e_ehsize == sizeof(*h) && h->e_phentsize == sizeof(Elf64_Phdr) &&
        h->e_phnum && h->e_phnum <= 128 && image_range(image, h->e_phoff,
        (uint64_t)h->e_phnum * sizeof(Elf64_Phdr));
    return format && layout && (h->e_type == ET_EXEC || h->e_type == ET_DYN);
}

static bool image_loader(const struct image_layout *image, const Elf64_Phdr *ph)
{
#if defined(__x86_64__)
    static const char loader[] = "/lib64/ld-linux-x86-64.so.2";
#elif defined(__aarch64__)
    static const char loader[] = "/lib/ld-linux-aarch64.so.1";
#else
    static const char loader[] = "unsupported";
#endif
    return ph->p_filesz == sizeof(loader) &&
        !memcmp(image->bytes + ph->p_offset, loader, sizeof(loader));
}

static bool image_pages_conflict(const struct image_layout *image,
    const Elf64_Phdr *a, const Elf64_Phdr *b)
{
    bool permissions = ((a->p_flags & PF_X) && (b->p_flags & PF_W)) ||
        ((b->p_flags & PF_X) && (a->p_flags & PF_W));
    if (!permissions || !a->p_memsz || !b->p_memsz) return false;
    uint64_t mask = image->page_size - 1;
    uint64_t a_end = (a->p_vaddr + a->p_memsz + mask) & ~mask;
    uint64_t b_end = (b->p_vaddr + b->p_memsz + mask) & ~mask;
    return (a->p_vaddr & ~mask) < b_end && (b->p_vaddr & ~mask) < a_end;
}

static bool image_load_overlap(const struct image_layout *image, const Elf64_Phdr *ph)
{
    for (size_t i = 0; i < image->load_count; ++i) {
        const Elf64_Phdr *prior = &image->loads[i];
        if (image_pages_conflict(image, ph, prior)) return true;
        if (ph->p_memsz && prior->p_memsz && ph->p_vaddr < prior->p_vaddr + prior->p_memsz &&
            prior->p_vaddr < ph->p_vaddr + ph->p_memsz) return true;
    }
    return false;
}

static bool image_load_geometry(const struct image_layout *image, const Elf64_Phdr *ph)
{
    if (ph->p_filesz > ph->p_memsz || ph->p_memsz > UINT64_MAX - image->page_size ||
        ph->p_vaddr > UINT64_MAX - ph->p_memsz - image->page_size ||
        (ph->p_flags & (PF_W | PF_X)) == (PF_W | PF_X)) return false;
    if (ph->p_align > 1 && ((ph->p_align & (ph->p_align - 1)) ||
        ph->p_vaddr % ph->p_align != ph->p_offset % ph->p_align)) return false;
    return true;
}

static bool image_load(struct image_layout *image, const Elf64_Phdr *ph)
{
    if (!image_load_geometry(image, ph)) return false;
    if (image_load_overlap(image, ph)) return false;
    image->loads[image->load_count++] = *ph;
    if ((ph->p_flags & PF_X) && image->header.e_entry >= ph->p_vaddr &&
        image->header.e_entry - ph->p_vaddr < ph->p_filesz) image->entry_found = true;
    return true;
}

static bool image_segment(struct image_layout *image, const Elf64_Phdr *ph)
{
    if (!image_range(image, ph->p_offset, ph->p_filesz)) return false;
    switch (ph->p_type) {
    case PT_LOAD: return image_load(image, ph);
    case PT_INTERP:
        if (image->has_interpreter || !image_loader(image, ph)) return false;
        image->has_interpreter = true; return true;
    case PT_DYNAMIC:
        if (image->has_dynamic || !ph->p_filesz || ph->p_filesz % sizeof(Elf64_Dyn)) return false;
        image->dynamic = *ph; image->has_dynamic = true; return true;
    case PT_GNU_STACK: return !(ph->p_flags & PF_X);
    default: return true;
    }
}

static bool image_virtual(const struct image_layout *image, uint64_t address,
    uint64_t length, uint64_t *offset)
{
    for (size_t i = 0; i < image->load_count; ++i) {
        const Elf64_Phdr *load = &image->loads[i];
        if (address < load->p_vaddr) continue;
        uint64_t delta = address - load->p_vaddr;
        if (delta <= load->p_filesz && length <= load->p_filesz - delta) {
            *offset = load->p_offset + delta; return true;
        }
    }
    return false;
}

static bool image_forbidden_dynamic(const Elf64_Dyn *entry)
{
    switch (entry->d_tag) {
    case DT_RPATH: case DT_RUNPATH: case DT_TEXTREL:
    case DT_AUDIT: case DT_DEPAUDIT: case DT_FILTER: case DT_AUXILIARY:
        return true;
    case DT_FLAGS: return (entry->d_un.d_val & DF_TEXTREL) != 0;
    default: return false;
    }
}

static Elf64_Dyn image_dynamic_entry(const struct image_layout *image, size_t index)
{
    Elf64_Dyn entry;
    memcpy(&entry, image->bytes + image->dynamic.p_offset + index * sizeof(entry), sizeof(entry));
    return entry;
}

static bool image_dynamic_strings(const struct image_layout *image,
    uint64_t *strings, uint64_t *length, size_t *count)
{
    uint64_t address = 0; bool has_address = false, has_length = false;
    size_t total = image->dynamic.p_filesz / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < total; ++i) {
        Elf64_Dyn entry = image_dynamic_entry(image, i);
        if (image_forbidden_dynamic(&entry)) return false;
        if (entry.d_tag == DT_NULL) { *count = i; break; }
        if (entry.d_tag == DT_STRTAB) {
            if (has_address) return false;
            address = entry.d_un.d_ptr; has_address = true;
        }
        if (entry.d_tag == DT_STRSZ) {
            if (has_length) return false;
            *length = entry.d_un.d_val; has_length = true;
        }
    }
    return *count < total && has_address && has_length && *length &&
        *length <= 65536 && image_virtual(image, address, *length, strings);
}

static bool image_dynamic_policy(const struct image_layout *image)
{
    if (!image->has_dynamic) return !image->has_interpreter;
    uint64_t mapped = 0;
    if (image->dynamic.p_filesz / sizeof(Elf64_Dyn) > 4096 ||
        !image_virtual(image, image->dynamic.p_vaddr, image->dynamic.p_filesz, &mapped) ||
        mapped != image->dynamic.p_offset) return false;
    uint64_t strings = 0, length = 0; size_t count = SIZE_MAX, needed = 0;
    if (!image_dynamic_strings(image, &strings, &length, &count)) return false;
    for (size_t i = 0; i < count; ++i) {
        Elf64_Dyn entry = image_dynamic_entry(image, i);
        if (entry.d_tag != DT_NEEDED) continue;
        static const char libc[] = "libc.so.6";
        uint64_t offset = entry.d_un.d_val;
        if (offset >= length || sizeof(libc) > length - offset ||
            memcmp(image->bytes + strings + offset, libc, sizeof(libc))) return false;
        if (++needed > 1) return false;
    }
    return image->has_interpreter ? needed == 1 : needed == 0;
}

static bool image_policy(const void *bytes, size_t length)
{
    struct image_layout image = {.bytes = bytes, .length = length};
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || page > 65536 || ((unsigned long)page & ((unsigned long)page - 1))) return false;
    image.page_size = (uint64_t)page;
    if (!image_header(&image)) return false;
    for (size_t i = 0; i < image.header.e_phnum; ++i) {
        Elf64_Phdr ph;
        memcpy(&ph, image.bytes + image.header.e_phoff + i * sizeof(ph), sizeof(ph));
        if (!image_segment(&image, &ph)) return false;
    }
    return image.entry_found && image_dynamic_policy(&image);
}

static bool image_write(int fd, const uint8_t *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        offset += (size_t)count;
    }
    return true;
}

static bool image_digest(int fd, size_t length, const uint8_t expected[32])
{
    struct sha3_256_ctx hash; sha3_256_init(&hash);
    uint8_t buffer[4096], digest[32]; size_t offset = 0;
    while (offset < length) {
        size_t wanted = length - offset < sizeof(buffer) ? length - offset : sizeof(buffer);
        ssize_t count = pread(fd, buffer, wanted, (off_t)offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        sha3_256_write(&hash, buffer, (size_t)count); offset += (size_t)count;
    }
    sha3_256_finalize(&hash, digest);
    return !memcmp(digest, expected, sizeof(digest));
}

enum platform_supervised_image_result platform_supervised_image_capture(
    const void *bytes, size_t length, const uint8_t expected_sha3[32], int *image_fd)
{
    if (!bytes || !length || length > PLATFORM_SUPERVISED_IMAGE_MAX ||
        !expected_sha3 || !image_fd || *image_fd != -1 || !image_policy(bytes, length))
        return PLATFORM_SUPERVISED_IMAGE_REFUSED;
    int fd = memfd_create("z23-host-image", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return PLATFORM_SUPERVISED_IMAGE_IO_ERROR;
    int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    bool ok = image_write(fd, bytes, length) && fchmod(fd, 0500) == 0 &&
        fcntl(fd, F_ADD_SEALS, seals) == 0 && image_digest(fd, length, expected_sha3);
    if (!ok) { int error = errno; close(fd); errno = error;
        return PLATFORM_SUPERVISED_IMAGE_IO_ERROR; }
    *image_fd = fd; return PLATFORM_SUPERVISED_IMAGE_OK;
}

struct packet {
    uint32_t version, operation;
    uint32_t signal;
    int64_t deadline;
    struct platform_supervised_observation observation;
};
struct supervisor {
    int control;
    pid_t engine;
    int engine_pidfd;
    uint32_t cleanup_ms;
#ifdef ZCL_TESTING
    int fixture_cleanup_gate;
#endif
    struct platform_supervised_observation observation;
};
enum { PACKET_VERSION = 2, PACKET_STOP = 1, PACKET_REPORT = 2, PACKET_SIGNAL = 3 };

static pid_t raw_fork(void)
{
#if defined(SYS_fork)
    return (pid_t)syscall(SYS_fork);
#else
    return (pid_t)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
#endif
}

static int64_t monotonic_ns(void)
{
    struct timespec value;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &value) < 0) return -1;
    if (value.tv_sec < 0 || value.tv_sec > INT64_MAX / INT64_C(1000000000)) return -1;
    if (value.tv_sec == INT64_MAX / INT64_C(1000000000) &&
        value.tv_nsec > INT64_MAX % INT64_C(1000000000)) return -1;
    return (int64_t)value.tv_sec * INT64_C(1000000000) + value.tv_nsec;
}

static int remaining_ms(int64_t deadline)
{
    int64_t now = monotonic_ns();
    if (now < 0 || now >= deadline) return 0;
    uint64_t ns = (uint64_t)deadline - (uint64_t)now;
    uint64_t ms = ns / UINT64_C(1000000) + (ns % UINT64_C(1000000) != 0);
    return ms > 20 ? 20 : (int)ms;
}

static bool vector_valid(const char *const *values, bool nonempty, size_t maximum)
{
    if (!values) return false;
    for (size_t i = 0; i <= maximum; ++i) {
        if (!values[i]) return !nonempty || i != 0;
    }
    return false;
}

static bool mappings_valid(const struct platform_supervised_spec *spec)
{
    if (!spec->maps || spec->map_count < 3 || spec->map_count > PLATFORM_SUPERVISED_MAX_MAPS)
        return false;
    unsigned stdio = 0;
    for (size_t i = 0; i < spec->map_count; ++i) {
        const struct platform_supervised_fd_map *map = &spec->maps[i];
        if (map->source < 0 || map->target < 0 || map->target > 63 ||
            fcntl(map->source, F_GETFD) < 0) return false;
        if (map->target < 3) stdio |= 1U << (unsigned)map->target;
        for (size_t j = 0; j < i; ++j)
            if (map->target == spec->maps[j].target) return false;
    }
    return stdio == 7;
}

static bool executable_valid(int fd)
{
    struct stat status;
    uint8_t magic[4];
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    int seals = fcntl(fd, F_GET_SEALS);
    return seals >= 0 && (seals & required) == required &&
        fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
        pread(fd, magic, sizeof(magic), 0) == (ssize_t)sizeof(magic) &&
        !memcmp(magic, "\177ELF", sizeof(magic));
}

static bool cwd_valid(const struct platform_supervised_spec *spec)
{
    struct stat status;
    return !spec->use_cwd_fd || (spec->cwd_fd >= 0 &&
        fstat(spec->cwd_fd, &status) == 0 && S_ISDIR(status.st_mode));
}

static bool environment_valid(const struct platform_supervised_spec *spec)
{
    if (spec->env_policy == PLATFORM_SUPERVISED_ENV_DEFAULT)
        return vector_valid(spec->env, false, PLATFORM_SUPERVISED_ENV_MAX);
    if (spec->env_policy != PLATFORM_SUPERVISED_ENV_COMPLETE || !spec->env ||
        spec->env_count > SIZE_MAX / sizeof(*spec->env) - 1) return false;
    for (size_t i = 0; i < spec->env_count; ++i)
        if (!spec->env[i]) return false;
    return spec->env[spec->env_count] == NULL;
}

static bool spec_valid(const struct platform_supervised_spec *spec)
{
    if (!spec ||
        (spec->argv_policy != PLATFORM_SUPERVISED_ARGV_DEFAULT &&
         spec->argv_policy != PLATFORM_SUPERVISED_ARGV_EXTENDED) ||
        (spec->stack_policy != PLATFORM_SUPERVISED_STACK_INHERIT &&
         spec->stack_policy != PLATFORM_SUPERVISED_STACK_UNLIMITED)) return false;
    size_t maximum = spec->argv_policy == PLATFORM_SUPERVISED_ARGV_EXTENDED ?
        PLATFORM_SUPERVISED_ARGV_EXTENDED_MAX : PLATFORM_SUPERVISED_ARGV_DEFAULT_MAX;
    return vector_valid(spec->argv, true, maximum) &&
        environment_valid(spec) &&
        cwd_valid(spec) && mappings_valid(spec) && executable_valid(spec->executable_fd) &&
        remaining_ms(spec->launch_deadline_ns) && spec->cleanup_timeout_ms &&
        spec->cleanup_timeout_ms <= 10000;
}

static bool send_packet(int fd, const struct packet *packet)
{
    return send(fd, packet, sizeof(*packet), MSG_NOSIGNAL | MSG_DONTWAIT) == (ssize_t)sizeof(*packet);
}

static int receive_packet(int fd, struct packet *packet)
{
    ssize_t n = recv(fd, packet, sizeof(*packet), MSG_DONTWAIT | MSG_TRUNC);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    if (n != (ssize_t)sizeof(*packet) || packet->version != PACKET_VERSION) return -1;
    return 1;
}

/* close_range is mandatory; no RLIMIT-based ambient-descriptor blind spot. */
static bool close_except(const int *keep, size_t count)
{
    unsigned begin = 0;
    while (begin < UINT_MAX) {
        unsigned next = UINT_MAX;
        for (size_t i = 0; i < count; ++i) {
            unsigned fd = (unsigned)keep[i];
            if (fd >= begin && fd < next) next = fd;
        }
        if (next > begin && syscall(SYS_close_range, begin, next - 1, 0) < 0) return false;
        if (next == UINT_MAX) return syscall(SYS_close_range, UINT_MAX, UINT_MAX, 0) == 0;
        begin = next + 1;
    }
    return true;
}

static bool prepare_engine(const struct platform_supervised_spec *spec, int *image,
    int *error_fd, int keep[PLATFORM_SUPERVISED_MAX_MAPS + 2])
{
    if (spec->stack_policy == PLATFORM_SUPERVISED_STACK_UNLIMITED) {
        const struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
        if (syscall(SYS_prlimit64, 0, RLIMIT_STACK, &limit, NULL) < 0) return false;
    }
    if (spec->use_cwd_fd && fchdir(spec->cwd_fd) < 0) return false;
    int copies[PLATFORM_SUPERVISED_MAX_MAPS];
    *image = fcntl(spec->executable_fd, F_DUPFD_CLOEXEC, 64);
    if (*image < 0) return false;
    for (size_t i = 0; i < spec->map_count; ++i) {
        copies[i] = fcntl(spec->maps[i].source, F_DUPFD_CLOEXEC, 64);
        if (copies[i] < 0) return false;
    }
    for (size_t i = 0; i < spec->map_count; ++i) {
        int target = spec->maps[i].target;
        if (dup2(copies[i], target) < 0) return false;
        keep[i] = target;
    }
    keep[spec->map_count] = *image;
    keep[spec->map_count + 1] = *error_fd;
    return close_except(keep, spec->map_count + 2);
}

static void engine_exec(const struct platform_supervised_spec *spec, int error_fd)
{
    int original_error = error_fd;
    error_fd = fcntl(error_fd, F_DUPFD_CLOEXEC, 64);
    if (error_fd < 0) {
        int error = errno;
        ssize_t sent = write(original_error, &error, sizeof(error));
        if (sent != (ssize_t)sizeof(error)) _exit(126);
        _exit(127);
    }
    int image = -1, keep[PLATFORM_SUPERVISED_MAX_MAPS + 2];
    bool prepared = prepare_engine(spec, &image, &error_fd, keep);
    if (prepared)
        (void)syscall(SYS_execveat, image, "", spec->argv, spec->env, AT_EMPTY_PATH);
    int error = errno;
    ssize_t sent = write(error_fd, &error, sizeof(error));
    if (sent != (ssize_t)sizeof(error)) _exit(126);
    _exit(127);
}

static bool exec_observed(int error_fd, int64_t deadline, int *error)
{
    while (remaining_ms(deadline)) {
        struct pollfd entry = {.fd = error_fd, .events = POLLIN};
        int ready = poll(&entry, 1, remaining_ms(deadline));
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) { *error = errno; return false; }
        if (!ready) continue;
        ssize_t n = read(error_fd, error, sizeof(*error));
        if (n == 0) return true;
        if (n == (ssize_t)sizeof(*error)) return false;
        *error = EIO;
        return false;
    }
    *error = ETIMEDOUT;
    return false;
}

static bool signal_child(pid_t pid)
{
    int descriptor = (int)syscall(SYS_pidfd_open, pid, 0);
    if (descriptor < 0) return errno == ESRCH;
    int result = (int)syscall(SYS_pidfd_send_signal, descriptor, SIGKILL, NULL, 0);
    int error = errno;
    close(descriptor);
    return result == 0 || error == ESRCH;
}

/* Stream the entire child list; fixed chunks do not truncate child ownership. */
static bool signal_children(int64_t deadline)
{
    int fd = open("/proc/thread-self/children", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char bytes[512];
    unsigned pid = 0;
    bool ok = true;
    ssize_t n;
    while ((n = read(fd, bytes, sizeof(bytes))) > 0) {
        for (ssize_t i = 0; i < n; ++i) {
            if (!remaining_ms(deadline)) { ok = false; break; }
            if (bytes[i] >= '0' && bytes[i] <= '9') {
                unsigned digit = (unsigned)(bytes[i] - '0');
                if (pid > ((unsigned)INT_MAX - digit) / 10) { ok = false; break; }
                pid = pid * 10 + digit;
            } else {
                if (pid && !signal_child((pid_t)pid)) { ok = false; break; }
                pid = 0;
            }
        }
        if (!ok) break;
    }
    if (ok && pid) ok = signal_child((pid_t)pid);
    if (n < 0) ok = false;
    close(fd);
    return ok;
}

static bool reap_children(struct supervisor *state, int64_t deadline)
{
    while (remaining_ms(deadline)) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
            if (pid == state->engine) {
                state->observation.engine_exit_observed = true;
                state->observation.engine_wait_status = status;
            }
            continue;
        }
        if (pid < 0 && errno == ECHILD) {
            state->observation.no_children = true;
            return true;
        }
        return false;
    }
    state->observation.error_number = ETIMEDOUT;
    return false;
}

static bool cleanup(struct supervisor *state, int64_t deadline)
{
    while (remaining_ms(deadline)) {
        if (!signal_children(deadline)) {
            state->observation.error_number = errno ? errno : ETIMEDOUT;
            return false;
        }
        if (reap_children(state, deadline)) return true;
        struct pollfd delay = {.fd = -1};
        (void)poll(&delay, 0, remaining_ms(deadline));
    }
    state->observation.error_number = ETIMEDOUT;
    return false;
}

static void report(struct supervisor *state, enum platform_supervised_state result)
{
    state->observation.state = result;
    struct packet reply = {.version = PACKET_VERSION, .operation = PACKET_REPORT,
        .observation = state->observation};
    (void)send_packet(state->control, &reply);
}

static int64_t cleanup_deadline(const struct supervisor *state)
{
    int64_t now = monotonic_ns();
    int64_t duration = (int64_t)state->cleanup_ms * INT64_C(1000000);
    return now < 0 || now > INT64_MAX - duration ? 0 : now + duration;
}

static bool engine_exited(const struct supervisor *state)
{
    siginfo_t information = {0};
    return waitid(P_PID, (id_t)state->engine, &information,
        WEXITED | WNOHANG | WNOWAIT) == 0 && information.si_pid != 0;
}

static int forwarded_signal(unsigned signal)
{
    switch (signal) {
    case PLATFORM_SUPERVISED_HANGUP: return SIGHUP;
    case PLATFORM_SUPERVISED_INTERRUPT: return SIGINT;
    case PLATFORM_SUPERVISED_TERMINATE: return SIGTERM;
    default: return 0;
    }
}

static void forward_engine_signal(const struct supervisor *state, unsigned signal)
{
    int number = forwarded_signal(signal);
    if (!number || state->engine_pidfd < 0 || state->observation.engine_exit_observed) return;
    (void)syscall(SYS_pidfd_send_signal, state->engine_pidfd, number, NULL, 0);
}

static void supervise_request(struct supervisor *state, bool *stopping,
    bool *owner_eof, int64_t *deadline)
{
    struct packet request;
    int received = receive_packet(state->control, &request);
    if (received > 0 && request.operation == PACKET_STOP) {
        *stopping = true;
        *deadline = request.deadline;
    } else if (received > 0 && request.operation == PACKET_SIGNAL) {
        if (!*stopping) forward_engine_signal(state, request.signal);
    } else if (received < 0) {
        *stopping = true;
        *deadline = cleanup_deadline(state);
        *owner_eof = true;
    }
}

static void supervise(struct supervisor *state)
{
    bool stopping = false;
    bool owner_eof = false;
    int64_t deadline = 0;
    for (;;) {
        struct pollfd event = {.fd = owner_eof ? -1 : state->control, .events = POLLIN};
        (void)poll(&event, 1, 20);
        if (event.revents) supervise_request(state, &stopping, &owner_eof, &deadline);
        if (!stopping && engine_exited(state)) {
            stopping = true;
            deadline = cleanup_deadline(state);
        }
        if (!stopping) continue;
#ifdef ZCL_TESTING
        if (state->fixture_cleanup_gate >= 0) {
            uint8_t byte;
            ssize_t received = read(state->fixture_cleanup_gate, &byte, sizeof(byte));
            (void)received;
            close(state->fixture_cleanup_gate);
            state->fixture_cleanup_gate = -1;
        }
#endif
        bool clean = cleanup(state, deadline);
        report(state, clean ? PLATFORM_SUPERVISED_CLEAN : PLATFORM_SUPERVISED_INCOMPLETE);
        if (clean) _exit(0);
        deadline = cleanup_deadline(state);
    }
}

static int arm_subreaper(void)
{
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    sigset_t unblocked;
    sigemptyset(&unblocked);
    for (int number = 1; number < NSIG; ++number) {
        if (number == SIGKILL || number == SIGSTOP) continue;
        if (sigaction(number, &action, NULL) < 0 && errno != EINVAL) return errno;
    }
    if (sigprocmask(SIG_SETMASK, &unblocked, NULL) < 0 || prctl(PR_SET_CHILD_SUBREAPER, 1) < 0)
        return errno;
    return 0;
}

static int launch_descriptors(struct supervisor *state, const struct platform_supervised_spec *spec)
{
    int error = arm_subreaper();
    int keep[PLATFORM_SUPERVISED_MAX_MAPS + 4] = {state->control, spec->executable_fd};
    for (size_t i = 0; i < spec->map_count; ++i) keep[i + 2] = spec->maps[i].source;
    size_t kept = spec->map_count + 2;
    if (spec->use_cwd_fd) keep[kept++] = spec->cwd_fd;
#ifdef ZCL_TESTING
    if (state->fixture_cleanup_gate >= 0) keep[kept++] = state->fixture_cleanup_gate;
#endif
    if (!error && !close_except(keep, kept)) error = errno;
    return error;
}

static bool launch_engine(struct supervisor *state, const struct platform_supervised_spec *spec)
{
    int error = launch_descriptors(state, spec);
    int errors[2] = {-1, -1};
    if (!error && pipe2(errors, O_CLOEXEC) < 0) error = errno;
    if (!error) {
        state->engine = raw_fork();
        if (state->engine == 0) { close(errors[0]); engine_exec(spec, errors[1]); }
        if (state->engine < 0) error = errno;
        if (state->engine > 0) {
            state->engine_pidfd = (int)syscall(SYS_pidfd_open, state->engine, 0);
            if (state->engine_pidfd < 0) error = errno;
        }
    }
    if (errors[1] >= 0) close(errors[1]);
    bool executed = !error && exec_observed(errors[0], spec->launch_deadline_ns, &error);
    if (errors[0] >= 0) close(errors[0]);
    state->observation.error_number = error;
    return executed;
}

static void supervisor_main(int control, int other, const struct platform_supervised_spec *spec,
    int fixture_gate)
{
    close(other);
    struct supervisor state = {.control = control, .engine = -1,
        .engine_pidfd = -1,
        .cleanup_ms = spec->cleanup_timeout_ms};
#ifdef ZCL_TESTING
    state.fixture_cleanup_gate = fixture_gate;
#else
    (void)fixture_gate;
#endif
    bool executed = launch_engine(&state, spec);
    for (size_t i = 0; i < spec->map_count; ++i) close(spec->maps[i].source);
    close(spec->executable_fd);
    report(&state, executed ? PLATFORM_SUPERVISED_RUNNING : PLATFORM_SUPERVISED_LAUNCH_FAILED);
    if (state.engine < 0) {
        bool clean = reap_children(&state, cleanup_deadline(&state));
        report(&state, clean ? PLATFORM_SUPERVISED_CLEAN : PLATFORM_SUPERVISED_INCOMPLETE);
        _exit(clean ? 0 : 1);
    }
    if (!executed) {
        bool clean = cleanup(&state, cleanup_deadline(&state));
        report(&state, clean ? PLATFORM_SUPERVISED_CLEAN : PLATFORM_SUPERVISED_INCOMPLETE);
        if (clean) _exit(0);
    }
    supervise(&state);
}

static pid_t fork_supervisor(int control, int other, const struct platform_supervised_spec *spec)
{
    int fixture_gate = -1;
#ifdef ZCL_TESTING
    fixture_gate = retirement_cleanup_gate; /* Snapshot TLS before the raw fork. */
#endif
    sigset_t blocked, previous;
    sigfillset(&blocked);
    if (sigprocmask(SIG_SETMASK, &blocked, &previous) < 0) return -1;
    pid_t pid = raw_fork();
    if (pid == 0) supervisor_main(control, other, spec, fixture_gate);
    (void)sigprocmask(SIG_SETMASK, &previous, NULL);
    return pid;
}

static enum platform_supervised_state consume(struct platform_supervised_process *process)
{
#ifdef ZCL_TESTING
    if (observation_error_once) {
        observation_error_once = false;
        return PLATFORM_SUPERVISED_OBSERVATION_FAILED;
    }
#endif
    struct packet packet;
    int received = receive_packet(process->control_fd, &packet);
    if (!received) return process->observation.state;
    if (received < 0 && process->observation.no_children) return PLATFORM_SUPERVISED_CLEAN;
    if (received < 0 || packet.operation != PACKET_REPORT ||
        packet.observation.state < PLATFORM_SUPERVISED_RUNNING ||
        packet.observation.state > PLATFORM_SUPERVISED_OBSERVATION_FAILED ||
        (packet.observation.state == PLATFORM_SUPERVISED_CLEAN && !packet.observation.no_children))
        return PLATFORM_SUPERVISED_OBSERVATION_FAILED;
    process->observation = packet.observation;
    return process->observation.state;
}

static void finish_supervisor(struct platform_supervised_process *process)
{
    if (!process->observation.no_children &&
        process->observation.state != PLATFORM_SUPERVISED_OBSERVATION_FAILED) return;
    int status;
    pid_t reaped = waitpid((pid_t)process->supervisor_pid, &status, WNOHANG);
    if (reaped == (pid_t)process->supervisor_pid || (reaped < 0 && errno == ECHILD)) {
        if (reaped < 0) process->observation.no_children = false;
        if (!process->observation.no_children)
            process->observation.state = PLATFORM_SUPERVISED_OBSERVATION_FAILED;
        process->supervisor_pid = -1;
        if (process->control_fd >= 0) close(process->control_fd);
        process->control_fd = -1;
    }
}

enum platform_supervised_state platform_supervised_poll(struct platform_supervised_process *process)
{
    if (!process) return PLATFORM_SUPERVISED_INVALID;
    if (process->supervisor_pid < 0) return process->observation.state;
    enum platform_supervised_state result = consume(process);
    if (result == PLATFORM_SUPERVISED_OBSERVATION_FAILED)
        process->observation.state = result;
    finish_supervisor(process);
    result = process->observation.state;
    if (result == PLATFORM_SUPERVISED_CLEAN && process->supervisor_pid >= 0)
        return PLATFORM_SUPERVISED_RUNNING;
    return result;
}

enum platform_supervised_state platform_supervised_start(struct platform_supervised_process *process,
    const struct platform_supervised_spec *spec)
{
    if (!process || process->supervisor_pid >= 0 || !spec_valid(spec)) return PLATFORM_SUPERVISED_INVALID;
    struct sigaction disposition;
    if (sigaction(SIGCHLD, NULL, &disposition) < 0 || disposition.sa_handler == SIG_IGN ||
        (disposition.sa_flags & SA_NOCLDWAIT)) return PLATFORM_SUPERVISED_INVALID;
    int probe = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (probe < 0) return PLATFORM_SUPERVISED_UNSUPPORTED;
    bool signals = syscall(SYS_pidfd_send_signal, probe, 0, NULL, 0) == 0;
    close(probe);
    if (!signals) return PLATFORM_SUPERVISED_UNSUPPORTED;
    if (syscall(SYS_close_range, UINT_MAX, UINT_MAX, 0) < 0) return PLATFORM_SUPERVISED_UNSUPPORTED;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) < 0)
        return PLATFORM_SUPERVISED_LAUNCH_FAILED;
    pid_t pid = fork_supervisor(pair[1], pair[0], spec);
    close(pair[1]);
    if (pid < 0) { close(pair[0]); return PLATFORM_SUPERVISED_LAUNCH_FAILED; }
    process->supervisor_pid = pid;
    process->control_fd = pair[0];
    process->observation = (struct platform_supervised_observation){.state = PLATFORM_SUPERVISED_RUNNING};
    while (remaining_ms(spec->launch_deadline_ns)) {
        struct pollfd entry = {.fd = pair[0], .events = POLLIN};
        if (poll(&entry, 1, remaining_ms(spec->launch_deadline_ns)) > 0)
            return platform_supervised_poll(process);
    }
    process->observation.state = PLATFORM_SUPERVISED_INCOMPLETE;
    process->observation.error_number = ETIMEDOUT;
    return PLATFORM_SUPERVISED_INCOMPLETE;
}

enum platform_supervised_state platform_supervised_stop(struct platform_supervised_process *process,
    int64_t deadline_ns)
{
    if (!process) return PLATFORM_SUPERVISED_INVALID;
    if (process->supervisor_pid < 0) return process->observation.state;
    if (process->control_fd >= 0) {
        struct packet request = {.version = PACKET_VERSION, .operation = PACKET_STOP, .deadline = deadline_ns};
        if (!send_packet(process->control_fd, &request))
            process->observation.state = PLATFORM_SUPERVISED_OBSERVATION_FAILED;
    }
    while (remaining_ms(deadline_ns)) {
        enum platform_supervised_state result = platform_supervised_poll(process);
        if (process->supervisor_pid < 0) return result;
        struct pollfd entry = {.fd = process->control_fd, .events = POLLIN};
        (void)poll(&entry, 1, remaining_ms(deadline_ns));
    }
    process->observation.state = PLATFORM_SUPERVISED_INCOMPLETE;
    process->observation.error_number = ETIMEDOUT;
    return PLATFORM_SUPERVISED_INCOMPLETE;
}





#ifdef ZCL_TESTING


#endif
#else
enum platform_supervised_image_result platform_supervised_image_capture(
    const void *bytes, size_t length, const uint8_t expected_sha3[32], int *image_fd)
{
    (void)bytes; (void)length; (void)expected_sha3; (void)image_fd;
    return PLATFORM_SUPERVISED_IMAGE_UNSUPPORTED;
}
enum platform_supervised_state platform_supervised_start(struct platform_supervised_process *process,
    const struct platform_supervised_spec *spec)
{
    (void)process; (void)spec;
    return PLATFORM_SUPERVISED_UNSUPPORTED;
}
enum platform_supervised_state platform_supervised_poll(struct platform_supervised_process *process)
{
    (void)process;
    return PLATFORM_SUPERVISED_UNSUPPORTED;
}
enum platform_supervised_state platform_supervised_stop(struct platform_supervised_process *process,
    int64_t deadline_ns)
{
    (void)process; (void)deadline_ns;
    return PLATFORM_SUPERVISED_UNSUPPORTED;
}


#ifdef ZCL_TESTING


#endif
#endif

void platform_supervised_owner_eof(struct platform_supervised_process *process)
{
#if defined(__linux__)

    if (!process || process->control_fd < 0) return;
    (void)shutdown(process->control_fd, SHUT_WR);
#else

    (void)process;
#endif
}

#ifdef ZCL_TESTING
void platform_supervised_fixture_observation_error_once(void)
{
#if defined(__linux__)
    observation_error_once = true;
#endif
}

void platform_supervised_fixture_cleanup_gate(int fd)
{
#if defined(__linux__)
    retirement_cleanup_gate = fd;
#else
    (void)fd;
#endif
}

bool platform_supervised_fixture_subreaper(void)
{
#if defined(__linux__)
    return prctl(PR_SET_CHILD_SUBREAPER, 1) == 0;
#else
    return false;
#endif
}
#endif

bool platform_supervised_signal(struct platform_supervised_process *process,
    enum platform_supervised_signal signal)
{
#if defined(__linux__)

    if (!process || process->supervisor_pid < 0 || process->control_fd < 0 ||
        process->observation.state != PLATFORM_SUPERVISED_RUNNING || !forwarded_signal(signal)) return false;
    struct packet request = {.version = PACKET_VERSION, .operation = PACKET_SIGNAL, .signal = signal};
    return send_packet(process->control_fd, &request);
#else

    (void)process; (void)signal; return false;
#endif
}

#ifdef ZCL_TESTING
int platform_supervised_fixture_pidfd_open(int64_t owned_pid)
{
#if defined(__linux__)

    if (owned_pid <= 0 || owned_pid > INT_MAX) { errno = EINVAL; return -1; }
    return (int)syscall(SYS_pidfd_open, (pid_t)owned_pid, 0);
#else

    (void)owned_pid; errno = ENOTSUP; return -1;
#endif
}
#endif

#ifdef ZCL_TESTING
bool platform_supervised_fixture_pidfd_kill(int owned_fd)
{
#if defined(__linux__)

    if (owned_fd < 0) { errno = EINVAL; return false; }
    return syscall(SYS_pidfd_send_signal, owned_fd, SIGKILL, NULL, 0) == 0 || errno == ESRCH;
#else

    (void)owned_fd; errno = ENOTSUP; return false;
#endif
}
#endif
