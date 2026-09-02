/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Provides the bounded native GPU implementation of the Equihash solver. */

#include "miner/gpu_equihash.h"
#include "util/safe_alloc.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

typedef int32_t cl_int;
typedef uint32_t cl_uint;
typedef uint64_t cl_ulong;
typedef cl_uint cl_bool;
typedef cl_ulong cl_device_type;
typedef cl_ulong cl_mem_flags;
typedef intptr_t cl_context_properties;
typedef struct _cl_platform_id *cl_platform_id;
typedef struct _cl_device_id *cl_device_id;
typedef struct _cl_context *cl_context;
typedef struct _cl_command_queue *cl_command_queue;
typedef struct _cl_mem *cl_mem;
typedef struct _cl_program *cl_program;
typedef struct _cl_kernel *cl_kernel;
typedef struct _cl_event *cl_event;

#define CL_SUCCESS 0
#define CL_TRUE 1u
#define CL_DEVICE_TYPE_GPU (1ull << 2)
#define CL_MEM_READ_WRITE (1ull << 0)
#define CL_MEM_READ_ONLY (1ull << 2)
#define CL_PLATFORM_NAME 0x0902u
#define CL_DEVICE_MAX_MEM_ALLOC_SIZE 0x1010u
#define CL_DEVICE_GLOBAL_MEM_SIZE 0x101fu
#define CL_DEVICE_MAX_COMPUTE_UNITS 0x1002u
#define CL_DEVICE_ENDIAN_LITTLE 0x1026u
#define CL_DEVICE_NAME 0x102bu
#define CL_DEVICE_VENDOR 0x102cu
#define CL_PROGRAM_BUILD_LOG 0x1183u

#define EH_BUCKETS (1u << 20)
#define EH_SLOTS 64u
#define EH_BLOCKS (1u << 24)
#define EH_MAX_SOLUTIONS 8u
#define EH_D0_CHUNK (1u << 18)
#define EH_BUCKET_CHUNK (1u << 13)

#include "miner/gpu_equihash_kernel.inc"

struct opencl_api {
    cl_int (WINAPI *get_platform_ids)(cl_uint, cl_platform_id *, cl_uint *);
    cl_int (WINAPI *get_platform_info)(cl_platform_id, cl_uint, size_t, void *, size_t *);
    cl_int (WINAPI *get_device_ids)(cl_platform_id, cl_device_type, cl_uint, cl_device_id *, cl_uint *);
    cl_int (WINAPI *get_device_info)(cl_device_id, cl_uint, size_t, void *, size_t *);
    cl_context (WINAPI *create_context)(const cl_context_properties *, cl_uint,
        const cl_device_id *, void *, void *, cl_int *);
    cl_command_queue (WINAPI *create_queue)(cl_context, cl_device_id, cl_ulong, cl_int *);
    cl_program (WINAPI *create_program_source)(cl_context, cl_uint, const char **,
        const size_t *, cl_int *);
    cl_int (WINAPI *build_program)(cl_program, cl_uint, const cl_device_id *,
        const char *, void *, void *);
    cl_int (WINAPI *get_program_build_info)(cl_program, cl_device_id, cl_uint,
        size_t, void *, size_t *);
    cl_kernel (WINAPI *create_kernel)(cl_program, const char *, cl_int *);
    cl_mem (WINAPI *create_buffer)(cl_context, cl_mem_flags, size_t, void *, cl_int *);
    cl_int (WINAPI *set_kernel_arg)(cl_kernel, cl_uint, size_t, const void *);
    cl_int (WINAPI *enqueue_write)(cl_command_queue, cl_mem, cl_bool, size_t,
        size_t, const void *, cl_uint, const cl_event *, cl_event *);
    cl_int (WINAPI *enqueue_read)(cl_command_queue, cl_mem, cl_bool, size_t,
        size_t, void *, cl_uint, const cl_event *, cl_event *);
    cl_int (WINAPI *enqueue_fill)(cl_command_queue, cl_mem, const void *, size_t,
        size_t, size_t, cl_uint, const cl_event *, cl_event *);
    cl_int (WINAPI *enqueue_ndrange)(cl_command_queue, cl_kernel, cl_uint,
        const size_t *, const size_t *, const size_t *, cl_uint,
        const cl_event *, cl_event *);
    cl_int (WINAPI *finish)(cl_command_queue);
    cl_int (WINAPI *release_mem)(cl_mem);
    cl_int (WINAPI *release_kernel)(cl_kernel);
    cl_int (WINAPI *release_program)(cl_program);
    cl_int (WINAPI *release_queue)(cl_command_queue);
    cl_int (WINAPI *release_context)(cl_context);
};

struct z23_gpu_equihash {
    HMODULE library;
    struct opencl_api cl;
    cl_device_id device;
    cl_context context;
    cl_command_queue queue;
    cl_program program;
    cl_kernel digit0;
    cl_kernel digit_round;
    cl_kernel digit_final;
    cl_kernel rebuild;
    cl_mem init_h;
    cl_mem init_t;
    cl_mem init_buf;
    cl_mem heap0;
    cl_mem heap1;
    cl_mem counts;
    cl_mem candidates;
    cl_mem candidate_count;
    cl_mem proofs;
    uint64_t global_memory;
    uint64_t max_allocation;
    bool buffers_ready;
};

static void gpu_equihash_close_native(struct z23_gpu_equihash *gpu);

static void set_error(char *dst, size_t cap, const char *fmt, ...)
{
    if (!dst || cap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(dst, cap, fmt, ap);
    va_end(ap);
    dst[cap - 1] = '\0';
}

static uint64_t tick_us(void)
{
    LARGE_INTEGER now, freq;
    QueryPerformanceCounter(&now);
    QueryPerformanceFrequency(&freq);
    return (uint64_t)((now.QuadPart * 1000000ull) / freq.QuadPart);
}

static bool load_opencl(struct z23_gpu_equihash *g, char *error, size_t cap)
{
    DWORD prior = 0;
    (void)SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX,
                             &prior);
    g->library = LoadLibraryExW(L"OpenCL.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    (void)SetThreadErrorMode(prior, NULL);
    if (!g->library) {
        set_error(error, cap, "OpenCL.dll is unavailable (win32=%lu)",
                  (unsigned long)GetLastError());
        return false;
    }

#define LOAD_CL(field, symbol) do { \
    FARPROC proc = GetProcAddress(g->library, symbol); \
    if (!proc) { set_error(error, cap, "OpenCL entry %s is unavailable", symbol); return false; } \
    _Static_assert(sizeof(proc) == sizeof(g->cl.field), "OpenCL function pointer width"); \
    memcpy(&g->cl.field, &proc, sizeof(proc)); \
} while (0)
    LOAD_CL(get_platform_ids, "clGetPlatformIDs");
    LOAD_CL(get_platform_info, "clGetPlatformInfo");
    LOAD_CL(get_device_ids, "clGetDeviceIDs");
    LOAD_CL(get_device_info, "clGetDeviceInfo");
    LOAD_CL(create_context, "clCreateContext");
    LOAD_CL(create_queue, "clCreateCommandQueue");
    LOAD_CL(create_program_source, "clCreateProgramWithSource");
    LOAD_CL(build_program, "clBuildProgram");
    LOAD_CL(get_program_build_info, "clGetProgramBuildInfo");
    LOAD_CL(create_kernel, "clCreateKernel");
    LOAD_CL(create_buffer, "clCreateBuffer");
    LOAD_CL(set_kernel_arg, "clSetKernelArg");
    LOAD_CL(enqueue_write, "clEnqueueWriteBuffer");
    LOAD_CL(enqueue_read, "clEnqueueReadBuffer");
    LOAD_CL(enqueue_fill, "clEnqueueFillBuffer");
    LOAD_CL(enqueue_ndrange, "clEnqueueNDRangeKernel");
    LOAD_CL(finish, "clFinish");
    LOAD_CL(release_mem, "clReleaseMemObject");
    LOAD_CL(release_kernel, "clReleaseKernel");
    LOAD_CL(release_program, "clReleaseProgram");
    LOAD_CL(release_queue, "clReleaseCommandQueue");
    LOAD_CL(release_context, "clReleaseContext");
#undef LOAD_CL
    return true;
}

static bool device_text(struct z23_gpu_equihash *g, cl_device_id d,
                        cl_uint key, char *out, size_t cap)
{
    if (cap == 0)
        return false;
    out[0] = '\0';
    cl_int rc = g->cl.get_device_info(d, key, cap - 1, out, NULL);
    out[cap - 1] = '\0';
    return rc == CL_SUCCESS;
}

static bool choose_device(struct z23_gpu_equihash *g,
                          struct z23_gpu_equihash_device *out,
                          char *error, size_t cap)
{
    cl_platform_id platforms[16];
    cl_uint np = 0;
    cl_int rc = g->cl.get_platform_ids(16, platforms, &np);
    if (rc != CL_SUCCESS || np == 0) {
        set_error(error, cap, "no OpenCL platform (rc=%d)", rc);
        return false;
    }

    cl_platform_id selected_platform = NULL;
    cl_device_id selected = NULL;
    for (cl_uint p = 0; p < np && p < 16; ++p) {
        cl_device_id devices[16];
        cl_uint nd = 0;
        if (g->cl.get_device_ids(platforms[p], CL_DEVICE_TYPE_GPU,
                                 16, devices, &nd) != CL_SUCCESS)
            continue;
        for (cl_uint d = 0; d < nd && d < 16; ++d) {
            char vendor[128];
            if (!selected) {
                selected = devices[d];
                selected_platform = platforms[p];
            }
            if (device_text(g, devices[d], CL_DEVICE_VENDOR,
                            vendor, sizeof(vendor)) && strstr(vendor, "NVIDIA")) {
                selected = devices[d];
                selected_platform = platforms[p];
                p = np;
                break;
            }
        }
    }
    if (!selected) {
        set_error(error, cap, "no OpenCL GPU device");
        return false;
    }

    cl_bool little = 0;
    if (g->cl.get_device_info(selected, CL_DEVICE_ENDIAN_LITTLE,
                              sizeof(little), &little, NULL) != CL_SUCCESS ||
        !little) {
        set_error(error, cap, "GPU is not little-endian");
        return false;
    }
    g->device = selected;
    (void)g->cl.get_device_info(selected, CL_DEVICE_GLOBAL_MEM_SIZE,
                                sizeof(g->global_memory), &g->global_memory, NULL);
    (void)g->cl.get_device_info(selected, CL_DEVICE_MAX_MEM_ALLOC_SIZE,
                                sizeof(g->max_allocation), &g->max_allocation, NULL);
    if (out) {
        memset(out, 0, sizeof(*out));
        (void)g->cl.get_platform_info(selected_platform, CL_PLATFORM_NAME,
                                      sizeof(out->platform) - 1,
                                      out->platform, NULL);
        (void)device_text(g, selected, CL_DEVICE_VENDOR,
                          out->vendor, sizeof(out->vendor));
        (void)device_text(g, selected, CL_DEVICE_NAME,
                          out->name, sizeof(out->name));
        out->global_memory_bytes = g->global_memory;
        out->max_allocation_bytes = g->max_allocation;
        (void)g->cl.get_device_info(selected, CL_DEVICE_MAX_COMPUTE_UNITS,
                                    sizeof(out->compute_units),
                                    &out->compute_units, NULL);
    }
    return true;
}

static bool build_kernels(struct z23_gpu_equihash *g, char *error, size_t cap)
{
    cl_int rc = CL_SUCCESS;
    g->context = g->cl.create_context(NULL, 1, &g->device, NULL, NULL, &rc);
    if (!g->context || rc != CL_SUCCESS) {
        set_error(error, cap, "clCreateContext failed (rc=%d)", rc);
        return false;
    }
    g->queue = g->cl.create_queue(g->context, g->device, 0, &rc);
    if (!g->queue || rc != CL_SUCCESS) {
        set_error(error, cap, "clCreateCommandQueue failed (rc=%d)", rc);
        return false;
    }
    const char *sources[2] = {
        z23_gpu_equihash_kernel_sources[0],
        z23_gpu_equihash_kernel_sources[1],
    };
    size_t source_len[2] = {
        strlen(sources[0]),
        strlen(sources[1]),
    };
    g->program = g->cl.create_program_source(g->context, 2,
        sources, source_len, &rc);
    if (!g->program || rc != CL_SUCCESS) {
        set_error(error, cap, "clCreateProgramWithSource failed (rc=%d)", rc);
        return false;
    }
    rc = g->cl.build_program(g->program, 1, &g->device,
                             "-cl-std=CL1.2", NULL, NULL);
    if (rc != CL_SUCCESS) {
        char log[4096] = {0};
        (void)g->cl.get_program_build_info(g->program, g->device,
            CL_PROGRAM_BUILD_LOG, sizeof(log) - 1, log, NULL);
        set_error(error, cap, "OpenCL kernel build failed (rc=%d): %.3000s", rc, log);
        return false;
    }
#define MAKE_KERNEL(field, name) do { \
    g->field = g->cl.create_kernel(g->program, name, &rc); \
    if (!g->field || rc != CL_SUCCESS) { set_error(error, cap, "clCreateKernel(%s) failed (rc=%d)", name, rc); return false; } \
} while (0)
    MAKE_KERNEL(digit0, "d0");
    MAKE_KERNEL(digit_round, "dr");
    MAKE_KERNEL(digit_final, "dk");
    MAKE_KERNEL(rebuild, "rebuild");
#undef MAKE_KERNEL
    return true;
}

static struct z23_gpu_equihash *gpu_equihash_open_native(
    struct z23_gpu_equihash_device *device, char *error, size_t error_cap)
{
    if (error && error_cap)
        error[0] = '\0';
    struct z23_gpu_equihash *g = zcl_calloc(1, sizeof(*g), "gpu_equihash");
    if (!g) {
        set_error(error, error_cap, "out of memory opening GPU solver");
        return NULL;
    }
    if (!load_opencl(g, error, error_cap) ||
        !choose_device(g, device, error, error_cap) ||
        !build_kernels(g, error, error_cap)) {
        gpu_equihash_close_native(g);
        return NULL;
    }
    return g;
}

static void release_buffer(struct z23_gpu_equihash *g, cl_mem *buffer)
{
    if (*buffer) {
        (void)g->cl.release_mem(*buffer);
        *buffer = NULL;
    }
}

static bool make_buffer(struct z23_gpu_equihash *g, cl_mem *out,
                        cl_mem_flags flags, size_t bytes,
                        const char *name, char *error, size_t cap)
{
    cl_int rc = CL_SUCCESS;
    *out = g->cl.create_buffer(g->context, flags, bytes, NULL, &rc);
    if (!*out || rc != CL_SUCCESS) {
        set_error(error, cap, "GPU allocation %s (%zu bytes) failed (rc=%d)",
                  name, bytes, rc);
        return false;
    }
    return true;
}

static bool ensure_buffers(struct z23_gpu_equihash *g, char *error, size_t cap)
{
    if (g->buffers_ready)
        return true;
    const size_t heap0_bytes = (size_t)EH_BUCKETS * EH_SLOTS * 7u * 4u;
    const size_t heap1_bytes = (size_t)EH_BUCKETS * EH_SLOTS * 6u * 4u;
    const size_t count_bytes = (size_t)EH_BUCKETS * 2u * 4u;
    const uint64_t required = (uint64_t)heap0_bytes + heap1_bytes +
                              count_bytes + (512ull << 20);
    if (g->max_allocation < heap0_bytes || g->global_memory < required) {
        set_error(error, cap,
            "GPU memory insufficient: need max_alloc>=%zu and global>=%llu; have %llu/%llu",
            heap0_bytes, (unsigned long long)required,
            (unsigned long long)g->max_allocation,
            (unsigned long long)g->global_memory);
        return false;
    }
    if (!make_buffer(g, &g->init_h, CL_MEM_READ_ONLY, 8u * 8u,
                     "BLAKE2b state", error, cap) ||
        !make_buffer(g, &g->init_t, CL_MEM_READ_ONLY, 2u * 8u,
                     "BLAKE2b counter", error, cap) ||
        !make_buffer(g, &g->init_buf, CL_MEM_READ_ONLY, 128u,
                     "BLAKE2b tail", error, cap) ||
        !make_buffer(g, &g->heap0, CL_MEM_READ_WRITE, heap0_bytes,
                     "Equihash heap0", error, cap) ||
        !make_buffer(g, &g->heap1, CL_MEM_READ_WRITE, heap1_bytes,
                     "Equihash heap1", error, cap) ||
        !make_buffer(g, &g->counts, CL_MEM_READ_WRITE, count_bytes,
                     "bucket counters", error, cap) ||
        !make_buffer(g, &g->candidates, CL_MEM_READ_WRITE,
                     EH_MAX_SOLUTIONS * 4u, "candidates", error, cap) ||
        !make_buffer(g, &g->candidate_count, CL_MEM_READ_WRITE,
                     4u, "candidate count", error, cap) ||
        !make_buffer(g, &g->proofs, CL_MEM_READ_WRITE,
                     EH_MAX_SOLUTIONS * 128u * 4u, "proofs", error, cap))
        return false;
    g->buffers_ready = true;
    return true;
}

static bool set_arg(struct z23_gpu_equihash *g, cl_kernel k, cl_uint i,
                    size_t n, const void *p, char *error, size_t cap)
{
    cl_int rc = g->cl.set_kernel_arg(k, i, n, p);
    if (rc != CL_SUCCESS) {
        set_error(error, cap, "clSetKernelArg(%u) failed (rc=%d)", i, rc);
        return false;
    }
    return true;
}

static bool run_kernel(struct z23_gpu_equihash *g, cl_kernel k,
                       size_t global, size_t local,
                       char *error, size_t cap)
{
    cl_int rc = g->cl.enqueue_ndrange(g->queue, k, 1, NULL, &global, &local,
                                      0, NULL, NULL);
    if (rc != CL_SUCCESS) {
        set_error(error, cap, "clEnqueueNDRangeKernel failed (rc=%d global=%zu local=%zu)",
                  rc, global, local);
        return false;
    }
    return true;
}

static bool write_buffer(struct z23_gpu_equihash *g, cl_mem b,
                         const void *src, size_t bytes,
                         char *error, size_t cap)
{
    cl_int rc = g->cl.enqueue_write(g->queue, b, CL_TRUE, 0, bytes, src,
                                    0, NULL, NULL);
    if (rc != CL_SUCCESS) {
        set_error(error, cap, "clEnqueueWriteBuffer failed (rc=%d)", rc);
        return false;
    }
    return true;
}

static bool read_buffer(struct z23_gpu_equihash *g, cl_mem b,
                        void *dst, size_t bytes,
                        char *error, size_t cap)
{
    cl_int rc = g->cl.enqueue_read(g->queue, b, CL_TRUE, 0, bytes, dst,
                                   0, NULL, NULL);
    if (rc != CL_SUCCESS) {
        set_error(error, cap, "clEnqueueReadBuffer failed (rc=%d)", rc);
        return false;
    }
    return true;
}

static bool zero_buffer(struct z23_gpu_equihash *g, cl_mem b, size_t bytes,
                        char *error, size_t cap)
{
    const cl_uint zero = 0;
    cl_int rc = g->cl.enqueue_fill(g->queue, b, &zero, sizeof(zero), 0,
                                   bytes, 0, NULL, NULL);
    if (rc != CL_SUCCESS) {
        set_error(error, cap, "clEnqueueFillBuffer failed (rc=%d)", rc);
        return false;
    }
    return true;
}

static bool proof_indices_distinct(const uint32_t proof[128])
{
    for (size_t i = 0; i < 128u; ++i)
        for (size_t j = i + 1u; j < 128u; ++j)
            if (proof[i] == proof[j])
                return false;
    return true;
}

static bool gpu_equihash_solve_native(
    struct z23_gpu_equihash *g, const struct equihash_params *params,
    const struct blake2b_ctx *base,
    unsigned char solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES],
    struct z23_gpu_equihash_stats *stats, char *error, size_t error_cap)
{
    if (error && error_cap)
        error[0] = '\0';
    if (!g || !params || !base || !solution || params->N != 192 ||
        params->K != 7 || params->solution_width != 400 ||
        base->buflen + 4u > sizeof(base->buf)) {
        set_error(error, error_cap, "GPU solver requires a valid N=192,K=7 base state");
        return false;
    }
    struct z23_gpu_equihash_stats local_stats;
    memset(&local_stats, 0, sizeof(local_stats));
    uint64_t all_start = tick_us();
    if (!ensure_buffers(g, error, error_cap))
        return false;

    const size_t count_bytes = (size_t)EH_BUCKETS * 2u * 4u;
    if (!write_buffer(g, g->init_h, base->h, sizeof(base->h), error, error_cap) ||
        !write_buffer(g, g->init_t, base->t, sizeof(base->t), error, error_cap) ||
        !write_buffer(g, g->init_buf, base->buf, sizeof(base->buf), error, error_cap) ||
        !zero_buffer(g, g->counts, count_bytes, error, error_cap) ||
        !zero_buffer(g, g->candidate_count, 4u, error, error_cap))
        return false;

    cl_uint buflen = (cl_uint)base->buflen;
    if (!set_arg(g, g->digit0, 0, sizeof(g->init_h), &g->init_h, error, error_cap) ||
        !set_arg(g, g->digit0, 1, sizeof(g->init_t), &g->init_t, error, error_cap) ||
        !set_arg(g, g->digit0, 2, sizeof(g->init_buf), &g->init_buf, error, error_cap) ||
        !set_arg(g, g->digit0, 3, sizeof(buflen), &buflen, error, error_cap) ||
        !set_arg(g, g->digit0, 5, sizeof(g->heap0), &g->heap0, error, error_cap) ||
        !set_arg(g, g->digit0, 6, sizeof(g->counts), &g->counts, error, error_cap))
        return false;

    uint64_t stage = tick_us();
    for (cl_uint base_index = 0; base_index < EH_BLOCKS; base_index += EH_D0_CHUNK) {
        size_t global = EH_D0_CHUNK;
        if (!set_arg(g, g->digit0, 4, sizeof(base_index), &base_index,
                     error, error_cap) ||
            !run_kernel(g, g->digit0, global, 256u, error, error_cap))
            return false;
    }
    if (g->cl.finish(g->queue) != CL_SUCCESS) {
        set_error(error, error_cap, "clFinish after digit0 failed");
        return false;
    }
    local_stats.initial_hash_us = tick_us() - stage;

    for (cl_uint round = 1; round < 7; ++round) {
        if (!set_arg(g, g->digit_round, 0, sizeof(round), &round, error, error_cap) ||
            !set_arg(g, g->digit_round, 2, sizeof(g->heap0), &g->heap0, error, error_cap) ||
            !set_arg(g, g->digit_round, 3, sizeof(g->heap1), &g->heap1, error, error_cap) ||
            !set_arg(g, g->digit_round, 4, sizeof(g->counts), &g->counts, error, error_cap))
            return false;
        stage = tick_us();
        for (cl_uint bucket = 0; bucket < EH_BUCKETS; bucket += EH_BUCKET_CHUNK) {
            size_t global = (size_t)EH_BUCKET_CHUNK * EH_SLOTS;
            if (!set_arg(g, g->digit_round, 1, sizeof(bucket), &bucket,
                         error, error_cap) ||
                !run_kernel(g, g->digit_round, global, EH_SLOTS,
                            error, error_cap))
                return false;
        }
        if (g->cl.finish(g->queue) != CL_SUCCESS) {
            set_error(error, error_cap, "clFinish after collision round %u failed", round);
            return false;
        }
        local_stats.collision_round_us[round - 1] = tick_us() - stage;
    }

    if (!set_arg(g, g->digit_final, 1, sizeof(g->heap0), &g->heap0, error, error_cap) ||
        !set_arg(g, g->digit_final, 2, sizeof(g->counts), &g->counts, error, error_cap) ||
        !set_arg(g, g->digit_final, 3, sizeof(g->candidates), &g->candidates, error, error_cap) ||
        !set_arg(g, g->digit_final, 4, sizeof(g->candidate_count), &g->candidate_count,
                 error, error_cap))
        return false;
    stage = tick_us();
    for (cl_uint bucket = 0; bucket < EH_BUCKETS; bucket += EH_BUCKET_CHUNK) {
        size_t global = (size_t)EH_BUCKET_CHUNK * EH_SLOTS;
        if (!set_arg(g, g->digit_final, 0, sizeof(bucket), &bucket, error, error_cap) ||
            !run_kernel(g, g->digit_final, global, EH_SLOTS, error, error_cap))
            return false;
    }
    if (g->cl.finish(g->queue) != CL_SUCCESS) {
        set_error(error, error_cap, "clFinish after final collision round failed");
        return false;
    }
    local_stats.collision_round_us[6] = tick_us() - stage;

    cl_uint candidate_count = 0;
    if (!read_buffer(g, g->candidate_count, &candidate_count,
                     sizeof(candidate_count), error, error_cap))
        return false;
    local_stats.candidates = candidate_count;
    cl_uint retained = candidate_count > EH_MAX_SOLUTIONS ? EH_MAX_SOLUTIONS : candidate_count;
    if (retained > 0) {
        if (!set_arg(g, g->rebuild, 0, sizeof(g->heap0), &g->heap0, error, error_cap) ||
            !set_arg(g, g->rebuild, 1, sizeof(g->heap1), &g->heap1, error, error_cap) ||
            !set_arg(g, g->rebuild, 2, sizeof(g->candidates), &g->candidates, error, error_cap) ||
            !set_arg(g, g->rebuild, 3, sizeof(retained), &retained, error, error_cap) ||
            !set_arg(g, g->rebuild, 4, sizeof(g->proofs), &g->proofs, error, error_cap) ||
            !run_kernel(g, g->rebuild, retained, 1u, error, error_cap) ||
            g->cl.finish(g->queue) != CL_SUCCESS) {
            if (!error || !error[0])
                set_error(error, error_cap, "GPU proof reconstruction failed");
            return false;
        }
        uint32_t proofs[EH_MAX_SOLUTIONS][128];
        if (!read_buffer(g, g->proofs, proofs,
                         retained * 128u * sizeof(uint32_t), error, error_cap))
            return false;
        for (cl_uint i = 0; i < retained; ++i) {
            unsigned char candidate[Z23_GPU_EQUIHASH_SOLUTION_BYTES];
            if (!proof_indices_distinct(proofs[i]))
                continue;
            size_t got = eh_get_minimal_from_indices(
                proofs[i], 128u, params->collision_bit_length,
                candidate, sizeof(candidate));
            if (got != sizeof(candidate) ||
                !equihash_is_valid_solution(params, base, candidate, got))
                continue;
            if (local_stats.valid_solutions == 0)
                memcpy(solution, candidate, sizeof(candidate));
            local_stats.valid_solutions++;
        }
    }
    local_stats.elapsed_us = tick_us() - all_start;
    if (stats)
        *stats = local_stats;
    if (local_stats.valid_solutions == 0) {
        set_error(error, error_cap,
                  "GPU completed the nonce but found no valid Equihash solution (%u candidates)",
                  candidate_count);
        return false;
    }
    return true;
}

static void gpu_equihash_close_native(struct z23_gpu_equihash *g)
{
    if (!g)
        return;
    if (g->library) {
        release_buffer(g, &g->proofs);
        release_buffer(g, &g->candidate_count);
        release_buffer(g, &g->candidates);
        release_buffer(g, &g->counts);
        release_buffer(g, &g->heap1);
        release_buffer(g, &g->heap0);
        release_buffer(g, &g->init_buf);
        release_buffer(g, &g->init_t);
        release_buffer(g, &g->init_h);
        if (g->rebuild) (void)g->cl.release_kernel(g->rebuild);
        if (g->digit_final) (void)g->cl.release_kernel(g->digit_final);
        if (g->digit_round) (void)g->cl.release_kernel(g->digit_round);
        if (g->digit0) (void)g->cl.release_kernel(g->digit0);
        if (g->program) (void)g->cl.release_program(g->program);
        if (g->queue) (void)g->cl.release_queue(g->queue);
        if (g->context) (void)g->cl.release_context(g->context);
        FreeLibrary(g->library);
    }
    free(g);
}

#else

struct z23_gpu_equihash { int unavailable; };

static struct z23_gpu_equihash *gpu_equihash_open_native(
    struct z23_gpu_equihash_device *device, char *error, size_t error_cap)
{
    (void)device;
    if (error && error_cap)
        (void)snprintf(error, error_cap,
                       "GPU Equihash is currently qualified only on native Windows");
    return NULL;
}

static bool gpu_equihash_solve_native(
    struct z23_gpu_equihash *gpu, const struct equihash_params *params,
    const struct blake2b_ctx *base_state,
    unsigned char solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES],
    struct z23_gpu_equihash_stats *stats, char *error, size_t error_cap)
{
    (void)gpu; (void)params; (void)base_state; (void)solution; (void)stats;
    if (error && error_cap)
        (void)snprintf(error, error_cap,
                       "GPU Equihash is currently qualified only on native Windows");
    return false;
}

static void gpu_equihash_close_native(struct z23_gpu_equihash *gpu)
{
    (void)gpu;
}

#endif

struct z23_gpu_equihash *z23_gpu_equihash_open(
    struct z23_gpu_equihash_device *device, char *error, size_t error_cap)
{
    return gpu_equihash_open_native(device, error, error_cap);
}

bool z23_gpu_equihash_solve(
    struct z23_gpu_equihash *gpu, const struct equihash_params *params,
    const struct blake2b_ctx *base_state,
    unsigned char solution[Z23_GPU_EQUIHASH_SOLUTION_BYTES],
    struct z23_gpu_equihash_stats *stats, char *error, size_t error_cap)
{
    return gpu_equihash_solve_native(gpu, params, base_state, solution, stats,
                                     error, error_cap);
}

void z23_gpu_equihash_close(struct z23_gpu_equihash *gpu)
{
    gpu_equihash_close_native(gpu);
}
