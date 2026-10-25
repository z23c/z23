/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. */
/* Native byte/replay/recovery proof; the POSIX kill9 lane remains separate. */
#if defined(_WIN32)
#include "storage/event_log.h"
#include "platform/private_file.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "event_log_windows_acceptance: line %d: %s\n", \
            __LINE__, #expr); return false; } } while (0)

struct fixture {
    wchar_t dir[MAX_PATH], file[MAX_PATH], receipt[MAX_PATH];
    char path[MAX_PATH * 4];
    event_log_t *log;
    uint64_t second, third, end;
};

static bool fixture_open(struct fixture *f)
{
    wchar_t temp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, temp);
    CHECK(n > 0 && n < MAX_PATH);
    CHECK(GetTempFileNameW(temp, L"zel", 0, f->dir));
    CHECK(DeleteFileW(f->dir));
    CHECK(CreateDirectoryW(f->dir, NULL));
    CHECK(swprintf(f->file, MAX_PATH, L"%ls/events.log", f->dir) > 0);
    CHECK(swprintf(f->receipt, MAX_PATH, L"%ls.verified", f->file) > 0);
    CHECK(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, f->file, -1,
                             f->path, sizeof(f->path), NULL, NULL) > 0);
    f->log = event_log_open(f->path);
    CHECK(f->log);
    return true;
}

static bool fixture_roundtrip(struct fixture *f)
{
    static const unsigned char data[] = {0, 255, 1, 128};
    CHECK(event_log_append(f->log, EV_PEER_OBSERVED, "abc", 3) == 0);
    f->second = EVENT_LOG_FRAME_OVERHEAD + 3;
    CHECK(event_log_append(f->log, EV_PEER_DROPPED, NULL, 0) == f->second);
    f->third = f->second + EVENT_LOG_FRAME_OVERHEAD;
    CHECK(event_log_append(f->log, EV_BLOCK_STATUS, data, sizeof(data)) == f->third);
    f->end = f->third + EVENT_LOG_FRAME_OVERHEAD + sizeof(data);
    CHECK(event_log_size(f->log) == f->end);
    unsigned char got[4] = {0};
    size_t len = 0;
    enum event_log_type type = 0;
    CHECK(event_log_read(f->log, f->third, &type, got, sizeof(got), &len) == 0);
    CHECK(type == EV_BLOCK_STATUS && len == sizeof(data));
    CHECK(memcmp(got, data, sizeof(data)) == 0);
    CHECK(event_log_read(f->log, f->third, NULL, got, 3, NULL) == -1);
    CHECK(event_log_read(f->log, f->end, NULL, got, sizeof(got), NULL) == -1);
    return true;
}

struct stream_check { unsigned count, stop; uint64_t offset; bool valid; };

static bool check_record(uint64_t off, enum event_log_type type,
                         const void *data, size_t len, void *user)
{
    struct stream_check *s = user;
    static const struct {
        enum event_log_type type;
        size_t len;
        unsigned char bytes[4];
    } expected[] = {
        {EV_PEER_OBSERVED, 3, {'a', 'b', 'c'}},
        {EV_PEER_DROPPED, 0, {0}},
        {EV_BLOCK_STATUS, 4, {0, 255, 1, 128}},
    };
    bool valid = s->count < sizeof(expected) / sizeof(expected[0]);
    if (valid) {
        valid = type == expected[s->count].type && len == expected[s->count].len;
        if (valid)
            valid = len ? data && memcmp(data, expected[s->count].bytes, len) == 0
                        : data == NULL;
    }
    s->valid = s->valid && valid && off == s->offset;
    s->offset += EVENT_LOG_FRAME_OVERHEAD + len;
    s->count++;
    return s->valid && s->count < s->stop;
}

static bool fixture_reopen_stream(struct fixture *f)
{
    uint8_t before[32], after[32];
    CHECK(event_log_fingerprint(f->log, before) == 0);
    event_log_close(f->log);
    f->log = event_log_open(f->path);
    CHECK(f->log && event_log_size(f->log) == f->end);
    CHECK(event_log_fingerprint(f->log, after) == 0);
    CHECK(memcmp(before, after, sizeof(before)) == 0);
    struct stream_check all = {.stop = 4, .valid = true};
    CHECK(event_log_stream(f->log, 0, check_record, &all) == 0);
    CHECK(all.valid && all.count == 3 && all.offset == f->end);
    struct stream_check stop = {.stop = 1, .valid = true};
    CHECK(event_log_stream(f->log, 0, check_record, &stop) == 0);
    CHECK(stop.valid && stop.count == 1 && stop.offset == f->second);
    struct stream_check suffix = {.count = 1, .stop = 4,
                                  .offset = f->second, .valid = true};
    CHECK(event_log_stream(f->log, f->second, check_record, &suffix) == 0);
    CHECK(suffix.valid && suffix.count == 3 && suffix.offset == f->end);
    return true;
}

static bool fixture_damage(struct fixture *f, uint64_t off)
{
    event_log_close(f->log);
    f->log = NULL;
    struct platform_private_file file;
    platform_private_file_init(&file);
    CHECK(platform_private_file_open_locked(f->path, &file));
    const unsigned char bad = 42;
    bool ok = platform_private_file_write_at(&file, &bad, 1, off) &&
              platform_private_file_flush(&file);
    platform_private_file_close(&file);
    CHECK(ok);
    f->log = event_log_open(f->path);
    CHECK(f->log);
    return true;
}

static bool fixture_recovery(struct fixture *f)
{
    CHECK(fixture_damage(f, f->end)); /* one-byte torn header after prefix */
    CHECK(event_log_size(f->log) == f->end);
    CHECK(fixture_damage(f, f->third + 16 + 4)); /* last sentinel magic */
    CHECK(event_log_size(f->log) == f->third);
    static const unsigned char restored[] = {0, 255, 1, 128};
    CHECK(event_log_append(f->log, EV_BLOCK_STATUS, restored,
                           sizeof(restored)) == f->third);
    CHECK(fixture_damage(f, f->third + 16)); /* last payload CRC mismatch */
    CHECK(event_log_size(f->log) == f->third);
    char data[3];
    CHECK(event_log_read(f->log, 0, NULL, data, sizeof(data), NULL) == 0);
    CHECK(memcmp(data, "abc", sizeof(data)) == 0);
    CHECK(event_log_append(f->log, EV_PEER_OBSERVED, "new", 3) == f->third);
    return true;
}

static bool fixture_deferred(struct fixture *f)
{
    unsigned char payload[8192], got[sizeof(payload)];
    memset(payload, 0xa5, sizeof(payload));
    uint64_t off = event_log_size(f->log);
    event_log_set_deferred_sync(f->log, true);
    CHECK(event_log_deferred_sync_enabled(f->log));
    CHECK(event_log_append(f->log, EV_PEER_OBSERVED, payload, sizeof(payload)) == off);
    CHECK(event_log_size(f->log) == off);
    CHECK(event_log_flush(f->log));
    CHECK(event_log_size(f->log) == off + EVENT_LOG_FRAME_OVERHEAD + sizeof(payload));
    event_log_close(f->log);
    f->log = event_log_open(f->path);
    CHECK(f->log);
    size_t len = 0;
    CHECK(event_log_read(f->log, off, NULL, got, sizeof(got), &len) == 0);
    CHECK(len == sizeof(payload) && memcmp(got, payload, sizeof(payload)) == 0);
    return true;
}

static bool fixture_cleanup(struct fixture *f)
{
    event_log_close(f->log);
    f->log = NULL;
    if (f->file[0] && GetFileAttributesW(f->file) != INVALID_FILE_ATTRIBUTES)
        CHECK(DeleteFileW(f->file));
    if (f->receipt[0] && GetFileAttributesW(f->receipt) != INVALID_FILE_ATTRIBUTES)
        CHECK(DeleteFileW(f->receipt));
    if (f->dir[0]) CHECK(RemoveDirectoryW(f->dir));
    return true;
}

int main(void)
{
    struct fixture f = {0};
    /* Isolate the fixture from an operator's per-append kill switch. */
    if (_putenv_s("ZCL_EVENTLOG_SYNC_PER_APPEND", "") != 0) {
        fputs("event_log_windows_acceptance: cannot isolate sync mode\n", stderr);
        return 1;
    }
    bool ok = fixture_open(&f) && fixture_roundtrip(&f) &&
              fixture_reopen_stream(&f) && fixture_recovery(&f) &&
              fixture_deferred(&f);
    bool cleaned = fixture_cleanup(&f);
    ok = ok && cleaned;
    if (!ok) return 1;
    puts("event_log_windows_acceptance: PASS (roundtrip, replay, reopen, recovery, deferred flush)");
    return 0;
}
#else
typedef int event_log_windows_acceptance_not_built;
#endif
