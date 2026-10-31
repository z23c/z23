/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "clip_store.h"
#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* SHA3-512 of "abc" from FIPS 202. */
#define ABC_ID "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" \
               "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"

static char root[512];

static void put(const char *path, const char *bytes)
{
    FILE *f = fopen(path, "wb");
    assert(f != NULL && fputs(bytes, f) >= 0 && fclose(f) == 0);
}
static bool present(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}
static void path_of(char *out, size_t cap, const char *name)
{
    assert(snprintf(out, cap, "%s/%s", root, name) < (int)cap);
}
static struct zapp_clip_meta meta_of(uint8_t level, int64_t created)
{
    struct zapp_clip_meta m = {.level = level, .created_at = created, .duration_ms = 1500};
    snprintf(m.caption, sizeof(m.caption), "clip %lld", (long long)created);
    return m;
}
static bool commit(const char *bytes, const struct zapp_clip_meta *meta, char id[ZAPP_CLIP_ID_CAP])
{
    char source[600], error[128];
    path_of(source, sizeof(source), "pending.mp4");
    put(source, bytes);
    return zapp_clip_store_commit(root, source, meta, id, error, sizeof(error));
}
static size_t entries_ending(const char *suffix)
{
    DIR *d = opendir(root);
    size_t n = 0, tail = strlen(suffix);
    assert(d != NULL);
    for (const struct dirent *e; (e = readdir(d)) != NULL;) {
        size_t len = strlen(e->d_name);
        if (len >= tail && !strcmp(e->d_name + len - tail, suffix)) ++n;
    }
    closedir(d);
    return n;
}

static void id_cases(void)
{
    assert(zapp_clip_id_valid(ABC_ID));
    assert(!zapp_clip_id_valid(NULL));
    assert(!zapp_clip_id_valid(""));
    assert(!zapp_clip_id_valid(ABC_ID "0"));
    assert(!zapp_clip_id_valid(&ABC_ID[1]));
    char upper[ZAPP_CLIP_ID_CAP], odd[ZAPP_CLIP_ID_CAP];
    strcpy(upper, ABC_ID); upper[0] = 'B';
    strcpy(odd, ABC_ID); odd[5] = 'g';
    assert(!zapp_clip_id_valid(upper) && !zapp_clip_id_valid(odd));
    char path[600], id[ZAPP_CLIP_ID_CAP];
    path_of(path, sizeof(path), "abc.bin");
    put(path, "abc");
    assert(zapp_clip_hash_file(path, id) && !strcmp(id, ABC_ID));
    path_of(path, sizeof(path), "missing.bin");
    assert(!zapp_clip_hash_file(path, id));
}

static void refusal_cases(void)
{
    char id[ZAPP_CLIP_ID_CAP], source[600];
    struct zapp_clip_meta m = meta_of(0, 10);
    assert(!zapp_clip_meta_valid(&m));
    assert(!commit("abc", &m, id));
    path_of(source, sizeof(source), "pending.mp4");
    assert(present(source));
    char media[600];
    path_of(media, sizeof(media), ABC_ID ".mp4");
    assert(!present(media));
    m = meta_of(6, 10); assert(!zapp_clip_meta_valid(&m));
    m = meta_of(1, 10); m.descriptors = 0x80; assert(!zapp_clip_meta_valid(&m));
    m = meta_of(1, 10); m.descriptors = 0x7f; assert(zapp_clip_meta_valid(&m));
    m = meta_of(1, 10); m.duration_ms = 0; assert(!zapp_clip_meta_valid(&m));
    m = meta_of(1, 10); memset(m.caption, 'x', sizeof(m.caption)); assert(!zapp_clip_meta_valid(&m));
    m = meta_of(5, 10); assert(zapp_clip_meta_valid(&m));
    assert(!zapp_clip_meta_valid(NULL));
    assert(entries_ending(".json") == 0);
    assert(unlink(source) == 0);
}

static void commit_and_tamper_cases(void)
{
    char id[ZAPP_CLIP_ID_CAP], path[600], error[128];
    struct zapp_clip_meta m = meta_of(3, 1000);
    m.descriptors = 0x09;
    snprintf(m.caption, sizeof(m.caption), "quote \" slash \\ line\nbreak \xc3\xa9");
    assert(commit("abc", &m, id));
    assert(!strcmp(id, ABC_ID));
    path_of(path, sizeof(path), "pending.mp4");
    assert(!present(path));
    path_of(path, sizeof(path), ABC_ID ".mp4");
    assert(present(path));
    path_of(path, sizeof(path), ABC_ID ".json");
    assert(present(path));
    assert(entries_ending(".tmp") == 0);
    struct zapp_clip list[4];
    assert(zapp_clip_store_list(root, list, 4) == 1);
    assert(!strcmp(list[0].id, ABC_ID) && list[0].meta.level == 3 && list[0].meta.descriptors == 0x09);
    assert(list[0].meta.created_at == 1000 && list[0].meta.duration_ms == 1500);
    assert(!strcmp(list[0].meta.caption, m.caption));
    assert(zapp_clip_store_verify(root, ABC_ID, error, sizeof(error)));
    path_of(path, sizeof(path), ABC_ID ".mp4");
    put(path, "abd");
    assert(!zapp_clip_store_verify(root, ABC_ID, error, sizeof(error)) && strstr(error, "changed"));
    put(path, "abc");
    assert(zapp_clip_store_verify(root, ABC_ID, error, sizeof(error)));
    assert(!zapp_clip_store_verify(root, "../etc", error, sizeof(error)));
}

static void order_and_bound_cases(void)
{
    char id[ZAPP_CLIP_ID_CAP], body[16];
    for (int i = 1; i <= 5; ++i) {
        struct zapp_clip_meta m = meta_of((uint8_t)i, 100 * i);
        snprintf(body, sizeof(body), "clip-%d", i);
        assert(commit(body, &m, id));
    }
    struct zapp_clip list[16];
    assert(zapp_clip_store_list(root, list, 16) == 6);
    for (size_t i = 1; i < 6; ++i) assert(list[i - 1].meta.created_at >= list[i].meta.created_at);
    assert(list[0].meta.created_at == 1000 && list[1].meta.created_at == 500);
    assert(zapp_clip_store_list(root, list, 3) == 3);
    assert(list[0].meta.created_at == 1000 && list[1].meta.created_at == 500 && list[2].meta.created_at == 400);
    assert(zapp_clip_store_list(root, list, 1) == 1 && list[0].meta.created_at == 1000);
    for (size_t max = 1; max <= 3; max += 2) {
        for (size_t i = 0; i < 16; ++i) list[i].id[0] = 'S';
        assert(zapp_clip_store_list(root, list, max) == max);
        for (size_t i = max; i < 16; ++i) assert(list[i].id[0] == 'S');
    }
    assert(zapp_clip_store_list(root, list, 0) == 0);
    struct zapp_clip_meta tie = meta_of(2, 500);
    assert(commit("tied", &tie, id));
    assert(zapp_clip_store_list(root, list, 16) == 7);
    assert(list[1].meta.created_at == 500 && list[2].meta.created_at == 500 && strcmp(list[1].id, list[2].id) < 0);
}

static void skip_and_delete_cases(void)
{
    char path[600], orphan[ZAPP_CLIP_ID_CAP];
    memset(orphan, 'a', ZAPP_CLIP_ID_LEN); orphan[ZAPP_CLIP_ID_LEN] = '\0';
    char name[200];
    snprintf(name, sizeof(name), "%s.json", orphan);
    path_of(path, sizeof(path), name);
    put(path, "{\"level\":1,\"descriptors\":0,\"caption\":\"\",\"created_at\":9999,\"duration_ms\":10}");
    path_of(path, sizeof(path), "notes.json");
    put(path, "{}");
    struct zapp_clip list[16];
    assert(zapp_clip_store_list(root, list, 16) == 7);
    snprintf(name, sizeof(name), "%s.mp4", orphan);
    path_of(path, sizeof(path), name);
    put(path, "x");
    assert(zapp_clip_store_list(root, list, 16) == 8 && list[0].meta.created_at == 9999);
    snprintf(name, sizeof(name), "%s.json", orphan);
    path_of(path, sizeof(path), name);
    put(path, "{\"level\":0,\"descriptors\":0,\"caption\":\"\",\"created_at\":9999,\"duration_ms\":10}");
    assert(zapp_clip_store_list(root, list, 16) == 7);
    assert(zapp_clip_store_delete(root, orphan));
    assert(zapp_clip_store_delete(root, ABC_ID));
    assert(zapp_clip_store_list(root, list, 16) == 6);
    path_of(path, sizeof(path), ABC_ID ".mp4");
    assert(!present(path));
    assert(!zapp_clip_store_delete(root, "short"));
}

static void rollback_case(void)
{
    char id[ZAPP_CLIP_ID_CAP], path[600], source[600], error[128];
    path_of(path, sizeof(path), "rollback.mp4");
    put(path, "rollback");
    char hashed[ZAPP_CLIP_ID_CAP];
    assert(zapp_clip_hash_file(path, hashed));
    char name[200];
    snprintf(name, sizeof(name), "%s.json", hashed);
    path_of(source, sizeof(source), name);
    assert(mkdir(source, 0700) == 0);
    struct zapp_clip_meta m = meta_of(2, 7);
    assert(!zapp_clip_store_commit(root, path, &m, id, error, sizeof(error)));
    assert(present(path));
    snprintf(name, sizeof(name), "%s.mp4", hashed);
    path_of(source, sizeof(source), name);
    assert(!present(source));
    snprintf(name, sizeof(name), "%s.json", hashed);
    path_of(source, sizeof(source), name);
    assert(rmdir(source) == 0 && unlink(path) == 0);
}

int main(int argc, char **argv)
{
    if (argc != 2 || snprintf(root, sizeof(root), "%s/clips", argv[1]) >= (int)sizeof(root)) return 2;
    assert(mkdir(root, 0700) == 0);
    id_cases();
    refusal_cases();
    commit_and_tamper_cases();
    order_and_bound_cases();
    skip_and_delete_cases();
    rollback_case();
    puts("clip_store_test ok");
    return 0;
}
