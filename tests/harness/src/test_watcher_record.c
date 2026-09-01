/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: proves the durable watcher-record codec round-trips exactly,
 * refuses every malformed encoding it is handed, and rejects a binding that
 * differs from the record in any single member.
 *
 * Rehomed from platform/modules/platform/tests/test_watcher_record.c, which NOTHING read:
 * it was in no windows_acceptance.mk row, no Makefile rule and not in the
 * files list of platform/modules/platform/zcode-package.json. As a registered group it
 * executes on every suite run. platform_watcher_record.c is pure, bounded and
 * carries no _WIN32 arm at all, so the whole program runs natively here --
 * the probe body below is the original main() verbatim, CHECK macro and all,
 * including the Windows-shaped canonical paths, which are just opaque
 * printable byte strings to this codec. */
#include "test/test_core.h"

#include "platform/watcher_record.h"

#include <stdio.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed line %d: %s\n", __LINE__, #x); return 1; } } while (0)

static struct platform_watcher_record example(void)
{
    struct platform_watcher_record r = {
        .version=1, .pid=42, .start_token=987654321,
        .mode=PLATFORM_WATCHER_MODE_VERIFY,
        .root_identity={7,8,9}, .image_identity={10,11,12},
        .image_size=123456, .state=PLATFORM_WATCHER_STATE_READY
    };
    memset(r.nonce,'a',64); r.nonce[64]=0;
    memset(r.image_sha256,'b',64); r.image_sha256[64]=0;
    strcpy(r.canonical_root,"C:\\Users\\dev\\z23");
    strcpy(r.canonical_image,"C:\\Users\\dev\\z23\\z23-dev.exe");
    return r;
}

static struct platform_watcher_record_binding binding(const struct platform_watcher_record *r)
{
    struct platform_watcher_record_binding b = {0};
    strcpy(b.nonce,r->nonce); b.pid=r->pid; b.start_token=r->start_token;
    b.mode=r->mode; strcpy(b.canonical_root,r->canonical_root);
    b.root_identity=r->root_identity; strcpy(b.canonical_image,r->canonical_image);
    b.image_identity=r->image_identity; b.image_size=r->image_size;
    strcpy(b.image_sha256,r->image_sha256); b.state=r->state; return b;
}

static int watcher_record_probe(void)
{
    struct platform_watcher_record original=example(), decoded;
    char text[PLATFORM_WATCHER_RECORD_ENCODED_MAX]; size_t used=0;
    CHECK(platform_watcher_record_serialize(&original,text,sizeof(text),&used));
    char tiny[32]; size_t tiny_n=99;
    CHECK(!platform_watcher_record_serialize(&original,tiny,sizeof(tiny),&tiny_n));
    CHECK(tiny_n==0 && tiny[0]==0);
    CHECK(used==strlen(text));
    CHECK(platform_watcher_record_parse(text,used,&decoded));
    struct platform_watcher_record_binding b=binding(&original);
    CHECK(platform_watcher_record_matches(&decoded,&b));
    char again[PLATFORM_WATCHER_RECORD_ENCODED_MAX]; size_t again_n=0;
    CHECK(platform_watcher_record_serialize(&decoded,again,sizeof(again),&again_n));
    CHECK(again_n==used && memcmp(text,again,used)==0);

    CHECK(!platform_watcher_record_parse(text,used-1,&decoded));
    char bad[PLATFORM_WATCHER_RECORD_ENCODED_MAX]; memcpy(bad,text,used+1);
    char *p=strstr(bad,"pid=42"); CHECK(p); p[4]='0';
    CHECK(!platform_watcher_record_parse(bad,used,&decoded)); /* leading zero */
    memcpy(bad,text,used+1); p=strstr(bad,"mode=verify"); CHECK(p); p[5]='x';
    CHECK(!platform_watcher_record_parse(bad,used,&decoded));
    memcpy(bad,text,used+1); bad[used-1]='x';
    CHECK(!platform_watcher_record_parse(bad,used,&decoded));
    memcpy(bad,text,used+1); bad[20]='X';
    CHECK(!platform_watcher_record_parse(bad,used,&decoded));
    CHECK(!platform_watcher_record_parse(text,PLATFORM_WATCHER_RECORD_ENCODED_MAX,&decoded));

    b=binding(&original); b.pid++; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.start_token++; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.root_identity.file_low++; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.image_identity.volume++; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.canonical_root[3]='X'; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.canonical_image[3]='X'; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.image_sha256[0]='c'; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.nonce[0]='c'; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.mode=PLATFORM_WATCHER_MODE_AUTO; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.state=PLATFORM_WATCHER_STATE_STOPPING; CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); memset(b.nonce,'a',sizeof(b.nonce)); CHECK(!platform_watcher_record_matches(&original,&b));
    b=binding(&original); b.image_size=0; CHECK(!platform_watcher_record_matches(&original,&b));

    original.nonce[0]='A'; CHECK(!platform_watcher_record_is_valid(&original));
    original=example(); original.canonical_root[2]='\n'; CHECK(!platform_watcher_record_is_valid(&original));
    original=example(); original.start_token=0; CHECK(!platform_watcher_record_is_valid(&original));
    return 0;
}

#undef CHECK

int test_watcher_record(void)
{
    int failures = 0;
    printf("watcher_record: exact round-trip, malformed-encoding refusals, "
           "per-member binding mismatch... ");
    if (watcher_record_probe() == 0) {
        printf("OK\n");
    } else {
        printf("FAIL\n");
        failures++;
    }
    return failures;
}
