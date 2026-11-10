/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Host controls of the actual preparation body; no guest/Capsicum proof. */
static struct {
    unsigned event, fail_event, clocks, fail_clock, closes, writes, syncs;
    unsigned short_write, interrupted;
    bool valid, clock_error, zero_write, expired, wrong_type, wrong_size;
    int fd;
    size_t bytes;
    char trace[64];
} gp;
static bool gp_event(char event)
{
    if (event=='W' || event=='F') gp.valid &= !gp.expired;
    if (gp.event >= sizeof gp.trace - 1) { gp.valid=false; return false; }
    gp.trace[gp.event++]=event;
    return gp.event != gp.fail_event;
}
static int gp_open(const char *path, int flags)
{
    gp.valid &= strcmp(path,"/dev/vtbd0.eli")==0 && flags==(O_RDWR|O_CLOEXEC);
    return gp_event('O') ? gp.fd : -1;
}
static int gp_stat(int fd, struct stat *st)
{
    gp.valid &= fd==3; st->st_mode=gp.wrong_type ? S_IFREG : S_IFCHR;
    return gp_event('T') ? 0 : -1;
}
static int gp_size(int fd, off_t *size)
{
    gp.valid &= fd==3; *size=gp.wrong_size ? 14909439 : 14909440;
    return gp_event('M') ? 0 : -1;
}
static bool gp_confine(int fd)
{
    gp.valid &= fd==3;
    return gp_event('C');
}
static ssize_t gp_write(int fd, const void *bytes, size_t size, off_t offset)
{
    static const off_t pages[]={8192,12288,61440,65536,69632};
    gp.valid &= fd==3 && gp.bytes/4096 < 5;
    if (!gp.valid) return -1;
    gp.valid &= offset==pages[gp.bytes/4096]+(off_t)(gp.bytes%4096) && size==4096-gp.bytes%4096;
    const unsigned char *p=bytes;
    for (size_t i=0;i<size;i++) gp.valid &= p[i]==0;
    ++gp.writes;
    if (!gp_event('W')) { errno=EIO; return -1; }
    if (gp.interrupted) { --gp.interrupted; errno=EINTR; return -1; }
    if (gp.zero_write) return 0;
    if (gp.short_write && size>1) { --gp.short_write; size/=2; }
    gp.bytes+=size;
    return (ssize_t)size;
}
static int gp_sync(int fd)
{
    gp.valid &= fd==3 && gp.bytes==(gp.syncs==0 ? 8192u : 20480u);
    ++gp.syncs;
    return gp_event('F') ? 0 : -1;
}
static int gp_close(int fd)
{
    gp.valid &= fd==gp.fd; ++gp.closes;
    return gp_event('X') ? 0 : -1;
}
static int64_t gp_now(void)
{
    ++gp.clocks;
    gp.expired=gp.fail_clock && gp.clocks>=gp.fail_clock;
    return gp.fail_clock && gp.clocks>=gp.fail_clock ? (gp.clock_error ? -1 : 100) : 1;
}
static bool gp_diag(const char *text, int64_t end)
{
    gp.valid &= text && *text && end==100;
    return true;
}
#define GB_PREP_OPEN gp_open
#define GB_PREP_STAT gp_stat
#define GB_PREP_SIZE gp_size
#define GB_PREP_CONFINE gp_confine
#define GB_PREP_WRITE gp_write
#define GB_PREP_SYNC gp_sync
#define GB_PREP_CLOSE gp_close
#define GB_PREP_NOW gp_now
#define GB_PREP_DIAG gp_diag
#include "../../fixtures/rvmachine/src/geli_public_prepare.inc"
#undef GB_PREP_OPEN
#undef GB_PREP_STAT
#undef GB_PREP_SIZE
#undef GB_PREP_CONFINE
#undef GB_PREP_WRITE
#undef GB_PREP_SYNC
#undef GB_PREP_CLOSE
#undef GB_PREP_NOW
#undef GB_PREP_DIAG
static void gp_reset(void) { memset(&gp,0,sizeof gp); gp.valid=true; gp.fd=3; }
static int t_public_prepare_gate_controls(void)
{
    int failures=0;
    TEST("PUBLIC helper preparation requires attach and leaves recovery without I/O") {
        gp_reset(); ASSERT(gb_prepare_finish(false,true,100));
        ASSERT(gp.event==0 && gp.clocks==0);
        ASSERT(!gb_prepare_finish(true,false,100));
        ASSERT(!gb_prepare_finish(false,false,100));
        ASSERT(gp.event==0 && gp.clocks==0);
        PASS();
    } _test_next:;
    return failures;
}
static int gp_failure_controls(unsigned events, unsigned clocks)
{
    int failures=0;
    for (unsigned i=1;i<=events;i++) {
        gp_reset(); gp.fail_event=i;
        ASSERT(!gb_prepare_finish(true,true,100));
        ASSERT(gp.valid && gp.closes==(i==1 ? 0u : 1u));
        ASSERT(gp.event==i+(i>1 && i<events ? 1u : 0u));
    }
    for (unsigned error=0;error<2;error++) for (unsigned i=1;i<=clocks;i++) {
        gp_reset(); gp.fail_clock=i; gp.clock_error=error!=0;
        ASSERT(!gb_prepare_finish(true,true,100));
        ASSERT(gp.valid && gp.closes<=1);
    }
    _test_next:;
    return failures;
}
static int t_public_prepare_controls(void)
{
    int failures=t_public_prepare_gate_controls();
    TEST("PUBLIC helper preparation writes exactly five pages and two ordered barriers") {
        gp_reset(); ASSERT(gb_prepare_finish(true,true,100));
        ASSERT(gp.valid && gp.bytes==20480 && gp.closes==1);
        ASSERT(strcmp(gp.trace,"OTMCWWFWWWFX")==0);
        unsigned events=gp.event, clocks=gp.clocks;
        int control_failures=gp_failure_controls(events,clocks);
        failures+=control_failures;
        if (control_failures) goto _test_next;
        gp_reset(); gp.short_write=1; gp.interrupted=1;
        ASSERT(gb_prepare_finish(true,true,100));
        ASSERT(gp.valid && gp.bytes==20480 && gp.syncs==2 && gp.closes==1);
        gp_reset(); gp.zero_write=true;
        ASSERT(!gb_prepare_finish(true,true,100));
        ASSERT(gp.valid && gp.bytes==0 && gp.syncs==0 && gp.closes==1);
        for (unsigned mode=0;mode<5;mode++) {
            gp_reset(); gp.wrong_type=mode==0; gp.wrong_size=mode==1;
            if (mode>=2) gp.fd=(int)mode-2;
            ASSERT(!gb_prepare_finish(true,true,100));
            ASSERT(gp.valid && gp.bytes==0 && gp.syncs==0 && gp.closes==1);
            ASSERT(strchr(gp.trace,'C')==NULL);
        }
        PASS();
    } _test_next:;
    return failures;
}
