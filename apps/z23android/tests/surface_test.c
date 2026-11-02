/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Attack-surface checks on the packaged manifest, the backup rules and the text entry widgets. Run from apps/z23android. */
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot read %s\n", path); abort(); }
    char *buf = calloc(1, 1 << 20);
    assert(buf);
    size_t n = fread(buf, 1, (1 << 20) - 1, f);
    assert(!ferror(f) && feof(f));
    fclose(f);
    buf[n] = 0;
    return buf;
}
static size_t count(const char *hay, const char *needle)
{
    size_t n = 0;
    for (const char *p = hay; (p = strstr(p, needle)); p += strlen(needle)) n++;
    return n;
}
static void require(const char *text, const char *needle, const char *why)
{
    if (!strstr(text, needle)) { fprintf(stderr, "missing %s: %s\n", needle, why); abort(); }
}

/* No wallet file leaves the phone by cloud backup, device-to-device transfer or adb backup, and no cleartext HTTP is allowed. */
static void manifest_blocks_extraction(void)
{
    char *m = slurp("AndroidManifest.xml");
    require(m, "android:allowBackup=\"false\"", "adb and cloud backup");
    require(m, "android:dataExtractionRules=\"@xml/data_extraction_rules\"", "Android 12+ cloud backup and device transfer");
    require(m, "android:usesCleartextTraffic=\"false\"", "no cleartext HTTP from the Java stack");
    require(m, "android:debuggable=\"false\"", "run-as would expose the wallet files");
    assert(!strstr(m, "android:debuggable=\"true\""));
    free(m);
    char *r = slurp("res/xml/data_extraction_rules.xml");
    static const char *const domains[] = {"root", "file", "database", "sharedpref", "external"};
    const char *sections[] = {"<cloud-backup", "<device-transfer"};
    const char *ends[] = {"</cloud-backup>", "</device-transfer>"};
    for (size_t s = 0; s < 2; s++) {
        const char *at = strstr(r, sections[s]);
        const char *end = at ? strstr(at, ends[s]) : NULL;
        assert(at && end);
        for (size_t d = 0; d < sizeof(domains) / sizeof(*domains); d++) {
            char want[80];
            snprintf(want, sizeof(want), "<exclude domain=\"%s\"", domains[d]);
            const char *hit = strstr(at, want);
            if (!hit || hit > end) { fprintf(stderr, "%s not excluded from %s\n", domains[d], sections[s]); abort(); }
        }
    }
    assert(!strstr(r, "<include"));
    free(r);
}

/* Only the launcher activity is exported; the node service is not reachable from other apps. */
static void manifest_exports_only_the_launcher(void)
{
    char *m = slurp("AndroidManifest.xml");
    assert(count(m, "android:exported=\"true\"") == 1);
    const char *service = strstr(m, "<service");
    assert(service && strstr(service, "android:exported=\"false\""));
    assert(!strstr(m, "<receiver") && !strstr(m, "<provider"));
    assert(!strstr(m, "android:scheme"));
    free(m);
}

/* A file that creates an EditText also asks the keyboard not to learn from it and not to suggest. */
static void text_entry_is_private(void)
{
    DIR *dir = opendir(".");
    assert(dir);
    size_t fields = 0;
    for (struct dirent *e; (e = readdir(dir));) {
        size_t n = strlen(e->d_name);
        if (n < 3 || strcmp(e->d_name + n - 2, ".c")) continue;
        char *src = slurp(e->d_name);
        if (strstr(src, "android/widget/EditText")) {
            fields++;
            if (!strstr(src, "setImeOptions") || !strstr(src, "0x1000000")) { fprintf(stderr, "%s: EditText without IME_FLAG_NO_PERSONALIZED_LEARNING\n", e->d_name); abort(); }
            if (!strstr(src, "setInputType")) { fprintf(stderr, "%s: EditText without an input type that disables suggestions\n", e->d_name); abort(); }
        }
        free(src);
    }
    closedir(dir);
    assert(fields >= 4);
}

int main(void)
{
    manifest_blocks_extraction();
    manifest_exports_only_the_launcher();
    text_entry_is_private();
    puts("surface_test: ok");
    return 0;
}
