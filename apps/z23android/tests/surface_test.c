/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Attack-surface checks on the packaged manifest, the backup rules and the text entry widgets. Run from apps/z23android. */
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
    static const char *const domains[] = {"root", "file", "database", "sharedpref", "external", "device_root", "device_file", "device_database", "device_sharedpref"};
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

/* Counts lines of src that contain every one of the needles. */
static size_t lines_with(const char *src, const char *a, const char *b, const char *c)
{
    size_t n = 0;
    for (const char *p = src; *p;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[1024];
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len); line[len] = 0;
        if (strstr(line, a) && (!b || strstr(line, b)) && (!c || strstr(line, c))) n++;
        p += eol ? len + 1 : len;
    }
    return n;
}
/* Every EditText a file creates is given a no-suggestions input type and IME_FLAG_NO_PERSONALIZED_LEARNING, and a failed
 * flag call is not discarded. native_ui.c styles both of its fields through style_prompt. */
static void text_entry_is_private(void)
{
    DIR *dir = opendir(".");
    assert(dir);
    size_t fields = 0;
    for (struct dirent *e; (e = readdir(dir));) {
        size_t n = strlen(e->d_name);
        if (n < 3 || strcmp(e->d_name + n - 2, ".c")) continue;
        char *src = slurp(e->d_name);
        size_t created = count(src, "android/widget/EditText");
        if (created) {
            size_t ime = lines_with(src, "setImeOptions", "0x1000000", NULL) + lines_with(src, "setImeOptions", "IME_NO_LEARNING", NULL);
            size_t type = lines_with(src, "setInputType", NULL, NULL);
            size_t helper_calls = count(src, "style_prompt(env, ");
            if (helper_calls) { ime = ime - 1 + helper_calls; type = type - 1 + helper_calls; }
            fields += created;
            if (ime < created) { fprintf(stderr, "%s: %zu EditText fields, %zu with IME_FLAG_NO_PERSONALIZED_LEARNING\n", e->d_name, created, ime); abort(); }
            if (type < created) { fprintf(stderr, "%s: %zu EditText fields, %zu with an input type\n", e->d_name, created, type); abort(); }
            if (lines_with(src, "(void)", "setImeOptions", NULL) || lines_with(src, "(void)", "setInputType", NULL)) {
                fprintf(stderr, "%s: the result of an IME flag call is discarded\n", e->d_name); abort();
            }
        }
        free(src);
    }
    closedir(dir);
    assert(fields >= 6);
}

/* The node notification and its channel are secret on the lock screen. */
static void node_notification_is_secret(void)
{
    char *src = slurp("node_service.c");
    require(src, "VISIBILITY_SECRET = -1", "Notification.VISIBILITY_SECRET");
    require(src, "\"setLockscreenVisibility\"", "channel lock screen visibility");
    assert(lines_with(src, "\"setVisibility\"", "VISIBILITY_SECRET", NULL) >= 2);
    free(src);
}

int main(int argc, char **argv)
{
    if (argc > 1 && chdir(argv[1])) { perror(argv[1]); return 1; }
    manifest_blocks_extraction();
    manifest_exports_only_the_launcher();
    text_entry_is_private();
    node_notification_is_secret();
    puts("surface_test: ok");
    return 0;
}
