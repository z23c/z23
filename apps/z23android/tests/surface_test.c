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
            size_t autofill = lines_with(src, "setImportantForAutofill", "ZAPP_FIELD_AUTOFILL_NO", NULL);
            size_t type = lines_with(src, "setInputType", NULL, NULL);
            size_t helper_calls = count(src, "style_prompt(env, ");
            if (helper_calls) { ime = ime - 1 + helper_calls; type = type - 1 + helper_calls; autofill = autofill - 1 + helper_calls; }
            fields += created;
            if (ime < created) { fprintf(stderr, "%s: %zu EditText fields, %zu with IME_FLAG_NO_PERSONALIZED_LEARNING\n", e->d_name, created, ime); abort(); }
            if (type < created) { fprintf(stderr, "%s: %zu EditText fields, %zu with an input type\n", e->d_name, created, type); abort(); }
            if (autofill < created) { fprintf(stderr, "%s: %zu EditText fields, %zu with autofill off\n", e->d_name, created, autofill); abort(); }
            if (lines_with(src, "(void)", "setImeOptions", NULL) || lines_with(src, "(void)", "setInputType", NULL)) {
                fprintf(stderr, "%s: the result of an IME flag call is discarded\n", e->d_name); abort();
            }
        }
        free(src);
    }
    closedir(dir);
    /* Five fields: native_ui.c creates two and each of the three wallet screens creates one. The sixth field was in
     * clip_screen.c, which was removed with the Clips screen. */
    assert(fields == 6);
}

/* Paste must keep working in the fields that take payment and invitation text, so none turns long-click off. */
static void paste_stays_available(void)
{
    static const char *const fields[][2] = {{"native_ui.c", "static bool style_prompt("}, {"wallet_send_ui.c", "static bool input_view("},
                                            {"wallet_ui.c", "static bool input_view("}};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        char *src = slurp(fields[i][0]);
        const char *at = strstr(src, fields[i][1]);
        const char *end = at ? strstr(at, "\n}\n") : NULL;
        assert(at && end);
        char *body = strndup(at, (size_t)(end - at));
        assert(body);
        if (strstr(body, "setLongClickable")) { fprintf(stderr, "%s turns long-click off on a field\n", fields[i][0]); abort(); }
        free(body);
        free(src);
    }
}

/* The screens that take or show secrets get the window protections and the obscured-touch drop: the wallet screens, and the
 * Assistant, which takes pasted invitations and pairing descriptors. */
static void secret_screens_are_protected(void)
{
    char *src = slurp("shell.c");
    const char *list = strstr(src, "static bool wallet_screen(");
    const char *list_end = list ? strchr(list, '\n') : NULL;
    assert(list && list_end);
    char *line = strndup(list, (size_t)(list_end - list));
    assert(line);
    require(line, "SCREEN_WALLET", "the wallet screen is protected");
    require(line, "SCREEN_SEND", "the send screen is protected");
    require(line, "SCREEN_SETUP", "the setup screens are protected");
    free(line);
    const char *go = strstr(src, "static void go(JNIEnv *env, enum screen next)\n{");
    const char *end = go ? strstr(go, "\n}\n") : NULL;
    assert(go && end);
    char *body = strndup(go, (size_t)(end - go));
    assert(body);
    require(body, "(next == SCREEN_ASSISTANT || next == SCREEN_FLEET_REVIEW) && !protect_window(env, true)", "the Assistant and fleet review are not shown unprotected");
    require(body, "set_protection(env, next);", "every screen change sets the protection");
    free(body);
    const char *set = strstr(src, "static void set_protection(JNIEnv *env, enum screen next)\n{");
    const char *set_end = set ? strstr(set, "\n}\n") : NULL;
    assert(set && set_end);
    body = strndup(set, (size_t)(set_end - set));
    assert(body);
    require(body, "wallet_screen(next) || next == SCREEN_ASSISTANT || next == SCREEN_FLEET_REVIEW || (next == SCREEN_SCAN && shell.paste_mode)) shell.gate.protect = true", "obscured touches are dropped on the Assistant and fleet review");
    require(body, "protect_window(env, false)", "leaving the Assistant lifts the protection");
    require(src, "(shell.current == SCREEN_ASSISTANT || shell.current == SCREEN_FLEET_REVIEW) && !protect_window(env, true)", "the Assistant and fleet review are protected again on resume");
    free(body);
    free(src);
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

/* A pairing offer is read only when the launching uid is this app, the adb shell or root; the layouts folder is
 * created owner-only and home.json is read without following links. */
static void inputs_are_gated(void)
{
    char *src = slurp("android_main.c");
    require(src, "\"getLaunchedFromUid\"", "caller uid of the launch");
    require(src, "zapp_pair_caller_allowed(", "uid policy");
    const char *body = strstr(src, "static bool intent_pairing(");
    const char *end = body ? strstr(body, "\n}\n") : NULL;
    assert(body && end);
    size_t gated = 0;
    for (const char *p = body; p < end;) {
        const char *eol = strchr(p, '\n');
        char line[512];
        size_t len = (size_t)(eol - p);
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len); line[len] = 0;
        if (strstr(line, "!pairing_caller_allowed(env, activity)") && strstr(line, "memory_cleanse")) gated++;
        p = eol + 1;
    }
    if (gated != 1) { fprintf(stderr, "intent_pairing does not drop the offer of a refused caller\n"); abort(); }
    free(src);
    src = slurp("shell.c");
    assert(!strstr(src, "0770"));
    require(src, "mkdir(layouts, 0700)", "owner-only layouts folder");
    require(src, "zapp_layout_read(", "checked read of home.json");
    free(src);
    src = slurp("layout.c");
    require(src, "O_NOFOLLOW", "no symbolic link for home.json");
    free(src);
}

/* The Clips screen opens from no launch path: no intent extra names it, no source file but its own opens it and the
 * manifest declares no Clips filter. */
static void clips_is_unreachable(void)
{
    char *src = slurp("android_main.c");
    assert(!strstr(src, "org.z23.clips") && !strstr(src, "clip_screen.h"));
    free(src);
    DIR *dir = opendir(".");
    assert(dir);
    for (struct dirent *e; (e = readdir(dir));) {
        size_t n = strlen(e->d_name);
        if (n < 3 || strcmp(e->d_name + n - 2, ".c") || !strcmp(e->d_name, "clip_screen.c")) continue;
        src = slurp(e->d_name);
        if (strstr(src, "zapp_clip_screen_open(")) { fprintf(stderr, "%s opens the Clips screen\n", e->d_name); abort(); }
        free(src);
    }
    closedir(dir);
    char *m = slurp("AndroidManifest.xml");
    assert(!strstr(m, "clips") && !strstr(m, "Clips"));
    free(m);
}

/* Clipped text ends with an ellipsis: every line limit surface.c sets, fixed or maximum, comes with TruncateAt.END,
 * and make_text applies the node's limit. */
static void text_is_ellipsized(void)
{
    char *src = slurp("surface.c");
    require(src, "\"android/text/TextUtils$TruncateAt\"", "TruncateAt class");
    require(src, "\"END\", \"Landroid/text/TextUtils$TruncateAt;\"", "TruncateAt.END");
    require(src, "\"setEllipsize\"", "end ellipsis");
    static const char *const limits[] = {"\"setLines\"", "\"setMaxLines\""};
    for (size_t i = 0; i < 2; i++) {
        size_t set = lines_with(src, limits[i], NULL, NULL);
        if (!set || lines_with(src, limits[i], "ellipsize_end(", NULL) != set) { fprintf(stderr, "%s without an ellipsis\n", limits[i]); abort(); }
    }
    const char *body = strstr(src, "static jobject make_text(");
    const char *end = body ? strstr(body, "\n}\n") : NULL;
    assert(body && end);
    const char *call = strstr(body, "line_limits(b->env, view, node)");
    assert(call && call < end);
    free(src);
}

int main(int argc, char **argv)
{
    if (argc > 1 && chdir(argv[1])) { perror(argv[1]); return 1; }
    manifest_blocks_extraction();
    manifest_exports_only_the_launcher();
    text_entry_is_private();
    paste_stays_available();
    secret_screens_are_protected();
    node_notification_is_secret();
    inputs_are_gated();
    clips_is_unreachable();
    text_is_ellipsized();
    puts("surface_test: ok");
    return 0;
}
