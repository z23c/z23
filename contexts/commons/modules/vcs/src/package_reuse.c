/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic reuse ranking over verified local package APIs. */

#include "vcs/package_reuse.h"

#include <ctype.h>
#include <string.h>
#include <strings.h>

struct reuse_request {
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char version[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    bool exact;
    bool has_version;
};

static bool ascii_equal_ci_n(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return false;
    return true;
}

static bool ascii_contains_ci(const char *haystack, const char *needle)
{
    size_t hn = haystack ? strlen(haystack) : 0;
    size_t nn = needle ? strlen(needle) : 0;
    if (nn == 0 || nn > hn) return false;
    for (size_t i = 0; i + nn <= hn; i++)
        if (ascii_equal_ci_n(haystack + i, needle, nn)) return true;
    return false;
}

static const char *package_basename(const char *name)
{
    const char *slash = name ? strrchr(name, '/') : NULL;
    return slash ? slash + 1 : name;
}

static bool request_word(const char *word, size_t len)
{
    static const char *const ignored[] = {
        "add", "and", "c23", "code", "for", "make", "package",
        "please", "should", "the", "use", "using", "with",
    };
    if (len < 2) return false;
    for (size_t i = 0; i < sizeof(ignored) / sizeof(ignored[0]); i++)
        if (strlen(ignored[i]) == len &&
            ascii_equal_ci_n(word, ignored[i], len)) return false;
    return true;
}

static void parse_exact_request(const char *goal, struct reuse_request *out)
{
    memset(out, 0, sizeof(*out));
    if (!goal) return;
    while (isspace((unsigned char)*goal)) goal++;
    const char *start = goal;
    const char *space = strchr(start, ' ');
    if (space) {
        size_t verb_len = (size_t)(space - start);
        if ((verb_len == 3 && ascii_equal_ci_n(start, "use", 3)) ||
            (verb_len == 5 && ascii_equal_ci_n(start, "reuse", 5)) ||
            (verb_len == 7 && ascii_equal_ci_n(start, "install", 7))) {
            start = space + 1;
            while (isspace((unsigned char)*start)) start++;
        }
    }
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) end--;
    if (end == start || memchr(start, ' ', (size_t)(end - start))) return;
    const char *at = memchr(start, '@', (size_t)(end - start));
    size_t name_len = at ? (size_t)(at - start) : (size_t)(end - start);
    size_t version_len = at ? (size_t)(end - at - 1) : 0;
    if (name_len == 0 || name_len >= sizeof(out->name) ||
        version_len >= sizeof(out->version) || (at && version_len == 0))
        return;
    memcpy(out->name, start, name_len); out->name[name_len] = '\0';
    if (at) {
        memcpy(out->version, at + 1, version_len);
        out->version[version_len] = '\0'; out->has_version = true;
    }
    out->exact = true;
}

static bool request_matches_name(const struct reuse_request *request,
                                 const char *name)
{
    if (!request->exact || !name) return false;
    return strcasecmp(request->name, name) == 0 ||
           strcasecmp(request->name, package_basename(name)) == 0;
}

static uint32_t semantic_score(const char *goal,
                               const struct vcs_package_reuse_input *input)
{
    const struct vcs_package_index_entry *package = input->package;
    if (!package || !goal) return 0;
    uint32_t score = 0;
    if (ascii_contains_ci(goal, package->name)) score += 1000;
    const char *base = package_basename(package->name);
    if (base && ascii_contains_ci(goal, base)) score += 400;
    const char *p = goal;
    while (*p) {
        while (*p && !isalnum((unsigned char)*p)) p++;
        const char *word = p;
        while (isalnum((unsigned char)*p) || *p == '_') p++;
        size_t len = (size_t)(p - word);
        if (!request_word(word, len)) continue;
        char token[96];
        if (len >= sizeof(token)) len = sizeof(token) - 1u;
        memcpy(token, word, len); token[len] = '\0';
        if (base && ascii_contains_ci(base, token)) score += 80;
        for (size_t i = 0; i < input->api_count; i++)
            if (ascii_contains_ci(input->apis[i], token)) score += 30;
    }
    return score;
}

static int selection_cmp(const struct vcs_package_reuse_selection *a,
                         const struct vcs_package_reuse_selection *b,
                         const struct vcs_package_reuse_input *inputs)
{
    if (a->score != b->score) return a->score > b->score ? -1 : 1;
    const struct vcs_package_reuse_input *ia = &inputs[a->input_index];
    const struct vcs_package_reuse_input *ib = &inputs[b->input_index];
    if (ia->locked != ib->locked) return ia->locked ? -1 : 1;
    if (ia->installed != ib->installed) return ia->installed ? -1 : 1;
    int c = strcmp(ia->package->name, ib->package->name);
    if (c != 0) return c;
    c = strcmp(ia->package->semver, ib->package->semver);
    if (c != 0) return c;
    return strcmp(ia->package->package_root_hex,
                  ib->package->package_root_hex);
}

static void insert_selection(struct vcs_package_reuse_plan *out,
                             const struct vcs_package_reuse_input *inputs,
                             size_t input_index, uint32_t score)
{
    struct vcs_package_reuse_selection value = {
        .input_index = input_index, .score = score,
    };
    size_t pos = 0;
    while (pos < out->selected_count &&
           selection_cmp(&out->selected[pos], &value, inputs) <= 0) pos++;
    if (pos >= VCS_PACKAGE_REUSE_MAX_SELECTED) return;
    size_t count = out->selected_count;
    if (count < VCS_PACKAGE_REUSE_MAX_SELECTED) count++;
    for (size_t i = count - 1u; i > pos; i--)
        out->selected[i] = out->selected[i - 1u];
    out->selected[pos] = value; out->selected_count = count;
}

bool vcs_package_reuse_plan_build(
    const char *goal, const struct vcs_package_reuse_input *inputs,
    size_t input_count, struct vcs_package_reuse_plan *out)
{
    if (!goal || !goal[0] || !inputs || !out ||
        input_count > VCS_PACKAGE_REUSE_MAX_INPUTS) return false;
    memset(out, 0, sizeof(*out)); out->packages_scanned = input_count;
    out->new_code_required = true;
    struct reuse_request request; parse_exact_request(goal, &request);
    out->exact_request = request.exact;
    out->requested_version = request.has_version;
    size_t exact_compatible = 0;
    for (size_t i = 0; i < input_count; i++) {
        if (!inputs[i].package ||
            inputs[i].api_count > VCS_PACKAGE_REUSE_MAX_APIS) return false;
        bool name_match = request_matches_name(&request,
                                               inputs[i].package->name);
        bool version_match = !request.has_version ||
            strcmp(request.version, inputs[i].package->semver) == 0;
        uint32_t score = semantic_score(goal, &inputs[i]);
        if (name_match && !version_match) {
            out->incompatible_matches++; continue;
        }
        if (request.exact && !name_match) continue;
        if (!inputs[i].compatible) {
            if (score > 0 || name_match) out->incompatible_matches++;
            continue;
        }
        if (name_match && version_match) {
            score += 2000; exact_compatible++;
        }
        if (score == 0) continue;
        out->compatible_matches++;
        if (inputs[i].locked) score += 40;
        if (inputs[i].installed) score += 20;
        insert_selection(out, inputs, i, score);
    }
    if (request.exact && exact_compatible == 1) {
        out->disposition = VCS_PACKAGE_REUSE_COMPLETE;
        out->new_code_required = false;
    } else if (request.exact && exact_compatible > 1) {
        out->disposition = VCS_PACKAGE_REUSE_AMBIGUOUS;
    } else if (out->selected_count > 0) {
        out->disposition = VCS_PACKAGE_REUSE_PARTIAL;
    } else if (out->incompatible_matches > 0) {
        out->disposition = VCS_PACKAGE_REUSE_INCOMPATIBLE;
    } else {
        out->disposition = VCS_PACKAGE_REUSE_NONE;
    }
    return true;
}

const char *vcs_package_reuse_disposition_string(
    enum vcs_package_reuse_disposition disposition)
{
    switch (disposition) {
    case VCS_PACKAGE_REUSE_NONE: return "no_match";
    case VCS_PACKAGE_REUSE_PARTIAL: return "partial_match";
    case VCS_PACKAGE_REUSE_COMPLETE: return "exact_reuse";
    case VCS_PACKAGE_REUSE_AMBIGUOUS: return "conflicting_candidates";
    case VCS_PACKAGE_REUSE_INCOMPATIBLE: return "incompatible";
    }
    return "unknown";
}
