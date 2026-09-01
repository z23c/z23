#!/usr/bin/env bash
# Phase-0 containment: no production path may create a network release until
# immutable quality/release evidence and the signed stable publisher exist.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELF_REL='tools/scripts/check_stable_publish_containment.sh'

# Known tag/release/upload primitives across common source, workflow, service,
# JSON/TOML configuration, and named extensionless automation files. This is a
# textual tripwire, not a parser or a proof against every bespoke transport;
# the actual stable entrypoints are separately asserted hard-contained below.
PATTERN_PUBLISH='gh[[:space:]]+release[[:space:]]+(create|upload)|"gh"[[:space:]]*,[[:space:]]*"release"[[:space:]]*,[[:space:]]*"(create|upload)"|gh[[:space:]]+api.*(/releases|uploads\.github\.com)|hub[[:space:]]+release[[:space:]]+(create|edit)|glab[[:space:]]+release|git[[:space:]]+push.*(--tags|refs/tags|\$TAG)|actions/(create-release|upload-release-asset)|softprops/action-gh-release|ncipollo/release-action|uploads\.github\.com/[^[:space:]]*/releases|aws[[:space:]]+s3[[:space:]]+(cp|sync)|gsutil[[:space:]]+(cp|rsync)|python(.*)-m[[:space:]]+twine[[:space:]]+upload|curl.*(--upload-file|-T[[:space:]]|-X[[:space:]]*(POST|PUT)|--request[[:space:]]*(POST|PUT)).*(release|upload|artifact|s3|gitlab)'

# Host-to-host file transfer, split out from the publication primitives above.
#
# Copying a file to a machine is not the same act as creating a release, and
# conflating them made this gate refuse operator fleet deployment — installing
# a binary the operator built onto a host the operator owns and already runs
# the service on. That is the opposite of an unsigned artifact escaping to
# third parties: nothing is published, nothing is advertised, and no consumer
# can fetch it. The exemption is a SINGLE path (below), and PATTERN_PUBLISH is
# still scanned in that path too, so the fleet-deploy tool cannot grow a
# `gh release create` or an `aws s3 cp` without tripping. The self-test pins
# both halves: a transfer outside the exempt path trips, and a publication
# primitive inside the exempt path trips.
PATTERN_TRANSFER='scp[[:space:]].+[^[:space:]]:[^[:space:]]|rsync[[:space:]].+[^[:space:]]:[^[:space:]]'

# The one operator fleet-deploy entrypoint. Keep this list at exactly one entry
# unless there is a reason a second tool must move bytes between owned hosts;
# every addition widens what this gate stops seeing.
TRANSFER_EXEMPT_REL='tools/ship.sh'

resolve_scanner()
{
    # Stock grep only — this repo forbids non-stock tool dependencies, and a
    # missing scanner must fail CLOSED, never skip the scan.
    local candidate="${ZCL_CONTAINMENT_GREP:-}"
    if [[ -z "$candidate" ]]; then
        candidate="$(command -v grep 2>/dev/null || true)"
    fi
    if [[ -z "$candidate" || ! -x "$candidate" ]]; then
        printf '%s\n' \
            'FAIL: stable-publish containment cannot scan (grep missing/unexecutable)' >&2
        return 3
    fi
    printf '%s\n' "$candidate"
}

containment_hits()
{
    local root="$1" grep_bin output rc
    local -a paths=()
    grep_bin="$(resolve_scanner)" || return $?
    for path in Makefile Dockerfile Jenkinsfile Justfile Taskfile \
        core engine contexts cognition platform tools .github deploy; do
        [[ -e "$root/$path" ]] && paths+=("$path")
    done
    if (( ${#paths[@]} == 0 )); then
        printf '%s\n' \
            'FAIL: stable-publish containment has no scannable roots' >&2
        return 3
    fi

    set +e
    output="$({ cd "$root" && "$grep_bin" -rEn \
        --include='Makefile' --include='*.mk' --include='*.sh' \
        --include='*.c' --include='*.h' \
        --include='*.yml' --include='*.yaml' --include='*.json' \
        --include='*.toml' --include='Dockerfile*' \
        --include='Jenkinsfile*' --include='Justfile' \
        --include='Taskfile' --include='*.service' --include='*.timer' \
        --exclude-dir=build --exclude-dir=vendor --exclude-dir=test-tmp \
        -e "$PATTERN_PUBLISH|$PATTERN_TRANSFER" "${paths[@]}"; } 2>&1)"
    rc=$?
    set -e
    if (( rc > 1 )); then
        printf 'FAIL: stable-publish containment scan error (grep=%d):\n%s\n' \
            "$rc" "$output" >&2
        return 3
    fi
    [[ -n "$output" ]] || return 0
    # Two exclusions, and only two:
    #   1. this gate's own pattern/self-test text;
    #   2. lines in the operator fleet-deploy tool that matched ONLY the
    #      host-to-host transfer pattern. A line there that also matches a
    #      publication primitive is re-tested and still reported, so the
    #      exemption cannot be used to smuggle a release out.
    # awk has a useful zero-match exit status, unlike an unguarded pipeline
    # under pipefail.
    printf '%s\n' "$output" |
        awk -v self="$SELF_REL:" 'index($0, self) != 1 { print }' |
        while IFS= read -r line; do
            case "$line" in
                "$TRANSFER_EXEMPT_REL":*)
                    body="${line#*:}"; body="${body#*:}"
                    if printf '%s' "$body" | "$grep_bin" -qE "$PATTERN_PUBLISH"
                    then
                        printf '%s\n' "$line"
                    fi
                    ;;
                *) printf '%s\n' "$line" ;;
            esac
        done
}

known_entrypoints_contained()
{
    local root="$1"
    if [[ -f "$root/tools/release.sh" ]]; then
        grep -q 'REFUSING: stable release build/package/sign/publish is contained' \
            "$root/tools/release.sh" || {
            printf '%s\n' 'FAIL: tools/release.sh is not hard-contained' >&2
            return 2
        }
    fi
    if [[ -f "$root/Makefile" ]] && grep -q '^release:' "$root/Makefile"; then
        awk '
            /^release:/ {
                seen=1
                if ($0 != "release:") bad=1
                if ((getline line) <= 0 || line !~ /^\t@\.\/tools\/release\.sh$/)
                    bad=1
            }
            END { exit !(seen && !bad) }
        ' "$root/Makefile" || {
            printf '%s\n' \
                'FAIL: make release has prerequisites or bypasses contained release.sh' >&2
            return 2
        }
    fi
    if [[ -f "$root/Makefile" ]] &&
       grep -q '^bootstrap-publish:' "$root/Makefile"; then
        awk '
            /^bootstrap-publish:/ { in_target=1; seen=1; next }
            in_target && /^\t/ && /REFUSING/ { refused=1 }
            in_target && !/^\t/ { in_target=0 }
            END { exit !(seen && refused) }
        ' "$root/Makefile" || {
            printf '%s\n' 'FAIL: bootstrap-publish is not hard-contained' >&2
            return 2
        }
    fi
}

check_root()
{
    local root="$1" hits rc
    set +e
    hits="$(containment_hits "$root")"
    rc=$?
    set -e
    if (( rc != 0 )); then
        return "$rc"
    fi
    if [[ -n "$hits" ]]; then
        printf '%s\n' "$hits" >&2
        printf '%s\n' \
            'FAIL: network release creation is contained until stable evidence/signing gates land' >&2
        return 2
    fi
    known_entrypoints_contained "$root"
}

if [[ "${1:-}" == "--check-root" ]]; then
    [[ -n "${2:-}" ]] || {
        printf '%s\n' 'FAIL: --check-root requires a directory' >&2
        exit 3
    }
    check_root "$2"
    exit $?
fi

if [[ "${1:-}" == "--self-test" ]]; then
    fixture="$(mktemp -d "${TMPDIR:-/tmp}/zcl-publish-containment.XXXXXX")"
    trap 'rm -rf "$fixture"' EXIT

    selftest_bad_fixture()
    {
        local name="$1" rel="$2" body="$3" root
        root="$fixture/bad-$name"
        mkdir -p "$(dirname "$root/$rel")"
        printf '%s\n' "$body" > "$root/$rel"
        if check_root "$root" >/dev/null 2>&1; then
            printf 'FAIL: stable-publish %s fixture did not trip\n' \
                "$name" >&2
            exit 2
        fi
    }

    # Every case owns a fresh root. A previous forbidden file can therefore
    # never make a later detector appear to pass.
    selftest_bad_fixture gh-cli Makefile \
        $'bad:\n\tgh release create forbidden'
    selftest_bad_fixture gh-api Makefile \
        $'bad:\n\tgh api repos/acme/project/releases'
    selftest_bad_fixture tag-push Makefile \
        $'bad:\n\tgit push origin refs/tags/v1.2.3'
    selftest_bad_fixture workflow .github/workflows/release.yml \
        'uses: softprops/action-gh-release@deadbeef'
    selftest_bad_fixture service deploy/publish.service \
        'ExecStart=scp artifact host:/stable/releases/'
    selftest_bad_fixture json config/release.json \
        '{"command":["gh","release","upload","v1","artifact"]}'
    selftest_bad_fixture toml config/release.toml \
        'command = "aws s3 cp artifact s3://stable/releases/"'
    selftest_bad_fixture extensionless Dockerfile \
        'RUN gh release create forbidden'
    # The transfer exemption is one path wide. A transfer from ANY other tool
    # still trips, so the carve-out cannot spread by copy-paste.
    selftest_bad_fixture transfer-elsewhere tools/other_deploy.sh \
        'scp artifact host:/stable/releases/'
    # And the exempt path is exempt from the TRANSFER pattern only: a genuine
    # publication primitive inside it still trips. This is the assertion that
    # keeps the carve-out from becoming a hole.
    selftest_bad_fixture publish-inside-exempt "$TRANSFER_EXEMPT_REL" \
        'gh release create v1 artifact'
    selftest_bad_fixture s3-inside-exempt "$TRANSFER_EXEMPT_REL" \
        'aws s3 cp artifact s3://stable/releases/'

    clean="$fixture/clean"
    mkdir -p "$clean/tools"
    printf '%s\n' $'safe:\n\t@echo local-only' > "$clean/Makefile"
    # The positive case for the exemption: an operator transfer in the one
    # exempt path must NOT trip, or the gate blocks fleet deployment outright
    # (which is the failure this split exists to fix).
    printf '%s\n' 'scp -q "$CANDIDATE" "$REMOTE_HOST:${svc_bin}.incoming"' \
        > "$clean/$TRANSFER_EXEMPT_REL"
    if ZCL_CONTAINMENT_GREP=/definitely/missing/grep \
        bash "$0" --check-root "$clean" >/dev/null 2>&1; then
        printf '%s\n' 'FAIL: missing scanner fixture failed open' >&2
        exit 2
    fi
    if ! check_root "$clean" >/dev/null 2>&1; then
        printf '%s\n' 'FAIL: stable-publish containment clean fixture failed' >&2
        exit 2
    fi
    printf '%s\n' \
        '  OK: independent CLI/tag/workflow/service/JSON/TOML/extensionless fixtures trip; clean and scanner-failure fixtures behave'
    exit 0
fi

check_root "$ROOT"
printf '%s\n' \
    '  OK: known stable entrypoints are hard-contained; no known network publication primitive found'
