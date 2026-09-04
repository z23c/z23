#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Prove that ordinary development profiles cannot acquire release-only LTO.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
profiles="$(make -s --no-print-directory -C "$ROOT" dev-loop-profile-flags)"

fail()
{
    printf 'check-dev-loop-profiles: FAIL: %s\n' "$*" >&2
    exit 1
}

scratch="$(mktemp "${TMPDIR:-/tmp}/zcl-dev-profile.XXXXXX")" ||
    fail 'cannot allocate expanded-recipe scratch file'
trap 'rm -f "$scratch"' EXIT HUP INT TERM

profile_line()
{
    local name="$1"
    printf '%s\n' "$profiles" | awk -F '\t' -v wanted="$name" \
        '$1 == wanted { print; found = 1 } END { if (!found) exit 1 }'
}

for name in DEV_LIVE DEV_RESTART INTEGRATION; do
    line="$(profile_line "$name")" || fail "missing $name profile"
    case " $line " in
        *' -flto'*|*' -fuse-linker-plugin'*)
            fail "$name contains release-only LTO flags: $line"
            ;;
    esac
done

release="$(profile_line RELEASE)" || fail 'missing RELEASE profile'
case " $release " in
    *' -flto'*) ;;
    *) fail 'RELEASE no longer carries whole-program LTO' ;;
esac

if ! command -v mold >/dev/null 2>&1 &&
   ! command -v ld.lld >/dev/null 2>&1 &&
   command -v ld.gold >/dev/null 2>&1; then
    restart="$(profile_line DEV_RESTART)" ||
        fail 'missing DEV_RESTART profile for linker selection'
    case " $restart " in
        *' -fuse-ld=gold '*) ;;
        *) fail 'installed gold linker is not selected for DEV_RESTART' ;;
    esac
    case " $release " in
        *' -fuse-ld=gold '*)
            fail 'development linker leaked into RELEASE'
            ;;
    esac
fi

git -C "$ROOT" grep -q '\$(DEV_RESTART_CFLAGS) \$(DEV_RESTART_LDFLAGS)' -- Makefile ||
    fail 'incremental dev link is not owned by DEV_RESTART'
git -C "$ROOT" grep -q '^$(DEV_RESTART_BASE_RELOC):' -- Makefile ||
    fail 'generation-frozen dev relocatable base is missing'
git -C "$ROOT" grep -q '^$(TEST_RESTART_BASE_RELOC):' -- Makefile ||
    fail 'generation-frozen proof relocatable base is missing'
git -C "$ROOT" grep -q "printf 'DEV_BASE_RELOC=" -- Makefile ||
    fail 'restart plan does not bind the dev relocatable base'
git -C "$ROOT" grep -q "printf 'TEST_BASE_RELOC=" -- Makefile ||
    fail 'restart plan does not bind the proof relocatable base'
git -C "$ROOT" grep -q -- '-Wl,--allow-multiple-definition' -- \
    tools/dev/devloop_restart_build.c ||
    fail 'overlay objects are not ordered ahead of the frozen base'
git -C "$ROOT" grep -q 'dev-bin z23-dev zclassic23-dev:.*\$(ZCLASSIC23_DEV_BIN)' -- Makefile ||
    fail 'dev-bin target is missing'
git -C "$ROOT" grep -q 'Z23_DEV_UNSHIPPABLE_BIN = \$(BIN_DIR)/z23.dev' -- Makefile ||
    fail 'unsippable compiler-speed binary name z23.dev is missing'
git -C "$ROOT" grep -q '^dev: \$(Z23_DEV_UNSHIPPABLE_BIN)' -- Makefile ||
    fail 'make dev does not produce the unsippable z23.dev artifact'
git -C "$ROOT" grep -qF 'ln -f "$<" "$@"' -- Makefile ||
    fail 'z23-dev is not installed as a regular hard link of z23.dev'
if git -C "$ROOT" grep -qF 'ln -sfn z23.dev' -- Makefile; then
    fail 'z23-dev is a symlink: dev proof opens it with O_NOFOLLOW (ELOOP)'
fi
git -C "$ROOT" grep -q 'ship: REFUSE: ZCL_PROFILE=dev' -- Makefile ||
    fail 'make ship does not refuse the dev profile'
git -C "$ROOT" grep -q 'deploy: REFUSE: ZCL_PROFILE=dev' -- Makefile ||
    fail 'make deploy does not refuse the dev profile'
git -C "$ROOT" grep -q '\$(HOTSWAP_ACTION_PLAN) \$(DEV_PACKAGE_VERIFIER_TARGET)' -- Makefile ||
    fail 'dev-bin does not use the platform-qualified package verifier prerequisite'
git -C "$ROOT" grep -q '\$(DEV_RESTART_PLAN_TARGET)' -- Makefile ||
    fail 'dev-bin does not use the platform-qualified restart-plan prerequisite'
git -C "$ROOT" grep -q '^DEV_RESTART_PLAN_TARGET = \$(DEV_RESTART_PLAN)' -- Makefile ||
    fail 'non-Windows dev-bin does not bootstrap its restart plan'
git -C "$ROOT" grep -q '^DEV_RESTART_PLAN_TARGET =$' -- Makefile ||
    fail 'Windows dev-bin does not omit the unavailable proof restart plan'
git -C "$ROOT" grep -q '^dev-proof-bundle:.*dev-bin' -- Makefile ||
    fail 'proof bundle does not serialize its development prerequisites through dev-bin'
git -C "$ROOT" grep -q '^dev-proof-bundle:.*\$(DEV_RESTART_PLAN)' -- Makefile ||
    fail 'explicit proof bundle does not bootstrap the complete restart plan'
if git -C "$ROOT" grep -q '^dev-proof-bundle:.*dev-package-verifier-ensure' -- Makefile; then
    fail 'proof bundle races dev-bin through a duplicate package-verifier bootstrap'
fi
git -C "$ROOT" grep -q '^DEV_PACKAGE_VERIFIER_TARGET = dev-package-verifier' -- Makefile ||
    fail 'non-Windows dev-bin does not bootstrap the fixed development package verifier'
git -C "$ROOT" grep -q '^DEV_PACKAGE_VERIFIER_TARGET =$' -- Makefile ||
    fail 'Windows dev-bin does not preserve the package-verifier refusal boundary'
git -C "$ROOT" grep -q '^test-parallel-fast-active-locked:.*dev-package-verifier-ensure' -- \
    Makefile ||
    fail 'locked focused test profile does not use the non-LTO package verifier'
git -C "$ROOT" grep -q '^test-parallel-locked:.*dev-package-verifier-ensure' -- Makefile ||
    fail 'integration test profile does not use the non-LTO package verifier'
git -C "$ROOT" grep -q '^dev-package-verifier-ensure:' -- Makefile ||
    fail 'test profile package-verifier bootstrap is missing'
git -C "$ROOT" grep -q 'want=.*\$(BUILD_SOURCE_ID).*\$(BUILD_MUTATION)' -- \
    Makefile ||
    fail 'test profile package-verifier bootstrap is not source-identity bound'
git -C "$ROOT" grep -q '^dev-package-verifier:.*\$(DEV_PACKAGE_VERIFY_BIN)' -- \
    Makefile ||
    fail 'nested dev profile does not own the development package verifier'
git -C "$ROOT" grep -q '^$(DEV_PACKAGE_VERIFY_BIN):' -- Makefile ||
    fail 'development package verifier target is missing'
git -C "$ROOT" grep -q '\$(CC) \$(DEV_RESTART_CFLAGS) \$(DEV_RESTART_LDFLAGS).*' -- Makefile ||
    fail 'development package verifier is not owned by DEV_RESTART'
git -C "$ROOT" grep -q 'NODE_C23_PACKAGE_VERIFY_LINK_RSP = .*$(BUILD_INVOCATION_ID)' -- \
    Makefile ||
    fail 'release package verifier response file is not invocation-local'
git -C "$ROOT" grep -q '\$(file >\$(NODE_C23_PACKAGE_VERIFY_LINK_RSP),\$(NODE_C23_PACKAGE_VERIFY_OBJ) \$(NODE_C23_PACKAGE_VERIFY_NODE_OBJS))' -- \
    Makefile ||
    fail 'release package verifier response file does not own its complete object graph'
git -C "$ROOT" grep -q '"@\$(NODE_C23_PACKAGE_VERIFY_LINK_RSP)"' -- Makefile ||
    fail 'release package verifier does not link through its shared-object response file'
git -C "$ROOT" grep -q 'rm -f .*\$(NODE_C23_PACKAGE_VERIFY_LINK_RSP)' -- Makefile ||
    fail 'release package verifier does not remove its invocation-local response file'
git -C "$ROOT" grep -q '\$(BUILD_EPOCH_SESSION_TOOL) verify "\$(NODE_C23_SESSION)" "\$(NODE_C23_LEASE)"' -- \
    Makefile ||
    fail 'release object-graph links do not verify their build epoch before publication'
# The restart plan is the only thing in an ordinary `make z23-dev` that builds
# the fast-test object tree — TEST_PARALLEL_FAST_LINK_RSP and
# TEST_RESTART_BASE_RELOC are made from all of those objects — and that goal
# links no test binary, so nothing else in it reaches the aggregate verify.
# Publishing an object into a shared epoch writes `<epoch>/.unverified` first
# and only that verify clears it, so a plan that skips it leaves the marker
# behind on a build that finished perfectly well. The next make invocation
# reads the marker as a dead writer's leftovers and quarantines and deletes
# the entire epoch directory. MEASURED on this host with a warm compile cache:
# a no-op `make -j8 z23-dev` cost 27 s and recompiled 3 263 objects with the
# marker present, and 13 s with zero recompiles without it. Assert the verify
# is inside this recipe, not merely somewhere in the Makefile.
awk '/^\$\(DEV_RESTART_PLAN\):/ { inrule = 1; next }
     inrule && /^[^\t]/ { inrule = 0 }
     inrule && /BUILD_EPOCH_SESSION_TOOL\) verify "\$\(TEST_FAST_SESSION\)"/ {
         found = 1
     }
     END { exit found ? 0 : 1 }' "$ROOT/Makefile" ||
    fail 'the dev restart plan builds fast-test objects without verifying their epoch, so every later make deletes and rebuilds that whole object tree'
if git -C "$ROOT" grep -Fq '$(BUILD_IDENTITY_STAMP) tools/package_verify.c $(ALL_SRCS)' -- \
        Makefile; then
    fail 'release package verifier recompiles the complete source tree'
fi
git -C "$ROOT" grep -q 'zclassic23-package-verify-dev' -- \
    engine/services/src/build_fabric_worker.c ||
    fail 'fixed worker does not resolve the development package verifier'
git -C "$ROOT" grep -q 'PKGL_DEV_WORKER_NAME "zclassic23-package-verify-dev"' -- \
    contexts/commons/services/src/package_lifecycle_install.c ||
    fail 'package lifecycle does not resolve the development package verifier'
git -C "$ROOT" grep -q '\$(CC) \$(DEV_RESTART_CFLAGS) -Wno-deprecated-declarations' -- \
    Makefile ||
    fail 'development adapter runner is not owned by DEV_RESTART'
git -C "$ROOT" grep -q '\$(DEV_LIVE_CFLAGS) -fPIC' -- Makefile ||
    fail 'resident module compiler is not owned by DEV_LIVE'
git -C "$ROOT" grep -q 'resident action plan contains release-only LTO flags' -- \
    tools/dev/devloop_hotswap_build.c ||
    fail 'resident action-plan LTO refusal is missing'
git -C "$ROOT" grep -q '^ifeq ($(strip $(MAKECMDGOALS)),)' -- Makefile ||
    fail 'default build does not have an explicit epoch-profile selection'
awk '$0 == "ifeq ($(strip $(MAKECMDGOALS)),)" {
         n = 0
         while (getline > 0 && n < 8) {
             n++
             if ($0 == "ZCL_EPOCH_PROFILES := node-c23") { found = 1; break }
             if ($0 ~ /^else ifeq/) break
         }
     }
     END { exit found ? 0 : 1 }' "$ROOT/Makefile" ||
    fail 'default z23 build fingerprints profiles it cannot consume'
git -C "$ROOT" grep -q '^ZCL_NODE_ONLY_BUILD := .*),1)$' -- Makefile ||
    fail 'default z23 build does not select the node-only dependency scope'
awk '$0 == "else ifeq ($(strip $(MAKECMDGOALS)),)" {
         if (getline > 0 && $0 == "ZCL_DEPFILE_PROFILES := node-c23")
             found = 1
     }
     END { exit found ? 0 : 1 }' "$ROOT/Makefile" ||
    fail 'default z23 build imports unrelated dependency graphs'

# Isolate these diagnostic Makes from the parent jobserver. Invoked under
# `make pre-push-ci`, an inherited MAKEFLAGS/MAKELEVEL recursive make prints
# directory banners onto stdout even with --no-print-directory, and those
# banners are not profile paths.
profile_dirs="$(MAKEFLAGS= make -s --no-print-directory -C "$ROOT" --eval \
    'print-dev-profile-dirs: ; @printf "%s\n" "$(DEV_OBJ_DIR)" "$(TEST_FAST_OBJ_DIR)"' \
    print-dev-profile-dirs)" ||
    fail 'cannot derive development profile directories'
while IFS= read -r profile_dir; do
    case "$profile_dir" in
        build/dev-obj/epochs/*|build/test-obj/epochs/*)
            mkdir -p "$ROOT/$profile_dir" ||
                fail "cannot create derived profile directory $profile_dir"
            ;;
        ''|make*|gen_templates:*)
            # Directory banners, jobserver warnings, and template generation
            # are transport chatter, not a derived profile path.
            ;;
        *) fail "unexpected development profile directory: $profile_dir" ;;
    esac
done <<<"$profile_dirs"

MAKEFLAGS= make -s -nB --no-print-directory -C "$ROOT" dev-bin >"$scratch" ||
    fail 'cannot expand the complete dev-bin recipe graph'
if grep -Eq -- '(^|[[:space:]])-flto|(^|[[:space:]])-fuse-linker-plugin' \
        "$scratch"; then
    fail 'expanded dev-bin dependency graph invokes release-only LTO'
fi

printf '%s\n' \
    'check-dev-loop-profiles: PASS — DEV_LIVE/DEV_RESTART/INTEGRATION are non-LTO; RELEASE retains LTO'
