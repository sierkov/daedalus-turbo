#!/usr/bin/env bash

set -euo pipefail

usage()
{
    cat <<'EOF'
Usage:
  bash test/gen-coverage.sh [OPTIONS] test [FILTER]
  bash test/gen-coverage.sh [OPTIONS] cli -- TADA_ARGUMENTS...

Options (before test or cli):
  --scope=all|cbor|ledger        Sources to report (default: all)
  --out-dir=DIR                Report directory (default: tmp/coverage)
  --build-dir=DIR              Coverage build directory (default: build-cov)
  -h, --help                   Show this help

Examples:
  bash test/gen-coverage.sh test
  bash test/gen-coverage.sh cli -- sync --max-slot=100000 tmp/sync-cov
  bash test/gen-coverage.sh --scope=cbor cli -- test-cbor-dataset /path/to/dataset
  bash test/gen-coverage.sh --scope=ledger cli -- sync --max-slot=100000 tmp/sync-cov
  bash test/gen-coverage.sh --out-dir=tmp/coverage-p2p test 'sync::p2p'
EOF
}

fail()
{
    echo "error: $*" >&2
    exit 2
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SOURCE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
cd -- "$SOURCE_DIR"

SCOPE=all
OUT_DIR=tmp/coverage
BUILD_DIR=build-cov
LLVM_PROFDATA=${LLVM_PROFDATA:-llvm-profdata-21}
LLVM_COV=${LLVM_COV:-llvm-cov-21}

while (( $# )); do
    case $1 in
        --scope=|--out-dir=|--build-dir=) fail "${1%=} requires a nonempty value" ;;
        --scope=*) SCOPE=${1#*=} ;;
        --out-dir=*) OUT_DIR=${1#*=} ;;
        --build-dir=*) BUILD_DIR=${1#*=} ;;
        --scope|--out-dir|--build-dir) fail "use $1=VALUE" ;;
        -h|--help) usage; exit 0 ;;
        test|cli) break ;;
        *) fail "unknown option or workload: $1 (see --help)" ;;
    esac
    shift
done

case $SCOPE in
    all|cbor|ledger) ;;
    *) fail "unknown scope: $SCOPE" ;;
esac
case ${1:-} in
    '') usage; exit 0 ;;
    test)
        shift
        (( $# <= 1 )) || fail "test accepts one optional FILTER"
        [[ ${1:-} != -* ]] || fail "options must precede test"
        BIN_NAME=tada-test
        RUN_ARGS=("${1:-*}")
        ;;
    cli)
        shift
        [[ ${1:-} == -- ]] || fail "cli requires -- before TADA arguments"
        shift
        (( $# )) || fail "cli requires TADA arguments after --"
        BIN_NAME=tada
        RUN_ARGS=("$@")
        ;;
    *) fail "choose a workload: test or cli (see --help)" ;;
esac

BIN_PATH="$BUILD_DIR/$BIN_NAME"
[[ -x $BIN_PATH ]] || fail "missing coverage executable: $BIN_PATH; build with CMAKE_BUILD_TYPE=Coverage first"
for tool in "$LLVM_PROFDATA" "$LLVM_COV"; do
    command -v -- "$tool" >/dev/null || fail "required tool not found: $tool"
done

mkdir -p -- "$OUT_DIR"
REPORT_LOCK="$OUT_DIR/.gen-coverage.lock"
if ! mkdir -- "$REPORT_LOCK" 2>/dev/null; then
    fail "cannot lock $OUT_DIR; use another directory or remove $REPORT_LOCK after confirming no run is active"
fi
release_report_lock()
{
    rmdir -- "$REPORT_LOCK" 2>/dev/null || true
}
trap release_report_lock EXIT

PROFILE_ROOT=${COVERAGE_PROFILE_DIR:-tmp/coverage-profiles}
mkdir -p -- "$PROFILE_ROOT"
PROFILE_DIR=$(mktemp -d "$PROFILE_ROOT/$BIN_NAME.XXXXXX")
PROFILE_DIR=$(cd -- "$PROFILE_DIR" && pwd)
PROFILE_DATA="$PROFILE_DIR/coverage.profdata"
PROFILE_PATTERN="$PROFILE_DIR/%p-%m.profraw"

find "$SOURCE_DIR/lib/turbo" "$SOURCE_DIR/src" -type f \
    \( -name '*.cpp' -o -name '*.hpp' -o -name '*.ipp' \) \
    ! -name '*.test.cpp' ! -name '*.bench.cpp' ! -name '*.fuzz.cpp' \
    ! -name 'run-test.cpp' -print0 |
    LC_ALL=C sort -z > "$PROFILE_DIR/source-candidates.nul"

REPORT_SOURCES=()
while IFS= read -r -d '' source; do
    relative_source=${source#"$SOURCE_DIR/"}
    case "$SCOPE:$relative_source" in
        all:*|cbor:lib/turbo/cbor/*|cbor:lib/turbo/*/cbor/*|\
        cbor:lib/turbo/cardano/common/types.hpp|cbor:lib/turbo/cardano/common/types/base.hpp|\
        ledger:lib/turbo/cardano/ledger/rules/*)
            REPORT_SOURCES+=("$source")
            ;;
    esac
done < "$PROFILE_DIR/source-candidates.nul"
(( ${#REPORT_SOURCES[@]} )) || fail "no production sources found for scope: $SCOPE"
printf '%s\n' "${REPORT_SOURCES[@]}" > "$OUT_DIR/sources.txt"

{
    printf 'working_directory: %q\nscope: %s\nbinary: %q\n' "$SOURCE_DIR" "$SCOPE" "$BIN_PATH"
    printf 'profile_data: %q\nllvm_profdata: %q\nllvm_cov: %q\n' "$PROFILE_DATA" "$LLVM_PROFDATA" "$LLVM_COV"
    printf 'command: LLVM_PROFILE_FILE=%q' "$PROFILE_PATTERN"
    printf ' %q' "$BIN_PATH" "${RUN_ARGS[@]}"
    printf '\n'
} > "$OUT_DIR/run.txt"

printf 'Running:'
printf ' %q' "$BIN_PATH" "${RUN_ARGS[@]}"
printf '\n'
WORKLOAD_STATUS=0
LLVM_PROFILE_FILE="$PROFILE_PATTERN" "$BIN_PATH" "${RUN_ARGS[@]}" || WORKLOAD_STATUS=$?
printf 'workload_exit_status: %s\n' "$WORKLOAD_STATUS" >> "$OUT_DIR/run.txt"

shopt -s nullglob
RAW_PROFILES=("$PROFILE_DIR"/*.profraw)
if (( ${#RAW_PROFILES[@]} == 0 )); then
    echo "error: the workload produced no raw LLVM profiles in $PROFILE_DIR" >&2
    exit "$(( WORKLOAD_STATUS == 0 ? 1 : WORKLOAD_STATUS ))"
fi
if (( WORKLOAD_STATUS != 0 )); then
    echo "Workload exited with status $WORKLOAD_STATUS; reporting available profiles" >&2
fi

echo "Indexing ${#RAW_PROFILES[@]} raw profile(s) into $PROFILE_DATA"
"$LLVM_PROFDATA" merge -sparse "${RAW_PROFILES[@]}" -o "$PROFILE_DATA"

REPORT_ARGS=("$BIN_PATH" "-instr-profile=$PROFILE_DATA" "${REPORT_SOURCES[@]}")
echo "Generating $SCOPE coverage report into $OUT_DIR"
"$LLVM_COV" show "${REPORT_ARGS[@]}" -show-branches=percent -format=html "-output-dir=$OUT_DIR"
"$LLVM_COV" export "${REPORT_ARGS[@]}" -format=text > "$OUT_DIR/coverage.json"
"$LLVM_COV" export "${REPORT_ARGS[@]}" -format=lcov > "$OUT_DIR/coverage.lcov"
"$LLVM_COV" report "${REPORT_ARGS[@]}" > "$OUT_DIR/summary.txt"
echo "Coverage report: $OUT_DIR/index.html"
echo "Raw and indexed profiles: $PROFILE_DIR"
exit "$WORKLOAD_STATUS"
