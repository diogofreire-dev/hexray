#!/usr/bin/env bash
# Compares `hexray dump` with the real `hexdump -C`: output and exit code must match.
#
# Usage: tests/test_dump.sh path/to/hexray
#
# Written for bash 3.2, the version that ships with macOS.

set -u

# The locale changes what isprint() considers printable, so fix it for both programs
export LC_ALL=C

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
    echo "Usage: $0 path/to/hexray" >&2
    exit 2
fi
hexray=$1

work=$(mktemp -d "${TMPDIR:-/tmp}/hexray-tests.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
fixtures=$work/fixtures
mkdir "$fixtures"

passed=0
failed=0

# Prints why a case failed, plus the first lines of the difference
report_failure() {
    failed=$((failed + 1))
    echo "FAIL: $1"
    echo "  exit codes: hexdump=$2 hexray=$3"
    diff "$work/expected" "$work/actual" | head -6 | sed 's/^/  /'
    head -6 "$work/errors" | sed 's/^/  /'
}

# check LABEL EXPECTED_STATUS ACTUAL_STATUS
check() {
    if [ "$2" -eq "$3" ] && cmp -s "$work/expected" "$work/actual"; then
        passed=$((passed + 1))
    else
        report_failure "$1" "$2" "$3"
    fi
}

# Runs one file with one set of options, in the three ways input can arrive.
# $options is left unquoted on purpose, so "-s 5 -n 20" becomes separate arguments.
compare() {
    local file=$1 options=$2 name
    name=$(basename "$file")

    hexdump -C $options "$file" >"$work/expected" 2>/dev/null
    local expected=$?
    "$hexray" dump $options "$file" >"$work/actual" 2>"$work/errors"
    check "$name [$options] as a file" "$expected" "$?"

    hexdump -C $options <"$file" >"$work/expected" 2>/dev/null
    expected=$?
    "$hexray" dump $options <"$file" >"$work/actual" 2>"$work/errors"
    check "$name [$options] redirected to stdin" "$expected" "$?"

    cat "$file" | hexdump -C $options >"$work/expected" 2>/dev/null
    expected=${PIPESTATUS[1]}
    cat "$file" | "$hexray" dump $options >"$work/actual" 2>"$work/errors"
    check "$name [$options] through a pipe" "$expected" "${PIPESTATUS[1]}"
}

# Invalid usage: must exit with 1, say why on stderr and print nothing on stdout
expect_error() {
    local label=$1
    shift
    "$@" >"$work/actual" 2>"$work/errors"
    local status=$?
    if [ "$status" -eq 1 ] && [ ! -s "$work/actual" ] && [ -s "$work/errors" ]; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        echo "FAIL: $label (exit code $status, expected 1)"
    fi
}

# --- Files to test with ---------------------------------------------------------

: >"$fixtures/empty"
printf 'A' >"$fixtures/one-byte"
printf '0123456789abcde' >"$fixtures/15-bytes"
printf '0123456789abcdef' >"$fixtures/16-bytes"
printf '0123456789abcdefg' >"$fixtures/17-bytes"
head -c 4096 /dev/zero >"$fixtures/zeros"
head -c 40 /dev/zero >"$fixtures/zeros-short-tail"
head -c 8192 /dev/urandom >"$fixtures/random"
cp README.md "$fixtures/text with spaces.md"
cp "$hexray" "$fixtures/compiled-binary"

# A run of repeated lines with different data on both sides: the * must stop and start
{
    printf 'first line here!'
    head -c 64 /dev/zero
    printf 'in the middle...'
    head -c 64 /dev/zero
    printf 'end'
} >"$fixtures/repeats"

# Every byte value, for the printable/non-printable column
for high in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
    for low in 0 1 2 3 4 5 6 7 8 9 a b c d e f; do
        printf "\\x$high$low"
    done
done >"$fixtures/all-bytes"

# --- Option combinations --------------------------------------------------------

option_sets=(
    ""
    "-v"
    "-s 0"
    "-s 5"
    "-s 16"
    "-s 0x10"
    "-s 020"
    "-s 1000000"
    "-n 0"
    "-n 1"
    "-n 16"
    "-n 17"
    "-n 020"
    "-n 1000000"
    "-s 5 -n 20"
    "-s 8 -n 0"
    "-s 16 -n 32 -v"
    "-v -s 3 -n 100"
)

for file in "$fixtures"/*; do
    for options in "${option_sets[@]}"; do
        compare "$file" "$options"
    done
done

# A real system binary, with fewer combinations because it is much larger
if [ -f /bin/ls ]; then
    for options in "" "-v" "-s 0x100 -n 512"; do
        compare /bin/ls "$options"
    done
fi

# --- Errors ---------------------------------------------------------------------

expect_error "no command" "$hexray"
expect_error "unknown command" "$hexray" nonsense
expect_error "missing file" "$hexray" dump "$work/does-not-exist"
expect_error "two files" "$hexray" dump "$fixtures/one-byte" "$fixtures/empty"
expect_error "unknown option" "$hexray" dump -z "$fixtures/one-byte"
expect_error "invalid offset" "$hexray" dump -s abc "$fixtures/one-byte"
expect_error "invalid length" "$hexray" dump -n 12x "$fixtures/one-byte"
expect_error "length in hex (only decimal is accepted)" "$hexray" dump -n 0x20 "$fixtures/one-byte"
expect_error "negative offset" "$hexray" dump -s -1 "$fixtures/one-byte"
expect_error "negative offset after a space" "$hexray" dump -s " -1" "$fixtures/one-byte"

# --- Result ---------------------------------------------------------------------

echo "$hexray: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
