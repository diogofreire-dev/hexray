#!/usr/bin/env bash
# Checks `hexray hash` against the official NIST test vectors and the real shasum.
#
# Usage: tests/test_hash.sh path/to/hexray
#
# Written for bash 3.2, the version that ships with macOS.

set -u

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
    echo "Usage: $0 path/to/hexray" >&2
    exit 2
fi

# An absolute path, because the tests run from inside a temporary folder
hexray=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
original=$1

work=$(mktemp -d "${TMPDIR:-/tmp}/hexray-tests.XXXXXX") || exit 2
trap 'rm -rf "$work"' EXIT
cd "$work" || exit 2

passed=0
failed=0

pass() { passed=$((passed + 1)); }

fail() {
    failed=$((failed + 1))
    echo "FAIL: $1"
}

# expect STATUS OUTPUT ARGUMENTS...  compares against `hexray hash ARGUMENTS`
expect() {
    local status=$1 output=$2 actual actual_status
    shift 2
    actual=$("$hexray" hash "$@" 2>errors)
    actual_status=$?
    if [ "$actual_status" -eq "$status" ] && [ "$actual" = "$output" ] &&
        { [ "$status" -eq 0 ] || [ -s errors ]; }; then
        pass
    else
        fail "hash $*"
        echo "  expected ($status): $output"
        echo "  actual ($actual_status): $actual"
        head -6 errors | sed 's/^/  /'
    fi
}

# same_as_shasum FILE: the whole line must match the real tool
same_as_shasum() {
    local expected
    expected=$(shasum -a 256 "$1")
    expect 0 "$expected" "$1"
}

# --- NIST test vectors (FIPS 180-4 examples) ------------------------------------

: >nist-empty
expect 0 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  nist-empty" nist-empty

printf 'abc' >nist-abc
expect 0 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  nist-abc" nist-abc

printf 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' >nist-448
expect 0 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1  nist-448" nist-448

printf 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu' >nist-896
expect 0 "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1  nist-896" nist-896

head -c 1000000 /dev/zero | tr '\000' 'a' >nist-million
expect 0 "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0  nist-million" nist-million

# --- Against the real tool ------------------------------------------------------

# Every length around the block size, where the padding has its three cases:
# it fits in the block, it just fits, or it spills into one more block.
# (Length 0 is the first NIST vector, and head -c 0 is an error on macOS.)
head -c 300 /dev/urandom >source
length=1
while [ "$length" -le 200 ]; do
    head -c "$length" source >"length-$length"
    same_as_shasum "length-$length"
    length=$((length + 1))
done

# Around the size of one read of the file
head -c 131073 /dev/urandom >large
for length in 65535 65536 65537 131071 131072 131073; do
    head -c "$length" large >"read-$length"
    same_as_shasum "read-$length"
done

head -c 2000000 /dev/urandom >random
same_as_shasum random
head -c 100000 /dev/zero >zeros
same_as_shasum zeros

if [ -f /bin/ls ]; then
    same_as_shasum /bin/ls
fi

# --- Inputs and errors ----------------------------------------------------------

abc="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
empty="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

actual=$("$hexray" hash <nist-abc)
if [ "$actual" = "$abc  -" ]; then pass; else fail "redirected stdin: $actual"; fi
actual=$(cat nist-abc | "$hexray" hash)
if [ "$actual" = "$abc  -" ]; then pass; else fail "stdin through a pipe: $actual"; fi

# Several files, and a missing one must not stop the others
expect 0 "$(printf '%s  nist-abc\n%s  nist-empty' "$abc" "$empty")" nist-abc nist-empty
expect 1 "$(printf '%s  nist-abc\n%s  nist-empty' "$abc" "$empty")" nist-abc missing.bin nist-empty

expect 1 "" missing.bin
mkdir folder
expect 1 "" folder
expect 1 "" -z nist-abc

printf 'abc' >./-dash
expect 0 "$abc  -dash" -- -dash

# Terminal escape sequences in a file name must not reach the screen
escape_name=$(printf 'evil\033[31m.bin')
printf 'abc' >"$escape_name"
expect 0 "$abc  evil?[31m.bin" "$escape_name"

echo "$original: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
