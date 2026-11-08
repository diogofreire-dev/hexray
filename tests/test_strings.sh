#!/usr/bin/env bash
# Checks the output and exit code of `hexray strings` on files built byte by byte.
#
# Usage: tests/test_strings.sh path/to/hexray
#
# Written for bash 3.2, the version that ships with macOS. The fixtures are harmless
# text: IPs come from the range reserved for documentation (203.0.113.0/24).

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

# expect STATUS OUTPUT ARGUMENTS...  compares against `hexray strings ARGUMENTS`
expect() {
    local status=$1 output=$2 actual actual_status
    shift 2
    actual=$("$hexray" strings "$@" 2>errors)
    actual_status=$?
    if [ "$actual_status" -eq "$status" ] && [ "$actual" = "$output" ] &&
        { [ "$status" -eq 0 ] || [ -s errors ]; }; then
        pass
    else
        fail "strings $*"
        echo "  expected ($status): $output"
        echo "  actual ($actual_status): $actual"
        head -6 errors | sed 's/^/  /'
    fi
}

# found NAME PRINTF_FORMAT EXPECTED_OUTPUT [OPTIONS...]: creates the file and checks it
found() {
    local name=$1 format=$2 output=$3
    shift 3
    printf "$format" >"$name"
    expect 0 "$output" "$@" "$name"
}

# flagged TEXT FLAGS: TEXT must be reported at offset 0 with exactly those flags
flagged() {
    printf '%s' "$1" >flag-input
    expect 0 "00000000  ascii   $1  [$2]" flag-input
}

# clean TEXT: TEXT must be reported at offset 0 with no flag at all
clean() {
    printf '%s' "$1" >flag-input
    expect 0 "00000000  ascii   $1" flag-input
}

# --- Finding strings ------------------------------------------------------------

found exact-min 'abcd' "00000000  ascii   abcd"
found too-short 'abc' ""
found custom-min 'abc' "00000000  ascii   abc" -n 3
found raised-min 'abcdef\x00abcdefghij' "00000007  ascii   abcdefghij" -n 8
found offsets '\x00\x00\x01hello\xffworld' \
    "$(printf '00000003  ascii   hello\n00000009  ascii   world')"
found edges-printable ' ~~ \x1f\x7f' "00000000  ascii    ~~ "

# UTF-16, on an even offset, on an odd offset, and next to ASCII
found utf16-even 'H\x00e\x00l\x00l\x00o\x00' "00000000  utf-16  Hello"
found utf16-odd '\xffH\x00i\x00t\x00h\x00' "00000001  utf-16  Hith"
found utf16-short 'H\x00i\x00' ""
found utf16-mixed 'ascii\x00\x00w\x00i\x00d\x00e\x00\xff\xffmore!' \
    "$(printf '00000000  ascii   ascii\n00000007  utf-16  wide\n00000011  ascii   more!')"
found utf16-truncated 'H\x00e\x00l\x00l\x00o' "00000000  utf-16  Hell"

# Strings that cross the boundary between two reads of the file
{ head -c 65532 /dev/zero; printf 'boundary'; } >across-ascii
expect 0 "0000fffc  ascii   boundary" across-ascii
{ head -c 65531 /dev/zero; printf 'w\000i\000d\000e\000'; } >across-utf16
expect 0 "0000fffb  utf-16  wide" across-utf16

# --- Flags ----------------------------------------------------------------------

flagged 'http://example.com/a' "URL"
flagged 'see HTTPS://example.com' "URL"
flagged 'ftp://example.com/x' "URL"
flagged 'cmd.exe /c whoami' "SHELL"
flagged 'C:\Windows\System32\CMD.EXE' "SHELL"
flagged '/bin/sh -c ls' "SHELL"
flagged '/bin/bash' "SHELL"
flagged 'powershell -nop' "SHELL"
flagged 'powershell -enc AAAA' "SHELL, ENCODED-COMMAND"
flagged 'PowerShell.exe -EncodedCommand AAAA' "SHELL, ENCODED-COMMAND"
flagged 'Software\Microsoft\Windows\CurrentVersion\Run' "PERSISTENCE"
flagged 'Software\Microsoft\Windows\CurrentVersion\RunOnce' "PERSISTENCE"
flagged 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' "PERSISTENCE"
flagged 'connect 203.0.113.5:443' "IP"
flagged '203.0.113.5' "IP"
flagged 'server is 203.0.113.5.' "IP"
flagged 'http://203.0.113.5/x cmd.exe' "URL, SHELL, IP"
flagged 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAA' "BASE64"
flagged 'U29tZSByYW5kb20gYmluYXJ5IGRhdGEgZ29lcyBoZXJlIQ==' "BASE64"
flagged 'data=TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAA;' "BASE64"

clean 'just an ordinary sentence'
clean 'an option called -enc on its own'
clean '__ZN5dyld44APIs25NSVersionOfRunTimeLibraryEPKc'
clean 'version 1.2.3'
clean '999.0.113.5'
clean '1.2.3.4.5'
clean 'v1.2.3.4'
clean '203.0.113.1234'
clean 'TVqQAAMAAAAEAAAA//8AAL'
clean '/System/Library/Frameworks/CoreFoundation/Versions/A/CoreFoundation'
clean 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
clean 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAB'

# UTF-16 text is flagged too, which is the whole point of reading it
found utf16-flag 'c\x00m\x00d\x00.\x00e\x00x\x00e\x00' "00000000  utf-16  cmd.exe  [SHELL]"

# --- Options --------------------------------------------------------------------

found only-flagged 'boring text\x00cmd.exe\x00also boring' "0000000c  ascii   cmd.exe  [SHELL]" -f
found nothing-flagged 'boring text' "" -f

# Long strings are cut for display, but -v shows them whole
head -c 200000 /dev/zero | tr '\0' 'a' >long
sample=$(head -c 200 long)
expect 0 "00000000  ascii   $sample... (200000 characters)" long
length=$("$hexray" strings -v long | wc -c | tr -d ' ')
# 200000 characters, 18 for the offset and encoding columns, 1 for the newline
if [ "$length" -eq 200019 ]; then pass; else fail "-v shows the whole string: $length bytes"; fi

# Something suspicious after the part that is displayed must still be flagged
{ head -c 500 long; printf 'http://example.com'; } >hidden
sample=$(head -c 200 hidden)
expect 0 "00000000  ascii   $sample... (518 characters)  [URL]" hidden

# --- Inputs and errors ----------------------------------------------------------

: >empty
expect 0 "" empty
expect 1 "" missing.bin
mkdir folder
expect 1 "" folder
printf 'abcd' >one
printf 'efgh' >two
expect 1 "" one two
expect 1 "" -z one
expect 1 "" -n 1 one
expect 1 "" -n 0 one
expect 1 "" -n abc one

actual=$("$hexray" strings <one)
if [ "$actual" = "00000000  ascii   abcd" ]; then pass; else fail "redirected stdin: $actual"; fi
actual=$(cat one | "$hexray" strings)
if [ "$actual" = "00000000  ascii   abcd" ]; then pass; else fail "stdin through a pipe: $actual"; fi

# --- Real and random data: no crashes, which matters most on the sanitized build --

head -c 1000000 /dev/urandom >random
"$hexray" strings random >output 2>errors
status=$?
if [ "$status" -eq 0 ] && [ -s output ] && [ ! -s errors ]; then pass; else
    fail "random data (exit code $status)"; head -6 errors; fi

if [ -f /bin/ls ]; then
    "$hexray" strings /bin/ls >output 2>errors
    status=$?
    if [ "$status" -eq 0 ] && [ -s output ] && [ ! -s errors ]; then pass; else
        fail "/bin/ls (exit code $status)"; head -6 errors; fi
fi

echo "$original: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
